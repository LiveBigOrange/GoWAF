package logdb

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type QueryCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
	sf      singleflight
	stopCh  chan struct{}
}

type CacheEntry struct {
	data      interface{}
	createdAt time.Time
	hits      atomic.Int64
}

type singleflight struct {
	mu    sync.Mutex
	calls map[string]*sfCall
}

type sfCall struct {
	wg  sync.WaitGroup
	val interface{}
	err error
}

func (sf *singleflight) Do(key string, fn func() (interface{}, error)) (interface{}, error) {
	sf.mu.Lock()
	if sf.calls == nil {
		sf.calls = make(map[string]*sfCall)
	}
	if c, ok := sf.calls[key]; ok {
		sf.mu.Unlock()
		c.wg.Wait()
		return c.val, c.err
	}
	c := &sfCall{}
	sf.calls[key] = c
	sf.mu.Unlock()

	c.wg.Add(1)
	func() {
		defer func() {
			if r := recover(); r != nil {
				c.err = fmt.Errorf("singleflight panic: %v", r)
			}
		}()
		c.val, c.err = fn()
	}()
	c.wg.Done()

	sf.mu.Lock()
	delete(sf.calls, key)
	sf.mu.Unlock()

	return c.val, c.err
}

func NewQueryCache(maxSize int, ttl time.Duration) *QueryCache {
	cache := &QueryCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}

	go cache.cleanup()

	return cache
}

func (c *QueryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Since(entry.createdAt) > c.ttl {
		return nil, false
	}

	entry.hits.Add(1)

	return entry.data, true
}

func (c *QueryCache) Set(key string, data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &CacheEntry{
		data:      data,
		createdAt: time.Now(),
	}
}

func (c *QueryCache) GetOrLoad(key string, fn func() (interface{}, error)) (interface{}, error) {
	if data, ok := c.Get(key); ok {
		return data, nil
	}

	data, err := c.sf.Do(key, fn)
	if err != nil {
		return nil, err
	}

	c.Set(key, data)
	return data, nil
}

func (c *QueryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *QueryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

func (c *QueryCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalHits int
	for _, entry := range c.entries {
		totalHits += int(entry.hits.Load())
	}

	return CacheStats{
		Size:      len(c.entries),
		MaxSize:   c.maxSize,
		TotalHits: totalHits,
		TTL:       c.ttl,
	}
}

type CacheStats struct {
	Size      int
	MaxSize   int
	TotalHits int
	TTL       time.Duration
}

func (c *QueryCache) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range c.entries {
		if oldestKey == "" || entry.createdAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.createdAt
		}
	}

	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

func (c *QueryCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for key, entry := range c.entries {
				if now.Sub(entry.createdAt) > c.ttl {
					delete(c.entries, key)
				}
			}
			c.mu.Unlock()
		}
	}
}

func (c *QueryCache) Stop() {
	close(c.stopCh)
}
