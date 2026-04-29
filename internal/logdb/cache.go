package logdb

import (
	"sync"
	"time"
)

// QueryCache 查询缓存
type QueryCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
	ttl     time.Duration
}

// CacheEntry 缓存条目
type CacheEntry struct {
	data      interface{}
	createdAt time.Time
	hits      int
}

// NewQueryCache 创建查询缓存
func NewQueryCache(maxSize int, ttl time.Duration) *QueryCache {
	cache := &QueryCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
		ttl:     ttl,
	}

	// 启动清理协程
	go cache.cleanup()

	return cache
}

// Get 获取缓存
func (c *QueryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	// 检查是否过期
	if time.Since(entry.createdAt) > c.ttl {
		c.mu.RUnlock()
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		c.mu.RLock()
		return nil, false
	}

	// 增加命中次数
	entry.hits++

	return entry.data, true
}

// Set 设置缓存
func (c *QueryCache) Set(key string, data interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查是否需要清理
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}

	c.entries[key] = &CacheEntry{
		data:      data,
		createdAt: time.Now(),
		hits:      0,
	}
}

// Delete 删除缓存
func (c *QueryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// Clear 清空缓存
func (c *QueryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// Stats 获取缓存统计
func (c *QueryCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var totalHits int
	for _, entry := range c.entries {
		totalHits += entry.hits
	}

	return CacheStats{
		Size:     len(c.entries),
		MaxSize:  c.maxSize,
		TotalHits: totalHits,
		TTL:      c.ttl,
	}
}

// CacheStats 缓存统计
type CacheStats struct {
	Size      int
	MaxSize   int
	TotalHits int
	TTL       time.Duration
}

// evictOldest 清理最老的条目
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

// cleanup 定期清理过期条目
func (c *QueryCache) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
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
