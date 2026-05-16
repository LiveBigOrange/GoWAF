package detector

import (
	"hash/fnv"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type detectionCacheEntry struct {
	key      uint64
	results  []DetectionResult
	expireAt int64
	prev     *detectionCacheEntry
	next     *detectionCacheEntry
}

type DetectionCache struct {
	mu       sync.Mutex
	capacity int
	entries  map[uint64]*detectionCacheEntry
	head     *detectionCacheEntry
	tail     *detectionCacheEntry
	ttl      time.Duration
	keyLen   int
	hits     uint64
	misses   uint64
	rng      *rand.Rand
}

func NewDetectionCache(capacity int, ttl time.Duration, keyLen int) *DetectionCache {
	if capacity <= 0 {
		capacity = 4096
	}
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if keyLen <= 0 {
		keyLen = 128
	}
	return &DetectionCache{
		capacity: capacity,
		entries:  make(map[uint64]*detectionCacheEntry, capacity),
		ttl:      ttl,
		keyLen:   keyLen,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (c *DetectionCache) computeCacheKey(method, path, query, body string) uint64 {
	h := fnv.New64a()

	h.Write([]byte(method))
	h.Write([]byte{0})

	truncate := func(s string, maxLen int) []byte {
		if len(s) > maxLen {
			return []byte(s[:maxLen])
		}
		return []byte(s)
	}

	h.Write(truncate(path, c.keyLen))
	h.Write([]byte{0})

	h.Write(truncate(query, c.keyLen))
	h.Write([]byte{0})

	h.Write(truncate(body, c.keyLen))

	return h.Sum64()
}

func (c *DetectionCache) Get(key uint64) ([]DetectionResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	now := time.Now().UnixNano()
	if now > e.expireAt {
		c.removeEntry(e)
		delete(c.entries, key)
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}

	c.moveToHead(e)

	atomic.AddUint64(&c.hits, 1)
	return deepCopyResults(e.results), true
}

func (c *DetectionCache) Put(key uint64, results []DetectionResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[key]; ok {
		e.results = deepCopyResults(results)
		now := time.Now().UnixNano()
		jitter := c.ttlJitter()
		e.expireAt = now + int64(c.ttl+jitter)
		c.moveToHead(e)
		return
	}

	if len(c.entries) >= c.capacity {
		if c.tail != nil {
			delete(c.entries, c.tail.key)
			c.removeEntry(c.tail)
		}
	}

	now := time.Now().UnixNano()
	jitter := c.ttlJitter()
	entry := &detectionCacheEntry{
		key:      key,
		results:  deepCopyResults(results),
		expireAt: now + int64(c.ttl+jitter),
	}

	c.entries[key] = entry
	c.addToHead(entry)
}

func (c *DetectionCache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[uint64]*detectionCacheEntry, c.capacity)
	c.head = nil
	c.tail = nil
}

func (c *DetectionCache) Stats() (hits, misses uint64, size int, hitRate float64) {
	hits = atomic.LoadUint64(&c.hits)
	misses = atomic.LoadUint64(&c.misses)
	c.mu.Lock()
	size = len(c.entries)
	c.mu.Unlock()
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}
	return
}

func (c *DetectionCache) ttlJitter() time.Duration {
	jitterRange := float64(c.ttl) * 0.1
	jitterSec := c.rng.Float64()*2*jitterRange - jitterRange
	return time.Duration(jitterSec)
}

func (c *DetectionCache) moveToHead(e *detectionCacheEntry) {
	if e == c.head {
		return
	}
	c.removeEntry(e)
	c.addToHead(e)
}

func (c *DetectionCache) addToHead(e *detectionCacheEntry) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

func (c *DetectionCache) removeEntry(e *detectionCacheEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

func deepCopyResults(results []DetectionResult) []DetectionResult {
	if len(results) == 0 {
		return nil
	}
	cp := make([]DetectionResult, len(results))
	copy(cp, results)
	return cp
}
