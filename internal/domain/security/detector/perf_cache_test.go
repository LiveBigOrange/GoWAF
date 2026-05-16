package detector

import (
	"sync"
	"testing"
	"time"
)

func TestNewDetectionCache(t *testing.T) {
	c := NewDetectionCache(100, 30*time.Second, 64)
	if c.capacity != 100 {
		t.Errorf("expected capacity 100, got %d", c.capacity)
	}
	if c.ttl != 30*time.Second {
		t.Errorf("expected ttl 30s, got %v", c.ttl)
	}
	if c.keyLen != 64 {
		t.Errorf("expected keyLen 64, got %d", c.keyLen)
	}
}

func TestNewDetectionCache_Defaults(t *testing.T) {
	c := NewDetectionCache(0, 0, 0)
	if c.capacity != 4096 {
		t.Errorf("expected default capacity 4096, got %d", c.capacity)
	}
	if c.ttl != 60*time.Second {
		t.Errorf("expected default ttl 60s, got %v", c.ttl)
	}
	if c.keyLen != 128 {
		t.Errorf("expected default keyLen 128, got %d", c.keyLen)
	}
}

func TestDetectionCache_computeCacheKey(t *testing.T) {
	c := NewDetectionCache(100, 10*time.Second, 128)

	key1 := c.computeCacheKey("GET", "/api", "id=1", "")
	key2 := c.computeCacheKey("GET", "/api", "id=1", "")
	if key1 != key2 {
		t.Errorf("same input should produce same key: %d != %d", key1, key2)
	}

	key3 := c.computeCacheKey("POST", "/api", "id=1", "")
	if key1 == key3 {
		t.Errorf("different method should produce different key")
	}

	key4 := c.computeCacheKey("GET", "/other", "id=1", "")
	if key1 == key4 {
		t.Errorf("different path should produce different key")
	}
}

func TestDetectionCache_PutGet(t *testing.T) {
	c := NewDetectionCache(100, 10*time.Second, 128)

	results := []DetectionResult{
		{Detected: true, AttackType: "sql_injection", Pattern: "union select", Confidence: 0.7},
	}
	key := c.computeCacheKey("GET", "/api", "id=1", "")
	c.Put(key, results)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	if got[0].AttackType != "sql_injection" {
		t.Errorf("expected AttackType sql_injection, got %s", got[0].AttackType)
	}

	got[0].AttackType = "modified"
	got2, _ := c.Get(key)
	if got2[0].AttackType == "modified" {
		t.Errorf("deep copy should prevent mutation of cached data")
	}
}

func TestDetectionCache_Miss(t *testing.T) {
	c := NewDetectionCache(100, 10*time.Second, 128)

	_, ok := c.Get(999)
	if ok {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestDetectionCache_TTLExpiry(t *testing.T) {
	c := NewDetectionCache(100, 50*time.Millisecond, 128)

	results := []DetectionResult{{Detected: true, AttackType: "xss"}}
	key := uint64(42)
	c.Put(key, results)

	_, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit before TTL expiry")
	}

	time.Sleep(120 * time.Millisecond)

	_, ok = c.Get(key)
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestDetectionCache_Eviction(t *testing.T) {
	capacity := 5
	c := NewDetectionCache(capacity, 10*time.Second, 128)

	for i := 0; i < capacity+3; i++ {
		results := []DetectionResult{{Detected: true, AttackType: "test"}}
		c.Put(uint64(i), results)
	}

	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()

	if size > capacity {
		t.Errorf("cache size %d exceeds capacity %d", size, capacity)
	}

	_, ok := c.Get(0)
	if ok {
		t.Error("key 0 should have been evicted")
	}

	_, ok = c.Get(uint64(capacity + 2))
	if !ok {
		t.Error("most recent key should still be in cache")
	}
}

func TestDetectionCache_Invalidate(t *testing.T) {
	c := NewDetectionCache(100, 10*time.Second, 128)

	results := []DetectionResult{{Detected: true, AttackType: "sql_injection"}}
	c.Put(1, results)
	c.Put(2, results)

	c.Invalidate()

	_, ok := c.Get(1)
	if ok {
		t.Error("expected miss after invalidate")
	}

	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	if size != 0 {
		t.Errorf("expected size 0 after invalidate, got %d", size)
	}
}

func TestDetectionCache_Stats(t *testing.T) {
	c := NewDetectionCache(100, 10*time.Second, 128)

	results := []DetectionResult{{Detected: true, AttackType: "sql_injection"}}
	c.Put(1, results)

	c.Get(1)
	c.Get(1)
	c.Get(2)

	hits, misses, size, hitRate := c.Stats()
	if hits != 2 {
		t.Errorf("expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("expected size 1, got %d", size)
	}
	expectedRate := 2.0 / 3.0
	if hitRate < expectedRate-0.01 || hitRate > expectedRate+0.01 {
		t.Errorf("expected hit rate ~%.2f, got %.2f", expectedRate, hitRate)
	}
}

func TestDetectionCache_UpdateExisting(t *testing.T) {
	c := NewDetectionCache(100, 10*time.Second, 128)

	results1 := []DetectionResult{{Detected: true, AttackType: "sql_injection"}}
	results2 := []DetectionResult{{Detected: true, AttackType: "xss"}}
	key := uint64(1)

	c.Put(key, results1)
	c.Put(key, results2)

	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got[0].AttackType != "xss" {
		t.Errorf("expected updated AttackType xss, got %s", got[0].AttackType)
	}
}

func TestDetectionCache_Concurrent(t *testing.T) {
	c := NewDetectionCache(1000, 10*time.Second, 128)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := uint64(id)
			results := []DetectionResult{{Detected: true, AttackType: "test"}}
			c.Put(key, results)
			c.Get(key)
			c.Get(uint64(id + 1000))
		}(i)
	}
	wg.Wait()

	hits, misses, size, _ := c.Stats()
	if size == 0 {
		t.Error("expected non-zero cache size after concurrent ops")
	}
	_ = hits
	_ = misses
}

func TestDeepCopyResults(t *testing.T) {
	original := []DetectionResult{
		{Detected: true, AttackType: "sql_injection", Pattern: "union", Confidence: 0.9},
	}
	cp := deepCopyResults(original)

	cp[0].AttackType = "modified"
	if original[0].AttackType == "modified" {
		t.Error("deep copy should not affect original")
	}

	nilResult := deepCopyResults(nil)
	if nilResult != nil {
		t.Error("deep copy of nil should be nil")
	}

	emptyResult := deepCopyResults([]DetectionResult{})
	if emptyResult != nil {
		t.Error("deep copy of empty slice should be nil")
	}
}
