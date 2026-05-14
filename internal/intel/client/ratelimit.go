package client

import (
	"sync"
	"time"
)

type RateLimitTracker struct {
	mu       sync.Mutex
	maxCount int
	window   time.Duration
	count    int
	start    time.Time
}

func NewRateLimitTracker(maxCount int, window time.Duration) *RateLimitTracker {
	return &RateLimitTracker{
		maxCount: maxCount,
		window:   window,
		start:    time.Now(),
	}
}

func (r *RateLimitTracker) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if now.Sub(r.start) >= r.window {
		r.count = 0
		r.start = now
	}

	if r.count >= r.maxCount {
		return false
	}

	r.count++
	return true
}

func (r *RateLimitTracker) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count = 0
	r.start = time.Now()
}

func (r *RateLimitTracker) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}
