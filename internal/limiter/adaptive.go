package limiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type AdaptiveLimiter struct {
	mu             sync.RWMutex
	limiter        *rate.Limiter
	baseRate       rate.Limit
	baseBurst      int
	currentRate    rate.Limit
	window         time.Duration
	totalRequests  int64
	blockedRequests int64
	lastReset      time.Time
	threshold      float64
	maxMultiplier  float64
}

func NewAdaptiveLimiter(r rate.Limit, burst int, window time.Duration, threshold float64) *AdaptiveLimiter {
	return &AdaptiveLimiter{
		limiter:       rate.NewLimiter(r, burst),
		baseRate:      r,
		baseBurst:     burst,
		currentRate:   r,
		window:        window,
		lastReset:     time.Now(),
		threshold:     threshold,
		maxMultiplier: 4.0,
	}
}

func (a *AdaptiveLimiter) Allow() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.limiter.Allow()
}

func (a *AdaptiveLimiter) RecordRequest() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.totalRequests++
	a.checkAndAdjust()
}

func (a *AdaptiveLimiter) RecordBlock() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.blockedRequests++
	a.checkAndAdjust()
}

func (a *AdaptiveLimiter) checkAndAdjust() {
	now := time.Now()
	if now.Sub(a.lastReset) < a.window {
		return
	}
	if a.totalRequests == 0 {
		a.lastReset = now
		return
	}

	blockRate := float64(a.blockedRequests) / float64(a.totalRequests)

	var newRate rate.Limit
	if blockRate > a.threshold {
		multiplier := 1.0 + (blockRate-a.threshold)*2.0
		if multiplier > a.maxMultiplier {
			multiplier = a.maxMultiplier
		}
		newRate = rate.Limit(float64(a.baseRate) * multiplier)
	} else {
		newRate = a.baseRate
	}

	if newRate != a.currentRate {
		a.currentRate = newRate
		a.limiter = rate.NewLimiter(newRate, a.baseBurst)
	}

	a.totalRequests = 0
	a.blockedRequests = 0
	a.lastReset = now
}

func (a *AdaptiveLimiter) GetStats() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return map[string]interface{}{
		"base_rate":    float64(a.baseRate),
		"current_rate": float64(a.currentRate),
		"burst":        a.baseBurst,
		"threshold":    a.threshold,
	}
}
