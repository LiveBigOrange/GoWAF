package limiter

import (
	"hash/fnv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const shardCount = 64

type shard struct {
	mu   sync.Mutex
	ips  map[string]*rate.Limiter
	r    rate.Limit
	b    int
}

type IPRateLimiter struct {
	shards  [shardCount]shard
	enabled bool
	stopChan chan struct{}
}

func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		enabled:  true,
		stopChan: make(chan struct{}),
	}
	for idx := range i.shards {
		i.shards[idx].ips = make(map[string]*rate.Limiter)
		i.shards[idx].r = r
		i.shards[idx].b = b
	}
	return i
}

func (i *IPRateLimiter) getShard(ip string) *shard {
	h := fnv.New32a()
	h.Write([]byte(ip))
	return &i.shards[h.Sum32()%shardCount]
}

func (i *IPRateLimiter) Allow(ip string) bool {
	if !i.enabled {
		return true
	}
	s := i.getShard(ip)
	s.mu.Lock()
	limiter, exists := s.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(s.r, s.b)
		s.ips[ip] = limiter
	}
	s.mu.Unlock()
	return limiter.Allow()
}

func (i *IPRateLimiter) UpdateConfig(r rate.Limit, b int) {
	for idx := range i.shards {
		s := &i.shards[idx]
		s.mu.Lock()
		s.r = r
		s.b = b
		s.ips = make(map[string]*rate.Limiter)
		s.mu.Unlock()
	}
}

func (i *IPRateLimiter) SetEnabled(enabled bool) {
	i.enabled = enabled
}

func (i *IPRateLimiter) GetEnabled() bool {
	return i.enabled
}

func (i *IPRateLimiter) GetConfig() (rate.Limit, int) {
	return i.shards[0].r, i.shards[0].b
}

func (i *IPRateLimiter) Cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-i.stopChan:
				ticker.Stop()
				return
			case <-ticker.C:
				for idx := range i.shards {
					s := &i.shards[idx]
					s.mu.Lock()
					for ip, limiter := range s.ips {
						if limiter.Tokens() >= float64(s.b) {
							delete(s.ips, ip)
						}
					}
					if len(s.ips) > 50000 {
						cnt := 0
						for ip := range s.ips {
							delete(s.ips, ip)
							cnt++
							if cnt > len(s.ips)/2 {
								break
							}
						}
					}
					s.mu.Unlock()
				}
			}
		}
	}()
}

func (i *IPRateLimiter) Stop() {
	close(i.stopChan)
}
