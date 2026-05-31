package limiter

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const shardCount = 64

type ipEntry struct {
	limiter    *rate.Limiter
	lastAccess int64
}

type shard struct {
	mu  sync.Mutex
	ips map[string]*ipEntry
	r   rate.Limit
	b   int
}

// IPRateLimiter 基于分片的IP限流器
//
// Deprecated: 请使用 ratelimit.Engine 替代。该类型将在未来版本移除。
type IPRateLimiter struct {
	shards   [shardCount]shard
	enabled  atomic.Int32
	stopChan chan struct{}
}

// NewIPRateLimiter 创建IP限流器
//
// Deprecated: 请使用 ratelimit.Engine 替代。该构造函数将在未来版本移除。
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		stopChan: make(chan struct{}),
	}
	i.enabled.Store(1)
	for idx := range i.shards {
		i.shards[idx].ips = make(map[string]*ipEntry)
		i.shards[idx].r = r
		i.shards[idx].b = b
	}
	return i
}

func (i *IPRateLimiter) getShard(ip string) *shard {
	h := uint32(2166136261)
	for j := 0; j < len(ip); j++ {
		h ^= uint32(ip[j])
		h *= 16777619
	}
	return &i.shards[h%shardCount]
}

func (i *IPRateLimiter) Allow(ip string) bool {
	if i.enabled.Load() == 0 {
		return true
	}
	s := i.getShard(ip)
	s.mu.Lock()
	entry, exists := s.ips[ip]
	if !exists {
		entry = &ipEntry{
			limiter:    rate.NewLimiter(s.r, s.b),
			lastAccess: time.Now().Unix(),
		}
		s.ips[ip] = entry
	} else {
		entry.lastAccess = time.Now().Unix()
	}
	s.mu.Unlock()
	return entry.limiter.Allow()
}

func (i *IPRateLimiter) UpdateConfig(r rate.Limit, b int) {
	for idx := range i.shards {
		s := &i.shards[idx]
		s.mu.Lock()
		s.r = r
		s.b = b
		s.ips = make(map[string]*ipEntry)
		s.mu.Unlock()
	}
}

func (i *IPRateLimiter) SetEnabled(enabled bool) {
	if enabled {
		i.enabled.Store(1)
	} else {
		i.enabled.Store(0)
	}
}

func (i *IPRateLimiter) GetEnabled() bool {
	return i.enabled.Load() == 1
}

func (i *IPRateLimiter) GetConfig() (rate.Limit, int) {
	s := &i.shards[0]
	s.mu.Lock()
	r, b := s.r, s.b
	s.mu.Unlock()
	return r, b
}

func (i *IPRateLimiter) Cleanup(interval time.Duration) {
	i.CleanupWithIdle(interval, 600)
}

func (i *IPRateLimiter) CleanupWithIdle(interval time.Duration, idleSeconds int64) {
	ticker := time.NewTicker(interval)
	for {
		select {
		case <-i.stopChan:
			ticker.Stop()
			return
		case <-ticker.C:
			now := time.Now().Unix()
			for idx := range i.shards {
				s := &i.shards[idx]
				s.mu.Lock()
				for ip, entry := range s.ips {
					if now-entry.lastAccess > idleSeconds && entry.limiter.Tokens() >= float64(s.b) {
						delete(s.ips, ip)
					}
				}
				if len(s.ips) > 50000 {
					minAge := int64(30)
					type kv struct {
						ip         string
						lastAccess int64
					}
					entries := make([]kv, 0, len(s.ips))
					for ip, entry := range s.ips {
						if now-entry.lastAccess > minAge {
							entries = append(entries, kv{ip: ip, lastAccess: entry.lastAccess})
						}
					}
					sort.Slice(entries, func(i, j int) bool {
						return entries[i].lastAccess < entries[j].lastAccess
					})
					target := len(entries) / 2
					if target > 0 {
						for k := 0; k < target; k++ {
							delete(s.ips, entries[k].ip)
						}
					}
				}
				s.mu.Unlock()
			}
		}
	}
}

func (i *IPRateLimiter) Stop() {
	close(i.stopChan)
}

// IsDeprecated 标记该限流器已废弃
func (i *IPRateLimiter) IsDeprecated() bool {
	return true
}
