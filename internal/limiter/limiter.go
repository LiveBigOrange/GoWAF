package limiter

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	ips      map[string]*rate.Limiter
	mu       sync.RWMutex
	r        rate.Limit
	b        int
	enabled  bool
	stopChan chan struct{} // 用于停止Cleanup goroutine
}

func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips:      make(map[string]*rate.Limiter),
		r:        r,
		b:        b,
		enabled:  true,
		stopChan: make(chan struct{}),
	}
}

// Allow 检查 IP 是否允许通过
func (i *IPRateLimiter) Allow(ip string) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	
	// 如果限流未启用，直接返回true
	if !i.enabled {
		return true
	}
	
	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}
	return limiter.Allow()
}

// UpdateConfig 动态更新限流参数，清空现有令牌桶
func (i *IPRateLimiter) UpdateConfig(r rate.Limit, b int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.r = r
	i.b = b
	i.ips = make(map[string]*rate.Limiter)
}

// SetEnabled 设置启用状态
func (i *IPRateLimiter) SetEnabled(enabled bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.enabled = enabled
}

// GetEnabled 获取启用状态
func (i *IPRateLimiter) GetEnabled() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.enabled
}

// GetConfig 返回当前配置
func (i *IPRateLimiter) GetConfig() (rate.Limit, int) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.r, i.b
}

// Cleanup 定期清理长时间未使用的 IP 记录
func (i *IPRateLimiter) Cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-i.stopChan:
				ticker.Stop()
				return
			case <-ticker.C:
				i.mu.Lock()
				for ip, limiter := range i.ips {
					if limiter.Tokens() >= float64(i.b) {
						delete(i.ips, ip)
					}
				}
				i.mu.Unlock()
			}
		}
	}()
}

// Stop 停止限流器的Cleanup goroutine
func (i *IPRateLimiter) Stop() {
	close(i.stopChan)
}
