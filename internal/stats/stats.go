package stats

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

var (
	totalRequests   uint64
	blockedRequests uint64
)

var (
	lastSecondRequests  uint64
	lastSecondTimestamp int64
)

// TOP 统计相关
var (
	topMutex      sync.RWMutex
	blockedIPs    = make(map[string]int)
	blockedPaths  = make(map[string]int)
	ruleHits      = make(map[string]int)
)

func IncTotal() {
	atomic.AddUint64(&totalRequests, 1)
	now := time.Now().Unix()
	if atomic.LoadInt64(&lastSecondTimestamp) == now {
		atomic.AddUint64(&lastSecondRequests, 1)
	} else {
		atomic.StoreInt64(&lastSecondTimestamp, now)
		atomic.StoreUint64(&lastSecondRequests, 1)
	}
}

func IncBlocked() {
	atomic.AddUint64(&blockedRequests, 1)
}

// IncBlockedIP 增加被拦截 IP 的计数
func IncBlockedIP(ip string) {
	topMutex.Lock()
	blockedIPs[ip]++
	topMutex.Unlock()
}

// IncBlockedPath 增加被攻击路径的计数
func IncBlockedPath(path string) {
	topMutex.Lock()
	blockedPaths[path]++
	topMutex.Unlock()
}

// IncRuleHit 增加规则命中计数
func IncRuleHit(rule string) {
	topMutex.Lock()
	ruleHits[rule]++
	topMutex.Unlock()
}

func GetTotal() uint64 {
	return atomic.LoadUint64(&totalRequests)
}

func GetBlocked() uint64 {
	return atomic.LoadUint64(&blockedRequests)
}

func GetQPS() float64 {
	now := time.Now().Unix()
	if atomic.LoadInt64(&lastSecondTimestamp) == now {
		return float64(atomic.LoadUint64(&lastSecondRequests))
	}
	return 0
}

// TopItem TOP 统计项
type TopItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// GetTopBlockedIPs 获取被拦截最多的 IP（TOP N）
func GetTopBlockedIPs(n int) []TopItem {
	topMutex.RLock()
	defer topMutex.RUnlock()

	items := make([]TopItem, 0, len(blockedIPs))
	for ip, count := range blockedIPs {
		items = append(items, TopItem{Name: ip, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// GetTopBlockedPaths 获取被攻击最多的路径（TOP N）
func GetTopBlockedPaths(n int) []TopItem {
	topMutex.RLock()
	defer topMutex.RUnlock()

	items := make([]TopItem, 0, len(blockedPaths))
	for path, count := range blockedPaths {
		items = append(items, TopItem{Name: path, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// GetRuleHits 获取各规则命中分布
func GetRuleHits() []TopItem {
	topMutex.RLock()
	defer topMutex.RUnlock()

	items := make([]TopItem, 0, len(ruleHits))
	for rule, count := range ruleHits {
		items = append(items, TopItem{Name: rule, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	return items
}
