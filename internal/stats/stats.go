package stats

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gowaf-demo/internal/timeutil"
)

var (
	totalRequests   uint64
	blockedRequests uint64
	errorRequests   uint64 // 错误请求数（4xx+5xx）
	totalLatency    uint64 // 总延迟（毫秒）
	activeConns     uint64 // 活跃连接数
	networkBytesIn  uint64 // 网络入站字节数
	networkBytesOut uint64 // 网络出站字节数
)

var (
	lastSecondRequests  uint64
	lastSecondTimestamp int64
)

// TOP 统计相关
var (
	topMutex         sync.RWMutex
	blockedIPs       = make(map[string]int)
	blockedPaths     = make(map[string]int)
	ruleHits         = make(map[string]int)
	blockedIPsTime   = make(map[string]time.Time)   // IP最后拦截时间
	blockedPathsTime = make(map[string]time.Time)   // 路径最后攻击时间
	ruleHitsTime     = make(map[string]time.Time)   // 规则最后命中时间
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
	blockedIPsTime[ip] = time.Now()
	topMutex.Unlock()
}

// IncBlockedPath 增加被攻击路径的计数
func IncBlockedPath(path string) {
	topMutex.Lock()
	blockedPaths[path]++
	blockedPathsTime[path] = time.Now()
	topMutex.Unlock()
}

// IncRuleHit 增加规则命中计数
func IncRuleHit(rule string) {
	topMutex.Lock()
	ruleHits[rule]++
	ruleHitsTime[rule] = time.Now()
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

// IncError 增加错误请求计数
func IncError() {
	atomic.AddUint64(&errorRequests, 1)
}

// AddLatency 增加延迟统计
func AddLatency(latencyMs uint64) {
	atomic.AddUint64(&totalLatency, latencyMs)
}

// IncActiveConn 增加活跃连接
func IncActiveConn() {
	atomic.AddUint64(&activeConns, 1)
}

// DecActiveConn 减少活跃连接
func DecActiveConn() {
	if atomic.LoadUint64(&activeConns) > 0 {
		atomic.AddUint64(&activeConns, ^uint64(0))
	}
}

// GetErrorRate 获取错误率
func GetErrorRate() float64 {
	total := atomic.LoadUint64(&totalRequests)
	if total == 0 {
		return 0
	}
	errors := atomic.LoadUint64(&errorRequests)
	return float64(errors) / float64(total) * 100
}

// GetBlockRate 获取拦截率
func GetBlockRate() float64 {
	total := atomic.LoadUint64(&totalRequests)
	if total == 0 {
		return 0
	}
	blocked := atomic.LoadUint64(&blockedRequests)
	return float64(blocked) / float64(total) * 100
}

// GetAvgLatency 获取平均延迟
func GetAvgLatency() float64 {
	total := atomic.LoadUint64(&totalRequests)
	if total == 0 {
		return 0
	}
	latency := atomic.LoadUint64(&totalLatency)
	return float64(latency) / float64(total)
}

// GetActiveConns 获取活跃连接数
func GetActiveConns() uint64 {
	return atomic.LoadUint64(&activeConns)
}

// AddNetworkBytes 增加网络流量统计
func AddNetworkBytes(bytesIn, bytesOut uint64) {
	atomic.AddUint64(&networkBytesIn, bytesIn)
	atomic.AddUint64(&networkBytesOut, bytesOut)
}

// GetNetworkStats 获取网络统计
func GetNetworkStats() (bytesIn, bytesOut uint64) {
	return atomic.LoadUint64(&networkBytesIn), atomic.LoadUint64(&networkBytesOut)
}

// BusinessStats 业务统计
type BusinessStats struct {
	ErrorRate    float64 `json:"error_rate"`    // 错误率
	BlockRate    float64 `json:"block_rate"`    // 拦截率
	AvgLatency   float64 `json:"avg_latency"`   // 平均延迟
	ActiveConns  uint64  `json:"active_conns"`  // 活跃连接
	NetworkIn    uint64  `json:"network_in"`    // 网络入站字节
	NetworkOut   uint64  `json:"network_out"`   // 网络出站字节
}

// GetBusinessStats 获取业务统计
func GetBusinessStats() BusinessStats {
	bytesIn, bytesOut := GetNetworkStats()
	return BusinessStats{
		ErrorRate:   GetErrorRate(),
		BlockRate:   GetBlockRate(),
		AvgLatency:  GetAvgLatency(),
		ActiveConns: GetActiveConns(),
		NetworkIn:   bytesIn,
		NetworkOut:  bytesOut,
	}
}

// TopItem TOP 统计项
type TopItem struct {
	Name          string            `json:"name"`
	Count         int               `json:"count"`
	LastSeen      timeutil.LocalTime `json:"last_seen,omitempty"`
	RuleTypes     map[string]int    `json:"rule_types,omitempty"`
	SourceIPCount int               `json:"source_ip_count,omitempty"`
	Methods       map[string]int    `json:"methods,omitempty"`
	RiskLevel     string            `json:"risk_level,omitempty"`
	RuleType      string            `json:"rule_type,omitempty"`
	GeoCountry    string            `json:"geo_country,omitempty"`
	GeoFlag       string            `json:"geo_flag,omitempty"`
}


// GetTopBlockedIPs 获取被拦截最多的 IP（TOP N）
func GetTopBlockedIPs(n int) []TopItem {
	topMutex.RLock()
	defer topMutex.RUnlock()

	items := make([]TopItem, 0, len(blockedIPs))
	for ip, count := range blockedIPs {
		items = append(items, TopItem{
			Name:     ip,
			Count:    count,
			LastSeen: timeutil.FromTime(blockedIPsTime[ip]),
		})
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
		items = append(items, TopItem{
			Name:     path,
			Count:    count,
			LastSeen: timeutil.FromTime(blockedPathsTime[path]),
		})
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
		items = append(items, TopItem{
			Name:     rule,
			Count:    count,
			LastSeen: timeutil.FromTime(ruleHitsTime[rule]),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	return items
}
