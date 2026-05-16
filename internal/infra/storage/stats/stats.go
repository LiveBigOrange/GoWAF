package stats

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gowaf/internal/pkg/xutil"
)

var (
	totalRequests   uint64
	blockedRequests uint64
	errorRequests   uint64 // 错误请求数（4xx+5xx）
	networkBytesIn  uint64 // 网络入站字节数
	networkBytesOut uint64 // 网络出站字节数
)

var (
	activeConns uint64 // 活跃连接数
)

var (
	lastSecondRequests  uint64
	lastSecondTimestamp int64
)

var (
	latencyWindow     [60]uint64
	latencyWindowIdx  uint64
	latencyWindowLock sync.Mutex
)

// TOP 统计相关
var (
	topMutex            sync.RWMutex
	blockedIPs          = make(map[string]int)
	blockedPaths        = make(map[string]int)
	ruleHits            = make(map[string]int)
	blockedIPsTime      = make(map[string]time.Time)
	blockedPathsTime    = make(map[string]time.Time)
	ruleHitsTime        = make(map[string]time.Time)
	blockedIPsRules     = make(map[string]map[string]int)
	blockedPathsMethods = make(map[string]map[string]int)
	blockedPathsIPs     = make(map[string]map[string]int)
)

const maxTopEntries = 10000

// CleanupTopStats 清理 TOP 统计 map 中过旧的条目，防止内存无限增长
func CleanupTopStats() {
	topMutex.Lock()
	defer topMutex.Unlock()

	cleanupMap := func(m map[string]int, timeMap map[string]time.Time, extraMaps ...map[string]map[string]int) {
		if len(m) <= maxTopEntries {
			return
		}
		type kv struct {
			key string
			t   time.Time
		}
		entries := make([]kv, 0, len(m))
		for k := range m {
			entries = append(entries, kv{k, timeMap[k]})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].t.After(entries[j].t)
		})
		keep := maxTopEntries / 2
		for i := keep; i < len(entries); i++ {
			key := entries[i].key
			delete(m, key)
			delete(timeMap, key)
			for _, em := range extraMaps {
				delete(em, key)
			}
		}
	}

	cleanupMap(blockedIPs, blockedIPsTime, blockedIPsRules)
	cleanupMap(blockedPaths, blockedPathsTime, blockedPathsMethods, blockedPathsIPs)
	cleanupMap(ruleHits, ruleHitsTime)
}

func IncTotal() {
	atomic.AddUint64(&totalRequests, 1)
	now := time.Now().Unix()
	for {
		old := atomic.LoadInt64(&lastSecondTimestamp)
		if old == now {
			atomic.AddUint64(&lastSecondRequests, 1)
			break
		}
		if atomic.CompareAndSwapInt64(&lastSecondTimestamp, old, now) {
			atomic.StoreUint64(&lastSecondRequests, 1)
			break
		}
		// CAS failed: another goroutine updated timestamp, retry
	}
}

func IncBlocked() {
	atomic.AddUint64(&blockedRequests, 1)
}

// IncBlockedIP 增加被拦截 IP 的计数
func IncBlockedIP(ip string, rule string) {
	topMutex.Lock()
	blockedIPs[ip]++
	blockedIPsTime[ip] = time.Now().UTC()
	if rule != "" {
		if blockedIPsRules[ip] == nil {
			blockedIPsRules[ip] = make(map[string]int)
		}
		blockedIPsRules[ip][rule]++
	}
	topMutex.Unlock()
}

// IncBlockedPath 增加被攻击路径的计数
func IncBlockedPath(path string, method string, clientIP string) {
	topMutex.Lock()
	blockedPaths[path]++
	blockedPathsTime[path] = time.Now().UTC()
	if method != "" {
		if blockedPathsMethods[path] == nil {
			blockedPathsMethods[path] = make(map[string]int)
		}
		blockedPathsMethods[path][method]++
	}
	if clientIP != "" {
		if blockedPathsIPs[path] == nil {
			blockedPathsIPs[path] = make(map[string]int)
		}
		blockedPathsIPs[path][clientIP]++
	}
	topMutex.Unlock()
}

// IncRuleHit 增加规则命中计数
func IncRuleHit(rule string) {
	topMutex.Lock()
	ruleHits[rule]++
	ruleHitsTime[rule] = time.Now().UTC()
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

func AddLatency(latencyMs uint64) {
	latencyWindowLock.Lock()
	idx := latencyWindowIdx % 60
	latencyWindow[idx] = latencyMs
	latencyWindowIdx++
	latencyWindowLock.Unlock()
}

func IncActiveConn() {
	atomic.AddUint64(&activeConns, 1)
}

func DecActiveConn() {
	if atomic.LoadUint64(&activeConns) > 0 {
		atomic.AddUint64(&activeConns, ^uint64(0))
	}
}

func GetErrorRate() float64 {
	total := atomic.LoadUint64(&totalRequests)
	blocked := atomic.LoadUint64(&blockedRequests)
	all := total + blocked
	if all == 0 {
		return 0
	}
	errors := atomic.LoadUint64(&errorRequests)
	return float64(errors) / float64(all) * 100
}

func GetBlockRate() float64 {
	total := atomic.LoadUint64(&totalRequests)
	blocked := atomic.LoadUint64(&blockedRequests)
	all := total + blocked
	if all == 0 {
		return 0
	}
	return float64(blocked) / float64(all) * 100
}

func GetAvgLatency() float64 {
	latencyWindowLock.Lock()
	defer latencyWindowLock.Unlock()
	count := latencyWindowIdx
	if count == 0 {
		return 0
	}
	start := uint64(0)
	if count > 60 {
		start = count - 60
	}
	var total uint64
	samples := count - start
	for i := start; i < count; i++ {
		total += latencyWindow[i%60]
	}
	if samples == 0 {
		return 0
	}
	return float64(total) / float64(samples)
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
	ErrorRate   float64 `json:"error_rate"`   // 错误率
	BlockRate   float64 `json:"block_rate"`   // 拦截率
	AvgLatency  float64 `json:"avg_latency"`  // 平均延迟
	ActiveConns uint64  `json:"active_conns"` // 活跃连接
	NetworkIn   uint64  `json:"network_in"`   // 网络入站字节
	NetworkOut  uint64  `json:"network_out"`  // 网络出站字节
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
	Name          string             `json:"name"`
	Count         int                `json:"count"`
	LastSeen      xutil.LocalTime `json:"last_seen,omitempty"`
	RuleTypes     map[string]int     `json:"rule_types,omitempty"`
	SourceIPCount int                `json:"source_ip_count,omitempty"`
	Methods       map[string]int     `json:"methods,omitempty"`
	RiskLevel     string             `json:"risk_level,omitempty"`
	RuleType      string             `json:"rule_type,omitempty"`
	GeoCountry    string             `json:"geo_country,omitempty"`
	GeoFlag       string             `json:"geo_flag,omitempty"`
}

// GetTopBlockedIPs 获取被拦截最多的 IP（TOP N）
func GetTopBlockedIPs(n int) []TopItem {
	topMutex.RLock()
	defer topMutex.RUnlock()

	items := make([]TopItem, 0, len(blockedIPs))
	for ip, count := range blockedIPs {
		item := TopItem{
			Name:      ip,
			Count:     count,
			LastSeen:  xutil.FromTime(blockedIPsTime[ip]),
			RuleTypes: blockedIPsRules[ip],
		}
		if len(item.RuleTypes) > 0 {
			maxRule, maxCnt := "", 0
			for r, c := range item.RuleTypes {
				if c > maxCnt {
					maxRule = r
					maxCnt = c
				}
			}
			item.RuleType = maxRule
		}
		items = append(items, item)
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
		item := TopItem{
			Name:          path,
			Count:         count,
			LastSeen:      xutil.FromTime(blockedPathsTime[path]),
			Methods:       blockedPathsMethods[path],
			SourceIPCount: len(blockedPathsIPs[path]),
		}
		items = append(items, item)
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
			LastSeen: xutil.FromTime(ruleHitsTime[rule]),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	return items
}
