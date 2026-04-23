package stats

import (
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
)

var (
	startTime  time.Time
	startOnce  sync.Once
	lastCPUUsage     float64
	lastCPUUpdate    time.Time
	cpuUsageMu       sync.RWMutex
)

// getStartTime 获取服务启动时间（只初始化一次）
func getStartTime() time.Time {
	startOnce.Do(func() {
		startTime = time.Now()
	})
	return startTime
}

// SystemStats 系统性能统计
type SystemStats struct {
	CPUUsage    float64 `json:"cpu_usage"`    // CPU 使用率（百分比）
	MemUsed     uint64  `json:"mem_used"`     // 已使用内存（字节）
	MemTotal    uint64  `json:"mem_total"`    // 总内存（字节）
	MemPercent  float64 `json:"mem_percent"`  // 内存使用率（百分比）
	Goroutines  int     `json:"goroutines"`   // goroutine 数量
	GoVersion   string  `json:"go_version"`   // Go 版本
	Uptime      float64 `json:"uptime"`       // 运行时长（秒）
	DiskUsed    uint64  `json:"disk_used"`    // 已使用磁盘（字节）
	DiskTotal   uint64  `json:"disk_total"`   // 总磁盘（字节）
	DiskPercent float64 `json:"disk_percent"` // 磁盘使用率（百分比）
}

// GetSystemStats 获取系统性能统计
func GetSystemStats() SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 计算内存使用率
	memPercent := 0.0
	if m.Sys > 0 {
		memPercent = float64(m.Alloc) / float64(m.Sys) * 100
	}

	// 获取 CPU 使用率（使用缓存，避免阻塞）
	cpuUsage := getCachedCPUUsage()

	// 获取磁盘使用率
	diskUsed, diskTotal, diskPercent := getDiskUsage()

	return SystemStats{
		CPUUsage:    cpuUsage,
		MemUsed:     m.Alloc,
		MemTotal:    m.Sys,
		MemPercent:  memPercent,
		Goroutines:  runtime.NumGoroutine(),
		GoVersion:   runtime.Version(),
		Uptime:      time.Since(getStartTime()).Seconds(),
		DiskUsed:    diskUsed,
		DiskTotal:   diskTotal,
		DiskPercent: diskPercent,
	}
}

// getDiskUsage 获取磁盘使用率
func getDiskUsage() (uint64, uint64, float64) {
	// 获取根目录磁盘使用情况
	usage, err := disk.Usage("/")
	if err != nil {
		// Windows 系统尝试获取 C: 盘
		usage, err = disk.Usage("C:")
		if err != nil {
			return 0, 0, 0
		}
	}

	diskPercent := 0.0
	if usage.Total > 0 {
		diskPercent = float64(usage.Used) / float64(usage.Total) * 100
	}

	return usage.Used, usage.Total, diskPercent
}

// getCachedCPUUsage 获取缓存的 CPU 使用率，避免每次调用都阻塞 1 秒
func getCachedCPUUsage() float64 {
	cpuUsageMu.RLock()
	// 如果距离上次更新不到 3 秒，使用缓存值
	if time.Since(lastCPUUpdate) < 3*time.Second {
		defer cpuUsageMu.RUnlock()
		return lastCPUUsage
	}
	cpuUsageMu.RUnlock()

	// 异步更新 CPU 使用率
	go updateCPUUsage()

	// 返回当前缓存值
	cpuUsageMu.RLock()
	defer cpuUsageMu.RUnlock()
	return lastCPUUsage
}

// updateCPUUsage 更新 CPU 使用率（在后台运行）
func updateCPUUsage() {
	if cpuPercents, err := cpu.Percent(time.Second, false); err == nil && len(cpuPercents) > 0 {
		cpuUsageMu.Lock()
		lastCPUUsage = cpuPercents[0]
		lastCPUUpdate = time.Now()
		cpuUsageMu.Unlock()
	}
}
