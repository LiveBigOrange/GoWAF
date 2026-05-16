package stats

import (
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
)

var (
	startTime     time.Time
	startOnce     sync.Once
	lastCPUUsage  float64
	lastCPUUpdate time.Time
	cpuUsageMu    sync.RWMutex
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
	// ===== 基础系统指标 =====
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

	// ===== Go 运行时指标 =====
	NumGC        uint32  `json:"num_gc"`         // GC 次数
	GCPauseTotal uint64  `json:"gc_pause_total"` // GC 总暂停时间（纳秒）
	GCPauseAvg   float64 `json:"gc_pause_avg"`   // GC 平均暂停时间（毫秒）
	HeapAlloc    uint64  `json:"heap_alloc"`     // 堆分配字节数
	HeapSys      uint64  `json:"heap_sys"`       // 堆系统内存
	HeapObjects  uint64  `json:"heap_objects"`   // 堆对象数量
	StackInuse   uint64  `json:"stack_inuse"`    // 栈使用内存
	StackSys     uint64  `json:"stack_sys"`      // 栈系统内存

	// ===== 系统资源指标 =====
	NumThread int `json:"num_thread"` // OS 线程数
	NumFD     int `json:"num_fd"`     // 文件描述符数量（仅Unix）
}

// GetSystemStats 获取系统性能统计
func GetSystemStats() SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// 计算内存使用率（系统级）
	memUsed, memTotal, memPercent := getMemUsage()

	// 获取 CPU 使用率（使用缓存，避免阻塞）
	cpuUsage := getCachedCPUUsage()

	// 获取磁盘使用率
	diskUsed, diskTotal, diskPercent := getDiskUsage()

	// 计算 GC 平均暂停时间
	gcPauseAvg := 0.0
	if m.NumGC > 0 && m.PauseTotalNs > 0 {
		gcPauseAvg = float64(m.PauseTotalNs) / float64(m.NumGC) / 1e6 // 转换为毫秒
	}

	return SystemStats{
		// 基础系统指标
		CPUUsage:    cpuUsage,
		MemUsed:     memUsed,
		MemTotal:    memTotal,
		MemPercent:  memPercent,
		Goroutines:  runtime.NumGoroutine(),
		GoVersion:   runtime.Version(),
		Uptime:      time.Since(getStartTime()).Seconds(),
		DiskUsed:    diskUsed,
		DiskTotal:   diskTotal,
		DiskPercent: diskPercent,

		// Go 运行时指标
		NumGC:        m.NumGC,
		GCPauseTotal: m.PauseTotalNs,
		GCPauseAvg:   gcPauseAvg,
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapObjects:  m.HeapObjects,
		StackInuse:   m.StackInuse,
		StackSys:     m.StackSys,

		// 系统资源指标
		NumThread: runtime.GOMAXPROCS(0),
		NumFD:     getFDCount(),
	}
}

// getMemUsage 获取系统级内存使用情况
func getMemUsage() (uint64, uint64, float64) {
	v, err := mem.VirtualMemory()
	if err != nil {
		return 0, 0, 0
	}
	return v.Used, v.Total, v.UsedPercent
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
