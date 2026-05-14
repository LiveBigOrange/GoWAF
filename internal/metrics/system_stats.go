package metrics

import (
	"database/sql"
	"time"

	"gowaf/internal/logger"
	"gowaf/internal/stats"
	"gowaf/internal/timeutil"
)

// SystemStatsRecord 持久化的系统指标记录
type SystemStatsRecord struct {
	Time        timeutil.LocalTime `json:"time"`
	CPUUsage    float64            `json:"cpu_usage"`
	MemPercent  float64            `json:"mem_percent"`
	MemUsed     uint64             `json:"mem_used"`
	MemTotal    uint64             `json:"mem_total"`
	DiskPercent float64            `json:"disk_percent"`
	DiskUsed    uint64             `json:"disk_used"`
	DiskTotal   uint64             `json:"disk_total"`
	Goroutines  int                `json:"goroutines"`
	NumGC       uint32             `json:"num_gc"`
	GCPauseAvg  float64            `json:"gc_pause_avg"`
	HeapAlloc   uint64             `json:"heap_alloc"`
	HeapSys     uint64             `json:"heap_sys"`
	HeapObjects uint64             `json:"heap_objects"`
	StackInuse  uint64             `json:"stack_inuse"`
	NumThread   int                `json:"num_thread"`
	NumFD       int                `json:"num_fd"`
}

// CollectAndSaveSystemStats 采集系统指标并写入数据库
func (m *Manager) CollectAndSaveSystemStats() {
	s := stats.GetSystemStats()

	now := time.Now().UTC().Truncate(30 * time.Second).Format("2006-01-02 15:04:05.999999")

	_, err := m.db.Exec(`
		INSERT INTO system_stats (time, cpu_usage, mem_percent, mem_used, mem_total,
			disk_percent, disk_used, disk_total, goroutines, num_gc, gc_pause_avg,
			heap_alloc, heap_sys, heap_objects, stack_inuse, num_thread, num_fd)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(time) DO UPDATE SET
			cpu_usage = excluded.cpu_usage, mem_percent = excluded.mem_percent,
			mem_used = excluded.mem_used, mem_total = excluded.mem_total,
			disk_percent = excluded.disk_percent, disk_used = excluded.disk_used,
			disk_total = excluded.disk_total, goroutines = excluded.goroutines,
			num_gc = excluded.num_gc, gc_pause_avg = excluded.gc_pause_avg,
			heap_alloc = excluded.heap_alloc, heap_sys = excluded.heap_sys,
			heap_objects = excluded.heap_objects, stack_inuse = excluded.stack_inuse,
			num_thread = excluded.num_thread, num_fd = excluded.num_fd
	`, now, s.CPUUsage, s.MemPercent, s.MemUsed, s.MemTotal,
		s.DiskPercent, s.DiskUsed, s.DiskTotal, s.Goroutines, s.NumGC, s.GCPauseAvg,
		s.HeapAlloc, s.HeapSys, s.HeapObjects, s.StackInuse, s.NumThread, s.NumFD)
	if err != nil {
		logger.Warn("CollectAndSaveSystemStats: %v", err)
	}
}

// GetSystemStatsTrend 查询系统指标历史趋势
func (m *Manager) GetSystemStatsTrend(start, end time.Time) ([]SystemStatsRecord, error) {
	rows, err := m.db.Query(`
		SELECT time, cpu_usage, mem_percent, mem_used, mem_total,
			disk_percent, disk_used, disk_total, goroutines, num_gc, gc_pause_avg,
			heap_alloc, heap_sys, heap_objects, stack_inuse, num_thread, num_fd
		FROM system_stats WHERE time >= ? AND time <= ? ORDER BY time
	`, start.Format("2006-01-02 15:04:05.999999"), end.Format("2006-01-02 15:04:05.999999"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []SystemStatsRecord
	for rows.Next() {
		var r SystemStatsRecord
		var t string
		if err := rows.Scan(&t, &r.CPUUsage, &r.MemPercent, &r.MemUsed, &r.MemTotal,
			&r.DiskPercent, &r.DiskUsed, &r.DiskTotal, &r.Goroutines, &r.NumGC, &r.GCPauseAvg,
			&r.HeapAlloc, &r.HeapSys, &r.HeapObjects, &r.StackInuse, &r.NumThread, &r.NumFD); err != nil {
			return nil, err
		}
		r.Time = timeutil.LocalTime(parseTime(t))
		records = append(records, r)
	}
	return records, rows.Err()
}

// CleanupSystemStats 清理过期的系统指标数据
func (m *Manager) CleanupSystemStats(retentionDays int) {
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format("2006-01-02")
	for {
		result, err := m.db.Exec(`DELETE FROM system_stats WHERE time < ? AND id IN (SELECT id FROM system_stats WHERE time < ? LIMIT 10000)`, cutoff, cutoff)
		if err != nil {
			logger.Warn("CleanupSystemStats: %v", err)
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func parseTime(s string) time.Time {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999",
		"2006-01-02 15:04:05",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// GetSystemStatsLatest 获取最近一条系统指标记录
func (m *Manager) GetSystemStatsLatest() (*SystemStatsRecord, error) {
	var r SystemStatsRecord
	var t string
	err := m.db.QueryRow(`
		SELECT time, cpu_usage, mem_percent, mem_used, mem_total,
			disk_percent, disk_used, disk_total, goroutines, num_gc, gc_pause_avg,
			heap_alloc, heap_sys, heap_objects, stack_inuse, num_thread, num_fd
		FROM system_stats ORDER BY time DESC LIMIT 1
	`).Scan(&t, &r.CPUUsage, &r.MemPercent, &r.MemUsed, &r.MemTotal,
		&r.DiskPercent, &r.DiskUsed, &r.DiskTotal, &r.Goroutines, &r.NumGC, &r.GCPauseAvg,
		&r.HeapAlloc, &r.HeapSys, &r.HeapObjects, &r.StackInuse, &r.NumThread, &r.NumFD)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Time = timeutil.LocalTime(parseTime(t))
	return &r, nil
}
