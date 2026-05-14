package metrics

import (
	"time"

	"gowaf/internal/timeutil"
)

// GetTotalStats 获取总请求数和拦截数
func (m *Manager) GetTotalStats(startTime, endTime time.Time) (total int64, blocked int64, err error) {
	startDate := startTime.Format("2006-01-02")
	endDate := endTime.Format("2006-01-02")

	err = m.db.QueryRow(`
		SELECT COALESCE(SUM(total_requests), 0), COALESCE(SUM(blocked_requests), 0)
		FROM daily_stats WHERE date >= ? AND date <= ?
	`, startDate, endDate).Scan(&total, &blocked)
	if err != nil {
		return 0, 0, err
	}

	return total, blocked, nil
}

// GetHourlyStats 获取小时统计
func (m *Manager) GetHourlyStats(startTime, endTime time.Time) ([]HourlyStats, error) {
	rows, err := m.db.Query(`
		SELECT 
			strftime('%Y-%m-%d %H:00:00', time_minute) as time_hour,
			COALESCE(SUM(total_requests), 0),
			COALESCE(SUM(blocked_requests), 0),
			CASE WHEN SUM(total_requests + blocked_requests) > 0
				THEN SUM(avg_qps * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
				ELSE 0 END,
			CASE WHEN SUM(total_requests + blocked_requests) > 0
				THEN SUM(avg_latency_ms * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
				ELSE 0 END,
			COALESCE(SUM(inbound_bytes), 0),
			COALESCE(SUM(outbound_bytes), 0),
			CASE WHEN SUM(total_requests + blocked_requests) > 0
				THEN SUM(error_rate * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
				ELSE 0 END,
			CASE WHEN SUM(total_requests + blocked_requests) > 0
				THEN SUM(CAST(active_conns AS FLOAT) * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
				ELSE 0 END
		FROM minute_stats
		WHERE time_minute >= ? AND time_minute <= ?
		GROUP BY time_hour
		ORDER BY time_hour ASC
	`, startTime.Format("2006-01-02 15:04:05.999999"), endTime.Format("2006-01-02 15:04:05.999999"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []HourlyStats
	for rows.Next() {
		var s HourlyStats
		var timeHourStr string
		if err := rows.Scan(&timeHourStr, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes,
			&s.ErrorRate, &s.ActiveConns); err == nil {
			pt, _ := timeutil.ParseTime(timeHourStr)
			s.TimeHour = timeutil.FromTime(pt)
			stats = append(stats, s)
		}
	}
	if stats == nil {
		stats = make([]HourlyStats, 0)
	}
	return stats, nil
}

// RecordMinuteStats 记录分钟级统计（实时监控，原子计数，定时刷盘）
func (m *Manager) RecordMinuteStats(totalReqs, blockedReqs int64, latencyMs float64, inboundBytes, outboundBytes int64, errorRate float64, activeConns int64) error {
	m.pendingMinuteTotal.Add(totalReqs)
	m.pendingMinuteBlocked.Add(blockedReqs)
	m.pendingMinuteLatency.Add(int64(latencyMs * 1000))
	m.pendingMinuteInbound.Add(inboundBytes)
	m.pendingMinuteOutbound.Add(outboundBytes)
	m.pendingMinuteErrorRate.Add(int64(errorRate * 100))
	m.pendingMinuteConns.Add(activeConns)
	return nil
}

// GetMinuteStats 获取分钟级统计（实时监控）
func (m *Manager) GetMinuteStats(startTime, endTime time.Time) ([]MinuteStats, error) {
	rows, err := m.db.Query(`
		SELECT time_minute, total_requests, blocked_requests, avg_qps, avg_latency_ms, 
		       COALESCE(inbound_bytes, 0), COALESCE(outbound_bytes, 0),
		       COALESCE(error_rate, 0), COALESCE(active_conns, 0)
		FROM minute_stats
		WHERE time_minute >= ? AND time_minute <= ?
		ORDER BY time_minute ASC
	`, startTime.Format("2006-01-02 15:04:05.999999"), endTime.Format("2006-01-02 15:04:05.999999"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []MinuteStats
	for rows.Next() {
		var s MinuteStats
		var timeMinuteStr string
		if err := rows.Scan(&timeMinuteStr, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes,
			&s.ErrorRate, &s.ActiveConns); err == nil {
			pt, _ := timeutil.ParseTime(timeMinuteStr)
			s.TimeMinute = timeutil.FromTime(pt)
			stats = append(stats, s)
		}
	}
	if stats == nil {
		stats = make([]MinuteStats, 0)
	}
	return stats, nil
}

// CleanupMinuteStats 清理过期的分钟级数据（保留7天）
func (m *Manager) CleanupMinuteStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -7).Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`DELETE FROM minute_stats WHERE time_minute < ?`, cutoff)
	return err
}

// GetHourlyStatsFromTable 从 hourly_stats 持久化表获取小时统计（支持90天历史）
func (m *Manager) GetHourlyStatsFromTable(startTime, endTime time.Time) ([]HourlyStats, error) {
	rows, err := m.db.Query(`
		SELECT time_hour, total_requests, blocked_requests, avg_qps, avg_latency_ms,
		       COALESCE(inbound_bytes, 0), COALESCE(outbound_bytes, 0),
		       COALESCE(error_rate, 0), COALESCE(active_conns, 0)
		FROM hourly_stats
		WHERE time_hour >= ? AND time_hour <= ?
		ORDER BY time_hour ASC
	`, startTime.Format("2006-01-02 15:04:05.999999"), endTime.Format("2006-01-02 15:04:05.999999"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []HourlyStats
	for rows.Next() {
		var s HourlyStats
		var timeHourStr string
		if err := rows.Scan(&timeHourStr, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes,
			&s.ErrorRate, &s.ActiveConns); err == nil {
			pt, _ := timeutil.ParseTime(timeHourStr)
			s.TimeHour = timeutil.FromTime(pt)
			stats = append(stats, s)
		}
	}
	if stats == nil {
		stats = make([]HourlyStats, 0)
	}
	return stats, nil
}

// CleanupHourlyStats 清理过期的小时级数据（保留90天）
func (m *Manager) CleanupHourlyStats() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -90).Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`DELETE FROM hourly_stats WHERE time_hour < ?`, cutoff)
	return err
}

// GetDailyStatsFromTable 获取日级统计（支持长期历史）
func (m *Manager) GetDailyStatsFromTable(startTime, endTime time.Time) ([]DailyStats, error) {
	rows, err := m.db.Query(`
		SELECT date, total_requests, blocked_requests,
		       COALESCE(avg_qps, 0), COALESCE(avg_latency_ms, 0),
		       COALESCE(inbound_bytes, 0), COALESCE(outbound_bytes, 0)
		FROM daily_stats
		WHERE date >= ? AND date <= ?
		ORDER BY date ASC
	`, startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []DailyStats
	for rows.Next() {
		var s DailyStats
		var dateStr string
		if err := rows.Scan(&dateStr, &s.TotalRequests, &s.BlockedRequests,
			&s.AvgQPS, &s.AvgLatencyMs, &s.InboundBytes, &s.OutboundBytes); err == nil {
			pt, _ := timeutil.ParseTime(dateStr)
			s.Date = timeutil.FromTime(pt)
			stats = append(stats, s)
		}
	}
	if stats == nil {
		stats = make([]DailyStats, 0)
	}
	return stats, nil
}
