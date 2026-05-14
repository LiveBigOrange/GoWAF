package metrics

import (
	"time"

	"gowaf/internal/logger"
)

// IncTotalRequest 增加总请求计数（内存atomic，定时刷盘）
func (m *Manager) IncTotalRequest() error {
	m.pendingTotal.Add(1)
	return nil
}

// IncBlockedRequest 增加拦截计数（内存atomic，定时刷盘）
func (m *Manager) IncBlockedRequest() error {
	m.pendingBlocked.Add(1)
	return nil
}

// StartFlushLoop 启动定时刷盘协程
func (m *Manager) StartFlushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	hourlyTicker := time.NewTicker(time.Hour)
	systemStatsTicker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-m.flushStop:
				ticker.Stop()
				hourlyTicker.Stop()
				systemStatsTicker.Stop()
				m.flushCounters()
				m.flushMinuteStats()
				return
			case <-ticker.C:
				m.flushCounters()
				m.flushMinuteStats()
			case <-hourlyTicker.C:
				m.AggregateHourlyStats()
			case <-systemStatsTicker.C:
				m.CollectAndSaveSystemStats()
			}
		}
	}()
}

// StopFlush 停止刷盘
func (m *Manager) StopFlush() {
	close(m.flushStop)
}

func (m *Manager) flushCounters() {
	total := m.pendingTotal.Swap(0)
	blocked := m.pendingBlocked.Swap(0)
	if total == 0 && blocked == 0 {
		return
	}
	date := time.Now().UTC().Format("2006-01-02")
	if total > 0 {
		if _, err := m.db.Exec(`INSERT INTO daily_stats (date, total_requests, blocked_requests) VALUES (?, ?, 0) ON CONFLICT(date) DO UPDATE SET total_requests = total_requests + ?`, date, total, total); err != nil {
			logger.Warn("flushCounters total: %v", err)
		}
	}
	if blocked > 0 {
		if _, err := m.db.Exec(`INSERT INTO daily_stats (date, total_requests, blocked_requests) VALUES (?, 0, ?) ON CONFLICT(date) DO UPDATE SET blocked_requests = blocked_requests + ?`, date, blocked, blocked); err != nil {
			logger.Warn("flushCounters blocked: %v", err)
		}
	}
}

func (m *Manager) flushMinuteStats() {
	total := m.pendingMinuteTotal.Swap(0)
	blocked := m.pendingMinuteBlocked.Swap(0)
	latencyRaw := m.pendingMinuteLatency.Swap(0)
	inbound := m.pendingMinuteInbound.Swap(0)
	outbound := m.pendingMinuteOutbound.Swap(0)
	errRateRaw := m.pendingMinuteErrorRate.Swap(0)
	connsRaw := m.pendingMinuteConns.Swap(0)
	if total == 0 && blocked == 0 && inbound == 0 && outbound == 0 && errRateRaw == 0 && connsRaw == 0 {
		return
	}
	minute := time.Now().UTC().Truncate(time.Minute).Format("2006-01-02 15:04:05.999999")
	reqCount := total + blocked
	var avgLatency, qps, errorRate float64
	var activeConns float64
	if reqCount > 0 {
		avgLatency = float64(latencyRaw) / 1000.0 / float64(reqCount)
		qps = float64(reqCount) / 60.0
		errorRate = float64(errRateRaw) / 100.0 / float64(reqCount)
		activeConns = float64(connsRaw) / float64(reqCount)
	}
	if _, err := m.db.Exec(`
		INSERT INTO minute_stats (time_minute, total_requests, blocked_requests, avg_qps, avg_latency_ms, inbound_bytes, outbound_bytes, error_rate, active_conns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(time_minute) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blocked_requests = blocked_requests + excluded.blocked_requests,
			avg_qps = CASE WHEN total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests > 0
				THEN (avg_qps * (total_requests + blocked_requests) + excluded.avg_qps * (excluded.total_requests + excluded.blocked_requests))
					/ (total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests)
				ELSE excluded.avg_qps END,
			avg_latency_ms = CASE WHEN total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests > 0
				THEN (avg_latency_ms * (total_requests + blocked_requests) + excluded.avg_latency_ms * (excluded.total_requests + excluded.blocked_requests))
					/ (total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests)
				ELSE excluded.avg_latency_ms END,
			inbound_bytes = inbound_bytes + excluded.inbound_bytes,
			outbound_bytes = outbound_bytes + excluded.outbound_bytes,
			error_rate = CASE WHEN total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests > 0
				THEN (error_rate * (total_requests + blocked_requests) + excluded.error_rate * (excluded.total_requests + excluded.blocked_requests))
					/ (total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests)
				ELSE excluded.error_rate END,
			active_conns = CASE WHEN total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests > 0
				THEN (active_conns * (total_requests + blocked_requests) + excluded.active_conns * (excluded.total_requests + excluded.blocked_requests))
					/ (total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests)
				ELSE excluded.active_conns END
	`, minute, total, blocked, qps, avgLatency, inbound, outbound, errorRate, activeConns); err != nil {
		logger.Warn("flushMinuteStats: %v", err)
	}
}

func (m *Manager) AggregateHourlyStats() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	currentHour := now.Truncate(time.Hour)
	prevHour := currentHour.Add(-time.Hour)
	prevHourStr := prevHour.Format("2006-01-02 15:04:05.999999")
	prevHourEnd := currentHour.Format("2006-01-02 15:04:05.999999")

	var totalReqs, blockedReqs, inBytes, outBytes int64
	var avgQPS, avgLatency, avgErrRate, avgConns float64
	err := m.db.QueryRow(`
		SELECT COALESCE(SUM(total_requests),0), COALESCE(SUM(blocked_requests),0),
		       CASE WHEN SUM(total_requests + blocked_requests) > 0
		           THEN SUM(avg_qps * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
		           ELSE 0 END,
		       CASE WHEN SUM(total_requests + blocked_requests) > 0
		           THEN SUM(avg_latency_ms * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
		           ELSE 0 END,
		       COALESCE(SUM(inbound_bytes),0), COALESCE(SUM(outbound_bytes),0),
		       CASE WHEN SUM(total_requests + blocked_requests) > 0
		           THEN SUM(error_rate * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
		           ELSE 0 END,
		       CASE WHEN SUM(total_requests + blocked_requests) > 0
		           THEN SUM(CAST(active_conns AS FLOAT) * (total_requests + blocked_requests)) / SUM(total_requests + blocked_requests)
		           ELSE 0 END
		FROM minute_stats WHERE time_minute >= ? AND time_minute < ?
	`, prevHourStr, prevHourEnd).Scan(&totalReqs, &blockedReqs, &avgQPS, &avgLatency, &inBytes, &outBytes, &avgErrRate, &avgConns)
	if err != nil {
		logger.Warn("AggregateHourlyStats query: %v", err)
		return
	}
	if totalReqs == 0 && blockedReqs == 0 {
		return
	}
	if _, err := m.db.Exec(`
		INSERT INTO hourly_stats (time_hour, total_requests, blocked_requests, avg_qps, avg_latency_ms, inbound_bytes, outbound_bytes, error_rate, active_conns)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(time_hour) DO UPDATE SET
			total_requests = excluded.total_requests,
			blocked_requests = excluded.blocked_requests,
			avg_qps = excluded.avg_qps,
			avg_latency_ms = excluded.avg_latency_ms,
			inbound_bytes = excluded.inbound_bytes,
			outbound_bytes = excluded.outbound_bytes,
			error_rate = excluded.error_rate,
			active_conns = excluded.active_conns
	`, prevHourStr, totalReqs, blockedReqs, avgQPS, avgLatency, inBytes, outBytes, avgErrRate, avgConns); err != nil {
		logger.Warn("AggregateHourlyStats insert: %v", err)
	}

	date := prevHour.Format("2006-01-02")
	if _, err := m.db.Exec(`
		INSERT INTO daily_stats (date, total_requests, blocked_requests, avg_qps, avg_latency_ms, inbound_bytes, outbound_bytes)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(date) DO UPDATE SET
			total_requests = total_requests + excluded.total_requests,
			blocked_requests = blocked_requests + excluded.blocked_requests,
			avg_qps = CASE WHEN total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests > 0
				THEN (avg_qps * (total_requests + blocked_requests) + excluded.avg_qps * (excluded.total_requests + excluded.blocked_requests))
					/ (total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests)
				ELSE excluded.avg_qps END,
			avg_latency_ms = CASE WHEN total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests > 0
				THEN (avg_latency_ms * (total_requests + blocked_requests) + excluded.avg_latency_ms * (excluded.total_requests + excluded.blocked_requests))
					/ (total_requests + blocked_requests + excluded.total_requests + excluded.blocked_requests)
				ELSE excluded.avg_latency_ms END,
			inbound_bytes = inbound_bytes + excluded.inbound_bytes,
			outbound_bytes = outbound_bytes + excluded.outbound_bytes
	`, date, totalReqs, blockedReqs, avgQPS, avgLatency, inBytes, outBytes); err != nil {
		logger.Warn("AggregateHourlyStats daily: %v", err)
	}
}
