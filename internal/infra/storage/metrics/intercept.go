package metrics

import (
	"database/sql"
	"time"

	"gowaf/internal/infra/logger"
	"gowaf/internal/pkg/xutil"
)

// SaveEvent 保存拦截事件（增强版，异步批量写入）
func (m *Manager) SaveEvent(clientIP, host, path, query, method, userAgent, referer, contentType, rule string, status int, requestID string, latencyMs float64, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme string, requestSize int64, upstreamLatencyMs float64, errorMessage string) error {
	if m.eventChan == nil {
		return m.saveEventSync(clientIP, host, path, query, method, userAgent, referer, contentType, rule, status, requestID, latencyMs, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme, requestSize, upstreamLatencyMs, errorMessage)
	}
	ev := interceptEventData{
		clientIP: clientIP, host: host, path: path, query: query, method: method,
		userAgent: userAgent, referer: referer, contentType: contentType, rule: rule,
		status: status, requestID: requestID, latencyMs: latencyMs,
		geoCountry: geoCountry, geoCity: geoCity, geoFlag: geoFlag,
		matchDetail: matchDetail, matchLocation: matchLocation, action: action,
		upstreamAddr: upstreamAddr, protocol: protocol, scheme: scheme,
		requestSize: requestSize, upstreamLatencyMs: upstreamLatencyMs, errorMessage: errorMessage,
	}
	select {
	case m.eventChan <- ev:
		return nil
	default:
		logger.Warn("SaveEvent队列满,降级同步写入: ip=%s path=%s", clientIP, path)
		return m.saveEventSync(clientIP, host, path, query, method, userAgent, referer, contentType, rule, status, requestID, latencyMs, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme, requestSize, upstreamLatencyMs, errorMessage)
	}
}

func (m *Manager) saveEventSync(clientIP, host, path, query, method, userAgent, referer, contentType, rule string, status int, requestID string, latencyMs float64, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme string, requestSize int64, upstreamLatencyMs float64, errorMessage string) error {
	now := time.Now().UTC().Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`
		INSERT INTO intercept_events (time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms, geo_country, geo_city, geo_flag, match_detail, match_location, action, upstream_addr, protocol, scheme, request_size, upstream_latency_ms, error_message)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, now, clientIP, host, path, query, method, userAgent, referer, contentType, rule, status, requestID, latencyMs, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme, requestSize, upstreamLatencyMs, errorMessage)
	if err != nil {
		logger.Warn("SaveEvent写入失败: %v, data: ip=%s path=%s rule=%s", err, clientIP, path, rule)
	}
	return err
}

func (m *Manager) startEventWriter() {
	if m.eventChan != nil {
		return
	}
	m.eventChan = make(chan interceptEventData, 5000)
	go func() {
		batch := make([]interceptEventData, 0, 100)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case ev, ok := <-m.eventChan:
				if !ok {
					m.flushEventBatch(batch)
					return
				}
				batch = append(batch, ev)
				if len(batch) >= 100 {
					m.flushEventBatch(batch)
					batch = batch[:0]
				}
			case <-ticker.C:
				if len(batch) > 0 {
					m.flushEventBatch(batch)
					batch = batch[:0]
				}
			}
		}
	}()
}

func (m *Manager) flushEventBatch(batch []interceptEventData) {
	if len(batch) == 0 || m.db == nil {
		return
	}
	if m.flushBatchWithTx(batch) {
		return
	}
	const smallBatch = 50
	for i := 0; i < len(batch); i += smallBatch {
		end := i + smallBatch
		if end > len(batch) {
			end = len(batch)
		}
		if !m.flushBatchWithTx(batch[i:end]) {
			for _, ev := range batch[i:end] {
				m.saveEventSync(ev.clientIP, ev.host, ev.path, ev.query, ev.method, ev.userAgent, ev.referer, ev.contentType, ev.rule, ev.status, ev.requestID, ev.latencyMs, ev.geoCountry, ev.geoCity, ev.geoFlag, ev.matchDetail, ev.matchLocation, ev.action, ev.upstreamAddr, ev.protocol, ev.scheme, ev.requestSize, ev.upstreamLatencyMs, ev.errorMessage)
			}
		}
	}
}

func (m *Manager) flushBatchWithTx(batch []interceptEventData) bool {
	tx, err := m.db.Begin()
	if err != nil {
		return false
	}
	stmt, err := tx.Prepare(`INSERT INTO intercept_events (time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms, geo_country, geo_city, geo_flag, match_detail, match_location, action, upstream_addr, protocol, scheme, request_size, upstream_latency_ms, error_message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return false
	}
	defer stmt.Close()
	for _, ev := range batch {
		now := time.Now().UTC().Format("2006-01-02 15:04:05.999999")
		if _, err := stmt.Exec(now, ev.clientIP, ev.host, ev.path, ev.query, ev.method, ev.userAgent, ev.referer, ev.contentType, ev.rule, ev.status, ev.requestID, ev.latencyMs, ev.geoCountry, ev.geoCity, ev.geoFlag, ev.matchDetail, ev.matchLocation, ev.action, ev.upstreamAddr, ev.protocol, ev.scheme, ev.requestSize, ev.upstreamLatencyMs, ev.errorMessage); err != nil {
			logger.Warn("flushEventBatch insert error: %v", err)
		}
	}
	if err := tx.Commit(); err != nil {
		logger.Warn("flushEventBatch提交失败: %v, batch=%d", err, len(batch))
		return false
	}
	return true
}

// GetEvents 获取拦截事件（支持时间范围和分页）
func (m *Manager) GetEvents(startTime, endTime time.Time, offset, limit int) ([]InterceptEvent, error) {
	startStr := startTime.Format("2006-01-02 15:04:05.999999")
	endStr := endTime.Format("2006-01-02 15:04:05.999999")
	rows, err := m.db.Query(`
		SELECT id, time, client_ip, host, path, query, method, user_agent, referer, content_type, rule, status, request_id, latency_ms, geo_country, geo_city, geo_flag, match_detail, match_location, action, upstream_addr, protocol, scheme, upstream_latency_ms, request_size, error_message
		FROM intercept_events
		WHERE time >= ? AND time <= ?
		ORDER BY id DESC
		LIMIT ? OFFSET ?
	`, startStr, endStr, limit, offset)
	if err != nil {
		logger.Warn("GetEvents查询失败: %v", err)
		return nil, err
	}
	defer rows.Close()

	var events []InterceptEvent
	for rows.Next() {
		var e InterceptEvent
		var timeStr string
		var latencyMs, upstreamLatencyMs sql.NullFloat64
		var requestSize sql.NullInt64
		var host, query, userAgent, referer, contentType, geoCountry, geoCity, geoFlag, matchDetail, matchLocation, action, upstreamAddr, protocol, scheme, errorMessage sql.NullString
		if err := rows.Scan(&e.ID, &timeStr, &e.ClientIP, &host, &e.Path, &query, &e.Method,
			&userAgent, &referer, &contentType, &e.Rule, &e.Status, &e.RequestID, &latencyMs, &geoCountry, &geoCity, &geoFlag, &matchDetail, &matchLocation, &action, &upstreamAddr, &protocol, &scheme, &upstreamLatencyMs, &requestSize, &errorMessage); err == nil {
			pt, _ := xutil.ParseTime(timeStr)
			e.Time = xutil.FromTime(pt)
			if host.Valid {
				e.Host = host.String
			}
			if query.Valid {
				e.Query = query.String
			}
			if userAgent.Valid {
				e.UserAgent = userAgent.String
			}
			if referer.Valid {
				e.Referer = referer.String
			}
			if contentType.Valid {
				e.ContentType = contentType.String
			}
			if latencyMs.Valid {
				e.LatencyMs = latencyMs.Float64
			}
			if geoCountry.Valid {
				e.GeoCountry = geoCountry.String
			}
			if geoCity.Valid {
				e.GeoCity = geoCity.String
			}
			if geoFlag.Valid {
				e.GeoFlag = geoFlag.String
			}
			if matchDetail.Valid {
				e.MatchDetail = matchDetail.String
			}
			if matchLocation.Valid {
				e.MatchLocation = matchLocation.String
			}
			if action.Valid {
				e.Action = action.String
			}
			if upstreamAddr.Valid {
				e.UpstreamAddr = upstreamAddr.String
			}
			if protocol.Valid {
				e.Protocol = protocol.String
			}
			if scheme.Valid {
				e.Scheme = scheme.String
			}
			if upstreamLatencyMs.Valid {
				e.UpstreamLatencyMs = upstreamLatencyMs.Float64
			}
			if requestSize.Valid {
				e.RequestSize = requestSize.Int64
			}
			if errorMessage.Valid {
				e.ErrorMessage = errorMessage.String
			}
			if e.GeoCountry == "" && e.ClientIP != "" {
				if geo := m.getGeoLocation(e.ClientIP); geo.Country != "" {
					e.GeoCountry = geo.Country
					e.GeoCity = geo.City
					e.GeoFlag = geo.Flag
				}
			}
			events = append(events, e)
		} else {
			logger.Warn("GetEvents Scan行失败: %v", err)
		}
	}
	return events, nil
}

// CountEvents 获取事件数量
func (m *Manager) CountEvents(startTime, endTime time.Time) (int64, error) {
	var count int64
	startStr := startTime.Format("2006-01-02 15:04:05.999999")
	endStr := endTime.Format("2006-01-02 15:04:05.999999")
	err := m.db.QueryRow(`SELECT COUNT(*) FROM intercept_events WHERE time >= ? AND time <= ?`, startStr, endStr).Scan(&count)
	return count, err
}

// GetEventCount 获取事件总数
func (m *Manager) GetEventCount(startTime, endTime time.Time) (int64, error) {
	var count int64
	startStr := startTime.Format("2006-01-02 15:04:05.999999")
	endStr := endTime.Format("2006-01-02 15:04:05.999999")
	err := m.db.QueryRow(`SELECT COUNT(*) FROM intercept_events WHERE time >= ? AND time <= ?`, startStr, endStr).Scan(&count)
	return count, err
}

// GetTotalEventCount 获取所有事件总数（从daily_stats汇总，避免全表COUNT）
func (m *Manager) GetTotalEventCount() (int64, error) {
	var count int64
	err := m.db.QueryRow(`SELECT COALESCE(SUM(blocked_requests), 0) FROM daily_stats`).Scan(&count)
	if err != nil {
		err = m.db.QueryRow(`SELECT COUNT(*) FROM intercept_events`).Scan(&count)
	}
	return count, err
}
