package metrics

import (
	"strings"
	"time"

	"gowaf/internal/infra/logger"
	"gowaf/internal/pkg/xutil"
)

// IncTopStat 增加TOP统计计数
func (m *Manager) IncTopStat(statType, itemKey string) error {
	date := time.Now().UTC().Format("2006-01-02")
	now := time.Now().UTC().Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`
		INSERT INTO top_stats (date, stat_type, item_key, count, last_seen)
		VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(date, stat_type, item_key) DO UPDATE SET count = count + 1, last_seen = ?
	`, date, statType, itemKey, now, now)
	return err
}

// GetTopStats 获取TOP统计
func (m *Manager) GetTopStats(statType string, startTime, endTime time.Time, limit int) ([]TopStatItem, error) {
	rows, err := m.db.Query(`
		SELECT item_key, SUM(count) as total_count, MAX(last_seen) as last_seen
		FROM top_stats
		WHERE stat_type = ? AND date >= ? AND date <= ?
		GROUP BY item_key
		ORDER BY total_count DESC
		LIMIT ?
	`, statType, startTime.Format("2006-01-02"), endTime.Format("2006-01-02"), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []TopStatItem
	for rows.Next() {
		var item TopStatItem
		var lastSeenStr string
		if err := rows.Scan(&item.Name, &item.Count, &lastSeenStr); err == nil {
			pt, _ := xutil.ParseTime(lastSeenStr)
			item.LastSeen = xutil.FromTime(pt)
			items = append(items, item)
		}
	}

	startStr := startTime.Format("2006-01-02 15:04:05.999999")
	endStr := endTime.Format("2006-01-02 15:04:05.999999")

	if statType == "blocked_ip" && len(items) > 0 {
		ipList := make([]string, len(items))
		for i := range items {
			ipList[i] = items[i].Name
		}
		ruleByIP := m.queryRuleTypesBatch(ipList, startStr, endStr)
		for i := range items {
			items[i].RuleTypes = ruleByIP[items[i].Name]
			items[i].RiskLevel = calculateRiskLevel(items[i].Count, items[i].RuleTypes)
			geo := m.getGeoLocation(items[i].Name)
			items[i].GeoCountry = geo.Country
			items[i].GeoFlag = geo.Flag
		}
	} else if statType == "attacked_path" && len(items) > 0 {
		pathList := make([]string, len(items))
		for i := range items {
			pathList[i] = items[i].Name
		}
		ipByPath, methodByPath := m.queryPathDetailsBatch(pathList, startStr, endStr)
		for i := range items {
			items[i].SourceIPCount = int(ipByPath[items[i].Name])
			items[i].Methods = methodByPath[items[i].Name]
		}
	}

	return items, nil
}

// IncRuleHit 增加规则命中计数
func (m *Manager) IncRuleHit(ruleType string) error {
	date := time.Now().UTC().Format("2006-01-02")
	now := time.Now().UTC().Format("2006-01-02 15:04:05.999999")
	_, err := m.db.Exec(`
		INSERT INTO rule_hit_stats (date, rule_type, hit_count, last_seen)
		VALUES (?, ?, 1, ?)
		ON CONFLICT(date, rule_type) DO UPDATE SET hit_count = hit_count + 1, last_seen = ?
	`, date, ruleType, now, now)
	return err
}

func (m *Manager) queryRuleTypesBatch(ips []string, startStr, endStr string) map[string]map[string]int {
	result := make(map[string]map[string]int)
	if len(ips) == 0 || m.db == nil {
		return result
	}
	placeholders := make([]string, len(ips))
	args := make([]interface{}, len(ips)+2)
	for i, ip := range ips {
		placeholders[i] = "?"
		args[i+2] = ip
	}
	args[0], args[1] = startStr, endStr
	rows, err := m.db.Query(`
		SELECT client_ip, rule, COUNT(*) as count
		FROM intercept_events
		WHERE time >= ? AND time <= ? AND client_ip IN (`+strings.Join(placeholders, ",")+`)
		GROUP BY client_ip, rule
		ORDER BY count DESC
	`, args...)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var ip, rule string
		var count int
		if rows.Scan(&ip, &rule, &count) != nil {
			continue
		}
		if result[ip] == nil {
			result[ip] = make(map[string]int)
		}
		result[ip][rule] = count
	}
	return result
}

func (m *Manager) queryPathDetailsBatch(paths []string, startStr, endStr string) (map[string]int64, map[string]map[string]int) {
	ipCount := make(map[string]int64)
	methodCount := make(map[string]map[string]int)
	if len(paths) == 0 || m.db == nil {
		return ipCount, methodCount
	}
	placeholders := make([]string, len(paths))
	args := make([]interface{}, len(paths)+2)
	for i, p := range paths {
		placeholders[i] = "?"
		args[i+2] = p
	}
	args[0], args[1] = startStr, endStr

	ipRows, err := m.db.Query(`
		SELECT path, COUNT(DISTINCT client_ip) as cnt
		FROM intercept_events
		WHERE time >= ? AND time <= ? AND path IN (`+strings.Join(placeholders, ",")+`)
		GROUP BY path
	`, args...)
	if err == nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var path string
			var cnt int64
			if ipRows.Scan(&path, &cnt) == nil {
				ipCount[path] = cnt
			}
		}
	}

	methodRows, err := m.db.Query(`
		SELECT path, method, COUNT(*) as cnt
		FROM intercept_events
		WHERE time >= ? AND time <= ? AND path IN (`+strings.Join(placeholders, ",")+`)
		GROUP BY path, method
		ORDER BY cnt DESC
	`, args...)
	if err == nil {
		defer methodRows.Close()
		for methodRows.Next() {
			var path, method string
			var cnt int
			if methodRows.Scan(&path, &method, &cnt) == nil {
				if methodCount[path] == nil {
					methodCount[path] = make(map[string]int)
				}
				methodCount[path][method] = cnt
			}
		}
	}
	return ipCount, methodCount
}

func (m *Manager) queryIPCountByRuleBatch(rules []string, startStr, endStr string) map[string]int {
	result := make(map[string]int)
	if len(rules) == 0 || m.db == nil {
		return result
	}
	placeholders := make([]string, len(rules))
	args := make([]interface{}, len(rules)+2)
	for i, rule := range rules {
		placeholders[i] = "?"
		args[i+2] = rule
	}
	args[0], args[1] = startStr, endStr
	rows, err := m.db.Query(`
		SELECT rule, COUNT(DISTINCT client_ip) as cnt
		FROM intercept_events
		WHERE time >= ? AND time <= ? AND rule IN (`+strings.Join(placeholders, ",")+`)
		GROUP BY rule
	`, args...)
	if err != nil {
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var rule string
		var cnt int
		if rows.Scan(&rule, &cnt) == nil {
			result[rule] = cnt
		}
	}
	return result
}

func (m *Manager) GetRuleHitStats(startTime, endTime time.Time) ([]RuleHitStat, error) {
	rows, err := m.db.Query(`
		SELECT rule_type, SUM(hit_count) as total_count, MAX(last_seen) as last_seen
		FROM rule_hit_stats
		WHERE date >= ? AND date <= ?
		GROUP BY rule_type
		ORDER BY total_count DESC
	`, startTime.Format("2006-01-02"), endTime.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stats []RuleHitStat
	for rows.Next() {
		var s RuleHitStat
		var lastSeenStr string
		if err := rows.Scan(&s.Name, &s.Count, &lastSeenStr); err == nil {
			if pt, err := xutil.ParseTime(lastSeenStr); err == nil {
				s.LastSeen = xutil.FromTime(pt)
			}
			stats = append(stats, s)
		}
	}

	startStr := startTime.Format("2006-01-02 15:04:05.999999")
	endStr := endTime.Format("2006-01-02 15:04:05.999999")

	if len(stats) > 0 {
		ruleNames := make([]string, len(stats))
		for i := range stats {
			ruleNames[i] = stats[i].Name
		}
		ipByRule := m.queryIPCountByRuleBatch(ruleNames, startStr, endStr)
		for i := range stats {
			stats[i].AffectedIPs = ipByRule[stats[i].Name]
			stats[i].Severity = calculateSeverity(stats[i].Name, stats[i].Count)
			stats[i].RuleType = classifyRuleType(stats[i].Name)
		}
	}

	return stats, nil
}

// CleanupOldData 清理过期数据（保留retentionDays天，分批删除避免长时间持锁）
func (m *Manager) CleanupOldData(retentionDays int) error {
	if retentionDays <= 0 {
		retentionDays = 7
	}

	cutoffTime := time.Now().UTC().AddDate(0, 0, -retentionDays)
	cutoffDate := cutoffTime.Format("2006-01-02")
	cutoffTimeStr := cutoffTime.Format("2006-01-02 15:04:05.999999")

	const batchSize = 10000
	for {
		result, err := m.db.Exec(`DELETE FROM intercept_events WHERE rowid IN (SELECT rowid FROM intercept_events WHERE time < ? LIMIT ?)`, cutoffTimeStr, batchSize)
		if err != nil {
			return err
		}
		affected, _ := result.RowsAffected()
		if affected < int64(batchSize) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	_, err := m.db.Exec(`DELETE FROM daily_stats WHERE date < ?`, cutoffDate)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`DELETE FROM top_stats WHERE date < ?`, cutoffDate)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`DELETE FROM rule_hit_stats WHERE date < ?`, cutoffDate)
	if err != nil {
		return err
	}

	_, err = m.db.Exec(`DELETE FROM minute_stats WHERE time_minute < ?`, cutoffTimeStr)
	if err != nil {
		logger.Warn("清理minute_stats失败: %v", err)
	}

	m.db.Exec(`PRAGMA incremental_vacuum`)

	return nil
}
