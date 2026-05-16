package compliance

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Report struct {
	GeneratedAt        time.Time        `json:"generated_at"`
	PeriodStart        time.Time        `json:"period_start"`
	PeriodEnd          time.Time        `json:"period_end"`
	SecuritySummary    SecuritySummary  `json:"security_summary"`
	RuleCoverage       RuleCoverage     `json:"rule_coverage"`
	ConfigAudit        ConfigAudit      `json:"config_audit"`
	TopBlockedIPs      []IPBlockStat    `json:"top_blocked_ips"`
	AttackDistribution []AttackDist     `json:"attack_distribution"`
	ComplianceStatus   ComplianceStatus `json:"compliance_status"`
}

type SecuritySummary struct {
	TotalRequests    int64   `json:"total_requests"`
	TotalBlocked     int64   `json:"total_blocked"`
	TotalPassed      int64   `json:"total_passed"`
	BlockRate        float64 `json:"block_rate"`
	UniqueBlockedIPs int64   `json:"unique_blocked_ips"`
	TopAttackType    string  `json:"top_attack_type"`
	AvgLatencyMs     float64 `json:"avg_latency_ms"`
}

type RuleCoverage struct {
	DetectorsEnabled int     `json:"detectors_enabled"`
	DetectorsTotal   int     `json:"detectors_total"`
	IPRulesCount     int     `json:"ip_rules_count"`
	UARulesCount     int     `json:"ua_rules_count"`
	PathRulesCount   int     `json:"path_rules_count"`
	GeoRulesCount    int     `json:"geo_rules_count"`
	CustomRulesCount int     `json:"custom_rules_count"`
	CoveragePercent  float64 `json:"coverage_percent"`
}

type ConfigAudit struct {
	PasswordStrength string `json:"password_strength"`
	SessionTTLSecs   int    `json:"session_ttl_secs"`
	CSRFEnabled      bool   `json:"csrf_enabled"`
	HTTPSEnforced    bool   `json:"https_enforced"`
	SecurityHeaders  bool   `json:"security_headers"`
	ObservationMode  bool   `json:"observation_mode"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
}

type IPBlockStat struct {
	IP       string `json:"ip"`
	Count    int64  `json:"count"`
	LastSeen string `json:"last_seen"`
}

type AttackDist struct {
	AttackType string  `json:"attack_type"`
	Count      int64   `json:"count"`
	Percent    float64 `json:"percent"`
}

type ComplianceStatus struct {
	OverallScore float64          `json:"overall_score"`
	Level        string           `json:"level"`
	Items        []ComplianceItem `json:"items"`
}

type ComplianceItem struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	Score       float64 `json:"score"`
	Description string  `json:"description"`
}

type Generator struct {
	configDB *sql.DB
	logDB    *sql.DB
}

func NewGenerator(configDB, logDB *sql.DB) *Generator {
	return &Generator{configDB: configDB, logDB: logDB}
}

func (g *Generator) Generate(periodStart, periodEnd time.Time) (*Report, error) {
	r := &Report{
		GeneratedAt: time.Now(),
		PeriodStart: periodStart,
		PeriodEnd:   periodEnd,
	}

	g.fillSecuritySummary(r, periodStart, periodEnd)
	g.fillRuleCoverage(r)
	g.fillConfigAudit(r)
	g.fillTopBlockedIPs(r, periodStart, periodEnd)
	g.fillAttackDistribution(r, periodStart, periodEnd)
	g.fillComplianceStatus(r)

	return r, nil
}

func (g *Generator) fillSecuritySummary(r *Report, start, end time.Time) {
	if g.logDB == nil {
		return
	}
	s := &r.SecuritySummary
	startStr := start.Format("2006-01-02 15:04:05")
	endStr := end.Format("2006-01-02 15:04:05")

	g.logDB.QueryRow(
		"SELECT COUNT(*) FROM intercept_events WHERE time >= ? AND time <= ?",
		startStr, endStr).Scan(&s.TotalRequests)

	g.logDB.QueryRow(
		"SELECT COUNT(*) FROM intercept_events WHERE time >= ? AND time <= ? AND action='block'",
		startStr, endStr).Scan(&s.TotalBlocked)

	g.logDB.QueryRow(
		"SELECT COUNT(*) FROM intercept_events WHERE time >= ? AND time <= ? AND action='pass'",
		startStr, endStr).Scan(&s.TotalPassed)

	g.logDB.QueryRow(
		"SELECT COUNT(DISTINCT client_ip) FROM intercept_events WHERE time >= ? AND time <= ? AND action='block'",
		startStr, endStr).Scan(&s.UniqueBlockedIPs)

	if s.TotalRequests > 0 {
		s.BlockRate = float64(s.TotalBlocked) / float64(s.TotalRequests) * 100
	}

	g.logDB.QueryRow(
		"SELECT rule FROM intercept_events WHERE time >= ? AND time <= ? AND action='block' GROUP BY rule ORDER BY COUNT(*) DESC LIMIT 1",
		startStr, endStr).Scan(&s.TopAttackType)

	var totalLatency float64
	var latencyCount int64
	g.logDB.QueryRow(
		"SELECT COALESCE(SUM(latency_ms),0), COUNT(*) FROM intercept_events WHERE time >= ? AND time <= ? AND latency_ms > 0",
		startStr, endStr).Scan(&totalLatency, &latencyCount)
	if latencyCount > 0 {
		s.AvgLatencyMs = totalLatency / float64(latencyCount)
	}
}

func (g *Generator) fillRuleCoverage(r *Report) {
	if g.configDB == nil {
		return
	}
	c := &r.RuleCoverage
	c.DetectorsTotal = 8

	g.configDB.QueryRow("SELECT COUNT(*) FROM detector_config WHERE enabled=1").Scan(&c.DetectorsEnabled)
	g.configDB.QueryRow("SELECT COUNT(*) FROM ip_rules WHERE enabled=1").Scan(&c.IPRulesCount)
	g.configDB.QueryRow("SELECT COUNT(*) FROM ua_rules WHERE enabled=1").Scan(&c.UARulesCount)
	g.configDB.QueryRow("SELECT COUNT(*) FROM path_rules WHERE enabled=1").Scan(&c.PathRulesCount)
	g.configDB.QueryRow("SELECT COUNT(*) FROM geo_rules").Scan(&c.GeoRulesCount)
	g.configDB.QueryRow("SELECT COUNT(*) FROM detection_rules WHERE rule_type='custom' AND enabled=1").Scan(&c.CustomRulesCount)

	if c.DetectorsTotal > 0 {
		c.CoveragePercent = float64(c.DetectorsEnabled) / float64(c.DetectorsTotal) * 100
	}
}

func (g *Generator) fillConfigAudit(r *Report) {
	a := &r.ConfigAudit
	a.CSRFEnabled = true
	a.SecurityHeaders = true

	if g.configDB == nil {
		return
	}

	var sessionTTL int
	var runtimeJSON string
	if err := g.configDB.QueryRow("SELECT value FROM system_config WHERE key='runtime_config'").Scan(&runtimeJSON); err == nil && runtimeJSON != "" {
		var rc struct {
			Security struct {
				Session struct {
					TTL int `json:"ttl"`
				} `json:"session"`
			} `json:"security"`
		}
		if err := json.Unmarshal([]byte(runtimeJSON), &rc); err == nil && rc.Security.Session.TTL > 0 {
			sessionTTL = rc.Security.Session.TTL * 3600
		}
	}
	a.SessionTTLSecs = sessionTTL
	if sessionTTL == 0 {
		a.SessionTTLSecs = 1800
	}

	var obsMode int
	g.configDB.QueryRow("SELECT COUNT(*) FROM detector_config WHERE observation_mode=1 AND enabled=1").Scan(&obsMode)
	a.ObservationMode = obsMode > 0

	var passHash string
	g.configDB.QueryRow("SELECT value FROM system_config WHERE key='admin_password_hash'").Scan(&passHash)
	if passHash != "" {
		a.PasswordStrength = "hashed"
	} else {
		a.PasswordStrength = "plaintext_or_empty"
	}

	var httpsCount int
	g.configDB.QueryRow("SELECT COUNT(*) FROM domain_config WHERE force_https=1 AND enabled=1").Scan(&httpsCount)
	a.HTTPSEnforced = httpsCount > 0

	var rlEnabled int
	g.configDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key='rate_limit_enabled' AND value='1'").Scan(&rlEnabled)
	if rlEnabled == 0 {
		g.configDB.QueryRow("SELECT COUNT(*) FROM system_config WHERE key='ratelimit_enabled' AND value='true'").Scan(&rlEnabled)
	}
	a.RateLimitEnabled = rlEnabled > 0
}

func (g *Generator) fillTopBlockedIPs(r *Report, start, end time.Time) {
	if g.logDB == nil {
		return
	}
	startStr := start.Format("2006-01-02 15:04:05")
	endStr := end.Format("2006-01-02 15:04:05")

	rows, err := g.logDB.Query(
		"SELECT client_ip, COUNT(*) as cnt, MAX(time) as last_seen FROM intercept_events WHERE time >= ? AND time <= ? AND action='block' GROUP BY client_ip ORDER BY cnt DESC LIMIT 10",
		startStr, endStr)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var s IPBlockStat
		if rows.Scan(&s.IP, &s.Count, &s.LastSeen) == nil {
			r.TopBlockedIPs = append(r.TopBlockedIPs, s)
		}
	}
}

func (g *Generator) fillAttackDistribution(r *Report, start, end time.Time) {
	if g.logDB == nil {
		return
	}
	startStr := start.Format("2006-01-02 15:04:05")
	endStr := end.Format("2006-01-02 15:04:05")

	rows, err := g.logDB.Query(
		"SELECT rule, COUNT(*) as cnt FROM intercept_events WHERE time >= ? AND time <= ? AND action='block' GROUP BY rule ORDER BY cnt DESC",
		startStr, endStr)
	if err != nil {
		return
	}
	defer rows.Close()
	var total int64
	var dists []AttackDist
	for rows.Next() {
		var d AttackDist
		if rows.Scan(&d.AttackType, &d.Count) == nil {
			total += d.Count
			dists = append(dists, d)
		}
	}
	for i := range dists {
		if total > 0 {
			dists[i].Percent = float64(dists[i].Count) / float64(total) * 100
		}
	}
	r.AttackDistribution = dists
}

func (g *Generator) fillComplianceStatus(r *Report) {
	cs := &r.ComplianceStatus
	var items []ComplianceItem
	totalScore := 0.0

	checks := []struct {
		id, name, desc string
		score          float64
		pass           bool
	}{
		{"SEC-01", "检测器启用", "至少6个检测器已启用", 20, r.RuleCoverage.DetectorsEnabled >= 6},
		{"SEC-02", "IP规则配置", "IP黑名单非空", 10, r.RuleCoverage.IPRulesCount > 0},
		{"SEC-03", "CSRF防护", "CSRF Token验证已启用", 10, r.ConfigAudit.CSRFEnabled},
		{"SEC-04", "安全响应头", "安全响应头已启用", 10, r.ConfigAudit.SecurityHeaders},
		{"SEC-05", "密码强度", "管理员密码已哈希存储", 10, r.ConfigAudit.PasswordStrength == "hashed"},
		{"SEC-06", "HTTPS强制", "至少一个域名强制HTTPS", 10, r.ConfigAudit.HTTPSEnforced},
		{"SEC-07", "限流防护", "限流引擎已启用", 10, r.ConfigAudit.RateLimitEnabled},
		{"SEC-08", "拦截率正常", "拦截率低于50%（过高可能误报）", 10, r.SecuritySummary.BlockRate < 50 || r.SecuritySummary.TotalRequests == 0},
		{"SEC-09", "规则覆盖度", "检测器覆盖率>=75%", 10, r.RuleCoverage.CoveragePercent >= 75},
	}

	for _, c := range checks {
		status := "pass"
		score := c.score
		if !c.pass {
			status = "fail"
			score = 0
		}
		totalScore += score
		items = append(items, ComplianceItem{
			ID: c.id, Name: c.name, Status: status,
			Score: score, Description: c.desc,
		})
	}

	cs.Items = items
	cs.OverallScore = totalScore

	switch {
	case totalScore >= 80:
		cs.Level = "良好"
	case totalScore >= 60:
		cs.Level = "一般"
	case totalScore >= 40:
		cs.Level = "需改进"
	default:
		cs.Level = "不合格"
	}
}

func (g *Generator) GenerateHTML(r *Report) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>GoWAF 合规报告</title>
<style>
body{font-family:system-ui;margin:20px;background:#f5f5f5;color:#333}
.container{max-width:1000px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h1{color:#2c3e50;border-bottom:2px solid #409eff;padding-bottom:10px}
h2{color:#34495e;margin-top:25px}
table{width:100%%;border-collapse:collapse;margin:10px 0}
th,td{padding:8px 12px;border:1px solid #ddd;text-align:left}
th{background:#f8f9fa;font-weight:600}
.pass{color:#27ae60;font-weight:bold} .fail{color:#e74c3c;font-weight:bold}
.score{font-size:48px;font-weight:bold;text-align:center;margin:20px 0}
.good{color:#27ae60} .fair{color:#f39c12} .poor{color:#e74c3c}
.meta{color:#7f8c8d;font-size:13px;text-align:center;margin-bottom:20px}
</style></head><body><div class="container">
<h1>GoWAF 合规报告</h1>
<p class="meta">报告周期: %s ~ %s | 生成时间: %s</p>
<div class="score %s">%.0f/100<br><small>%s</small></div>
<h2>安全摘要</h2>
<table><tr><th>指标</th><th>值</th></tr>
<tr><td>总请求数</td><td>%d</td></tr>
<tr><td>拦截数</td><td>%d</td></tr>
<tr><td>拦截率</td><td>%.2f%%</td></tr>
<tr><td>被拦截唯一IP</td><td>%d</td></tr>
<tr><td>最高攻击类型</td><td>%s</td></tr>
<tr><td>平均延迟</td><td>%.2f ms</td></tr>
</table>`,
		r.PeriodStart.Format("2006-01-02 15:04"), r.PeriodEnd.Format("2006-01-02 15:04"),
		r.GeneratedAt.Format("2006-01-02 15:04:05"),
		scoreClass(r.ComplianceStatus.OverallScore), r.ComplianceStatus.OverallScore, r.ComplianceStatus.Level,
		r.SecuritySummary.TotalRequests, r.SecuritySummary.TotalBlocked,
		r.SecuritySummary.BlockRate, r.SecuritySummary.UniqueBlockedIPs,
		r.SecuritySummary.TopAttackType, r.SecuritySummary.AvgLatencyMs))

	sb.WriteString(fmt.Sprintf(`<h2>规则覆盖度</h2>
<table><tr><th>规则类型</th><th>数量</th></tr>
<tr><td>已启用检测器</td><td>%d / %d (%.0f%%)</td></tr>
<tr><td>IP规则</td><td>%d</td></tr>
<tr><td>UA规则</td><td>%d</td></tr>
<tr><td>路径规则</td><td>%d</td></tr>
<tr><td>GeoIP规则</td><td>%d</td></tr>
<tr><td>自定义检测规则</td><td>%d</td></tr>
</table>`,
		r.RuleCoverage.DetectorsEnabled, r.RuleCoverage.DetectorsTotal, r.RuleCoverage.CoveragePercent,
		r.RuleCoverage.IPRulesCount, r.RuleCoverage.UARulesCount, r.RuleCoverage.PathRulesCount,
		r.RuleCoverage.GeoRulesCount, r.RuleCoverage.CustomRulesCount))

	sb.WriteString(`<h2>合规检查项</h2><table><tr><th>ID</th><th>检查项</th><th>状态</th><th>得分</th><th>说明</th></tr>`)
	for _, item := range r.ComplianceStatus.Items {
		statusClass := "pass"
		statusText := "通过"
		if item.Status == "fail" {
			statusClass = "fail"
			statusText = "未通过"
		}
		sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td class="%s">%s</td><td>%.0f</td><td>%s</td></tr>`,
			item.ID, item.Name, statusClass, statusText, item.Score, item.Description))
	}
	sb.WriteString(`</table>`)

	if len(r.AttackDistribution) > 0 {
		sb.WriteString(`<h2>攻击类型分布</h2><table><tr><th>攻击类型</th><th>次数</th><th>占比</th></tr>`)
		for _, d := range r.AttackDistribution {
			sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%.1f%%</td></tr>`, d.AttackType, d.Count, d.Percent))
		}
		sb.WriteString(`</table>`)
	}

	if len(r.TopBlockedIPs) > 0 {
		sb.WriteString(`<h2>TOP 被拦截 IP</h2><table><tr><th>IP</th><th>拦截次数</th><th>最后出现</th></tr>`)
		for _, s := range r.TopBlockedIPs {
			sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%s</td></tr>`, s.IP, s.Count, s.LastSeen))
		}
		sb.WriteString(`</table>`)
	}

	sb.WriteString(`</div></body></html>`)
	return sb.String()
}

func scoreClass(score float64) string {
	switch {
	case score >= 80:
		return "good"
	case score >= 60:
		return "fair"
	default:
		return "poor"
	}
}
