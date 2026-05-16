package rules

import (
	"net"
)

// ----------------- IP 规则 -----------------

func (e *Engine) buildIPRules() ([]ipEntry, []ipEntry, map[string]bool, map[string]bool) {
	rows, err := e.db.Query("SELECT rule_type, ip FROM ip_rules WHERE enabled=1")
	if err != nil {
		return nil, nil, nil, nil
	}
	defer rows.Close()

	var blackEntries, whiteEntries []ipEntry
	blackExact := make(map[string]bool)
	whiteExact := make(map[string]bool)
	for rows.Next() {
		var ruleType, ip string
		if err := rows.Scan(&ruleType, &ip); err != nil {
			continue
		}
		entry := ipEntry{original: ip}
		if _, cidr, err := net.ParseCIDR(ip); err == nil {
			entry.cidr = cidr
			entry.isCIDR = true
		}
		if ruleType == "blacklist" {
			if entry.isCIDR {
				blackEntries = append(blackEntries, entry)
			} else {
				blackExact[ip] = true
			}
		} else if ruleType == "whitelist" {
			if entry.isCIDR {
				whiteEntries = append(whiteEntries, entry)
			} else {
				whiteExact[ip] = true
			}
		}
	}
	return blackEntries, whiteEntries, blackExact, whiteExact
}

func (e *Engine) IsIPBlocked(ipStr string) RuleMatchResult {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return RuleMatchResult{}
	}
	snap := e.loadSnapshot()
	if snap.whiteIPExact[ipStr] {
		return RuleMatchResult{}
	}
	for _, entry := range snap.whiteIPs {
		if entry.cidr.Contains(ip) {
			return RuleMatchResult{}
		}
	}
	if snap.blackIPExact[ipStr] {
		return RuleMatchResult{
			Matched:   true,
			RuleType:  "ip_blacklist",
			Pattern:   ipStr,
			MatchType: "exact",
			Detail:    "IP黑名单匹配: " + ipStr,
		}
	}
	for _, entry := range snap.blackIPs {
		if entry.cidr.Contains(ip) {
			return RuleMatchResult{
				Matched:   true,
				RuleType:  "ip_blacklist",
				Pattern:   entry.original,
				MatchType: "cidr",
				Detail:    "IP黑名单匹配: " + entry.original,
			}
		}
	}
	return RuleMatchResult{}
}

// IPRuleRow IP规则行
type IPRuleRow struct {
	RuleType string `json:"rule_type"`
	IP       string `json:"ip"`
	Enabled  bool   `json:"enabled"`
	Source   string `json:"source"`
	IntelID  string `json:"intel_id,omitempty"`
}

// SetIPRuleEnabled 启用/禁用IP规则
func (e *Engine) SetIPRuleEnabled(ruleType, ip string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := e.db.Exec("UPDATE ip_rules SET enabled=? WHERE rule_type=? AND ip=?", v, ruleType, ip)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

// AddIPRule 添加IP规则（自动合并相邻IP为CIDR）
func (e *Engine) AddIPRule(ruleType, ip string) error {
	result, err := e.db.Exec("INSERT OR IGNORE INTO ip_rules(rule_type, ip) VALUES(?,?)", ruleType, ip)
	if err != nil {
		return err
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil
	}

	e.tryMergeIPRules(ruleType)
	return nil
}

func (e *Engine) tryMergeIPRules(ruleType string) {
	rows, err := e.db.Query("SELECT ip FROM ip_rules WHERE rule_type=? AND enabled=1", ruleType)
	if err != nil {
		return
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			ips = append(ips, ip)
		}
	}
	if err := rows.Err(); err != nil {
		return
	}
	if len(ips) <= 1 {
		return
	}

	merged := mergeIPsToCIDRs(ips)
	if len(merged) >= len(ips) {
		return
	}

	tx, err := e.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM ip_rules WHERE rule_type=?", ruleType); err != nil {
		return
	}
	for _, m := range merged {
		if _, err := tx.Exec("INSERT OR IGNORE INTO ip_rules(rule_type, ip) VALUES(?,?)", ruleType, m); err != nil {
			return
		}
	}
	tx.Commit()
	e.loadAllRules()
}

// RemoveIPRule 删除IP规则
func (e *Engine) RemoveIPRule(ruleType, ip string) error {
	_, err := e.db.Exec("DELETE FROM ip_rules WHERE rule_type=? AND ip=?", ruleType, ip)
	if err != nil {
		return err
	}
	e.loadAllRules()
	e.tryMergeIPRules(ruleType)
	return nil
}

// ListIPRules 列出所有IP规则
func (e *Engine) ListIPRules() ([]IPRuleRow, error) {
	rows, err := e.db.Query("SELECT rule_type, ip, enabled, COALESCE(source,'manual'), COALESCE(intel_rule_id,'') FROM ip_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []IPRuleRow
	for rows.Next() {
		var r IPRuleRow
		var enabled int
		if err := rows.Scan(&r.RuleType, &r.IP, &enabled, &r.Source, &r.IntelID); err == nil {
			r.Enabled = enabled == 1
			switch r.Source {
			case "local":
				r.Source = "manual"
			case "intel-bot", "intel-sig":
				r.Source = "intel"
			}
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// 保留旧方法以兼容
func (e *Engine) AddIP(ip string) error {
	return e.AddIPRule("blacklist", ip)
}

func (e *Engine) RemoveIP(ip string) error {
	return e.RemoveIPRule("blacklist", ip)
}

func (e *Engine) ListIPs() ([]string, error) {
	rules, err := e.ListIPRules()
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, r := range rules {
		if r.RuleType == "blacklist" {
			ips = append(ips, r.IP)
		}
	}
	return ips, nil
}

// AddIPRuleWithSource 添加IP规则（带来源信息）
func (e *Engine) AddIPRuleWithSource(ruleType, ip, source, intelID string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO ip_rules(rule_type, ip, source, intel_rule_id) VALUES(?,?,?,?)", ruleType, ip, source, intelID)
	if err != nil {
		return err
	}
	e.tryMergeIPRules(ruleType)
	return nil
}

// RemoveIPRuleByIntelID 根据IntelID删除IP规则
func (e *Engine) RemoveIPRuleByIntelID(intelID string) {
	e.configMu.Lock()
	defer e.configMu.Unlock()
	e.db.Exec("DELETE FROM ip_rules WHERE intel_rule_id = ? AND source = 'intel'", intelID)
	newSnap := e.buildRuleSnapshot()
	e.snapshot.Store(newSnap)
}
