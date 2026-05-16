package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// ----------------- UA 规则 -----------------

func (e *Engine) buildUARules() ([]uaRule, []uaRule) {
	rows, err := e.db.Query("SELECT rule_type, match_type, pattern FROM ua_rules WHERE enabled=1")
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	var whitelist, blacklist []uaRule
	for rows.Next() {
		var ruleType, matchType, pattern string
		if err := rows.Scan(&ruleType, &matchType, &pattern); err != nil {
			continue
		}
		rule := uaRule{Pattern: pattern, MatchType: matchType}
		if matchType == "regex" {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			rule.Regex = re
		}
		if ruleType == "whitelist" {
			whitelist = append(whitelist, rule)
		} else {
			blacklist = append(blacklist, rule)
		}
	}
	return whitelist, blacklist
}

func (e *Engine) CheckUA(userAgent string) RuleMatchResult {
	snap := e.loadSnapshot()

	matchRule := func(rule uaRule, ua string) bool {
		if rule.Regex != nil {
			return rule.Regex.MatchString(ua)
		}
		switch rule.MatchType {
		case "contains":
			return strings.Contains(ua, rule.Pattern)
		case "exact":
			return rule.Pattern == ua
		default:
			return rule.Pattern == ua
		}
	}

	for _, rule := range snap.uaWhitelist {
		if matchRule(rule, userAgent) {
			return RuleMatchResult{}
		}
	}
	for _, rule := range snap.uaBlacklist {
		if matchRule(rule, userAgent) {
			return RuleMatchResult{
				Matched:   true,
				RuleType:  "ua_blacklist",
				Pattern:   rule.Pattern,
				MatchType: rule.MatchType,
				Detail:    "UA黑名单匹配[" + rule.MatchType + "]: " + rule.Pattern,
			}
		}
	}
	return RuleMatchResult{}
}

func (e *Engine) AddUARule(ruleType, matchType, pattern, description string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO ua_rules(rule_type, match_type, pattern, description) VALUES(?,?,?,?)",
		ruleType, matchType, pattern, description)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) RemoveUARule(ruleType, pattern string) error {
	_, err := e.db.Exec("DELETE FROM ua_rules WHERE rule_type=? AND pattern=?", ruleType, pattern)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) ListUARules() ([]UARuleRow, error) {
	rows, err := e.db.Query("SELECT id, rule_type, match_type, pattern, COALESCE(description,''), enabled, COALESCE(source,'manual'), COALESCE(intel_rule_id,'') FROM ua_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []UARuleRow
	for rows.Next() {
		var r UARuleRow
		var enabledInt int
		if err := rows.Scan(&r.ID, &r.RuleType, &r.MatchType, &r.Pattern, &r.Description, &enabledInt, &r.Source, &r.IntelID); err != nil {
			return nil, fmt.Errorf("scan ua rule row: %w", err)
		}
		r.Enabled = enabledInt == 1
		switch r.Source {
		case "local":
			r.Source = "manual"
		case "intel-bot", "intel-sig":
			r.Source = "intel"
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (e *Engine) UpdateUARule(id int, ruleType, matchType, pattern, description string, enabled bool) error {
	_, err := e.db.Exec("UPDATE ua_rules SET rule_type=?, match_type=?, pattern=?, description=?, enabled=? WHERE id=?",
		ruleType, matchType, pattern, description, enabled, id)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) ToggleUARule(id int) error {
	_, err := e.db.Exec("UPDATE ua_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?", id)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

// AddUARuleWithSource 添加UA规则（带来源信息）
func (e *Engine) AddUARuleWithSource(ruleType, matchType, pattern, source, intelID string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO ua_rules(rule_type, match_type, pattern, source, intel_rule_id) VALUES(?,?,?,?,?)", ruleType, matchType, pattern, source, intelID)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

// RemoveUARuleByIntelID 根据IntelID删除UA规则
func (e *Engine) RemoveUARuleByIntelID(intelID string) {
	e.configMu.Lock()
	defer e.configMu.Unlock()
	e.db.Exec("DELETE FROM ua_rules WHERE intel_rule_id = ? AND source = 'intel'", intelID)
	newSnap := e.buildRuleSnapshot()
	e.snapshot.Store(newSnap)
}
