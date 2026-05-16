package rules

import (
	"fmt"
	"regexp"
)

// ----------------- 路径规则 -----------------

func (e *Engine) buildPathRules() ([]pathRule, []pathRule) {
	rows, err := e.db.Query("SELECT rule_type, match_type, pattern FROM path_rules WHERE enabled=1")
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	var whitelist, blacklist []pathRule
	for rows.Next() {
		var ruleType, matchType, pattern string
		if err := rows.Scan(&ruleType, &matchType, &pattern); err != nil {
			continue
		}
		rule := pathRule{Pattern: pattern, MatchType: matchType}
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

func matchPath(path string, rule pathRule) bool {
	switch rule.MatchType {
	case "prefix":
		return len(path) >= len(rule.Pattern) && path[:len(rule.Pattern)] == rule.Pattern
	case "suffix":
		return len(path) >= len(rule.Pattern) && path[len(path)-len(rule.Pattern):] == rule.Pattern
	case "exact":
		return path == rule.Pattern
	case "contains":
		for i := 0; i <= len(path)-len(rule.Pattern); i++ {
			if path[i:i+len(rule.Pattern)] == rule.Pattern {
				return true
			}
		}
		return false
	case "regex":
		if rule.Regex != nil {
			return rule.Regex.MatchString(path)
		}
		return false
	default:
		return len(path) >= len(rule.Pattern) && path[:len(rule.Pattern)] == rule.Pattern
	}
}

func (e *Engine) CheckPath(path string) RuleMatchResult {
	snap := e.loadSnapshot()

	for _, rule := range snap.pathWhitelist {
		if matchPath(path, rule) {
			return RuleMatchResult{}
		}
	}
	for _, rule := range snap.pathBlacklist {
		if matchPath(path, rule) {
			return RuleMatchResult{
				Matched:   true,
				RuleType:  "path_blacklist",
				Pattern:   rule.Pattern,
				MatchType: rule.MatchType,
				Detail:    "路径黑名单匹配[" + rule.MatchType + "]: " + rule.Pattern,
			}
		}
	}
	return RuleMatchResult{}
}

func (e *Engine) AddPathRule(ruleType, matchType, pattern, description string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO path_rules(rule_type, match_type, pattern, description) VALUES(?,?,?,?)", ruleType, matchType, pattern, description)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) RemovePathRule(ruleType, pattern string) error {
	_, err := e.db.Exec("DELETE FROM path_rules WHERE rule_type=? AND pattern=?", ruleType, pattern)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) ListPathRules() ([]PathRuleRow, error) {
	rows, err := e.db.Query("SELECT id, rule_type, match_type, pattern, COALESCE(description,''), enabled, COALESCE(source,'manual'), COALESCE(intel_rule_id,'') FROM path_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PathRuleRow
	for rows.Next() {
		var r PathRuleRow
		var enabledInt int
		if err := rows.Scan(&r.ID, &r.RuleType, &r.MatchType, &r.Pattern, &r.Description, &enabledInt, &r.Source, &r.IntelID); err != nil {
			return nil, fmt.Errorf("scan path rule row: %w", err)
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

func (e *Engine) UpdatePathRule(id int, ruleType, matchType, pattern, description string, enabled bool) error {
	_, err := e.db.Exec("UPDATE path_rules SET rule_type=?, match_type=?, pattern=?, description=?, enabled=? WHERE id=?",
		ruleType, matchType, pattern, description, enabled, id)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) TogglePathRule(id int) error {
	_, err := e.db.Exec("UPDATE path_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id=?", id)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

// AddPathRuleWithSource 添加路径规则（带来源信息）
func (e *Engine) AddPathRuleWithSource(ruleType, matchType, pattern, source, intelID string) error {
	_, err := e.db.Exec("INSERT OR IGNORE INTO path_rules(rule_type, match_type, pattern, source, intel_rule_id) VALUES(?,?,?,?,?)", ruleType, matchType, pattern, source, intelID)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

// RemovePathRuleByIntelID 根据IntelID删除路径规则
func (e *Engine) RemovePathRuleByIntelID(intelID string) {
	e.configMu.Lock()
	defer e.configMu.Unlock()
	e.db.Exec("DELETE FROM path_rules WHERE intel_rule_id = ? AND source = 'intel'", intelID)
	newSnap := e.buildRuleSnapshot()
	e.snapshot.Store(newSnap)
}
