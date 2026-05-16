package rules

import (
	"strings"
)

// ----------------- HTTP 方法限制 -----------------

func (e *Engine) SetAllowedMethods(methods []string) {
	newMethods := make(map[string]bool)
	for _, m := range methods {
		newMethods[strings.ToUpper(m)] = true
	}
	e.updateSnapshot(func(cur *ruleSnapshot) *ruleSnapshot {
		newSnap := *cur
		newSnap.allowedMethods = newMethods
		return &newSnap
	})
}

func (e *Engine) IsMethodAllowed(method string) RuleMatchResult {
	snap := e.loadSnapshot()
	if len(snap.allowedMethods) == 0 {
		return RuleMatchResult{Matched: false}
	}
	if snap.allowedMethods[strings.ToUpper(method)] {
		return RuleMatchResult{Matched: false}
	}
	return RuleMatchResult{
		Matched:   true,
		RuleType:  "method_blocked",
		Pattern:   method,
		MatchType: "exact",
		Detail:    "HTTP方法限制: " + strings.ToUpper(method),
	}
}

func (e *Engine) buildAllowedMethods() map[string]bool {
	allowedMethods := make(map[string]bool)
	rows, err := e.db.Query("SELECT method FROM allowed_methods WHERE enabled = 1")
	if err != nil {
		return allowedMethods
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err == nil {
			allowedMethods[strings.ToUpper(m)] = true
		}
	}
	return allowedMethods
}

type AllowedMethodRow struct {
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Enabled bool   `json:"enabled"`
}

func (e *Engine) ListAllowedMethods() ([]AllowedMethodRow, error) {
	rows, err := e.db.Query("SELECT id, method, enabled FROM allowed_methods ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var methods []AllowedMethodRow
	for rows.Next() {
		var m AllowedMethodRow
		var enc int
		if err := rows.Scan(&m.ID, &m.Method, &enc); err == nil {
			m.Enabled = enc == 1
			methods = append(methods, m)
		}
	}
	return methods, nil
}

func (e *Engine) SetAllowedMethodDB(method string, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("INSERT OR REPLACE INTO allowed_methods(method, enabled) VALUES(?,?)", strings.ToUpper(method), enc)
	return err
}

func (e *Engine) RemoveAllowedMethodDB(method string) error {
	_, err := e.db.Exec("DELETE FROM allowed_methods WHERE method=?", strings.ToUpper(method))
	return err
}
