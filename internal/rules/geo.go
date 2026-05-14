package rules

import (
	"strings"
)

// ----------------- GeoIP 规则 -----------------

func (e *Engine) buildGeoRules() (map[string]bool, string) {
	geoBlockCountries := make(map[string]bool)
	rows, err := e.db.Query("SELECT mode, country_code FROM geo_rules WHERE enabled = 1")
	if err != nil {
		return geoBlockCountries, "blacklist"
	}
	defer rows.Close()

	mode := ""
	for rows.Next() {
		var m, code string
		if err := rows.Scan(&m, &code); err != nil {
			continue
		}
		if mode == "" {
			mode = m
		}
		if m != mode {
			continue
		}
		geoBlockCountries[strings.ToUpper(code)] = true
	}
	if mode == "" {
		mode = "blacklist"
	}
	return geoBlockCountries, mode
}

func (e *Engine) IsGeoBlocked(countryCode string) RuleMatchResult {
	snap := e.loadSnapshot()

	if len(snap.geoBlockCountries) == 0 {
		return RuleMatchResult{}
	}

	code := strings.ToUpper(countryCode)
	if snap.geoMode == "whitelist" {
		_, ok := snap.geoBlockCountries[code]
		if !ok {
			return RuleMatchResult{
				Matched:   true,
				RuleType:  "geo_whitelist",
				Pattern:   code,
				MatchType: "whitelist",
				Detail:    "GeoIP白名单阻断: " + code,
			}
		}
		return RuleMatchResult{}
	}
	_, ok := snap.geoBlockCountries[code]
	if ok {
		return RuleMatchResult{
			Matched:   true,
			RuleType:  "geo_blacklist",
			Pattern:   code,
			MatchType: "blacklist",
			Detail:    "GeoIP黑名单阻断: " + code,
		}
	}
	return RuleMatchResult{}
}

type GeoRuleRow struct {
	ID          int    `json:"id"`
	Mode        string `json:"mode"`
	CountryCode string `json:"country_code"`
	Enabled     bool   `json:"enabled"`
}

func (e *Engine) AddGeoRule(mode, countryCode string, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("INSERT OR IGNORE INTO geo_rules(mode, country_code, enabled) VALUES(?,?,?)", mode, strings.ToUpper(countryCode), enc)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) UpdateGeoRule(id int, mode, countryCode string, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("UPDATE geo_rules SET mode=?, country_code=?, enabled=? WHERE id=?", mode, strings.ToUpper(countryCode), enc, id)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) RemoveGeoRule(id int) error {
	_, err := e.db.Exec("DELETE FROM geo_rules WHERE id=?", id)
	if err != nil {
		return err
	}
	e.loadAllRules()
	return nil
}

func (e *Engine) ListGeoRules() ([]GeoRuleRow, error) {
	rows, err := e.db.Query("SELECT id, mode, country_code, enabled FROM geo_rules ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []GeoRuleRow
	for rows.Next() {
		var r GeoRuleRow
		var enc int
		if err := rows.Scan(&r.ID, &r.Mode, &r.CountryCode, &enc); err == nil {
			r.Enabled = enc == 1
			rules = append(rules, r)
		}
	}
	return rules, nil
}
