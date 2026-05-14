package store

type ExclusionRule struct {
	ID          int    `json:"id"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

func (s *Store) AddExclusion(excl *ExclusionRule) error {
	enabledInt := 0
	if excl.Enabled {
		enabledInt = 1
	}
	_, err := s.db.Exec(
		"INSERT INTO threat_intel_exclusions (match_type, pattern, enabled, description) VALUES (?, ?, ?, ?)",
		excl.MatchType, excl.Pattern, enabledInt, excl.Description,
	)
	return err
}

func (s *Store) GetExclusions() ([]ExclusionRule, error) {
	rows, err := s.db.Query("SELECT id, match_type, pattern, enabled, description FROM threat_intel_exclusions")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []ExclusionRule
	for rows.Next() {
		var r ExclusionRule
		var enabledInt int
		if err := rows.Scan(&r.ID, &r.MatchType, &r.Pattern, &enabledInt, &r.Description); err != nil {
			return nil, err
		}
		r.Enabled = enabledInt == 1
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) DeleteExclusion(id int) error {
	_, err := s.db.Exec("DELETE FROM threat_intel_exclusions WHERE id = ?", id)
	return err
}
