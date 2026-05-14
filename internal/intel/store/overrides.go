package store

type RuleOverride struct {
	ID        int    `json:"id"`
	IntelID   string `json:"intel_id"`
	DataType  string `json:"data_type"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	CreatedBy string `json:"created_by"`
}

func (s *Store) AddOverride(override *RuleOverride) error {
	_, err := s.db.Exec(
		"INSERT INTO threat_intel_overrides (intel_id, data_type, action, reason, created_by) VALUES (?, ?, ?, ?, ?)",
		override.IntelID, override.DataType, override.Action, override.Reason, override.CreatedBy,
	)
	return err
}

func (s *Store) GetOverrides() ([]RuleOverride, error) {
	rows, err := s.db.Query("SELECT id, intel_id, data_type, action, reason, created_by FROM threat_intel_overrides")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var overrides []RuleOverride
	for rows.Next() {
		var o RuleOverride
		if err := rows.Scan(&o.ID, &o.IntelID, &o.DataType, &o.Action, &o.Reason, &o.CreatedBy); err != nil {
			return nil, err
		}
		overrides = append(overrides, o)
	}
	return overrides, rows.Err()
}

func (s *Store) DeleteOverride(id int) error {
	_, err := s.db.Exec("DELETE FROM threat_intel_overrides WHERE id = ?", id)
	return err
}

func (s *Store) GetOverride(intelID, dataType string) (*RuleOverride, error) {
	var o RuleOverride
	err := s.db.QueryRow(
		"SELECT id, intel_id, data_type, action, reason, created_by FROM threat_intel_overrides WHERE intel_id = ? AND data_type = ?",
		intelID, dataType,
	).Scan(&o.ID, &o.IntelID, &o.DataType, &o.Action, &o.Reason, &o.CreatedBy)
	if err != nil {
		return nil, err
	}
	return &o, nil
}
