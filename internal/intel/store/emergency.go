package store

type EmergencyRule struct {
	IntelID     string `json:"intel_id"`
	DataType    string `json:"data_type"`
	PayloadJSON string `json:"payload_json"`
	Severity    string `json:"severity"`
	Reason      string `json:"reason"`
	ExpiresAt   string `json:"expires_at"`
}

func (s *Store) SaveEmergencyRule(rule *EmergencyRule) error {
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_emergency (intel_id, data_type, payload_json, severity, reason, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(intel_id) DO UPDATE SET
			data_type=excluded.data_type,
			payload_json=excluded.payload_json,
			severity=excluded.severity,
			reason=excluded.reason,
			expires_at=excluded.expires_at`,
		rule.IntelID, rule.DataType, rule.PayloadJSON, rule.Severity, rule.Reason, rule.ExpiresAt,
	)
	return err
}

func (s *Store) GetActiveEmergencyRules() ([]EmergencyRule, error) {
	rows, err := s.db.Query(
		"SELECT intel_id, data_type, payload_json, severity, reason, expires_at FROM threat_intel_emergency WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []EmergencyRule
	for rows.Next() {
		var r EmergencyRule
		if err := rows.Scan(&r.IntelID, &r.DataType, &r.PayloadJSON, &r.Severity, &r.Reason, &r.ExpiresAt); err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

func (s *Store) DeleteExpiredEmergencyRules() error {
	_, err := s.db.Exec("DELETE FROM threat_intel_emergency WHERE expires_at IS NOT NULL AND expires_at <= CURRENT_TIMESTAMP")
	return err
}
