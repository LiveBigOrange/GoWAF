package store

type FalsePositiveRecord struct {
	ID          int64  `json:"id"`
	EventID     int64  `json:"event_id"`
	RuleID      string `json:"rule_id"`
	IntelRuleID string `json:"intel_rule_id"`
	Reason      string `json:"reason"`
	Status      string `json:"status"`
}

func (s *Store) AddFalsePositive(fp *FalsePositiveRecord) error {
	_, err := s.db.Exec(
		"INSERT INTO threat_intel_false_positives (event_id, rule_id, intel_rule_id, reason, status) VALUES (?, ?, ?, ?, ?)",
		fp.EventID, fp.RuleID, fp.IntelRuleID, fp.Reason, fp.Status,
	)
	return err
}

func (s *Store) UpdateFalsePositiveStatus(id int64, status string) error {
	_, err := s.db.Exec(
		"UPDATE threat_intel_false_positives SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		status, id,
	)
	return err
}
