package store

type CreditsEntry struct {
	Amount      int    `json:"amount"`
	Type        string `json:"type"`
	Reference   string `json:"reference"`
	Description string `json:"description"`
}

func (s *Store) AddCredits(entry *CreditsEntry) error {
	_, err := s.db.Exec(
		"INSERT INTO threat_intel_credits (amount, type, reference, description) VALUES (?, ?, ?, ?)",
		entry.Amount, entry.Type, entry.Reference, entry.Description,
	)
	return err
}

func (s *Store) GetCreditBalance() (int, error) {
	var balance int
	err := s.db.QueryRow("SELECT COALESCE(SUM(amount), 0) FROM threat_intel_credits").Scan(&balance)
	return balance, err
}
