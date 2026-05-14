package store

func (s *Store) AddConnectionLog(eventType, detail string) error {
	_, err := s.db.Exec(
		"INSERT INTO threat_intel_connection_log (event_type, detail) VALUES (?, ?)",
		eventType, detail,
	)
	return err
}

type ConnectionLogEntry struct {
	ID        int64  `json:"id"`
	EventType string `json:"event_type"`
	Detail    string `json:"detail"`
	CreatedAt string `json:"created_at"`
}

func (s *Store) QueryConnectionLogs(limit int) ([]ConnectionLogEntry, error) {
	rows, err := s.db.Query(
		"SELECT id, event_type, detail, created_at FROM threat_intel_connection_log ORDER BY created_at DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []ConnectionLogEntry
	for rows.Next() {
		var e ConnectionLogEntry
		if err := rows.Scan(&e.ID, &e.EventType, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
