package store

import (
	"database/sql"
	"time"
)

type UploadLogEntry struct {
	ID             int64     `json:"id"`
	DataType       string    `json:"data_type"`
	ItemsCount     int       `json:"items_count"`
	AcceptedCount  int       `json:"accepted_count"`
	RejectedCount  int       `json:"rejected_count"`
	CreditsAwarded int       `json:"credits_awarded"`
	QualityScore   float64   `json:"quality_score"`
	Success        bool      `json:"success"`
	ErrorMsg       string    `json:"error_msg"`
	UploadedAt     time.Time `json:"uploaded_at"`
}

func (s *Store) AddUploadLog(entry *UploadLogEntry) error {
	successInt := 0
	if entry.Success {
		successInt = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_upload_log (data_type, items_count, accepted_count, rejected_count, credits_awarded, quality_score, success, error_msg)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.DataType, entry.ItemsCount, entry.AcceptedCount, entry.RejectedCount,
		entry.CreditsAwarded, entry.QualityScore, successInt, entry.ErrorMsg,
	)
	return err
}

type UploadLogFilter struct {
	DataType string
	Limit    int
	Offset   int
}

func (s *Store) QueryUploadLogs(filter UploadLogFilter) ([]UploadLogEntry, error) {
	query := "SELECT id, data_type, items_count, accepted_count, rejected_count, credits_awarded, quality_score, success, error_msg, uploaded_at FROM threat_intel_upload_log"
	var args []interface{}

	if filter.DataType != "" {
		query += " WHERE data_type = ?"
		args = append(args, filter.DataType)
	}

	query += " ORDER BY uploaded_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []UploadLogEntry
	for rows.Next() {
		var e UploadLogEntry
		var successInt int
		var errorMsg sql.NullString
		if err := rows.Scan(&e.ID, &e.DataType, &e.ItemsCount, &e.AcceptedCount, &e.RejectedCount,
			&e.CreditsAwarded, &e.QualityScore, &successInt, &errorMsg, &e.UploadedAt); err != nil {
			return nil, err
		}
		e.Success = successInt == 1
		e.ErrorMsg = errorMsg.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
