package store

import (
	"database/sql"
	"time"
)

type SyncLogEntry struct {
	ID            int64     `json:"id"`
	DataType      string    `json:"data_type"`
	Action        string    `json:"action"`
	AddedCount    int       `json:"added_count"`
	ModifiedCount int       `json:"modified_count"`
	DeletedCount  int       `json:"deleted_count"`
	SkippedCount  int       `json:"skipped_count"`
	VersionFrom   string    `json:"version_from"`
	VersionTo     string    `json:"version_to"`
	Success       bool      `json:"success"`
	ErrorMsg      string    `json:"error_msg"`
	DurationMs    int       `json:"duration_ms"`
	DetailJSON    string    `json:"detail_json"`
	CreatedAt     time.Time `json:"created_at"`
}

func (s *Store) AddSyncLog(entry *SyncLogEntry) error {
	successInt := 0
	if entry.Success {
		successInt = 1
	}
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_sync_log (data_type, action, added_count, modified_count, deleted_count, skipped_count, version_from, version_to, success, error_msg, duration_ms, detail_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.DataType, entry.Action, entry.AddedCount, entry.ModifiedCount, entry.DeletedCount, entry.SkippedCount,
		entry.VersionFrom, entry.VersionTo, successInt, entry.ErrorMsg, entry.DurationMs, entry.DetailJSON,
	)
	return err
}

type SyncLogFilter struct {
	DataType string
	Limit    int
	Offset   int
}

func (s *Store) QuerySyncLogs(filter SyncLogFilter) ([]SyncLogEntry, error) {
	query := "SELECT id, data_type, action, added_count, modified_count, deleted_count, skipped_count, version_from, version_to, success, error_msg, duration_ms, detail_json, created_at FROM threat_intel_sync_log"
	var args []interface{}

	if filter.DataType != "" {
		query += " WHERE data_type = ?"
		args = append(args, filter.DataType)
	}

	query += " ORDER BY created_at DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []SyncLogEntry
	for rows.Next() {
		var e SyncLogEntry
		var successInt int
		var errorMsg sql.NullString
		var detailJSON sql.NullString
		if err := rows.Scan(&e.ID, &e.DataType, &e.Action, &e.AddedCount, &e.ModifiedCount, &e.DeletedCount, &e.SkippedCount,
			&e.VersionFrom, &e.VersionTo, &successInt, &errorMsg, &e.DurationMs, &detailJSON, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Success = successInt == 1
		e.ErrorMsg = errorMsg.String
		e.DetailJSON = detailJSON.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}
