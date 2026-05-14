package store

import "time"

type UploadQueueItem struct {
	ID                  int64     `json:"id"`
	DataType            string    `json:"data_type"`
	PayloadJSON         string    `json:"payload_json"`
	OriginalPayloadJSON string    `json:"original_payload_json,omitempty"`
	Status              string    `json:"status"`
	SensitiveRisk       int       `json:"sensitive_risk"`
	AuditNote           string    `json:"audit_note,omitempty"`
	ApprovedBy          string    `json:"approved_by,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

func (s *Store) EnqueueUpload(item *UploadQueueItem) error {
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_upload_queue (data_type, payload_json, original_payload_json, status, sensitive_risk)
		 VALUES (?, ?, ?, ?, ?)`,
		item.DataType, item.PayloadJSON, item.OriginalPayloadJSON, item.Status, item.SensitiveRisk,
	)
	return err
}

func (s *Store) GetPendingUploads(dataType string, limit int) ([]UploadQueueItem, error) {
	rows, err := s.db.Query(
		"SELECT id, data_type, payload_json, original_payload_json, status, sensitive_risk, audit_note, approved_by, created_at FROM threat_intel_upload_queue WHERE data_type = ? AND status IN ('pending', 'approved') ORDER BY created_at ASC LIMIT ?",
		dataType, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []UploadQueueItem
	for rows.Next() {
		var item UploadQueueItem
		if err := rows.Scan(&item.ID, &item.DataType, &item.PayloadJSON, &item.OriginalPayloadJSON,
			&item.Status, &item.SensitiveRisk, &item.AuditNote, &item.ApprovedBy, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateUploadStatus(id int64, status string, note string) error {
	_, err := s.db.Exec(
		"UPDATE threat_intel_upload_queue SET status = ?, audit_note = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		status, note, id,
	)
	return err
}

func (s *Store) DeleteProcessedUploads(before time.Time) error {
	_, err := s.db.Exec(
		"DELETE FROM threat_intel_upload_queue WHERE status IN ('sent', 'rejected') AND updated_at < ?",
		before,
	)
	return err
}
