package store

import (
	"database/sql"
	"time"
)

type SyncState struct {
	DataType              string     `json:"data_type"`
	CurrentVersion        string     `json:"current_version"`
	LastFullSyncAt        *time.Time `json:"last_full_sync_at"`
	LastIncrementalSyncAt *time.Time `json:"last_incremental_sync_at"`
	ItemsCount            int        `json:"items_count"`
	Status                string     `json:"status"`
}

func (s *Store) GetState(dataType string) (*SyncState, error) {
	var state SyncState
	err := s.db.QueryRow(
		"SELECT data_type, current_version, last_full_sync_at, last_incremental_sync_at, items_count, status FROM threat_intel_state WHERE data_type = ?",
		dataType,
	).Scan(&state.DataType, &state.CurrentVersion, &state.LastFullSyncAt, &state.LastIncrementalSyncAt, &state.ItemsCount, &state.Status)
	if err == sql.ErrNoRows {
		return &SyncState{DataType: dataType, Status: "pending"}, nil
	}
	if err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *Store) SaveState(state *SyncState) error {
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_state (data_type, current_version, last_full_sync_at, last_incremental_sync_at, items_count, status)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(data_type) DO UPDATE SET
			current_version=excluded.current_version,
			last_full_sync_at=excluded.last_full_sync_at,
			last_incremental_sync_at=excluded.last_incremental_sync_at,
			items_count=excluded.items_count,
			status=excluded.status`,
		state.DataType, state.CurrentVersion, state.LastFullSyncAt, state.LastIncrementalSyncAt, state.ItemsCount, state.Status,
	)
	return err
}

func (s *Store) GetAllStates() ([]SyncState, error) {
	rows, err := s.db.Query("SELECT data_type, current_version, last_full_sync_at, last_incremental_sync_at, items_count, status FROM threat_intel_state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var states []SyncState
	for rows.Next() {
		var st SyncState
		if err := rows.Scan(&st.DataType, &st.CurrentVersion, &st.LastFullSyncAt, &st.LastIncrementalSyncAt, &st.ItemsCount, &st.Status); err != nil {
			return nil, err
		}
		states = append(states, st)
	}
	return states, rows.Err()
}
