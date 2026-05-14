package store

import (
	"encoding/json"
	"time"
)

type Snapshot struct {
	ID           int64     `json:"id"`
	Description  string    `json:"description"`
	SnapshotJSON string    `json:"snapshot_json"`
	RulesCount   int       `json:"rules_count"`
	Auto         bool      `json:"auto"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s *Store) CreateSnapshot(desc string, data interface{}, auto bool) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	autoInt := 0
	if auto {
		autoInt = 1
	}
	_, err = s.db.Exec(
		"INSERT INTO threat_intel_snapshots (description, snapshot_json, rules_count, auto) VALUES (?, ?, 0, ?)",
		desc, string(jsonData), autoInt,
	)
	return err
}

func (s *Store) ListSnapshots(limit, offset int) ([]Snapshot, error) {
	rows, err := s.db.Query(
		"SELECT id, description, snapshot_json, rules_count, auto, created_at FROM threat_intel_snapshots ORDER BY created_at DESC LIMIT ? OFFSET ?",
		limit, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []Snapshot
	for rows.Next() {
		var snap Snapshot
		var autoInt int
		if err := rows.Scan(&snap.ID, &snap.Description, &snap.SnapshotJSON, &snap.RulesCount, &autoInt, &snap.CreatedAt); err != nil {
			return nil, err
		}
		snap.Auto = autoInt == 1
		snapshots = append(snapshots, snap)
	}
	return snapshots, rows.Err()
}

func (s *Store) GetSnapshot(id int) (*Snapshot, error) {
	var snap Snapshot
	var autoInt int
	err := s.db.QueryRow(
		"SELECT id, description, snapshot_json, rules_count, auto, created_at FROM threat_intel_snapshots WHERE id = ?",
		id,
	).Scan(&snap.ID, &snap.Description, &snap.SnapshotJSON, &snap.RulesCount, &autoInt, &snap.CreatedAt)
	if err != nil {
		return nil, err
	}
	snap.Auto = autoInt == 1
	return &snap, nil
}

type InstanceInfo struct {
	InstanceID string    `json:"instance_id"`
	Hostname   string    `json:"hostname"`
	Version    string    `json:"version"`
	LastSeen   time.Time `json:"last_seen"`
	Status     string    `json:"status"`
}

func (s *Store) SaveInstance(inst *InstanceInfo) error {
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_instances (instance_id, hostname, version, last_seen, status)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(instance_id) DO UPDATE SET
			hostname=excluded.hostname,
			version=excluded.version,
			last_seen=excluded.last_seen,
			status=excluded.status`,
		inst.InstanceID, inst.Hostname, inst.Version, inst.LastSeen, inst.Status,
	)
	return err
}

func (s *Store) GetInstances() ([]InstanceInfo, error) {
	rows, err := s.db.Query("SELECT instance_id, hostname, version, last_seen, status FROM threat_intel_instances")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var instances []InstanceInfo
	for rows.Next() {
		var inst InstanceInfo
		if err := rows.Scan(&inst.InstanceID, &inst.Hostname, &inst.Version, &inst.LastSeen, &inst.Status); err != nil {
			return nil, err
		}
		instances = append(instances, inst)
	}
	return instances, rows.Err()
}
