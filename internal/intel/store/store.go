package store

import (
	"database/sql"
	"fmt"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) (*Store, error) {
	s := &Store{db: db}
	if err := s.InitSchema(); err != nil {
		return nil, fmt.Errorf("failed to init intel schema: %w", err)
	}
	return s, nil
}

func (s *Store) InitSchema() error {
	schemas := []string{
		sqlIntelConfig,
		sqlIntelState,
		sqlIntelSyncLog,
		sqlIntelUploadQueue,
		sqlIntelUploadLog,
		sqlIntelCredits,
		sqlIntelEmergency,
		sqlIntelOverrides,
		sqlIntelExclusions,
		sqlIntelFalsePositives,
		sqlIntelConnectionLog,
		sqlIntelSnapshots,
		sqlIntelInstances,
	}

	for _, schema := range schemas {
		if _, err := s.db.Exec(schema); err != nil {
			return fmt.Errorf("failed to execute schema: %w", err)
		}
	}
	return nil
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

const sqlIntelConfig = `
CREATE TABLE IF NOT EXISTS threat_intel_config (
    id INTEGER PRIMARY KEY CHECK(id=1),
    server_url TEXT NOT NULL DEFAULT '',
    license_key_encrypted TEXT NOT NULL DEFAULT '',
    license_tier TEXT NOT NULL DEFAULT '',
    license_status TEXT NOT NULL DEFAULT 'unknown',
    license_expires_at DATETIME,
    upload_enabled INTEGER NOT NULL DEFAULT 0,
    upload_data_types TEXT NOT NULL DEFAULT '[]',
    sync_enabled INTEGER NOT NULL DEFAULT 1,
    sync_data_types TEXT NOT NULL DEFAULT '[]',
    mask_level TEXT NOT NULL DEFAULT 'standard',
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelState = `
CREATE TABLE IF NOT EXISTS threat_intel_state (
    data_type TEXT PRIMARY KEY,
    current_version TEXT NOT NULL DEFAULT '',
    last_full_sync_at DATETIME,
    last_incremental_sync_at DATETIME,
    items_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending'
)`

const sqlIntelSyncLog = `
CREATE TABLE IF NOT EXISTS threat_intel_sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_type TEXT NOT NULL,
    action TEXT NOT NULL,
    added_count INTEGER NOT NULL DEFAULT 0,
    modified_count INTEGER NOT NULL DEFAULT 0,
    deleted_count INTEGER NOT NULL DEFAULT 0,
    skipped_count INTEGER NOT NULL DEFAULT 0,
    version_from TEXT,
    version_to TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    error_msg TEXT,
    duration_ms INTEGER NOT NULL DEFAULT 0,
    detail_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelUploadQueue = `
CREATE TABLE IF NOT EXISTS threat_intel_upload_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    original_payload_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    sensitive_risk INTEGER NOT NULL DEFAULT 0,
    audit_note TEXT,
    approved_by TEXT,
    approved_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelUploadLog = `
CREATE TABLE IF NOT EXISTS threat_intel_upload_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data_type TEXT NOT NULL,
    items_count INTEGER NOT NULL,
    accepted_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    credits_awarded INTEGER NOT NULL DEFAULT 0,
    quality_score REAL NOT NULL DEFAULT 0,
    success INTEGER NOT NULL DEFAULT 1,
    error_msg TEXT,
    response_json TEXT,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelCredits = `
CREATE TABLE IF NOT EXISTS threat_intel_credits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    reference TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelEmergency = `
CREATE TABLE IF NOT EXISTS threat_intel_emergency (
    intel_id TEXT PRIMARY KEY,
    data_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'high',
    reason TEXT,
    expires_at DATETIME,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelOverrides = `
CREATE TABLE IF NOT EXISTS threat_intel_overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    intel_id TEXT NOT NULL,
    data_type TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT,
    created_by TEXT,
    expires_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(intel_id, data_type)
)`

const sqlIntelExclusions = `
CREATE TABLE IF NOT EXISTS threat_intel_exclusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    match_type TEXT NOT NULL,
    pattern TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelFalsePositives = `
CREATE TABLE IF NOT EXISTS threat_intel_false_positives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    intel_rule_id TEXT,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    submit_result TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelConnectionLog = `
CREATE TABLE IF NOT EXISTS threat_intel_connection_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    detail TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelSnapshots = `
CREATE TABLE IF NOT EXISTS threat_intel_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    description TEXT NOT NULL DEFAULT '',
    snapshot_json TEXT NOT NULL,
    rules_count INTEGER NOT NULL DEFAULT 0,
    auto INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`

const sqlIntelInstances = `
CREATE TABLE IF NOT EXISTS threat_intel_instances (
    instance_id TEXT PRIMARY KEY,
    hostname TEXT,
    version TEXT,
    last_seen DATETIME,
    status TEXT DEFAULT 'unknown'
)`
