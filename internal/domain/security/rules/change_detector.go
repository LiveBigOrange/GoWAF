package rules

import (
	"database/sql"
	"sync"
)

type ruleChangeDetector struct {
	db          *sql.DB
	lastVersion int64
	mu          sync.Mutex
}

func newRuleChangeDetector(db *sql.DB) *ruleChangeDetector {
	return &ruleChangeDetector{db: db}
}

func (d *ruleChangeDetector) hasRuleChanged() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	var maxVer int64
	err := d.db.QueryRow("SELECT COALESCE(MAX(id),0) FROM config_versions").Scan(&maxVer)
	if err != nil {
		return true
	}
	if maxVer != d.lastVersion {
		d.lastVersion = maxVer
		return true
	}
	return false
}
