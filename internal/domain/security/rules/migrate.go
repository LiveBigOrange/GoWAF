package rules

import (
	"database/sql"
)

var allowedMigrateTables = map[string]bool{
	"ip_blacklist": true, "ip_whitelist": true, "ua_blacklist": true, "ua_whitelist": true,
	"path_blacklist": true, "path_whitelist": true,
	"ip_rules": true, "ua_rules": true, "path_rules": true, "geo_rules": true,
	"path_rate_limits": true, "allowed_methods": true,
}

var allowedMigrateColumns = map[string]bool{
	"expire_at": true, "reason": true, "detail": true, "country": true,
	"category": true, "is_regex": true, "enabled": true,
	"description": true, "match_type": true,
	"source": true, "intel_rule_id": true, "intel_category": true,
}

func migrateColumn(db *sql.DB, table, column, definition string) {
	if !allowedMigrateTables[table] || !allowedMigrateColumns[column] {
		return
	}
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, dfltValue, pk interface{}
		rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		if name == column {
			return
		}
	}
	db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition)
}
