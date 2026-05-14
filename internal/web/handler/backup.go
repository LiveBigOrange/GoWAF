package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"gowaf/internal/logger"
)

var identifierPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

type backupData struct {
	Version   string                 `json:"version"`
	Timestamp string                 `json:"timestamp"`
	Configs   map[string]interface{} `json:"configs"`
}

func APIBackupConfig(w http.ResponseWriter, r *http.Request) {
	if deps.ConfigDB == nil {
		jsonError(w, "Config database not initialized", http.StatusInternalServerError)
		return
	}
	db := deps.ConfigDB

	backup := backupData{
		Version:   "1.0",
		Timestamp: time.Now().Format(time.RFC3339),
		Configs:   make(map[string]interface{}),
	}

	tables := []string{
		"ip_rules", "ua_rules", "path_rules", "geo_rules",
		"path_rate_limits", "allowed_methods", "proxy_config",
		"domain_config", "ssl_certs", "backends",
		"backend_groups", "backend_group_members",
		"detector_config", "detection_rules", "system_config",
		"users", "api_keys", "resp_header_rules", "req_header_rules",
		"dlp_rules", "api_schemas", "virtual_patches",
		"bot_rules", "bot_known_overrides", "bot_policy",
		"notify_config", "alert_rules", "config_versions",
		"session_alerts", "geoip_update_config", "path_body_limits",
	}

	for _, table := range tables {
		rows, err := db.Query("SELECT * FROM " + table)
		if err != nil {
			logger.Warn("backup query %s: %v", table, err)
			continue
		}
		cols, err := rows.Columns()
		if err != nil {
			logger.Warn("backup columns %s: %v", table, err)
			rows.Close()
			continue
		}
		var tableData []map[string]interface{}
		for rows.Next() {
			values := make([]interface{}, len(cols))
			valuePtrs := make([]interface{}, len(cols))
			for i := range values {
				valuePtrs[i] = &values[i]
			}
			if err := rows.Scan(valuePtrs...); err != nil {
				logger.Warn("backup scan %s: %v", table, err)
				continue
			}
			row := make(map[string]interface{})
			for i, col := range cols {
				row[col] = values[i]
			}
			if table == "system_config" {
				if keyVal, ok := row["key"]; ok {
					keyStr, _ := keyVal.(string)
					if keyStr == "admin_password_hash" || keyStr == "email_password" || keyStr == "webhook_secret" {
						row["value"] = "******"
					}
				}
			}
			tableData = append(tableData, row)
		}
		rows.Close()
		if tableData != nil {
			backup.Configs[table] = tableData
		}
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=gowaf_backup_%s.json", time.Now().Format("20060102150405")))
	jsonSuccess(w, backup)
}

func APIRestoreConfig(w http.ResponseWriter, r *http.Request) {
	if deps.ConfigDB == nil {
		jsonError(w, "Config database not initialized", http.StatusInternalServerError)
		return
	}
	db := deps.ConfigDB

	var backup backupData
	if err := json.NewDecoder(r.Body).Decode(&backup); err != nil {
		jsonError(w, "Invalid backup data: "+err.Error(), http.StatusBadRequest)
		return
	}

	tables := []string{
		"ip_rules", "ua_rules", "path_rules", "geo_rules",
		"path_rate_limits", "allowed_methods", "proxy_config",
		"domain_config", "ssl_certs", "backends",
		"backend_groups", "backend_group_members",
		"detector_config", "detection_rules", "system_config",
		"users", "api_keys", "resp_header_rules", "req_header_rules",
		"dlp_rules", "api_schemas", "virtual_patches",
		"bot_rules", "bot_known_overrides", "bot_policy",
		"notify_config", "alert_rules", "config_versions",
		"session_alerts", "geoip_update_config", "path_body_limits",
	}

	var restoredTables []string

	tx, err := db.Begin()
	if err != nil {
		dbError(w, "恢复事务启动", err)
		return
	}
	defer tx.Rollback()

	for _, table := range tables {
		data, ok := backup.Configs[table]
		if !ok {
			continue
		}
		rows, isRows := data.([]interface{})
		if !isRows || len(rows) == 0 {
			continue
		}

		colSet, err := getTableColumns(tx, table)
		if err != nil {
			logger.Warn("[ConfigRestore] 获取表 %s 结构失败: %v", table, err)
			continue
		}

		if _, err := tx.Exec("DELETE FROM " + table); err != nil {
			jsonError(w, fmt.Sprintf("清空表失败 %s: %v", table, err), http.StatusInternalServerError)
			return
		}

		for _, row := range rows {
			rowMap, ok := row.(map[string]interface{})
			if !ok {
				continue
			}
			var cols []string
			var placeholders []string
			var vals []interface{}
			for col, val := range rowMap {
				if !identifierPattern.MatchString(col) {
					logger.Warn("[ConfigRestore] 跳过非法列名: %q", col)
					continue
				}
				if !colSet[col] {
					logger.Warn("[ConfigRestore] 跳过不存在的列: %s.%s", table, col)
					continue
				}
				cols = append(cols, col)
				placeholders = append(placeholders, "?")
				vals = append(vals, val)
			}
			if len(cols) == 0 {
				continue
			}
			query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", table,
				strings.Join(cols, ", "),
				strings.Join(placeholders, ", "))
			if _, err := tx.Exec(query, vals...); err != nil {
				jsonError(w, fmt.Sprintf("恢复表 %s 失败: %v", table, err), http.StatusInternalServerError)
				return
			}
		}
		restoredTables = append(restoredTables, table)
	}

	if err := tx.Commit(); err != nil {
		dbError(w, "恢复事务提交", err)
		return
	}

	logger.Info("[ConfigRestore] 配置恢复完成，恢复表: %v", restoredTables)

	jsonSuccess(w, map[string]interface{}{"restored_tables": restoredTables})
}

func getTableColumns(db interface {
	Query(string, ...interface{}) (*sql.Rows, error)
}, table string) (map[string]bool, error) {
	if !identifierPattern.MatchString(table) {
		return nil, fmt.Errorf("invalid table name: %q", table)
	}
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return nil, fmt.Errorf("PRAGMA table_info failed for %s: %w", table, err)
	}
	defer rows.Close()
	colSet := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dfltVal interface{}
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltVal, &pk); err != nil {
			continue
		}
		colSet[name] = true
	}
	return colSet, nil
}
