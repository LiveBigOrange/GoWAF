package configversion

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gowaf/internal/logger"
)

var validIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

type ConfigVersion struct {
	ID          int    `json:"id"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Snapshot    string `json:"snapshot,omitempty"`
	CreatedAt   int64  `json:"created_at"`
	Auto        bool   `json:"auto"`
}

type Manager struct {
	db *sql.DB
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{db: db}
	if db != nil {
		m.initTables()
	}
	return m
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS config_versions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version TEXT NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		snapshot TEXT NOT NULL,
		created_at INTEGER,
		auto INTEGER DEFAULT 0
	)`)
	if err != nil {
		logger.Warn("配置版本: 建表失败: %v", err)
	}
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) CreateSnapshot(description string, auto bool) error {
	if m.db == nil {
		return nil
	}
	fullSnapshot := make(map[string]interface{})

	rows, err := m.db.Query("SELECT key, value FROM system_config ORDER BY key")
	if err != nil {
		return fmt.Errorf("读取配置失败: %w", err)
	}
	configMap := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			continue
		}
		configMap[k] = v
	}
	rows.Close()
	fullSnapshot["system_config"] = configMap

	extraTables := []string{
		"resp_header_rules", "path_body_limits", "dlp_rules",
		"api_schemas", "bot_rules", "geoip_update_config",
	}
	allowedTables := map[string]bool{
		"resp_header_rules": true, "path_body_limits": true, "dlp_rules": true,
		"api_schemas": true, "bot_rules": true, "geoip_update_config": true,
		"system_config": true,
	}
	for _, tbl := range extraTables {
		if !allowedTables[tbl] {
			continue
		}
		tblRows, err := m.db.Query("SELECT * FROM " + tbl)
		if err != nil {
			continue
		}
		cols, _ := tblRows.Columns()
		var tblData []map[string]interface{}
		for tblRows.Next() {
			vals := make([]interface{}, len(cols))
			ptrs := make([]interface{}, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := tblRows.Scan(ptrs...); err != nil {
				continue
			}
			row := make(map[string]interface{})
			for i, col := range cols {
				row[col] = vals[i]
			}
			tblData = append(tblData, row)
		}
		tblRows.Close()
		fullSnapshot[tbl] = tblData
	}

	snapshot, err := json.Marshal(fullSnapshot)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	now := time.Now().Unix()
	version := time.Now().Format("20060102-150405")
	autoFlag := 0
	if auto {
		autoFlag = 1
	}
	_, err = m.db.Exec("INSERT INTO config_versions(version, description, snapshot, created_at, auto) VALUES(?,?,?,?,?)",
		version, description, string(snapshot), now, autoFlag)
	if err != nil {
		return fmt.Errorf("保存快照失败: %w", err)
	}
	logger.Info("配置版本: 创建快照 %s 成功", version)
	return nil
}

func (m *Manager) ListVersions(limit, offset int) ([]ConfigVersion, int, error) {
	if m.db == nil {
		return nil, 0, nil
	}
	var total int
	m.db.QueryRow("SELECT COUNT(*) FROM config_versions").Scan(&total)
	rows, err := m.db.Query("SELECT id, version, description, created_at, auto FROM config_versions ORDER BY id DESC LIMIT ? OFFSET ?",
		limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var versions []ConfigVersion
	for rows.Next() {
		var v ConfigVersion
		var autoFlag int
		if err := rows.Scan(&v.ID, &v.Version, &v.Description, &v.CreatedAt, &autoFlag); err != nil {
			continue
		}
		v.Auto = autoFlag == 1
		versions = append(versions, v)
	}
	return versions, total, nil
}

func (m *Manager) GetVersion(id int) (*ConfigVersion, error) {
	if m.db == nil {
		return nil, nil
	}
	var v ConfigVersion
	var autoFlag int
	err := m.db.QueryRow("SELECT id, version, description, snapshot, created_at, auto FROM config_versions WHERE id=?",
		id).Scan(&v.ID, &v.Version, &v.Description, &v.Snapshot, &v.CreatedAt, &autoFlag)
	if err != nil {
		return nil, err
	}
	v.Auto = autoFlag == 1
	return &v, nil
}

func (m *Manager) RestoreVersion(id int) error {
	if m.db == nil {
		return nil
	}
	var snapshot string
	err := m.db.QueryRow("SELECT snapshot FROM config_versions WHERE id=?", id).Scan(&snapshot)
	if err != nil {
		return fmt.Errorf("读取快照失败: %w", err)
	}
	var fullSnapshot map[string]interface{}
	if err := json.Unmarshal([]byte(snapshot), &fullSnapshot); err != nil {
		return fmt.Errorf("解析快照失败: %w", err)
	}
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("开启事务失败: %w", err)
	}
	now := time.Now().Unix()
	if sc, ok := fullSnapshot["system_config"]; ok {
		if scMap, ok := sc.(map[string]interface{}); ok {
			for k, v := range scMap {
				vs, _ := v.(string)
				if _, err := tx.Exec("INSERT OR REPLACE INTO system_config(key, value, updated_at) VALUES(?,?,?)", k, vs, now); err != nil {
					tx.Rollback()
					return fmt.Errorf("恢复配置项 %s 失败: %w", k, err)
				}
			}
		}
	}
	allowedTables := map[string]bool{
		"resp_header_rules": true, "path_body_limits": true, "dlp_rules": true,
		"api_schemas": true, "bot_rules": true, "geoip_update_config": true,
	}
	for tbl, data := range fullSnapshot {
		if tbl == "system_config" || !allowedTables[tbl] {
			continue
		}
		rows, ok := data.([]interface{})
		if !ok || len(rows) == 0 {
			continue
		}
		colSet, err := getTableColumns(m.db, tbl)
		if err != nil {
			logger.Warn("配置版本恢复: 获取表 %s 结构失败: %v", tbl, err)
			continue
		}
		if firstRow, ok := rows[0].(map[string]interface{}); ok {
			cols := make([]string, 0, len(firstRow))
			for c := range firstRow {
				if !validIdentifier.MatchString(c) {
					logger.Warn("配置版本恢复: 跳过非法列名 %q", c)
					continue
				}
				if !colSet[c] {
					logger.Warn("配置版本恢复: 跳过不存在的列 %s.%s", tbl, c)
					continue
				}
				cols = append(cols, c)
			}
			if len(cols) == 0 {
				continue
			}
			if _, err := tx.Exec("DELETE FROM " + tbl); err != nil {
				continue
			}
			for _, row := range rows {
				if r, ok := row.(map[string]interface{}); ok {
					vals := make([]interface{}, len(cols))
					placeholders := make([]string, len(cols))
					for i, c := range cols {
						vals[i] = r[c]
						placeholders[i] = "?"
					}
					q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", tbl, strings.Join(cols, ","), strings.Join(placeholders, ","))
					if _, err := tx.Exec(q, vals...); err != nil {
						logger.Warn("配置版本恢复: INSERT失败 %s: %v", tbl, err)
					}
				}
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交事务失败: %w", err)
	}
	logger.Info("配置版本: 已恢复到版本 id=%d", id)
	return nil
}

func (m *Manager) DiffVersions(id1, id2 int) (string, error) {
	if m.db == nil {
		return "", nil
	}
	v1, err := m.GetVersion(id1)
	if err != nil {
		return "", fmt.Errorf("获取版本 %d 失败: %w", id1, err)
	}
	v2, err := m.GetVersion(id2)
	if err != nil {
		return "", fmt.Errorf("获取版本 %d 失败: %w", id2, err)
	}
	s1 := v1.Snapshot
	s2 := v2.Snapshot
	var diffs []string
	if s1 == s2 {
		return "无差异", nil
	}
	var map1, map2 map[string]interface{}
	json.Unmarshal([]byte(s1), &map1)
	json.Unmarshal([]byte(s2), &map2)
	allKeys := make(map[string]bool)
	for k := range map1 {
		allKeys[k] = true
	}
	for k := range map2 {
		allKeys[k] = true
	}
	for k := range allKeys {
		j1, _ := json.Marshal(map1[k])
		j2, _ := json.Marshal(map2[k])
		_, ok1 := map1[k]
		_, ok2 := map2[k]
		if !ok1 {
			diffs = append(diffs, fmt.Sprintf("+ %s: %s", k, string(j2)))
		} else if !ok2 {
			diffs = append(diffs, fmt.Sprintf("- %s: %s", k, string(j1)))
		} else if string(j1) != string(j2) {
			diffs = append(diffs, fmt.Sprintf("~ %s: %s -> %s", k, string(j1), string(j2)))
		}
	}
	if len(diffs) == 0 {
		return "无差异", nil
	}
	return strings.Join(diffs, "\n"), nil
}

func getTableColumns(db *sql.DB, table string) (map[string]bool, error) {
	if !validIdentifier.MatchString(table) {
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
