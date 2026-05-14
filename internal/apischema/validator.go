package apischema

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"gowaf/internal/logger"
)

func migrateAddColumn(db *sql.DB, table, column, definition string) {
	query := "ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition
	if _, err := db.Exec(query); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			logger.Warn("migration: %s.%s %v", table, column, err)
		}
	}
}

type APISchema struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Spec       string `json:"spec"`
	SchemaType string `json:"schema_type"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  int64  `json:"created_at"`
	parsed     map[string]map[string][]string
}

type ValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
	Path   string   `json:"path"`
	Method string   `json:"method"`
}

type Manager struct {
	db      *sql.DB
	mu      sync.RWMutex
	schemas []APISchema
}

var builtinSchemas = []struct {
	name string
	spec string
}{
	{"通用用户API", `{"paths":{"/api/users":{"post":{"parameters":[{"name":"username","required":true},{"name":"email","required":true},{"name":"password","required":true}]},"put":{"parameters":[{"name":"id","required":true}]}},"/api/users/login":{"post":{"parameters":[{"name":"username","required":true},{"name":"password","required":true}]}}}}`},
	{"通用订单API", `{"paths":{"/api/orders":{"post":{"parameters":[{"name":"user_id","required":true},{"name":"amount","required":true},{"name":"currency","required":true}]},"put":{"parameters":[{"name":"id","required":true},{"name":"status","required":true}]}},"/api/orders/{id}":{"get":{"parameters":[{"name":"id","required":true}]}}}}`},
	{"通用文件上传API", `{"paths":{"/api/upload":{"post":{"requestBody":{"required":true},"parameters":[{"name":"type","required":true}]}},"/api/files/{id}":{"get":{"parameters":[{"name":"id","required":true}]},"delete":{"parameters":[{"name":"id","required":true}]}}}}`},
	{"通用支付API", `{"paths":{"/api/payments":{"post":{"parameters":[{"name":"order_id","required":true},{"name":"amount","required":true},{"name":"method","required":true}]},"get":{"parameters":[{"name":"order_id","required":true}]}},"/api/payments/refund":{"post":{"parameters":[{"name":"payment_id","required":true},{"name":"reason","required":true}]}}}}`},
	{"通用健康检查API", `{"paths":{"/health":{"get":{}},"/ready":{"get":{}},"/api/status":{"get":{}}}}`},
}

func NewManager(db *sql.DB) *Manager {
	m := &Manager{db: db}
	if db != nil {
		m.initTables()
		m.initBuiltinSchemas()
		m.loadSchemas()
	}
	return m
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS api_schemas (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		spec TEXT NOT NULL,
		schema_type TEXT NOT NULL DEFAULT 'custom',
		enabled INTEGER DEFAULT 1,
		created_at INTEGER
	)`)
	if err != nil {
		logger.Warn("API Schema: 建表失败: %v", err)
		return
	}
	migrateAddColumn(m.db, "api_schemas", "schema_type", "TEXT NOT NULL DEFAULT 'custom'")
	migrateAddColumn(m.db, "api_schemas", "created_at", "INTEGER")
	m.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_api_schemas_name_type ON api_schemas(name, schema_type)`)
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) initBuiltinSchemas() {
	var count int
	err := m.db.QueryRow("SELECT COUNT(*) FROM api_schemas WHERE schema_type='builtin'").Scan(&count)
	if err != nil || count > 0 {
		return
	}
	tx, err := m.db.Begin()
	if err != nil {
		logger.Warn("API Schema: 内置Schema事务失败: %v", err)
		return
	}
	stmt, err := tx.Prepare("INSERT OR IGNORE INTO api_schemas(name, spec, schema_type, enabled, created_at) VALUES(?,?,?,1,?)")
	if err != nil {
		tx.Rollback()
		logger.Warn("API Schema: 内置Schema预编译失败: %v", err)
		return
	}
	defer stmt.Close()
	now := time.Now().Unix()
	for _, s := range builtinSchemas {
		stmt.Exec(s.name, s.spec, "builtin", now)
	}
	if err := tx.Commit(); err != nil {
		logger.Warn("API Schema: 内置Schema提交失败: %v", err)
	}
}

func (m *Manager) loadSchemas() {
	rows, err := m.db.Query("SELECT id, name, spec, schema_type, enabled, created_at FROM api_schemas")
	if err != nil {
		return
	}
	defer rows.Close()
	var schemas []APISchema
	for rows.Next() {
		var s APISchema
		var enabled int
		if err := rows.Scan(&s.ID, &s.Name, &s.Spec, &s.SchemaType, &enabled, &s.CreatedAt); err != nil {
			continue
		}
		s.Enabled = enabled == 1
		s.parsed = parseSpec(s.Spec)
		schemas = append(schemas, s)
	}
	m.mu.Lock()
	m.schemas = schemas
	m.mu.Unlock()
}

func parseSpec(spec string) map[string]map[string][]string {
	result := make(map[string]map[string][]string)
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(spec), &raw); err != nil {
		return result
	}
	paths, ok := raw["paths"].(map[string]interface{})
	if !ok {
		return result
	}
	for path, pathObj := range paths {
		pathMap, ok := pathObj.(map[string]interface{})
		if !ok {
			continue
		}
		result[path] = make(map[string][]string)
		for method, methodObj := range pathMap {
			method = strings.ToUpper(method)
			methodMap, ok := methodObj.(map[string]interface{})
			if !ok {
				continue
			}
			var required []string
			if params, ok := methodMap["parameters"].([]interface{}); ok {
				for _, p := range params {
					if pm, ok := p.(map[string]interface{}); ok {
						if req, ok := pm["required"].(bool); ok && req {
							if name, ok := pm["name"].(string); ok {
								required = append(required, name)
							}
						}
					}
				}
			}
			if body, ok := methodMap["requestBody"].(map[string]interface{}); ok {
				if req, ok := body["required"].(bool); ok && req {
					required = append(required, "requestBody")
				}
			}
			result[path][method] = required
		}
	}
	return result
}

func (m *Manager) ValidateRequest(method, path string, body []byte) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:  true,
		Path:   path,
		Method: method,
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	pathFound := false
	for _, s := range m.schemas {
		if !s.Enabled {
			continue
		}
		for schemaPath, methods := range s.parsed {
			if schemaPath == path {
				pathFound = true
				requiredFields, ok := methods[strings.ToUpper(method)]
				if ok && len(requiredFields) > 0 {
					var bodyMap map[string]interface{}
					if len(body) > 0 {
						json.Unmarshal(body, &bodyMap)
					}
					for _, field := range requiredFields {
						if field == "requestBody" {
							if len(body) == 0 {
								result.Valid = false
								result.Errors = append(result.Errors, "缺少必需的请求体(requestBody)")
							}
							continue
						}
						if bodyMap != nil {
							if _, exists := bodyMap[field]; !exists {
								result.Valid = false
								result.Errors = append(result.Errors, "缺少必需字段: "+field)
							}
						}
					}
				}
				break
			}
		}
	}
	if !pathFound {
		result.Valid = true
		result.Errors = append(result.Errors, "路径未在Schema中定义")
	}
	return result, nil
}

func (m *Manager) AddSchema(name, spec string, enabled bool) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	e := 0
	if enabled {
		e = 1
	}
	now := time.Now().Unix()
	_, err := m.db.Exec("INSERT INTO api_schemas(name, spec, schema_type, enabled, created_at) VALUES(?,?,?,?,?)",
		name, spec, "custom", e, now)
	if err != nil {
		return err
	}
	m.loadSchemas()
	return nil
}

func (m *Manager) UpdateSchema(id int, name, spec string, enabled bool) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE api_schemas SET name=?, spec=?, enabled=? WHERE id=? AND schema_type='custom'",
		name, spec, e, id)
	if err != nil {
		return err
	}
	m.loadSchemas()
	return nil
}

func (m *Manager) DeleteSchema(id int) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	result, err := m.db.Exec("DELETE FROM api_schemas WHERE id=? AND schema_type='custom'", id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return errors.New("无法删除内置Schema或Schema不存在")
	}
	m.loadSchemas()
	return nil
}

func (m *Manager) ListSchemas() ([]APISchema, error) {
	if m.db == nil {
		return nil, nil
	}
	rows, err := m.db.Query("SELECT id, name, spec, schema_type, enabled, created_at FROM api_schemas ORDER BY schema_type DESC, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var schemas []APISchema
	for rows.Next() {
		var s APISchema
		var enabled int
		if err := rows.Scan(&s.ID, &s.Name, &s.Spec, &s.SchemaType, &enabled, &s.CreatedAt); err != nil {
			continue
		}
		s.Enabled = enabled == 1
		schemas = append(schemas, s)
	}
	return schemas, nil
}

func (m *Manager) ToggleEnabled(id int, enabled bool) error {
	if m.db == nil {
		return errors.New("database not initialized")
	}
	e := 0
	if enabled {
		e = 1
	}
	_, err := m.db.Exec("UPDATE api_schemas SET enabled=? WHERE id=?", e, id)
	if err != nil {
		return err
	}
	m.loadSchemas()
	return nil
}

func (m *Manager) Reload() {
	if m.db != nil {
		m.loadSchemas()
	}
}
