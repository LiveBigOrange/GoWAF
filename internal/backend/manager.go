package backend

import (
	"database/sql"
	"sync"
	"sync/atomic"
	"time"
)

// Backend 后端服务器配置
type Backend struct {
	ID             string `json:"id"`
	Name           string `json:"name"`             // 服务名称
	Address        string `json:"address"`          // 后端地址 (host:port)
	Enabled        bool   `json:"enabled"`          // 是否启用
	Healthy        bool   `json:"healthy"`          // 健康状态
	LastCheck      string `json:"last_check"`       // 最后检查时间
	TotalReqs      int64  `json:"total_reqs"`       // 总请求数
	ActiveConns    int    `json:"active_conns"`     // 活跃连接数
	HealthCheck    bool   `json:"health_check"`     // 是否启用健康检查
	CheckInterval  int    `json:"check_interval"`   // 健康检查间隔(秒)
	CheckPath      string `json:"check_path"`       // 健康检查路径
	CheckTimeout   int    `json:"check_timeout"`    // 健康检查超时(秒)
	FailThreshold  int    `json:"fail_threshold"`   // 失败阈值
	RecoverThreshold int  `json:"recover_threshold"` // 恢复阈值
}

// Manager 后端服务管理器
type Manager struct {
	db        *sql.DB
	mu        sync.RWMutex
	backends  []*Backend
	roundIdx  uint64 // 轮询索引（atomic）
	failCount map[string]int // 失败计数
}

// NewManager 创建后端管理器
func NewManager(db *sql.DB) (*Manager, error) {
	// 创建后端服务器表
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS backends (
			id TEXT PRIMARY KEY,
			name TEXT,
			address TEXT NOT NULL UNIQUE,
			enabled INTEGER DEFAULT 1,
			healthy INTEGER DEFAULT 1,
			last_check TEXT,
			total_reqs INTEGER DEFAULT 0,
			active_conns INTEGER DEFAULT 0,
			health_check INTEGER DEFAULT 1,
			check_interval INTEGER DEFAULT 10,
			check_path TEXT DEFAULT '/health',
			check_timeout INTEGER DEFAULT 5,
			fail_threshold INTEGER DEFAULT 3,
			recover_threshold INTEGER DEFAULT 2,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		db:        db,
		failCount: make(map[string]int),
	}

	// 数据库迁移：添加 name 列（如果不存在）
	m.migrateDatabase()

	// 加载数据
	m.loadBackends()

	return m, nil
}

// migrateDatabase 数据库迁移
func (m *Manager) migrateDatabase() {
	// 检查 name 列是否存在
	var columnName string
	err := m.db.QueryRow("SELECT name FROM pragma_table_info('backends') WHERE name = 'name'").Scan(&columnName)
	if err != nil {
		// name 列不存在，添加该列
		_, err := m.db.Exec("ALTER TABLE backends ADD COLUMN name TEXT")
		if err != nil {
			// 忽略错误，可能列已存在
			return
		}
	}
}

// loadBackends 加载后端列表
func (m *Manager) loadBackends() {
	rows, err := m.db.Query(`
		SELECT id, name, address, enabled, healthy, last_check, total_reqs, active_conns,
		       health_check, check_interval, check_path, check_timeout, fail_threshold, recover_threshold
		FROM backends ORDER BY created_at
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	var backends []*Backend
	for rows.Next() {
		var b Backend
		var enabled, healthy, healthCheck int
		var lastCheck sql.NullString
		var totalReqs sql.NullInt64
		var activeConns sql.NullInt64
		var name sql.NullString
		if err := rows.Scan(&b.ID, &name, &b.Address, &enabled, &healthy, &lastCheck, &totalReqs, &activeConns,
			&healthCheck, &b.CheckInterval, &b.CheckPath, &b.CheckTimeout, &b.FailThreshold, &b.RecoverThreshold); err == nil {
			if name.Valid {
				b.Name = name.String
			}
			b.Enabled = enabled == 1
			b.Healthy = healthy == 1
			b.HealthCheck = healthCheck == 1
			if lastCheck.Valid {
				b.LastCheck = lastCheck.String
			}
			if totalReqs.Valid {
				b.TotalReqs = totalReqs.Int64
			}
			if activeConns.Valid {
				b.ActiveConns = int(activeConns.Int64)
			}
			backends = append(backends, &b)
		}
	}
	m.backends = backends
}

// GetBackends 获取所有后端
func (m *Manager) GetBackends() []*Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.backends
}

// GetBackend 根据ID获取后端
func (m *Manager) GetBackend(id string) *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.backends {
		if b.ID == id {
			return b
		}
	}
	return nil
}

// AddBackend 添加后端
func (m *Manager) AddBackend(backend *Backend) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := time.Now().Format("20060102150405") + "_" + backend.Address
	backend.ID = id

	// 设置默认值
	if backend.CheckInterval <= 0 {
		backend.CheckInterval = 10
	}
	if backend.CheckPath == "" {
		backend.CheckPath = "/health"
	}
	if backend.CheckTimeout <= 0 {
		backend.CheckTimeout = 5
	}
	if backend.FailThreshold <= 0 {
		backend.FailThreshold = 3
	}
	if backend.RecoverThreshold <= 0 {
		backend.RecoverThreshold = 2
	}

	healthCheck := 0
	if backend.HealthCheck {
		healthCheck = 1
	}

	_, err := m.db.Exec(`
		INSERT INTO backends (id, name, address, enabled, healthy, 
		                     health_check, check_interval, check_path, check_timeout, fail_threshold, recover_threshold)
		VALUES (?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?)
	`, id, backend.Name, backend.Address, healthCheck, 
	   backend.CheckInterval, backend.CheckPath, backend.CheckTimeout, backend.FailThreshold, backend.RecoverThreshold)
	if err != nil {
		return err
	}

	backend.Enabled = true
	backend.Healthy = true
	m.backends = append(m.backends, backend)
	return nil
}

// RemoveBackend 删除后端
func (m *Manager) RemoveBackend(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, err := m.db.Exec("DELETE FROM backends WHERE id = ?", id)
	if err != nil {
		return err
	}

	for i, b := range m.backends {
		if b.ID == id {
			m.backends = append(m.backends[:i], m.backends[i+1:]...)
			break
		}
	}
	return nil
}

// UpdateBackend 更新后端
func (m *Manager) UpdateBackend(backend *Backend) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	enabledInt := 0
	if backend.Enabled {
		enabledInt = 1
	}

	healthCheck := 0
	if backend.HealthCheck {
		healthCheck = 1
	}

	_, err := m.db.Exec(`
		UPDATE backends SET name = ?, address = ?, enabled = ?,
		                    health_check = ?, check_interval = ?, check_path = ?, 
		                    check_timeout = ?, fail_threshold = ?, recover_threshold = ?
		WHERE id = ?
	`, backend.Name, backend.Address, enabledInt, healthCheck,
	   backend.CheckInterval, backend.CheckPath, backend.CheckTimeout, 
	   backend.FailThreshold, backend.RecoverThreshold, backend.ID)
	if err != nil {
		return err
	}

	for _, b := range m.backends {
		if b.ID == backend.ID {
			b.Name = backend.Name
			b.Address = backend.Address
			b.Enabled = backend.Enabled
			b.HealthCheck = backend.HealthCheck
			b.CheckInterval = backend.CheckInterval
			b.CheckPath = backend.CheckPath
			b.CheckTimeout = backend.CheckTimeout
			b.FailThreshold = backend.FailThreshold
			b.RecoverThreshold = backend.RecoverThreshold
			break
		}
	}
	return nil
}

// SelectBackend 选择后端（轮询）
func (m *Manager) SelectBackend() *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var available []*Backend
	for _, b := range m.backends {
		if b.Enabled && b.Healthy {
			available = append(available, b)
		}
	}

	if len(available) == 0 {
		return nil
	}

	idx := atomic.AddUint64(&m.roundIdx, 1) - 1
	return available[idx%uint64(len(available))]
}

// SelectBackendByID 根据ID选择后端
func (m *Manager) SelectBackendByID(id string) *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, b := range m.backends {
		if b.ID == id && b.Enabled && b.Healthy {
			return b
		}
	}
	return nil
}

// IncConn 增加连接数
func (m *Manager) IncConn(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.backends {
		if b.ID == id {
			b.ActiveConns++
			b.TotalReqs++
			break
		}
	}
}

// DecConn 减少连接数
func (m *Manager) DecConn(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.backends {
		if b.ID == id {
			if b.ActiveConns > 0 {
				b.ActiveConns--
			}
			break
		}
	}
}

// MarkHealthy 标记健康状态
func (m *Manager) MarkHealthy(id string, healthy bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, b := range m.backends {
		if b.ID == id {
			b.Healthy = healthy
			b.LastCheck = time.Now().Format(time.RFC3339)
			// 更新数据库
			healthyInt := 0
			if healthy {
				healthyInt = 1
			}
			_, _ = m.db.Exec(`
				UPDATE backends SET healthy = ?, last_check = ? WHERE id = ?
			`, healthyInt, b.LastCheck, id)
			break
		}
	}
}

// Close 关闭管理器（不关闭数据库连接，由统一的数据库管理器管理）
func (m *Manager) Close() error {
	// 不关闭数据库连接，因为连接是共享的
	return nil
}
