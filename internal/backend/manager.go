package backend

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gowaf/internal/timeutil"
)

// Backend 后端服务器配置
type Backend struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Address          string `json:"address"`
	Scheme           string `json:"scheme"`
	parsedSchemes    []string
	Weight           int    `json:"weight"`
	Enabled          bool   `json:"enabled"`
	Healthy          bool   `json:"healthy"`
	LastCheck        string `json:"last_check"`
	TotalReqs        int64  `json:"total_reqs"`
	ActiveConns      int    `json:"active_conns"`
	HealthCheck      bool   `json:"health_check"`
	CheckInterval    int    `json:"check_interval"`
	CheckPath        string `json:"check_path"`
	CheckTimeout     int    `json:"check_timeout"`
	FailThreshold    int    `json:"fail_threshold"`
	RecoverThreshold int    `json:"recover_threshold"`
}

func (b *Backend) parseScheme() {
	b.parsedSchemes = parseSchemeStr(b.Scheme)
}

func parseSchemeStr(s string) []string {
	if s == "" {
		return []string{"http"}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return []string{"http"}
	}
	return result
}

func (b *Backend) GetScheme() string {
	switch b.Scheme {
	case "http", "https", "ws", "wss":
		return b.Scheme
	default:
		schemes := b.GetSchemes()
		if len(schemes) > 0 {
			switch schemes[0] {
			case "http", "https", "ws", "wss":
				return schemes[0]
			}
		}
		return "http"
	}
}

func (b *Backend) GetSchemeForRequest(isWebSocket bool) string {
	schemes := b.GetSchemes()
	if isWebSocket {
		for _, s := range schemes {
			if s == "wss" {
				return "wss"
			}
			if s == "ws" {
				return "ws"
			}
		}
		return "ws"
	}
	for _, s := range schemes {
		if s == "https" || s == "http" {
			return s
		}
	}
	if len(schemes) > 0 {
		for _, s := range schemes {
			if s == "wss" {
				return "https"
			}
			if s == "ws" {
				return "http"
			}
		}
		return schemes[0]
	}
	return "http"
}

func (b *Backend) GetSchemes() []string {
	if b.parsedSchemes != nil {
		return b.parsedSchemes
	}
	return parseSchemeStr(b.Scheme)
}

func (b *Backend) SetSchemes(schemes []string) {
	trimmed := make([]string, 0, len(schemes))
	for _, s := range schemes {
		s = strings.TrimSpace(s)
		if s != "" {
			trimmed = append(trimmed, s)
		}
	}
	if len(trimmed) == 0 {
		b.Scheme = "http"
		b.parsedSchemes = []string{"http"}
		return
	}
	b.Scheme = strings.Join(trimmed, ",")
	b.parsedSchemes = trimmed
}

type LBPolicy string

const (
	LBRoundRobin LBPolicy = "round_robin"
	LBWeightedRR LBPolicy = "weighted_round_robin"
	LBLeastConns LBPolicy = "least_connections"
	LBIPHash     LBPolicy = "ip_hash"
	LBURLHash    LBPolicy = "url_hash"
	LBRandom     LBPolicy = "random"
)

var (
	currentLBPolicy   LBPolicy = LBWeightedRR
	currentLBPolicyMu sync.RWMutex
)

func SetLBPolicy(policy LBPolicy) {
	currentLBPolicyMu.Lock()
	currentLBPolicy = policy
	currentLBPolicyMu.Unlock()
}

func GetLBPolicy() LBPolicy {
	currentLBPolicyMu.RLock()
	defer currentLBPolicyMu.RUnlock()
	return currentLBPolicy
}

// Manager 后端服务管理器
type Manager struct {
	db                      *sql.DB
	mu                      sync.RWMutex
	backends                []*Backend
	availableBackends       []*Backend
	groups                  map[string]*BackendGroup
	groupMembers            map[string][]*GroupMemberItem
	roundIdx                uint64
	failCount               map[string]int
	recoverCount            map[string]int
	wrrState                map[string]*wrrEntry
	wrrMu                   sync.Mutex
	groupCache              atomic.Pointer[groupRouteCache]
	rebuildGroupCacheResult *groupRouteCache
}

type wrrEntry struct {
	currentWeight   int
	effectiveWeight int
}

// NewManager 创建后端管理器
func NewManager(db *sql.DB) (*Manager, error) {
	// 创建后端服务器表
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS backends (
			id TEXT PRIMARY KEY,
			name TEXT,
			address TEXT NOT NULL,
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
		db:           db,
		failCount:    make(map[string]int),
		recoverCount: make(map[string]int),
		wrrState:     make(map[string]*wrrEntry),
		groups:       make(map[string]*BackendGroup),
		groupMembers: make(map[string][]*GroupMemberItem),
	}

	if err := m.ensureGroupTables(); err != nil {
		return nil, err
	}

	// 数据库迁移：添加 name 列（如果不存在）
	m.migrateDatabase()

	// 唯一约束：同一地址可以注册多个后端，但不能有相同的 (address, scheme) 组合
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_backends_addr_scheme ON backends(address, scheme)`); err != nil {
		return nil, fmt.Errorf("创建唯一索引失败: %w", err)
	}

	// 数据库迁移：将 address UNIQUE 约束改为 (address, scheme) 唯一索引
	m.migrateAddressConstraint()

	// 加载数据
	m.loadBackends()
	m.refreshAvailable()
	m.loadGroups()
	m.rebuildGroupCache()

	return m, nil
}

// migrateDatabase 数据库迁移
func (m *Manager) migrateDatabase() {
	var columnName string
	err := m.db.QueryRow("SELECT name FROM pragma_table_info('backends') WHERE name = 'name'").Scan(&columnName)
	if err != nil {
		if _, err := m.db.Exec("ALTER TABLE backends ADD COLUMN name TEXT"); err != nil {
			log.Printf("[Backend] 添加name列失败: %v", err)
		}
	}
	var weightCol string
	err = m.db.QueryRow("SELECT name FROM pragma_table_info('backends') WHERE name = 'weight'").Scan(&weightCol)
	if err != nil {
		if _, err := m.db.Exec("ALTER TABLE backends ADD COLUMN weight INTEGER DEFAULT 1"); err != nil {
			log.Printf("[Backend] 添加weight列失败: %v", err)
		}
	}

	var schemeCol string
	err = m.db.QueryRow("SELECT name FROM pragma_table_info('backends') WHERE name = 'scheme'").Scan(&schemeCol)
	if err != nil {
		if _, err := m.db.Exec("ALTER TABLE backends ADD COLUMN scheme TEXT DEFAULT 'http'"); err != nil {
			log.Printf("[Backend] 添加scheme列失败: %v", err)
		}
	}
}

// migrateAddressConstraint 将 address UNIQUE 约束改为 (address, scheme) 唯一索引
func (m *Manager) migrateAddressConstraint() {
	var idxName string
	if err := m.db.QueryRow("SELECT name FROM pragma_index_list('backends') WHERE name = 'idx_backends_addr_scheme'").Scan(&idxName); err == nil {
		return
	}

	var oldIdx string
	err := m.db.QueryRow("SELECT name FROM pragma_index_list('backends') WHERE name LIKE 'sqlite_autoindex_backends%'").Scan(&oldIdx)
	if err != nil || oldIdx == "" {
		if _, err := m.db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_backends_addr_scheme ON backends(address, scheme)"); err != nil {
			log.Printf("[Backend] 创建唯一索引失败: %v", err)
		}
		return
	}

	tx, err := m.db.Begin()
	if err != nil {
		log.Printf("[Backend] 迁移事务启动失败: %v", err)
		return
	}

	if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS backends_new (
		id TEXT PRIMARY KEY, name TEXT, address TEXT NOT NULL,
		scheme TEXT DEFAULT 'http', weight INTEGER DEFAULT 1,
		enabled INTEGER DEFAULT 1, healthy INTEGER DEFAULT 1,
		last_check TEXT, total_reqs INTEGER DEFAULT 0,
		active_conns INTEGER DEFAULT 0, health_check INTEGER DEFAULT 1,
		check_interval INTEGER DEFAULT 10, check_path TEXT DEFAULT '/health',
		check_timeout INTEGER DEFAULT 5, fail_threshold INTEGER DEFAULT 3,
		recover_threshold INTEGER DEFAULT 2, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		tx.Rollback()
		log.Printf("[Backend] 创建新表失败: %v", err)
		return
	}

	if _, err := tx.Exec(`INSERT INTO backends_new (id, name, address, scheme, weight, enabled, healthy,
		last_check, total_reqs, active_conns, health_check, check_interval, check_path,
		check_timeout, fail_threshold, recover_threshold, created_at)
		SELECT id, name, address, COALESCE(scheme, 'http'), COALESCE(weight, 1), enabled, healthy,
		last_check, COALESCE(total_reqs, 0), COALESCE(active_conns, 0), COALESCE(health_check, 1),
		COALESCE(check_interval, 10), COALESCE(check_path, '/health'), COALESCE(check_timeout, 5),
		COALESCE(fail_threshold, 3), COALESCE(recover_threshold, 2), created_at
		FROM backends`); err != nil {
		tx.Rollback()
		log.Printf("[Backend] 数据迁移失败: %v", err)
		return
	}

	if _, err := tx.Exec("DROP TABLE backends"); err != nil {
		tx.Rollback()
		log.Printf("[Backend] 删除旧表失败: %v", err)
		return
	}

	if _, err := tx.Exec("ALTER TABLE backends_new RENAME TO backends"); err != nil {
		tx.Rollback()
		log.Printf("[Backend] 重命名表失败: %v", err)
		return
	}

	if _, err := tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_backends_addr_scheme ON backends(address, scheme)"); err != nil {
		tx.Rollback()
		log.Printf("[Backend] 创建唯一索引失败: %v", err)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[Backend] 迁移提交失败: %v", err)
	}
}

// loadBackends 加载后端列表
func (m *Manager) loadBackends() {
	rows, err := m.db.Query(`
		SELECT id, name, address, scheme, weight, enabled, healthy, last_check, total_reqs, active_conns,
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
		var enabled, healthy, healthCheck, weight int
		var lastCheck sql.NullString
		var totalReqs sql.NullInt64
		var activeConns sql.NullInt64
		var name sql.NullString
		var scheme sql.NullString
		if err := rows.Scan(&b.ID, &name, &b.Address, &scheme, &weight, &enabled, &healthy, &lastCheck, &totalReqs, &activeConns,
			&healthCheck, &b.CheckInterval, &b.CheckPath, &b.CheckTimeout, &b.FailThreshold, &b.RecoverThreshold); err == nil {
			if name.Valid {
				b.Name = name.String
			}
			if scheme.Valid && scheme.String != "" {
				b.Scheme = scheme.String
			} else {
				b.Scheme = "http"
			}
			b.parseScheme()
			if weight <= 0 {
				weight = 1
			}
			b.Weight = weight
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

// GetBackends 获取所有后端（返回深拷贝，避免外部修改内部状态）
func (m *Manager) GetBackends() []*Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*Backend, len(m.backends))
	for i, b := range m.backends {
		bc := *b
		bc.parsedSchemes = append([]string(nil), b.parsedSchemes...)
		result[i] = &bc
	}
	return result
}

// GetBackend 根据ID获取后端（返回深拷贝）
func (m *Manager) GetBackend(id string) *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, b := range m.backends {
		if b.ID == id {
			bc := *b
			return &bc
		}
	}
	return nil
}

// AddBackend 添加后端
func (m *Manager) AddBackend(backend *Backend) error {
	bc := *backend

	m.mu.Lock()
	defer m.mu.Unlock()

	id := time.Now().Format("20060102150405.000000000") + "_" + bc.Address + "_" + bc.Scheme
	bc.ID = id

	if bc.CheckInterval <= 0 {
		bc.CheckInterval = 10
	}
	if bc.CheckPath == "" {
		bc.CheckPath = "/health"
	}
	if bc.CheckTimeout <= 0 {
		bc.CheckTimeout = 5
	}
	if bc.FailThreshold <= 0 {
		bc.FailThreshold = 3
	}
	if bc.RecoverThreshold <= 0 {
		bc.RecoverThreshold = 2
	}
	if bc.Weight <= 0 {
		bc.Weight = 1
	}
	if bc.Scheme == "" {
		bc.Scheme = "http"
	}
	bc.parseScheme()

	healthCheck := 0
	if bc.HealthCheck {
		healthCheck = 1
	}

	_, err := m.db.Exec(`
		INSERT INTO backends (id, name, address, scheme, weight, enabled, healthy, 
		                     health_check, check_interval, check_path, check_timeout, fail_threshold, recover_threshold)
		VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?)
	`, id, bc.Name, bc.Address, bc.Scheme, bc.Weight, healthCheck,
		bc.CheckInterval, bc.CheckPath, bc.CheckTimeout, bc.FailThreshold, bc.RecoverThreshold)
	if err != nil {
		return err
	}

	bc.Enabled = true
	bc.Healthy = true
	m.backends = append(m.backends, &bc)
	m.refreshAvailable()
	m.rebuildGroupCacheLocked()

	backend.ID = id
	backend.Enabled = bc.Enabled
	backend.Healthy = bc.Healthy
	backend.Weight = bc.Weight
	backend.CheckInterval = bc.CheckInterval
	backend.CheckPath = bc.CheckPath
	backend.CheckTimeout = bc.CheckTimeout
	backend.FailThreshold = bc.FailThreshold
	backend.RecoverThreshold = bc.RecoverThreshold
	backend.Scheme = bc.Scheme
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

	if _, err := m.db.Exec("DELETE FROM backend_group_members WHERE backend_id = ?", id); err != nil {
		log.Printf("[Backend] 清理组成员关系失败: %v", err)
	}

	for i, b := range m.backends {
		if b.ID == id {
			m.backends = append(m.backends[:i], m.backends[i+1:]...)
			break
		}
	}
	delete(m.failCount, id)
	delete(m.recoverCount, id)
	m.wrrMu.Lock()
	delete(m.wrrState, id)
	m.wrrMu.Unlock()
	for gid, members := range m.groupMembers {
		for i, mi := range members {
			if mi.BackendID == id {
				m.groupMembers[gid] = append(members[:i], members[i+1:]...)
				break
			}
		}
	}
	m.refreshAvailable()
	m.rebuildGroupCacheLocked()
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
		UPDATE backends SET name = ?, address = ?, scheme = ?, weight = ?, enabled = ?,
		                    health_check = ?, check_interval = ?, check_path = ?, 
		                    check_timeout = ?, fail_threshold = ?, recover_threshold = ?
		WHERE id = ?
	`, backend.Name, backend.Address, backend.Scheme, backend.Weight, enabledInt, healthCheck,
		backend.CheckInterval, backend.CheckPath, backend.CheckTimeout,
		backend.FailThreshold, backend.RecoverThreshold, backend.ID)
	if err != nil {
		return err
	}

	for _, b := range m.backends {
		if b.ID == backend.ID {
			b.Name = backend.Name
			b.Address = backend.Address
			b.Scheme = backend.Scheme
			b.parseScheme()
			b.Weight = backend.Weight
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
	m.refreshAvailable()
	m.rebuildGroupCacheLocked()
	return nil
}

func (m *Manager) refreshAvailable() {
	available := make([]*Backend, 0, len(m.backends))
	for _, b := range m.backends {
		if b.Enabled && b.Healthy {
			available = append(available, b)
		}
	}
	m.availableBackends = available
}

// SelectBackend 选择后端（轮询，返回深拷贝）
func (m *Manager) SelectBackend() *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()

	available := m.availableBackends
	if len(available) == 0 {
		return nil
	}

	var b *Backend
	switch GetLBPolicy() {
	case LBLeastConns:
		b = m.selectLeastConns(available)
	case LBWeightedRR:
		b = m.selectWeightedRR(available)
	default:
		idx := atomic.AddUint64(&m.roundIdx, 1) - 1
		b = available[idx%uint64(len(available))]
	}
	if b != nil {
		bc := *b
		return &bc
	}
	return nil
}

func (m *Manager) selectLeastConns(available []*Backend) *Backend {
	best := available[0]
	bestWeight := best.Weight
	if bestWeight <= 0 {
		bestWeight = 1
	}
	bestScore := best.ActiveConns * 100 / bestWeight
	for _, b := range available[1:] {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		score := b.ActiveConns * 100 / w
		if score < bestScore {
			bestScore = score
			best = b
		}
	}
	return best
}

func (m *Manager) selectWeightedRR(available []*Backend) *Backend {
	m.wrrMu.Lock()
	defer m.wrrMu.Unlock()

	totalWeight := 0
	for _, b := range available {
		if b.Weight <= 0 {
			continue
		}
		state, ok := m.wrrState[b.ID]
		if !ok {
			state = &wrrEntry{currentWeight: 0, effectiveWeight: b.Weight}
			m.wrrState[b.ID] = state
		}
		state.effectiveWeight = b.Weight
		totalWeight += state.effectiveWeight
	}
	if totalWeight == 0 {
		idx := atomic.AddUint64(&m.roundIdx, 1) - 1
		return available[idx%uint64(len(available))]
	}

	var best *Backend
	bestWeight := -1
	for _, b := range available {
		state, ok := m.wrrState[b.ID]
		if !ok {
			continue
		}
		state.currentWeight += state.effectiveWeight
		if state.currentWeight > bestWeight {
			bestWeight = state.currentWeight
			best = b
		}
	}
	if best != nil {
		if state, ok := m.wrrState[best.ID]; ok {
			state.currentWeight -= totalWeight
		}
	}
	if best == nil {
		idx := atomic.AddUint64(&m.roundIdx, 1) - 1
		return available[idx%uint64(len(available))]
	}
	return best
}

// SelectBackendByID 根据ID选择后端（返回深拷贝）
func (m *Manager) SelectBackendByID(id string) *Backend {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, b := range m.backends {
		if b.ID == id && b.Enabled && b.Healthy {
			bc := *b
			return &bc
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
			b.LastCheck = timeutil.FormatRFC3339(time.Now())
			if healthy {
				m.failCount[id] = 0
				m.recoverCount[id] = 0
			} else {
				m.recoverCount[id] = 0
			}
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
	m.refreshAvailable()
	m.rebuildGroupCacheLocked()
}

// Close 关闭管理器（不关闭数据库连接，由统一的数据库管理器管理）
// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	if _, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS backends (
		id TEXT PRIMARY KEY, name TEXT, address TEXT NOT NULL,
		scheme TEXT DEFAULT 'http', weight INTEGER DEFAULT 1,
		enabled INTEGER DEFAULT 1, healthy INTEGER DEFAULT 1,
		last_check TEXT, total_reqs INTEGER DEFAULT 0,
		active_conns INTEGER DEFAULT 0, health_check INTEGER DEFAULT 1,
		check_interval INTEGER DEFAULT 10, check_path TEXT DEFAULT '/health',
		check_timeout INTEGER DEFAULT 5, fail_threshold INTEGER DEFAULT 3,
		recover_threshold INTEGER DEFAULT 2, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create backends table: %w", err)
	}
	if err := m.ensureGroupTables(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Close() error {
	// 不关闭数据库连接，因为连接是共享的
	return nil
}
