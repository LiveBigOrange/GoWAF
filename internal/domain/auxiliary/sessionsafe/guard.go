package sessionsafe

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"gowaf/internal/infra/logger"
)

type SessionProfile struct {
	SessionID string    `json:"session_id"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ipHistory []string
}

type SecurityAlert struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	Detail    string `json:"detail"`
}

type Manager struct {
	db                  *sql.DB
	mu                  sync.RWMutex
	sessionProfiles     map[string]*SessionProfile
	ipMutationThreshold int
	uaDetectionEnabled  bool
}

var defaultIPMutationThreshold = 3
var defaultUADetectionEnabled = true

func NewManager(db *sql.DB) *Manager {
	m := &Manager{
		db:                  db,
		sessionProfiles:     make(map[string]*SessionProfile),
		ipMutationThreshold: defaultIPMutationThreshold,
		uaDetectionEnabled:  defaultUADetectionEnabled,
	}
	if db != nil {
		m.initTables()
	}
	return m
}

// UpdateConfig 运行时更新会话安全配置
func (m *Manager) UpdateConfig(ipThreshold int, uaEnabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ipThreshold > 0 {
		m.ipMutationThreshold = ipThreshold
	}
	m.uaDetectionEnabled = uaEnabled
}

func (m *Manager) Reload() {
	if m.db == nil {
		return
	}
	var threshold int
	var uaEnabled int
	err := m.db.QueryRow("SELECT ip_mutation_threshold, ua_detection_enabled FROM session_safe_config LIMIT 1").Scan(&threshold, &uaEnabled)
	if err == nil {
		m.UpdateConfig(threshold, uaEnabled == 1)
		logger.Info("会话安全配置已重载")
	}
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS session_alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		alert_type TEXT NOT NULL,
		detail TEXT NOT NULL,
		created_at INTEGER
	)`)
	if err != nil {
		logger.Warn("会话安全: 建表失败: %v", err)
	}
	m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_session_alerts_session_id ON session_alerts(session_id)`)
	m.db.Exec(`CREATE INDEX IF NOT EXISTS idx_session_alerts_created_at ON session_alerts(created_at)`)
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) RecordSessionAccess(sessionID, ip, ua string) *SecurityAlert {
	if sessionID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	profile, exists := m.sessionProfiles[sessionID]
	if !exists {
		profile = &SessionProfile{
			SessionID: sessionID,
			IP:        ip,
			UserAgent: ua,
			CreatedAt: now,
			LastSeen:  now,
			ipHistory: []string{ip},
		}
		m.sessionProfiles[sessionID] = profile
		return nil
	}
	profile.LastSeen = now
	var alert *SecurityAlert
	uniqueIPs := make(map[string]bool)
	for _, hIP := range profile.ipHistory {
		uniqueIPs[hIP] = true
	}
	if !uniqueIPs[ip] {
		profile.ipHistory = append(profile.ipHistory, ip)
		uniqueIPs[ip] = true
	}
	if len(uniqueIPs) > m.ipMutationThreshold {
		alert = &SecurityAlert{
			Type:      "ip_mutation",
			SessionID: sessionID,
			Detail:    fmt.Sprintf("会话IP变化超过%d次，疑似Session Fixation/Hijacking", m.ipMutationThreshold),
		}
		m.recordAlert(alert)
	}
	if m.uaDetectionEnabled && ua != profile.UserAgent && ua != "" && profile.UserAgent != "" {
		alert = &SecurityAlert{
			Type:      "ua_change",
			SessionID: sessionID,
			Detail:    "会话UserAgent完全改变，疑似Session Hijacking",
		}
		m.recordAlert(alert)
	}
	if alert == nil {
		profile.IP = ip
		profile.UserAgent = ua
	}
	return alert
}

func (m *Manager) recordAlert(alert *SecurityAlert) {
	if m.db == nil {
		return
	}
	now := time.Now().Unix()
	_, err := m.db.Exec("INSERT INTO session_alerts(session_id, alert_type, detail, created_at) VALUES(?,?,?,?)",
		alert.SessionID, alert.Type, alert.Detail, now)
	if err != nil {
		logger.Warn("会话安全: 记录告警失败: %v", err)
	}
}
