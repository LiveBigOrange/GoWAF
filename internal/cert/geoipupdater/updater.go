package geoipupdater

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"gowaf/internal/infra/logger"
	"gowaf/internal/pkg/xutil"
)

type Manager struct {
	db            *sql.DB
	metricsMgr    MetricsReloader
	currentDBPath string
	stopCh        chan struct{}
	mu            sync.Mutex
	running       bool
}

type MetricsReloader interface {
	ReloadGeoIP(dbPath string) error
}

func NewManager(db *sql.DB, dbPath string, mm MetricsReloader) *Manager {
	m := &Manager{
		db:            db,
		metricsMgr:    mm,
		currentDBPath: dbPath,
		stopCh:        make(chan struct{}),
	}
	if db != nil {
		m.initTables()
	}
	return m
}

func (m *Manager) initTables() {
	_, err := m.db.Exec(`CREATE TABLE IF NOT EXISTS geoip_update_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at INTEGER
	)`)
	if err != nil {
		logger.Warn("GeoIP更新: 建表失败: %v", err)
		return
	}
	defaults := map[string]string{
		"download_url":          "https://updates.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz",
		"auto_update_enabled":   "0",
		"update_interval_hours": "168",
		"last_update_time":      "0",
	}
	now := time.Now().Unix()
	for k, v := range defaults {
		var cnt int
		m.db.QueryRow("SELECT COUNT(*) FROM geoip_update_config WHERE key=?", k).Scan(&cnt)
		if cnt == 0 {
			m.db.Exec("INSERT INTO geoip_update_config(key, value, updated_at) VALUES(?,?,?)", k, v, now)
		}
	}
}

// EnsureTables 确保数据库表已初始化
func (m *Manager) EnsureTables() error {
	m.initTables()
	return nil
}

func (m *Manager) LoadConfig() (url string, enabled bool, interval int, lastUpdate int64) {
	if m.db == nil {
		return
	}
	var val string
	if m.db.QueryRow("SELECT value FROM geoip_update_config WHERE key='download_url'").Scan(&val) == nil {
		url = val
	}
	if m.db.QueryRow("SELECT value FROM geoip_update_config WHERE key='auto_update_enabled'").Scan(&val) == nil {
		enabled = val == "1"
	}
	if m.db.QueryRow("SELECT value FROM geoip_update_config WHERE key='update_interval_hours'").Scan(&val) == nil {
		fmt.Sscanf(val, "%d", &interval)
	}
	if m.db.QueryRow("SELECT value FROM geoip_update_config WHERE key='last_update_time'").Scan(&val) == nil {
		fmt.Sscanf(val, "%d", &lastUpdate)
	}
	return
}

func (m *Manager) SaveConfig(url string, enabled bool, intervalHours int) error {
	if m.db == nil {
		return nil
	}
	if url != "" && !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("下载地址必须以 http:// 或 https:// 开头")
	}
	if intervalHours < 1 {
		intervalHours = 168
	}
	now := time.Now().Unix()
	eStr := "0"
	if enabled {
		eStr = "1"
	}
	intervalStr := fmt.Sprintf("%d", intervalHours)
	configs := map[string]string{
		"download_url":          url,
		"auto_update_enabled":   eStr,
		"update_interval_hours": intervalStr,
	}
	for k, v := range configs {
		_, err := m.db.Exec("INSERT OR REPLACE INTO geoip_update_config(key, value, updated_at) VALUES(?,?,?)", k, v, now)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) StartAutoUpdate() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	_, enabled, _, _ := m.LoadConfig()
	if !enabled {
		m.mu.Unlock()
		logger.Info("GeoIP自动更新未启用，跳过启动")
		return
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	go func() {
		for {
			_, enabled, interval, _ := m.LoadConfig()
			if !enabled || interval <= 0 {
				interval = 168
			}
			select {
			case <-time.After(time.Duration(interval) * time.Hour):
				url, enabled, _, _ := m.LoadConfig()
				if !enabled {
					continue
				}
				if err := m.DownloadAndUpdate(url); err != nil {
					logger.Warn("GeoIP自动更新失败: %v", err)
				} else {
					logger.Info("GeoIP自动更新成功")
				}
			case <-m.stopCh:
				return
			}
		}
	}()
	logger.Info("GeoIP自动更新已启动")
}

func (m *Manager) StopAutoUpdate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		close(m.stopCh)
		m.running = false
		logger.Info("GeoIP自动更新已停止")
	}
}

func (m *Manager) DownloadAndUpdate(downloadURL string) error {
	if downloadURL == "" {
		return fmt.Errorf("下载URL为空")
	}
	if xutil.IsURLHostPrivate(downloadURL) {
		return fmt.Errorf("下载URL指向私有IP地址，禁止访问: %s", downloadURL)
	}
	logger.Info("GeoIP更新: 开始下载 %s", downloadURL)
	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败, HTTP状态码: %d", resp.StatusCode)
	}
	tmpFile, err := os.CreateTemp("", "geoip-*.mmdb")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	hasher := sha256.New()
	mw := io.MultiWriter(tmpFile, hasher)
	if _, err := io.Copy(mw, resp.Body); err != nil {
		tmpFile.Close()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	tmpFile.Close()
	if reader, err := geoip2.Open(tmpPath); err != nil {
		return fmt.Errorf("验证mmdb文件失败: %w", err)
	} else {
		reader.Close()
	}
	targetDir := filepath.Dir(m.currentDBPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %w", err)
	}
	backupPath := m.currentDBPath + ".bak"
	os.Rename(m.currentDBPath, backupPath)
	if err := copyFile(tmpPath, m.currentDBPath); err != nil {
		os.Rename(backupPath, m.currentDBPath)
		return fmt.Errorf("替换mmdb文件失败: %w", err)
	}
	os.Remove(backupPath)
	if m.metricsMgr != nil {
		if err := m.metricsMgr.ReloadGeoIP(m.currentDBPath); err != nil {
			logger.Warn("GeoIP更新: 重载GeoIP失败: %v", err)
		}
	}
	now := time.Now().Unix()
	nowStr := fmt.Sprintf("%d", now)
	m.db.Exec("INSERT OR REPLACE INTO geoip_update_config(key, value, updated_at) VALUES('last_update_time', ?, ?)", nowStr, now)
	logger.Info("GeoIP更新: 完成, SHA256=%x", hasher.Sum(nil)[:8])
	return nil
}

func (m *Manager) TriggerUpdate() error {
	url, _, _, _ := m.LoadConfig()
	return m.DownloadAndUpdate(url)
}

func (m *Manager) UpdateFromFile(srcPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := os.Stat(srcPath); err != nil {
		return fmt.Errorf("源文件不存在: %w", err)
	}
	reader, err := geoip2.Open(srcPath)
	if err != nil {
		return fmt.Errorf("验证mmdb文件失败: %w", err)
	}
	reader.Close()
	targetDir := filepath.Dir(m.currentDBPath)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return fmt.Errorf("创建目标目录失败: %w", err)
	}
	backupPath := m.currentDBPath + ".bak"
	os.Rename(m.currentDBPath, backupPath)
	if err := copyFile(srcPath, m.currentDBPath); err != nil {
		os.Rename(backupPath, m.currentDBPath)
		return fmt.Errorf("替换mmdb文件失败: %w", err)
	}
	os.Remove(backupPath)
	if m.metricsMgr != nil {
		if err := m.metricsMgr.ReloadGeoIP(m.currentDBPath); err != nil {
			logger.Warn("GeoIP更新: 重载GeoIP失败: %v", err)
		}
	}
	now := time.Now().Unix()
	nowStr := fmt.Sprintf("%d", now)
	if m.db != nil {
		m.db.Exec("INSERT OR REPLACE INTO geoip_update_config(key, value, updated_at) VALUES('last_update_time', ?, ?)", nowStr, now)
	}
	logger.Info("GeoIP更新: 从上传文件更新成功")
	return nil
}

func (m *Manager) CurrentDBPath() string {
	return m.currentDBPath
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
