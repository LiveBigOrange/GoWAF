package database

import (
	"database/sql"
	"sync"

	_ "modernc.org/sqlite"
)

// Manager 数据库管理器
type Manager struct {
	db   *sql.DB
	path string
	mu   sync.RWMutex
}

// NewManager 创建数据库管理器
func NewManager(dbPath string) (*Manager, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// SQLite性能优化配置
	pragmas := []string{
		"PRAGMA journal_mode=WAL",        // WAL模式，提高并发性能
		"PRAGMA cache_size=5000",         // 增大缓存
		"PRAGMA synchronous=NORMAL",      // 平衡性能和安全
		"PRAGMA auto_vacuum=INCREMENTAL", // 自动回收空间
		"PRAGMA temp_store=MEMORY",       // 临时数据存内存
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			// 优化配置失败不影响启动
			continue
		}
	}

	return &Manager{
		db:   db,
		path: dbPath,
	}, nil
}

// GetDB 获取数据库连接
func (m *Manager) GetDB() *sql.DB {
	return m.db
}

// Close 关闭数据库连接
func (m *Manager) Close() error {
	return m.db.Close()
}
