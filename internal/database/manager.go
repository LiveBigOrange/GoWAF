package database

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

type Manager struct {
	db   *sql.DB
	path string
}

func NewManager(dbPath string) (*Manager, error) {
	// 通过 DSN 参数设置 pragma，确保连接池中所有连接（不仅是第一条）都继承这些设置
	// busy_timeout、synchronous、cache_size、temp_store 是连接级设置，必须在 DSN 中指定
	// journal_mode 和 auto_vacuum 是数据库级设置，设置一次即全局生效
	dsn := dbPath + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=cache_size(5000)&_pragma=temp_store(MEMORY)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	// auto_vacuum 是数据库级别设置，只需执行一次
	db.Exec("PRAGMA auto_vacuum=INCREMENTAL")
	// 更频繁的WAL检查点，避免WAL文件过大影响读性能
	db.Exec("PRAGMA wal_autocheckpoint=500")

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

// TableInitializer 定义数据库表初始化的接口约定
type TableInitializer interface {
	EnsureTables() error
}
