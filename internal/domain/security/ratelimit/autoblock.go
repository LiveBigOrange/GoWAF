package ratelimit

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"gowaf/internal/infra/logger"
)

type IPRuleManager interface {
	AddIPRule(ruleType, ip string) error
	AddIPRuleBySource(ruleType, ip, source string) error
	RemoveIPRule(ruleType, ip string) error
}

type AutoBlocker struct {
	mu            sync.Mutex
	failCount     map[string]int
	blockedUntil  map[string]time.Time
	ruleEngine    IPRuleManager
	maxFails      int
	blockDuration time.Duration
	db            *sql.DB
}

func NewAutoBlocker(ruleEngine IPRuleManager, maxFails int, blockDuration time.Duration, db *sql.DB) *AutoBlocker {
	if db != nil {
		if err := ensureAutoblockTables(db); err != nil {
			logger.Warn("autoblock_records表创建失败", "err", err)
		}
	}
	return &AutoBlocker{
		failCount:     make(map[string]int),
		blockedUntil:  make(map[string]time.Time),
		ruleEngine:    ruleEngine,
		maxFails:      maxFails,
		blockDuration: blockDuration,
		db:            db,
	}
}

// RecordChallengeFail 记录挑战失败，达到阈值时执行三步原子性封禁
// Step1: 持久化到数据库（失败则中止）
// Step2: 写入IP规则引擎（失败则回滚数据库）
// Step3: 更新内存状态
func (a *AutoBlocker) RecordChallengeFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, blocked := a.blockedUntil[ip]; blocked {
		return
	}

	if a.failCount[ip] >= a.maxFails-1 {
		until := time.Now().Add(a.blockDuration)

		// Step 1: 持久化到数据库
		if err := a.persistBlock(ip, until, a.failCount[ip]+1); err != nil {
			logger.Warn("autoblock持久化失败，中止封禁", "ip", ip, "err", err)
			a.failCount[ip]++
			return
		}

		// Step 2: 写入IP规则引擎
		if err := a.ruleEngine.AddIPRuleBySource("blacklist", ip, "autoblock"); err != nil {
			logger.Warn("autoblock写入规则引擎失败，回滚持久化", "ip", ip, "err", err)
			a.rollbackPersist(ip)
			a.failCount[ip]++
			return
		}

		// Step 3: 更新内存状态
		a.blockedUntil[ip] = until
		a.failCount[ip] = 0
		logger.Info("自动封禁IP", "ip", ip, "duration", a.blockDuration, "until", until)
	} else {
		a.failCount[ip]++
	}
}

func (a *AutoBlocker) RecordChallengePass(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failCount[ip] = 0
}

func (a *AutoBlocker) IsBlocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, exists := a.blockedUntil[ip]
	if !exists {
		return false
	}
	if time.Now().After(until) {
		delete(a.blockedUntil, ip)
		a.failCount[ip] = 0
		if err := a.ruleEngine.RemoveIPRule("blacklist", ip); err != nil {
			logger.Warn("自动解封IP失败", "ip", ip, "err", err)
		} else {
			a.deletePersistedBlock(ip)
			logger.Info("自动解封IP（已过期）", "ip", ip)
		}
		return false
	}
	return true
}

func (a *AutoBlocker) ExpireBlocks() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for ip, until := range a.blockedUntil {
		if now.After(until) {
			delete(a.blockedUntil, ip)
			a.failCount[ip] = 0
			if err := a.ruleEngine.RemoveIPRule("blacklist", ip); err != nil {
				logger.Warn("自动解封IP失败", "ip", ip, "err", err)
			} else {
				a.deletePersistedBlock(ip)
				logger.Info("自动解封IP（已过期）", "ip", ip)
			}
		}
	}
}

// AddIPRuleBySource 兼容旧接口：当IPRuleManager未实现AddIPRuleBySource时的降级处理
type fallbackIPRuleManager struct {
	IPRuleManager
}

func (f *fallbackIPRuleManager) AddIPRuleBySource(ruleType, ip, source string) error {
	return f.AddIPRule(ruleType, ip)
}

// WrapIPRuleManager 包装IPRuleManager，若未实现AddIPRuleBySource则降级
func WrapIPRuleManager(m IPRuleManager) IPRuleManager {
	if _, ok := m.(interface {
		AddIPRuleBySource(string, string, string) error
	}); ok {
		return m
	}
	return &fallbackIPRuleManager{IPRuleManager: m}
}

// RecoverFromDB 从数据库恢复autoblock状态（任务6）
func (a *AutoBlocker) RecoverFromDB() error {
	if a.db == nil {
		return nil
	}

	rows, err := a.db.Query(
		"SELECT ip, blocked_until, fail_count FROM autoblock_records WHERE source='autoblock' AND blocked_until > ?",
		time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to query autoblock_records: %w", err)
	}
	defer rows.Close()

	a.mu.Lock()
	defer a.mu.Unlock()

	count := 0
	for rows.Next() {
		var ip string
		var untilStr string
		var failCount int
		if err := rows.Scan(&ip, &untilStr, &failCount); err != nil {
			continue
		}
		until, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			until = time.Now().Add(a.blockDuration)
			logger.Warn("autoblock过期时间解析失败，使用默认值", "ip", ip, "raw", untilStr)
		}
		if time.Now().After(until) {
			a.deletePersistedBlock(ip)
			continue
		}
		a.blockedUntil[ip] = until
		a.failCount[ip] = failCount
		count++
	}

	logger.Info("autoblock状态恢复完成", "count", count)
	return nil
}
