package ratelimit

import (
	"sync"
	"time"

	"gowaf/internal/infra/logger"
)

type AutoBlockReconciler struct {
	autoBlocker       *AutoBlocker
	reconcileInterval time.Duration
	stopCh            chan struct{}
	wg                sync.WaitGroup
}

func NewAutoBlockReconciler(autoBlocker *AutoBlocker, interval time.Duration) *AutoBlockReconciler {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &AutoBlockReconciler{
		autoBlocker:       autoBlocker,
		reconcileInterval: interval,
		stopCh:            make(chan struct{}),
	}
}

func (r *AutoBlockReconciler) Start() {
	r.wg.Add(1)
	go r.run()
	logger.Info("autoblock对账启动", "interval", r.reconcileInterval)
}

func (r *AutoBlockReconciler) Stop() {
	close(r.stopCh)
	r.wg.Wait()
	logger.Info("autoblock对账停止")
}

func (r *AutoBlockReconciler) run() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.reconcile()
		}
	}
}

func (r *AutoBlockReconciler) reconcile() {
	if r.autoBlocker == nil || r.autoBlocker.db == nil {
		return
	}

	r.autoBlocker.mu.Lock()
	defer r.autoBlocker.mu.Unlock()

	rows, err := r.autoBlocker.db.Query(
		"SELECT ip, blocked_until FROM autoblock_records WHERE source='autoblock'")
	if err != nil {
		logger.Warn("autoblock对账查询失败", "err", err)
		return
	}
	defer rows.Close()

	dbRecords := make(map[string]time.Time)
	for rows.Next() {
		var ip, untilStr string
		if rows.Scan(&ip, &untilStr) != nil {
			continue
		}
		until, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			until = time.Now().Add(r.autoBlocker.blockDuration)
		}
		dbRecords[ip] = until
	}

	fixedCount := 0
	now := time.Now()

	for ip, dbUntil := range dbRecords {
		memUntil, inMem := r.autoBlocker.blockedUntil[ip]
		if now.After(dbUntil) {
			delete(r.autoBlocker.blockedUntil, ip)
			delete(r.autoBlocker.failCount, ip)
			r.autoBlocker.ruleEngine.RemoveIPRule("blacklist", ip)
			r.autoBlocker.deletePersistedBlock(ip)
			fixedCount++
			continue
		}
		if !inMem {
			r.autoBlocker.blockedUntil[ip] = dbUntil
			r.autoBlocker.failCount[ip] = 0
			fixedCount++
		} else if memUntil != dbUntil {
			r.autoBlocker.blockedUntil[ip] = dbUntil
			fixedCount++
		}
	}

	for ip := range r.autoBlocker.blockedUntil {
		if _, inDB := dbRecords[ip]; !inDB {
			until := r.autoBlocker.blockedUntil[ip]
			if err := r.autoBlocker.persistBlock(ip, until, r.autoBlocker.failCount[ip]); err != nil {
				logger.Warn("autoblock对账写回数据库失败", "ip", ip, "err", err)
			} else {
				fixedCount++
			}
		}
	}

	if fixedCount > 0 {
		logger.Info("autoblock对账完成", "fixed", fixedCount)
	}
}
