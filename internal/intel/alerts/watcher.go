package alerts

import (
	"sync"
	"time"

	"gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
)

type Watcher struct {
	store      *store.Store
	failureMu  sync.Mutex
	failCounts map[string]int
	threshold  int
}

func NewWatcher(store *store.Store, threshold int) *Watcher {
	return &Watcher{
		store:      store,
		failCounts: make(map[string]int),
		threshold:  threshold,
	}
}

func (w *Watcher) OnConnectionLost() {
	w.recordEvent("connection_lost", "IntelCenter 连接断开")
	logger.Error("intel center connection lost")
}

func (w *Watcher) OnConnectionRestored() {
	w.recordEvent("connection_restored", "IntelCenter 连接恢复")
	w.failureMu.Lock()
	delete(w.failCounts, "sync")
	delete(w.failCounts, "upload")
	w.failureMu.Unlock()
	logger.Info("intel center connection restored")
}

func (w *Watcher) OnSyncFailure(dataType string) {
	w.failureMu.Lock()
	key := "sync_" + dataType
	w.failCounts[key]++
	count := w.failCounts[key]
	w.failureMu.Unlock()

	if count >= w.threshold {
		w.recordEvent("sync_failure", "同步连续失败 "+string(rune('0'+count%10))+" 次: "+dataType)
		logger.Error("sync consecutive failures exceeded threshold", "data_type", dataType, "count", count)
	} else {
		w.recordEvent("sync_failure", "同步失败: "+dataType)
	}
}

func (w *Watcher) OnSyncSuccess(dataType string) {
	w.failureMu.Lock()
	delete(w.failCounts, "sync_"+dataType)
	w.failureMu.Unlock()
}

func (w *Watcher) OnLicenseExpiring(daysLeft int) {
	level := "warning"
	if daysLeft <= 7 {
		level = "critical"
	}
	w.recordEvent("license_expiring", "License 即将到期，剩余 "+string(rune('0'+daysLeft%10))+" 天")
	logger.Warn("license expiring soon", "days_left", daysLeft, "level", level)
}

func (w *Watcher) OnUploadFailure() {
	w.failureMu.Lock()
	w.failCounts["upload"]++
	count := w.failCounts["upload"]
	w.failureMu.Unlock()

	if count >= w.threshold {
		w.recordEvent("upload_failure", "上传连续失败超过阈值")
	}
}

func (w *Watcher) OnUploadSuccess() {
	w.failureMu.Lock()
	delete(w.failCounts, "upload")
	w.failureMu.Unlock()
}

func (w *Watcher) OnEmergencyRule(id, severity string) {
	w.recordEvent("emergency_rule", "收到紧急规则: "+id+" 严重度: "+severity)
	logger.Warn("emergency rule received", "id", id, "severity", severity)
}

func (w *Watcher) OnUploadRejected(qualityScore float64) {
	w.recordEvent("upload_rejected", "上传被拒绝，质量分过低")
}

func (w *Watcher) recordEvent(eventType, detail string) {
	if w.store != nil {
		_ = w.store.AddConnectionLog(eventType, detail)
	}
}

func (w *Watcher) CheckLicenseExpiry(expiresAt time.Time) {
	if expiresAt.IsZero() {
		return
	}
	daysLeft := int(time.Until(expiresAt).Hours() / 24)
	if daysLeft <= 30 {
		w.OnLicenseExpiring(daysLeft)
	}
}
