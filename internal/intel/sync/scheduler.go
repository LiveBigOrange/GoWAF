package sync

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gowaf/internal/intel/alerts"
	"gowaf/internal/intel/client"
	"gowaf/internal/intel/config"
	"gowaf/internal/intel/license"
	"gowaf/internal/intel/merger"
	"gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
)

type Scheduler struct {
	client  *client.IntelClient
	store   *store.Store
	license *license.LicenseManager
	merger  *merger.Merger
	watcher *alerts.Watcher
	cfg     *config.IntelConfig
	stopCh  chan struct{}
	mu      sync.Mutex
	running bool
}

func NewScheduler(c *client.IntelClient, s *store.Store, l *license.LicenseManager, m *merger.Merger, cfg *config.IntelConfig, w *alerts.Watcher) *Scheduler {
	return &Scheduler{
		client:  c,
		store:   s,
		license: l,
		merger:  m,
		watcher: w,
		cfg:     cfg,
		stopCh:  make(chan struct{}),
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	go s.run(ctx)
	logger.Info("intel sync scheduler started")
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		close(s.stopCh)
		s.running = false
		logger.Info("intel sync scheduler stopped")
	}
}

func (s *Scheduler) run(ctx context.Context) {
	interval := s.getSyncInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.syncAll(ctx)

	for {
		select {
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.syncAll(ctx)
			newInterval := s.getSyncInterval()
			if newInterval != interval {
				interval = newInterval
				ticker.Reset(interval)
				logger.Info("sync interval updated", "interval_secs", interval/time.Second)
			}
		}
	}
}

func (s *Scheduler) getSyncInterval() time.Duration {
	if s.license != nil {
		if interval := s.license.GetSyncInterval(); interval > 0 {
			return interval
		}
	}
	interval := time.Duration(s.cfg.Sync.IntervalSecs) * time.Second
	if interval <= 0 {
		interval = 3600 * time.Second
	}
	return interval
}

func (s *Scheduler) syncAll(ctx context.Context) {
	if !s.cfg.Sync.Enabled {
		return
	}
	if s.license != nil {
		state := s.license.GetState()
		if state.Status == "expired" {
			return
		}
	}

	for _, dataType := range s.cfg.Sync.DataTypes {
		if err := s.syncDataType(ctx, dataType); err != nil {
			logger.Error("sync failed", "data_type", dataType, "err", err)
			if s.watcher != nil {
				s.watcher.OnSyncFailure(dataType)
			}
		} else {
			if s.watcher != nil {
				s.watcher.OnSyncSuccess(dataType)
			}
		}
	}
}

func (s *Scheduler) syncDataType(ctx context.Context, dataType string) error {
	start := time.Now()

	var sinceVersion string
	if s.store != nil {
		state, err := s.store.GetState(dataType)
		if err != nil {
			return fmt.Errorf("get state: %w", err)
		}
		sinceVersion = state.CurrentVersion
	}

	resp, err := s.client.SyncData(ctx, dataType, sinceVersion, 500)
	if err != nil {
		s.recordSyncLog(dataType, "incremental", 0, 0, 0, 0, sinceVersion, "", false, err.Error(), start)
		return err
	}

	addedCount := len(resp.Added)
	modifiedCount := len(resp.Modified)
	deletedCount := len(resp.Deleted)

	for _, item := range resp.Added {
		if err := s.applySyncItem(dataType, "add", item); err != nil {
			logger.Error("apply sync item failed", "data_type", dataType, "action", "add", "intel_id", item.IntelID, "err", err)
		}
	}

	for _, item := range resp.Modified {
		if err := s.applySyncItem(dataType, "modify", item); err != nil {
			logger.Error("apply sync item failed", "data_type", dataType, "action", "modify", "intel_id", item.IntelID, "err", err)
		}
	}

	if deletedCount > 0 {
		intelIDs := make([]string, 0, deletedCount)
		if len(resp.DeletedIDs) > 0 {
			intelIDs = resp.DeletedIDs
		} else {
			for _, item := range resp.Deleted {
				intelIDs = append(intelIDs, item.IntelID)
			}
		}
		if err := s.merger.ApplyDeleted(intelIDs, dataType); err != nil {
			logger.Error("apply deleted failed", "data_type", dataType, "err", err)
		}
	}

	if s.store != nil {
		s.store.SaveState(&store.SyncState{
			DataType:       dataType,
			CurrentVersion: resp.CurrentVersion,
			Status:         "success",
		})
	}

	s.recordSyncLog(dataType, "incremental", addedCount, modifiedCount, deletedCount, 0, sinceVersion, resp.CurrentVersion, true, "", start)

	logger.Info("sync completed", "data_type", dataType, "added", addedCount, "modified", modifiedCount, "deleted", deletedCount)
	return nil
}

func (s *Scheduler) applySyncItem(dataType, action string, item client.SyncItem) error {
	switch dataType {
	case "ip_blacklist":
		if m, ok := item.Data.(map[string]interface{}); ok {
			ip, _ := m["ip"].(string)
			ruleType := "blacklist"
			if rt, ok := m["rule_type"].(string); ok {
				ruleType = rt
			}
			return s.merger.MergeIPRule(&merger.IPRuleEntry{
				IP:       ip,
				RuleType: ruleType,
				IntelID:  item.IntelID,
			})
		}
	case "ua_rules":
		if m, ok := item.Data.(map[string]interface{}); ok {
			pattern, _ := m["pattern"].(string)
			matchType := "contains"
			if mt, ok := m["match_type"].(string); ok {
				matchType = mt
			}
			return s.merger.MergeUARule(&merger.UARuleEntry{
				Pattern:   pattern,
				RuleType:  "blacklist",
				MatchType: matchType,
				IntelID:   item.IntelID,
			})
		}
	case "path_rules":
		if m, ok := item.Data.(map[string]interface{}); ok {
			pattern, _ := m["pattern"].(string)
			matchType := "prefix"
			if mt, ok := m["match_type"].(string); ok {
				matchType = mt
			}
			return s.merger.MergePathRule(&merger.PathRuleEntry{
				Pattern:   pattern,
				RuleType:  "blacklist",
				MatchType: matchType,
				IntelID:   item.IntelID,
			})
		}
	case "bot_ips":
		if m, ok := item.Data.(map[string]interface{}); ok {
			ip, _ := m["ip"].(string)
			cidr, _ := m["cidr"].(string)
			botType, _ := m["bot_type"].(string)
			return s.merger.MergeBotIP(&merger.BotIPEntry{
				IP:      ip,
				CIDR:    cidr,
				BotType: botType,
				IntelID: item.IntelID,
			})
		}
	case "threat_signatures":
		if m, ok := item.Data.(map[string]interface{}); ok {
			attackType, _ := m["attack_type"].(string)
			pattern, _ := m["pattern"].(string)
			severity, _ := m["severity"].(string)
			return s.merger.MergeSignatureRule(&merger.SignatureEntry{
				AttackType: attackType,
				Pattern:    pattern,
				Severity:   severity,
				IntelID:    item.IntelID,
			})
		}
	case "geoip":
		if m, ok := item.Data.(map[string]interface{}); ok {
			filePath, _ := m["file_path"].(string)
			checksum, _ := m["checksum"].(string)
			var fileSize int64
			if fs, ok := m["file_size"].(float64); ok {
				fileSize = int64(fs)
			}
			return s.merger.MergeGeoIPData(item.IntelID, filePath, checksum, fileSize)
		}
	}
	return nil
}

func (s *Scheduler) recordSyncLog(dataType, action string, added, modified, deleted, skipped int, versionFrom, versionTo string, success bool, errMsg string, start time.Time) {
	if s.store == nil {
		return
	}
	s.store.AddSyncLog(&store.SyncLogEntry{
		DataType:      dataType,
		Action:        action,
		AddedCount:    added,
		ModifiedCount: modified,
		DeletedCount:  deleted,
		SkippedCount:  skipped,
		VersionFrom:   versionFrom,
		VersionTo:     versionTo,
		Success:       success,
		ErrorMsg:      errMsg,
		DurationMs:    int(time.Since(start).Milliseconds()),
	})
}

func (s *Scheduler) TriggerSync(dataType string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.syncDataType(ctx, dataType); err != nil {
		logger.Error("manual sync failed", "data_type", dataType, "err", err)
	}
}

func (s *Scheduler) TriggerFullSync(dataType string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	resp, err := s.client.SyncData(ctx, dataType, "", 500)
	if err != nil {
		s.recordSyncLog(dataType, "full", 0, 0, 0, 0, "", "", false, err.Error(), start)
		return
	}

	for _, item := range resp.Added {
		s.applySyncItem(dataType, "add", item)
	}

	if s.store != nil {
		s.store.SaveState(&store.SyncState{
			DataType:       dataType,
			CurrentVersion: resp.CurrentVersion,
			Status:         "success",
		})
	}

	s.recordSyncLog(dataType, "full", len(resp.Added), 0, len(resp.Deleted), 0, "", resp.CurrentVersion, true, "", start)
	logger.Info("full sync completed", "data_type", dataType)
}
