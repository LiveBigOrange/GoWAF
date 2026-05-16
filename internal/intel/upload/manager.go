package upload

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"gowaf/internal/intel/client"
	"gowaf/internal/intel/config"
	"gowaf/internal/intel/license"
	"gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
)

type Manager struct {
	client  *client.IntelClient
	store   *store.Store
	config  *config.IntelConfig
	license *license.LicenseManager
	stopCh  chan struct{}
	mu      sync.Mutex
	running bool
}

func NewManager(c *client.IntelClient, s *store.Store, cfg *config.IntelConfig, l *license.LicenseManager) *Manager {
	return &Manager{
		client:  c,
		store:   s,
		config:  cfg,
		license: l,
		stopCh:  make(chan struct{}),
	}
}

func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	go m.run(ctx)
	logger.Info("upload manager started")
}

func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		close(m.stopCh)
		m.running = false
		logger.Info("upload manager stopped")
	}
}

func (m *Manager) run(ctx context.Context) {
	interval := m.config.Upload.IntervalSecs
	if interval <= 0 {
		interval = 300
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.processQueue(ctx)
		}
	}
}

func (m *Manager) processQueue(ctx context.Context) {
	if !m.config.Upload.Enabled {
		return
	}
	if m.license != nil {
		state := m.license.GetState()
		if state.Status != "active" && state.Status != "grace" {
			return
		}
	}

	for _, dataType := range m.config.Upload.DataTypes {
		items, err := m.store.GetPendingUploads(dataType, m.config.Upload.BatchSize)
		if err != nil {
			logger.Error("get pending uploads failed", "data_type", dataType, "err", err)
			continue
		}
		if len(items) == 0 {
			continue
		}

		events := make([]interface{}, 0, len(items))
		for _, item := range items {
			var data interface{}
			if err := json.Unmarshal([]byte(item.PayloadJSON), &data); err == nil {
				events = append(events, data)
			}
		}

		resp, err := m.client.UploadEvents(ctx, &client.UploadReq{
			DataType:   dataType,
			InstanceID: m.config.InstanceID,
			Events:     events,
		})

		if err != nil {
			logger.Error("upload events failed", "data_type", dataType, "err", err)
			m.recordUploadLog(dataType, len(items), 0, 0, 0, false, err.Error(), "")
			continue
		}

		for _, item := range items {
			m.store.UpdateUploadStatus(item.ID, "sent", "")
		}

		m.recordUploadLog(dataType, len(items), resp.Accepted, resp.Rejected, resp.CreditsAwarded, true, "", "")

		if resp.CreditsAwarded > 0 {
			m.store.AddCredits(&store.CreditsEntry{
				Amount:      resp.CreditsAwarded,
				Type:        "earned",
				Reference:   dataType,
				Description: fmt.Sprintf("上传 %d 条 %s 事件", len(items), dataType),
			})
		}

		logger.Info("upload completed", "data_type", dataType, "accepted", resp.Accepted, "rejected", resp.Rejected, "credits", resp.CreditsAwarded)
	}
}

func (m *Manager) recordUploadLog(dataType string, itemsCount, accepted, rejected, credits int, success bool, errMsg, responseJSON string) {
	if m.store == nil {
		return
	}
	successInt := 1
	if !success {
		successInt = 0
	}
	m.store.AddUploadLog(&store.UploadLogEntry{
		DataType:       dataType,
		ItemsCount:     itemsCount,
		AcceptedCount:  accepted,
		RejectedCount:  rejected,
		CreditsAwarded: credits,
		Success:        successInt == 1,
		ErrorMsg:       errMsg,
	})
}

func (m *Manager) ApproveItem(id int64, note string) error {
	return m.store.UpdateUploadStatus(id, "approved", note)
}

func (m *Manager) RejectItem(id int64, note string) error {
	return m.store.UpdateUploadStatus(id, "rejected", note)
}

func (m *Manager) BatchApprove(ids []int64, note string) error {
	for _, id := range ids {
		if err := m.ApproveItem(id, note); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) BatchReject(ids []int64, note string) error {
	for _, id := range ids {
		if err := m.RejectItem(id, note); err != nil {
			return err
		}
	}
	return nil
}
