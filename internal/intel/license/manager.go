package license

import (
	"context"
	"fmt"
	"sync"
	"time"

	"gowaf/internal/intel/client"
	"gowaf/internal/intel/config"
	"gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
)

type LicenseState struct {
	Valid            bool            `json:"valid"`
	Tier             string          `json:"tier"`
	Features         map[string]bool `json:"-"`
	SyncIntervalSecs int             `json:"sync_interval_secs"`
	ExpiresAt        time.Time       `json:"expires_at"`
	GraceEndsAt      time.Time       `json:"grace_ends_at"`
	Status           string          `json:"status"`
	LastVerifiedAt   time.Time       `json:"last_verified_at"`
	InstanceLimit    int             `json:"instance_limit"`
}

type LicenseManager struct {
	intelClient *client.IntelClient
	store       *store.Store
	state       LicenseState
	stateMu     sync.RWMutex
	stopCh      chan struct{}
	stopOnce    sync.Once
	cfg         *config.IntelConfig
}

func NewLicenseManager(intelClient *client.IntelClient, store *store.Store, cfg *config.IntelConfig) *LicenseManager {
	return &LicenseManager{
		intelClient: intelClient,
		store:       store,
		cfg:         cfg,
		stopCh:      make(chan struct{}),
		state: LicenseState{
			Status: "unknown",
			Tier:   "free",
		},
	}
}

func (m *LicenseManager) Start(ctx context.Context) {
	go m.verifyLoop(ctx)
	logger.Info("license manager started")
}

func (m *LicenseManager) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		logger.Info("license manager stopped")
	})
}

func (m *LicenseManager) verifyLoop(ctx context.Context) {
	interval := time.Duration(m.cfg.Sync.IntervalSecs) * time.Second
	if interval < time.Minute {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := m.Verify(ctx); err != nil {
		logger.Error("initial license verification failed", "err", err)
	}

	for {
		select {
		case <-m.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Verify(ctx); err != nil {
				logger.Error("license verification failed", "err", err)
			}
		}
	}
}

func (m *LicenseManager) Verify(ctx context.Context) error {
	req := &client.LicenseVerifyReq{
		LicenseKey: m.cfg.LicenseKey,
		InstanceID: m.cfg.InstanceID,
	}

	resp, err := m.intelClient.VerifyLicense(ctx, req)
	if err != nil {
		m.transitionTo("free")
		m.stateMu.Lock()
		m.state.Valid = false
		m.state.LastVerifiedAt = time.Now()
		m.stateMu.Unlock()
		return fmt.Errorf("license verify request failed: %w", err)
	}

	m.stateMu.Lock()
	defer m.stateMu.Unlock()

	m.state.Valid = resp.Valid
	m.state.Tier = resp.Tier
	m.state.InstanceLimit = resp.InstanceLimit
	m.state.SyncIntervalSecs = resp.SyncIntervalSecs
	m.state.LastVerifiedAt = time.Now()
	m.state.Features = make(map[string]bool)
	for _, f := range resp.Features {
		m.state.Features[f] = true
	}

	if resp.ExpiresAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, resp.ExpiresAt); parseErr == nil {
			m.state.ExpiresAt = t
		}
	}
	if resp.GraceEndsAt != "" {
		if t, parseErr := time.Parse(time.RFC3339, resp.GraceEndsAt); parseErr == nil {
			m.state.GraceEndsAt = t
		}
	}

	if !resp.Valid {
		m.state.Status = "expired"
	} else if !m.state.GraceEndsAt.IsZero() && time.Now().After(m.state.GraceEndsAt) {
		m.state.Status = "grace"
	} else {
		m.state.Status = "active"
	}

	if m.store != nil {
		_ = m.store.AddConnectionLog("license_verify", fmt.Sprintf("tier=%s status=%s", m.state.Tier, m.state.Status))
	}

	return nil
}

func (m *LicenseManager) GetState() LicenseState {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state
}

func (m *LicenseManager) HasFeature(feature string) bool {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return m.state.Features[feature]
}

func (m *LicenseManager) GetSyncInterval() time.Duration {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()

	if m.state.SyncIntervalSecs > 0 {
		return time.Duration(m.state.SyncIntervalSecs) * time.Second
	}
	return time.Duration(GetTierSyncInterval(m.state.Tier)) * time.Second
}

func (m *LicenseManager) GetAllowedDataTypes() []string {
	m.stateMu.RLock()
	tier := m.state.Tier
	m.stateMu.RUnlock()
	return GetTierAllowedDataTypes(tier)
}

func (m *LicenseManager) SetStateFree() {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.state = LicenseState{
		Status:   "free",
		Tier:     "free",
		Valid:    false,
		Features: make(map[string]bool),
	}
}

func (m *LicenseManager) SetStatePaused() {
	m.transitionTo("paused")
}

func (m *LicenseManager) transitionTo(status string) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	m.state.Status = status
	logger.Info("license state transitioned", "status", status)
}
