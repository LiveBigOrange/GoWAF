package backend

import (
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory DB: %v", err)
	}
	db.SetMaxOpenConns(1)

	m, err := NewManager(db)
	if err != nil {
		t.Fatalf("Failed to create Manager: %v", err)
	}
	t.Cleanup(func() {
		m.Close()
		db.Close()
	})
	return m
}

func TestNewManager(t *testing.T) {
	m := newTestManager(t)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
}

func TestManager_AddBackend(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{
		Name:    "test-backend",
		Address: "127.0.0.1:8080",
		Weight:  3,
	}
	if err := m.AddBackend(b); err != nil {
		t.Fatalf("AddBackend failed: %v", err)
	}
	if b.ID == "" {
		t.Error("AddBackend should set ID")
	}
	if !b.Enabled {
		t.Error("new backend should be enabled")
	}
	if !b.Healthy {
		t.Error("new backend should be healthy")
	}
	if b.Weight != 3 {
		t.Errorf("expected weight=3, got %d", b.Weight)
	}
}

func TestManager_AddBackend_Defaults(t *testing.T) {
	m := newTestManager(t)

	tests := []struct {
		name    string
		backend *Backend
		check   func(b *Backend)
	}{
		{
			name:    "default weight",
			backend: &Backend{Address: "10.0.0.1:80", Weight: 0},
			check: func(b *Backend) {
				if b.Weight != 1 {
					t.Errorf("expected default weight=1, got %d", b.Weight)
				}
			},
		},
		{
			name:    "default check interval",
			backend: &Backend{Address: "10.0.0.2:80", CheckInterval: 0},
			check: func(b *Backend) {
				if b.CheckInterval != 10 {
					t.Errorf("expected default CheckInterval=10, got %d", b.CheckInterval)
				}
			},
		},
		{
			name:    "default check path",
			backend: &Backend{Address: "10.0.0.3:80", CheckPath: ""},
			check: func(b *Backend) {
				if b.CheckPath != "/health" {
					t.Errorf("expected default CheckPath=/health, got %s", b.CheckPath)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := m.AddBackend(tt.backend); err != nil {
				t.Fatalf("AddBackend failed: %v", err)
			}
			tt.check(tt.backend)
		})
	}
}

func TestManager_GetBackends(t *testing.T) {
	m := newTestManager(t)

	m.AddBackend(&Backend{Address: "10.0.0.1:80"})
	m.AddBackend(&Backend{Address: "10.0.0.2:80"})

	backends := m.GetBackends()
	if len(backends) != 2 {
		t.Errorf("expected 2 backends, got %d", len(backends))
	}
}

func TestManager_GetBackend(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{Address: "10.0.0.1:80"}
	m.AddBackend(b)

	found := m.GetBackend(b.ID)
	if found == nil {
		t.Fatal("GetBackend should find added backend")
	}
	if found.Address != "10.0.0.1:80" {
		t.Errorf("expected address 10.0.0.1:80, got %s", found.Address)
	}

	notFound := m.GetBackend("nonexistent")
	if notFound != nil {
		t.Error("GetBackend should return nil for nonexistent ID")
	}
}

func TestManager_RemoveBackend(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{Address: "10.0.0.1:80"}
	m.AddBackend(b)

	if err := m.RemoveBackend(b.ID); err != nil {
		t.Fatalf("RemoveBackend failed: %v", err)
	}

	if m.GetBackend(b.ID) != nil {
		t.Error("backend should be removed after RemoveBackend")
	}
	backends := m.GetBackends()
	if len(backends) != 0 {
		t.Errorf("expected 0 backends after removal, got %d", len(backends))
	}
}

func TestManager_UpdateBackend(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{Address: "10.0.0.1:80", Name: "original", Weight: 1}
	m.AddBackend(b)

	updated := &Backend{
		ID:            b.ID,
		Address:       "10.0.0.1:8080",
		Name:          "updated",
		Weight:        5,
		Enabled:       true,
		CheckPath:     "/api/health",
		CheckInterval: 30,
	}
	if err := m.UpdateBackend(updated); err != nil {
		t.Fatalf("UpdateBackend failed: %v", err)
	}

	found := m.GetBackend(b.ID)
	if found.Name != "updated" {
		t.Errorf("expected name=updated, got %s", found.Name)
	}
	if found.Weight != 5 {
		t.Errorf("expected weight=5, got %d", found.Weight)
	}
	if found.Address != "10.0.0.1:8080" {
		t.Errorf("expected address=10.0.0.1:8080, got %s", found.Address)
	}
}

func TestManager_SelectBackend_WeightedRR(t *testing.T) {
	originalPolicy := GetLBPolicy()
	SetLBPolicy(LBWeightedRR)
	defer SetLBPolicy(originalPolicy)

	m := newTestManager(t)

	b1 := &Backend{Address: "10.0.0.1:80", Weight: 3}
	b2 := &Backend{Address: "10.0.0.2:80", Weight: 1}
	m.AddBackend(b1)
	m.AddBackend(b2)

	selected := m.SelectBackend()
	if selected == nil {
		t.Fatal("SelectBackend should return a backend")
	}
}

func TestManager_SelectBackend_RoundRobin(t *testing.T) {
	originalPolicy := GetLBPolicy()
	SetLBPolicy(LBRoundRobin)
	defer SetLBPolicy(originalPolicy)

	m := newTestManager(t)

	b1 := &Backend{Address: "10.0.0.1:80"}
	b2 := &Backend{Address: "10.0.0.2:80"}
	m.AddBackend(b1)
	m.AddBackend(b2)

	selections := make(map[string]int)
	for i := 0; i < 100; i++ {
		s := m.SelectBackend()
		if s == nil {
			t.Fatal("SelectBackend should return a backend")
		}
		selections[s.Address]++
	}
	if len(selections) < 2 {
		t.Errorf("round-robin should distribute across backends, got selections: %v", selections)
	}
}

func TestManager_SelectBackend_LeastConns(t *testing.T) {
	originalPolicy := GetLBPolicy()
	SetLBPolicy(LBLeastConns)
	defer SetLBPolicy(originalPolicy)

	m := newTestManager(t)

	b1 := &Backend{Address: "10.0.0.1:80", Weight: 1}
	b2 := &Backend{Address: "10.0.0.2:80", Weight: 1}
	m.AddBackend(b1)
	m.AddBackend(b2)

	m.IncConn(b1.ID)

	selected := m.SelectBackend()
	if selected == nil {
		t.Fatal("SelectBackend should return a backend")
	}
	if selected.ID != b2.ID {
		t.Errorf("least_conns should select backend with fewer connections; got %s, want %s", selected.Address, b2.Address)
	}

	m.DecConn(b1.ID)
}

func TestManager_SelectBackend_NoAvailable(t *testing.T) {
	originalPolicy := GetLBPolicy()
	SetLBPolicy(LBRoundRobin)
	defer SetLBPolicy(originalPolicy)

	m := newTestManager(t)

	if m.SelectBackend() != nil {
		t.Error("SelectBackend should return nil when no backends exist")
	}

	b := &Backend{Address: "10.0.0.1:80"}
	m.AddBackend(b)
	m.MarkHealthy(b.ID, false)

	if m.SelectBackend() != nil {
		t.Error("SelectBackend should return nil when all backends are unhealthy")
	}
}

func TestManager_MarkHealthy(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{Address: "10.0.0.1:80"}
	m.AddBackend(b)

	if !b.Healthy {
		t.Error("new backend should be healthy")
	}

	m.MarkHealthy(b.ID, false)
	found := m.GetBackend(b.ID)
	if found.Healthy {
		t.Error("backend should be unhealthy after MarkHealthy(false)")
	}

	m.MarkHealthy(b.ID, true)
	found = m.GetBackend(b.ID)
	if !found.Healthy {
		t.Error("backend should be healthy after MarkHealthy(true)")
	}
}

func TestManager_IncDecConn(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{Address: "10.0.0.1:80"}
	m.AddBackend(b)

	m.IncConn(b.ID)
	found := m.GetBackend(b.ID)
	if found.ActiveConns != 1 {
		t.Errorf("expected ActiveConns=1, got %d", found.ActiveConns)
	}
	if found.TotalReqs != 1 {
		t.Errorf("expected TotalReqs=1, got %d", found.TotalReqs)
	}

	m.IncConn(b.ID)
	found = m.GetBackend(b.ID)
	if found.ActiveConns != 2 {
		t.Errorf("expected ActiveConns=2, got %d", found.ActiveConns)
	}

	m.DecConn(b.ID)
	found = m.GetBackend(b.ID)
	if found.ActiveConns != 1 {
		t.Errorf("expected ActiveConns=1 after DecConn, got %d", found.ActiveConns)
	}

	m.DecConn(b.ID)
	found = m.GetBackend(b.ID)
	if found.ActiveConns != 0 {
		t.Errorf("expected ActiveConns=0, got %d", found.ActiveConns)
	}
}

func TestManager_DecConn_NotBelowZero(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{Address: "10.0.0.1:80"}
	m.AddBackend(b)

	m.DecConn(b.ID)
	found := m.GetBackend(b.ID)
	if found.ActiveConns != 0 {
		t.Errorf("ActiveConns should not go below 0, got %d", found.ActiveConns)
	}
}

func TestManager_SelectBackendByID(t *testing.T) {
	m := newTestManager(t)

	b1 := &Backend{Address: "10.0.0.1:80"}
	b2 := &Backend{Address: "10.0.0.2:80"}
	m.AddBackend(b1)
	m.AddBackend(b2)

	found := m.SelectBackendByID(b1.ID)
	if found == nil || found.ID != b1.ID {
		t.Error("SelectBackendByID should find existing enabled healthy backend")
	}

	if m.SelectBackendByID("nonexistent") != nil {
		t.Error("SelectBackendByID should return nil for nonexistent ID")
	}
}

func TestSetGetLBPolicy(t *testing.T) {
	original := GetLBPolicy()

	tests := []LBPolicy{LBRoundRobin, LBWeightedRR, LBLeastConns, LBIPHash, LBURLHash, LBRandom}
	for _, policy := range tests {
		SetLBPolicy(policy)
		if got := GetLBPolicy(); got != policy {
			t.Errorf("SetLBPolicy(%s) -> GetLBPolicy() = %s", policy, got)
		}
	}

	SetLBPolicy(original)
}

func TestManager_AddBackend_DuplicateAddress(t *testing.T) {
	m := newTestManager(t)

	b1 := &Backend{Address: "10.0.0.1:80"}
	if err := m.AddBackend(b1); err != nil {
		t.Fatalf("first AddBackend failed: %v", err)
	}

	b2 := &Backend{Address: "10.0.0.1:80"}
	if err := m.AddBackend(b2); err == nil {
		t.Error("adding backend with duplicate address should fail")
	}
}

func TestManager_ConsistentIDFormat(t *testing.T) {
	m := newTestManager(t)

	b := &Backend{Address: "192.168.1.1:8080"}
	m.AddBackend(b)

	expectedPrefix := time.Now().Format("20060102150405")
	if len(b.ID) < len(expectedPrefix) {
		t.Errorf("ID seems too short: %s", b.ID)
	}
}
