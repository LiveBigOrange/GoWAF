package limiter

import (
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestNewIPRateLimiter(t *testing.T) {
	l := NewIPRateLimiter(1, 5)
	if l == nil {
		t.Fatal("NewIPRateLimiter returned nil")
	}
	if !l.GetEnabled() {
		t.Error("new limiter should be enabled by default")
	}
	r, b := l.GetConfig()
	if r != 1 {
		t.Errorf("expected rate=1, got %v", r)
	}
	if b != 5 {
		t.Errorf("expected burst=5, got %d", b)
	}
}

func TestAllow_BasicRateLimiting(t *testing.T) {
	l := NewIPRateLimiter(1, 2)
	ip := "192.168.1.1"

	if !l.Allow(ip) {
		t.Fatal("first Allow should succeed with burst=2")
	}
	if !l.Allow(ip) {
		t.Fatal("second Allow should succeed with burst=2")
	}

	if l.Allow(ip) {
		t.Error("3rd call should be rate-limited with rate=1, burst=2")
	}

	time.Sleep(1100 * time.Millisecond)
	if !l.Allow(ip) {
		t.Error("After waiting >1s, Allow should succeed again")
	}
}

func TestAllow_DifferentIPsIndependent(t *testing.T) {
	l := NewIPRateLimiter(1, 1)

	if !l.Allow("10.0.0.1") {
		t.Error("first Allow for 10.0.0.1 should succeed")
	}
	if l.Allow("10.0.0.1") {
		t.Error("second Allow for 10.0.0.1 should be rate-limited (burst=1)")
	}
	if !l.Allow("10.0.0.2") {
		t.Error("Allow for different IP 10.0.0.2 should be independent and succeed")
	}
}

func TestAllow_DisabledReturnsTrue(t *testing.T) {
	l := NewIPRateLimiter(1, 1)
	l.SetEnabled(false)

	for i := 0; i < 100; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("Allow should always return true when disabled (call %d)", i)
		}
	}
}

func TestAllow_EnabledStateToggle(t *testing.T) {
	l := NewIPRateLimiter(1, 1)

	if !l.Allow("10.0.0.1") {
		t.Error("first Allow should succeed")
	}
	if l.Allow("10.0.0.1") {
		t.Error("second Allow should be rate-limited")
	}

	l.SetEnabled(false)
	if !l.Allow("10.0.0.1") {
		t.Error("Allow should return true when disabled")
	}

	l.SetEnabled(true)
	if l.Allow("10.0.0.1") {
		t.Error("After re-enabling, existing limiter entry should still be rate-limited")
	}

	time.Sleep(1100 * time.Millisecond)
	if !l.Allow("10.0.0.1") {
		t.Error("After token refill, Allow should succeed")
	}
}

func TestSetEnabled_GetEnabled(t *testing.T) {
	l := NewIPRateLimiter(1, 5)

	tests := []struct {
		set    bool
		expect bool
	}{
		{true, true},
		{false, false},
		{false, false},
		{true, true},
	}
	for i, tt := range tests {
		l.SetEnabled(tt.set)
		if got := l.GetEnabled(); got != tt.expect {
			t.Errorf("test %d: SetEnabled(%v) -> GetEnabled() = %v, want %v", i, tt.set, got, tt.expect)
		}
	}
}

func TestGetConfig(t *testing.T) {
	l := NewIPRateLimiter(5, 10)
	r, b := l.GetConfig()
	if r != 5 {
		t.Errorf("expected rate=5, got %v", r)
	}
	if b != 10 {
		t.Errorf("expected burst=10, got %d", b)
	}
}

func TestUpdateConfig_ResetsLimiters(t *testing.T) {
	l := NewIPRateLimiter(1, 1)

	if !l.Allow("10.0.0.1") {
		t.Error("first Allow should succeed")
	}
	if l.Allow("10.0.0.1") {
		t.Error("second Allow should be rate-limited (burst=1)")
	}

	l.UpdateConfig(10, 5)

	r, b := l.GetConfig()
	if r != 10 {
		t.Errorf("after UpdateConfig, expected rate=10, got %v", r)
	}
	if b != 5 {
		t.Errorf("after UpdateConfig, expected burst=5, got %d", b)
	}

	for i := 0; i < 5; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("after UpdateConfig(burst=5), Allow call %d should succeed", i+1)
		}
	}
}

func TestAllow_UpdatesLastAccessForLRU(t *testing.T) {
	l := NewIPRateLimiter(1, 5)
	ip := "10.0.0.1"

	s := l.getShard(ip)
	s.mu.Lock()
	entry, exists := s.ips[ip]
	s.mu.Unlock()

	if exists {
		t.Fatal("entry should not exist before first Allow")
	}

	l.Allow(ip)

	s.mu.Lock()
	entry, exists = s.ips[ip]
	s.mu.Unlock()

	if !exists {
		t.Fatal("entry should exist after Allow")
	}

	firstAccess := entry.lastAccess
	time.Sleep(1100 * time.Millisecond)

	l.Allow(ip)

	s.mu.Lock()
	entry = s.ips[ip]
	s.mu.Unlock()

	if entry.lastAccess <= firstAccess {
		t.Errorf("lastAccess should be updated on subsequent Allow; first=%d, current=%d", firstAccess, entry.lastAccess)
	}
}

func TestCleanup_RemovesIdleEntries(t *testing.T) {
	l := NewIPRateLimiter(1, 1)

	l.Allow("10.0.0.1")

	s := l.getShard("10.0.0.1")
	s.mu.Lock()
	if entry, ok := s.ips["10.0.0.1"]; ok {
		entry.lastAccess = time.Now().Add(-700 * time.Second).Unix()
	}
	s.mu.Unlock()

	go l.Cleanup(50 * time.Millisecond)

	condition := func() bool {
		s.mu.Lock()
		_, exists := s.ips["10.0.0.1"]
		s.mu.Unlock()
		return !exists
	}

	deadline := time.After(3 * time.Second)
	for {
		if condition() {
			break
		}
		select {
		case <-deadline:
			l.Stop()
			t.Fatal("idle entry should have been removed by Cleanup within 3s")
		default:
			time.Sleep(50 * time.Millisecond)
		}
	}
	l.Stop()

	s.mu.Lock()
	_, exists := s.ips["10.0.0.1"]
	s.mu.Unlock()

	if exists {
		t.Error("idle entry should be removed by Cleanup")
	}
}

func TestConcurrentAllow(t *testing.T) {
	l := NewIPRateLimiter(100, 100)
	var wg sync.WaitGroup
	errors := make(chan error, 1000)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ip := "10.0.0." + string(rune('0'+idx%10))
			for j := 0; j < 10; j++ {
				l.Allow(ip)
			}
		}(i)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestGetConfig_AfterUpdateConfig(t *testing.T) {
	l := NewIPRateLimiter(2, 3)
	l.UpdateConfig(rate.Inf, 10)
	r, b := l.GetConfig()
	if r != rate.Inf {
		t.Errorf("expected rate=Inf after UpdateConfig, got %v", r)
	}
	if b != 10 {
		t.Errorf("expected burst=10 after UpdateConfig, got %d", b)
	}
}
