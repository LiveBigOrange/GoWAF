package proxy

import (
	"sync"
)

type LogCapture struct {
	mu   sync.Mutex
	logs []map[string]string
}

func NewLogCapture() *LogCapture {
	return &LogCapture{}
}

func (lc *LogCapture) Add(log map[string]string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.logs = append(lc.logs, log)
}

func (lc *LogCapture) Logs() []map[string]string {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	cp := make([]map[string]string, len(lc.logs))
	copy(cp, lc.logs)
	return cp
}

func (lc *LogCapture) Reset() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	lc.logs = nil
}

type MockRateLimitEngine struct {
	mu        sync.Mutex
	feedbacks []rateLimitFeedback
}

type rateLimitFeedback struct {
	IP        string
	Path      string
	RuleID    string
	IsBlocked bool
}

func NewMockRateLimitEngine() *MockRateLimitEngine {
	return &MockRateLimitEngine{}
}

func (m *MockRateLimitEngine) RecordFeedback(info interface{ GetIP() string }) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.feedbacks = append(m.feedbacks, rateLimitFeedback{IP: info.GetIP()})
}

func (m *MockRateLimitEngine) Feedbacks() []rateLimitFeedback {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]rateLimitFeedback, len(m.feedbacks))
	copy(cp, m.feedbacks)
	return cp
}

func (m *MockRateLimitEngine) WasCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.feedbacks) > 0
}

type MockNotifyEngine struct {
	mu     sync.Mutex
	alerts []AlertRecord
}

type AlertRecord struct {
	AttackType string
	RuleID     string
	ClientIP   string
}

func NewMockNotifyEngine() *MockNotifyEngine {
	return &MockNotifyEngine{}
}

func (m *MockNotifyEngine) EvaluateAndAlert(attackType, ruleID, clientIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, AlertRecord{
		AttackType: attackType,
		RuleID:     ruleID,
		ClientIP:   clientIP,
	})
}

func (m *MockNotifyEngine) Alerts() []AlertRecord {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]AlertRecord, len(m.alerts))
	copy(cp, m.alerts)
	return cp
}

func (m *MockNotifyEngine) WasCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.alerts) > 0
}
