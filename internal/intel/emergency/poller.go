package emergency

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"gowaf/internal/intel/client"
	"gowaf/internal/intel/merger"
	"gowaf/internal/intel/store"
	"gowaf/internal/logger"
)

type Poller struct {
	client   *client.IntelClient
	store    *store.Store
	merger   *merger.Merger
	interval time.Duration
	stopCh   chan struct{}
	mu       sync.Mutex
	running  bool
}

func NewPoller(c *client.IntelClient, s *store.Store, m *merger.Merger) *Poller {
	return &Poller{
		client:   c,
		store:    s,
		merger:   m,
		interval: 30 * time.Second,
		stopCh:   make(chan struct{}),
	}
}

func (p *Poller) Start(ctx context.Context) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.mu.Unlock()

	go p.run(ctx)
	logger.Info("emergency rule poller started")
}

func (p *Poller) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		close(p.stopCh)
		p.running = false
		logger.Info("emergency rule poller stopped")
	}
}

func (p *Poller) run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.poll(ctx)

	for {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.poll(ctx)
		}
	}
}

func (p *Poller) poll(ctx context.Context) {
	resp, err := p.client.PollEmergency(ctx, time.Now().Add(-p.interval))
	if err != nil {
		logger.Error("poll emergency rules failed", "err", err)
		return
	}

	if len(resp.Rules) == 0 {
		return
	}

	logger.Info("received emergency rules", "count", len(resp.Rules))

	for _, rule := range resp.Rules {
		if p.store != nil {
			p.store.SaveEmergencyRule(&store.EmergencyRule{
				IntelID:     rule.IntelID,
				DataType:    rule.DataType,
				PayloadJSON: rule.Payload,
				Severity:    rule.Severity,
				Reason:      rule.Reason,
				ExpiresAt:   rule.ExpiresAt,
			})
		}

		p.applyEmergencyRule(rule)

		if p.store != nil {
			p.store.AddConnectionLog("emergency_rule", "id="+rule.IntelID+" severity="+rule.Severity+" reason="+rule.Reason)
		}
	}

	if p.store != nil {
		p.store.DeleteExpiredEmergencyRules()
	}
}

func (p *Poller) applyEmergencyRule(rule client.EmergencyRule) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(rule.Payload), &data); err != nil {
		logger.Error("unmarshal emergency rule payload failed", "intel_id", rule.IntelID, "err", err)
		return
	}

	switch rule.DataType {
	case "ip_blacklist":
		if ip, ok := data["ip"].(string); ok {
			p.merger.MergeIPRule(&merger.IPRuleEntry{
				IP:       ip,
				RuleType: "blacklist",
				IntelID:  rule.IntelID,
			})
		}
	case "ua_rules":
		if pattern, ok := data["pattern"].(string); ok {
			matchType := "contains"
			if mt, ok2 := data["match_type"].(string); ok2 {
				matchType = mt
			}
			p.merger.MergeUARule(&merger.UARuleEntry{
				Pattern:   pattern,
				RuleType:  "blacklist",
				MatchType: matchType,
				IntelID:   rule.IntelID,
			})
		}
	case "path_rules":
		if pattern, ok := data["pattern"].(string); ok {
			matchType := "prefix"
			if mt, ok2 := data["match_type"].(string); ok2 {
				matchType = mt
			}
			p.merger.MergePathRule(&merger.PathRuleEntry{
				Pattern:   pattern,
				RuleType:  "blacklist",
				MatchType: matchType,
				IntelID:   rule.IntelID,
			})
		}
	default:
		logger.Info("emergency rule data type not directly applicable", "data_type", rule.DataType, "intel_id", rule.IntelID)
	}
}
