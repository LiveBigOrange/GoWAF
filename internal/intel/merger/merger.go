package merger

import (
	"gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/security/rules"
)

type IPRuleEntry struct {
	IP            string `json:"ip"`
	RuleType      string `json:"rule_type"`
	IntelID       string `json:"intel_id"`
	IntelCategory string `json:"intel_category"`
}

type UARuleEntry struct {
	Pattern       string `json:"pattern"`
	RuleType      string `json:"rule_type"`
	MatchType     string `json:"match_type"`
	IntelID       string `json:"intel_id"`
	IntelCategory string `json:"intel_category"`
}

type PathRuleEntry struct {
	Pattern       string `json:"pattern"`
	RuleType      string `json:"rule_type"`
	MatchType     string `json:"match_type"`
	IntelID       string `json:"intel_id"`
	IntelCategory string `json:"intel_category"`
}

type SignatureEntry struct {
	AttackType string `json:"attack_type"`
	Pattern    string `json:"pattern"`
	Severity   string `json:"severity"`
	IntelID    string `json:"intel_id"`
}

type BotIPEntry struct {
	IP      string `json:"ip"`
	CIDR    string `json:"cidr"`
	BotType string `json:"bot_type"`
	IntelID string `json:"intel_id"`
}

type Merger struct {
	engine   *rules.Engine
	store    *store.Store
	priority string
}

func NewMerger(engine *rules.Engine, store *store.Store, priority string) *Merger {
	return &Merger{
		engine:   engine,
		store:    store,
		priority: priority,
	}
}

func (m *Merger) GetPriority() string {
	return m.priority
}

func (m *Merger) MergeIPRule(entry *IPRuleEntry) error {
	if m.store != nil {
		override, err := m.store.GetOverride(entry.IntelID, "ip_rules")
		if err == nil && override != nil {
			switch override.Action {
			case "whitelist":
				entry.RuleType = "whitelist"
			case "disable":
				return nil
			}
		}
	}

	return m.engine.AddIPRuleWithSource(entry.RuleType, entry.IP, "intel", entry.IntelID)
}

func (m *Merger) MergeUARule(entry *UARuleEntry) error {
	if m.store != nil {
		override, err := m.store.GetOverride(entry.IntelID, "ua_rules")
		if err == nil && override != nil {
			if override.Action == "disable" {
				return nil
			}
		}
	}

	return m.engine.AddUARuleWithSource(entry.RuleType, entry.MatchType, entry.Pattern, "intel", entry.IntelID)
}

func (m *Merger) MergePathRule(entry *PathRuleEntry) error {
	if m.store != nil {
		override, err := m.store.GetOverride(entry.IntelID, "path_rules")
		if err == nil && override != nil {
			if override.Action == "disable" {
				return nil
			}
		}
	}

	return m.engine.AddPathRuleWithSource(entry.RuleType, entry.MatchType, entry.Pattern, "intel", entry.IntelID)
}

func (m *Merger) ApplyDeleted(intelIDs []string, dataType string) error {
	for _, intelID := range intelIDs {
		switch dataType {
		case "ip_blacklist", "bot_ips":
			m.engine.RemoveIPRuleByIntelID(intelID)
		case "ua_rules":
			m.engine.RemoveUARuleByIntelID(intelID)
		case "path_rules", "threat_signatures":
			m.engine.RemovePathRuleByIntelID(intelID)
		}
	}
	return nil
}

func (m *Merger) MergeBotIP(entry *BotIPEntry) error {
	if m.store != nil {
		override, err := m.store.GetOverride(entry.IntelID, "bot_ips")
		if err == nil && override != nil {
			switch override.Action {
			case "whitelist":
				return nil
			case "disable":
				return nil
			}
		}
	}

	ip := entry.IP
	if ip == "" && entry.CIDR != "" {
		ip = entry.CIDR
	}
	if ip == "" {
		return nil
	}
	return m.engine.AddIPRuleWithSource("blacklist", ip, "intel-bot", entry.IntelID)
}

func (m *Merger) MergeSignatureRule(entry *SignatureEntry) error {
	if m.store != nil {
		override, err := m.store.GetOverride(entry.IntelID, "threat_signatures")
		if err == nil && override != nil {
			if override.Action == "disable" {
				return nil
			}
		}
	}

	if entry.Pattern == "" {
		return nil
	}
	matchType := "contains"
	if entry.AttackType == "sqli" || entry.AttackType == "xss" || entry.AttackType == "rce" {
		matchType = "regex"
	}
	return m.engine.AddPathRuleWithSource("blacklist", matchType, entry.Pattern, "intel-sig", entry.IntelID)
}

func (m *Merger) MergeGeoIPData(intelID, filePath, checksum string, fileSize int64) error {
	if m.store != nil {
		override, err := m.store.GetOverride(intelID, "geoip")
		if err == nil && override != nil {
			if override.Action == "disable" {
				return nil
			}
		}
	}
	logger.Info("geoip data updated", "intel_id", intelID, "file_path", filePath, "checksum", checksum, "file_size", fileSize)
	return nil
}
