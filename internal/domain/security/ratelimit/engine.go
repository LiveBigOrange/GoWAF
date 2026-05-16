package ratelimit

import (
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

type ScoreDetail struct {
	RequestRateScore    float64 `json:"request_rate_score"`
	BlockRateScore      float64 `json:"block_rate_score"`
	ErrorRatioScore     float64 `json:"error_ratio_score"`
	PathDivScore        float64 `json:"path_div_score"`
	RuleDivScore        float64 `json:"rule_div_score"`
	UADivScore          float64 `json:"ua_div_score"`
	IntervalVarScore    float64 `json:"interval_var_score"`
	SensitivePathScore  float64 `json:"sensitive_path_score"`
	GeoAnomalyScore     float64 `json:"geo_anomaly_score"`
	CookieAnomalyScore  float64 `json:"cookie_anomaly_score"`
	MethodAnomalyScore  float64 `json:"method_anomaly_score"`
	RefererAnomalyScore float64 `json:"referer_anomaly_score"`
	BodyAnomalyScore    float64 `json:"body_anomaly_score"`
	FingerprintScore    float64 `json:"fingerprint_score"`
	AttackChainScore    float64 `json:"attack_chain_score"`
	HourAnomalyScore    float64 `json:"hour_anomaly_score"`
	TotalScore          float64 `json:"total_score"`
	Action              string  `json:"action"`
}

type Decision struct {
	Action      Action      `json:"action"`
	Score       float64     `json:"score"`
	ScoreDetail ScoreDetail `json:"score_detail"`
	Reason      string      `json:"reason"`
	IP          string      `json:"ip"`
	Timestamp   time.Time   `json:"timestamp"`
	Observe     bool        `json:"observe"`
}

var browserUAHints = []string{"Mozilla", "Chrome", "Safari", "Edge", "Firefox", "Opera"}

type Engine struct {
	mu        sync.RWMutex
	config    *Config
	profiles  *ProfileStore
	globalQPS *SlidingWindow
	baselines map[string]float64

	fingerprints     *FingerprintTracker
	attackChains     *AttackChainTracker
	attackStats      *GlobalAttackStats
	hourTrusted      map[string]map[int]bool
	lastWeightUpdate time.Time

	whitelistNets  []*net.IPNet
	cachedConfig   *Config
	cachedConfigAt time.Time
	autoBlocker    *AutoBlocker
	stopCh         chan struct{}
}

func NewEngine(cfg *Config) *Engine {
	e := &Engine{
		config:       cfg,
		profiles:     NewProfileStore(cfg),
		globalQPS:    NewSlidingWindow(10, time.Second, cfg.GlobalQPSThreshold),
		baselines:    make(map[string]float64),
		fingerprints: NewFingerprintTracker(),
		attackChains: NewAttackChainTracker(),
		attackStats:  NewGlobalAttackStats(),
		hourTrusted:  make(map[string]map[int]bool),
		stopCh:       make(chan struct{}),
	}
	e.rebuildWhitelistNets()
	return e
}

func (e *Engine) Stop() {
	close(e.stopCh)
}

func (e *Engine) StopCh() <-chan struct{} {
	return e.stopCh
}

func (e *Engine) getConfigCached(now time.Time) *Config {
	e.mu.RLock()
	cached := e.cachedConfig
	if cached != nil && now.Sub(e.cachedConfigAt) < time.Second {
		e.mu.RUnlock()
		return cached
	}
	e.mu.RUnlock()

	e.mu.Lock()
	if e.cachedConfig != nil && now.Sub(e.cachedConfigAt) < time.Second {
		cfg := e.cachedConfig
		e.mu.Unlock()
		return cfg
	}
	e.cachedConfig = e.config.Clone()
	e.cachedConfigAt = now
	cfg := e.cachedConfig
	e.mu.Unlock()
	return cfg
}

func (e *Engine) rebuildWhitelistNets() {
	e.whitelistNets = nil
	cfg := e.config
	for _, ip := range cfg.WhitelistIPs {
		if strings.Contains(ip, "/") {
			_, cidr, err := net.ParseCIDR(ip)
			if err == nil {
				e.whitelistNets = append(e.whitelistNets, cidr)
			}
		}
	}
}

func (e *Engine) Evaluate(req RequestInfo) Decision {
	now := time.Now()

	e.mu.RLock()
	enabled := e.config.GetEnabled()
	mode := e.config.GetMode()
	e.mu.RUnlock()

	cfg := e.getConfigCached(now)

	if !enabled {
		return Decision{Action: Allow, Reason: "engine disabled", IP: req.IP, Timestamp: now}
	}

	for _, ip := range cfg.WhitelistIPs {
		if ip == req.IP {
			return Decision{Action: Allow, Reason: "whitelisted IP", IP: req.IP, Timestamp: now}
		}
	}
	if len(e.whitelistNets) > 0 {
		parsedIP := net.ParseIP(req.IP)
		for _, cidr := range e.whitelistNets {
			if parsedIP != nil && cidr.Contains(parsedIP) {
				return Decision{Action: Allow, Reason: "whitelisted IP (CIDR)", IP: req.IP, Timestamp: now}
			}
		}
	}

	observeOnly := mode == "observe"

	e.globalQPS.Incr()

	snapshot, exists := e.profiles.GetOrCreateSnapshot(req.IP)
	if !exists {
		return Decision{Action: Allow, Reason: "no profile", IP: req.IP, Timestamp: now}
	}

	// Fingerprint preemptive check
	if cfg.FingerprintEnabled {
		fp := e.fingerprints.GetFingerprint(req.IP)
		if fp != "" && e.fingerprints.IsSuspect(fp) {
			return Decision{
				Action:    Challenge,
				Score:     0.5,
				Reason:    "IP from suspicious fingerprint group",
				IP:        req.IP,
				Timestamp: now,
				Observe:   observeOnly,
			}
		}
	}

	if cfg.GlobalQPSThreshold > 0 && e.globalQPS.Sum() > cfg.GlobalQPSThreshold {
		return Decision{
			Action:    Throttle,
			Score:     1.0,
			Reason:    "global QPS exceeded",
			IP:        req.IP,
			Timestamp: now,
		}
	}

	detail := ScoreDetail{}
	totalScore := 0.0

	trustMultiplier := 1.0
	if snapshot.TrustScore > 0 {
		trustMultiplier = 1.0 + snapshot.TrustScore*0.02
	} else if snapshot.TrustScore < 0 {
		trustMultiplier = 1.0 / (1.0 + math.Abs(snapshot.TrustScore)*0.05)
	}
	if trustMultiplier < 0.2 {
		trustMultiplier = 0.2
	}
	if trustMultiplier > 5.0 {
		trustMultiplier = 5.0
	}

	effectiveReqThreshold := float64(cfg.IPRequestThreshold) * trustMultiplier
	effectiveBlockThreshold := float64(cfg.IPBlockThreshold) * trustMultiplier

	if cfg.IPRequestThreshold > 0 && snapshot.RequestRate > cfg.IPRequestThreshold {
		ratio := float64(snapshot.RequestRate) / effectiveReqThreshold
		if ratio >= 3.0 {
			action := Throttle
			if observeOnly {
				action = Allow
			}
			return Decision{
				Action:      action,
				Score:       math.Min(ratio-1.0, 1.0),
				ScoreDetail: ScoreDetail{RequestRateScore: math.Min(ratio-1.0, 1.0), TotalScore: math.Min(ratio-1.0, 1.0)},
				Reason:      fmt.Sprintf("request rate %.1fx exceeded effective threshold (hard limit, trust=%.0f)", ratio, snapshot.TrustScore),
				IP:          req.IP,
				Timestamp:   now,
				Observe:     observeOnly,
			}
		}
	}

	if cfg.IPBlockThreshold > 0 && snapshot.BlockRate > cfg.IPBlockThreshold {
		ratio := float64(snapshot.BlockRate) / effectiveBlockThreshold
		if ratio >= 2.0 {
			action := Block
			if observeOnly {
				action = Allow
			}
			return Decision{
				Action:      action,
				Score:       math.Min(ratio-1.0, 1.0),
				ScoreDetail: ScoreDetail{BlockRateScore: math.Min(ratio-1.0, 1.0), TotalScore: math.Min(ratio-1.0, 1.0)},
				Reason:      fmt.Sprintf("block rate %.0fx exceeded effective threshold (hard limit, trust=%.0f)", ratio, snapshot.TrustScore),
				IP:          req.IP,
				Timestamp:   now,
				Observe:     observeOnly,
			}
		}
	}

	if effectiveReqThreshold > 0 && float64(snapshot.RequestRate) > effectiveReqThreshold {
		ratio := float64(snapshot.RequestRate) / effectiveReqThreshold
		detail.RequestRateScore = math.Min(ratio-1.0, 1.0)
	} else if cfg.AdaptiveEnabled {
		baseline := e.getBaseline(req.IP)
		if baseline > 0 && float64(snapshot.RequestRate) > baseline*cfg.Sensitivity {
			detail.RequestRateScore = math.Min(float64(snapshot.RequestRate)/(baseline*cfg.Sensitivity)-1.0, 1.0)
		}
	}
	totalScore += cfg.W_RequestRate * detail.RequestRateScore

	if effectiveBlockThreshold > 0 && float64(snapshot.BlockRate) > effectiveBlockThreshold {
		ratio := float64(snapshot.BlockRate) / effectiveBlockThreshold
		detail.BlockRateScore = math.Min(ratio-1.0, 1.0)
	}
	totalScore += cfg.W_BlockRate * detail.BlockRateScore

	if snapshot.ErrorRatio > cfg.ErrorRatioThreshold {
		denom := 1.0 - cfg.ErrorRatioThreshold
		if denom > 0 {
			detail.ErrorRatioScore = math.Min((snapshot.ErrorRatio-cfg.ErrorRatioThreshold)/denom, 1.0)
		} else {
			detail.ErrorRatioScore = 1.0
		}
	}
	totalScore += cfg.W_ErrorRatio * detail.ErrorRatioScore

	if cfg.PathDivThreshold > 0 && snapshot.PathDiversity > cfg.PathDivThreshold {
		detail.PathDivScore = math.Min(float64(snapshot.PathDiversity)/float64(cfg.PathDivThreshold)-1.0, 1.0)
	}
	totalScore += cfg.W_PathDiv * detail.PathDivScore

	if cfg.RuleDivThreshold > 0 && snapshot.RuleDiversity > cfg.RuleDivThreshold {
		detail.RuleDivScore = math.Min(float64(snapshot.RuleDiversity)/float64(cfg.RuleDivThreshold)-1.0, 1.0)
	}
	totalScore += cfg.W_RuleDiv * detail.RuleDivScore

	if cfg.UADivThreshold > 0 && snapshot.UADiversity > cfg.UADivThreshold {
		detail.UADivScore = math.Min(float64(snapshot.UADiversity)/float64(cfg.UADivThreshold)-1.0, 1.0)
	}
	totalScore += cfg.W_UADiv * detail.UADivScore

	if snapshot.IntervalVariance < cfg.IntervalVarMin && snapshot.IntervalMean > 0 && snapshot.TotalCount > 20 {
		detail.IntervalVarScore = math.Min(1.0-cfg.IntervalVarMin/math.Max(snapshot.IntervalVariance, 0.0001), 1.0)
	}
	totalScore += cfg.W_IntervalVar * detail.IntervalVarScore

	if snapshot.SensitiveHitCount > cfg.SensitivePathHitLimit {
		detail.SensitivePathScore = math.Min(float64(snapshot.SensitiveHitCount)/float64(cfg.SensitivePathHitLimit)-1.0, 1.0)
	}
	totalScore += cfg.W_SensitivePath * detail.SensitivePathScore

	if cfg.ASNChangeThreshold > 0 && snapshot.ASNChangeCount >= cfg.ASNChangeThreshold {
		detail.GeoAnomalyScore = math.Min(float64(snapshot.ASNChangeCount)/float64(cfg.ASNChangeThreshold), 1.0)
	}
	totalScore += cfg.W_GeoAnomaly * detail.GeoAnomalyScore

	isBrowserUA := false
	if snapshot.TotalCount > 10 {
		for _, hint := range browserUAHints {
			if strings.Contains(snapshot.LastUA, hint) {
				isBrowserUA = true
				break
			}
		}
	}

	if isBrowserUA && snapshot.NoCookieRatio > cfg.NoCookieRatioThreshold && snapshot.TotalCount > 10 {
		denom := 1.0 - cfg.NoCookieRatioThreshold
		if denom > 0 {
			detail.CookieAnomalyScore = math.Min((snapshot.NoCookieRatio-cfg.NoCookieRatioThreshold)/denom, 1.0)
		} else {
			detail.CookieAnomalyScore = 1.0
		}
	}
	totalScore += cfg.W_CookieAnomaly * detail.CookieAnomalyScore

	if cfg.MethodDivThreshold > 0 && snapshot.MethodDiversity > cfg.MethodDivThreshold {
		detail.MethodAnomalyScore = math.Min(float64(snapshot.MethodDiversity)/float64(cfg.MethodDivThreshold)-1.0, 1.0)
	}
	totalScore += cfg.W_MethodAnomaly * detail.MethodAnomalyScore

	if isBrowserUA && snapshot.NoRefererRatio > cfg.NoRefererRatioThreshold && snapshot.TotalCount > 10 {
		denom := 1.0 - cfg.NoRefererRatioThreshold
		if denom > 0 {
			detail.RefererAnomalyScore = math.Min((snapshot.NoRefererRatio-cfg.NoRefererRatioThreshold)/denom, 1.0)
		} else {
			detail.RefererAnomalyScore = 1.0
		}
	}
	totalScore += cfg.W_RefererAnomaly * detail.RefererAnomalyScore

	if snapshot.BodySizeCount > cfg.BodySizeThreshold && cfg.BodySizeThreshold > 0 {
		detail.BodyAnomalyScore = math.Min(float64(snapshot.BodySizeCount)/float64(cfg.BodySizeThreshold)-1.0, 1.0)
	}
	totalScore += cfg.W_BodyAnomaly * detail.BodyAnomalyScore

	// === NEW INTELLIGENCE DIMENSIONS ===

	// Fingerprint-based risk
	if cfg.FingerprintEnabled {
		fpScore := e.fingerprints.GetSharedRiskScore(req.IP)
		if fpScore > 0 {
			detail.FingerprintScore = fpScore
			totalScore += fpScore
		}
		// Auto-mark suspect fingerprints
		fp := e.fingerprints.GetFingerprint(req.IP)
		if fp != "" {
			count := e.fingerprints.GetFingerprintIPCount(fp)
			if count >= cfg.FingerprintSuspectThreshold {
				e.fingerprints.MarkSuspect(fp)
			}
		}
	}

	// Attack chain detection
	if cfg.AttackChainEnabled {
		chainScore := e.attackChains.GetChainScore(req.IP)
		if chainScore > 0 {
			detail.AttackChainScore = chainScore
			totalScore += cfg.AttackChainWeight * chainScore
		}
	}

	// Hour-based anomaly
	if cfg.HourProfileEnabled {
		profile, _ := e.profiles.Get(req.IP)
		if profile != nil {
			trustedHours := e.getTrustedHours(req.IP)
			hourScore := profile.GetHourAnomaly(trustedHours)
			if hourScore > 0 {
				detail.HourAnomalyScore = hourScore
				totalScore += cfg.HourAnomalyWeight * hourScore
			}
		}
	}

	detail.TotalScore = totalScore

	action := Allow
	reason := "normal"
	switch {
	case totalScore >= cfg.BlockThreshold:
		action = Block
		reason = "threat score exceeded block threshold"
	case totalScore >= cfg.ChallengeThreshold:
		action = Challenge
		reason = "threat score exceeded challenge threshold"
	case totalScore >= cfg.ThrottleThreshold:
		action = Throttle
		reason = "threat score exceeded throttle threshold"
	}

	if observeOnly && action != Allow {
		reason = "[OBSERVE] " + reason
		action = Allow
	}

	if action == Allow && totalScore > 0 {
		if totalScore >= cfg.ChallengeThreshold*0.6 {
			action = Slowdown
			reason = "approaching threshold, applying progressive slowdown"
			if observeOnly {
				reason = "[OBSERVE] " + reason
				action = Allow
			}
		}
	}

	detail.Action = action.String()

	return Decision{
		Action:      action,
		Score:       totalScore,
		ScoreDetail: detail,
		Reason:      reason,
		IP:          req.IP,
		Timestamp:   now,
		Observe:     observeOnly,
	}
}

func (e *Engine) GetProfile(ip string) (ProfileSnapshot, bool) {
	return e.profiles.Snapshot(ip)
}

func (e *Engine) GetAllProfiles() []ProfileSnapshot {
	return e.profiles.AllSnapshots()
}

func (e *Engine) GetGlobalQPS() int64 {
	return e.globalQPS.Sum()
}

func (e *Engine) UpdateConfig(cfg *Config) {
	e.mu.Lock()
	oldSaver := e.config.persistSaver
	cfg.persistSaver = oldSaver
	e.config = cfg
	e.cachedConfig = nil
	e.globalQPS.SetThreshold(cfg.GlobalQPSThreshold)
	e.profiles.UpdateConfig(cfg)
	e.rebuildWhitelistNets()
	e.mu.Unlock()
	if err := cfg.SaveToFile(); err != nil {
		log.Printf("[ratelimit] 保存配置文件失败: %v", err)
	}
}

func (e *Engine) GetConfig() *Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.Clone()
}

func (e *Engine) SetIPThreshold(ip string, threshold int64) {
	profile, exists := e.profiles.Get(ip)
	if exists {
		profile.RequestRate.SetThreshold(threshold)
	}
}

func (e *Engine) getBaseline(ip string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if b, exists := e.baselines[ip]; exists {
		return b
	}
	return 0
}

func (e *Engine) UpdateBaseline(ip string, baseline float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.baselines[ip] = baseline
}

func (e *Engine) GetFingerprintTracker() *FingerprintTracker { return e.fingerprints }
func (e *Engine) GetAttackChainTracker() *AttackChainTracker { return e.attackChains }
func (e *Engine) GetAttackStats() *GlobalAttackStats         { return e.attackStats }

func (e *Engine) getTrustedHours(ip string) map[int]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if t, ok := e.hourTrusted[ip]; ok {
		copied := make(map[int]bool, len(t))
		for k, v := range t {
			copied[k] = v
		}
		return copied
	}
	return nil
}

func (e *Engine) SetFingerprintForIP(ip, fp string) {
	profile, _ := e.profiles.Get(ip)
	if profile != nil {
		profile.SetFingerprint(fp)
	}
	e.fingerprints.Record(ip, fp)
}

func (e *Engine) adjustWeights(cfg *Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !cfg.AutoWeightEnabled {
		return
	}
	if time.Since(e.lastWeightUpdate) < 60*time.Second {
		return
	}
	e.lastWeightUpdate = time.Now()

	e.attackStats.ResetIfNeeded()

	allTypes := []string{"sql_injection", "xss", "command_injection", "path_traversal",
		"ssrf", "file_upload", "header_injection", "sensitive_data"}
	hotWeights := e.attackStats.GetWeights(allTypes)

	if len(hotWeights) > 0 {
		maxW := 0.0
		for _, w := range hotWeights {
			if w > maxW {
				maxW = w
			}
		}

		if maxW > 0.05 {
			cfg.mu.Lock()
			rate := cfg.WeightLearningRate

			for _, w := range []struct {
				name string
				ptr  *float64
			}{
				{"path_traversal", &cfg.W_PathDiv},
				{"ssrf", &cfg.W_PathDiv},
				{"sql_injection", &cfg.W_RequestRate},
				{"command_injection", &cfg.W_RequestRate},
				{"xss", &cfg.W_BodyAnomaly},
				{"sensitive_data", &cfg.W_SensitivePath},
				{"file_upload", &cfg.W_BodyAnomaly},
			} {
				if hotWeights[w.name] > 0.03 {
					*w.ptr = *w.ptr + rate*(hotWeights[w.name]-*w.ptr)
					if *w.ptr > 0.35 {
						*w.ptr = 0.35
					}
					if *w.ptr < 0.02 {
						*w.ptr = 0.02
					}
				}
			}
			cfg.mu.Unlock()
		}
	}

	e.normalizeWeights(cfg)
}

func (e *Engine) normalizeWeights(cfg *Config) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	sum := cfg.W_RequestRate + cfg.W_BlockRate + cfg.W_ErrorRatio + cfg.W_PathDiv + cfg.W_RuleDiv +
		cfg.W_UADiv + cfg.W_IntervalVar + cfg.W_SensitivePath + cfg.W_GeoAnomaly + cfg.W_CookieAnomaly +
		cfg.W_MethodAnomaly + cfg.W_RefererAnomaly + cfg.W_BodyAnomaly

	if sum <= 0 || math.Abs(sum-1.0) < 0.001 {
		return
	}

	scale := 1.0 / sum
	cfg.W_RequestRate *= scale
	cfg.W_BlockRate *= scale
	cfg.W_ErrorRatio *= scale
	cfg.W_PathDiv *= scale
	cfg.W_RuleDiv *= scale
	cfg.W_UADiv *= scale
	cfg.W_IntervalVar *= scale
	cfg.W_SensitivePath *= scale
	cfg.W_GeoAnomaly *= scale
	cfg.W_CookieAnomaly *= scale
	cfg.W_MethodAnomaly *= scale
	cfg.W_RefererAnomaly *= scale
	cfg.W_BodyAnomaly *= scale
}

func (e *Engine) SetAutoBlocker(a *AutoBlocker) {
	e.autoBlocker = a
}

func (e *Engine) RecordChallengeFail(ip string) {
	if e.autoBlocker != nil {
		e.autoBlocker.RecordChallengeFail(ip)
	}
}

func (e *Engine) RecordChallengePass(ip string) {
	if e.autoBlocker != nil {
		e.autoBlocker.RecordChallengePass(ip)
	}
}

func (e *Engine) RunCleanup() {
	cfg := e.getConfigCached(time.Now())
	cleaned := e.profiles.Cleanup(cfg.ProfileMaxAge())
	if cleaned > 0 {
		log.Printf("[ratelimit] 清理过期IP画像: %d个, 剩余: %d个", cleaned, e.profiles.Count())
	}
	e.mu.Lock()
	for ip := range e.baselines {
		if _, exists := e.profiles.Get(ip); !exists {
			delete(e.baselines, ip)
		}
	}
	e.mu.Unlock()

	e.fingerprints.Cleanup(cfg.ProfileMaxAge())
	e.AutoFalsePositiveRepair()
	e.adjustWeights(e.config)
	if e.autoBlocker != nil {
		e.autoBlocker.ExpireBlocks()
	}
}

func (e *Engine) RecordFeedback(req RequestInfo) {
	e.mu.RLock()
	enabled := e.config.GetEnabled()
	e.mu.RUnlock()
	if !enabled {
		return
	}
	e.profiles.Record(req)

	if req.RuleID != "" {
		e.attackStats.Record(req.RuleID)
		e.attackChains.Record(req.IP, req.Path, req.RuleID)
	}
}

func (e *Engine) PardonIP(ip string) {
	profile, exists := e.profiles.Get(ip)
	if exists {
		profile.mu.Lock()
		profile.trustScore += 20.0
		if profile.trustScore > 100 {
			profile.trustScore = 100
		}
		profile.consecutivePass = 0
		profile.mu.Unlock()

		e.fingerprints.UnmarkFingerprint(profile.Snapshot().FingerprintHash)
	}
}

func (e *Engine) AutoFalsePositiveRepair() {
	e.mu.RLock()
	enabled := e.config.FalsePositiveRepair && e.config.AutoPardonEnabled
	e.mu.RUnlock()
	if !enabled {
		return
	}

	snapshots := e.profiles.AllSnapshots()
	currentHour := time.Now().Hour()

	for _, snap := range snapshots {
		if snap.ConsecutivePass > 500 && snap.TrustScore < -10 {
			e.PardonIP(snap.IP)
			e.mu.Lock()
			if e.hourTrusted[snap.IP] == nil {
				e.hourTrusted[snap.IP] = make(map[int]bool)
			}
			e.hourTrusted[snap.IP][currentHour] = true
			e.mu.Unlock()
			log.Printf("[ratelimit] auto-pardoned IP %s (consecutive pass=%d, trust=%.1f)",
				snap.IP, snap.ConsecutivePass, snap.TrustScore)
		}
	}
}

func (e *Engine) ProfileCount() int {
	return e.profiles.Count()
}
