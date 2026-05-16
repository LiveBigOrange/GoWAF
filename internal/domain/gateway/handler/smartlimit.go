package handler

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"gowaf/internal/domain/security/ratelimit"
	"gowaf/internal/domain/gateway/templates"
)

func APIGetSmartLimitConfig(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RateLimitEngine, "智能限流引擎") {
		return
	}
	cfg := deps.RateLimitEngine.GetConfig()
	jsonSuccess(w, map[string]interface{}{
		"enabled":                       cfg.Enabled,
		"mode":                          cfg.Mode,
		"window_size":                   cfg.WindowSize,
		"profile_max_age_sec":           cfg.ProfileMaxAgeSec,
		"cleanup_interval_sec":          cfg.CleanupIntervalSec,
		"ip_request_threshold":          cfg.IPRequestThreshold,
		"ip_block_threshold":            cfg.IPBlockThreshold,
		"global_qps_threshold":          cfg.GlobalQPSThreshold,
		"block_threshold":               cfg.BlockThreshold,
		"challenge_threshold":           cfg.ChallengeThreshold,
		"throttle_threshold":            cfg.ThrottleThreshold,
		"error_ratio_threshold":         cfg.ErrorRatioThreshold,
		"path_div_threshold":            cfg.PathDivThreshold,
		"ua_div_threshold":              cfg.UADivThreshold,
		"rule_div_threshold":            cfg.RuleDivThreshold,
		"interval_var_min":              cfg.IntervalVarMin,
		"sensitive_path_limit":          cfg.SensitivePathHitLimit,
		"adaptive_enabled":              cfg.AdaptiveEnabled,
		"sensitivity":                   cfg.Sensitivity,
		"auto_block_enabled":            cfg.AutoBlockEnabled,
		"auto_block_duration_sec":       cfg.AutoBlockDurationSec,
		"whitelist_ips":                 cfg.WhitelistIPs,
		"w_request_rate":                cfg.W_RequestRate,
		"w_block_rate":                  cfg.W_BlockRate,
		"w_error_ratio":                 cfg.W_ErrorRatio,
		"w_path_div":                    cfg.W_PathDiv,
		"w_rule_div":                    cfg.W_RuleDiv,
		"w_ua_div":                      cfg.W_UADiv,
		"w_interval_var":                cfg.W_IntervalVar,
		"w_sensitive_path":              cfg.W_SensitivePath,
		"w_geo_anomaly":                 cfg.W_GeoAnomaly,
		"w_cookie_anomaly":              cfg.W_CookieAnomaly,
		"w_method_anomaly":              cfg.W_MethodAnomaly,
		"w_referer_anomaly":             cfg.W_RefererAnomaly,
		"w_body_anomaly":                cfg.W_BodyAnomaly,
		"global_qps":                    deps.RateLimitEngine.GetGlobalQPS(),
		"profile_count":                 deps.RateLimitEngine.ProfileCount(),
		"method_div_threshold":          cfg.MethodDivThreshold,
		"no_cookie_ratio_threshold":     cfg.NoCookieRatioThreshold,
		"no_referer_ratio_threshold":    cfg.NoRefererRatioThreshold,
		"body_size_threshold":           cfg.BodySizeThreshold,
		"asn_change_threshold":          cfg.ASNChangeThreshold,
		"auto_weight_enabled":           cfg.AutoWeightEnabled,
		"weight_learning_rate":          cfg.WeightLearningRate,
		"dynamic_baseline_pct":          cfg.DynamicBaselinePct,
		"fingerprint_enabled":           cfg.FingerprintEnabled,
		"fingerprint_suspect_threshold": cfg.FingerprintSuspectThreshold,
		"attack_chain_enabled":          cfg.AttackChainEnabled,
		"attack_chain_weight":           cfg.AttackChainWeight,
		"false_positive_repair":         cfg.FalsePositiveRepair,
		"auto_pardon_enabled":           cfg.AutoPardonEnabled,
		"hour_profile_enabled":          cfg.HourProfileEnabled,
		"hour_anomaly_weight":           cfg.HourAnomalyWeight,
		"auto_block_threshold":          cfg.AutoBlockThreshold,
	})
}

func APIUpdateSmartLimitConfig(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RateLimitEngine, "智能限流引擎") {
		return
	}
	var req struct {
		Enabled                     *bool    `json:"enabled"`
		Mode                        *string  `json:"mode"`
		IPRequestThreshold          *int64   `json:"ip_request_threshold"`
		IPBlockThreshold            *int64   `json:"ip_block_threshold"`
		GlobalQPSThreshold          *int64   `json:"global_qps_threshold"`
		BlockThreshold              *float64 `json:"block_threshold"`
		ChallengeThreshold          *float64 `json:"challenge_threshold"`
		ThrottleThreshold           *float64 `json:"throttle_threshold"`
		ErrorRatioThreshold         *float64 `json:"error_ratio_threshold"`
		PathDivThreshold            *int     `json:"path_div_threshold"`
		UADivThreshold              *int     `json:"ua_div_threshold"`
		RuleDivThreshold            *int     `json:"rule_div_threshold"`
		AdaptiveEnabled             *bool    `json:"adaptive_enabled"`
		Sensitivity                 *float64 `json:"sensitivity"`
		WRequestRate                *float64 `json:"w_request_rate"`
		WBlockRate                  *float64 `json:"w_block_rate"`
		WErrorRatio                 *float64 `json:"w_error_ratio"`
		WPathDiv                    *float64 `json:"w_path_div"`
		WRuleDiv                    *float64 `json:"w_rule_div"`
		WUADiv                      *float64 `json:"w_ua_div"`
		WIntervalVar                *float64 `json:"w_interval_var"`
		WSensitivePath              *float64 `json:"w_sensitive_path"`
		WGeoAnomaly                 *float64 `json:"w_geo_anomaly"`
		WCookieAnomaly              *float64 `json:"w_cookie_anomaly"`
		WMethodAnomaly              *float64 `json:"w_method_anomaly"`
		WRefererAnomaly             *float64 `json:"w_referer_anomaly"`
		WBodyAnomaly                *float64 `json:"w_body_anomaly"`
		MethodDivThreshold          *int     `json:"method_div_threshold"`
		NoCookieRatioThreshold      *float64 `json:"no_cookie_ratio_threshold"`
		NoRefererRatioThreshold     *float64 `json:"no_referer_ratio_threshold"`
		BodySizeThreshold           *int64   `json:"body_size_threshold"`
		ASNChangeThreshold          *int     `json:"asn_change_threshold"`
		IntervalVarMin              *float64 `json:"interval_var_min"`
		SensitivePathHitLimit       *int64   `json:"sensitive_path_limit"`
		WhitelistIPs                []string `json:"whitelist_ips"`
		AutoWeightEnabled           *bool    `json:"auto_weight_enabled"`
		WeightLearningRate          *float64 `json:"weight_learning_rate"`
		DynamicBaselinePct          *float64 `json:"dynamic_baseline_pct"`
		FingerprintEnabled          *bool    `json:"fingerprint_enabled"`
		FingerprintSuspectThreshold *int     `json:"fingerprint_suspect_threshold"`
		AttackChainEnabled          *bool    `json:"attack_chain_enabled"`
		AttackChainWeight           *float64 `json:"attack_chain_weight"`
		FalsePositiveRepair         *bool    `json:"false_positive_repair"`
		AutoPardonEnabled           *bool    `json:"auto_pardon_enabled"`
		HourProfileEnabled          *bool    `json:"hour_profile_enabled"`
		HourAnomalyWeight           *float64 `json:"hour_anomaly_weight"`
		AutoBlockEnabled            *bool    `json:"auto_block_enabled"`
		AutoBlockThreshold          *int     `json:"auto_block_threshold"`
		AutoBlockDurationSec        *int64   `json:"auto_block_duration_sec"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	cfg := deps.RateLimitEngine.GetConfig()
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.Mode != nil && (*req.Mode == "observe" || *req.Mode == "intercept") {
		cfg.Mode = *req.Mode
	}
	if req.IPRequestThreshold != nil && *req.IPRequestThreshold > 0 {
		cfg.IPRequestThreshold = *req.IPRequestThreshold
	}
	if req.IPBlockThreshold != nil && *req.IPBlockThreshold > 0 {
		cfg.IPBlockThreshold = *req.IPBlockThreshold
	}
	if req.GlobalQPSThreshold != nil && *req.GlobalQPSThreshold >= 0 {
		cfg.GlobalQPSThreshold = *req.GlobalQPSThreshold
	}
	if req.BlockThreshold != nil && *req.BlockThreshold >= 0 {
		cfg.BlockThreshold = *req.BlockThreshold
	}
	if req.ChallengeThreshold != nil && *req.ChallengeThreshold >= 0 {
		cfg.ChallengeThreshold = *req.ChallengeThreshold
	}
	if req.ThrottleThreshold != nil && *req.ThrottleThreshold >= 0 {
		cfg.ThrottleThreshold = *req.ThrottleThreshold
	}
	if req.ErrorRatioThreshold != nil && *req.ErrorRatioThreshold >= 0 && *req.ErrorRatioThreshold < 1.0 {
		cfg.ErrorRatioThreshold = *req.ErrorRatioThreshold
	}
	if req.PathDivThreshold != nil && *req.PathDivThreshold > 0 {
		cfg.PathDivThreshold = *req.PathDivThreshold
	}
	if req.UADivThreshold != nil && *req.UADivThreshold > 0 {
		cfg.UADivThreshold = *req.UADivThreshold
	}
	if req.RuleDivThreshold != nil && *req.RuleDivThreshold > 0 {
		cfg.RuleDivThreshold = *req.RuleDivThreshold
	}
	if req.AdaptiveEnabled != nil {
		cfg.AdaptiveEnabled = *req.AdaptiveEnabled
	}
	if req.Sensitivity != nil && *req.Sensitivity >= 0.5 && *req.Sensitivity <= 10.0 {
		cfg.Sensitivity = *req.Sensitivity
	}
	if req.WRequestRate != nil && *req.WRequestRate >= 0 && *req.WRequestRate <= 1 {
		cfg.W_RequestRate = *req.WRequestRate
	}
	if req.WBlockRate != nil && *req.WBlockRate >= 0 && *req.WBlockRate <= 1 {
		cfg.W_BlockRate = *req.WBlockRate
	}
	if req.WErrorRatio != nil && *req.WErrorRatio >= 0 && *req.WErrorRatio <= 1 {
		cfg.W_ErrorRatio = *req.WErrorRatio
	}
	if req.WPathDiv != nil && *req.WPathDiv >= 0 && *req.WPathDiv <= 1 {
		cfg.W_PathDiv = *req.WPathDiv
	}
	if req.WRuleDiv != nil && *req.WRuleDiv >= 0 && *req.WRuleDiv <= 1 {
		cfg.W_RuleDiv = *req.WRuleDiv
	}
	if req.WUADiv != nil && *req.WUADiv >= 0 && *req.WUADiv <= 1 {
		cfg.W_UADiv = *req.WUADiv
	}
	if req.WIntervalVar != nil && *req.WIntervalVar >= 0 && *req.WIntervalVar <= 1 {
		cfg.W_IntervalVar = *req.WIntervalVar
	}
	if req.WSensitivePath != nil && *req.WSensitivePath >= 0 && *req.WSensitivePath <= 1 {
		cfg.W_SensitivePath = *req.WSensitivePath
	}
	if req.WGeoAnomaly != nil && *req.WGeoAnomaly >= 0 && *req.WGeoAnomaly <= 1 {
		cfg.W_GeoAnomaly = *req.WGeoAnomaly
	}
	if req.WCookieAnomaly != nil && *req.WCookieAnomaly >= 0 && *req.WCookieAnomaly <= 1 {
		cfg.W_CookieAnomaly = *req.WCookieAnomaly
	}
	if req.WMethodAnomaly != nil && *req.WMethodAnomaly >= 0 && *req.WMethodAnomaly <= 1 {
		cfg.W_MethodAnomaly = *req.WMethodAnomaly
	}
	if req.WRefererAnomaly != nil && *req.WRefererAnomaly >= 0 && *req.WRefererAnomaly <= 1 {
		cfg.W_RefererAnomaly = *req.WRefererAnomaly
	}
	if req.WBodyAnomaly != nil && *req.WBodyAnomaly >= 0 && *req.WBodyAnomaly <= 1 {
		cfg.W_BodyAnomaly = *req.WBodyAnomaly
	}
	if req.MethodDivThreshold != nil && *req.MethodDivThreshold > 0 {
		cfg.MethodDivThreshold = *req.MethodDivThreshold
	}
	if req.NoCookieRatioThreshold != nil && *req.NoCookieRatioThreshold >= 0 && *req.NoCookieRatioThreshold < 1.0 {
		cfg.NoCookieRatioThreshold = *req.NoCookieRatioThreshold
	}
	if req.NoRefererRatioThreshold != nil && *req.NoRefererRatioThreshold >= 0 && *req.NoRefererRatioThreshold < 1.0 {
		cfg.NoRefererRatioThreshold = *req.NoRefererRatioThreshold
	}
	if req.BodySizeThreshold != nil && *req.BodySizeThreshold > 0 {
		cfg.BodySizeThreshold = *req.BodySizeThreshold
	}
	if req.ASNChangeThreshold != nil && *req.ASNChangeThreshold > 0 {
		cfg.ASNChangeThreshold = *req.ASNChangeThreshold
	}
	if req.IntervalVarMin != nil && *req.IntervalVarMin >= 0 {
		cfg.IntervalVarMin = *req.IntervalVarMin
	}
	if req.SensitivePathHitLimit != nil && *req.SensitivePathHitLimit > 0 {
		cfg.SensitivePathHitLimit = *req.SensitivePathHitLimit
	}
	if req.WhitelistIPs != nil {
		cfg.WhitelistIPs = req.WhitelistIPs
	}
	if req.AutoWeightEnabled != nil {
		cfg.AutoWeightEnabled = *req.AutoWeightEnabled
	}
	if req.FingerprintEnabled != nil {
		cfg.FingerprintEnabled = *req.FingerprintEnabled
	}
	if req.AttackChainEnabled != nil {
		cfg.AttackChainEnabled = *req.AttackChainEnabled
	}
	if req.AttackChainWeight != nil && *req.AttackChainWeight >= 0 && *req.AttackChainWeight <= 0.5 {
		cfg.AttackChainWeight = *req.AttackChainWeight
	}
	if req.FalsePositiveRepair != nil {
		cfg.FalsePositiveRepair = *req.FalsePositiveRepair
	}
	if req.AutoPardonEnabled != nil {
		cfg.AutoPardonEnabled = *req.AutoPardonEnabled
	}
	if req.HourProfileEnabled != nil {
		cfg.HourProfileEnabled = *req.HourProfileEnabled
	}
	if req.HourAnomalyWeight != nil && *req.HourAnomalyWeight >= 0 && *req.HourAnomalyWeight <= 0.5 {
		cfg.HourAnomalyWeight = *req.HourAnomalyWeight
	}
	if req.WeightLearningRate != nil && *req.WeightLearningRate >= 0.01 && *req.WeightLearningRate <= 0.5 {
		cfg.WeightLearningRate = *req.WeightLearningRate
	}
	if req.DynamicBaselinePct != nil && *req.DynamicBaselinePct >= 50 && *req.DynamicBaselinePct <= 100 {
		cfg.DynamicBaselinePct = *req.DynamicBaselinePct
	}
	if req.FingerprintSuspectThreshold != nil && *req.FingerprintSuspectThreshold >= 5 {
		cfg.FingerprintSuspectThreshold = *req.FingerprintSuspectThreshold
	}
	if req.AutoBlockEnabled != nil {
		cfg.AutoBlockEnabled = *req.AutoBlockEnabled
	}
	if req.AutoBlockThreshold != nil && *req.AutoBlockThreshold >= 1 && *req.AutoBlockThreshold <= 10 {
		cfg.AutoBlockThreshold = *req.AutoBlockThreshold
	}
	if req.AutoBlockDurationSec != nil && *req.AutoBlockDurationSec >= 60 {
		cfg.AutoBlockDurationSec = *req.AutoBlockDurationSec
	}

	deps.RateLimitEngine.UpdateConfig(cfg)
	jsonSuccess(w, nil)
}

func APIGetSmartLimitProfiles(w http.ResponseWriter, r *http.Request) {
	if deps.RateLimitEngine == nil {
		jsonSuccess(w, []interface{}{})
		return
	}
	profiles := deps.RateLimitEngine.GetAllProfiles()
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].RequestRate > profiles[j].RequestRate
	})
	type profileJSON struct {
		IP                string           `json:"ip"`
		RequestRate       int64            `json:"request_rate"`
		RequestThreshold  int64            `json:"request_threshold"`
		BlockRate         int64            `json:"block_rate"`
		ErrorRatio        float64          `json:"error_ratio"`
		PathDiversity     int              `json:"path_diversity"`
		UADiversity       int              `json:"ua_diversity"`
		RuleDiversity     int              `json:"rule_diversity"`
		IntervalVariance  float64          `json:"interval_variance"`
		IntervalMean      float64          `json:"interval_mean"`
		SensitiveHitCount int64            `json:"sensitive_hit_count"`
		TotalCount        int64            `json:"total_count"`
		BlockCount        int64            `json:"block_count"`
		LastActive        time.Time        `json:"last_active"`
		PathRates         map[string]int64 `json:"path_rates,omitempty"`
		MethodDiversity   int              `json:"method_diversity"`
		NoCookieRatio     float64          `json:"no_cookie_ratio"`
		NoRefererRatio    float64          `json:"no_referer_ratio"`
		BodySizeCount     int64            `json:"body_size_count"`
		ASNChangeCount    int              `json:"asn_change_count"`
		FirstASN          string           `json:"first_asn"`
		TrustScore        float64          `json:"trust_score"`
	}
	result := make([]profileJSON, 0, len(profiles))
	for _, p := range profiles {
		result = append(result, profileJSON{
			IP:                p.IP,
			RequestRate:       p.RequestRate,
			RequestThreshold:  p.RequestThreshold,
			BlockRate:         p.BlockRate,
			ErrorRatio:        p.ErrorRatio,
			PathDiversity:     p.PathDiversity,
			UADiversity:       p.UADiversity,
			RuleDiversity:     p.RuleDiversity,
			IntervalVariance:  p.IntervalVariance,
			IntervalMean:      p.IntervalMean,
			SensitiveHitCount: p.SensitiveHitCount,
			TotalCount:        p.TotalCount,
			BlockCount:        p.BlockCount,
			LastActive:        p.LastActive,
			PathRates:         p.PathRates,
			MethodDiversity:   p.MethodDiversity,
			NoCookieRatio:     p.NoCookieRatio,
			NoRefererRatio:    p.NoRefererRatio,
			BodySizeCount:     p.BodySizeCount,
			ASNChangeCount:    p.ASNChangeCount,
			FirstASN:          p.FirstASN,
			TrustScore:        p.TrustScore,
		})
	}
	jsonSuccess(w, result)
}

func APIGetSmartLimitProfile(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RateLimitEngine, "智能限流引擎") {
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		jsonError(w, "ip parameter required", http.StatusBadRequest)
		return
	}
	snapshot, exists := deps.RateLimitEngine.GetProfile(ip)
	if !exists {
		jsonError(w, "profile not found for ip: "+ip, http.StatusNotFound)
		return
	}
	jsonSuccess(w, snapshot)
}

func APIEvaluateSmartLimit(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RateLimitEngine, "智能限流引擎") {
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		jsonError(w, "ip parameter required", http.StatusBadRequest)
		return
	}
	snapshot, exists := deps.RateLimitEngine.GetProfile(ip)
	if !exists {
		jsonSuccess(w, map[string]interface{}{
			"ip":     ip,
			"action": "allow",
			"reason": "no profile",
		})
		return
	}
	cfg := deps.RateLimitEngine.GetConfig()
	detail := ratelimit.ScoreDetail{}
	totalScore := 0.0

	if cfg.IPRequestThreshold > 0 && snapshot.RequestRate > cfg.IPRequestThreshold {
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
		effectiveThreshold := float64(cfg.IPRequestThreshold) * trustMultiplier
		ratio := float64(snapshot.RequestRate) / effectiveThreshold
		detail.RequestRateScore = math.Min(ratio-1.0, 1.0)
	}
	totalScore += cfg.W_RequestRate * detail.RequestRateScore

	if cfg.IPBlockThreshold > 0 && snapshot.BlockRate > cfg.IPBlockThreshold {
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
		effectiveBlockThreshold := float64(cfg.IPBlockThreshold) * trustMultiplier
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
		for _, hint := range []string{"Mozilla", "Chrome", "Safari", "Edge", "Firefox", "Opera"} {
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

	// Fingerprint-based risk
	if cfg.FingerprintEnabled {
		fpScore := deps.RateLimitEngine.GetFingerprintTracker().GetSharedRiskScore(ip)
		if fpScore > 0 {
			detail.FingerprintScore = fpScore
			totalScore += fpScore
		}
	}

	// Attack chain detection
	if cfg.AttackChainEnabled {
		chainScore := deps.RateLimitEngine.GetAttackChainTracker().GetChainScore(ip)
		if chainScore > 0 {
			detail.AttackChainScore = chainScore
			totalScore += cfg.AttackChainWeight * chainScore
		}
	}

	detail.TotalScore = totalScore

	action := "allow"
	switch {
	case totalScore >= cfg.BlockThreshold:
		action = "block"
	case totalScore >= cfg.ChallengeThreshold:
		action = "challenge"
	case totalScore >= cfg.ThrottleThreshold:
		action = "throttle"
	}
	if action == "allow" && totalScore > 0 && totalScore >= cfg.ChallengeThreshold*0.6 {
		action = "slowdown"
	}

	jsonSuccess(w, map[string]interface{}{
		"ip":           snapshot.IP,
		"request_rate": snapshot.RequestRate,
		"error_ratio":  snapshot.ErrorRatio,
		"block_rate":   snapshot.BlockRate,
		"path_div":     snapshot.PathDiversity,
		"ua_div":       snapshot.UADiversity,
		"rule_div":     snapshot.RuleDiversity,
		"score_detail": detail,
		"total_score":  totalScore,
		"action":       action,
		"trust_score":  snapshot.TrustScore,
		"thresholds": map[string]interface{}{
			"ip_request":       cfg.IPRequestThreshold,
			"ip_block":         cfg.IPBlockThreshold,
			"error_ratio":      cfg.ErrorRatioThreshold,
			"path_div":         cfg.PathDivThreshold,
			"ua_div":           cfg.UADivThreshold,
			"rule_div":         cfg.RuleDivThreshold,
			"interval_var_min": cfg.IntervalVarMin,
			"sensitive_path":   cfg.SensitivePathHitLimit,
			"asn_change":       cfg.ASNChangeThreshold,
			"no_cookie_ratio":  cfg.NoCookieRatioThreshold,
			"method_div":       cfg.MethodDivThreshold,
			"no_referer_ratio": cfg.NoRefererRatioThreshold,
			"body_size":        cfg.BodySizeThreshold,
			"block":            cfg.BlockThreshold,
			"challenge":        cfg.ChallengeThreshold,
			"throttle":         cfg.ThrottleThreshold,
		},
	})
}

func APIGetSmartLimitStats(w http.ResponseWriter, r *http.Request) {
	if deps.RateLimitEngine == nil {
		jsonSuccess(w, map[string]interface{}{"global_qps": 0, "profile_count": 0, "enabled": false})
		return
	}
	cfg := deps.RateLimitEngine.GetConfig()
	jsonSuccess(w, map[string]interface{}{
		"global_qps":    deps.RateLimitEngine.GetGlobalQPS(),
		"profile_count": deps.RateLimitEngine.ProfileCount(),
		"enabled":       cfg.Enabled,
		"mode":          cfg.Mode,
	})
}

func SmartLimitPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.SmartLimitTmpl, "smartlimit", "smartlimit")
}

func APIPardonIP(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RateLimitEngine, "智能限流引擎") {
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		jsonError(w, "ip is required", http.StatusBadRequest)
		return
	}
	deps.RateLimitEngine.PardonIP(req.IP)
	jsonSuccess(w, map[string]interface{}{"ip": req.IP})
}
