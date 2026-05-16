package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/domain/gateway/templates"
)

// SetDetectorConfigManager 设置检测器配置管理器

// DetectorPage 检测器管理页面
func DetectorPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.DetectorTmpl, "detector", "detector")
}

// APIDetectorList 列出所有检测器配置
func APIDetectorList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	configs, err := deps.DetectorConfigManager.ListConfigs()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, configs)
}

// APIDetectorGet 获取单个检测器配置
func APIDetectorGet(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	detectorType := r.URL.Query().Get("type")
	if detectorType == "" {
		jsonError(w, "Missing detector type", http.StatusBadRequest)
		return
	}

	config, err := deps.DetectorConfigManager.GetConfig(detectorType)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	jsonSuccess(w, config)
}

// APIDetectorUpdate 更新检测器配置
func APIDetectorUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	var req struct {
		DetectorType     string `json:"detector_type"`
		Enabled          bool   `json:"enabled"`
		ObservationMode  bool   `json:"observation_mode"`
		WhitelistIPs     string `json:"whitelist_ips"`
		WhitelistPaths   string `json:"whitelist_paths"`
		SensitivityLevel string `json:"sensitivity_level"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := deps.DetectorConfigManager.UpdateConfig(
		req.DetectorType,
		req.Enabled,
		req.ObservationMode,
		req.WhitelistIPs,
		req.WhitelistPaths,
		req.SensitivityLevel,
	)

	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 实时应用到WAFProxy
	if deps.WAFProxy != nil {
		deps.WAFProxy.ApplyDetectorConfig(req.DetectorType, req.Enabled)
		deps.WAFProxy.ApplyObservationMode(req.DetectorType, req.ObservationMode)
	}

	jsonSuccess(w, nil)
}

// APIDetectorToggle 切换检测器启用状态
func APIDetectorToggle(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	var req struct {
		DetectorType string `json:"detector_type"`
		Enabled      bool   `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 更新数据库配置
	err := deps.DetectorConfigManager.SetEnabled(req.DetectorType, req.Enabled)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 实时应用到WAFProxy
	if deps.WAFProxy != nil {
		deps.WAFProxy.ApplyDetectorConfig(req.DetectorType, req.Enabled)
	}

	jsonSuccess(w, nil)
}

// APIDetectorRules 获取检测器的所有规则
func APIDetectorRules(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	detectorType := r.URL.Query().Get("type")
	if detectorType == "" {
		jsonError(w, "Missing detector type", http.StatusBadRequest)
		return
	}

	rules, err := deps.DetectorConfigManager.ListRules(detectorType)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, rules)
}

// APIDetectorAddRule 添加自定义规则
func APIDetectorAddRule(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	var req struct {
		DetectorType string `json:"detector_type"`
		Pattern      string `json:"pattern"`
		Description  string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := deps.DetectorConfigManager.AddCustomRule(req.DetectorType, req.Pattern, req.Description)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if deps.DetectorManager != nil {
		rules, rerr := deps.DetectorConfigManager.ListRules(req.DetectorType)
		if rerr != nil {
			jsonError(w, "规则热加载失败: "+rerr.Error(), http.StatusInternalServerError)
			return
		}
		deps.DetectorManager.ReloadRules(req.DetectorType, rules)
	}

	jsonSuccess(w, nil)
}

// APIDetectorRemoveRule 删除规则
func APIDetectorRemoveRule(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	var req struct {
		RuleID int `json:"rule_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	detectorType, err := deps.DetectorConfigManager.RemoveRule(req.RuleID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if deps.DetectorManager != nil && detectorType != "" {
		rules, rerr := deps.DetectorConfigManager.ListRules(detectorType)
		if rerr != nil {
			jsonError(w, "规则热加载失败: "+rerr.Error(), http.StatusInternalServerError)
			return
		}
		deps.DetectorManager.ReloadRules(detectorType, rules)
	}

	jsonSuccess(w, nil)
}

// APIDetectorToggleRule 切换规则启用状态
func APIDetectorToggleRule(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	var req struct {
		RuleID  int  `json:"rule_id"`
		Enabled bool `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	err := deps.DetectorConfigManager.ToggleRule(req.RuleID, req.Enabled)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if deps.DetectorManager != nil {
		rule, rerr := deps.DetectorConfigManager.GetRuleByID(req.RuleID)
		if rerr != nil {
			jsonError(w, "规则热加载失败: "+rerr.Error(), http.StatusInternalServerError)
			return
		}
		rules, lerr := deps.DetectorConfigManager.ListRules(rule.DetectorType)
		if lerr != nil {
			jsonError(w, "规则热加载失败: "+lerr.Error(), http.StatusInternalServerError)
			return
		}
		deps.DetectorManager.ReloadRules(rule.DetectorType, rules)
	}

	jsonSuccess(w, nil)
}

// APIDetectorStats 获取检测器统计信息
func APIDetectorStats(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DetectorConfigManager, "检测器配置管理器") {
		return
	}

	stats, err := deps.DetectorConfigManager.GetStats()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, stats)
}
