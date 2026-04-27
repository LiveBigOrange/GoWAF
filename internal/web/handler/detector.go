package handler

import (
	"encoding/json"
	"net/http"

	"gowaf-demo/internal/detector"
	"gowaf-demo/internal/web/templates"
)

var detectorConfigManager *detector.ConfigManager

// SetDetectorConfigManager 设置检测器配置管理器
func SetDetectorConfigManager(cm *detector.ConfigManager) {
	detectorConfigManager = cm
}

// DetectorPage 检测器管理页面
func DetectorPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Active": "detector",
	}
	templates.DetectorTmpl.ExecuteTemplate(w, "detector", data)
}

// APIDetectorList 列出所有检测器配置
func APIDetectorList(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	configs, err := detectorConfigManager.ListConfigs()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(configs)
}

// APIDetectorGet 获取单个检测器配置
func APIDetectorGet(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	detectorType := r.URL.Query().Get("type")
	if detectorType == "" {
		jsonError(w, "Missing detector type", http.StatusBadRequest)
		return
	}
	
	config, err := detectorConfigManager.GetConfig(detectorType)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// APIDetectorUpdate 更新检测器配置
func APIDetectorUpdate(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		DetectorType     string `json:"detector_type"`
		Enabled          bool   `json:"enabled"`
		WhitelistIPs     string `json:"whitelist_ips"`
		WhitelistPaths   string `json:"whitelist_paths"`
		SensitivityLevel string `json:"sensitivity_level"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	err := detectorConfigManager.UpdateConfig(
		req.DetectorType,
		req.Enabled,
		req.WhitelistIPs,
		req.WhitelistPaths,
		req.SensitivityLevel,
	)
	
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// APIDetectorToggle 切换检测器启用状态
func APIDetectorToggle(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	err := detectorConfigManager.SetEnabled(req.DetectorType, req.Enabled)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	// 实时应用到WAFProxy
	if WAFProxyInstance != nil {
		WAFProxyInstance.ApplyDetectorConfig(req.DetectorType, req.Enabled)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// APIDetectorRules 获取检测器的所有规则
func APIDetectorRules(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	detectorType := r.URL.Query().Get("type")
	if detectorType == "" {
		jsonError(w, "Missing detector type", http.StatusBadRequest)
		return
	}
	
	rules, err := detectorConfigManager.ListRules(detectorType)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules)
}

// APIDetectorAddRule 添加自定义规则
func APIDetectorAddRule(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	
	err := detectorConfigManager.AddCustomRule(req.DetectorType, req.Pattern, req.Description)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// APIDetectorRemoveRule 删除规则
func APIDetectorRemoveRule(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		RuleID int `json:"rule_id"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	err := detectorConfigManager.RemoveRule(req.RuleID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// APIDetectorToggleRule 切换规则启用状态
func APIDetectorToggleRule(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	if r.Method != "POST" {
		jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
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
	
	err := detectorConfigManager.ToggleRule(req.RuleID, req.Enabled)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// APIDetectorStats 获取检测器统计信息
func APIDetectorStats(w http.ResponseWriter, r *http.Request) {
	if detectorConfigManager == nil {
		jsonError(w, "Detector config manager not initialized", http.StatusInternalServerError)
		return
	}
	
	stats, err := detectorConfigManager.GetStats()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}
