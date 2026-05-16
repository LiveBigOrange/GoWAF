package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	intelclient "gowaf/internal/intel/client"
	"gowaf/internal/intel/config"
	intelstore "gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/gateway/middleware"
	"gowaf/internal/domain/gateway/templates"
)

func IntelConfigPage(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		APIGetIntelConfig(w, r)
		return
	}
	data := map[string]interface{}{
		"Active":   "intel-config",
		"CSPNonce": middleware.GetCSPNonce(r),
	}
	templates.IntelConfigTmpl.ExecuteTemplate(w, "intel-config", data)
}

func IntelSyncPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Active":   "intel-sync",
		"CSPNonce": middleware.GetCSPNonce(r),
	}
	templates.IntelSyncTmpl.ExecuteTemplate(w, "intel-sync", data)
}

func IntelAuditPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Active":   "intel-audit",
		"CSPNonce": middleware.GetCSPNonce(r),
	}
	templates.IntelAuditTmpl.ExecuteTemplate(w, "intel-audit", data)
}

func APIGetIntelConfig(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	cfgData := map[string]interface{}{
		"enabled": deps.Config.Intel != nil && deps.Config.Intel.Enabled,
	}
	if IntelLicense != nil {
		state := IntelLicense.GetState()
		cfgData["license"] = map[string]interface{}{"status": state.Status, "tier": state.Tier, "valid": state.Valid}
		cfgData["features"] = state.Features
	} else {
		cfgData["license"] = map[string]interface{}{"status": "inactive", "tier": "free", "valid": false}
	}
	if deps.Config.Intel != nil {
		cfgData["sync_enabled"] = deps.Config.Intel.Sync.Enabled
		cfgData["sync_data_types"] = deps.Config.Intel.Sync.DataTypes
		cfgData["sync_interval_secs"] = deps.Config.Intel.Sync.IntervalSecs
		cfgData["full_sync_on_desync"] = deps.Config.Intel.Sync.FullOnDesync
		cfgData["upload_enabled"] = deps.Config.Intel.Upload.Enabled
		cfgData["upload_data_types"] = deps.Config.Intel.Upload.DataTypes
		cfgData["upload_audit_mode"] = deps.Config.Intel.Upload.AuditMode
		cfgData["upload_interval_secs"] = deps.Config.Intel.Upload.IntervalSecs
		cfgData["upload_batch_size"] = deps.Config.Intel.Upload.BatchSize
		cfgData["upload_max_body_length"] = deps.Config.Intel.Upload.MaxBodyLength
		cfgData["rule_priority"] = deps.Config.Intel.Rule.Priority
		cfgData["rule_override_enabled"] = deps.Config.Intel.Rule.OverrideEnabled
		cfgData["server_url"] = deps.Config.Intel.ServerURL
		cfgData["instance_id"] = deps.Config.Intel.InstanceID
		cfgData["connect_timeout_secs"] = deps.Config.Intel.ConnectTimeout
		cfgData["request_timeout_secs"] = deps.Config.Intel.RequestTimeout
		cfgData["ca_cert_path"] = deps.Config.Intel.TLS.CACertPath
		cfgData["insecure_skip_verify"] = deps.Config.Intel.TLS.InsecureSkipVerify
		cfgData["alerts_on_connection_lost"] = deps.Config.Intel.Alerts.OnConnectionLost
		cfgData["alerts_on_sync_failure"] = deps.Config.Intel.Alerts.OnSyncFailure
		cfgData["alerts_on_license_expiring"] = deps.Config.Intel.Alerts.OnLicenseExpiring
		cfgData["alerts_on_upload_failure"] = deps.Config.Intel.Alerts.OnUploadFailure
		cfgData["alerts_on_emergency_rule"] = deps.Config.Intel.Alerts.OnEmergencyRule
		cfgData["alerts_failure_threshold"] = deps.Config.Intel.Alerts.FailureThreshold
		cfgData["offline_allow_offline"] = deps.Config.Intel.Offline.AllowOffline
		cfgData["offline_cache_retention_days"] = deps.Config.Intel.Offline.CacheRetentionDays
		cfgData["offline_max_cache_age_hours"] = deps.Config.Intel.Offline.MaxCacheAgeHours
		cfgData["intel_rule_prefix"] = deps.Config.Intel.Rule.IntelRulePrefix
		cfgData["custom_patterns"] = deps.Config.Intel.SensitiveFilter.CustomPatterns
		cfgData["auto_approve_patterns"] = deps.Config.Intel.Upload.AutoApprovePaths
		if deps.Config.Intel.LicenseKey != "" {
			cfgData["license_key"] = "****" + deps.Config.Intel.LicenseKey[len(deps.Config.Intel.LicenseKey)-4:]
		} else if IntelStore != nil {
			if lk, err := IntelStore.GetLicenseKey(); err == nil && lk != "" {
				cfgData["license_key"] = "****" + lk[len(lk)-4:]
			}
		}
	}
	jsonSuccess(w, cfgData)
}

func APIUpdateIntelConfig(w http.ResponseWriter, r *http.Request) {
	if deps.Config.Intel == nil {
		jsonError(w, "intel config not initialized", http.StatusBadRequest)
		return
	}

	var req struct {
		ServerURL                 *string  `json:"server_url"`
		LicenseKey                *string  `json:"license_key"`
		InstanceID                *string  `json:"instance_id"`
		ConnectTimeoutSecs        *int     `json:"connect_timeout_secs"`
		RequestTimeoutSecs        *int     `json:"request_timeout_secs"`
		CaCertPath                *string  `json:"ca_cert_path"`
		InsecureSkipVerify        *bool    `json:"insecure_skip_verify"`
		SyncEnabled               *bool    `json:"sync_enabled"`
		SyncIntervalSecs          *int     `json:"sync_interval_secs"`
		SyncDataTypes             []string `json:"sync_data_types"`
		FullSyncOnDesync          *bool    `json:"full_sync_on_desync"`
		UploadEnabled             *bool    `json:"upload_enabled"`
		UploadAuditMode           *bool    `json:"upload_audit_mode"`
		UploadIntervalSecs        *int     `json:"upload_interval_secs"`
		UploadBatchSize           *int     `json:"upload_batch_size"`
		UploadMaxBodyLength       *int     `json:"upload_max_body_length"`
		UploadDataTypes           []string `json:"upload_data_types"`
		RulePriority              *string  `json:"rule_priority"`
		RuleOverrideEnabled       *bool    `json:"rule_override_enabled"`
		AlertsOnConnectionLost    *bool    `json:"alerts_on_connection_lost"`
		AlertsOnSyncFailure       *bool    `json:"alerts_on_sync_failure"`
		AlertsOnLicenseExpiring   *bool    `json:"alerts_on_license_expiring"`
		AlertsOnUploadFailure     *bool    `json:"alerts_on_upload_failure"`
		AlertsOnEmergencyRule     *bool    `json:"alerts_on_emergency_rule"`
		AlertsFailureThreshold    *int     `json:"alerts_failure_threshold"`
		OfflineAllowOffline       *bool    `json:"offline_allow_offline"`
		OfflineCacheRetentionDays *int     `json:"offline_cache_retention_days"`
		OfflineMaxCacheAgeHours   *int     `json:"offline_max_cache_age_hours"`
		IntelRulePrefix           *string  `json:"intel_rule_prefix"`
		CustomPatterns            []string `json:"custom_patterns"`
		AutoApprovePatterns       []string `json:"auto_approve_patterns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cfgMu.Lock()
	defer cfgMu.Unlock()

	if req.ServerURL != nil {
		deps.Config.Intel.ServerURL = *req.ServerURL
		if IntelStore != nil {
			if err := IntelStore.SaveServerURL(*req.ServerURL); err != nil {
				logger.Error("failed to save server url to db", "err", err)
			}
		}
	}
	if req.LicenseKey != nil {
		deps.Config.Intel.LicenseKey = *req.LicenseKey
		if IntelStore != nil {
			if err := IntelStore.SaveLicenseKey(*req.LicenseKey); err != nil {
				logger.Error("failed to save license key to db", "err", err)
			}
		}
	}
	if req.InstanceID != nil {
		deps.Config.Intel.InstanceID = *req.InstanceID
	}
	if req.ConnectTimeoutSecs != nil {
		deps.Config.Intel.ConnectTimeout = *req.ConnectTimeoutSecs
	}
	if req.RequestTimeoutSecs != nil {
		deps.Config.Intel.RequestTimeout = *req.RequestTimeoutSecs
	}
	if req.CaCertPath != nil {
		deps.Config.Intel.TLS.CACertPath = *req.CaCertPath
	}
	if req.InsecureSkipVerify != nil {
		deps.Config.Intel.TLS.InsecureSkipVerify = *req.InsecureSkipVerify
	}

	if req.SyncEnabled != nil {
		deps.Config.Intel.Sync.Enabled = *req.SyncEnabled
	}
	if req.SyncIntervalSecs != nil {
		deps.Config.Intel.Sync.IntervalSecs = *req.SyncIntervalSecs
	}
	if req.SyncDataTypes != nil {
		deps.Config.Intel.Sync.DataTypes = req.SyncDataTypes
	}
	if req.FullSyncOnDesync != nil {
		deps.Config.Intel.Sync.FullOnDesync = *req.FullSyncOnDesync
	}
	if req.UploadEnabled != nil {
		deps.Config.Intel.Upload.Enabled = *req.UploadEnabled
	}
	if req.UploadAuditMode != nil {
		deps.Config.Intel.Upload.AuditMode = *req.UploadAuditMode
	}
	if req.UploadIntervalSecs != nil {
		deps.Config.Intel.Upload.IntervalSecs = *req.UploadIntervalSecs
	}
	if req.UploadBatchSize != nil {
		deps.Config.Intel.Upload.BatchSize = *req.UploadBatchSize
	}
	if req.UploadMaxBodyLength != nil {
		deps.Config.Intel.Upload.MaxBodyLength = *req.UploadMaxBodyLength
	}
	if req.UploadDataTypes != nil {
		deps.Config.Intel.Upload.DataTypes = req.UploadDataTypes
	}
	if req.RulePriority != nil {
		deps.Config.Intel.Rule.Priority = *req.RulePriority
	}
	if req.RuleOverrideEnabled != nil {
		deps.Config.Intel.Rule.OverrideEnabled = *req.RuleOverrideEnabled
	}

	if req.AlertsOnConnectionLost != nil {
		deps.Config.Intel.Alerts.OnConnectionLost = *req.AlertsOnConnectionLost
	}
	if req.AlertsOnSyncFailure != nil {
		deps.Config.Intel.Alerts.OnSyncFailure = *req.AlertsOnSyncFailure
	}
	if req.AlertsOnLicenseExpiring != nil {
		deps.Config.Intel.Alerts.OnLicenseExpiring = *req.AlertsOnLicenseExpiring
	}
	if req.AlertsOnUploadFailure != nil {
		deps.Config.Intel.Alerts.OnUploadFailure = *req.AlertsOnUploadFailure
	}
	if req.AlertsOnEmergencyRule != nil {
		deps.Config.Intel.Alerts.OnEmergencyRule = *req.AlertsOnEmergencyRule
	}
	if req.AlertsFailureThreshold != nil {
		deps.Config.Intel.Alerts.FailureThreshold = *req.AlertsFailureThreshold
	}

	if req.OfflineAllowOffline != nil {
		deps.Config.Intel.Offline.AllowOffline = *req.OfflineAllowOffline
	}
	if req.OfflineCacheRetentionDays != nil {
		deps.Config.Intel.Offline.CacheRetentionDays = *req.OfflineCacheRetentionDays
	}
	if req.OfflineMaxCacheAgeHours != nil {
		deps.Config.Intel.Offline.MaxCacheAgeHours = *req.OfflineMaxCacheAgeHours
	}

	if req.IntelRulePrefix != nil {
		deps.Config.Intel.Rule.IntelRulePrefix = *req.IntelRulePrefix
	}
	if req.CustomPatterns != nil {
		deps.Config.Intel.SensitiveFilter.CustomPatterns = req.CustomPatterns
	}
	if req.AutoApprovePatterns != nil {
		deps.Config.Intel.Upload.AutoApprovePaths = req.AutoApprovePatterns
	}

	if err := deps.Config.Save(); err != nil {
		jsonError(w, "failed to persist intel config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"updated": true})
}

func APIGetIntelSyncStatus(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"states": []interface{}{}})
		return
	}
	states, err := IntelStore.GetAllStates()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"states": states})
}

func APIGetIntelSyncLogs(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"logs": []interface{}{}})
		return
	}
	dataType := r.URL.Query().Get("data_type")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	logs, err := IntelStore.QuerySyncLogs(intelstore.SyncLogFilter{
		DataType: dataType,
		Limit:    limit,
		Offset:   offset,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"logs": logs})
}

func APITriggerIntelSync(w http.ResponseWriter, r *http.Request) {
	if IntelScheduler == nil {
		jsonError(w, "intel scheduler not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		DataType string `json:"data_type"`
		Full     bool   `json:"full"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.DataType == "" {
		jsonError(w, "data_type is required", http.StatusBadRequest)
		return
	}

	if req.Full {
		go IntelScheduler.TriggerFullSync(req.DataType)
	} else {
		go IntelScheduler.TriggerSync(req.DataType)
	}
	jsonSuccess(w, map[string]interface{}{"triggered": true, "data_type": req.DataType, "full": req.Full})
}

func APIGetIntelCredits(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"balance": 0})
		return
	}
	balance, err := IntelStore.GetCreditBalance()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"balance": balance})
}

func APIGetIntelUploadQueue(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"items": []interface{}{}})
		return
	}
	dataType := r.URL.Query().Get("data_type")
	if dataType == "" {
		dataType = "intercept_events"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	items, err := IntelStore.GetPendingUploads(dataType, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"items": items})
}

func APIApproveIntelUpload(w http.ResponseWriter, r *http.Request) {
	if IntelUploadMgr == nil {
		jsonError(w, "upload manager not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		ID   int64  `json:"id"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := IntelUploadMgr.ApproveItem(req.ID, req.Note); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"approved": true, "id": req.ID})
}

func APIRejectIntelUpload(w http.ResponseWriter, r *http.Request) {
	if IntelUploadMgr == nil {
		jsonError(w, "upload manager not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		ID   int64  `json:"id"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := IntelUploadMgr.RejectItem(req.ID, req.Note); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"rejected": true, "id": req.ID})
}

func APIBatchApproveIntelUpload(w http.ResponseWriter, r *http.Request) {
	if IntelUploadMgr == nil {
		jsonError(w, "upload manager not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		IDs  []int64 `json:"ids"`
		Note string  `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := IntelUploadMgr.BatchApprove(req.IDs, req.Note); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"approved": len(req.IDs), "ids": req.IDs})
}

func APIGetIntelUploadLogs(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"logs": []interface{}{}})
		return
	}
	dataType := r.URL.Query().Get("data_type")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	logs, err := IntelStore.QueryUploadLogs(intelstore.UploadLogFilter{
		DataType: dataType,
		Limit:    limit,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"logs": logs})
}

func APIGetIntelOverrides(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"overrides": []interface{}{}})
		return
	}
	overrides, err := IntelStore.GetOverrides()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"overrides": overrides})
}

func APIAddIntelOverride(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonError(w, "intel store not initialized", http.StatusBadRequest)
		return
	}
	var req intelstore.RuleOverride
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.IntelID == "" || req.DataType == "" || req.Action == "" {
		jsonError(w, "intel_id, data_type and action are required", http.StatusBadRequest)
		return
	}
	if err := IntelStore.AddOverride(&req); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"added": true})
}

func APIDeleteIntelOverride(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonError(w, "intel store not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := IntelStore.DeleteOverride(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"deleted": true})
}

func APIGetIntelExclusions(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"exclusions": []interface{}{}})
		return
	}
	exclusions, err := IntelStore.GetExclusions()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"exclusions": exclusions})
}

func APIAddIntelExclusion(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonError(w, "intel store not initialized", http.StatusBadRequest)
		return
	}
	var req intelstore.ExclusionRule
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.MatchType == "" || req.Pattern == "" {
		jsonError(w, "match_type and pattern are required", http.StatusBadRequest)
		return
	}
	if err := IntelStore.AddExclusion(&req); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"added": true})
}

func APIDeleteIntelExclusion(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonError(w, "intel store not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := IntelStore.DeleteExclusion(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"deleted": true})
}

func APIGetIntelSnapshots(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"snapshots": []interface{}{}})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	snapshots, err := IntelStore.ListSnapshots(limit, offset)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"snapshots": snapshots})
}

func APICreateIntelSnapshot(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonError(w, "intel store not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := IntelStore.CreateSnapshot(req.Description, nil, false); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"created": true})
}

func APIGetIntelConnectionLogs(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"logs": []interface{}{}})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}

	logs, err := IntelStore.QueryConnectionLogs(limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"logs": logs})
}

func APIAddIntelFalsePositive(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonError(w, "intel store not initialized", http.StatusBadRequest)
		return
	}
	var req intelstore.FalsePositiveRecord
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.EventID == 0 || req.RuleID == "" {
		jsonError(w, "event_id and rule_id are required", http.StatusBadRequest)
		return
	}
	req.Status = "pending"
	if err := IntelStore.AddFalsePositive(&req); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"added": true})
}

func APIGetIntelEmergencyRules(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil {
		jsonSuccess(w, map[string]interface{}{"rules": []interface{}{}})
		return
	}
	rules, err := IntelStore.GetActiveEmergencyRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"rules": rules})
}

func APIValidateIntelLicense(w http.ResponseWriter, r *http.Request) {
	if IntelLicense == nil {
		jsonError(w, "license manager not initialized", http.StatusBadRequest)
		return
	}
	jsonSuccess(w, map[string]interface{}{
		"status": IntelLicense.GetState().Status,
		"tier":   IntelLicense.GetState().Tier,
		"valid":  IntelLicense.GetState().Valid,
	})
}

func APIGetIntelDataTypes(w http.ResponseWriter, r *http.Request) {
	dataTypes := []map[string]string{
		{"key": "ip_blacklist", "label": "IP 黑名单"},
		{"key": "ua_rules", "label": "UA 规则"},
		{"key": "path_rules", "label": "路径规则"},
		{"key": "bot_ips", "label": "Bot IP"},
		{"key": "threat_signatures", "label": "威胁签名"},
		{"key": "geoip", "label": "GeoIP 数据"},
	}
	jsonSuccess(w, map[string]interface{}{"data_types": dataTypes})
}

func APIToggleIntelEnabled(w http.ResponseWriter, r *http.Request) {
	if deps.Config.Intel == nil {
		jsonError(w, "intel config not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	cfgMu.Lock()
	deps.Config.Intel.Enabled = req.Enabled
	if err := deps.Config.Save(); err != nil {
		cfgMu.Unlock()
		jsonError(w, "failed to persist intel enabled state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfgMu.Unlock()

	if req.Enabled {
		if IntelStartFn != nil {
			if err := IntelStartFn(); err != nil {
				cfgMu.Lock()
				deps.Config.Intel.Enabled = false
				deps.Config.Save()
				cfgMu.Unlock()
				jsonError(w, "failed to start intel modules: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	} else {
		if IntelStopFn != nil {
			IntelStopFn()
		}
	}

	jsonSuccess(w, map[string]interface{}{"enabled": req.Enabled})
}

func APIGetIntelMaskConfig(w http.ResponseWriter, r *http.Request) {
	if deps.Config.Intel == nil {
		jsonSuccess(w, map[string]interface{}{"level": "standard", "enabled": false})
		return
	}
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	jsonSuccess(w, map[string]interface{}{
		"level":           deps.Config.Intel.SensitiveFilter.Action,
		"enabled":         deps.Config.Intel.SensitiveFilter.Enabled,
		"custom_patterns": deps.Config.Intel.SensitiveFilter.CustomPatterns,
	})
}

func APIUpdateIntelMaskConfig(w http.ResponseWriter, r *http.Request) {
	if deps.Config.Intel == nil {
		jsonError(w, "intel config not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		Enabled        *bool    `json:"enabled"`
		Level          *string  `json:"level"`
		CustomPatterns []string `json:"custom_patterns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	cfgMu.Lock()
	defer cfgMu.Unlock()
	if req.Enabled != nil {
		deps.Config.Intel.SensitiveFilter.Enabled = *req.Enabled
	}
	if req.Level != nil {
		validLevels := map[string]bool{"minimal": true, "standard": true, "strict": true}
		if !validLevels[*req.Level] {
			jsonError(w, "invalid mask level, must be minimal/standard/strict", http.StatusBadRequest)
			return
		}
		deps.Config.Intel.SensitiveFilter.Action = *req.Level
	}
	if req.CustomPatterns != nil {
		deps.Config.Intel.SensitiveFilter.CustomPatterns = req.CustomPatterns
	}
	if err := deps.Config.Save(); err != nil {
		jsonError(w, "failed to persist intel mask config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, map[string]interface{}{"updated": true})
}

var intelDataTypes = []string{"ip_blacklist", "ua_rules", "path_rules", "bot_ips", "threat_signatures", "geoip"}

func isValidDataType(dt string) bool {
	for _, v := range intelDataTypes {
		if v == dt {
			return true
		}
	}
	return false
}

func APIDisableIntelIPRule(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil || deps.RuleEngine == nil {
		jsonError(w, "intel not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		IntelID string `json:"intel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.IntelID == "" {
		jsonError(w, "intel_id is required", http.StatusBadRequest)
		return
	}
	deps.RuleEngine.RemoveIPRuleByIntelID(req.IntelID)
	jsonSuccess(w, map[string]interface{}{"disabled": true})
}

func APIDisableIntelUARule(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil || deps.RuleEngine == nil {
		jsonError(w, "intel not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		IntelID string `json:"intel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.IntelID == "" {
		jsonError(w, "intel_id is required", http.StatusBadRequest)
		return
	}
	deps.RuleEngine.RemoveUARuleByIntelID(req.IntelID)
	jsonSuccess(w, map[string]interface{}{"disabled": true})
}

func APIDisableIntelPathRule(w http.ResponseWriter, r *http.Request) {
	if IntelStore == nil || deps.RuleEngine == nil {
		jsonError(w, "intel not initialized", http.StatusBadRequest)
		return
	}
	var req struct {
		IntelID string `json:"intel_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.IntelID == "" {
		jsonError(w, "intel_id is required", http.StatusBadRequest)
		return
	}
	deps.RuleEngine.RemovePathRuleByIntelID(req.IntelID)
	jsonSuccess(w, map[string]interface{}{"disabled": true})
}

var _ = config.IntelConfig{}

func APITestIntelConnection(w http.ResponseWriter, r *http.Request) {
	cfgMu.RLock()
	if deps.Config.Intel == nil {
		cfgMu.RUnlock()
		jsonError(w, "intel config not initialized", http.StatusBadRequest)
		return
	}
	serverURL := deps.Config.Intel.ServerURL
	licenseKey := deps.Config.Intel.LicenseKey
	instanceID := deps.Config.Intel.InstanceID
	tlsCfg := deps.Config.Intel.TLS
	timeout := deps.Config.Intel.ConnectTimeout
	if timeout <= 0 {
		timeout = 10
	}
	cfgMu.RUnlock()

	if licenseKey == "" && IntelStore != nil {
		if lk, err := IntelStore.GetLicenseKey(); err == nil && lk != "" {
			licenseKey = lk
		}
	}

	var req struct {
		ServerURL  *string `json:"server_url"`
		LicenseKey *string `json:"license_key"`
		InstanceID *string `json:"instance_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
		if req.ServerURL != nil && *req.ServerURL != "" {
			serverURL = *req.ServerURL
		}
		if req.LicenseKey != nil && *req.LicenseKey != "" {
			licenseKey = *req.LicenseKey
		}
		if req.InstanceID != nil {
			instanceID = *req.InstanceID
		}
	}

	if serverURL == "" {
		jsonError(w, "server_url is required", http.StatusBadRequest)
		return
	}
	if licenseKey == "" {
		jsonError(w, "license_key is required", http.StatusBadRequest)
		return
	}

	tempCfg := &config.IntelConfig{
		Enabled:        true,
		ServerURL:      strings.TrimRight(serverURL, "/"),
		LicenseKey:     licenseKey,
		InstanceID:     instanceID,
		TLS:            tlsCfg,
		ConnectTimeout: timeout,
		RequestTimeout: timeout,
	}

	cli, err := intelclient.NewIntelClient(tempCfg)
	if err != nil {
		jsonError(w, "failed to create test client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	resp, err := cli.VerifyLicense(ctx, &intelclient.LicenseVerifyReq{
		LicenseKey: licenseKey,
		InstanceID: instanceID,
	})
	if err != nil {
		jsonSuccess(w, map[string]interface{}{
			"connected": false,
			"error":     err.Error(),
		})
		return
	}

	jsonSuccess(w, map[string]interface{}{
		"connected": resp.Valid,
		"valid":     resp.Valid,
		"tier":      resp.Tier,
		"status":    "active",
	})
}
