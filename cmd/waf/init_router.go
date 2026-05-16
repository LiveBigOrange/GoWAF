package main

import (
	"net/http"
	"net/http/pprof"

	"gowaf/internal/backend"
	"gowaf/internal/domain/gateway"
	"gowaf/internal/domain/gateway/handler"
	"gowaf/internal/domain/gateway/middleware"

	"github.com/gorilla/mux"
)

func setupRouter(backendManager *backend.Manager) *mux.Router {
	router := mux.NewRouter()

	staticHandler := gateway.FileServerWithMIME(gateway.GetStaticFS())
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", staticHandler))

	router.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/favicon.svg", http.StatusMovedPermanently)
	})

	router.HandleFunc("/login", handler.LoginPage).Methods("GET", "POST")
	router.HandleFunc("/captcha", handler.CaptchaHandler).Methods("GET")
	router.HandleFunc("/logout", handler.Logout).Methods("GET")

	apiRouter := router.PathPrefix("/api").Subrouter()
	apiRouter.Use(middleware.Auth)

	registerConfigAPI(apiRouter)
	registerDashboardAPI(apiRouter)
	registerRulesAPI(apiRouter)
	registerProxyAPI(apiRouter)
	registerBackendAPI(apiRouter)
	registerDetectorAPI(apiRouter)
	registerMetricsAPI(apiRouter)
	registerLogsAPI(apiRouter)
	registerRateLimitAPI(apiRouter)
	registerSecurityAPI(apiRouter)
	registerNotificationAPI(apiRouter)
	registerBotAPI(apiRouter)
	registerVPatchAPI(apiRouter)
	registerComplianceAPI(apiRouter)
	registerRespHeaderAPI(apiRouter)
	registerGeoIPAPI(apiRouter)
	registerDLPAPI(apiRouter)
	// [封存] 情报中心API路由暂时禁用
	// registerIntelAPI(apiRouter)
	registerAPISchemaAPI(apiRouter)
	registerConfigVersionAPI(apiRouter)

	apiRouter.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Methods("GET")
	apiRouter.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if backendManager != nil {
			backends := backendManager.GetBackends()
			hasHealthy := false
			for _, b := range backends {
				if b.Enabled && b.Healthy {
					hasHealthy = true
					break
				}
			}
			if !hasHealthy && len(backends) > 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte("no healthy backends"))
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Methods("GET")

	apiRouter.HandleFunc("/config/backup", handler.APIBackupConfig).Methods("GET")
	apiRouter.HandleFunc("/config/restore", handler.APIRestoreConfig).Methods("POST")

	pprofRouter := router.PathPrefix("/debug/pprof").Subrouter()
	pprofRouter.Use(middleware.Auth)
	pprofRouter.HandleFunc("/", pprof.Index).Methods("GET")
	pprofRouter.HandleFunc("/cmdline", pprof.Cmdline).Methods("GET")
	pprofRouter.HandleFunc("/profile", pprof.Profile).Methods("GET")
	pprofRouter.HandleFunc("/symbol", pprof.Symbol).Methods("GET")
	pprofRouter.HandleFunc("/trace", pprof.Trace).Methods("GET")
	pprofRouter.Handle("/goroutine", pprof.Handler("goroutine")).Methods("GET")
	pprofRouter.Handle("/heap", pprof.Handler("heap")).Methods("GET")
	pprofRouter.Handle("/threadcreate", pprof.Handler("threadcreate")).Methods("GET")
	pprofRouter.Handle("/block", pprof.Handler("block")).Methods("GET")

	registerPageRoutes(router, apiRouter)

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("session"); err == nil && middleware.IsValidSession(cookie.Value) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
		} else {
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}).Methods("GET")

	return router
}

func registerPageRoutes(router *mux.Router, apiRouter *mux.Router) {
	pageRouter := router.NewRoute().Subrouter()
	pageRouter.Use(middleware.Auth)

	pageRouter.HandleFunc("/dashboard", handler.DashboardPage).Methods("GET")
	pageRouter.HandleFunc("/ws/dashboard", handler.DashboardWebSocket).Methods("GET")
	pageRouter.HandleFunc("/config", handler.ConfigHandler).Methods("GET")
	pageRouter.HandleFunc("/config-system", handler.ConfigSystemHandler).Methods("GET")
	pageRouter.HandleFunc("/proxyconfig", handler.ProxyConfigPage).Methods("GET")
	pageRouter.HandleFunc("/domain", handler.DomainPage).Methods("GET")
	pageRouter.HandleFunc("/cert", handler.CertPage).Methods("GET")
	pageRouter.HandleFunc("/backend", handler.BackendPage).Methods("GET")
	pageRouter.HandleFunc("/detector", handler.DetectorPage).Methods("GET")
	pageRouter.HandleFunc("/rules", handler.RulesPage).Methods("GET", "POST")
	pageRouter.HandleFunc("/ua", handler.UAPage).Methods("GET", "POST")
	pageRouter.HandleFunc("/path", handler.PathPage).Methods("GET", "POST")
	apiRouter.HandleFunc("/ua/update", handler.UAUpdateAPI).Methods("POST")
	apiRouter.HandleFunc("/ua/toggle", handler.UAToggleAPI).Methods("POST")
	apiRouter.HandleFunc("/ua/delete", handler.UADeleteAPI).Methods("POST")
	apiRouter.HandleFunc("/path/update", handler.PathUpdateAPI).Methods("POST")
	apiRouter.HandleFunc("/path/toggle", handler.PathToggleAPI).Methods("POST")
	apiRouter.HandleFunc("/path/delete", handler.PathDeleteAPI).Methods("POST")
	pageRouter.HandleFunc("/ratelimit", handler.RateLimitPage).Methods("GET")
	pageRouter.HandleFunc("/geoblock", handler.GeoBlockPage).Methods("GET")
	pageRouter.HandleFunc("/httpmethods", handler.HTTPMethodsPage).Methods("GET")
	pageRouter.HandleFunc("/pathratelimit", handler.PathRateLimitPage).Methods("GET")
	pageRouter.HandleFunc("/smartlimit", handler.SmartLimitPage).Methods("GET")
	pageRouter.HandleFunc("/blockpage", handler.BlockPagePage).Methods("GET")
	pageRouter.HandleFunc("/notify", handler.NotifyPage).Methods("GET")
	pageRouter.HandleFunc("/bot", handler.BotPage).Methods("GET")
	pageRouter.HandleFunc("/vpatch", handler.VPatchPage).Methods("GET")
	pageRouter.HandleFunc("/compliance", handler.CompliancePage).Methods("GET")
	pageRouter.HandleFunc("/respheader", handler.RespHeaderPage).Methods("GET")
	pageRouter.HandleFunc("/dlp", handler.DLPPage).Methods("GET")
	pageRouter.HandleFunc("/apischema", handler.APISchemaPage).Methods("GET")
	pageRouter.HandleFunc("/trend", handler.TrendPage).Methods("GET")

	// [封存] 情报中心页面路由暂时禁用
	// pageRouter.HandleFunc("/intel/config", handler.IntelConfigPage).Methods("GET")
	// pageRouter.HandleFunc("/intel/sync", handler.IntelSyncPage).Methods("GET")
	// pageRouter.HandleFunc("/intel/audit", handler.IntelAuditPage).Methods("GET")
	pageRouter.HandleFunc("/intercepts", handler.InterceptsPage).Methods("GET")
	pageRouter.HandleFunc("/logs", handler.LogsPage).Methods("GET")
	pageRouter.HandleFunc("/adminlog", handler.AdminLogPage).Methods("GET")
	pageRouter.HandleFunc("/syslog", handler.SysLogPage).Methods("GET")
}

func registerConfigAPI(r *mux.Router) {
	r.HandleFunc("/config", handler.GetConfigAPI).Methods("GET")
	r.HandleFunc("/config/basic", handler.GetBasicConfigAPI).Methods("GET")
	r.HandleFunc("/config/security", handler.GetSecurityConfigAPI).Methods("GET")
	r.HandleFunc("/config/performance", handler.GetPerformanceConfigAPI).Methods("GET")
	r.HandleFunc("/config/scheduler", handler.GetSchedulerConfigAPI).Methods("GET")
	r.HandleFunc("/config/websocket", handler.GetWebSocketConfigAPI).Methods("GET")
	r.HandleFunc("/config", handler.UpdateConfigAPI).Methods("POST")
	r.HandleFunc("/config/reset", handler.ResetConfigAPI).Methods("POST")
	r.HandleFunc("/config/security", handler.UpdateSecurityConfigAPI).Methods("POST")
	r.HandleFunc("/config/security/reset", handler.ResetSecurityConfigAPI).Methods("POST")
	r.HandleFunc("/config/performance", handler.UpdatePerformanceConfigAPI).Methods("POST")
	r.HandleFunc("/config/performance/reset", handler.ResetPerformanceConfigAPI).Methods("POST")
	r.HandleFunc("/config/scheduler", handler.UpdateSchedulerConfigAPI).Methods("POST")
	r.HandleFunc("/config/scheduler/reset", handler.ResetSchedulerConfigAPI).Methods("POST")
	r.HandleFunc("/config/websocket", handler.UpdateWebSocketConfigAPI).Methods("POST")
	r.HandleFunc("/config/websocket/reset", handler.ResetWebSocketConfigAPI).Methods("POST")
	r.HandleFunc("/admin/change-password", handler.APIChangePassword).Methods("POST")

	// User Management API
	r.HandleFunc("/admin/users", handler.APIUserList).Methods("GET")
	r.HandleFunc("/admin/users/add", handler.APIUserAdd).Methods("POST")
	r.HandleFunc("/admin/users/delete", handler.APIUserDelete).Methods("POST")
	r.HandleFunc("/admin/users/toggle", handler.APIUserToggle).Methods("POST")
	r.HandleFunc("/admin/users/password", handler.APIPasswordChangeForUser).Methods("POST")
}

func registerDashboardAPI(r *mux.Router) {
	r.HandleFunc("/stats", handler.APIHandler).Methods("GET")
	r.HandleFunc("/events", handler.APIEvents).Methods("GET")
	r.HandleFunc("/system", handler.APISystem).Methods("GET")
	r.HandleFunc("/top/ips", handler.APITopIPs).Methods("GET")
	r.HandleFunc("/top/paths", handler.APITopPaths).Methods("GET")
	r.HandleFunc("/rule-hits", handler.APIRuleHits).Methods("GET")
	r.HandleFunc("/intercepts", handler.APIIntercepts).Methods("GET")
}

func registerRulesAPI(r *mux.Router) {
	r.HandleFunc("/rules", handler.APIRules).Methods("GET")
	r.HandleFunc("/rules/ip/add", handler.APIAddIPRule).Methods("POST")
	r.HandleFunc("/rules/ip/toggle", handler.APIToggleIPRule).Methods("POST")
	r.HandleFunc("/rules/ip/delete", handler.APIRemoveIPRule).Methods("POST")
	r.HandleFunc("/path", handler.APIPath).Methods("GET")
	r.HandleFunc("/ua", handler.APIUA).Methods("GET")
}

func registerProxyAPI(r *mux.Router) {
	r.HandleFunc("/proxy/list", handler.APIProxyList).Methods("GET")
	r.HandleFunc("/proxy/add", handler.APIProxyAdd).Methods("POST")
	r.HandleFunc("/proxy/update", handler.APIProxyUpdate).Methods("POST")
	r.HandleFunc("/proxy/delete", handler.APIProxyDelete).Methods("POST")
	r.HandleFunc("/domain/list", handler.APIDomainList).Methods("GET")
	r.HandleFunc("/domain/add", handler.APIDomainAdd).Methods("POST")
	r.HandleFunc("/domain/update", handler.APIDomainUpdate).Methods("POST")
	r.HandleFunc("/domain/delete", handler.APIDomainDelete).Methods("POST")
	r.HandleFunc("/cert/list", handler.APICertList).Methods("GET")
	r.HandleFunc("/cert/unified", handler.APIUnifiedCerts).Methods("GET")
	r.HandleFunc("/cert/get", handler.APICertGet).Methods("GET")
	r.HandleFunc("/cert/upload", handler.APICertUpload).Methods("POST")
	r.HandleFunc("/cert/update", handler.APICertUpdate).Methods("POST")
	r.HandleFunc("/cert/delete", handler.APICertDelete).Methods("POST")
	r.HandleFunc("/cert/check", handler.APICertCheck).Methods("GET")
	r.HandleFunc("/acme/status", handler.APIACMEStatus).Methods("GET")
	r.HandleFunc("/acme/renew", handler.APIACMERenew).Methods("POST")
	r.HandleFunc("/acme/config", handler.APIACMEConfig).Methods("GET", "POST")
	r.HandleFunc("/acme/precheck", handler.APIACMEPreCheck).Methods("POST")
	r.HandleFunc("/acme/convert-to-auto", handler.APIACMEConvertToAuto).Methods("POST")
	r.HandleFunc("/acme/remove-domain", handler.APIACMERemoveDomain).Methods("POST")
}

func registerBackendAPI(r *mux.Router) {
	r.HandleFunc("/backend/list", handler.APIBackendList).Methods("GET")
	r.HandleFunc("/backend/add", handler.APIBackendAdd).Methods("POST")
	r.HandleFunc("/backend/update", handler.APIBackendUpdate).Methods("POST")
	r.HandleFunc("/backend/delete", handler.APIBackendDelete).Methods("POST")
	r.HandleFunc("/backend/lb-policy", handler.APIBackendLBPolicy).Methods("GET")
	r.HandleFunc("/backend/lb-policy", handler.APIBackendSetLBPolicy).Methods("POST")
	r.HandleFunc("/backend/group/list", handler.APIBackendGroupList).Methods("GET")
	r.HandleFunc("/backend/group/add", handler.APIBackendGroupAdd).Methods("POST")
	r.HandleFunc("/backend/group/update", handler.APIBackendGroupUpdate).Methods("POST")
	r.HandleFunc("/backend/group/delete", handler.APIBackendGroupDelete).Methods("POST")
	r.HandleFunc("/backend/group/members", handler.APIBackendGroupMembers).Methods("GET")
	r.HandleFunc("/backend/group/member/add", handler.APIBackendGroupMemberAdd).Methods("POST")
	r.HandleFunc("/backend/group/member/update", handler.APIBackendGroupMemberUpdate).Methods("POST")
	r.HandleFunc("/backend/group/member/delete", handler.APIBackendGroupMemberDelete).Methods("POST")
	r.HandleFunc("/backend/group/used-backend-ids", handler.APIBackendGroupUsedIDs).Methods("GET")
	r.HandleFunc("/backend/group/map", handler.APIBackendGroupMap).Methods("GET")
}

func registerDetectorAPI(r *mux.Router) {
	r.HandleFunc("/detector/list", handler.APIDetectorList).Methods("GET")
	r.HandleFunc("/detector/get", handler.APIDetectorGet).Methods("GET")
	r.HandleFunc("/detector/update", handler.APIDetectorUpdate).Methods("POST")
	r.HandleFunc("/detector/toggle", handler.APIDetectorToggle).Methods("POST")
	r.HandleFunc("/detector/rules", handler.APIDetectorRules).Methods("GET")
	r.HandleFunc("/detector/rule/add", handler.APIDetectorAddRule).Methods("POST")
	r.HandleFunc("/detector/rule/remove", handler.APIDetectorRemoveRule).Methods("POST")
	r.HandleFunc("/detector/rule/toggle", handler.APIDetectorToggleRule).Methods("POST")
	r.HandleFunc("/detector/stats", handler.APIDetectorStats).Methods("GET")
}

func registerMetricsAPI(r *mux.Router) {
	r.HandleFunc("/metrics/minute", handler.GetMetricsMinuteStats).Methods("GET")
	r.HandleFunc("/metrics/hourly", handler.GetMetricsHourlyStats).Methods("GET")
	r.HandleFunc("/metrics/events", handler.GetMetricsEvents).Methods("GET")
	r.HandleFunc("/metrics/trend", handler.GetMetricsTrend).Methods("GET")
	r.HandleFunc("/metrics/system-trend", handler.GetSystemTrend).Methods("GET")
}

func registerLogsAPI(r *mux.Router) {
	r.HandleFunc("/logs/list", handler.GetLogsList).Methods("GET")
	r.HandleFunc("/logs/stats", handler.GetLogsStats).Methods("GET")
	r.HandleFunc("/logs/files", handler.GetLogFiles).Methods("GET")
	r.HandleFunc("/logs/export", handler.GetLogsExport).Methods("GET")
	r.HandleFunc("/adminlog/list", handler.APIAdminLogList).Methods("GET")
	r.HandleFunc("/syslog/list", handler.APISysLogList).Methods("GET")
}

func registerRateLimitAPI(r *mux.Router) {
	r.HandleFunc("/ratelimit", handler.APIGetRateLimit).Methods("GET")
	r.HandleFunc("/ratelimit", handler.APIPostRateLimit).Methods("POST")
	r.HandleFunc("/ratelimit-key", handler.GetRateLimitKeyConfig).Methods("GET")
	r.HandleFunc("/ratelimit-key", handler.PostRateLimitKeyConfig).Methods("POST")
	r.HandleFunc("/smartlimit/config", handler.APIGetSmartLimitConfig).Methods("GET")
	r.HandleFunc("/smartlimit/config", handler.APIUpdateSmartLimitConfig).Methods("POST")
	r.HandleFunc("/smartlimit/profiles", handler.APIGetSmartLimitProfiles).Methods("GET")
	r.HandleFunc("/smartlimit/profile", handler.APIGetSmartLimitProfile).Methods("GET")
	r.HandleFunc("/smartlimit/evaluate", handler.APIEvaluateSmartLimit).Methods("GET")
	r.HandleFunc("/smartlimit/stats", handler.APIGetSmartLimitStats).Methods("GET")
	r.HandleFunc("/smartlimit/pardon", handler.APIPardonIP).Methods("POST")
	r.HandleFunc("/blockpage/list", handler.GetBlockPageConfigs).Methods("GET")
	r.HandleFunc("/blockpage/update", handler.UpdateBlockPageConfig).Methods("POST")
	r.HandleFunc("/blockpage/create", handler.CreateBlockPageConfig).Methods("POST")
	r.HandleFunc("/blockpage/delete", handler.DeleteBlockPageConfig).Methods("POST")
}

func registerSecurityAPI(r *mux.Router) {
	r.HandleFunc("/geo/list", handler.APIGeoRulesList).Methods("GET")
	r.HandleFunc("/geo/add", handler.APIGeoRuleAdd).Methods("POST")
	r.HandleFunc("/geo/update", handler.APIGeoRuleUpdate).Methods("POST")
	r.HandleFunc("/geo/delete", handler.APIGeoRuleDelete).Methods("POST")
	r.HandleFunc("/geo/lookup", handler.APIGeoLookup).Methods("GET")
	r.HandleFunc("/methods/list", handler.APIAllowedMethodsList).Methods("GET")
	r.HandleFunc("/methods/set", handler.APIAllowedMethodSet).Methods("POST")
	r.HandleFunc("/methods/delete", handler.APIAllowedMethodDelete).Methods("POST")
	r.HandleFunc("/path-ratelimit/list", handler.APIPathRateLimitsList).Methods("GET")
	r.HandleFunc("/path-ratelimit/add", handler.APIPathRateLimitAdd).Methods("POST")
	r.HandleFunc("/path-ratelimit/update", handler.APIPathRateLimitUpdate).Methods("POST")
	r.HandleFunc("/path-ratelimit/delete", handler.APIPathRateLimitDelete).Methods("POST")
	r.HandleFunc("/config/trusted-proxies", handler.GetTrustedProxiesAPI).Methods("GET")
	r.HandleFunc("/config/trusted-proxies", handler.UpdateTrustedProxiesAPI).Methods("POST")
	r.HandleFunc("/config/log", handler.GetLogConfigAPI).Methods("GET")
	r.HandleFunc("/config/log", handler.UpdateLogConfigAPI).Methods("POST")
	r.HandleFunc("/config/log/reset", handler.ResetLogConfigAPI).Methods("POST")
	r.HandleFunc("/config/admin-whitelist", handler.GetAdminWhitelistAPI).Methods("GET")
	r.HandleFunc("/config/admin-whitelist", handler.UpdateAdminWhitelistAPI).Methods("POST")
	r.HandleFunc("/config/retention", handler.GetRetentionConfigAPI).Methods("GET")
	r.HandleFunc("/config/retention", handler.UpdateRetentionConfigAPI).Methods("POST")
	r.HandleFunc("/config/retention/reset", handler.ResetRetentionConfigAPI).Methods("POST")
	r.HandleFunc("/config/apikeys", handler.ListAPIKeysAPI).Methods("GET")
	r.HandleFunc("/config/apikeys", handler.CreateAPIKeyAPI).Methods("POST")
	r.HandleFunc("/config/apikeys/delete", handler.DeleteAPIKeyAPI).Methods("POST")
	r.HandleFunc("/config/apikeys/toggle", handler.ToggleAPIKeyAPI).Methods("POST")
	r.HandleFunc("/config/tls", handler.GetTLSConfigAPI).Methods("GET")
	r.HandleFunc("/config/pow", handler.GetPoWConfigAPI).Methods("GET")
	r.HandleFunc("/config/pow", handler.UpdatePoWConfigAPI).Methods("POST")
	r.HandleFunc("/config/global-enabled", handler.GetGlobalEnabledAPI).Methods("GET")
	r.HandleFunc("/config/global-enabled", handler.UpdateGlobalEnabledAPI).Methods("POST")
	r.HandleFunc("/config/session-safe", handler.GetSessionSafeConfigAPI).Methods("GET")
	r.HandleFunc("/config/session-safe", handler.UpdateSessionSafeConfigAPI).Methods("POST")
	r.HandleFunc("/config/session-safe/reset", handler.ResetSessionSafeConfigAPI).Methods("POST")
}

func registerNotificationAPI(r *mux.Router) {
	r.HandleFunc("/notify/rules", handler.GetAlertRules).Methods("GET")
	r.HandleFunc("/notify/rules/update", handler.UpdateAlertRule).Methods("POST")
	r.HandleFunc("/notify/rules/delete", handler.DeleteAlertRule).Methods("POST")
	r.HandleFunc("/notify/config", handler.GetNotifyConfig).Methods("GET")
	r.HandleFunc("/notify/config/update", handler.UpdateNotifyConfig).Methods("POST")
	r.HandleFunc("/notify/test", handler.TestNotify).Methods("POST")
}

func registerBotAPI(r *mux.Router) {
	r.HandleFunc("/bot/rules", handler.APIBotRules).Methods("GET")
	r.HandleFunc("/bot/rule/add", handler.APIBotRuleAdd).Methods("POST")
	r.HandleFunc("/bot/rule/update", handler.APIBotRuleUpdate).Methods("POST")
	r.HandleFunc("/bot/rule/delete", handler.APIBotRuleDelete).Methods("POST")
	r.HandleFunc("/bot/rule/toggle", handler.APIBotRuleToggle).Methods("POST")
	r.HandleFunc("/bot/rule/toggle-enabled", handler.APIBotRuleToggleEnabled).Methods("POST")
	r.HandleFunc("/bot/rule/batch-delete", handler.APIBotBatchDelete).Methods("POST")
	r.HandleFunc("/bot/rule/batch-toggle-enabled", handler.APIBotBatchToggleEnabled).Methods("POST")
	r.HandleFunc("/bot/known-bots", handler.APIBotKnownBots).Methods("GET")
	r.HandleFunc("/bot/known-bot-override", handler.APIBotKnownBotOverride).Methods("POST")
	r.HandleFunc("/bot/policies", handler.APIBotPolicies).Methods("GET")
	r.HandleFunc("/bot/policy/set", handler.APIBotSetPolicy).Methods("POST")
	r.HandleFunc("/bot/classify", handler.APIBotClassify).Methods("GET")
	r.HandleFunc("/bot/stats", handler.APIBotStats).Methods("GET")
}

func registerVPatchAPI(r *mux.Router) {
	r.HandleFunc("/vpatch/list", handler.APIVPatchList).Methods("GET")
	r.HandleFunc("/vpatch/add", handler.APIVPatchAdd).Methods("POST")
	r.HandleFunc("/vpatch/delete", handler.APIVPatchDelete).Methods("POST")
	r.HandleFunc("/vpatch/toggle", handler.APIVPatchToggle).Methods("POST")
}

func registerComplianceAPI(r *mux.Router) {
	r.HandleFunc("/compliance/report", handler.APIComplianceReport).Methods("GET")
	r.HandleFunc("/compliance/html", handler.APIComplianceHTML).Methods("GET")
}

func registerRespHeaderAPI(r *mux.Router) {
	r.HandleFunc("/respheader/list", handler.APIRespHeaderList).Methods("GET")
	r.HandleFunc("/respheader/add", handler.APIRespHeaderAdd).Methods("POST")
	r.HandleFunc("/respheader/update", handler.APIRespHeaderUpdate).Methods("POST")
	r.HandleFunc("/respheader/delete", handler.APIRespHeaderDelete).Methods("POST")
	r.HandleFunc("/respheader/toggle", handler.APIRespHeaderToggle).Methods("POST")

	// ReqHeader API
	r.HandleFunc("/reqheader/list", handler.APIReqHeaderList).Methods("GET")
	r.HandleFunc("/reqheader/add", handler.APIReqHeaderAdd).Methods("POST")
	r.HandleFunc("/reqheader/update", handler.APIReqHeaderUpdate).Methods("POST")
	r.HandleFunc("/reqheader/delete", handler.APIReqHeaderDelete).Methods("POST")
	r.HandleFunc("/reqheader/toggle", handler.APIReqHeaderToggle).Methods("POST")
}

func registerGeoIPAPI(r *mux.Router) {
	r.HandleFunc("/geoip/update/config", handler.APIGeoIPUpdateConfig).Methods("GET")
	r.HandleFunc("/geoip/update/config/save", handler.APIGeoIPUpdateConfigSave).Methods("POST")
	r.HandleFunc("/geoip/update/trigger", handler.APIGeoIPUpdateTrigger).Methods("POST")
	r.HandleFunc("/geoip/upload", handler.APIGeoIPUpload).Methods("POST")
}

func registerDLPAPI(r *mux.Router) {
	r.HandleFunc("/dlp/list", handler.APIDLPList).Methods("GET")
	r.HandleFunc("/dlp/add", handler.APIDLPAdd).Methods("POST")
	r.HandleFunc("/dlp/update", handler.APIDLPUpdate).Methods("POST")
	r.HandleFunc("/dlp/delete", handler.APIDLPDelete).Methods("POST")
	r.HandleFunc("/dlp/toggle", handler.APIAPIDlpToggle).Methods("POST")
}

func registerAPISchemaAPI(r *mux.Router) {
	r.HandleFunc("/apischema/list", handler.APIAPISchemaList).Methods("GET")
	r.HandleFunc("/apischema/add", handler.APIAPISchemaAdd).Methods("POST")
	r.HandleFunc("/apischema/update", handler.APIAPISchemaUpdate).Methods("POST")
	r.HandleFunc("/apischema/delete", handler.APIAPISchemaDelete).Methods("POST")
	r.HandleFunc("/apischema/toggle", handler.APIAPISchemaToggle).Methods("POST")
	r.HandleFunc("/apischema/validate", handler.APIAPISchemaValidate).Methods("POST")
}

func registerConfigVersionAPI(r *mux.Router) {
	r.HandleFunc("/config/version/list", handler.APIConfigVersionList).Methods("GET")
	r.HandleFunc("/config/version/get", handler.APIConfigVersionGet).Methods("GET")
	r.HandleFunc("/config/version/restore", handler.APIConfigVersionRestore).Methods("POST")
	r.HandleFunc("/config/version/diff", handler.APIConfigVersionDiff).Methods("GET")
	r.HandleFunc("/config/version/create", handler.APIConfigVersionCreate).Methods("POST")
}

func registerIntelAPI(r *mux.Router) {
	r.HandleFunc("/intel/config", handler.APIGetIntelConfig).Methods("GET")
	r.HandleFunc("/intel/config", handler.APIUpdateIntelConfig).Methods("POST")
	r.HandleFunc("/intel/config/toggle", handler.APIToggleIntelEnabled).Methods("POST")
	r.HandleFunc("/intel/config/test-connection", handler.APITestIntelConnection).Methods("POST")
	r.HandleFunc("/intel/license", handler.APIValidateIntelLicense).Methods("GET")
	r.HandleFunc("/intel/data-types", handler.APIGetIntelDataTypes).Methods("GET")
	r.HandleFunc("/intel/credits", handler.APIGetIntelCredits).Methods("GET")
	r.HandleFunc("/intel/mask", handler.APIGetIntelMaskConfig).Methods("GET")
	r.HandleFunc("/intel/mask", handler.APIUpdateIntelMaskConfig).Methods("POST")

	r.HandleFunc("/intel/sync/status", handler.APIGetIntelSyncStatus).Methods("GET")
	r.HandleFunc("/intel/sync/logs", handler.APIGetIntelSyncLogs).Methods("GET")
	r.HandleFunc("/intel/sync/trigger", handler.APITriggerIntelSync).Methods("POST")

	r.HandleFunc("/intel/upload/queue", handler.APIGetIntelUploadQueue).Methods("GET")
	r.HandleFunc("/intel/upload/approve", handler.APIApproveIntelUpload).Methods("POST")
	r.HandleFunc("/intel/upload/reject", handler.APIRejectIntelUpload).Methods("POST")
	r.HandleFunc("/intel/upload/batch-approve", handler.APIBatchApproveIntelUpload).Methods("POST")
	r.HandleFunc("/intel/upload/logs", handler.APIGetIntelUploadLogs).Methods("GET")

	r.HandleFunc("/intel/overrides", handler.APIGetIntelOverrides).Methods("GET")
	r.HandleFunc("/intel/overrides/add", handler.APIAddIntelOverride).Methods("POST")
	r.HandleFunc("/intel/overrides/delete", handler.APIDeleteIntelOverride).Methods("POST")

	r.HandleFunc("/intel/exclusions", handler.APIGetIntelExclusions).Methods("GET")
	r.HandleFunc("/intel/exclusions/add", handler.APIAddIntelExclusion).Methods("POST")
	r.HandleFunc("/intel/exclusions/delete", handler.APIDeleteIntelExclusion).Methods("POST")

	r.HandleFunc("/intel/snapshots", handler.APIGetIntelSnapshots).Methods("GET")
	r.HandleFunc("/intel/snapshots/create", handler.APICreateIntelSnapshot).Methods("POST")

	r.HandleFunc("/intel/emergency", handler.APIGetIntelEmergencyRules).Methods("GET")
	r.HandleFunc("/intel/false-positive", handler.APIAddIntelFalsePositive).Methods("POST")
	r.HandleFunc("/intel/connection-logs", handler.APIGetIntelConnectionLogs).Methods("GET")

	r.HandleFunc("/intel/rules/ip/disable", handler.APIDisableIntelIPRule).Methods("POST")
	r.HandleFunc("/intel/rules/ua/disable", handler.APIDisableIntelUARule).Methods("POST")
	r.HandleFunc("/intel/rules/path/disable", handler.APIDisableIntelPathRule).Methods("POST")
}
