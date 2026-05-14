package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func APIGeoLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		jsonError(w, "缺少ip参数", http.StatusBadRequest)
		return
	}
	if !requireManager(w, deps.MetricsManager, "指标管理器") {
		return
	}
	geo := deps.MetricsManager.GetGeoLocation(ip)
	jsonSuccess(w, geo)
}

func APIGeoRulesList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	geoRules, err := deps.RuleEngine.ListGeoRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, geoRules)
}

func APIGeoRuleAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	var req struct {
		Mode        string `json:"mode"`
		CountryCode string `json:"country_code"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.CountryCode == "" {
		jsonError(w, "国家代码不能为空", http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = "blacklist"
	}
	if err := deps.RuleEngine.AddGeoRule(req.Mode, req.CountryCode, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIGeoRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	var req struct {
		ID          int    `json:"id"`
		Mode        string `json:"mode"`
		CountryCode string `json:"country_code"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.RuleEngine.UpdateGeoRule(req.ID, req.Mode, req.CountryCode, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIGeoRuleDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "无效的ID", http.StatusBadRequest)
		return
	}
	if err := deps.RuleEngine.RemoveGeoRule(id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIAllowedMethodsList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	methods, err := deps.RuleEngine.ListAllowedMethods()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, methods)
}

func APIAllowedMethodSet(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	var req struct {
		Method  string `json:"method"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.Method == "" {
		jsonError(w, "HTTP方法不能为空", http.StatusBadRequest)
		return
	}
	if err := deps.RuleEngine.SetAllowedMethodDB(req.Method, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIAllowedMethodDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	method := r.URL.Query().Get("method")
	if method == "" {
		jsonError(w, "缺少method参数", http.StatusBadRequest)
		return
	}
	if err := deps.RuleEngine.RemoveAllowedMethodDB(method); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIPathRateLimitsList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	limits, err := deps.RuleEngine.ListPathRateLimits()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, limits)
}

func APIPathRateLimitAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	var req struct {
		PathPattern string  `json:"path_pattern"`
		Rate        float64 `json:"rate"`
		Burst       int     `json:"burst"`
		Enabled     bool    `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.PathPattern == "" {
		jsonError(w, "路径模式不能为空", http.StatusBadRequest)
		return
	}
	if req.Rate <= 0 {
		req.Rate = 10
	}
	if req.Burst <= 0 {
		req.Burst = 20
	}
	if err := deps.RuleEngine.AddPathRateLimit(req.PathPattern, req.Rate, req.Burst, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIPathRateLimitUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	var req struct {
		ID          int     `json:"id"`
		PathPattern string  `json:"path_pattern"`
		Rate        float64 `json:"rate"`
		Burst       int     `json:"burst"`
		Enabled     bool    `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.RuleEngine.UpdatePathRateLimit(req.ID, req.PathPattern, req.Rate, req.Burst, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIPathRateLimitDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "无效的ID", http.StatusBadRequest)
		return
	}
	if err := deps.RuleEngine.RemovePathRateLimit(id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}
