package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func APIGeoLookup(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "缺少ip参数"})
		return
	}
	if MetricsManager == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "metrics未初始化"})
		return
	}
	geo := MetricsManager.GetGeoLocation(ip)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": geo})
}

func APIGeoRulesList(w http.ResponseWriter, r *http.Request) {
	geoRules, err := RuleEngine.ListGeoRules()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": geoRules})
}

func APIGeoRuleAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode        string `json:"mode"`
		CountryCode string `json:"country_code"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求数据"})
		return
	}
	if req.CountryCode == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "国家代码不能为空"})
		return
	}
	if req.Mode == "" {
		req.Mode = "blacklist"
	}
	if err := RuleEngine.AddGeoRule(req.Mode, req.CountryCode, req.Enabled); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func APIGeoRuleUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          int    `json:"id"`
		Mode        string `json:"mode"`
		CountryCode string `json:"country_code"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求数据"})
		return
	}
	if err := RuleEngine.UpdateGeoRule(req.ID, req.Mode, req.CountryCode, req.Enabled); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func APIGeoRuleDelete(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的ID"})
		return
	}
	if err := RuleEngine.RemoveGeoRule(id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func APIAllowedMethodsList(w http.ResponseWriter, r *http.Request) {
	methods, err := RuleEngine.ListAllowedMethods()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": methods})
}

func APIAllowedMethodSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method  string `json:"method"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求数据"})
		return
	}
	if req.Method == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "HTTP方法不能为空"})
		return
	}
	if err := RuleEngine.SetAllowedMethodDB(req.Method, req.Enabled); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func APIAllowedMethodDelete(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Query().Get("method")
	if method == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "缺少method参数"})
		return
	}
	if err := RuleEngine.RemoveAllowedMethodDB(method); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func APIPathRateLimitsList(w http.ResponseWriter, r *http.Request) {
	limits, err := RuleEngine.ListPathRateLimits()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "data": limits})
}

func APIPathRateLimitAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PathPattern string  `json:"path_pattern"`
		Rate        float64 `json:"rate"`
		Burst       int     `json:"burst"`
		Enabled     bool    `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求数据"})
		return
	}
	if req.PathPattern == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "路径模式不能为空"})
		return
	}
	if req.Rate <= 0 {
		req.Rate = 10
	}
	if req.Burst <= 0 {
		req.Burst = 20
	}
	if err := RuleEngine.AddPathRateLimit(req.PathPattern, req.Rate, req.Burst, req.Enabled); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func APIPathRateLimitUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          int     `json:"id"`
		PathPattern string  `json:"path_pattern"`
		Rate        float64 `json:"rate"`
		Burst       int     `json:"burst"`
		Enabled     bool    `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的请求数据"})
		return
	}
	if err := RuleEngine.UpdatePathRateLimit(req.ID, req.PathPattern, req.Rate, req.Burst, req.Enabled); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func APIPathRateLimitDelete(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "无效的ID"})
		return
	}
	if err := RuleEngine.RemovePathRateLimit(id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}
