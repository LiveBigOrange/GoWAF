package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/domain/gateway/templates"
)

func DLPPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.DLPTmpl, "dlp", "dlp")
}

func APIDLPList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DLPRuleManager, "DLP规则管理器") {
		return
	}
	rules, err := deps.DLPRuleManager.ListRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, rules)
}

func APIDLPAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DLPRuleManager, "DLP规则管理器") {
		return
	}
	var req struct {
		Name     string `json:"name"`
		Pattern  string `json:"pattern"`
		Action   string `json:"action"`
		Category string `json:"category"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.DLPRuleManager.AddRule(req.Name, req.Pattern, req.Action, req.Category, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIDLPUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DLPRuleManager, "DLP规则管理器") {
		return
	}
	var req struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Pattern  string `json:"pattern"`
		Action   string `json:"action"`
		Category string `json:"category"`
		Enabled  bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.DLPRuleManager.UpdateRule(req.ID, req.Name, req.Pattern, req.Action, req.Category, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIDLPDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DLPRuleManager, "DLP规则管理器") {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.DLPRuleManager.DeleteRule(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIAPIDlpToggle(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.DLPRuleManager, "DLP规则管理器") {
		return
	}
	var req struct {
		ID      int  `json:"id"`
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.DLPRuleManager.ToggleEnabled(req.ID, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}
