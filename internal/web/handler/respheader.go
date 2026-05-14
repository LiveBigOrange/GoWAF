package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/web/templates"
)

func RespHeaderPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.RespHeaderTmpl, "respheader", "respheader")
}

func APIRespHeaderList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RespHeaderManager, "响应头管理器") {
		return
	}
	rules, err := deps.RespHeaderManager.ListRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, rules)
}

func APIRespHeaderAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RespHeaderManager, "响应头管理器") {
		return
	}
	var req struct {
		Domain    string `json:"domain"`
		PathRegex string `json:"path_regex"`
		Header    string `json:"header"`
		Value     string `json:"value"`
		Enabled   bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.RespHeaderManager.AddRule(req.Domain, req.PathRegex, req.Header, req.Value, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIRespHeaderUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RespHeaderManager, "响应头管理器") {
		return
	}
	var req struct {
		ID        int    `json:"id"`
		Domain    string `json:"domain"`
		PathRegex string `json:"path_regex"`
		Header    string `json:"header"`
		Value     string `json:"value"`
		Enabled   bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.RespHeaderManager.UpdateRule(req.ID, req.Domain, req.PathRegex, req.Header, req.Value, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIRespHeaderDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RespHeaderManager, "响应头管理器") {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.RespHeaderManager.DeleteRule(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIRespHeaderToggle(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.RespHeaderManager, "响应头管理器") {
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
	if err := deps.RespHeaderManager.ToggleEnabled(req.ID, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}
