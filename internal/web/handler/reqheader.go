package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/reqheader"
)

func APIReqHeaderList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ReqHeaderManager, "请求头管理器") {
		return
	}
	rules, err := deps.ReqHeaderManager.ListRules()
	if err != nil {
		jsonError(w, "获取规则列表失败", http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []reqheader.HeaderRule{}
	}
	jsonSuccess(w, rules)
}

func APIReqHeaderAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ReqHeaderManager, "请求头管理器") {
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
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if req.Header == "" {
		jsonError(w, "请求头名称不能为空", http.StatusBadRequest)
		return
	}
	if err := deps.ReqHeaderManager.AddRule(req.Domain, req.PathRegex, req.Header, req.Value, req.Enabled); err != nil {
		jsonError(w, "添加规则失败", http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIReqHeaderUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ReqHeaderManager, "请求头管理器") {
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
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if err := deps.ReqHeaderManager.UpdateRule(req.ID, req.Domain, req.PathRegex, req.Header, req.Value, req.Enabled); err != nil {
		jsonError(w, "更新规则失败", http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIReqHeaderDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ReqHeaderManager, "请求头管理器") {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if err := deps.ReqHeaderManager.DeleteRule(req.ID); err != nil {
		jsonError(w, "删除规则失败", http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIReqHeaderToggle(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ReqHeaderManager, "请求头管理器") {
		return
	}
	var req struct {
		ID      int  `json:"id"`
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "解析请求失败", http.StatusBadRequest)
		return
	}
	if err := deps.ReqHeaderManager.ToggleRule(req.ID, req.Enabled); err != nil {
		jsonError(w, "切换规则状态失败", http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}
