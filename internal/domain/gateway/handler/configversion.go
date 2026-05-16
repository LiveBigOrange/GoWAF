package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"

	"gowaf/internal/infra/logger"
)

func APIConfigVersionList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ConfigVersionManager, "配置版本管理器") {
		return
	}
	limit := 20
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	versions, total, err := deps.ConfigVersionManager.ListVersions(limit, offset)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccessPaged(w, versions, int64(total), offset/limit+1, limit)
}

func APIConfigVersionGet(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ConfigVersionManager, "配置版本管理器") {
		return
	}
	idStr := r.URL.Query().Get("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		jsonError(w, "无效的版本ID", http.StatusBadRequest)
		return
	}
	v, err := deps.ConfigVersionManager.GetVersion(id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}
	jsonSuccess(w, v)
}

func APIConfigVersionRestore(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ConfigVersionManager, "配置版本管理器") {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.ConfigVersionManager.RestoreVersion(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// O4: 审计日志 - 记录配置恢复操作及操作者IP
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	logger.Info("[审计] 配置版本恢复: version_id=%d, operator_ip=%s", req.ID, ip)
	jsonSuccess(w, nil)
}

func APIConfigVersionDiff(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ConfigVersionManager, "配置版本管理器") {
		return
	}
	id1Str := r.URL.Query().Get("id1")
	id2Str := r.URL.Query().Get("id2")
	id1, err := strconv.Atoi(id1Str)
	if err != nil {
		jsonError(w, "无效的版本ID1", http.StatusBadRequest)
		return
	}
	id2, err := strconv.Atoi(id2Str)
	if err != nil {
		jsonError(w, "无效的版本ID2", http.StatusBadRequest)
		return
	}
	diff, err := deps.ConfigVersionManager.DiffVersions(id1, id2)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, map[string]string{"diff": diff})
}

func APIConfigVersionCreate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ConfigVersionManager, "配置版本管理器") {
		return
	}
	var req struct {
		Description string `json:"description"`
		Auto        bool   `json:"auto"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.ConfigVersionManager.CreateSnapshot(req.Description, req.Auto); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}
