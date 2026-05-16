package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"gowaf/internal/backend"
	"gowaf/internal/domain/gateway/templates"
)

var validBackendSchemes = map[string]bool{
	"http":  true,
	"https": true,
	"ws":    true,
	"wss":   true,
}

func validateBackendScheme(scheme string) error {
	if scheme == "" {
		return nil
	}
	parts := strings.Split(scheme, ",")
	var protos []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !validBackendSchemes[p] {
			return fmt.Errorf("不支持的后端协议: %s（可选: http, https, ws, wss）", p)
		}
		protos = append(protos, p)
	}
	if len(protos) == 0 {
		return nil
	}
	hasHTTP := false
	hasHTTPS := false
	hasWS := false
	hasWSS := false
	for _, p := range protos {
		switch p {
		case "http":
			hasHTTP = true
		case "https":
			hasHTTPS = true
		case "ws":
			hasWS = true
		case "wss":
			hasWSS = true
		}
	}
	if hasHTTP && hasHTTPS {
		return fmt.Errorf("HTTP和HTTPS不能同时选择")
	}
	if hasWS && hasWSS {
		return fmt.Errorf("WS和WSS不能同时选择")
	}
	if hasHTTP && hasWSS {
		return fmt.Errorf("HTTP和WSS不匹配（HTTP应搭配WS，HTTPS应搭配WSS）")
	}
	if hasHTTPS && hasWS {
		return fmt.Errorf("HTTPS和WS不匹配（HTTP应搭配WS，HTTPS应搭配WSS）")
	}
	if hasWS && !hasHTTP {
		return fmt.Errorf("WS必须搭配HTTP")
	}
	if hasWSS && !hasHTTPS {
		return fmt.Errorf("WSS必须搭配HTTPS")
	}
	return nil
}

func BackendPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.BackendTmpl, "backend", "backend")
}

// APIBackendList 获取后端列表
func APIBackendList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	backends := deps.BackendManager.GetBackends()
	jsonSuccess(w, backends)
}

// APIBackendAdd 添加后端
func APIBackendAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req backend.Backend
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if err := validateBackendScheme(req.Scheme); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := deps.BackendManager.AddBackend(&req); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "UNIQUE constraint failed") && strings.Contains(errMsg, "idx_backends_addr_scheme") {
			errMsg = "该后端地址+协议组合已存在，请修改地址或协议"
		} else if strings.Contains(errMsg, "UNIQUE constraint failed") && strings.Contains(errMsg, "backends.address") {
			errMsg = "该后端地址已存在，请使用不同的地址"
		}
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}

	jsonSuccess(w, map[string]interface{}{"id": req.ID, "address": req.Address})
}

// APIBackendUpdate 更新后端
func APIBackendUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req backend.Backend
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}

	if err := validateBackendScheme(req.Scheme); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := deps.BackendManager.UpdateBackend(&req); err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "UNIQUE constraint failed") && strings.Contains(errMsg, "idx_backends_addr_scheme") {
			errMsg = "该后端地址+协议组合已被其他后端使用"
		} else if strings.Contains(errMsg, "UNIQUE constraint failed") && strings.Contains(errMsg, "backends.address") {
			errMsg = "该后端地址已被其他服务使用，请使用不同的地址"
		}
		jsonError(w, errMsg, http.StatusBadRequest)
		return
	}

	jsonSuccess(w, nil)
}

// APIBackendDelete 删除后端
func APIBackendDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		jsonError(w, "缺少ID参数", http.StatusBadRequest)
		return
	}

	if err := deps.BackendManager.RemoveBackend(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonSuccess(w, nil)
}

// APIBackendLBPolicy 获取负载均衡策略（全局，已废弃，请使用组级策略）
func APIBackendLBPolicy(w http.ResponseWriter, r *http.Request) {
	jsonSuccess(w, map[string]interface{}{
		"policy":    string(backend.GetLBPolicy()),
		"available": []string{"round_robin", "weighted_round_robin", "least_connections", "ip_hash", "url_hash", "random"},
	})
}

// APIBackendSetLBPolicy 设置负载均衡策略（全局，已废弃，请使用组级策略）
func APIBackendSetLBPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Policy string `json:"policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	policy := backend.LBPolicy(req.Policy)
	switch policy {
	case backend.LBRoundRobin, backend.LBWeightedRR, backend.LBLeastConns, backend.LBIPHash, backend.LBURLHash, backend.LBRandom:
		backend.SetLBPolicy(policy)
		jsonSuccess(w, nil)
	default:
		jsonError(w, "无效的策略，可选: round_robin, weighted_round_robin, least_connections, ip_hash, url_hash, random", http.StatusBadRequest)
	}
}

// ========== 后端组管理 API ==========

func APIBackendGroupList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	groups := deps.BackendManager.GetGroups()
	jsonSuccess(w, groups)
}

func APIBackendGroupAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req struct {
		Name     string `json:"name"`
		LbPolicy string `json:"lb_policy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "组名称不能为空", http.StatusBadRequest)
		return
	}

	g, err := deps.BackendManager.AddGroup(req.Name, req.LbPolicy)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, g)
}

func APIBackendGroupUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		LbPolicy string `json:"lb_policy"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.Enabled != nil {
		if err := deps.BackendManager.SetGroupEnabled(req.ID, *req.Enabled); err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		jsonSuccess(w, nil)
		return
	}
	if err := deps.BackendManager.UpdateGroup(req.ID, req.Name, req.LbPolicy); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBackendGroupDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		jsonError(w, "缺少ID参数", http.StatusBadRequest)
		return
	}
	if err := deps.BackendManager.DeleteGroup(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 清除引用该组的域名配置
	if deps.ProxyConfigManager != nil {
		domains, _ := deps.ProxyConfigManager.ListDomains()
		for _, d := range domains {
			if d.GroupID == req.ID {
				_ = deps.ProxyConfigManager.SetDomainGroupID(d.ID, "")
			}
		}
	}
	jsonSuccess(w, nil)
}

func APIBackendGroupMembers(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		jsonError(w, "缺少组ID参数", http.StatusBadRequest)
		return
	}
	members := deps.BackendManager.GetGroupMembersFull(id)
	jsonSuccess(w, members)
}

func APIBackendGroupMemberAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req struct {
		GroupID   string `json:"group_id"`
		BackendID string `json:"backend_id"`
		Weight    int    `json:"weight"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.GroupID == "" || req.BackendID == "" {
		jsonError(w, "缺少必要参数", http.StatusBadRequest)
		return
	}
	if err := deps.BackendManager.AddGroupMember(req.GroupID, req.BackendID, req.Weight); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBackendGroupMemberUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req struct {
		GroupID   string `json:"group_id"`
		BackendID string `json:"backend_id"`
		Weight    int    `json:"weight"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.GroupID == "" || req.BackendID == "" {
		jsonError(w, "缺少必要参数", http.StatusBadRequest)
		return
	}
	if err := deps.BackendManager.AddGroupMember(req.GroupID, req.BackendID, req.Weight); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBackendGroupMemberDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	var req struct {
		GroupID   string `json:"group_id"`
		BackendID string `json:"backend_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if req.GroupID == "" || req.BackendID == "" {
		jsonError(w, "缺少必要参数", http.StatusBadRequest)
		return
	}
	if err := deps.BackendManager.RemoveGroupMember(req.GroupID, req.BackendID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBackendGroupUsedIDs(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	ids := deps.BackendManager.GetGroupedBackendIDs()
	jsonSuccess(w, ids)
}

func APIBackendGroupMap(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BackendManager, "后端服务管理器") {
		return
	}
	data := deps.BackendManager.GetBackendGroupsMap()
	jsonSuccess(w, data)
}
