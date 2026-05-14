package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/vpatch"
	"gowaf/internal/web/templates"
)

func VPatchPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.VPatchTmpl, "vpatch", "vpatch")
}

func APIVPatchList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.VPatchManager, "虚拟补丁管理器") {
		return
	}
	patches, err := deps.VPatchManager.ListPatches()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, patches)
}

func APIVPatchAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.VPatchManager, "虚拟补丁管理器") {
		return
	}
	var p vpatch.Patch
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.VPatchManager.AddPatch(p); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIVPatchDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.VPatchManager, "虚拟补丁管理器") {
		return
	}
	var req struct {
		CVEID string `json:"cve_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.VPatchManager.DeletePatch(req.CVEID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIVPatchToggle(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.VPatchManager, "虚拟补丁管理器") {
		return
	}
	var req struct {
		CVEID   string `json:"cve_id"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.VPatchManager.TogglePatch(req.CVEID, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}
