package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/domain/gateway/templates"
)

func APISchemaPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.APISchemaTmpl, "apischema", "apischema")
}

func APIAPISchemaList(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.APISchemaManager, "API Schema管理器") {
		return
	}
	schemas, err := deps.APISchemaManager.ListSchemas()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, schemas)
}

func APIAPISchemaAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.APISchemaManager, "API Schema管理器") {
		return
	}
	var req struct {
		Name    string `json:"name"`
		Spec    string `json:"spec"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.APISchemaManager.AddSchema(req.Name, req.Spec, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIAPISchemaDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.APISchemaManager, "API Schema管理器") {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.APISchemaManager.DeleteSchema(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIAPISchemaUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.APISchemaManager, "API Schema管理器") {
		return
	}
	var req struct {
		ID      int    `json:"id"`
		Name    string `json:"name"`
		Spec    string `json:"spec"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.APISchemaManager.UpdateSchema(req.ID, req.Name, req.Spec, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIAPISchemaToggle(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.APISchemaManager, "API Schema管理器") {
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
	if err := deps.APISchemaManager.ToggleEnabled(req.ID, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIAPISchemaValidate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.APISchemaManager, "API Schema管理器") {
		return
	}
	var req struct {
		Method string `json:"method"`
		Path   string `json:"path"`
		Body   string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	result, err := deps.APISchemaManager.ValidateRequest(req.Method, req.Path, []byte(req.Body))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, result)
}
