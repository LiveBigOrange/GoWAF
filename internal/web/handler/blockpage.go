package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/blockpage"
	"gowaf/internal/web/templates"
)

func BlockPagePage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.BlockPageTmpl, "blockpage", "blockpage")
}

func GetBlockPageConfigs(w http.ResponseWriter, r *http.Request) {
	configs := blockpage.GetConfigs()
	jsonSuccess(w, configs)
}

func UpdateBlockPageConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason        string `json:"reason"`
		ResponseType  string `json:"response_type"`
		StatusCode    *int   `json:"status_code"`
		HTMLTemplate  string `json:"html_template"`
		JSONTemplate  string `json:"json_template"`
		RedirectURL   string `json:"redirect_url"`
		DefaultReason string `json:"default_reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request data", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	configs := blockpage.GetConfigs()
	existing, ok := configs[req.Reason]
	if !ok {
		// 允许创建新类型（自定义拦截类型）
		existing = blockpage.BlockPageConfig{
			ResponseType:  "html",
			StatusCode:    403,
			DefaultReason: req.Reason,
		}
	}

	if req.ResponseType != "" {
		existing.ResponseType = req.ResponseType
	}
	if req.StatusCode != nil {
		existing.StatusCode = *req.StatusCode
	}
	if req.HTMLTemplate != "" {
		existing.HTMLTemplate = req.HTMLTemplate
	}
	if req.JSONTemplate != "" {
		existing.JSONTemplate = req.JSONTemplate
	}
	if req.RedirectURL != "" {
		existing.RedirectURL = req.RedirectURL
	}
	if req.DefaultReason != "" {
		existing.DefaultReason = req.DefaultReason
	}

	blockpage.UpdateConfig(req.Reason, existing)

	jsonSuccess(w, nil)
}

func CreateBlockPageConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason        string `json:"reason"`
		ResponseType  string `json:"response_type"`
		StatusCode    int    `json:"status_code"`
		HTMLTemplate  string `json:"html_template"`
		JSONTemplate  string `json:"json_template"`
		RedirectURL   string `json:"redirect_url"`
		DefaultReason string `json:"default_reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request data", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	configs := blockpage.GetConfigs()
	if _, exists := configs[req.Reason]; exists {
		jsonError(w, "reason already exists, use update instead", http.StatusConflict)
		return
	}

	cfg := blockpage.BlockPageConfig{
		ResponseType:  "html",
		StatusCode:    403,
		DefaultReason: req.Reason,
	}
	if req.ResponseType != "" {
		cfg.ResponseType = req.ResponseType
	}
	if req.StatusCode > 0 {
		cfg.StatusCode = req.StatusCode
	}
	if req.DefaultReason != "" {
		cfg.DefaultReason = req.DefaultReason
	}
	if req.HTMLTemplate != "" {
		cfg.HTMLTemplate = req.HTMLTemplate
	}
	if req.JSONTemplate != "" {
		cfg.JSONTemplate = req.JSONTemplate
	}
	if req.RedirectURL != "" {
		cfg.RedirectURL = req.RedirectURL
	}

	blockpage.UpdateConfig(req.Reason, cfg)

	jsonSuccess(w, nil)
}

func DeleteBlockPageConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "Invalid request data", http.StatusBadRequest)
		return
	}
	if req.Reason == "" {
		jsonError(w, "reason is required", http.StatusBadRequest)
		return
	}

	if err := blockpage.DeleteConfig(req.Reason); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonSuccess(w, nil)
}
