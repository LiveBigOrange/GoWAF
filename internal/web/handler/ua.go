package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"gowaf/internal/web/templates"
)

func UAPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			jsonError(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		action := r.FormValue("action")

		if action == "delete" {
			ruleType := r.FormValue("type")
			pattern := r.FormValue("ua")

			if pattern == "" {
				jsonError(w, "Pattern is required", http.StatusBadRequest)
				return
			}

			if !requireManager(w, deps.RuleEngine, "规则引擎") {
				return
			}

			err := deps.RuleEngine.RemoveUARule(ruleType, pattern)
			if err != nil {
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			jsonSuccess(w, nil)
			return
		}

		ruleType := r.FormValue("rule_type")
		matchType := r.FormValue("match_type")
		pattern := r.FormValue("pattern")
		description := r.FormValue("description")

		if pattern != "" {
			if !requireManager(w, deps.RuleEngine, "规则引擎") {
				return
			}

			err := deps.RuleEngine.AddUARule(ruleType, matchType, pattern, description)
			if err != nil {
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		jsonSuccess(w, nil)
		return
	}

	renderPage(w, r, templates.UATmpl, "ua", "ua")
}

func UAUpdateAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          int    `json:"id"`
		RuleType    string `json:"rule_type"`
		MatchType   string `json:"match_type"`
		Pattern     string `json:"pattern"`
		Description string `json:"description"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	if err := deps.RuleEngine.UpdateUARule(req.ID, req.RuleType, req.MatchType, req.Pattern, req.Description, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func UAToggleAPI(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	if id == 0 {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	if err := deps.RuleEngine.ToggleUARule(id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func UADeleteAPI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RuleType string `json:"rule_type"`
		Pattern  string `json:"pattern"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Pattern == "" {
		jsonError(w, "pattern is required", http.StatusBadRequest)
		return
	}
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	if err := deps.RuleEngine.RemoveUARule(req.RuleType, req.Pattern); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}
