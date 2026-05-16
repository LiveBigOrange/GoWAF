package handler

import (
	"encoding/json"
	"net"
	"net/http"

	"gowaf/internal/domain/gateway/templates"
)

func RulesPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		err := r.ParseMultipartForm(10 << 20)
		if err != nil {
			jsonError(w, "Failed to parse form data", http.StatusBadRequest)
			return
		}

		action := r.FormValue("action")

		if action == "delete" {
			ruleType := r.FormValue("type")
			ip := r.FormValue("ip")

			if ip == "" {
				jsonError(w, "IP address is required", http.StatusBadRequest)
				return
			}

			if !requireManager(w, deps.RuleEngine, "规则引擎") {
				return
			}

			if ruleType == "" {
				ruleType = "blacklist"
			}

			err := deps.RuleEngine.RemoveIPRule(ruleType, ip)
			if err != nil {
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			jsonSuccess(w, nil)
			return
		}

		ruleType := r.FormValue("rule_type")
		ip := r.FormValue("ip")

		if ip != "" {
			if !requireManager(w, deps.RuleEngine, "规则引擎") {
				return
			}

			if ruleType == "" {
				ruleType = "blacklist"
			}

			err := deps.RuleEngine.AddIPRule(ruleType, ip)
			if err != nil {
				jsonError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		jsonSuccess(w, nil)
		return
	}

	renderPage(w, r, templates.RulesTmpl, "rules", "rules")
}

func APIAddIPRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		jsonError(w, "ip is required", http.StatusBadRequest)
		return
	}
	if !isValidIPOrCIDR(req.IP) {
		jsonError(w, "ip format invalid, must be valid IP or CIDR", http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		req.Type = "blacklist"
	}
	if req.Type != "blacklist" && req.Type != "whitelist" {
		jsonError(w, "type must be blacklist or whitelist", http.StatusBadRequest)
		return
	}
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	if err := deps.RuleEngine.AddIPRule(req.Type, req.IP); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIToggleIPRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type    string `json:"type"`
		IP      string `json:"ip"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		jsonError(w, "ip is required", http.StatusBadRequest)
		return
	}
	if !isValidIPOrCIDR(req.IP) {
		jsonError(w, "ip format invalid", http.StatusBadRequest)
		return
	}
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	if err := deps.RuleEngine.SetIPRuleEnabled(req.Type, req.IP, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func APIRemoveIPRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type string `json:"type"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		jsonError(w, "ip is required", http.StatusBadRequest)
		return
	}
	if !isValidIPOrCIDR(req.IP) {
		jsonError(w, "ip format invalid", http.StatusBadRequest)
		return
	}
	if !requireManager(w, deps.RuleEngine, "规则引擎") {
		return
	}
	if req.Type == "" {
		req.Type = "blacklist"
	}
	if err := deps.RuleEngine.RemoveIPRule(req.Type, req.IP); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func isValidIPOrCIDR(ip string) bool {
	if len(ip) > 256 {
		return false
	}
	if net.ParseIP(ip) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(ip)
	return err == nil
}
