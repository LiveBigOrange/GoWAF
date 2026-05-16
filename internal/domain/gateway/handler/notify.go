package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/infra/notify"

	"github.com/google/uuid"
)

func GetAlertRules(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.NotifyEngine, "通知引擎") {
		return
	}
	rules := deps.NotifyEngine.GetRules()
	if rules == nil {
		rules = []notify.AlertRule{}
	}
	jsonSuccess(w, rules)
}

func UpdateAlertRule(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.NotifyEngine, "通知引擎") {
		return
	}
	var rule notify.AlertRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	if rule.MatchType == "" {
		rule.MatchType = "attack_type"
	}
	if rule.Level == "" {
		rule.Level = notify.AlertWarning
	}
	if rule.NotifyType == "" {
		rule.NotifyType = notify.NotifyDingTalk
	}
	if rule.CooldownSec <= 0 {
		rule.CooldownSec = 300
	}
	if rule.WindowSecs <= 0 {
		rule.WindowSecs = 60
	}
	if rule.Threshold <= 0 {
		rule.Threshold = 1
	}
	if err := deps.NotifyEngine.SaveRule(rule); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func DeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.NotifyEngine, "通知引擎") {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.ID == "" {
		jsonError(w, "id is required", http.StatusBadRequest)
		return
	}
	if err := deps.NotifyEngine.DeleteRule(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func GetNotifyConfig(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.NotifyEngine, "通知引擎") {
		return
	}
	cfg := deps.NotifyEngine.GetConfig()
	if cfg.EmailPassword != "" {
		cfg.EmailPassword = "******"
	}
	jsonSuccess(w, cfg)
}

func UpdateNotifyConfig(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.NotifyEngine, "通知引擎") {
		return
	}
	var cfg notify.NotificationConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if cfg.EmailPassword == "******" {
		cfg.EmailPassword = deps.NotifyEngine.GetConfig().EmailPassword
	}
	if err := deps.NotifyEngine.SaveConfig(cfg); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, nil)
}

func TestNotify(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.NotifyEngine, "通知引擎") {
		return
	}
	var req struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Type == "" {
		jsonError(w, "type is required", http.StatusBadRequest)
		return
	}
	if err := deps.NotifyEngine.TestNotify(notify.NotifyType(req.Type)); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}
