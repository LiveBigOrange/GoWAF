package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/domain/security/bot"
	"gowaf/internal/domain/gateway/templates"
)

func BotPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.BotTmpl, "bot", "bot")
}

func APIBotClassify(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	ua := r.URL.Query().Get("ua")
	cookies := r.URL.Query().Get("cookies") == "1"
	referer := r.URL.Query().Get("referer") == "1"
	acceptLang := r.URL.Query().Get("accept_lang") == "1"
	result := deps.BotManager.Classify(ua, cookies, referer, acceptLang)
	jsonSuccess(w, result)
}

func APIBotRules(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	rules, err := deps.BotManager.ListRules()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []bot.BotRule{}
	}
	jsonSuccess(w, rules)
}

func APIBotRuleAdd(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Category    string `json:"category"`
		UAPattern   string `json:"ua_pattern"`
		Whitelisted bool   `json:"whitelisted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.AddRule(req.Name, req.Category, req.UAPattern, req.Whitelisted); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotRuleUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Category    string `json:"category"`
		UAPattern   string `json:"ua_pattern"`
		Whitelisted bool   `json:"whitelisted"`
		Enabled     bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.UpdateRule(req.ID, req.Name, req.Category, req.UAPattern, req.Whitelisted, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotRuleDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.DeleteRuleByID(req.ID); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotRuleToggle(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		ID          int  `json:"id"`
		Whitelisted bool `json:"whitelisted"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.UpdateWhitelistedByID(req.ID, req.Whitelisted); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotRuleToggleEnabled(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
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
	if err := deps.BotManager.ToggleEnabled(req.ID, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotBatchDelete(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		IDs []int `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.BatchDelete(req.IDs); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotBatchToggleEnabled(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		IDs     []int `json:"ids"`
		Enabled bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.BatchToggleEnabled(req.IDs, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotKnownBots(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	bots := deps.BotManager.ListKnownBots()
	jsonSuccess(w, bots)
}

func APIBotKnownBotOverride(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Whitelisted *bool  `json:"whitelisted"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.UpdateKnownBotOverride(req.Name, req.Whitelisted, req.Enabled); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotPolicies(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	policies := deps.BotManager.GetPolicies()
	jsonSuccess(w, policies)
}

func APIBotSetPolicy(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.BotManager, "Bot管理器") {
		return
	}
	var req struct {
		Category string `json:"category"`
		Action   string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.BotManager.SetPolicy(bot.BotCategory(req.Category), bot.PolicyAction(req.Action)); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}

func APIBotStats(w http.ResponseWriter, r *http.Request) {
	jsonSuccess(w, bot.GetStats())
}
