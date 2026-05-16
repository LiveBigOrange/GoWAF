package notify

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"gowaf/internal/infra/logger"
	"gowaf/internal/pkg/xutil"
)

func migrateAddColumn(db *sql.DB, table, column, definition string) {
	query := "ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition
	if _, err := db.Exec(query); err != nil {
		if !strings.Contains(err.Error(), "duplicate column name") {
			logger.Warn("migration: %s.%s %v", table, column, err)
		}
	}
}

type NotifyType string

const (
	NotifyDingTalk   NotifyType = "dingtalk"
	NotifyWeCom      NotifyType = "wecom"
	NotifySlack      NotifyType = "slack"
	NotifyEmail      NotifyType = "email"
	NotifyWebhook    NotifyType = "webhook"
	NotifyIntelAlert NotifyType = "intel_event"
)

type AlertLevel string

const (
	AlertInfo     AlertLevel = "info"
	AlertWarning  AlertLevel = "warning"
	AlertCritical AlertLevel = "critical"
)

type AlertRule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Enabled     bool       `json:"enabled"`
	Level       AlertLevel `json:"level"`
	MatchType   string     `json:"match_type"`
	MatchValue  string     `json:"match_value"`
	Threshold   int        `json:"threshold"`
	WindowSecs  int        `json:"window_secs"`
	NotifyType  NotifyType `json:"notify_type"`
	CooldownSec int        `json:"cooldown_secs"`
}

type NotificationConfig struct {
	DingTalkWebhook string `json:"dingtalk_webhook"`
	DingTalkEnabled bool   `json:"dingtalk_enabled"`
	WeComWebhook    string `json:"wecom_webhook"`
	WeComEnabled    bool   `json:"wecom_enabled"`
	SlackWebhook    string `json:"slack_webhook"`
	SlackEnabled    bool   `json:"slack_enabled"`
	EmailSMTPHost   string `json:"email_smtp_host"`
	EmailSMTPPort   int    `json:"email_smtp_port"`
	EmailFrom       string `json:"email_from"`
	EmailTo         string `json:"email_to"`
	EmailPassword   string `json:"email_password"`
	EmailEnabled    bool   `json:"email_enabled"`
	WebhookURL      string `json:"webhook_url"`
	WebhookSecret   string `json:"webhook_secret"`
	WebhookEnabled  bool   `json:"webhook_enabled"`
}

type Engine struct {
	mu         sync.RWMutex
	db         *sql.DB
	rules      []AlertRule
	config     NotificationConfig
	cooldowns  map[string]time.Time
	counters   map[string][]time.Time
	stopChan   chan struct{}
	httpClient *http.Client
}

func NewEngine(db *sql.DB) *Engine {
	e := &Engine{
		db:         db,
		cooldowns:  make(map[string]time.Time),
		counters:   make(map[string][]time.Time),
		stopChan:   make(chan struct{}),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	if db != nil {
		if err := e.initTables(); err != nil {
			logger.Warn("通知引擎建表失败: %v", err)
		}
		if err := e.loadConfig(); err != nil {
			logger.Warn("通知引擎加载配置失败: %v", err)
		}
		if err := e.loadRules(); err != nil {
			logger.Warn("通知引擎加载规则失败: %v", err)
		}
		go e.cleanupLoop()
	}
	return e
}

func (e *Engine) initTables() error {
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS notify_config (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		dingtalk_webhook TEXT DEFAULT '',
		dingtalk_enabled INTEGER DEFAULT 0,
		wecom_webhook TEXT DEFAULT '',
		wecom_enabled INTEGER DEFAULT 0,
		slack_webhook TEXT DEFAULT '',
		slack_enabled INTEGER DEFAULT 0,
		email_smtp_host TEXT DEFAULT '',
		email_smtp_port INTEGER DEFAULT 587,
		email_from TEXT DEFAULT '',
		email_to TEXT DEFAULT '',
		email_password TEXT DEFAULT '',
		email_enabled INTEGER DEFAULT 0,
		webhook_url TEXT DEFAULT '',
		webhook_secret TEXT DEFAULT '',
		webhook_enabled INTEGER DEFAULT 0
	)`); err != nil {
		return err
	}
	// migration: add enabled columns for existing databases
	var allowedNotifyMigrateColumns = map[string]bool{
		"dingtalk_enabled": true, "wecom_enabled": true, "slack_enabled": true,
		"email_enabled": true, "webhook_url": true, "webhook_secret": true, "webhook_enabled": true,
	}
	for _, col := range []string{"dingtalk_enabled", "wecom_enabled", "slack_enabled", "email_enabled", "webhook_url", "webhook_secret", "webhook_enabled"} {
		if !allowedNotifyMigrateColumns[col] {
			continue
		}
		migrateAddColumn(e.db, "notify_config", col, "INTEGER DEFAULT 0")
	}
	if _, err := e.db.Exec(`CREATE TABLE IF NOT EXISTS alert_rules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		enabled INTEGER DEFAULT 1,
		level TEXT DEFAULT 'warning',
		match_type TEXT NOT NULL,
		match_value TEXT NOT NULL,
		threshold INTEGER DEFAULT 1,
		window_secs INTEGER DEFAULT 60,
		notify_type TEXT DEFAULT 'dingtalk',
		cooldown_secs INTEGER DEFAULT 300
	)`); err != nil {
		return err
	}
	return nil
}

// EnsureTables 确保数据库表已初始化
func (e *Engine) EnsureTables() error {
	return e.initTables()
}

func (e *Engine) loadConfig() error {
	var c NotificationConfig
	var dingEnabled, wcEnabled, slEnabled, emEnabled, whEnabled int
	err := e.db.QueryRow(`SELECT dingtalk_webhook, wecom_webhook, slack_webhook,
		email_smtp_host, email_smtp_port, email_from, email_to, email_password,
		dingtalk_enabled, wecom_enabled, slack_enabled, email_enabled,
		COALESCE(webhook_url, ''), COALESCE(webhook_secret, ''), COALESCE(webhook_enabled, 0)
		FROM notify_config WHERE id=1`).Scan(
		&c.DingTalkWebhook, &c.WeComWebhook, &c.SlackWebhook,
		&c.EmailSMTPHost, &c.EmailSMTPPort, &c.EmailFrom, &c.EmailTo, &c.EmailPassword,
		&dingEnabled, &wcEnabled, &slEnabled, &emEnabled,
		&c.WebhookURL, &c.WebhookSecret, &whEnabled,
	)
	if err != nil {
		e.db.Exec(`INSERT INTO notify_config (id) VALUES (1)`)
		return nil
	}
	c.DingTalkEnabled = dingEnabled == 1
	c.WeComEnabled = wcEnabled == 1
	c.SlackEnabled = slEnabled == 1
	c.EmailEnabled = emEnabled == 1
	c.WebhookEnabled = whEnabled == 1
	// 尝试解密邮件密码，如果失败则保留原文并重新加密保存
	if c.EmailPassword != "" {
		decrypted, decErr := decryptPassword(c.EmailPassword)
		if decErr == nil {
			c.EmailPassword = decrypted
		} else {
			logger.Warn("邮件密码解密失败(可能是旧明文密码)，将重新加密保存: %v", decErr)
			encryptedPwd, encErr := encryptPassword(c.EmailPassword)
			if encErr == nil {
				e.db.Exec("UPDATE notify_config SET email_password=? WHERE id=1", encryptedPwd)
			}
		}
	}
	e.mu.Lock()
	e.config = c
	e.mu.Unlock()
	return nil
}

func (e *Engine) loadRules() error {
	rows, err := e.db.Query(`SELECT id, name, enabled, level, match_type, match_value,
		threshold, window_secs, notify_type, cooldown_secs FROM alert_rules`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var rules []AlertRule
	for rows.Next() {
		var r AlertRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &enabled, &r.Level, &r.MatchType, &r.MatchValue,
			&r.Threshold, &r.WindowSecs, &r.NotifyType, &r.CooldownSec); err != nil {
			logger.Warn("扫描告警规则失败: %v", err)
			continue
		}
		r.Enabled = enabled == 1
		rules = append(rules, r)
	}
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
	return nil
}

func (e *Engine) GetConfig() NotificationConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

func (e *Engine) SaveConfig(cfg NotificationConfig) error {
	if e.db == nil {
		return fmt.Errorf("database not initialized")
	}
	ding, wc, sl, em, wh := 0, 0, 0, 0, 0
	if cfg.DingTalkEnabled {
		ding = 1
	}
	if cfg.WeComEnabled {
		wc = 1
	}
	if cfg.SlackEnabled {
		sl = 1
	}
	if cfg.EmailEnabled {
		em = 1
	}
	if cfg.WebhookEnabled {
		wh = 1
	}
	encryptedPwd, err := encryptPassword(cfg.EmailPassword)
	if err != nil {
		logger.Warn("邮件密码加密失败，将明文存储: %v", err)
		encryptedPwd = cfg.EmailPassword
	}
	_, err = e.db.Exec(`INSERT OR REPLACE INTO notify_config (id, dingtalk_webhook, wecom_webhook, slack_webhook,
		email_smtp_host, email_smtp_port, email_from, email_to, email_password,
		dingtalk_enabled, wecom_enabled, slack_enabled, email_enabled,
		webhook_url, webhook_secret, webhook_enabled)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cfg.DingTalkWebhook, cfg.WeComWebhook, cfg.SlackWebhook,
		cfg.EmailSMTPHost, cfg.EmailSMTPPort, cfg.EmailFrom, cfg.EmailTo, encryptedPwd,
		ding, wc, sl, em, cfg.WebhookURL, cfg.WebhookSecret, wh)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.config = cfg
	e.mu.Unlock()
	return nil
}

func (e *Engine) GetRules() []AlertRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := make([]AlertRule, len(e.rules))
	copy(rules, e.rules)
	return rules
}

func (e *Engine) SaveRule(rule AlertRule) error {
	if e.db == nil {
		return fmt.Errorf("database not initialized")
	}
	enabled := 0
	if rule.Enabled {
		enabled = 1
	}
	_, err := e.db.Exec(`INSERT OR REPLACE INTO alert_rules
		(id, name, enabled, level, match_type, match_value,
		 threshold, window_secs, notify_type, cooldown_secs)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rule.ID, rule.Name, enabled, rule.Level, rule.MatchType, rule.MatchValue,
		rule.Threshold, rule.WindowSecs, rule.NotifyType, rule.CooldownSec)
	if err != nil {
		return err
	}
	e.loadRules()
	return nil
}

func (e *Engine) DeleteRule(id string) error {
	if e.db == nil {
		return fmt.Errorf("database not initialized")
	}
	_, err := e.db.Exec(`DELETE FROM alert_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	e.loadRules()
	return nil
}

func (e *Engine) SendAlert(level AlertLevel, title, message string) {
	cfg := e.GetConfig()
	var channels []NotifyType
	if cfg.DingTalkEnabled && cfg.DingTalkWebhook != "" {
		channels = append(channels, NotifyDingTalk)
	}
	if cfg.WeComEnabled && cfg.WeComWebhook != "" {
		channels = append(channels, NotifyWeCom)
	}
	if cfg.SlackEnabled && cfg.SlackWebhook != "" {
		channels = append(channels, NotifySlack)
	}
	if cfg.EmailEnabled && cfg.EmailSMTPHost != "" && cfg.EmailTo != "" {
		channels = append(channels, NotifyEmail)
	}
	if cfg.WebhookEnabled && cfg.WebhookURL != "" {
		channels = append(channels, NotifyWebhook)
	}
	for _, ch := range channels {
		e.SendToChannel(ch, level, title, message)
	}
}

var notifyEncryptKey []byte

func init() {
	keyStr := os.Getenv("GOWAF_NOTIFY_KEY")
	if keyStr != "" {
		keyBytes := []byte(keyStr)
		if len(keyBytes) == 16 || len(keyBytes) == 24 || len(keyBytes) == 32 {
			notifyEncryptKey = keyBytes
		} else {
			logger.Warn("GOWAF_NOTIFY_KEY长度不合法(需16/24/32字节)，使用默认密钥")
		}
	}
	if notifyEncryptKey == nil {
		randomKey := make([]byte, 16)
		if _, err := crypto_rand.Read(randomKey); err != nil {
			logger.Fatal("生成随机通知加密密钥失败: %v", err)
		}
		notifyEncryptKey = randomKey
		logger.Warn("邮件密码加密使用自动生成随机密钥，建议设置环境变量 GOWAF_NOTIFY_KEY 以便跨重启解密")
	}
}

func encryptPassword(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	block, err := aes.NewCipher(notifyEncryptKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(crypto_rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(ciphertext), nil
}

func decryptPassword(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	data, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(notifyEncryptKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (e *Engine) SendToChannel(channel NotifyType, level AlertLevel, title, message string) {
	switch channel {
	case NotifyDingTalk:
		e.sendDingTalk(level, title, message)
	case NotifyWeCom:
		e.sendWeCom(level, title, message)
	case NotifySlack:
		e.sendSlack(level, title, message)
	case NotifyEmail:
		e.sendEmail(level, title, message)
	case NotifyWebhook:
		e.sendWebhook(level, title, message)
	case NotifyIntelAlert:
		logger.Info("情报事件通知触发: %s", title)
	}
}

func (e *Engine) EvaluateAndAlert(attackType, ruleID, clientIP string) {
	e.mu.RLock()
	rules := make([]AlertRule, len(e.rules))
	copy(rules, e.rules)
	cfg := e.config
	e.mu.RUnlock()

	now := time.Now()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// 根据规则的匹配类型决定比对目标
		var matched bool
		switch rule.MatchType {
		case "attack_type":
			matched = strings.Contains(attackType, rule.MatchValue)
		case "rule_id":
			matched = strings.Contains(ruleID, rule.MatchValue)
		case "ip":
			matched = strings.Contains(clientIP, rule.MatchValue)
		default:
			matched = strings.Contains(attackType, rule.MatchValue)
		}

		if !matched {
			continue
		}

		ruleKey := rule.ID
		e.mu.Lock()
		lastAlert, hasCooldown := e.cooldowns[ruleKey]
		if hasCooldown && now.Sub(lastAlert) < time.Duration(rule.CooldownSec)*time.Second {
			e.mu.Unlock()
			continue
		}
		e.counters[ruleKey] = append(e.counters[ruleKey], now)
		windowStart := now.Add(-time.Duration(rule.WindowSecs) * time.Second)
		var recent []time.Time
		for _, t := range e.counters[ruleKey] {
			if t.After(windowStart) {
				recent = append(recent, t)
			}
		}
		e.counters[ruleKey] = recent
		count := len(recent)
		e.mu.Unlock()

		if count < rule.Threshold {
			continue
		}

		e.mu.Lock()
		e.cooldowns[ruleKey] = now
		e.mu.Unlock()

		title := fmt.Sprintf("GoWAF Alert: %s %s", rule.MatchType, rule.MatchValue)
		body := fmt.Sprintf("时间: %s\n> 触发规则: %s\n> 匹配类型: %s\n> 匹配值: %s\n> 攻击类型: %s",
			now.Format("2006-01-02 15:04:05"), rule.Name, rule.MatchType, rule.MatchValue, attackType)

		go e.sendToChannel(cfg, rule.NotifyType, rule.Level, title, body)
	}
}

func (e *Engine) sendToChannel(cfg NotificationConfig, channel NotifyType, level AlertLevel, title, message string) {
	switch channel {
	case NotifyDingTalk:
		e.sendDingTalk(level, title, message)
	case NotifyWeCom:
		e.sendWeCom(level, title, message)
	case NotifySlack:
		e.sendSlack(level, title, message)
	case NotifyEmail:
		e.sendEmail(level, title, message)
	case NotifyWebhook:
		e.sendWebhook(level, title, message)
	case NotifyIntelAlert:
		logger.Info("情报事件通知触发: %s", title)
	}
}

func (e *Engine) sendDingTalk(level AlertLevel, title, message string) {
	cfg := e.GetConfig()
	if cfg.DingTalkWebhook == "" {
		return
	}
	if xutil.IsURLHostPrivate(cfg.DingTalkWebhook) {
		logger.Warn("DingTalk Webhook指向私有IP地址，禁止发送: %s", cfg.DingTalkWebhook)
		return
	}
	levelStr := strings.ToUpper(string(level))
	text := fmt.Sprintf("### GoWAF 安全告警\n> 级别: **%s**\n> %s", levelStr, message)
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": title,
			"text":  text,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Warn("DingTalk通知JSON序列化失败: %v", err)
		return
	}
	resp, err := e.httpClient.Post(cfg.DingTalkWebhook, "application/json", bytes.NewReader(data))
	if err != nil {
		logger.Warn("DingTalk通知发送失败: %v", err)
		return
	}
	resp.Body.Close()
	logger.Info("DingTalk通知已发送: %s", title)
}

func (e *Engine) sendWeCom(level AlertLevel, title, message string) {
	cfg := e.GetConfig()
	if cfg.WeComWebhook == "" {
		return
	}
	if xutil.IsURLHostPrivate(cfg.WeComWebhook) {
		logger.Warn("WeCom Webhook指向私有IP地址，禁止发送: %s", cfg.WeComWebhook)
		return
	}
	levelColor := "info"
	switch level {
	case AlertWarning:
		levelColor = "warning"
	case AlertCritical:
		levelColor = "red"
	}
	levelStr := strings.ToUpper(string(level))
	content := fmt.Sprintf("### GoWAF 安全告警\n> 级别: <font color=\"%s\">%s</font>\n> %s", levelColor, levelStr, message)
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"content": content,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Warn("WeCom通知JSON序列化失败: %v", err)
		return
	}
	resp, err := e.httpClient.Post(cfg.WeComWebhook, "application/json", bytes.NewReader(data))
	if err != nil {
		logger.Warn("WeCom通知发送失败: %v", err)
		return
	}
	resp.Body.Close()
	logger.Info("WeCom通知已发送: %s", title)
}

func (e *Engine) sendSlack(level AlertLevel, title, message string) {
	cfg := e.GetConfig()
	if cfg.SlackWebhook == "" {
		return
	}
	if xutil.IsURLHostPrivate(cfg.SlackWebhook) {
		logger.Warn("Slack Webhook指向私有IP地址，禁止发送: %s", cfg.SlackWebhook)
		return
	}
	levelEmoji := ":warning:"
	if level == AlertCritical {
		levelEmoji = ":red_circle:"
	} else if level == AlertInfo {
		levelEmoji = ":information_source:"
	}
	levelStr := strings.ToUpper(string(level))
	text := fmt.Sprintf("%s *%s*\n*级别:* %s\n%s", levelEmoji, title, levelStr, message)
	payload := map[string]interface{}{
		"text": text,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Warn("Slack通知JSON序列化失败: %v", err)
		return
	}
	resp, err := e.httpClient.Post(cfg.SlackWebhook, "application/json", bytes.NewReader(data))
	if err != nil {
		logger.Warn("Slack通知发送失败: %v", err)
		return
	}
	resp.Body.Close()
	logger.Info("Slack通知已发送: %s", title)
}

func (e *Engine) sendWebhook(level AlertLevel, title, message string) {
	cfg := e.GetConfig()
	if cfg.WebhookURL == "" {
		return
	}
	if xutil.IsURLHostPrivate(cfg.WebhookURL) {
		logger.Warn("Webhook URL指向私有IP地址，禁止发送: %s", cfg.WebhookURL)
		return
	}
	levelStr := strings.ToUpper(string(level))
	payload := map[string]interface{}{
		"level":   levelStr,
		"title":   title,
		"message": message,
		"source":  "GoWAF",
		"time":    time.Now().Format("2006-01-02 15:04:05"),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		logger.Warn("Webhook通知JSON序列化失败: %v", err)
		return
	}
	req, err := http.NewRequest("POST", cfg.WebhookURL, bytes.NewReader(data))
	if err != nil {
		logger.Warn("Webhook通知创建请求失败: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.WebhookSecret != "" {
		h := sha256.New()
		h.Write(data)
		h.Write([]byte(cfg.WebhookSecret))
		sig := hex.EncodeToString(h.Sum(nil))
		req.Header.Set("X-Webhook-Signature", sig)
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		logger.Warn("Webhook通知发送失败: %v", err)
		return
	}
	resp.Body.Close()
	logger.Info("Webhook通知已发送: %s", title)
}

func SendWebhook(url, secret, message string) error {
	if url == "" {
		return fmt.Errorf("webhook URL is empty")
	}
	if xutil.IsURLHostPrivate(url) {
		return fmt.Errorf("webhook URL指向私有IP地址，禁止发送: %s", url)
	}
	payload := map[string]string{
		"message": message,
		"source":  "GoWAF",
		"time":    time.Now().Format("2006-01-02 15:04:05"),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		h := sha256.New()
		h.Write(data)
		h.Write([]byte(secret))
		sig := hex.EncodeToString(h.Sum(nil))
		req.Header.Set("X-Webhook-Signature", sig)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (e *Engine) sendEmail(level AlertLevel, title, message string) {
	cfg := e.GetConfig()
	if cfg.EmailSMTPHost == "" || cfg.EmailTo == "" {
		return
	}
	levelStr := strings.ToUpper(string(level))
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\n\n级别: %s\n%s",
		cfg.EmailFrom, cfg.EmailTo, title, title, levelStr, message)

	host, port, _ := net.SplitHostPort(fmt.Sprintf("%s:%d", cfg.EmailSMTPHost, cfg.EmailSMTPPort))
	if port == "" {
		port = "25"
	}
	addr := net.JoinHostPort(host, port)

	var auth smtp.Auth
	if cfg.EmailFrom != "" && cfg.EmailPassword != "" {
		auth = smtp.PlainAuth("", cfg.EmailFrom, cfg.EmailPassword, host)
	}

	// Note: 在生产环境中，EmailPassword应通过环境变量注入
	client, err := smtp.Dial(addr)
	if err != nil {
		// 直连失败，尝试TLS直连
		tlsConfig := &tls.Config{ServerName: host}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			logger.Warn("邮件通知发送失败(Dial): %v", err)
			return
		}
		client, err = smtp.NewClient(conn, host)
		if err != nil {
			logger.Warn("邮件通知发送失败(NewClient): %v", err)
			return
		}
	} else {
		// 直连成功后尝试升级为STARTTLS
		tlsConfig := &tls.Config{ServerName: host}
		if err := client.StartTLS(tlsConfig); err != nil {
			logger.Warn("邮件STARTTLS升级失败,中止发送: %v", err)
			client.Quit()
			return
		}
	}
	defer client.Quit()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			logger.Warn("邮件通知发送失败(Auth): %v", err)
			return
		}
	}

	if err := client.Mail(cfg.EmailFrom); err != nil {
		logger.Warn("邮件通知发送失败(Mail): %v", err)
		return
	}
	recipients := strings.Split(cfg.EmailTo, ",")
	for _, rcpt := range recipients {
		rcpt = strings.TrimSpace(rcpt)
		if rcpt != "" {
			if err := client.Rcpt(rcpt); err != nil {
				logger.Warn("邮件通知发送失败(Rcpt %s): %v", rcpt, err)
				return
			}
		}
	}

	w, err := client.Data()
	if err != nil {
		logger.Warn("邮件通知发送失败(Data): %v", err)
		return
	}
	_, err = w.Write([]byte(body))
	if err != nil {
		logger.Warn("邮件通知发送失败(Write): %v", err)
		return
	}
	w.Close()
	logger.Info("邮件通知已发送: %s", title)
}

func (e *Engine) TestNotify(channel NotifyType) error {
	title := "GoWAF Test Notification"
	message := fmt.Sprintf("时间: %s\n> 类型: 测试通知\n> 状态: 通知渠道验证通过", time.Now().Format("2006-01-02 15:04:05"))

	cfg := e.GetConfig()
	switch channel {
	case NotifyDingTalk:
		if cfg.DingTalkWebhook == "" {
			return fmt.Errorf("DingTalk webhook URL not configured")
		}
		e.sendDingTalk(AlertInfo, title, message)
	case NotifyWeCom:
		if cfg.WeComWebhook == "" {
			return fmt.Errorf("WeCom webhook URL not configured")
		}
		e.sendWeCom(AlertInfo, title, message)
	case NotifySlack:
		if cfg.SlackWebhook == "" {
			return fmt.Errorf("slack webhook URL not configured")
		}
		e.sendSlack(AlertInfo, title, message)
	case NotifyEmail:
		if cfg.EmailSMTPHost == "" {
			return fmt.Errorf("email SMTP host not configured")
		}
		e.sendEmail(AlertInfo, title, message)
	case NotifyWebhook:
		if cfg.WebhookURL == "" {
			return fmt.Errorf("webhook URL not configured")
		}
		e.sendWebhook(AlertInfo, title, message)
	default:
		return fmt.Errorf("unknown notify type: %s", channel)
	}
	return nil
}

func (e *Engine) Close() {
	select {
	case <-e.stopChan:
		return
	default:
		close(e.stopChan)
	}
}

func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			e.mu.Lock()
			now := time.Now()
			for key, timestamps := range e.counters {
				var recent []time.Time
				for _, t := range timestamps {
					if now.Sub(t) < 5*time.Minute {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(e.counters, key)
				} else {
					e.counters[key] = recent
				}
			}
			for key, lastAlert := range e.cooldowns {
				if now.Sub(lastAlert) > 30*time.Minute {
					delete(e.cooldowns, key)
				}
			}
			e.mu.Unlock()
		case <-e.stopChan:
			return
		}
	}
}
