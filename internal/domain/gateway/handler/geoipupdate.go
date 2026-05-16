package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func APIGeoIPUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.GeoIPUpdateManager, "GeoIP更新管理器") {
		return
	}
	url, enabled, interval, lastUpdate := deps.GeoIPUpdateManager.LoadConfig()
	dbPath := deps.GeoIPUpdateManager.CurrentDBPath()
	jsonSuccess(w, map[string]interface{}{
		"download_url":          url,
		"auto_update_enabled":   enabled,
		"update_interval_hours": interval,
		"last_update_time":      lastUpdate,
		"db_path":               dbPath,
	})
}

func APIGeoIPUpdateConfigSave(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.GeoIPUpdateManager, "GeoIP更新管理器") {
		return
	}
	var req struct {
		DownloadURL         string `json:"download_url"`
		AutoUpdateEnabled   bool   `json:"auto_update_enabled"`
		UpdateIntervalHours int    `json:"update_interval_hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "无效的请求数据", http.StatusBadRequest)
		return
	}
	if err := deps.GeoIPUpdateManager.SaveConfig(req.DownloadURL, req.AutoUpdateEnabled, req.UpdateIntervalHours); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.AutoUpdateEnabled {
		deps.GeoIPUpdateManager.StartAutoUpdate()
	} else {
		deps.GeoIPUpdateManager.StopAutoUpdate()
	}
	jsonSuccess(w, nil)
}

func APIGeoIPUpdateTrigger(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.GeoIPUpdateManager, "GeoIP更新管理器") {
		return
	}
	url, _, _, _ := deps.GeoIPUpdateManager.LoadConfig()
	if url == "" || url == "https://updates.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz" {
		jsonError(w, "请先在GeoIP更新配置中设置有效的下载地址（MaxMind URL需要付费账号认证）", http.StatusBadRequest)
		return
	}
	if err := deps.GeoIPUpdateManager.TriggerUpdate(); err != nil {
		dbError(w, "更新", err)
		return
	}
	jsonSuccess(w, nil)
}

func APIGeoIPUpload(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.GeoIPUpdateManager, "GeoIP更新管理器") {
		return
	}
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		jsonError(w, "文件解析失败，文件不能超过100MB", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "未找到上传文件", http.StatusBadRequest)
		return
	}
	defer file.Close()
	if header.Size < 1024 {
		jsonError(w, "文件过小，不是有效的mmdb数据库文件", http.StatusBadRequest)
		return
	}
	tmpFile, err := os.CreateTemp("", "geoip-upload-*.mmdb")
	if err != nil {
		jsonError(w, fmt.Errorf("创建临时文件失败: %w", err).Error(), http.StatusInternalServerError)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.ReadFrom(file); err != nil {
		tmpFile.Close()
		jsonError(w, fmt.Errorf("写入临时文件失败: %w", err).Error(), http.StatusInternalServerError)
		return
	}
	tmpFile.Close()
	if err := deps.GeoIPUpdateManager.UpdateFromFile(tmpPath); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonSuccess(w, nil)
}
