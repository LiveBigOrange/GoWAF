package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"

	"gowaf-demo/internal/web/templates"
)

// AdminLogEntry 管理端口日志条目
type AdminLogEntry struct {
	Timestamp string `json:"timestamp"`
	ClientIP  string `json:"client_ip"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	UserAgent string `json:"user_agent,omitempty"`
	Referer   string `json:"referer,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Action    string `json:"action,omitempty"` // login_success, login_fail, logout, api_call, page_view
	Username  string `json:"username,omitempty"`
}

// AdminLogPage 管理日志页面
func AdminLogPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Active": "adminlog",
	}
	templates.AdminLogTmpl.ExecuteTemplate(w, "adminlog", data)
}

// APIAdminLogList 获取管理日志列表
func APIAdminLogList(w http.ResponseWriter, r *http.Request) {
	// 获取limit参数，默认1000条
	limitStr := r.URL.Query().Get("limit")
	limit := 1000 // 默认加载1000条
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// 从配置获取日志文件路径
	logPath := "./admin.log" // 默认路径
	if cfg != nil && cfg.Admin.AdminLog != "" {
		logPath = cfg.Admin.AdminLog
	}

	// 读取日志文件
	file, err := os.Open(logPath)
	if err != nil {
		// 文件不存在时返回空数组，而不是错误
		if os.IsNotExist(err) {
			log.Printf("管理日志文件不存在: %s", logPath)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]AdminLogEntry{})
			return
		}
		log.Printf("无法打开管理日志文件: %v", err)
		jsonError(w, "无法打开日志文件: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// 获取文件大小
	stat, err := file.Stat()
	if err != nil {
		log.Printf("获取文件信息失败: %v", err)
		jsonError(w, "获取文件信息失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fileSize := stat.Size()

	// 如果文件为空，返回空数组
	if fileSize == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]AdminLogEntry{})
		return
	}

	// 从文件末尾反向读取，提高性能
	logs, err := readRecentAdminLogsFromFile(file, fileSize, limit)
	if err != nil {
		log.Printf("读取日志文件失败: %v", err)
		jsonError(w, "读取日志文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

// readRecentAdminLogsFromFile 从文件末尾读取最近N条管理日志
func readRecentAdminLogsFromFile(file *os.File, fileSize int64, limit int) ([]AdminLogEntry, error) {
	var logs []AdminLogEntry
	chunkSize := int64(64 * 1024) // 每次读取64KB
	var offset = fileSize
	var lines []string

	// 从文件末尾反向读取
	for len(lines) < limit && offset > 0 {
		readSize := chunkSize
		if offset < chunkSize {
			readSize = offset
		}
		offset -= readSize

		// 移动到读取位置
		_, err := file.Seek(offset, 0)
		if err != nil {
			return nil, err
		}

		// 读取数据块
		buf := make([]byte, readSize)
		_, err = file.Read(buf)
		if err != nil {
			return nil, err
		}

		// 按行分割
		start := 0
		for i := 0; i < len(buf); i++ {
			if buf[i] == '\n' {
				line := string(buf[start:i])
				if line != "" {
					lines = append([]string{line}, lines...)
				}
				start = i + 1
			}
		}

		// 如果是第一次读取，处理最后一行
		if offset == 0 && start < len(buf) {
			line := string(buf[start:])
			if line != "" {
				lines = append([]string{line}, lines...)
			}
		}

		// 如果已经读取了足够的行，停止
		if len(lines) >= limit {
			break
		}
	}

	// 只取最近的limit条
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}

	// 解析日志
	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry AdminLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			logs = append(logs, entry)
		}
	}

	// 反转顺序，最新的在前面
	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	return logs, nil
}
