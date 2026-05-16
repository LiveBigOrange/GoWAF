package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"

	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/gateway/model"
	"gowaf/internal/domain/gateway/templates"
)

// AdminLogPage 管理日志页面
func AdminLogPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.AdminLogTmpl, "adminlog", "adminlog")
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
	if deps.Config != nil && deps.Config.Admin.AdminLog != "" {
		logPath = deps.Config.Admin.AdminLog
	}

	// 读取日志文件
	file, err := os.Open(logPath)
	if err != nil {
		// 文件不存在时返回空数组，而不是错误
		if os.IsNotExist(err) {
			logger.Error("管理日志文件不存在: %s", logPath)
			jsonSuccess(w, []model.AdminLogEntry{})
			return
		}
		logger.Error("无法打开管理日志文件: %v", err)
		jsonError(w, "无法打开日志文件: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// 获取文件大小
	stat, err := file.Stat()
	if err != nil {
		logger.Error("获取文件信息失败: %v", err)
		dbError(w, "获取文件信息", err)
		return
	}
	fileSize := stat.Size()

	// 如果文件为空，返回空数组
	if fileSize == 0 {
		jsonSuccess(w, []model.AdminLogEntry{})
		return
	}

	// 从文件末尾反向读取，提高性能
	logs, err := readRecentAdminLogsFromFile(file, fileSize, limit)
	if err != nil {
		logger.Error("读取日志文件失败: %v", err)
		dbError(w, "读取日志文件", err)
		return
	}

	jsonSuccess(w, logs)
}

// readRecentAdminLogsFromFile 从文件末尾读取最近N条管理日志
func readRecentAdminLogsFromFile(file *os.File, fileSize int64, limit int) ([]model.AdminLogEntry, error) {
	var logs []model.AdminLogEntry
	chunkSize := int64(64 * 1024)
	var offset = fileSize
	var lines []string
	var partialLine string

	for len(lines) < limit && offset > 0 {
		readSize := chunkSize
		if offset < chunkSize {
			readSize = offset
		}
		offset -= readSize

		_, err := file.Seek(offset, 0)
		if err != nil {
			return nil, err
		}

		buf := make([]byte, readSize)
		_, err = io.ReadFull(file, buf)
		if err != nil {
			return nil, err
		}

		// 按行分割
		start := 0
		for i := 0; i < len(buf); i++ {
			if buf[i] == '\n' {
				line := string(buf[start:i])
				start = i + 1
				if line == "" {
					continue
				}
				// 如果有上一个chunk遗留的半行，拼接到当前行开头
				if partialLine != "" {
					line = partialLine + line
					partialLine = ""
				}
				lines = append([]string{line}, lines...)
			}
		}

		// 处理chunk尾部未换行结束的部分
		if start < len(buf) {
			tail := string(buf[start:])
			if offset == 0 {
				// 文件开头，完整行
				if tail != "" {
					if partialLine != "" {
						tail = partialLine + tail
					}
					if tail != "" {
						lines = append([]string{tail}, lines...)
					}
				}
				partialLine = ""
			} else {
				// 中间chunk，保存半行等下一个chunk拼接
				partialLine = tail + partialLine
			}
		}

		if len(lines) >= limit {
			break
		}
	}

	// 处理最后残留的partialLine
	if partialLine != "" {
		lines = append([]string{partialLine}, lines...)
		partialLine = ""
	}

	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}

	for _, line := range lines {
		if line == "" {
			continue
		}
		var entry model.AdminLogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			logs = append(logs, entry)
		}
	}

	for i, j := 0, len(logs)-1; i < j; i, j = i+1, j-1 {
		logs[i], logs[j] = logs[j], logs[i]
	}

	return logs, nil
}
