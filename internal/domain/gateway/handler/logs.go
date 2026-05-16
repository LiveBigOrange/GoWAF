package handler

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gowaf/internal/infra/logger"
	"gowaf/internal/pkg/xutil"
)

// LogEntry 日志条目结构 - 使用统一的AccessLog结构
type LogEntry = logger.AccessLog

// LogQueryRequest 日志查询请求
type LogQueryRequest struct {
	StartTime  string `json:"start_time"`
	EndTime    string `json:"end_time"`
	ClientIP   string `json:"client_ip"`
	Method     string `json:"method"`
	StatusCode string `json:"status_code"`
	Action     string `json:"action"`
	Path       string `json:"path"`
	Keyword    string `json:"keyword"`
	Page       int    `json:"page"`
	PageSize   int    `json:"page_size"`
	SortField  string `json:"sort_field"`
	SortOrder  string `json:"sort_order"`
}

// LogStatsResponse 日志统计响应
type LogStatsResponse struct {
	TotalRequests  int64            `json:"total_requests"`
	TotalBlocked   int64            `json:"total_blocked"`
	TotalErrors    int64            `json:"total_errors"`
	AvgLatency     float64          `json:"avg_latency"`
	StatusCodeDist map[string]int64 `json:"status_code_dist"`
	MethodDist     map[string]int64 `json:"method_dist"`
	ActionDist     map[string]int64 `json:"action_dist"`
	TopIPs         []IPCount        `json:"top_ips"`
	TopPaths       []PathCount      `json:"top_paths"`
	TrendData      []TrendPoint     `json:"trend_data"`
}

// IPCount IP计数
type IPCount struct {
	IP    string `json:"ip"`
	Count int64  `json:"count"`
}

// PathCount 路径计数
type PathCount struct {
	Path  string `json:"path"`
	Count int64  `json:"count"`
}

// TrendPoint 趋势数据点
type TrendPoint struct {
	Time     string `json:"time"`
	Requests int64  `json:"requests"`
	Blocked  int64  `json:"blocked"`
	Errors   int64  `json:"errors"`
}

// SimpleStats 简单统计（用于页面显示）
type SimpleStats struct {
	TotalRequests   int64   `json:"total_requests"`
	BlockedRequests int64   `json:"blocked_requests"`
	ErrorRequests   int64   `json:"error_requests"`
	AvgLatency      float64 `json:"avg_latency"`
	MaxLatency      float64 `json:"max_latency"`
	MinLatency      float64 `json:"min_latency"`
}

// LogFileInfo 日志文件信息
type LogFileInfo struct {
	FilePath      string `json:"file_path"`
	FileSize      int64  `json:"file_size"`
	TotalLines    int64  `json:"total_lines"`
	FirstLineTime string `json:"first_line_time"`
	LastLineTime  string `json:"last_line_time"`
	ModifiedTime  string `json:"modified_time"`
}

// getLogFilePath 获取日志文件路径
func getLogFilePath() string {
	if deps.Config != nil && deps.Config.Log.File != "" {
		return deps.Config.Log.File
	}
	return "waf.log" // 默认路径
}

func validateLogFilePath(logFile string) (string, error) {
	if strings.Contains(logFile, "..") {
		return "", fmt.Errorf("invalid file path: path traversal detected")
	}
	absPath, err := filepath.Abs(filepath.Clean(logFile))
	if err != nil {
		return "", fmt.Errorf("invalid file path: %w", err)
	}
	var baseDir string
	if deps.Config != nil && deps.Config.Log.File != "" {
		baseDir, _ = filepath.Abs(filepath.Dir(deps.Config.Log.File))
	}
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}
	if !strings.HasPrefix(absPath, baseDir) {
		return "", fmt.Errorf("invalid file path: access denied")
	}
	return absPath, nil
}

// GetLogsList 获取日志列表
func GetLogsList(w http.ResponseWriter, r *http.Request) {
	query := parseLogQuery(r)
	logFile := getLogFilePath()
	entries, total, err := readAndFilterLogs(logFile, query)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// 为每条日志填充地理位置
	if deps.MetricsManager != nil {
		for i := range entries {
			geo := deps.MetricsManager.GetGeoLocation(entries[i].ClientIP)
			entries[i].GeoCountry = geo.Country
			entries[i].GeoCity = geo.City
			entries[i].GeoFlag = geo.Flag
		}
	}

	jsonSuccessPaged(w, entries, int64(total), query.Page, query.PageSize)
}

// GetLogDetail 获取日志详情
func GetLogDetail(w http.ResponseWriter, r *http.Request) {
	requestID := r.URL.Query().Get("request_id")
	if requestID == "" {
		jsonError(w, "request_id is required", http.StatusBadRequest)
		return
	}

	logFile := getLogFilePath()
	entry, err := findLogByRequestID(logFile, requestID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusNotFound)
		return
	}

	jsonSuccess(w, entry)
}

// GetLogsStats 获取日志统计
func GetLogsStats(w http.ResponseWriter, r *http.Request) {
	startTime := r.URL.Query().Get("start_time")
	endTime := r.URL.Query().Get("end_time")

	if startTime == "" {
		startTime = time.Now().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	}
	if endTime == "" {
		endTime = time.Now().Format("2006-01-02 15:04:05")
	}

	logFile := getLogFilePath()
	stats, err := calculateLogStats(logFile, startTime, endTime)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, stats)
}

// ExportLogs 导出日志
func ExportLogs(w http.ResponseWriter, r *http.Request) {
	query := parseLogQuery(r)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	logFile := getLogFilePath()
	entries, _, err := readAndFilterLogs(logFile, query)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	switch format {
	case "csv":
		exportLogsCSV(w, entries)
	case "json":
		exportLogsJSON(w, entries)
	default:
		jsonError(w, "unsupported format", http.StatusBadRequest)
	}
}

// GetLogFiles 获取日志文件列表
func GetLogFiles(w http.ResponseWriter, r *http.Request) {
	files, err := listLogFiles()
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, files)
}

// GetLogFileInfo 获取日志文件信息
func GetLogFileInfo(w http.ResponseWriter, r *http.Request) {
	logFile := r.URL.Query().Get("file")
	if logFile == "" {
		logFile = getLogFilePath()
	}

	validatedPath, err := validateLogFilePath(logFile)
	if err != nil {
		if strings.Contains(err.Error(), "path traversal") {
			jsonError(w, err.Error(), http.StatusBadRequest)
		} else {
			jsonError(w, err.Error(), http.StatusForbidden)
		}
		return
	}
	logFile = validatedPath

	info, err := os.Stat(logFile)
	if err != nil {
		jsonError(w, "file not found: "+err.Error(), http.StatusNotFound)
		return
	}

	if info.IsDir() {
		jsonError(w, "path is a directory, not a file", http.StatusBadRequest)
		return
	}

	file, err := os.Open(logFile)
	if err != nil {
		jsonError(w, "cannot open file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer file.Close()

	var totalLines int64 = 0
	var firstLineTime string
	var lastLineTime string

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	// 使用JSON解析器
	parser := NewJSONLogParser()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		totalLines++

		entry, err := parser.Parse(line)
		if err == nil {
			if firstLineTime == "" {
				firstLineTime = entry.Timestamp
			}
			lastLineTime = entry.Timestamp
		}
	}

	fileInfo := LogFileInfo{
		FilePath:      logFile,
		FileSize:      info.Size(),
		TotalLines:    totalLines,
		FirstLineTime: firstLineTime,
		LastLineTime:  lastLineTime,
		ModifiedTime:  xutil.FormatRFC3339(info.ModTime()),
	}

	jsonSuccess(w, fileInfo)
}

// GetSimpleStats 获取简单统计
func GetSimpleStats(w http.ResponseWriter, r *http.Request) {
	logFile := r.URL.Query().Get("file")
	if logFile == "" {
		logFile = getLogFilePath()
	}

	validatedPath, err := validateLogFilePath(logFile)
	if err != nil {
		if strings.Contains(err.Error(), "path traversal") {
			jsonError(w, err.Error(), http.StatusBadRequest)
		} else {
			jsonError(w, err.Error(), http.StatusForbidden)
		}
		return
	}
	logFile = validatedPath

	query := parseLogQuery(r)
	entries, _, err := readAndFilterLogs(logFile, query)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stats := calculateSimpleStats(entries)

	jsonSuccess(w, stats)
}

// ReadRecentLogs 读取最近N条日志
func ReadRecentLogs(w http.ResponseWriter, r *http.Request) {
	logFile := r.URL.Query().Get("file")
	if logFile == "" {
		logFile = getLogFilePath()
	}

	validatedPath, err := validateLogFilePath(logFile)
	if err != nil {
		if strings.Contains(err.Error(), "path traversal") {
			jsonError(w, err.Error(), http.StatusBadRequest)
		} else {
			jsonError(w, err.Error(), http.StatusForbidden)
		}
		return
	}
	logFile = validatedPath

	limitStr := r.URL.Query().Get("limit")
	limit := 1000
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries, err := readRecentLogsFromFile(logFile, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonSuccess(w, map[string]interface{}{
		"logs":  entries,
		"count": len(entries),
	})
}

// calculateSimpleStats 计算简单统计
func calculateSimpleStats(entries []LogEntry) SimpleStats {
	stats := SimpleStats{
		MinLatency: 1e10,
	}

	var totalLatency float64
	var latencyCount int

	for _, entry := range entries {
		stats.TotalRequests++

		if entry.Action == "block" {
			stats.BlockedRequests++
		}

		if entry.Status >= 400 {
			stats.ErrorRequests++
		}

		if entry.LatencyMs > 0 {
			totalLatency += entry.LatencyMs
			latencyCount++

			if entry.LatencyMs > stats.MaxLatency {
				stats.MaxLatency = entry.LatencyMs
			}
			if entry.LatencyMs < stats.MinLatency {
				stats.MinLatency = entry.LatencyMs
			}
		}
	}

	if latencyCount > 0 {
		stats.AvgLatency = totalLatency / float64(latencyCount)
	}

	if stats.TotalRequests == 0 {
		stats.MinLatency = 0
	}

	return stats
}

// readRecentLogsFromFile 从文件末尾读取最近N条日志
func readRecentLogsFromFile(filePath string, limit int) ([]LogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	fileSize := info.Size()

	chunkSize := int64(64 * 1024)
	var lines []string
	var offset = fileSize
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

		// 逐字节扫描按行分割
		start := 0
		for i := 0; i < len(buf); i++ {
			if buf[i] == '\n' {
				line := string(buf[start:i])
				start = i + 1
				if line == "" {
					continue
				}
				if partialLine != "" {
					line = partialLine + line
					partialLine = ""
				}
				lines = append([]string{line}, lines...)
				if len(lines) >= limit {
					break
				}
			}
		}

		if len(lines) >= limit {
			break
		}

		// 处理chunk尾部未换行结束的部分
		if start < len(buf) {
			tail := string(buf[start:])
			if offset == 0 {
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
				partialLine = tail + partialLine
			}
		}
	}

	if partialLine != "" {
		lines = append([]string{partialLine}, lines...)
	}

	// 使用JSON解析器
	parser := NewJSONLogParser()
	var entries []LogEntry
	for _, line := range lines {
		entry, err := parser.Parse(line)
		if err == nil {
			entries = append(entries, *entry)
		}
	}

	return entries, nil
}

// parseLogQuery 解析日志查询参数
func parseLogQuery(r *http.Request) *LogQueryRequest {
	query := &LogQueryRequest{
		Page:     1,
		PageSize: 50,
	}

	query.StartTime = r.URL.Query().Get("start_time")
	query.EndTime = r.URL.Query().Get("end_time")
	query.ClientIP = r.URL.Query().Get("client_ip")
	query.Method = r.URL.Query().Get("method")
	query.StatusCode = r.URL.Query().Get("status_code")
	query.Action = r.URL.Query().Get("action")
	query.Path = r.URL.Query().Get("path")
	query.Keyword = r.URL.Query().Get("keyword")
	query.SortField = r.URL.Query().Get("sort_field")
	query.SortOrder = r.URL.Query().Get("sort_order")

	if page := r.URL.Query().Get("page"); page != "" {
		if v, err := strconv.Atoi(page); err == nil && v > 0 {
			query.Page = v
		}
	}
	if pageSize := r.URL.Query().Get("page_size"); pageSize != "" {
		if v, err := strconv.Atoi(pageSize); err == nil && v > 0 {
			query.PageSize = v
		}
	}
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if v, err := strconv.Atoi(limit); err == nil && v > 0 {
			query.PageSize = v
			query.Page = 1
		}
	}

	return query
}

// readAndFilterLogs 读取并过滤日志
func readAndFilterLogs(filename string, query *LogQueryRequest) ([]LogEntry, int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(file)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	// 使用JSON解析器
	parser := NewJSONLogParser()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry, err := parser.Parse(line)
		if err != nil {
			// 解析失败,跳过此行
			continue
		}

		if !matchLogEntry(entry, query) {
			continue
		}

		entries = append(entries, *entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}

	sortLogs(entries, query.SortField, query.SortOrder)

	total := len(entries)

	start := (query.Page - 1) * query.PageSize
	end := start + query.PageSize
	if start >= total {
		return []LogEntry{}, total, nil
	}
	if end > total {
		end = total
	}

	return entries[start:end], total, nil
}

// matchLogEntry 匹配日志条目
func matchLogEntry(entry *LogEntry, query *LogQueryRequest) bool {
	if query.StartTime != "" {
		if entry.Timestamp < query.StartTime {
			return false
		}
	}
	if query.EndTime != "" {
		if entry.Timestamp > query.EndTime {
			return false
		}
	}

	if query.ClientIP != "" && !strings.Contains(entry.ClientIP, query.ClientIP) {
		return false
	}

	if query.Method != "" && entry.Method != query.Method {
		return false
	}

	if query.StatusCode != "" {
		if strconv.Itoa(entry.Status) != query.StatusCode {
			return false
		}
	}

	if query.Action != "" && entry.Action != query.Action {
		return false
	}

	if query.Path != "" && !strings.Contains(entry.Path, query.Path) {
		return false
	}

	if query.Keyword != "" {
		keyword := strings.ToLower(query.Keyword)
		if !strings.Contains(strings.ToLower(entry.Path), keyword) &&
			!strings.Contains(strings.ToLower(entry.ClientIP), keyword) &&
			!strings.Contains(strings.ToLower(entry.UserAgent), keyword) &&
			!strings.Contains(strings.ToLower(entry.Host), keyword) &&
			!strings.Contains(strings.ToLower(entry.Query), keyword) {
			return false
		}
	}

	return true
}

// sortLogs 排序日志
func sortLogs(entries []LogEntry, field, order string) {
	if field == "" {
		field = "timestamp"
	}
	if order == "" {
		order = "desc"
	}

	sort.Slice(entries, func(i, j int) bool {
		var less bool
		switch field {
		case "timestamp":
			less = entries[i].Timestamp < entries[j].Timestamp
		case "status":
			less = entries[i].Status < entries[j].Status
		case "latency":
			less = entries[i].LatencyMs < entries[j].LatencyMs
		default:
			less = entries[i].Timestamp < entries[j].Timestamp
		}

		if order == "desc" {
			return !less
		}
		return less
	})
}

// findLogByRequestID 根据RequestID查找日志
func findLogByRequestID(filename, requestID string) (*LogEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	// 使用JSON解析器
	parser := NewJSONLogParser()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entry, err := parser.Parse(line)
		if err != nil {
			continue
		}

		if entry.RequestID == requestID {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("log not found")
}

// calculateLogStats 计算日志统计
func calculateLogStats(filename, startTime, endTime string) (*LogStatsResponse, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats := &LogStatsResponse{
		StatusCodeDist: make(map[string]int64),
		MethodDist:     make(map[string]int64),
		ActionDist:     make(map[string]int64),
	}

	var totalLatency float64
	var latencyCount int64
	ipCount := make(map[string]int64)
	pathCount := make(map[string]int64)
	trendMap := make(map[string]*TrendPoint)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.Timestamp < startTime || entry.Timestamp > endTime {
			continue
		}

		stats.TotalRequests++

		statusCode := strconv.Itoa(entry.Status)
		stats.StatusCodeDist[statusCode]++

		stats.MethodDist[entry.Method]++

		stats.ActionDist[entry.Action]++

		totalLatency += entry.LatencyMs
		latencyCount++

		ipCount[entry.ClientIP]++

		pathCount[entry.Path]++

		if entry.Action == "block" {
			stats.TotalBlocked++
		}
		if entry.Status >= 500 {
			stats.TotalErrors++
		}

		if t, err := time.Parse(time.RFC3339, entry.Timestamp); err == nil {
			hourKey := t.Format("2006-01-02 15:00")
			if trend, ok := trendMap[hourKey]; ok {
				trend.Requests++
				if entry.Action == "block" {
					trend.Blocked++
				}
				if entry.Status >= 500 {
					trend.Errors++
				}
			} else {
				trendMap[hourKey] = &TrendPoint{
					Time:     hourKey,
					Requests: 1,
					Blocked:  0,
					Errors:   0,
				}
				if entry.Action == "block" {
					trendMap[hourKey].Blocked = 1
				}
				if entry.Status >= 500 {
					trendMap[hourKey].Errors = 1
				}
			}
		}
	}

	if latencyCount > 0 {
		stats.AvgLatency = totalLatency / float64(latencyCount)
	}

	stats.TopIPs = getTopN(ipCount, 10)

	stats.TopPaths = getTopNPath(pathCount, 10)

	for _, trend := range trendMap {
		stats.TrendData = append(stats.TrendData, *trend)
	}
	sort.Slice(stats.TrendData, func(i, j int) bool {
		return stats.TrendData[i].Time < stats.TrendData[j].Time
	})

	return stats, nil
}

// getTopN 获取TOP N
func getTopN(m map[string]int64, n int) []IPCount {
	var items []IPCount
	for k, v := range m {
		items = append(items, IPCount{IP: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// getTopNPath 获取TOP N路径
func getTopNPath(m map[string]int64, n int) []PathCount {
	var items []PathCount
	for k, v := range m {
		items = append(items, PathCount{Path: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].Count > items[j].Count
	})
	if len(items) > n {
		items = items[:n]
	}
	return items
}

// exportLogsCSV 导出CSV格式
func exportLogsCSV(w http.ResponseWriter, entries []LogEntry) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=logs.csv")

	writer := csv.NewWriter(w)
	defer writer.Flush()

	header := []string{"Timestamp", "Client IP", "Host", "Method", "Path", "Query", "Status", "Action", "Rule ID", "Match Detail", "Match Location", "Latency(ms)", "Request ID"}
	writer.Write(header)

	for _, entry := range entries {
		record := []string{
			entry.Timestamp,
			entry.ClientIP,
			entry.Host,
			entry.Method,
			entry.Path,
			entry.Query,
			strconv.Itoa(entry.Status),
			entry.Action,
			entry.RuleID,
			entry.MatchDetail,
			entry.MatchLocation,
			fmt.Sprintf("%.2f", entry.LatencyMs),
			entry.RequestID,
		}
		writer.Write(record)
	}
}

// exportLogsJSON 导出JSON格式
func exportLogsJSON(w http.ResponseWriter, entries []LogEntry) {
	w.Header().Set("Content-Disposition", "attachment; filename=logs.json")
	jsonSuccess(w, entries)
}

// listLogFiles 列出日志文件
func listLogFiles() ([]map[string]interface{}, error) {
	var files []map[string]interface{}

	matches, err := filepath.Glob("*.log")
	if err != nil {
		return nil, err
	}

	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			continue
		}

		files = append(files, map[string]interface{}{
			"name":     match,
			"size":     info.Size(),
			"modified": info.ModTime().Format("2006-01-02 15:04:05"),
		})
	}

	return files, nil
}
