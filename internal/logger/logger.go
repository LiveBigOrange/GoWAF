package logger

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"gowaf/internal/logdb"
)

// 注意：AccessLog 结构已移至 format.go 统一定义

// RotationConfig 日志轮转配置
type RotationConfig struct {
	MaxSize    int  // 单个日志文件最大大小（MB）
	MaxBackups int  // 保留的旧日志文件数量
	MaxAge     int  // 保留旧日志文件的最大天数
	Compress   bool // 是否压缩旧日志文件
}

var (
	logChan      chan AccessLog
	callbackChan chan AccessLog
	logFile      *os.File
	closeOnce    sync.Once
	wg           sync.WaitGroup
	fieldConfig  LogFieldConfig  // 字段配置
	fieldMu      sync.RWMutex    // 保护fieldConfig的读写
	logCallback  func(AccessLog) // 日志回调函数
	callbackMu   sync.RWMutex    // 保护logCallback的读写
	dropCount    uint64          // 日志丢弃计数
	rotation     RotationConfig  // 轮转配置
	logFilePath  string          // 日志文件路径
	currentSize  int64           // 当前日志文件大小
	rotationMu   sync.Mutex      // 轮转锁
	logDB        *logdb.LogDB    // 日志数据库
	useDB        bool            // 是否使用数据库存储
	stopChan     chan struct{}   // 停止信号，用于终止cleanup goroutine
)

// 移除硬编码常量,改用配置变量
var (
	channelSize   = 10000                  // 日志通道大小
	batchSize     = 100                    // 批量大小
	flushInterval = 2 * time.Second        // 刷新间隔
	writeDBSem    = make(chan struct{}, 4) // 并发写入DB上限
)

// SetLogConfig 设置日志系统配置
func SetLogConfig(channelSz int, flushSec int) {
	if channelSz > 0 {
		channelSize = channelSz
	}
	if flushSec > 0 {
		flushInterval = time.Duration(flushSec) * time.Second
	}
}

// Init 初始化日志系统
func Init(filePath string) error {
	return InitWithConfig(filePath, DefaultLogFieldConfig())
}

// InitWithConfig 使用配置初始化日志系统
func InitWithConfig(filePath string, config LogFieldConfig) error {
	return InitWithRotation(filePath, config, RotationConfig{
		MaxSize:    100, // 默认100MB
		MaxBackups: 10,  // 默认保留10个
		MaxAge:     7,   // 默认保留7天
		Compress:   false,
	})
}

// InitWithRotation 使用轮转配置初始化日志系统
func InitWithRotation(filePath string, config LogFieldConfig, rotConfig RotationConfig) error {
	return InitWithRotationAndDB(filePath, config, rotConfig, nil)
}

// InitWithRotationAndDB 使用轮转配置和数据库初始化日志系统
func InitWithRotationAndDB(filePath string, config LogFieldConfig, rotConfig RotationConfig, db *logdb.LogDB) error {
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	// 获取当前文件大小
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	logFile = f
	logFilePath = filePath
	logChan = make(chan AccessLog, channelSize)
	callbackChan = make(chan AccessLog, channelSize)
	stopChan = make(chan struct{})
	fieldMu.Lock()
	fieldConfig = config
	fieldMu.Unlock()
	rotation = rotConfig
	currentSize = stat.Size()
	logDB = db
	useDB = (db != nil)

	wg.Add(1)
	go func() {
		defer wg.Done()
		batch := make([]AccessLog, 0, batchSize)
		ticker := time.NewTicker(flushInterval)
		defer ticker.Stop()

		for {
			select {
			case entry, ok := <-logChan:
				if !ok {
					flushBatch(batch)
					return
				}
				batch = append(batch, entry)
				if len(batch) >= batchSize {
					flushBatch(batch)
					batch = batch[:0]
				}
			case <-ticker.C:
				if len(batch) > 0 {
					flushBatch(batch)
					batch = batch[:0]
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case entry, ok := <-callbackChan:
				if !ok {
					return
				}
				callbackMu.RLock()
				cb := logCallback
				callbackMu.RUnlock()
				if cb != nil {
					cb(entry)
				}
			case <-stopChan:
				return
			}
		}
	}()

	if rotation.MaxAge > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cleanupOldLogs()
		}()
	}

	if useDB && rotation.MaxAge > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cleanupOldDBLogs()
		}()
	}

	return nil
}

func flushBatch(batch []AccessLog) {
	if len(batch) == 0 {
		return
	}

	// 写入文件
	var data []byte
	for _, entry := range batch {
		jsonData, err := json.Marshal(entry)
		if err != nil {
			jsonData = []byte(`{"error":"json_marshal_failed"}`)
		}
		data = append(data, jsonData...)
		data = append(data, '\n')
	}

	// 写入前检查是否需要轮转
	checkRotation(len(data))

	var n int
	var err error
	rotationMu.Lock()
	if logFile != nil {
		n, err = logFile.Write(data)
	}
	rotationMu.Unlock()
	if err == nil {
		currentSize += int64(n)
	}

	// 写入数据库
	if useDB && logDB != nil {
		select {
		case writeDBSem <- struct{}{}:
			go func() {
				defer func() { <-writeDBSem }()
				writeToDB(batch)
			}()
		default:
			writeToDB(batch)
		}
	}
}

// writeToDB 写入日志到数据库
func writeToDB(batch []AccessLog) {
	var records []*logdb.AccessLogRecord
	for _, entry := range batch {
		record := &logdb.AccessLogRecord{
			Timestamp:     entry.Timestamp,
			ClientIP:      entry.ClientIP,
			Method:        entry.Method,
			Host:          entry.Host,
			Path:          entry.Path,
			Query:         entry.Query,
			Status:        entry.Status,
			Action:        entry.Action,
			RequestID:     entry.RequestID,
			UserAgent:     entry.UserAgent,
			Referer:       entry.Referer,
			ContentType:   entry.ContentType,
			BodySize:      entry.BodySize,
			LatencyMs:     entry.LatencyMs,
			UpstreamAddr:  entry.UpstreamAddr,
			RuleID:        entry.RuleID,
			MatchDetail:   entry.MatchDetail,
			MatchLocation: entry.MatchLocation,
			GeoCountry:    entry.GeoCountry,
			GeoCity:       entry.GeoCity,
			GeoFlag:       entry.GeoFlag,
		}
		records = append(records, record)
	}

	if len(records) > 0 {
		logDB.BatchInsertLogs(records)
	}
}

// cleanupOldDBLogs 清理数据库中的旧日志
func cleanupOldDBLogs() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if logDB != nil && rotation.MaxAge > 0 {
				logDB.CleanOldLogs(rotation.MaxAge)
			}
		case <-stopChan:
			return
		}
	}
}

// checkRotation 检查是否需要轮转
func checkRotation(dataSize int) {
	rotationMu.Lock()
	defer rotationMu.Unlock()

	// 检查文件大小是否超过限制
	maxSizeBytes := int64(rotation.MaxSize) * 1024 * 1024
	if currentSize+int64(dataSize) > maxSizeBytes {
		rotateLog()
	}
}

// rotateLog 执行日志轮转
func rotateLog() {
	if logFile == nil {
		return
	}

	// 关闭当前文件
	logFile.Close()

	// 重命名当前文件
	base := filepath.Dir(logFilePath)
	name := filepath.Base(logFilePath)
	timestamp := time.Now().Format("2006-01-02T15-04-05")
	backupPath := filepath.Join(base, name+"."+timestamp)

	err := os.Rename(logFilePath, backupPath)
	if err != nil {
		// 重命名失败，尝试直接删除
		os.Remove(logFilePath)
	}

	// 压缩旧文件（如果配置了压缩）
	if rotation.Compress && err == nil {
		go compressFile(backupPath)
	}

	// 清理旧文件
	cleanOldBackups()

	// 创建新文件
	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	logFile = f
	currentSize = 0
}

// compressFile 压缩日志文件
func compressFile(filePath string) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		log.Printf("compress read %s: %v", filePath, err)
		return
	}

	gzPath := filePath + ".gz"
	f, err := os.Create(gzPath)
	if err != nil {
		log.Printf("compress create %s: %v", gzPath, err)
		return
	}
	defer f.Close()

	w := gzip.NewWriter(f)
	if _, err := w.Write(data); err != nil {
		log.Printf("compress write %s: %v", gzPath, err)
		return
	}
	if err := w.Close(); err != nil {
		log.Printf("compress close %s: %v", gzPath, err)
		return
	}
	os.Remove(filePath)
	log.Printf("compressed %s -> %s", filePath, gzPath)
}

// cleanOldBackups 清理旧的备份文件
func cleanOldBackups() {
	if rotation.MaxBackups <= 0 {
		return
	}

	base := filepath.Dir(logFilePath)
	name := filepath.Base(logFilePath)

	// 查找所有备份文件
	pattern := filepath.Join(base, name+".*")
	matches, _ := filepath.Glob(pattern)

	// 如果备份数量超过限制，删除最旧的
	if len(matches) > rotation.MaxBackups {
		// 按修改时间排序
		type fileInfo struct {
			path    string
			modTime time.Time
		}
		var files []fileInfo
		for _, m := range matches {
			stat, err := os.Stat(m)
			if err == nil {
				files = append(files, fileInfo{path: m, modTime: stat.ModTime()})
			}
		}

		// 按时间排序（旧的在前）
		for i := 0; i < len(files); i++ {
			for j := i + 1; j < len(files); j++ {
				if files[i].modTime.After(files[j].modTime) {
					files[i], files[j] = files[j], files[i]
				}
			}
		}

		// 删除最旧的文件
		for i := 0; i < len(files)-rotation.MaxBackups; i++ {
			os.Remove(files[i].path)
		}
	}
}

// cleanupOldLogs 定期清理过期日志
func cleanupOldLogs() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if rotation.MaxAge <= 0 {
				continue
			}

			base := filepath.Dir(logFilePath)
			name := filepath.Base(logFilePath)
			pattern := filepath.Join(base, name+".*")
			matches, _ := filepath.Glob(pattern)

			cutoff := time.Now().AddDate(0, 0, -rotation.MaxAge)
			for _, m := range matches {
				stat, err := os.Stat(m)
				if err == nil && stat.ModTime().Before(cutoff) {
					os.Remove(m)
				}
			}
		case <-stopChan:
			return
		}
	}
}

// SetLogCallback 设置日志回调函数
func SetLogCallback(callback func(AccessLog)) {
	callbackMu.Lock()
	defer callbackMu.Unlock()
	logCallback = callback
}

// Write 写入日志（应用字段配置）
func Write(entry AccessLog) {
	fieldMu.RLock()
	fc := fieldConfig
	fieldMu.RUnlock()
	entry.ApplyFieldConfig(fc)

	callbackMu.RLock()
	hasCallback := logCallback != nil
	callbackMu.RUnlock()
	if hasCallback {
		select {
		case callbackChan <- entry:
		default:
		}
	}

	select {
	case logChan <- entry:
	default:
		atomic.AddUint64(&dropCount, 1)
	}
}

// WriteRaw 写入原始日志（不应用字段配置）
func WriteRaw(entry AccessLog) {
	select {
	case logChan <- entry:
	default:
		atomic.AddUint64(&dropCount, 1)
	}
}

// GetDropCount 获取日志丢弃计数
func GetDropCount() uint64 {
	return atomic.LoadUint64(&dropCount)
}

// Close 关闭日志系统
func Close() {
	closeOnce.Do(func() {
		close(stopChan)
		close(logChan)
		close(callbackChan)
		wg.Wait()
		if logFile != nil {
			logFile.Close()
		}
	})
}

// GetFieldConfig 获取当前字段配置
func GetFieldConfig() LogFieldConfig {
	fieldMu.RLock()
	defer fieldMu.RUnlock()
	return fieldConfig
}

// SetFieldConfig 设置字段配置
func SetFieldConfig(config LogFieldConfig) {
	fieldMu.Lock()
	defer fieldMu.Unlock()
	fieldConfig = config
}

// GetLogDB 获取日志数据库实例
func GetLogDB() *logdb.LogDB {
	return logDB
}

// UpdateRotationConfig 运行时更新日志轮转配置
func UpdateRotationConfig(maxSize, maxBackups, maxAge int, compress bool) {
	rotationMu.Lock()
	defer rotationMu.Unlock()
	if maxSize > 0 {
		rotation.MaxSize = maxSize
	}
	if maxBackups >= 0 {
		rotation.MaxBackups = maxBackups
	}
	if maxAge > 0 {
		rotation.MaxAge = maxAge
	}
	rotation.Compress = compress
}

// GetRotationConfig 获取当前日志轮转配置
func GetRotationConfig() RotationConfig {
	rotationMu.Lock()
	defer rotationMu.Unlock()
	return rotation
}

// IsUsingDB 是否使用数据库存储
func IsUsingDB() bool {
	return useDB
}
