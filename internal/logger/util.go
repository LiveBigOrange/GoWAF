package logger

import (
	"log"
	"os"
)

// LogLevel 日志级别
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var (
	currentLevel = LevelInfo
	stdLogger    = log.New(os.Stdout, "", log.LstdFlags)
)

// SetLevel 设置日志级别
func SetLevel(level LogLevel) {
	currentLevel = level
}

// Debug 调试日志
func Debug(format string, args ...interface{}) {
	if currentLevel <= LevelDebug {
		stdLogger.Printf("[DEBUG] "+format, args...)
	}
}

// Info 信息日志
func Info(format string, args ...interface{}) {
	if currentLevel <= LevelInfo {
		stdLogger.Printf("[INFO] "+format, args...)
	}
}

// Warn 警告日志
func Warn(format string, args ...interface{}) {
	if currentLevel <= LevelWarn {
		stdLogger.Printf("[WARN] "+format, args...)
	}
}

// Error 错误日志
func Error(format string, args ...interface{}) {
	if currentLevel <= LevelError {
		stdLogger.Printf("[ERROR] "+format, args...)
	}
}

// Fatal 致命错误日志
func Fatal(format string, args ...interface{}) {
	stdLogger.Fatalf("[FATAL] "+format, args...)
}

// Print 普通日志（兼容标准库）
func Print(format string, args ...interface{}) {
	Info(format, args...)
}

// Printf 格式化日志（兼容标准库）
func Printf(format string, args ...interface{}) {
	Info(format, args...)
}

// Println 打印日志（兼容标准库）
func Println(args ...interface{}) {
	stdLogger.Println(args...)
}
