package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

var (
	currentLevel    atomic.Int32
	stdLogger       = log.New(os.Stdout, "", log.LstdFlags)
	captureWriter   = &ringCaptureWriter{}
	inLogAndCapture int32
)

func init() {
	currentLevel.Store(int32(LevelInfo))
	log.SetOutput(captureWriter)
}

type ringCaptureWriter struct{}

func (w *ringCaptureWriter) Write(p []byte) (int, error) {
	line := string(p)
	if len(line) > 0 && line[len(line)-1] == '\n' {
		line = line[:len(line)-1]
	}
	if atomic.LoadInt32(&inLogAndCapture) == 0 {
		addRingEntry(line)
	}
	n, err := os.Stdout.Write(p)
	return n, err
}

func logAndCapture(prefix, format string, args ...interface{}) {
	msg := fmt.Sprintf(prefix+format, args...)
	atomic.StoreInt32(&inLogAndCapture, 1)
	stdLogger.Print(msg)
	atomic.StoreInt32(&inLogAndCapture, 0)
	now := time.Now().Format("2006/01/02 15:04:05")
	addRingEntry(now + " " + msg)
}

// GetLevel 获取当前日志级别
func GetLevel() LogLevel {
	return LogLevel(currentLevel.Load())
}

// ParseLevel 将字符串解析为LogLevel
func ParseLevel(s string) LogLevel {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal":
		return LevelFatal
	default:
		return LevelInfo
	}
}

// LevelString 将LogLevel转为字符串
func LevelString(l LogLevel) string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelFatal:
		return "fatal"
	default:
		return "info"
	}
}

// SetLevel 设置日志级别
func SetLevel(level LogLevel) {
	currentLevel.Store(int32(level))
}

func Debug(format string, args ...interface{}) {
	if GetLevel() <= LevelDebug {
		logAndCapture("[DEBUG] ", format, args...)
	}
}

func Info(format string, args ...interface{}) {
	if GetLevel() <= LevelInfo {
		logAndCapture("[INFO] ", format, args...)
	}
}

func Warn(format string, args ...interface{}) {
	if GetLevel() <= LevelWarn {
		logAndCapture("[WARN] ", format, args...)
	}
}

func Error(format string, args ...interface{}) {
	if GetLevel() <= LevelError {
		logAndCapture("[ERROR] ", format, args...)
	}
}

func Fatal(format string, args ...interface{}) {
	msg := fmt.Sprintf("[FATAL] "+format, args...)
	atomic.StoreInt32(&inLogAndCapture, 1)
	stdLogger.Print(msg)
	atomic.StoreInt32(&inLogAndCapture, 0)
	now := time.Now().Format("2006/01/02 15:04:05")
	addRingEntry(now + " " + msg)
	os.Exit(1)
}

func Print(format string, args ...interface{}) {
	logAndCapture("[INFO] ", format, args...)
}

func Printf(format string, args ...interface{}) {
	logAndCapture("[INFO] ", format, args...)
}

func Println(args ...interface{}) {
	msg := fmt.Sprint(args...)
	logAndCapture("[INFO] ", "%s", msg)
}
