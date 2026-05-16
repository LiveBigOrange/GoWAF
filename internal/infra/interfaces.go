package infra

// Logger 统一日志接口，供业务域通过接口依赖而非具体实现
type Logger interface {
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// MetricsCollector 统一指标采集接口
type MetricsCollector interface {
	Increment(name string, tags ...string)
	Gauge(name string, value float64, tags ...string)
	Timing(name string, duration interface{}, tags ...string)
}

// EventPublisher 统一事件发布接口
type EventPublisher interface {
	Publish(eventType string, data interface{})
}

// ConfigProvider 统一配置提供接口
type ConfigProvider interface {
	GetString(key string) string
	GetInt(key string) int
	GetBool(key string) bool
}
