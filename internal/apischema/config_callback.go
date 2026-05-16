package apischema

// SessionConfigInitFunc 初始化 Session 配置的回调函数类型
type SessionConfigInitFunc func(ttlHours, absoluteTTLHours int)

// RateLimitConfigInitFunc 初始化限流配置的回调函数类型
type RateLimitConfigInitFunc func(limit int, windowMinutes int)

var (
	sessionConfigInit    SessionConfigInitFunc
	rateLimitConfigInit  RateLimitConfigInitFunc
)

// RegisterSessionConfigInit 注册 Session 配置初始化回调
func RegisterSessionConfigInit(fn SessionConfigInitFunc) {
	sessionConfigInit = fn
}

// RegisterRateLimitConfigInit 注册限流配置初始化回调
func RegisterRateLimitConfigInit(fn RateLimitConfigInitFunc) {
	rateLimitConfigInit = fn
}

// InitSessionConfig 通过回调初始化 Session 配置
func InitSessionConfig(ttlHours, absoluteTTLHours int) {
	if sessionConfigInit != nil {
		sessionConfigInit(ttlHours, absoluteTTLHours)
	}
}

// InitRateLimitConfig 通过回调初始化限流配置
func InitRateLimitConfig(limit int, windowMinutes int) {
	if rateLimitConfigInit != nil {
		rateLimitConfigInit(limit, windowMinutes)
	}
}
