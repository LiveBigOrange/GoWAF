package limiter

import (
	"gowaf/internal/domain/security/ratelimit"
	"gowaf/internal/infra/logger"
)

// MigrateToSmartLimit 将简单限流配置迁移到智能限流引擎
// 若简单限流为默认配置（rate=0且burst=0），跳过迁移
func MigrateToSmartLimit(limiter *IPRateLimiter, smartEngine *ratelimit.Engine) error {
	if limiter == nil || smartEngine == nil {
		logger.Info("简单限流迁移跳过", "reason", "limiter或smartEngine为nil")
		return nil
	}

	r, b := limiter.GetConfig()
	if r == 0 && b == 0 {
		logger.Info("简单限流迁移跳过", "reason", "默认配置无需迁移")
		return nil
	}

	cfg := smartEngine.GetConfig()
	if cfg == nil {
		logger.Warn("简单限流迁移失败", "reason", "智能限流配置不可用")
		return nil
	}

	if r > 0 {
		cfg.IPRequestThreshold = int64(r)
	}
	if r > 0 && b > 0 {
		cfg.IPBlockThreshold = int64(float64(b) / float64(r) * 2)
	}

	smartEngine.UpdateConfig(cfg)

	logger.Info("简单限流配置迁移成功", "rate", r, "burst", b,
		"new_ip_request_threshold", cfg.IPRequestThreshold,
		"new_ip_block_threshold", cfg.IPBlockThreshold)
	return nil
}
