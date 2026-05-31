package rules

// ruleSnapshot 存储不可变规则快照，检测热路径通过 atomic.Value 无锁读取
type ruleSnapshot struct {
	blackIPs     []ipEntry
	whiteIPs     []ipEntry
	blackIPExact map[string]bool
	whiteIPExact map[string]bool

	uaWhitelist []uaRule
	uaBlacklist []uaRule

	pathWhitelist []pathRule
	pathBlacklist []pathRule

	geoBlockCountries map[string]bool
	geoMode           string

	allowedMethods map[string]bool

	pathRateLimiters map[string]*pathLimiterEntry

	pathDecoder *PathDecoder
}

// buildRuleSnapshot 从数据库构建完整规则快照
func (e *Engine) buildRuleSnapshot() *ruleSnapshot {
	blackIPs, whiteIPs, blackIPExact, whiteIPExact := e.buildIPRules()
	uaWhitelist, uaBlacklist := e.buildUARules()
	pathWhitelist, pathBlacklist := e.buildPathRules()
	geoBlockCountries, geoMode := e.buildGeoRules()
	allowedMethods := e.buildAllowedMethods()
	pathRateLimiters := e.buildPathRateLimits()

	return &ruleSnapshot{
		blackIPs:          blackIPs,
		whiteIPs:          whiteIPs,
		blackIPExact:      blackIPExact,
		whiteIPExact:      whiteIPExact,
		uaWhitelist:       uaWhitelist,
		uaBlacklist:       uaBlacklist,
		pathWhitelist:     pathWhitelist,
		pathBlacklist:     pathBlacklist,
		geoBlockCountries: geoBlockCountries,
		geoMode:           geoMode,
		allowedMethods:    allowedMethods,
		pathRateLimiters:  pathRateLimiters,
		pathDecoder:       NewPathDecoder(true, 2),
	}
}

// loadSnapshot 原子读取当前规则快照（无锁，检测热路径使用）
func (e *Engine) loadSnapshot() *ruleSnapshot {
	return e.snapshot.Load().(*ruleSnapshot)
}

// updateSnapshot 在 configMu 保护下更新快照，fn 接收当前快照并返回新快照
func (e *Engine) updateSnapshot(fn func(cur *ruleSnapshot) *ruleSnapshot) {
	e.configMu.Lock()
	defer e.configMu.Unlock()
	cur := e.snapshot.Load().(*ruleSnapshot)
	e.snapshot.Store(fn(cur))
}
