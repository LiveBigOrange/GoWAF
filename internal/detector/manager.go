package detector

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gowaf/internal/logger"
)

type DetectionResult struct {
	Detected   bool
	AttackType string
	Pattern    string
	Location   string
	Input      string
	RuleID     int
	RuleDesc   string
	Confidence float64
}

// PerfConfig 性能优化配置开关
type PerfConfig struct {
	EnableOptimizedInputBuild   bool          // 默认 true
	EnableMergedPreScreening    bool          // 默认 true
	EnableDetectionShortCircuit bool          // 默认 true
	EnableResultPool            bool          // 默认 true
	EnableDetectionCache        bool          // 默认 false
	DetectionCacheSize          int           // 默认 4096
	DetectionCacheTTL           time.Duration // 默认 60s
	DetectionCacheKeyLen        int           // 默认 128
	EnableParallelDetect        bool          // 默认 false
	ParallelThreshold           int           // 默认 5
}

// DefaultPerfConfig 返回默认性能配置
func DefaultPerfConfig() PerfConfig {
	return PerfConfig{
		EnableOptimizedInputBuild:   true,
		EnableMergedPreScreening:    true,
		EnableDetectionShortCircuit: true,
		EnableResultPool:            true,
		EnableDetectionCache:        false,
		DetectionCacheSize:          4096,
		DetectionCacheTTL:           60 * time.Second,
		DetectionCacheKeyLen:        128,
		EnableParallelDetect:        false,
		ParallelThreshold:           5,
	}
}

type detectorFuncType func(string, string, string, string, map[string][]string) (bool, string, string, int, string)

type detectorInfoType struct {
	name         string
	fn           detectorFuncType
	requiredRisk riskFlags
	alwaysScan   bool
}

type Manager struct {
	sqlDetector        *SQLInjectionDetector
	xssDetector        *XSSDetector
	cmdDetector        *CommandInjectionDetector
	pathDetector       *PathTraversalDetector
	headerDetector     *HeaderInjectionDetector
	sensitiveDetector  *SensitiveDataDetector
	ssrfDetector       *SSRFDetector
	fileUploadDetector *FileUploadDetector
	errorLeakDetector  *ErrorLeakDetector
	smuggingDetector   *RequestSmuggingDetector
	xxeDetector        *XXEDetector
	nosqlDetector      *NoSQLDetector
	sstiDetector       *SSTIDetector
	ipReputation       *IPReputationChecker
	syntaxAnalyzer     *SyntaxAnalyzer
	enabledDetectors   atomic.Value
	observationModes   atomic.Value
	configMu           sync.Mutex
	detectionCache     *DetectionCache
	perfCfg            atomic.Value
}

func NewManager() *Manager {
	m := &Manager{
		sqlDetector:        NewSQLInjectionDetector(),
		xssDetector:        NewXSSDetector(),
		cmdDetector:        NewCommandInjectionDetector(),
		pathDetector:       NewPathTraversalDetector(),
		headerDetector:     NewHeaderInjectionDetector(),
		sensitiveDetector:  NewSensitiveDataDetector(),
		ssrfDetector:       NewSSRFDetector(),
		fileUploadDetector: NewFileUploadDetector(),
		errorLeakDetector:  NewErrorLeakDetector(),
		smuggingDetector:   NewRequestSmuggingDetector(),
		xxeDetector:        NewXXEDetector(),
		nosqlDetector:      NewNoSQLDetector(),
		sstiDetector:       NewSSTIDetector(),
		ipReputation:       NewIPReputationChecker(),
		syntaxAnalyzer:     NewSyntaxAnalyzer(),
	}

	enabled := make(map[string]bool, 12)
	enabled["sql_injection"] = true
	enabled["xss"] = true
	enabled["command_injection"] = true
	enabled["path_traversal"] = true
	enabled["header_injection"] = true
	enabled["sensitive_data"] = true
	enabled["ssrf"] = true
	enabled["file_upload"] = true
	enabled["error_leak"] = true
	enabled["request_smuggling"] = true
	enabled["xxe"] = true
	enabled["nosql"] = true
	enabled["ssti"] = true
	m.enabledDetectors.Store(enabled)

	observed := make(map[string]bool, 12)
	observed["sql_injection"] = false
	observed["xss"] = false
	observed["command_injection"] = false
	observed["path_traversal"] = false
	observed["header_injection"] = false
	observed["sensitive_data"] = false
	observed["ssrf"] = false
	observed["file_upload"] = false
	observed["error_leak"] = false
	observed["request_smuggling"] = false
	observed["xxe"] = false
	observed["nosql"] = false
	observed["ssti"] = false
	m.observationModes.Store(observed)

	m.perfCfg.Store(DefaultPerfConfig())

	return m
}

// SetPerfConfig 设置性能优化配置
func (m *Manager) SetPerfConfig(cfg PerfConfig) {
	m.configMu.Lock()
	defer m.configMu.Unlock()

	if cfg.EnableDetectionCache {
		if m.detectionCache == nil {
			m.detectionCache = NewDetectionCache(
				cfg.DetectionCacheSize,
				cfg.DetectionCacheTTL,
				cfg.DetectionCacheKeyLen,
			)
		}
	} else {
		m.detectionCache = nil
	}

	m.perfCfg.Store(cfg)
}

// GetPerfConfig 获取当前性能配置
func (m *Manager) GetPerfConfig() PerfConfig {
	return m.perfCfg.Load().(PerfConfig)
}

func (m *Manager) EnableDetector(detectorType string, enabled bool) {
	m.configMu.Lock()
	old := m.enabledDetectors.Load().(map[string]bool)
	newMap := make(map[string]bool, len(old))
	for k, v := range old {
		newMap[k] = v
	}
	newMap[detectorType] = enabled
	m.enabledDetectors.Store(newMap)
	if m.detectionCache != nil {
		m.detectionCache.Invalidate()
	}
	m.configMu.Unlock()
}

func (m *Manager) IsDetectorEnabled(detectorType string) bool {
	snapshot := m.enabledDetectors.Load().(map[string]bool)
	return snapshot[detectorType]
}

func (m *Manager) SetObservationMode(detectorType string, observationMode bool) {
	m.configMu.Lock()
	old := m.observationModes.Load().(map[string]bool)
	newMap := make(map[string]bool, len(old))
	for k, v := range old {
		newMap[k] = v
	}
	newMap[detectorType] = observationMode
	m.observationModes.Store(newMap)
	if m.detectionCache != nil {
		m.detectionCache.Invalidate()
	}
	m.configMu.Unlock()
}

func (m *Manager) IsObservationMode(detectorType string) bool {
	snapshot := m.observationModes.Load().(map[string]bool)
	return snapshot[detectorType]
}

func (m *Manager) detectWithDetectors(method, path, query, body string, headers http.Header) []DetectionResult {
	perfCfg := m.perfCfg.Load().(PerfConfig)

	var cacheKey uint64
	cacheEnabled := perfCfg.EnableDetectionCache && m.detectionCache != nil
	if cacheEnabled {
		cacheKey = m.detectionCache.computeCacheKey(method, path, query, body)
		if cached, ok := m.detectionCache.Get(cacheKey); ok {
			return cached
		}
	}

	enabledSnapshot := m.enabledDetectors.Load().(map[string]bool)
	observedSnapshot := m.observationModes.Load().(map[string]bool)

	input := buildDetectionInput(path, query, body, headers)
	combined := input.combined
	lowerCombined := input.lowerCombined
	decodedQuery := input.decodedQuery
	risks := preScreenRiskChars(combined, lowerCombined)

	detectors := []detectorInfoType{
		{"sql_injection", m.sqlDetector.DetectRequest, riskSQL, false},
		{"xss", m.xssDetector.DetectRequest, riskXSS, false},
		{"command_injection", m.cmdDetector.DetectRequest, riskCMD, false},
		{"path_traversal", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.pathDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, riskPath, false},
		{"header_injection", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.headerDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, riskHeader, false},
		{"ssrf", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.ssrfDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, 0, true},
		{"file_upload", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.fileUploadDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, 0, true},
		{"sensitive_data", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.sensitiveDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, 0, true},
		{"request_smuggling", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.smuggingDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, 0, true},
		{"xxe", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.xxeDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, 0, true},
		{"nosql", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.nosqlDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, 0, true},
		{"ssti", func(method, path, query, body string, h map[string][]string) (bool, string, string, int, string) {
			return m.sstiDetector.DetectRequest(method, path, query, body, http.Header(h))
		}, 0, true},
	}

	anyRisk := risks.hasAnyRisk()
	hdrMap := map[string][]string(headers)

	var results []DetectionResult

	if perfCfg.EnableParallelDetect && len(detectors) >= perfCfg.ParallelThreshold && body != "" {
		results = m.detectParallel(detectors, method, path, query, body, hdrMap, enabledSnapshot, observedSnapshot, anyRisk, risks, decodedQuery)
	} else {
		resultsPtr := acquireResults()
		defer releaseResults(resultsPtr)
		results = *resultsPtr
		results = m.detectSequential(detectors, method, path, query, body, hdrMap, enabledSnapshot, observedSnapshot, anyRisk, risks, decodedQuery, results, resultsPtr, perfCfg.EnableDetectionShortCircuit)
	}

	if m.syntaxAnalyzer != nil && risks.hasRisk(riskSQL) {
		sqlAnalysis := m.syntaxAnalyzer.AnalyzeSQLInjection(combined)
		if sqlAnalysis.IsLikelyInjection {
			reason := strings.Join(sqlAnalysis.Reasons, ", ")
			if !observedSnapshot["sql_injection"] {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "sql_injection",
					Pattern:    reason,
					Location:   "syntax",
					RuleID:     0,
					RuleDesc:   "syntax_analysis",
					Confidence: sqlAnalysis.RiskScore,
				})
			} else {
				logger.Warn("OBSERVE: sql_injection syntax_analysis pattern=%q", reason)
			}
		}
	}

	if len(results) > 1 {
		attackTypeCount := make(map[string]int)
		for _, r := range results {
			attackTypeCount[r.AttackType]++
		}
		for i := range results {
			detCount := attackTypeCount[results[i].AttackType]
			if detCount > 1 {
				results[i].Confidence = 0.95
			} else if len(results) > 1 {
				results[i].Confidence = 0.85
			}
		}
	}

	finalResults := append([]DetectionResult(nil), results...)

	if cacheEnabled && m.detectionCache != nil {
		m.detectionCache.Put(cacheKey, finalResults)
	}

	return finalResults
}

func (m *Manager) detectSequential(
	detectors []detectorInfoType,
	method, path, query, body string,
	hdrMap map[string][]string,
	enabledSnapshot, observedSnapshot map[string]bool,
	anyRisk bool,
	risks riskFlags,
	decodedQuery string,
	results []DetectionResult,
	resultsPtr *[]DetectionResult,
	shortCircuit bool,
) []DetectionResult {
	for _, det := range detectors {
		if !enabledSnapshot[det.name] {
			continue
		}
		if !anyRisk && !det.alwaysScan {
			continue
		}
		if !det.alwaysScan && !risks.hasRisk(det.requiredRisk) {
			continue
		}
		if detected, pattern, location, ruleID, ruleDesc := det.fn(method, path, query, body, hdrMap); detected {
			if observedSnapshot[det.name] {
				logger.Warn("OBSERVE: %s detected pattern=%q location=%s ruleID=%d ruleDesc=%q", det.name, pattern, location, ruleID, ruleDesc)
			} else {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: det.name,
					Pattern:    pattern,
					Location:   location,
					RuleID:     ruleID,
					RuleDesc:   ruleDesc,
					Confidence: 0.7,
				})
				*resultsPtr = results
				if shortCircuit {
					return append([]DetectionResult(nil), results...)
				}
			}
		}
		if decodedQuery != "" {
			if detected, pattern, location, ruleID, ruleDesc := det.fn(method, path, decodedQuery, body, hdrMap); detected {
				if observedSnapshot[det.name] {
					logger.Warn("OBSERVE: %s detected pattern=%q location=%s_decoded ruleID=%d ruleDesc=%q", det.name, pattern, location, ruleID, ruleDesc)
				} else {
					results = append(results, DetectionResult{
						Detected:   true,
						AttackType: det.name,
						Pattern:    pattern,
						Location:   location + "_decoded",
						RuleID:     ruleID,
						RuleDesc:   ruleDesc,
						Confidence: 0.7,
					})
					*resultsPtr = results
					if shortCircuit {
						return append([]DetectionResult(nil), results...)
					}
				}
			}
		}
	}
	return results
}

func (m *Manager) detectParallel(
	detectors []detectorInfoType,
	method, path, query, body string,
	hdrMap map[string][]string,
	enabledSnapshot, observedSnapshot map[string]bool,
	anyRisk bool,
	risks riskFlags,
	decodedQuery string,
) []DetectionResult {
	type parallelResult struct {
		detected   bool
		attackType string
		pattern    string
		location   string
		ruleID     int
		ruleDesc   string
		observed   bool
	}

	var active []detectorInfoType
	for _, det := range detectors {
		if !enabledSnapshot[det.name] {
			continue
		}
		if !anyRisk && !det.alwaysScan {
			continue
		}
		if !det.alwaysScan && !risks.hasRisk(det.requiredRisk) {
			continue
		}
		active = append(active, det)
	}

	if len(active) == 0 {
		return nil
	}

	ch := make(chan parallelResult, len(active)*2)
	var wg sync.WaitGroup

	for _, det := range active {
		det := det
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				recover()
			}()
			if detected, pattern, location, ruleID, ruleDesc := det.fn(method, path, query, body, hdrMap); detected {
				ch <- parallelResult{
					detected:   true,
					attackType: det.name,
					pattern:    pattern,
					location:   location,
					ruleID:     ruleID,
					ruleDesc:   ruleDesc,
					observed:   observedSnapshot[det.name],
				}
			}
			if decodedQuery != "" {
				if detected, pattern, location, ruleID, ruleDesc := det.fn(method, path, decodedQuery, body, hdrMap); detected {
					ch <- parallelResult{
						detected:   true,
						attackType: det.name,
						pattern:    pattern,
						location:   location + "_decoded",
						ruleID:     ruleID,
						ruleDesc:   ruleDesc,
						observed:   observedSnapshot[det.name],
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var results []DetectionResult
	for pr := range ch {
		if pr.observed {
			logger.Warn("OBSERVE: %s detected pattern=%q location=%s ruleID=%d ruleDesc=%q", pr.attackType, pr.pattern, pr.location, pr.ruleID, pr.ruleDesc)
		} else {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: pr.attackType,
				Pattern:    pr.pattern,
				Location:   pr.location,
				RuleID:     pr.ruleID,
				RuleDesc:   pr.ruleDesc,
				Confidence: 0.7,
			})
		}
	}

	return results
}

func (m *Manager) DetectRequest(r *http.Request) []DetectionResult {
	return m.detectWithDetectors(r.Method, r.URL.Path, r.URL.RawQuery, "", r.Header)
}

func (m *Manager) DetectRequestWithBody(r *http.Request, body string) []DetectionResult {
	const maxDetectBodySize = 32 * 1024
	if len(body) > maxDetectBodySize {
		body = body[:maxDetectBodySize]
	}
	return m.detectWithDetectors(r.Method, r.URL.Path, r.URL.RawQuery, body, r.Header)
}

func (m *Manager) DetectString(input string) []DetectionResult {
	results := make([]DetectionResult, 0)
	enabledSnapshot := m.enabledDetectors.Load().(map[string]bool)

	type strDetectorFunc func(string) (bool, string, int, string)
	type strDetectorInfo struct {
		name string
		fn   strDetectorFunc
	}

	detectors := []strDetectorInfo{
		{"sql_injection", m.sqlDetector.Detect},
		{"xss", m.xssDetector.Detect},
		{"command_injection", m.cmdDetector.Detect},
		{"path_traversal", m.pathDetector.Detect},
		{"header_injection", m.headerDetector.Detect},
		{"sensitive_data", m.sensitiveDetector.Detect},
	}

	for _, det := range detectors {
		if !enabledSnapshot[det.name] {
			continue
		}
		if detected, pattern, ruleID, ruleDesc := det.fn(input); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: det.name,
				Pattern:    pattern,
				Location:   "input",
				RuleID:     ruleID,
				RuleDesc:   ruleDesc,
			})
		}
	}

	return results
}

func (m *Manager) GetStats() map[string]interface{} {
	stats := make(map[string]interface{})
	stats["sql_injection_patterns"] = m.sqlDetector.GetPatternCount()
	stats["xss_patterns"] = m.xssDetector.GetPatternCount()
	stats["command_injection_patterns"] = m.cmdDetector.GetPatternCount()
	stats["path_traversal_patterns"] = m.pathDetector.GetPatternCount()
	stats["header_injection_patterns"] = m.headerDetector.GetPatternCount()
	stats["sensitive_data_patterns"] = m.sensitiveDetector.GetPatternCount()
	stats["ssrf_patterns"] = m.ssrfDetector.GetPatternCount()
	stats["file_upload_patterns"] = m.fileUploadDetector.GetPatternCount()
	stats["error_leak_patterns"] = m.errorLeakDetector.GetPatternCount()
	stats["request_smuggling_patterns"] = m.smuggingDetector.GetPatternCount()
	stats["xxe_patterns"] = m.xxeDetector.GetPatternCount()
	stats["nosql_patterns"] = m.nosqlDetector.GetPatternCount()
	stats["ssti_patterns"] = m.sstiDetector.GetPatternCount()
	enabledSnapshot := m.enabledDetectors.Load().(map[string]bool)
	enabledCopy := make(map[string]bool, len(enabledSnapshot))
	for k, v := range enabledSnapshot {
		enabledCopy[k] = v
	}
	observedSnapshot := m.observationModes.Load().(map[string]bool)
	obsCopy := make(map[string]bool, len(observedSnapshot))
	for k, v := range observedSnapshot {
		obsCopy[k] = v
	}
	stats["enabled_detectors"] = enabledCopy
	stats["observation_modes"] = obsCopy
	if m.detectionCache != nil {
		hits, misses, size, hitRate := m.detectionCache.Stats()
		cacheStats := make(map[string]interface{})
		cacheStats["hits"] = hits
		cacheStats["misses"] = misses
		cacheStats["size"] = size
		cacheStats["hit_rate"] = hitRate
		stats["detection_cache"] = cacheStats
	}
	return stats
}

func (m *Manager) HasAttack(results []DetectionResult) bool {
	for _, result := range results {
		if result.Detected {
			return true
		}
	}
	return false
}

func (m *Manager) GetAttackTypes(results []DetectionResult) []string {
	types := make([]string, 0)
	seen := make(map[string]bool)
	for _, result := range results {
		if result.Detected && !seen[result.AttackType] {
			types = append(types, result.AttackType)
			seen[result.AttackType] = true
		}
	}
	return types
}

func (m *Manager) FormatResults(results []DetectionResult) string {
	if len(results) == 0 {
		return "no attack detected"
	}
	var parts []string
	for _, result := range results {
		parts = append(parts, result.AttackType+"@"+result.Location)
	}
	return strings.Join(parts, ", ")
}

func (m *Manager) AggregateScore(results []DetectionResult) float64 {
	if len(results) == 0 {
		return 0
	}
	seenTypes := make(map[string]bool)
	var total float64
	for _, r := range results {
		if !r.Detected {
			continue
		}
		conf := r.Confidence
		if conf <= 0 {
			conf = 0.7
		}
		if seenTypes[r.AttackType] {
			conf *= 0.5
		}
		seenTypes[r.AttackType] = true
		total += conf
	}
	if total > 1.0 {
		total = 1.0
	}
	return total
}

func (m *Manager) CheckIPReputation(ip string) (bool, string) {
	if m.ipReputation == nil {
		return false, ""
	}
	return m.ipReputation.Check(ip)
}

func (m *Manager) DetectResponse(body string, statusCode int) []DetectionResult {
	results := make([]DetectionResult, 0)
	enabledSnapshot := m.enabledDetectors.Load().(map[string]bool)
	observedSnapshot := m.observationModes.Load().(map[string]bool)
	if enabledSnapshot["error_leak"] && m.errorLeakDetector != nil {
		if detected, pattern, location, ruleID, ruleDesc := m.errorLeakDetector.DetectResponse(body, statusCode); detected {
			results = append(results, DetectionResult{
				Detected:   true,
				AttackType: "error_leak",
				Pattern:    pattern,
				Location:   location,
				RuleID:     ruleID,
				RuleDesc:   ruleDesc,
				Confidence: 0.8,
			})
		}
	}
	if enabledSnapshot["sensitive_data"] && m.sensitiveDetector != nil {
		if detected, pattern, ruleID, ruleDesc := m.sensitiveDetector.Detect(body); detected {
			if observedSnapshot["sensitive_data"] {
				logger.Warn("OBSERVE: sensitive_data detected in response pattern=%q ruleID=%d", pattern, ruleID)
			} else {
				results = append(results, DetectionResult{
					Detected:   true,
					AttackType: "sensitive_data",
					Pattern:    pattern,
					Location:   "response_body",
					RuleID:     ruleID,
					RuleDesc:   ruleDesc,
					Confidence: 0.6,
				})
			}
		}
	}
	return results
}
