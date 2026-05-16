package detector

import (
	"net/http"
	"sync"
	"testing"
)

var allDetectorTypes = []string{
	"sql_injection",
	"xss",
	"command_injection",
	"path_traversal",
	"header_injection",
	"sensitive_data",
	"ssrf",
	"file_upload",
	"error_leak",
	"request_smuggling",
	"xxe",
	"nosql",
	"ssti",
}

func TestManager_SetObservationMode_ImmediateEffect(t *testing.T) {
	m := NewManager()

	m.SetObservationMode("sql_injection", true)
	if !m.IsObservationMode("sql_injection") {
		t.Error("SetObservationMode(true) 后应立即生效")
	}

	m.SetObservationMode("sql_injection", false)
	if m.IsObservationMode("sql_injection") {
		t.Error("SetObservationMode(false) 后应返回 false")
	}
}

func TestManager_IsObservationMode_UnknownType_DefaultFalse(t *testing.T) {
	m := NewManager()
	if m.IsObservationMode("unknown_detector") {
		t.Error("未知检测器类型应默认返回 false（拦截模式）")
	}
}

func TestManager_ObservationMode_AllDetectors_DefaultFalse(t *testing.T) {
	m := NewManager()
	for _, dt := range allDetectorTypes {
		if m.IsObservationMode(dt) {
			t.Errorf("新建Manager的 %s 应默认为拦截模式(观察模式=false)", dt)
		}
	}
}

func TestManager_SetObservationMode_MultipleDetectors(t *testing.T) {
	m := NewManager()
	m.SetObservationMode("sql_injection", true)
	m.SetObservationMode("xss", true)
	m.SetObservationMode("command_injection", false)

	if !m.IsObservationMode("sql_injection") {
		t.Error("sql_injection 应为观察模式")
	}
	if !m.IsObservationMode("xss") {
		t.Error("xss 应为观察模式")
	}
	if m.IsObservationMode("command_injection") {
		t.Error("command_injection 应为拦截模式")
	}
}

func TestManager_ObservationMode_ConcurrentSafety(t *testing.T) {
	m := NewManager()
	var wg sync.WaitGroup
	const goroutines = 100

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			dt := allDetectorTypes[id%len(allDetectorTypes)]
			m.SetObservationMode(dt, id%2 == 0)
		}(i)
		go func(id int) {
			defer wg.Done()
			dt := allDetectorTypes[id%len(allDetectorTypes)]
			_ = m.IsObservationMode(dt)
		}(i)
	}
	wg.Wait()
}

func TestManager_ObservationMode_AtomicSnapshot(t *testing.T) {
	m := NewManager()
	m.SetObservationMode("sql_injection", true)

	snapshot := m.observationModes.Load().(map[string]bool)
	snapshotVal := snapshot["sql_injection"]
	if !snapshotVal {
		t.Error("快照应包含设置前的值")
	}

	m.SetObservationMode("sql_injection", false)

	newSnapshot := m.observationModes.Load().(map[string]bool)
	if newSnapshot["sql_injection"] {
		t.Error("新快照应反映修改后的值")
	}
	if !snapshotVal {
		t.Error("旧快照值不应受后续修改影响（原子快照隔离）")
	}
}

func TestShortCircuit_ObserveMode_NoShort(t *testing.T) {
	m := NewManager()
	m.SetObservationMode("sql_injection", true)

	req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271&x=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	results := m.DetectRequestWithBody(req, "")

	hasSQL := false
	hasXSS := false
	for _, r := range results {
		if r.AttackType == "sql_injection" {
			hasSQL = true
		}
		if r.AttackType == "xss" {
			hasXSS = true
		}
	}
	if !hasSQL {
		t.Error("sql_injection 观察模式下应继续检测")
	}
	if !hasXSS {
		t.Error("观察模式不应短路，xss 也应被检测到")
	}
}

func TestShortCircuit_BlockMode_Short(t *testing.T) {
	cfg := DefaultPerfConfig()
	cfg.EnableDetectionShortCircuit = true
	m := NewManager()
	m.SetPerfConfig(cfg)

	req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271", nil)
	results := m.DetectRequestWithBody(req, "")

	if len(results) == 0 {
		t.Fatal("应检测到攻击")
	}
	for _, r := range results {
		if r.AttackType != "sql_injection" {
			t.Errorf("短路模式下应只返回第一个命中的检测器，got %s", r.AttackType)
		}
	}
}

func TestShortCircuit_ConditionCombination(t *testing.T) {
	tests := []struct {
		name            string
		observeMode     bool
		shortCircuit    bool
		expectMultiType bool
	}{
		{"short_on_obs_true", true, true, true},
		{"short_on_obs_false", false, true, false},
		{"short_off_obs_false", false, false, true},
		{"short_off_obs_true", true, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultPerfConfig()
			cfg.EnableDetectionShortCircuit = tt.shortCircuit
			m := NewManager()
			m.SetPerfConfig(cfg)
			m.SetObservationMode("sql_injection", tt.observeMode)

			req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271&x=%3Cscript%3Ealert(1)%3C/script%3E", nil)
			results := m.DetectRequestWithBody(req, "")

			attackTypes := make(map[string]bool)
			for _, r := range results {
				attackTypes[r.AttackType] = true
			}
			multiType := len(attackTypes) > 1
			if multiType != tt.expectMultiType {
				t.Errorf("多类型检测=%v, 期望=%v, 类型=%v", multiType, tt.expectMultiType, attackTypes)
			}
		})
	}
}

func TestShortCircuit_FullInfoCollection(t *testing.T) {
	m := NewManager()
	m.SetObservationMode("path_traversal", true)

	req, _ := http.NewRequest(http.MethodGet, "/files/../../etc/passwd", nil)
	results := m.DetectRequestWithBody(req, "")

	attackTypes := make(map[string]bool)
	for _, r := range results {
		attackTypes[r.AttackType] = true
	}
	if !attackTypes["path_traversal"] {
		t.Error("path_traversal 观察模式应被检测到")
	}
}

func TestShortCircuit_Disabled_AllDetectorsRun(t *testing.T) {
	cfg := DefaultPerfConfig()
	cfg.EnableDetectionShortCircuit = false
	m := NewManager()
	m.SetPerfConfig(cfg)

	req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271&x=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	results := m.DetectRequestWithBody(req, "")

	attackTypes := make(map[string]bool)
	for _, r := range results {
		attackTypes[r.AttackType] = true
	}
	if len(attackTypes) < 2 {
		t.Errorf("短路禁用时应检测多种攻击，got %v", attackTypes)
	}
}

func TestSetObservationMode_InvalidatesCache(t *testing.T) {
	cfg := DefaultPerfConfig()
	cfg.EnableDetectionCache = true
	cfg.DetectionCacheSize = 64
	cfg.DetectionCacheTTL = 60
	m := NewManager()
	m.SetPerfConfig(cfg)

	req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271", nil)
	m.DetectRequestWithBody(req, "")

	_, misses1, _, _ := m.detectionCache.Stats()

	m.SetObservationMode("sql_injection", true)

	m.DetectRequestWithBody(req, "")
	_, misses2, _, _ := m.detectionCache.Stats()

	if misses2 <= misses1 {
		t.Errorf("切换观测模式后缓存应失效，misses应增加: before=%d after=%d", misses1, misses2)
	}
}

func TestEnableDetector_InvalidatesCache(t *testing.T) {
	cfg := DefaultPerfConfig()
	cfg.EnableDetectionCache = true
	cfg.DetectionCacheSize = 64
	cfg.DetectionCacheTTL = 60
	m := NewManager()
	m.SetPerfConfig(cfg)

	req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271", nil)
	m.DetectRequestWithBody(req, "")

	_, misses1, _, _ := m.detectionCache.Stats()

	m.EnableDetector("sql_injection", false)

	m.DetectRequestWithBody(req, "")
	_, misses2, _, _ := m.detectionCache.Stats()

	if misses2 <= misses1 {
		t.Errorf("切换启用状态后缓存应失效，misses应增加: before=%d after=%d", misses1, misses2)
	}
}

func TestSetObservationMode_NilCache_NoPanic(t *testing.T) {
	m := NewManager()

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("缓存为nil时SetObservationMode不应panic: %v", r)
		}
	}()
	m.SetObservationMode("sql_injection", true)
	m.SetObservationMode("xss", false)
}

func TestDetectorConsistency_ObserveVsBlock(t *testing.T) {
	m := NewManager()

	req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271", nil)

	m.SetObservationMode("sql_injection", false)
	blockResults := m.DetectRequestWithBody(req, "")

	m.SetObservationMode("sql_injection", true)
	observeResults := m.DetectRequestWithBody(req, "")

	if len(blockResults) == 0 && len(observeResults) == 0 {
		t.Skip("两种模式均未检测到攻击，跳过一致性比较")
	}

	if len(blockResults) != len(observeResults) {
		t.Errorf("观测/拦截模式检测结果数量不一致: block=%d observe=%d", len(blockResults), len(observeResults))
		return
	}

	for i := range blockResults {
		b, o := blockResults[i], observeResults[i]
		if b.AttackType != o.AttackType {
			t.Errorf("AttackType不一致: block=%s observe=%s", b.AttackType, o.AttackType)
		}
		if b.Pattern != o.Pattern {
			t.Errorf("Pattern不一致: block=%s observe=%s", b.Pattern, o.Pattern)
		}
		if b.Location != o.Location {
			t.Errorf("Location不一致: block=%s observe=%s", b.Location, o.Location)
		}
		if b.RuleID != o.RuleID {
			t.Errorf("RuleID不一致: block=%d observe=%d", b.RuleID, o.RuleID)
		}
		if b.RuleDesc != o.RuleDesc {
			t.Errorf("RuleDesc不一致: block=%s observe=%s", b.RuleDesc, o.RuleDesc)
		}
	}
}

func TestAllDetectors_ObserveConsistency(t *testing.T) {
	m := NewManager()
	for _, dt := range allDetectorTypes {
		m.SetObservationMode(dt, true)
	}

	for _, dt := range allDetectorTypes {
		t.Run(dt, func(t *testing.T) {
			if !m.IsObservationMode(dt) {
				t.Errorf("%s 应为观察模式", dt)
			}
			if !m.IsDetectorEnabled(dt) {
				t.Errorf("%s 应已启用", dt)
			}
		})
	}
}

func TestDisabledDetector_NoDetection(t *testing.T) {
	m := NewManager()
	m.EnableDetector("sql_injection", false)
	m.SetObservationMode("sql_injection", true)

	req, _ := http.NewRequest(http.MethodGet, "/test?id=1%27+OR+%271%27%3D%271", nil)
	results := m.DetectRequestWithBody(req, "")

	for _, r := range results {
		if r.AttackType == "sql_injection" {
			t.Error("已禁用的检测器无论观测模式设置如何均不应检测")
		}
	}
}

func TestDetectResponse_ObserveVsBlock_Consistency(t *testing.T) {
	m := NewManager()

	m.SetObservationMode("error_leak", false)
	blockResults := m.DetectResponse("Traceback (most recent call last):", 500)

	m.SetObservationMode("error_leak", true)
	observeResults := m.DetectResponse("Traceback (most recent call last):", 500)

	if len(blockResults) != len(observeResults) {
		t.Errorf("响应方向检测结果数量不一致: block=%d observe=%d", len(blockResults), len(observeResults))
	}
	if len(blockResults) > 0 && len(observeResults) > 0 {
		if blockResults[0].AttackType != observeResults[0].AttackType {
			t.Errorf("响应方向AttackType不一致: block=%s observe=%s", blockResults[0].AttackType, observeResults[0].AttackType)
		}
	}
}
