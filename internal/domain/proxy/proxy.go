package proxy

import (
	crypto_rand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gowaf/internal/cert/acme"
	"gowaf/internal/backend"
	"gowaf/internal/domain/security/bot"
	"gowaf/internal/infra/config/config"
	"gowaf/internal/domain/security/detector"
	"gowaf/internal/domain/security/dlprule"
	"gowaf/internal/domain/security/limiter"
	"gowaf/internal/infra/storage/metrics"
	"gowaf/internal/infra/notify"
	"gowaf/internal/domain/proxy/pathbodylimit"
	"gowaf/internal/domain/proxyconfig"
	"gowaf/internal/domain/security/ratelimit"
	"gowaf/internal/domain/auxiliary/reqheader"
	"gowaf/internal/domain/auxiliary/respheader"
	"gowaf/internal/domain/security/rules"
	"gowaf/internal/domain/security/vpatch"

	"gowaf/internal/apischema"
)

var IntelCollectFn func(eventType string, eventData map[string]interface{})

type WAFProxy struct {
	ruleEngine             *rules.Engine
	limiter                *limiter.IPRateLimiter
	cfg                    *config.Config
	backendManager         *backend.Manager
	metricsManager         *metrics.Manager
	proxy                  *httputil.ReverseProxy
	detectorManager        *detector.Manager
	proxyConfigMgr         *proxyconfig.Manager
	rateLimitEngine        *ratelimit.Engine
	rateLimitKeyCfg        limiter.RateLimitKeyConfig
	notifyEngine           *notify.Engine
	botManager             *bot.Manager
	vpatchManager          *vpatch.Manager
	respHeaderMgr          *respheader.Manager
	pathBodyLimitMgr       *pathbodylimit.Manager
	dlpRuleMgr             *dlprule.Manager
	apiSchemaMgr           *apischema.Manager
	reqHeaderMgr           *reqheader.Manager
	acmeMgr                *acme.Manager
	maxRequestBodyProvider MaxRequestBodyProvider
	metricEventCh          chan metricEvent
	metricStopCh           chan struct{}
	metricDropCount        uint64
	trustedProxyMatcher    *trustedProxyMatcher
}

func NewWAFProxy(cfg *config.Config, engine *rules.Engine, lim *limiter.IPRateLimiter, bm *backend.Manager, mm *metrics.Manager, pcm *proxyconfig.Manager) (*WAFProxy, error) {
	p := &WAFProxy{
		ruleEngine:          engine,
		limiter:             lim,
		cfg:                 cfg,
		backendManager:      bm,
		metricsManager:      mm,
		detectorManager:     detector.NewManager(),
		proxyConfigMgr:      pcm,
		metricEventCh:       make(chan metricEvent, 1000),
		metricStopCh:        make(chan struct{}),
		trustedProxyMatcher: newTrustedProxyMatcher(cfg.TrustedProxies),
	}

	p.proxy = &httputil.ReverseProxy{
		Director:       p.director,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.errorHandler,
		Transport: &http.Transport{
			MaxIdleConns:          500,
			MaxIdleConnsPerHost:   100,
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    cfg.Performance.DisableCompression,
			ForceAttemptHTTP2:     true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	go p.metricEventWorker()
	return p, nil
}

// ApplyDetectorConfig 应用检测器配置
func (p *WAFProxy) ApplyDetectorConfig(detectorType string, enabled bool) {
	if p.detectorManager != nil {
		p.detectorManager.EnableDetector(detectorType, enabled)
	}
}

// ApplyObservationMode 应用观察模式配置
func (p *WAFProxy) ApplyObservationMode(detectorType string, observationMode bool) {
	if p.detectorManager != nil {
		p.detectorManager.SetObservationMode(detectorType, observationMode)
	}
}

// GetDetectorManager 获取检测器管理器
func (p *WAFProxy) GetDetectorManager() *detector.Manager {
	return p.detectorManager
}

// SetRateLimitEngine 设置智能限流引擎
func (p *WAFProxy) SetRateLimitEngine(e *ratelimit.Engine) {
	p.rateLimitEngine = e
}

// SetBotManager 设置Bot管理器
func (p *WAFProxy) SetBotManager(m *bot.Manager) {
	p.botManager = m
}

// SetVPatchManager 设置虚拟补丁管理器
func (p *WAFProxy) SetVPatchManager(m *vpatch.Manager) {
	p.vpatchManager = m
}

// SetRespHeaderManager 设置响应头管理器
func (p *WAFProxy) SetRespHeaderManager(m *respheader.Manager) {
	p.respHeaderMgr = m
}

func (p *WAFProxy) SetACMEManager(m *acme.Manager) {
	p.acmeMgr = m
}

// SetMaxRequestBodyProvider 设置最大请求体大小提供者，解耦与middleware包的依赖
func (p *WAFProxy) SetMaxRequestBodyProvider(provider MaxRequestBodyProvider) {
	p.maxRequestBodyProvider = provider
}

func (p *WAFProxy) SetReqHeaderManager(m *reqheader.Manager) {
	p.reqHeaderMgr = m
}

// SetPathBodyLimitManager 设置路径级请求体限制管理器
func (p *WAFProxy) SetPathBodyLimitManager(m *pathbodylimit.Manager) {
	p.pathBodyLimitMgr = m
}

// SetDLPRuleManager 设置DLP规则管理器
func (p *WAFProxy) SetDLPRuleManager(m *dlprule.Manager) {
	p.dlpRuleMgr = m
}

// SetAPISchemaManager 设置API Schema管理器
func (p *WAFProxy) SetAPISchemaManager(m *apischema.Manager) {
	p.apiSchemaMgr = m
}

// GetLimiter 返回限流器实例，供 Handler 层调用
func (p *WAFProxy) GetLimiter() *limiter.IPRateLimiter {
	return p.limiter
}

func (p *WAFProxy) SetRateLimitKeyConfig(cfg limiter.RateLimitKeyConfig) {
	p.rateLimitKeyCfg = cfg
}

func (p *WAFProxy) SetNotifyEngine(e *notify.Engine) {
	p.notifyEngine = e
}

func (p *WAFProxy) GetRateLimitKeyConfig() limiter.RateLimitKeyConfig {
	return p.rateLimitKeyCfg
}

var (
	wafGlobalEnabled   = true
	wafGlobalEnabledMu sync.RWMutex
)

func IsWAFGlobalEnabled() bool {
	wafGlobalEnabledMu.RLock()
	defer wafGlobalEnabledMu.RUnlock()
	return wafGlobalEnabled
}

func SetGlobalEnabled(enabled bool) {
	wafGlobalEnabledMu.Lock()
	defer wafGlobalEnabledMu.Unlock()
	wafGlobalEnabled = enabled
}

var powDifficulty atomic.Int32

func init() {
	powDifficulty.Store(4)
}

func SetPoWDifficulty(d int) {
	if d > 0 && d <= 6 {
		powDifficulty.Store(int32(d))
	}
}

var (
	powChallenges   = make(map[string]int)
	powChallengesMu sync.RWMutex

	jsChallenges   = make(map[string]time.Time)
	jsChallengesMu sync.RWMutex
)

func storePoWChallenge(challenge string, difficulty int) {
	powChallengesMu.Lock()
	powChallenges[challenge] = difficulty
	powChallengesMu.Unlock()
}

func getPoWDifficulty(challenge string) (int, bool) {
	powChallengesMu.RLock()
	diff, ok := powChallenges[challenge]
	powChallengesMu.RUnlock()
	return diff, ok
}

func (p *WAFProxy) verifyPoW(r *http.Request) bool {
	cookie, err := r.Cookie("gowaf_pow")
	if err != nil {
		return false
	}
	parts := strings.SplitN(cookie.Value, ":", 2)
	if len(parts) != 2 {
		return false
	}
	challenge := parts[0]
	nonceStr := parts[1]

	difficulty, ok := getPoWDifficulty(challenge)
	if !ok || difficulty <= 0 || difficulty > 6 {
		return false
	}
	nonce, err := strconv.ParseInt(nonceStr, 10, 64)
	if err != nil {
		return false
	}
	hash := sha256.Sum256([]byte(challenge + strconv.FormatInt(nonce, 10)))
	hashHex := hex.EncodeToString(hash[:])
	prefix := strings.Repeat("0", difficulty)
	if !strings.HasPrefix(hashHex, prefix) {
		return false
	}

	powChallengesMu.Lock()
	delete(powChallenges, challenge)
	powChallengesMu.Unlock()
	return true
}

func (p *WAFProxy) verifyJSChallenge(r *http.Request) bool {
	cookie, err := r.Cookie("gowaf_js_challenge")
	if err != nil || cookie.Value == "" {
		return false
	}
	jsChallengesMu.Lock()
	_, ok := jsChallenges[cookie.Value]
	if ok {
		delete(jsChallenges, cookie.Value)
	}
	jsChallengesMu.Unlock()
	return ok
}

func (p *WAFProxy) generatePoWChallenge(w http.ResponseWriter, r *http.Request) string {
	challengeBytes := make([]byte, 16)
	if _, err := crypto_rand.Read(challengeBytes); err != nil {
		now := time.Now().UnixNano()
		for i := 0; i < 16; i++ {
			challengeBytes[i] = byte((now >> (i * 4)) & 0xFF)
		}
	}
	challenge := hex.EncodeToString(challengeBytes)
	difficulty := int(powDifficulty.Load())
	storePoWChallenge(challenge, difficulty)

	jsTokenBytes := make([]byte, 16)
	if _, err := crypto_rand.Read(jsTokenBytes); err != nil {
		now := time.Now().UnixNano()
		for i := 0; i < 16; i++ {
			jsTokenBytes[i] = byte((now >> (i * 4)) & 0xFF)
		}
	}
	jsToken := hex.EncodeToString(jsTokenBytes)
	jsChallengesMu.Lock()
	jsChallenges[jsToken] = time.Now()
	jsChallengesMu.Unlock()

	powPage := fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>安全验证</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f5f5f5}
.box{text-align:center;padding:40px;background:white;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1)}
h3{color:#2c3e50;margin-bottom:16px}.status{color:#95a5a6;font-size:13px;margin-top:12px}
.bar{width:200px;height:6px;background:#e8e9ed;border-radius:3px;margin:12px auto;overflow:hidden}
.bar-fill{height:100%%;background:#409eff;border-radius:3px;transition:width .3s}
</style></head><body><div class="box">
<h3>安全验证</h3><div class="bar"><div class="bar-fill" id="pb" style="width:0%%"></div></div>
<div class="status" id="st">正在计算验证码...</div>
</div><script>
var ch="%s",diff=%d,jsTok="%s";
function sha256(s){var h=new TextEncoder().encode(s);return crypto.subtle.digest('SHA-256',h).then(function(b){return Array.from(new Uint8Array(b)).map(function(x){return x.toString(16).padStart(2,'0')}).join('')})}
function solve(){var n=0,limit=2000000,bs=5000;
function batch(){for(var i=0;i<bs&&n<limit;i++,n++){sha256(ch+n.toString()).then(function(h){if(document.getElementById('st').textContent.indexOf('通过')>=0)return;
if(h.substring(0,diff)==='0'.repeat(diff)){document.getElementById('st').textContent='验证通过，正在跳转...';document.getElementById('pb').style.width='100%%';
document.cookie='gowaf_pow='+ch+':'+n.toString()+'; Path=/; Max-Age=300; SameSite=Strict';
document.cookie='gowaf_js_challenge='+jsTok+'; Path=/; Max-Age=300; SameSite=Lax';
setTimeout(function(){location.reload()},800)}})}document.getElementById('pb').style.width=Math.min(90,n/limit*100)+'%%';requestAnimationFrame(batch)}
batch()}solve();
</script></body></html>`, challenge, difficulty, jsToken)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(powPage))
	return challenge
}
