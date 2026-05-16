package handler

import (
	"database/sql"

	"gowaf/internal/cert/acme"
	"gowaf/internal/apischema"
	"gowaf/internal/backend"
	"gowaf/internal/domain/security/bot"
	"gowaf/internal/domain/auxiliary/compliance"
	"gowaf/internal/infra/config/config"
	"gowaf/internal/infra/config/configversion"
	"gowaf/internal/domain/security/detector"
	"gowaf/internal/domain/security/dlprule"
	"gowaf/internal/cert/geoipupdater"
	intelemergency "gowaf/internal/intel/emergency"
	intellicense "gowaf/internal/intel/license"
	intelstore "gowaf/internal/intel/store"
	intelsync "gowaf/internal/intel/sync"
	intelupload "gowaf/internal/intel/upload"
	"gowaf/internal/domain/security/limiter"
	"gowaf/internal/infra/storage/logdb"
	"gowaf/internal/infra/storage/metrics"
	"gowaf/internal/infra/notify"
	"gowaf/internal/domain/proxyconfig"
	"gowaf/internal/domain/security/ratelimit"
	"gowaf/internal/domain/auxiliary/reqheader"
	"gowaf/internal/domain/auxiliary/respheader"
	"gowaf/internal/domain/security/rules"
	"gowaf/internal/domain/security/vpatch"
)

type AppDeps struct {
	Config                *config.Config
	RuleEngine            *rules.Engine
	BackendManager        *backend.Manager
	MetricsManager        *metrics.Manager
	ProxyConfigManager    *proxyconfig.Manager
	DetectorConfigManager *detector.ConfigManager
	DetectorManager       *detector.Manager
	BotManager            *bot.Manager
	VPatchManager         *vpatch.Manager
	ComplianceGenerator   *compliance.Generator
	RespHeaderManager     *respheader.Manager
	DLPRuleManager        *dlprule.Manager
	ConfigVersionManager  *configversion.Manager
	APISchemaManager      *apischema.Manager
	GeoIPUpdateManager    *geoipupdater.Manager
	NotifyEngine          *notify.Engine
	ConfigDB              *sql.DB
	LogDB                 *logdb.LogDB

	WAFProxy interface {
		ApplyDetectorConfig(detectorType string, enabled bool)
		ApplyObservationMode(detectorType string, observationMode bool)
		GetDetectorManager() *detector.Manager
		GetRateLimitKeyConfig() limiter.RateLimitKeyConfig
		SetRateLimitKeyConfig(limiter.RateLimitKeyConfig)
	}

	ProxyServerManager interface {
		AddProxy(cfg *proxyconfig.ProxyConfig) error
		UpdateProxy(cfg *proxyconfig.ProxyConfig) error
		DeleteProxy(id string) error
		ReloadAll() error
	}

	ACMEManager      *acme.Manager
	ReqHeaderManager *reqheader.Manager
	Limiter          LimiterInterface
	RateLimitEngine  *ratelimit.Engine
}

var deps *AppDeps

func InitAppDeps(d *AppDeps) {
	deps = d
}

func GetDeps() *AppDeps {
	return deps
}

var (
	IntelLicense   *intellicense.LicenseManager
	IntelScheduler *intelsync.Scheduler
	IntelStore     *intelstore.Store
	IntelUploadMgr *intelupload.Manager
	IntelCollector *intelupload.Collector
	IntelPoller    *intelemergency.Poller

	IntelStartFn func() error
	IntelStopFn  func()
)

func SetIntelLicenseManager(l *intellicense.LicenseManager) {
	IntelLicense = l
}

func SetIntelScheduler(s *intelsync.Scheduler) {
	IntelScheduler = s
}

func SetIntelStore(s *intelstore.Store) {
	IntelStore = s
}

func SetIntelUploadManager(m *intelupload.Manager) {
	IntelUploadMgr = m
}

func SetIntelCollector(c *intelupload.Collector) {
	IntelCollector = c
}

func SetIntelPoller(p *intelemergency.Poller) {
	IntelPoller = p
}
