package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"gowaf/internal/cert/acme"
	"gowaf/internal/apischema"
	"gowaf/internal/backend"
	"gowaf/internal/domain/security/bot"
	"gowaf/internal/domain/auxiliary/compliance"
	"gowaf/internal/infra/config/config"
	"gowaf/internal/infra/config/configversion"
	"gowaf/internal/infra/storage/database"
	"gowaf/internal/domain/security/detector"
	"gowaf/internal/domain/security/dlprule"
	"gowaf/internal/cert/geoipupdater"
	intelalerts "gowaf/internal/intel/alerts"
	intelclient "gowaf/internal/intel/client"
	intelemergency "gowaf/internal/intel/emergency"
	intellicense "gowaf/internal/intel/license"
	intelmerger "gowaf/internal/intel/merger"
	intelstore "gowaf/internal/intel/store"
	intelsync "gowaf/internal/intel/sync"
	intelupload "gowaf/internal/intel/upload"
	"gowaf/internal/domain/security/limiter"
	"gowaf/internal/infra/storage/logdb"
	"gowaf/internal/infra/logger"
	"gowaf/internal/infra/storage/metrics"
	"gowaf/internal/infra/notify"
	"gowaf/internal/domain/proxy/pathbodylimit"
	"gowaf/internal/domain/proxy"
	"gowaf/internal/domain/proxyconfig"
	"gowaf/internal/domain/security/ratelimit"
	"gowaf/internal/domain/auxiliary/reqheader"
	"gowaf/internal/domain/auxiliary/respheader"
	"gowaf/internal/domain/security/rules"
	"gowaf/internal/domain/auxiliary/sessionsafe"
	"gowaf/internal/infra/storage/stats"
	"gowaf/internal/domain/security/vpatch"
	"gowaf/internal/domain/gateway/handler"
	"gowaf/internal/domain/gateway/middleware"

	"github.com/gorilla/mux"
)

func main() {
	cfg, configDB, logDB := initConfigAndDB()
	defer configDB.Close()
	defer logDB.Close()
	defer logger.Close()

	core := initCoreManagers(cfg, configDB)
	defer core.ruleEngine.Stop()
	core.metricsManager.StartFlushLoop(5 * time.Second)
	defer core.metricsManager.StopFlush()
	defer core.metricsManager.Close()

	sec := initSecurityManagers(cfg, configDB, core)

	cleanupAuth := initAuthAndSession(cfg, configDB)
	defer cleanupAuth()

	proxyCtx := initProxyService(cfg, configDB, core, sec, logDB)
	defer proxyCtx.ipLimiter.Stop()
	defer proxyCtx.proxyServerManager.StopAll()
	defer proxyCtx.rateLimitEngine.Stop()
	defer sec.botMgr.Stop()
	defer handler.StopSessionCleaner()
	defer sec.acmeMgr.StopAutoRenewal()

	cleanupSched := initSchedulers(cfg, configDB, core, logDB)
	defer cleanupSched()

	// [封存] 情报中心功能暂时禁用，恢复时取消注释即可
	// intelStarted := initIntelModules(cfg, configDB, core)
	// if intelStarted {
	// 	defer stopIntelModules()
	// }

	router := setupRouter(core.backendManager)
	startAdminServer(cfg, router, core, sec, proxyCtx)
}

type coreManagers struct {
	ruleEngine            *rules.Engine
	backendManager        *backend.Manager
	metricsManager        *metrics.Manager
	proxyConfigManager    *proxyconfig.Manager
	detectorConfigManager *detector.ConfigManager
}

type securityManagers struct {
	botMgr           *bot.Manager
	vpatchMgr        *vpatch.Manager
	acmeMgr          *acme.Manager
	respHeaderMgr    *respheader.Manager
	reqHeaderMgr     *reqheader.Manager
	pathBodyLimitMgr *pathbodylimit.Manager
	sessionSafeMgr   *sessionsafe.Manager
	dlpRuleMgr       *dlprule.Manager
	apiSchemaMgr     *apischema.Manager
	complianceGen    *compliance.Generator
	configVersionMgr *configversion.Manager
	geoIPUpdateMgr   *geoipupdater.Manager
}

type proxyService struct {
	ipLimiter          *limiter.IPRateLimiter
	wafProxy           *proxy.WAFProxy
	proxyServerManager *proxy.ProxyServerManager
	rateLimitEngine    *ratelimit.Engine
}

func initConfigAndDB() (*config.Config, *database.Manager, *logdb.LogDB) {
	logger.Info("正在加载配置文件...")
	cfg, err := config.Load("config.yaml")
	if err != nil {
		logger.Fatal("加载配置文件失败: %v", err)
	}

	logger.Info("正在初始化配置数据库...")
	configDB, err := database.NewManager(cfg.Database.ConfigPath)
	if err != nil {
		logger.Fatal("初始化配置数据库失败: %v", err)
	}

	logger.Info("正在初始化核心配置...")
	apischema.RegisterSessionConfigInit(middleware.InitSessionConfig)
	apischema.RegisterRateLimitConfigInit(middleware.InitRateLimitConfig)
	config.InitCoreConfigs(cfg, configDB.GetDB())

	logger.Info("正在初始化日志系统...")
	if err := logger.InitWithRotationAndDB(cfg.Log.File, logger.DefaultLogFieldConfig(), cfg.Log.Rotation, nil); err != nil {
		logger.Fatal("初始化日志系统失败: %v", err)
	}

	logger.Info("正在初始化日志数据库...")
	logDB, err := config.InitLogDBWithConfig(configDB.GetDB(), cfg.Database.LogsPath)
	if err != nil {
		logger.Fatal("初始化日志数据库失败: %v", err)
	}
	logger.SetDB(logDB)

	return cfg, configDB, logDB
}

func initCoreManagers(cfg *config.Config, configDB *database.Manager) *coreManagers {
	logger.Info("正在初始化管理器...")

	var (
		ruleEngine            *rules.Engine
		backendManager        *backend.Manager
		metricsManager        *metrics.Manager
		proxyConfigManager    *proxyconfig.Manager
		detectorConfigManager *detector.ConfigManager
		err                   error
	)

	ruleEngine, err = rules.NewEngine(configDB.GetDB())
	if err != nil {
		logger.Fatal("规则引擎初始化失败: %v", err)
	}

	backendManager, err = backend.NewManager(configDB.GetDB())
	if err != nil {
		logger.Fatal("后端管理器初始化失败: %v", err)
	}

	proxyConfigManager, err = proxyconfig.NewManager(configDB.GetDB())
	if err != nil {
		logger.Fatal("代理配置管理器初始化失败: %v", err)
	}

	detectorConfigManager, err = detector.NewConfigManager(configDB.GetDB())
	if err != nil {
		logger.Fatal("检测器配置管理器初始化失败: %v", err)
	}

	metricsManager, err = metrics.NewManager(cfg.Database.MetricsPath, cfg.GeoIP.DBPath)
	if err != nil {
		logger.Fatal("指标管理器初始化失败: %v", err)
	}

	logger.Info("所有管理器初始化完成")

	if err := proxyConfigManager.EnsureAPIKeyTable(); err != nil {
		logger.Warn("创建API密钥表失败: %v", err)
	}

	if cfg.DefaultProxy != nil && cfg.DefaultProxy.Enabled {
		proxyConfigs, err := proxyConfigManager.ListProxies()
		if err != nil {
			logger.Warn("获取代理配置列表失败: %v", err)
		} else if len(proxyConfigs) == 0 {
			logger.Info("正在初始化默认代理配置...")
			defaultProxy := &proxyconfig.ProxyConfig{
				ID:         uuid.New().String(),
				ListenAddr: cfg.DefaultProxy.ListenAddr,
				Protocol:   cfg.DefaultProxy.Protocol,
				Enabled:    true,
			}
			if err := proxyConfigManager.AddProxy(defaultProxy); err != nil {
				logger.Warn("初始化默认代理配置失败: %v", err)
			} else {
				logger.Info("默认代理配置已初始化: %s (%s)", defaultProxy.ListenAddr, defaultProxy.Protocol)
			}
		}
	}

	return &coreManagers{
		ruleEngine:            ruleEngine,
		backendManager:        backendManager,
		metricsManager:        metricsManager,
		proxyConfigManager:    proxyConfigManager,
		detectorConfigManager: detectorConfigManager,
	}
}

func initSecurityManagers(cfg *config.Config, configDB *database.Manager, core *coreManagers) *securityManagers {
	botMgr := bot.NewManager(configDB.GetDB())
	vpatchMgr := vpatch.NewManager(configDB.GetDB())
	complianceGen := compliance.NewGenerator(configDB.GetDB(), core.metricsManager.GetDB())
	acmeMgr := acme.NewManager(cfg.TLS.CertDir, cfg.TLS.ACMEEmail, cfg.TLS.Domains)

	// 设置 proxyConfigMgr，使 ACME 证书写入数据库
	if core.proxyConfigManager != nil {
		acmeMgr.SetProxyConfigMgr(core.proxyConfigManager)
	}

	// 从数据库加载ACME配置（优先级高于config.yaml）
	if core.proxyConfigManager != nil {
		dbEmail, _ := core.proxyConfigManager.GetSystemConfig("acme_email")
		dbDomains, _ := core.proxyConfigManager.GetSystemConfig("acme_domains")

		if dbEmail != "" && dbDomains != "" {
			// DB 有配置，使用 DB
			var domains []string
			for _, d := range regexp.MustCompile(`\s*,\s*`).Split(dbDomains, -1) {
				d = strings.TrimSpace(d)
				if d != "" {
					domains = append(domains, d)
				}
			}
			if len(domains) > 0 {
				acmeMgr.UpdateConfig(dbEmail, domains)
				logger.Info("ACME: 已从数据库加载配置 (邮箱=%s, 域名数=%d)", dbEmail, len(domains))
			}
		} else if cfg.TLS.ACMEEmail != "" && len(cfg.TLS.Domains) > 0 {
			// DB 无配置但 yaml 有，首次写入 DB 并激活
			core.proxyConfigManager.SetSystemConfig("acme_email", cfg.TLS.ACMEEmail)
			core.proxyConfigManager.SetSystemConfig("acme_domains", strings.Join(cfg.TLS.Domains, ","))
			logger.Info("ACME: 已将yaml配置写入数据库")
		}

		// 迁移磁盘上的 ACME 证书到数据库（仅导入仍在管理列表中的域名）
		var currentACMEDomains []string
		if dbDomains != "" {
			for _, d := range regexp.MustCompile(`\s*,\s*`).Split(dbDomains, -1) {
				d = strings.TrimSpace(d)
				if d != "" {
					currentACMEDomains = append(currentACMEDomains, d)
				}
			}
		} else {
			currentACMEDomains = cfg.TLS.Domains
		}
		absCertDir, err := filepath.Abs(cfg.TLS.CertDir)
		if err == nil {
			migrateDiskCertsToDB(absCertDir, core.proxyConfigManager, currentACMEDomains)
		} else {
			migrateDiskCertsToDB(cfg.TLS.CertDir, core.proxyConfigManager, currentACMEDomains)
		}
	}
	respHeaderMgr := respheader.NewManager(configDB.GetDB())
	reqHeaderMgr := reqheader.NewManager(configDB.GetDB())
	pathBodyLimitMgr := pathbodylimit.NewManager(configDB.GetDB())
	sessionSafeMgr := sessionsafe.NewManager(configDB.GetDB())
	dlpRuleMgr := dlprule.NewManager(configDB.GetDB())
	configVersionMgr := configversion.NewManager(configDB.GetDB())
	apiSchemaMgr := apischema.NewManager(configDB.GetDB())

	botMgr.StartCleanup()

	acmeFromDB := false
	if core.proxyConfigManager != nil {
		if email, _ := core.proxyConfigManager.GetSystemConfig("acme_email"); email != "" {
			if domains, _ := core.proxyConfigManager.GetSystemConfig("acme_domains"); domains != "" {
				acmeFromDB = true
			}
		}
	}

	if acmeMgr.IsEnabled() && !acmeFromDB {
		acmeMgr.StartAutoRenewal()
		for _, domain := range cfg.TLS.Domains {
			if err := acmeMgr.ObtainCertificate(context.Background(), domain); err != nil {
				logger.Warn("ACME: 证书获取失败 %s: %v", domain, err)
			}
		}
	}

	geoIPUpdateMgr := geoipupdater.NewManager(configDB.GetDB(), cfg.GeoIP.DBPath, core.metricsManager)
	geoIPUpdateMgr.StartAutoUpdate()

	middleware.SetSessionSafeManager(sessionSafeMgr)

	logger.Info("正在初始化Web处理器...")

	return &securityManagers{
		botMgr:           botMgr,
		vpatchMgr:        vpatchMgr,
		acmeMgr:          acmeMgr,
		respHeaderMgr:    respHeaderMgr,
		reqHeaderMgr:     reqHeaderMgr,
		pathBodyLimitMgr: pathBodyLimitMgr,
		sessionSafeMgr:   sessionSafeMgr,
		dlpRuleMgr:       dlpRuleMgr,
		apiSchemaMgr:     apiSchemaMgr,
		complianceGen:    complianceGen,
		configVersionMgr: configVersionMgr,
		geoIPUpdateMgr:   geoIPUpdateMgr,
	}
}

func initAuthAndSession(cfg *config.Config, configDB *database.Manager) func() {
	logger.Info("正在检查并初始化运行时配置...")
	cfg.Admin.Username = cfg.Auth.Username

	var passwordHash string
	var runtimeConfigJSON string
	if configDB != nil {
		err := configDB.GetDB().QueryRow("SELECT value FROM system_config WHERE key='admin_password_hash'").Scan(&passwordHash)
		if err != nil {
			if cfg.Auth.Password != "" {
				hash, err := bcrypt.GenerateFromPassword([]byte(cfg.Auth.Password), bcrypt.DefaultCost)
				if err != nil {
					logger.Fatal("生成密码哈希失败: %v", err)
				}
				passwordHash = string(hash)
				if _, err := configDB.GetDB().Exec("INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('admin_password_hash', ?, ?)", passwordHash, time.Now().Unix()); err != nil {
					logger.Warn("保存密码哈希到数据库失败: %v", err)
				} else {
					logger.Info("已将配置文件中的明文密码转换为哈希并存入数据库")
				}
			}
		}

		err = configDB.GetDB().QueryRow("SELECT value FROM system_config WHERE key='runtime_config'").Scan(&runtimeConfigJSON)
		if err != nil || runtimeConfigJSON == "" {
			defaultCfg := config.GetDefaultRuntimeConfig()
			data, err := json.Marshal(defaultCfg)
			if err != nil {
				logger.Fatal("序列化默认运行时配置失败: %v", err)
			}
			if _, err := configDB.GetDB().Exec("INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('runtime_config', ?, ?)", string(data), time.Now().Unix()); err != nil {
				logger.Warn("保存运行时配置到数据库失败: %v", err)
			} else {
				logger.Info("已初始化默认运行时配置（安全、性能、定时任务等）")
			}
		}
	}

	if runtimeConfigJSON != "" {
		var rc config.RuntimeConfig
		if err := json.Unmarshal([]byte(runtimeConfigJSON), &rc); err == nil {
			logger.SetFieldConfig(logger.LogFieldConfig{
				Host:        rc.Log.Fields.Host,
				Query:       rc.Log.Fields.Query,
				Referer:     rc.Log.Fields.Referer,
				ContentType: rc.Log.Fields.ContentType,
				BodySize:    rc.Log.Fields.BodySize,
				LatencyUs:   rc.Log.Fields.LatencyUs,
			})
		}
	}

	cfg.Admin.PasswordHash = passwordHash

	middleware.InitAdminAllowedNets(cfg.Admin.AllowedCIDRs)

	logger.Info("正在初始化管理日志...")
	if err := middleware.InitAdminLog(cfg.Admin.AdminLog); err != nil {
		logger.Warn("初始化管理日志失败: %v", err)
	} else {
		logger.Info("管理日志已初始化: %s", cfg.Admin.AdminLog)
	}

	logger.Info("正在初始化Session持久化...")
	if err := middleware.InitSessionDB(configDB.GetDB()); err != nil {
		logger.Fatal("初始化Session数据库失败: %v", err)
	}

	handler.StartSessionCleaner()

	return middleware.CloseAdminLog
}

func initProxyService(cfg *config.Config, configDB *database.Manager, core *coreManagers, sec *securityManagers, logDB *logdb.LogDB) *proxyService {
	logger.Info("正在初始化代理服务...")
	ipLimiter := limiter.NewIPRateLimiter(100, 200)
	go ipLimiter.Cleanup(10 * time.Minute)

	wafProxy, err := proxy.NewWAFProxy(cfg, core.ruleEngine, ipLimiter, core.backendManager, core.metricsManager, core.proxyConfigManager)
	if err != nil {
		logger.Fatal("初始化WAF代理失败: %v", err)
	}
	wafProxy.SetBotManager(sec.botMgr)
	wafProxy.SetVPatchManager(sec.vpatchMgr)
	wafProxy.SetRespHeaderManager(sec.respHeaderMgr)
	wafProxy.SetReqHeaderManager(sec.reqHeaderMgr)
	wafProxy.SetPathBodyLimitManager(sec.pathBodyLimitMgr)
	wafProxy.SetDLPRuleManager(sec.dlpRuleMgr)
	wafProxy.SetAPISchemaManager(sec.apiSchemaMgr)
	wafProxy.SetACMEManager(sec.acmeMgr)
	wafProxy.SetMaxRequestBodyProvider(middleware.MaxRequestBodyProvider{})

	proxyServerManager := proxy.NewProxyServerManager(core.proxyConfigManager, wafProxy)

	logger.Info("正在初始化通知引擎...")
	notifyEngine := notify.NewEngine(configDB.GetDB())
	wafProxy.SetNotifyEngine(notifyEngine)

	if keyCfg, err := core.proxyConfigManager.GetRateLimitKeyConfig(); err == nil && keyCfg != nil {
		wafProxy.SetRateLimitKeyConfig(limiter.RateLimitKeyConfig{
			KeyType:    limiter.RateLimitKeyType(keyCfg.KeyType),
			HeaderName: keyCfg.HeaderName,
			CookieName: keyCfg.CookieName,
			SessionKey: keyCfg.SessionKey,
		})
	}

	logger.Info("正在初始化智能限流引擎...")
	rateLimitCfg := ratelimit.DefaultConfig()
	if core.proxyConfigManager != nil {
		if dbCfg, err := core.proxyConfigManager.GetSystemConfig("smartlimit_config"); err == nil && dbCfg != "" {
			var savedCfg ratelimit.Config
			if err := json.Unmarshal([]byte(dbCfg), &savedCfg); err == nil {
				rateLimitCfg = &savedCfg
				logger.Info("已从数据库加载智能拦截配置")
			} else {
				logger.Warn("解析数据库智能拦截配置失败(使用默认): %v", err)
			}
		}
		savedRateLimitCfg := rateLimitCfg
		rateLimitCfg.SetPersistSaver(func() error {
			data, err := savedRateLimitCfg.MarshalJSONSafe()
			if err != nil {
				return err
			}
			return core.proxyConfigManager.SetSystemConfig("smartlimit_config", string(data))
		})
	} else {
		smartlimitConfigPath := "smartlimit_config.json"
		if savedCfg, err := ratelimit.LoadConfigFromFile(smartlimitConfigPath); err == nil && savedCfg != nil {
			rateLimitCfg = savedCfg
			logger.Info("已加载持久化智能拦截配置: %s", smartlimitConfigPath)
		} else if err != nil {
			logger.Info("加载智能拦截配置失败(使用默认): %v", err)
		}
		rateLimitCfg.PersistPath = "smartlimit_config.json"
	}
	rateLimitEngine := ratelimit.NewEngine(rateLimitCfg)
	wafProxy.SetRateLimitEngine(rateLimitEngine)

	autoBlocker := ratelimit.NewAutoBlocker(core.ruleEngine, rateLimitCfg.AutoBlockThreshold, time.Duration(rateLimitCfg.AutoBlockDurationSec)*time.Second)
	rateLimitEngine.SetAutoBlocker(autoBlocker)

	go func() {
		ticker := time.NewTicker(rateLimitCfg.CleanupInterval())
		defer ticker.Stop()
		for {
			select {
			case <-rateLimitEngine.StopCh():
				return
			case <-ticker.C:
				rateLimitEngine.RunCleanup()
			}
		}
	}()
	logger.Info("智能限流引擎已启动，画像清理间隔: %v", rateLimitCfg.CleanupInterval())

	if core.detectorConfigManager != nil {
		detectorConfigs, dcerr := core.detectorConfigManager.ListConfigs()
		if dcerr == nil {
			for _, dcfg := range detectorConfigs {
				wafProxy.ApplyDetectorConfig(dcfg.DetectorType, dcfg.Enabled)
				wafProxy.ApplyObservationMode(dcfg.DetectorType, dcfg.ObservationMode)
				logger.Info("同步检测器配置: %s enabled=%v observation_mode=%v", dcfg.DetectorType, dcfg.Enabled, dcfg.ObservationMode)
			}
		} else {
			logger.Warn("同步检测器配置失败: %v", dcerr)
		}
	}

	if wafProxy.GetDetectorManager() != nil && core.detectorConfigManager != nil {
		wafProxy.GetDetectorManager().LoadAllRulesFromDB(core.detectorConfigManager)
		logger.Info("已从数据库加载检测器规则到内存")
	}

	if err := proxyServerManager.StartAll(); err != nil {
		logger.Warn("启动代理服务失败: %v", err)
	} else {
		logger.Info("代理服务已启动，共 %d 个监听端口", proxyServerManager.GetServerCount())
	}

	if val, err := core.proxyConfigManager.GetSystemConfig("waf_global_enabled"); err == nil && val == "false" {
		proxy.SetGlobalEnabled(false)
		logger.Info("WAF全局开关：已关闭（从数据库读取）")
	} else {
		logger.Info("WAF全局开关：已开启")
	}

	if val, err := core.proxyConfigManager.GetSystemConfig("pow_difficulty"); err == nil && val != "" {
		var d int
		if _, err := fmt.Sscanf(val, "%d", &d); err == nil {
			proxy.SetPoWDifficulty(d)
			logger.Info("PoW难度：%d", d)
		}
	}

	if sessCfg := config.GetSessionSafeFromDB(configDB.GetDB()); sessCfg != nil {
		middleware.UpdateSessionSafeConfig(sessCfg.IPMutationThreshold, sessCfg.UADetectionEnabled)
	}

	handler.InitAppDeps(&handler.AppDeps{
		Config:                cfg,
		RuleEngine:            core.ruleEngine,
		BackendManager:        core.backendManager,
		MetricsManager:        core.metricsManager,
		ProxyConfigManager:    core.proxyConfigManager,
		DetectorConfigManager: core.detectorConfigManager,
		DetectorManager:       wafProxy.GetDetectorManager(),
		BotManager:            sec.botMgr,
		VPatchManager:         sec.vpatchMgr,
		ComplianceGenerator:   sec.complianceGen,
		RespHeaderManager:     sec.respHeaderMgr,
		DLPRuleManager:        sec.dlpRuleMgr,
		ConfigVersionManager:  sec.configVersionMgr,
		APISchemaManager:      sec.apiSchemaMgr,
		GeoIPUpdateManager:    sec.geoIPUpdateMgr,
		NotifyEngine:          notifyEngine,
		ConfigDB:              configDB.GetDB(),
		LogDB:                 logDB,
		WAFProxy:              wafProxy,
		ProxyServerManager:    proxyServerManager,
		ACMEManager:           sec.acmeMgr,
		ReqHeaderManager:      sec.reqHeaderMgr,
		Limiter:               ipLimiter,
		RateLimitEngine:       rateLimitEngine,
	})

	return &proxyService{
		ipLimiter:          ipLimiter,
		wafProxy:           wafProxy,
		proxyServerManager: proxyServerManager,
		rateLimitEngine:    rateLimitEngine,
	}
}

func initSchedulers(cfg *config.Config, configDB *database.Manager, core *coreManagers, logDB *logdb.LogDB) func() {
	logger.Info("正在初始化WebSocket...")
	dashboardPush, logHeartbeat, bufferSize, broadcastChannel := config.GetWebSocketConfig(configDB.GetDB())
	handler.InitDashboardHub(dashboardPush)
	handler.InitLogHub(logHeartbeat, bufferSize, broadcastChannel)

	healthCheck, _, logCleanup, metricsCleanup, ruleReload := config.GetSchedulerConfig(configDB.GetDB())
	_, _, _, maxRequestBody, _ := config.GetPerformanceConfig(configDB.GetDB())
	logRetentionDays, metricsRetentionDays, adminLogRetentionDays := config.GetRetentionConfig(configDB.GetDB())

	var cleanups []func()
	schedCtx, schedCancel := context.WithCancel(context.Background())

	if healthCheck > 0 {
		hc := backend.NewHealthChecker(core.backendManager, healthCheck)
		go hc.Start()
		cleanups = append(cleanups, hc.Stop)
		logger.Info("健康检查已启动，间隔 %d 秒", healthCheck)
	}

	if logCleanup > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(logCleanup) * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-schedCtx.Done():
					return
				case <-ticker.C:
					logger.Info("日志自动清理周期触发（间隔 %d 分钟），保留 %d 天", logCleanup, logRetentionDays)
					if logDB != nil {
						if err := logDB.CleanOldLogs(logRetentionDays); err != nil {
							logger.Warn("日志自动清理失败: %v", err)
						}
					}
				}
			}
		}()
		logger.Info("日志自动清理已启动，间隔 %d 分钟，保留 %d 天", logCleanup, logRetentionDays)
	}

	if ruleReload > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(ruleReload) * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-schedCtx.Done():
					return
				case <-ticker.C:
					if err := core.ruleEngine.ReloadRules(); err != nil {
						logger.Warn("规则热重载失败: %v", err)
					}
				}
			}
		}()
		logger.Info("规则热重载已启动，间隔 %d 秒", ruleReload)
	}

	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-schedCtx.Done():
				return
			case <-ticker.C:
				stats.CleanupTopStats()
			}
		}
	}()
	logger.Info("TOP统计清理已启动，间隔 10 分钟")

	if metricsCleanup > 0 {
		metricsScheduler := metrics.NewSchedulerWithPeriod(core.metricsManager, metricsRetentionDays, time.Duration(metricsCleanup)*time.Minute)
		go metricsScheduler.Start()
		cleanups = append(cleanups, metricsScheduler.Stop)
		logger.Info("指标清理已启动，保留 %d 天，间隔 %d 分钟", metricsRetentionDays, metricsCleanup)
	}

	if adminLogRetentionDays > 0 {
		middleware.CheckAdminLogRetention(adminLogRetentionDays)
		logger.Info("管理日志保留 %d 天", adminLogRetentionDays)
	}

	if maxRequestBody > 0 {
		middleware.SetMaxRequestBody(maxRequestBody)
	}

	go handler.GetDashboardHub().Run()
	go handler.StartLogHub()

	return func() {
		schedCancel()
		handler.GetDashboardHub().Stop()
		handler.GetLogHub().Close()
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
}

func startAdminServer(cfg *config.Config, router *mux.Router, core *coreManagers, sec *securityManagers, proxyCtx *proxyService) {
	logger.Info("正在启动管理后台服务: %s", cfg.Admin.Addr)

	loggedRouter := middleware.AdminAccessLog(router)

	server := &http.Server{
		Addr:         cfg.Admin.Addr,
		Handler:      middleware.SecurityHeaders(loggedRouter),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			if sig == syscall.SIGHUP {
				logger.Info("收到SIGHUP信号，执行配置热重载...")
				if err := core.ruleEngine.ReloadRules(); err != nil {
					logger.Warn("规则热重载失败: %v", err)
				} else {
					logger.Info("规则热重载完成")
				}
				proxyCtx.proxyServerManager.ReloadAll()
				sec.respHeaderMgr.Reload()
				sec.reqHeaderMgr.Reload()
				sec.dlpRuleMgr.Reload()
				sec.apiSchemaMgr.Reload()
				sec.pathBodyLimitMgr.Reload()
				sec.vpatchMgr.Reload()
				sec.botMgr.Reload()
				sec.sessionSafeMgr.Reload()
				if core.detectorConfigManager != nil {
					if configs, err := core.detectorConfigManager.ListConfigs(); err == nil {
						for _, dcfg := range configs {
							proxyCtx.wafProxy.ApplyDetectorConfig(dcfg.DetectorType, dcfg.Enabled)
							proxyCtx.wafProxy.ApplyObservationMode(dcfg.DetectorType, dcfg.ObservationMode)
						}
					}
				}
				logger.Info("所有模块配置热重载完成")
				continue
			}
			logger.Info("收到信号 %v，正在优雅关闭...", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := server.Shutdown(ctx); err != nil {
				logger.Warn("管理后台关闭超时: %v", err)
			}
			cancel()
			proxyCtx.proxyServerManager.ShutdownAll()
			logger.Info("所有服务已关闭")
			return
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal("启动服务失败: %v", err)
	}

	logger.Info("服务已关闭")
}

var (
	intelMu       sync.Mutex
	intelStoreRef *intelstore.Store
	intelCancelFn context.CancelFunc
	intelRunning  bool
)

func initIntelModules(cfg *config.Config, configDB *database.Manager, core *coreManagers) bool {
	if cfg.Intel == nil {
		logger.Info("情报中心配置未初始化，跳过")
		return false
	}

	intelStore, err := intelstore.NewStore(configDB.GetDB())
	if err != nil {
		logger.Error("情报中心存储层初始化失败", "err", err)
		return false
	}

	if cfg.Intel.LicenseKey != "" {
		if err := intelStore.MigrateFromConfig(cfg.Intel.ServerURL, cfg.Intel.LicenseKey); err != nil {
			logger.Error("凭证迁移到数据库失败", "err", err)
		} else {
			logger.Info("凭证已从config.yaml迁移到数据库加密存储")
			cfg.Intel.LicenseKey = ""
			cfg.Save()
		}
	}

	if dbLK, err := intelStore.GetLicenseKey(); err == nil && dbLK != "" {
		cfg.Intel.LicenseKey = dbLK
	}

	handler.SetIntelStore(intelStore)
	intelStoreRef = intelStore

	handler.IntelStartFn = func() error {
		return startIntelModules(cfg, configDB, core)
	}
	handler.IntelStopFn = stopIntelModules

	if !cfg.Intel.Enabled {
		logger.Info("情报中心未启用，跳过模块初始化")
		return false
	}

	if err := startIntelModules(cfg, configDB, core); err != nil {
		logger.Error("情报中心模块启动失败", "err", err)
		return false
	}
	return true
}

func startIntelModules(cfg *config.Config, configDB *database.Manager, core *coreManagers) error {
	intelMu.Lock()
	defer intelMu.Unlock()

	if intelRunning {
		return nil
	}

	if cfg.Intel == nil || !cfg.Intel.Enabled {
		return fmt.Errorf("intel config not initialized or not enabled")
	}

	if cfg.Intel.LicenseKey == "" && intelStoreRef != nil {
		if lk, err := intelStoreRef.GetLicenseKey(); err == nil && lk != "" {
			cfg.Intel.LicenseKey = lk
		}
	}

	logger.Info("正在启动情报中心模块...")

	intelCli, err := intelclient.NewIntelClient(cfg.Intel)
	if err != nil {
		return fmt.Errorf("failed to create intel client: %w", err)
	}

	licenseMgr := intellicense.NewLicenseManager(intelCli, intelStoreRef, cfg.Intel)

	if cfg.Intel.LicenseKey == "" {
		licenseMgr.SetStateFree()
		logger.Info("未配置 License Key，以 Free 模式运行")
	} else {
		vCtx, vCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := licenseMgr.Verify(vCtx); err != nil {
			logger.Error("License 验证失败", "err", err)
		}
		vCancel()
	}

	intelMerger := intelmerger.NewMerger(core.ruleEngine, intelStoreRef, cfg.Intel.Rule.Priority)
	alertWatcher := intelalerts.NewWatcher(intelStoreRef, 3)
	scheduler := intelsync.NewScheduler(intelCli, intelStoreRef, licenseMgr, intelMerger, cfg.Intel, alertWatcher)
	uploadMgr := intelupload.NewManager(intelCli, intelStoreRef, cfg.Intel, licenseMgr)
	collector := intelupload.NewCollector(intelStoreRef, &cfg.Intel.Upload, intelupload.NewMaskEngine(cfg.Intel.SensitiveFilter.Action, nil))
	poller := intelemergency.NewPoller(intelCli, intelStoreRef, intelMerger)

	ctx, cancel := context.WithCancel(context.Background())
	intelCancelFn = cancel

	licenseMgr.Start(ctx)
	scheduler.Start(ctx)
	uploadMgr.Start(ctx)
	poller.Start(ctx)

	core.ruleEngine.AutoManageBuiltinRules(true)

	handler.SetIntelLicenseManager(licenseMgr)
	handler.SetIntelScheduler(scheduler)
	handler.SetIntelUploadManager(uploadMgr)
	handler.SetIntelCollector(collector)
	handler.SetIntelPoller(poller)

	proxy.IntelCollectFn = func(eventType string, eventData map[string]interface{}) {
		if handler.IntelCollector != nil {
			_ = handler.IntelCollector.Collect(eventType, eventData)
		}
	}

	intelRunning = true
	logger.Info("情报中心模块已启动")
	return nil
}

func stopIntelModules() {
	intelMu.Lock()
	defer intelMu.Unlock()

	if !intelRunning {
		return
	}

	logger.Info("正在停止情报中心模块...")

	if handler.IntelPoller != nil {
		handler.IntelPoller.Stop()
	}
	if handler.IntelUploadMgr != nil {
		handler.IntelUploadMgr.Stop()
	}
	if handler.IntelScheduler != nil {
		handler.IntelScheduler.Stop()
	}
	if handler.IntelLicense != nil {
		handler.IntelLicense.Stop()
	}
	if intelCancelFn != nil {
		intelCancelFn()
		intelCancelFn = nil
	}

	handler.SetIntelLicenseManager(nil)
	handler.SetIntelScheduler(nil)
	handler.SetIntelUploadManager(nil)
	handler.SetIntelCollector(nil)
	handler.SetIntelPoller(nil)

	proxy.IntelCollectFn = nil

	intelRunning = false
	logger.Info("情报中心模块已停止")
}

// migrateDiskCertsToDB 将磁盘上的 ACME 证书迁移到 ssl_certs 数据库
func migrateDiskCertsToDB(certDir string, pcm *proxyconfig.Manager, acmeDomains []string) {
	if pcm == nil || certDir == "" {
		return
	}

	acmeDomainSet := make(map[string]bool, len(acmeDomains))
	for _, d := range acmeDomains {
		acmeDomainSet[d] = true
	}

	entries, err := os.ReadDir(certDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".crt") {
			continue
		}
		domain := strings.TrimSuffix(entry.Name(), ".crt")
		if domain == "acme_account" || domain == "" {
			continue
		}

		if !acmeDomainSet[domain] {
			certFile := filepath.Join(certDir, domain+".crt")
			keyFile := filepath.Join(certDir, domain+".key")
			os.Remove(certFile)
			os.Remove(keyFile)
			logger.Info("ACME迁移: 域名 %s 已不在管理列表中，已清理磁盘证书文件", domain)
			continue
		}

		certFile := filepath.Join(certDir, domain+".crt")
		keyFile := filepath.Join(certDir, domain+".key")

		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			continue
		}

		sslCert, err := proxyconfig.ParseCertificate(string(certPEM), string(keyPEM))
		if err != nil {
			logger.Warn("ACME迁移: 解析磁盘证书失败 %s: %v", domain, err)
			continue
		}

		sslCert.Name = "ACME: " + domain
		sslCert.Source = "acme"
		sslCert.AutoRenew = true
		if sslCert.Issuer == "" {
			sslCert.Issuer = "自签名"
		}

		if err := pcm.UpsertACMECert(sslCert); err != nil {
			logger.Warn("ACME迁移: 保存证书到数据库失败 %s: %v", domain, err)
		} else {
			logger.Info("ACME迁移: 已将磁盘证书导入数据库: %s", domain)
		}
	}
}
