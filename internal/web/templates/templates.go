package templates

import (
	"embed"
	"fmt"
	"html/template"
)

//go:embed dashboard.html sidebar.html intercepts.html proxyconfig.html domain.html cert.html rules.html ua.html path.html ratelimit.html backend.html detector.html logs.html adminlog.html config.html config-security.html config-performance.html config-scheduler.html config-websocket.html change_password.html geoblock.html httpmethods.html pathratelimit.html
var FS embed.FS

// DashboardTmpl 是仪表盘模板
var DashboardTmpl *template.Template

// SidebarTmpl 是侧边栏模板片段
var SidebarTmpl *template.Template

// InterceptsTmpl 是拦截数据页面模板
var InterceptsTmpl *template.Template

// ProxyConfigTmpl 是代理配置页面模板
var ProxyConfigTmpl *template.Template

// DomainTmpl 是域名管理页面模板
var DomainTmpl *template.Template

// CertTmpl 是证书管理页面模板
var CertTmpl *template.Template

// RulesTmpl 是IP黑名单页面模板
var RulesTmpl *template.Template

// UATmpl 是UA规则页面模板
var UATmpl *template.Template

// PathTmpl 是路径规则页面模板
var PathTmpl *template.Template

// RateLimitTmpl 是限流配置页面模板
var RateLimitTmpl *template.Template

// BackendTmpl 是后端服务页面模板
var BackendTmpl *template.Template

// DetectorTmpl 是检测器管理页面模板
var DetectorTmpl *template.Template

// LogsTmpl 是访问日志页面模板
var LogsTmpl *template.Template

// AdminLogTmpl 是管理日志页面模板
var AdminLogTmpl *template.Template

// ConfigTmpl 是系统配置页面模板
var ConfigTmpl *template.Template

// ConfigSecurityTmpl 是安全配置页面模板
var ConfigSecurityTmpl *template.Template

// ConfigPerformanceTmpl 是性能配置页面模板
var ConfigPerformanceTmpl *template.Template

// ConfigSchedulerTmpl 是定时任务配置页面模板
var ConfigSchedulerTmpl *template.Template

// ConfigWebSocketTmpl 是WebSocket配置页面模板
var ConfigWebSocketTmpl *template.Template

// ChangePasswordTmpl 是修改密码页面模板
var ChangePasswordTmpl *template.Template

// GeoBlockTmpl 是GeoIP阻断页面模板
var GeoBlockTmpl *template.Template

// HTTPMethodsTmpl 是HTTP方法限制页面模板
var HTTPMethodsTmpl *template.Template

// PathRateLimitTmpl 是路径级限流页面模板
var PathRateLimitPageTmpl *template.Template

// InitTemplates 初始化所有模板，返回错误而不是panic
func InitTemplates() error {
	var err error

	// 加载仪表盘模板（包含sidebar）
	DashboardTmpl, err = template.ParseFS(FS, "sidebar.html", "dashboard.html")
	if err != nil {
		return fmt.Errorf("加载仪表盘模板失败: %w", err)
	}

	// 加载侧边栏片段
	SidebarTmpl, err = template.ParseFS(FS, "sidebar.html")
	if err != nil {
		return fmt.Errorf("加载侧边栏模板失败: %w", err)
	}

	// 加载拦截数据页面模板
	InterceptsTmpl, err = template.ParseFS(FS, "sidebar.html", "intercepts.html")
	if err != nil {
		return fmt.Errorf("加载拦截数据模板失败: %w", err)
	}

	// 加载代理配置页面模板
	ProxyConfigTmpl, err = template.ParseFS(FS, "sidebar.html", "proxyconfig.html")
	if err != nil {
		return fmt.Errorf("加载代理配置模板失败: %w", err)
	}

	// 加载域名管理页面模板
	DomainTmpl, err = template.ParseFS(FS, "sidebar.html", "domain.html")
	if err != nil {
		return fmt.Errorf("加载域名管理模板失败: %w", err)
	}

	// 加载证书管理页面模板
	CertTmpl, err = template.ParseFS(FS, "sidebar.html", "cert.html")
	if err != nil {
		return fmt.Errorf("加载证书管理模板失败: %w", err)
	}

	// 加载IP黑名单页面模板
	RulesTmpl, err = template.ParseFS(FS, "sidebar.html", "rules.html")
	if err != nil {
		return fmt.Errorf("加载IP黑名单模板失败: %w", err)
	}

	// 加载UA规则页面模板
	UATmpl, err = template.ParseFS(FS, "sidebar.html", "ua.html")
	if err != nil {
		return fmt.Errorf("加载UA规则模板失败: %w", err)
	}

	// 加载路径规则页面模板
	PathTmpl, err = template.ParseFS(FS, "sidebar.html", "path.html")
	if err != nil {
		return fmt.Errorf("加载路径规则模板失败: %w", err)
	}

	// 加载限流配置页面模板
	RateLimitTmpl, err = template.ParseFS(FS, "sidebar.html", "ratelimit.html")
	if err != nil {
		return fmt.Errorf("加载限流配置模板失败: %w", err)
	}

	// 加载后端服务页面模板
	BackendTmpl, err = template.ParseFS(FS, "sidebar.html", "backend.html")
	if err != nil {
		return fmt.Errorf("加载后端服务模板失败: %w", err)
	}

	// 加载检测器管理页面模板
	DetectorTmpl, err = template.ParseFS(FS, "sidebar.html", "detector.html")
	if err != nil {
		return fmt.Errorf("加载检测器管理模板失败: %w", err)
	}

	// 加载访问日志页面模板
	LogsTmpl, err = template.ParseFS(FS, "sidebar.html", "logs.html")
	if err != nil {
		return fmt.Errorf("加载访问日志模板失败: %w", err)
	}

	// 加载管理日志页面模板
	AdminLogTmpl, err = template.ParseFS(FS, "sidebar.html", "adminlog.html")
	if err != nil {
		return fmt.Errorf("加载管理日志模板失败: %w", err)
	}

	// 加载系统配置页面模板
	ConfigTmpl, err = template.ParseFS(FS, "sidebar.html", "config.html")
	if err != nil {
		return fmt.Errorf("加载系统配置模板失败: %w", err)
	}

	// 加载安全配置页面模板
	ConfigSecurityTmpl, err = template.ParseFS(FS, "sidebar.html", "config-security.html")
	if err != nil {
		return fmt.Errorf("加载安全配置模板失败: %w", err)
	}

	// 加载性能配置页面模板
	ConfigPerformanceTmpl, err = template.ParseFS(FS, "sidebar.html", "config-performance.html")
	if err != nil {
		return fmt.Errorf("加载性能配置模板失败: %w", err)
	}

	// 加载定时任务配置页面模板
	ConfigSchedulerTmpl, err = template.ParseFS(FS, "sidebar.html", "config-scheduler.html")
	if err != nil {
		return fmt.Errorf("加载定时任务配置模板失败: %w", err)
	}

	// 加载WebSocket配置页面模板
	ConfigWebSocketTmpl, err = template.ParseFS(FS, "sidebar.html", "config-websocket.html")
	if err != nil {
		return fmt.Errorf("加载WebSocket配置模板失败: %w", err)
	}

	// 加载修改密码页面模板
	ChangePasswordTmpl, err = template.ParseFS(FS, "sidebar.html", "change_password.html")
	if err != nil {
		return fmt.Errorf("加载修改密码模板失败: %w", err)
	}

	// 加载GeoIP阻断页面模板
	GeoBlockTmpl, err = template.ParseFS(FS, "sidebar.html", "geoblock.html")
	if err != nil {
		return fmt.Errorf("加载GeoIP阻断模板失败: %w", err)
	}

	// 加载HTTP方法限制页面模板
	HTTPMethodsTmpl, err = template.ParseFS(FS, "sidebar.html", "httpmethods.html")
	if err != nil {
		return fmt.Errorf("加载HTTP方法限制模板失败: %w", err)
	}

	// 加载路径级限流页面模板
	PathRateLimitPageTmpl, err = template.ParseFS(FS, "sidebar.html", "pathratelimit.html")
	if err != nil {
		return fmt.Errorf("加载路径级限流模板失败: %w", err)
	}

	return nil
}

func init() {
	// 在init中调用初始化，如果失败则panic（保持向后兼容）
	if err := InitTemplates(); err != nil {
		panic(err)
	}
}
