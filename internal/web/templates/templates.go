package templates

import (
	"embed"
	"html/template"
)

//go:embed dashboard.html sidebar.html intercepts.html proxyconfig.html domain.html cert.html rules.html ua.html path.html ratelimit.html backend.html detector.html logs.html adminlog.html
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

func init() {
	var err error

	// 加载仪表盘模板（包含sidebar）
	DashboardTmpl, err = template.ParseFS(FS, "sidebar.html", "dashboard.html")
	if err != nil {
		panic(err)
	}

	// 加载侧边栏片段
	SidebarTmpl, err = template.ParseFS(FS, "sidebar.html")
	if err != nil {
		panic(err)
	}

	// 加载拦截数据页面模板
	InterceptsTmpl, err = template.ParseFS(FS, "sidebar.html", "intercepts.html")
	if err != nil {
		panic(err)
	}

	// 加载代理配置页面模板
	ProxyConfigTmpl, err = template.ParseFS(FS, "sidebar.html", "proxyconfig.html")
	if err != nil {
		panic(err)
	}

	// 加载域名管理页面模板
	DomainTmpl, err = template.ParseFS(FS, "sidebar.html", "domain.html")
	if err != nil {
		panic(err)
	}

	// 加载证书管理页面模板
	CertTmpl, err = template.ParseFS(FS, "sidebar.html", "cert.html")
	if err != nil {
		panic(err)
	}

	// 加载IP黑名单页面模板
	RulesTmpl, err = template.ParseFS(FS, "sidebar.html", "rules.html")
	if err != nil {
		panic(err)
	}

	// 加载UA规则页面模板
	UATmpl, err = template.ParseFS(FS, "sidebar.html", "ua.html")
	if err != nil {
		panic(err)
	}

	// 加载路径规则页面模板
	PathTmpl, err = template.ParseFS(FS, "sidebar.html", "path.html")
	if err != nil {
		panic(err)
	}

	// 加载限流配置页面模板
	RateLimitTmpl, err = template.ParseFS(FS, "sidebar.html", "ratelimit.html")
	if err != nil {
		panic(err)
	}

	// 加载后端服务页面模板
	BackendTmpl, err = template.ParseFS(FS, "sidebar.html", "backend.html")
	if err != nil {
		panic(err)
	}

	// 加载检测器管理页面模板
	DetectorTmpl, err = template.ParseFS(FS, "sidebar.html", "detector.html")
	if err != nil {
		panic(err)
	}

	// 加载访问日志页面模板
	LogsTmpl, err = template.ParseFS(FS, "sidebar.html", "logs.html")
	if err != nil {
		panic(err)
	}

	// 加载管理日志页面模板
	AdminLogTmpl, err = template.ParseFS(FS, "sidebar.html", "adminlog.html")
	if err != nil {
		panic(err)
	}
}
