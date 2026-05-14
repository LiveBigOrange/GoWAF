package proxy

// MaxRequestBodyProvider 最大请求体大小提供者接口
// 用于解耦 proxy 包与 web/middleware 包的跨层依赖
type MaxRequestBodyProvider interface {
	GetMaxRequestBody() int64
}
