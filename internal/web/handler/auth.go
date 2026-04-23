package handler

import (
	"crypto/rand"
	"encoding/hex"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"

	"gowaf-demo/internal/backend"
	"gowaf-demo/internal/config"
	"gowaf-demo/internal/metrics"
	"gowaf-demo/internal/proxyconfig"
	"gowaf-demo/internal/rules"
	"gowaf-demo/internal/web"
	"gowaf-demo/internal/web/middleware"
)

var cfg *config.Config
var RuleEngine *rules.Engine
var BackendManager *backend.Manager
var MetricsManager *metrics.Manager
var ProxyConfigManager *proxyconfig.Manager
var StaticFS = web.StaticFS

// WAFProxy WAF代理实例,用于动态更新检测器配置
var WAFProxyInstance interface {
	ApplyDetectorConfig(detectorType string, enabled bool)
}

// ProxyServerManager 代理服务器管理器，用于动态更新代理端口
var ProxyServerManager interface {
	AddProxy(cfg *proxyconfig.ProxyConfig) error
	UpdateProxy(cfg *proxyconfig.ProxyConfig) error
	DeleteProxy(id string) error
	ReloadAll() error
}

// --- 登录暴力破解防护 ---

var (
	loginAttempts = make(map[string]int)
	loginBlocked  = make(map[string]time.Time)
	loginMu       sync.RWMutex
)

const (
	maxLoginAttempts   = 5
	loginBlockDuration = 15 * time.Minute
)

func isLoginBlocked(ip string) bool {
	loginMu.RLock()
	defer loginMu.RUnlock()
	blockedUntil, ok := loginBlocked[ip]
	if !ok {
		return false
	}
	return time.Now().Before(blockedUntil)
}

func recordLoginFailure(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	loginAttempts[ip]++
	if loginAttempts[ip] >= maxLoginAttempts {
		loginBlocked[ip] = time.Now().Add(loginBlockDuration)
		delete(loginAttempts, ip)
	}
}

func clearLoginAttempts(ip string) {
	loginMu.Lock()
	defer loginMu.Unlock()
	delete(loginAttempts, ip)
	delete(loginBlocked, ip)
}

func getClientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// --- 验证码 ---

type captchaEntry struct {
	answer    string
	createdAt time.Time
}

var (
	captchaStore = make(map[string]captchaEntry) // captchaID -> answer
	captchaMu    sync.RWMutex
	captchaTTL   = 5 * time.Minute
)

// captchaChars 验证码字符集（排除易混淆字符：0/O, 1/l/I）
const captchaChars = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// generateCaptcha 生成验证码：返回 (captchaID, answer)
func generateCaptcha() (string, string) {
	// 生成4位验证码
	answer := make([]byte, 4)
	charsLen := big.NewInt(int64(len(captchaChars)))
	for i := range answer {
		n, _ := rand.Int(rand.Reader, charsLen)
		answer[i] = captchaChars[n.Int64()]
	}

	// 生成captchaID
	idBytes := make([]byte, 16)
	rand.Read(idBytes)
	captchaID := hex.EncodeToString(idBytes)

	captchaMu.Lock()
	captchaStore[captchaID] = captchaEntry{
		answer:    string(answer),
		createdAt: time.Now(),
	}
	captchaMu.Unlock()

	return captchaID, string(answer)
}

// validateCaptcha 验证验证码（不区分大小写，一次性使用）
func validateCaptcha(captchaID, userInput string) bool {
	if captchaID == "" || userInput == "" {
		return false
	}
	captchaMu.Lock()
	defer captchaMu.Unlock()

	entry, ok := captchaStore[captchaID]
	if !ok {
		return false
	}
	// 一次性使用，验证后立即删除
	delete(captchaStore, captchaID)

	// 检查过期
	if time.Since(entry.createdAt) > captchaTTL {
		return false
	}

	// 不区分大小写比较
	return stringsEqualFold(entry.answer, userInput)
}

// stringsEqualFold 简单的不区分大小写比较
func stringsEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// cleanExpiredCaptchas 清理过期验证码
func cleanExpiredCaptchas() {
	captchaMu.Lock()
	defer captchaMu.Unlock()
	now := time.Now()
	for id, entry := range captchaStore {
		if now.Sub(entry.createdAt) > captchaTTL {
			delete(captchaStore, id)
		}
	}
}

// drawCaptchaImage 绘制验证码图片
func drawCaptchaImage(answer string) *image.RGBA {
	width := 160
	height := 60
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// 背景色
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{240, 240, 240, 255}}, image.Point{}, draw.Src)

	// 干扰线
	for i := 0; i < 6; i++ {
		x1 := randomInt(width)
		y1 := randomInt(height)
		x2 := randomInt(width)
		y2 := randomInt(height)
		lineColor := color.RGBA{
			uint8(randomInt(200)),
			uint8(randomInt(200)),
			uint8(randomInt(200)),
			255,
		}
		drawLine(img, x1, y1, x2, y2, lineColor)
	}

	// 干扰点
	for i := 0; i < 50; i++ {
		x := randomInt(width)
		y := randomInt(height)
		dotColor := color.RGBA{
			uint8(randomInt(200)),
			uint8(randomInt(200)),
			uint8(randomInt(200)),
			255,
		}
		img.Set(x, y, dotColor)
	}

	// 绘制字符
	charWidth := width / (len(answer) + 1)
	for i, ch := range answer {
		x := charWidth*(i+1) - 8
		y := 15 + randomInt(20)
		charColor := color.RGBA{
			uint8(30 + randomInt(80)),
			uint8(30 + randomInt(80)),
			uint8(30 + randomInt(80)),
			255,
		}
		drawChar(img, x, y, ch, charColor)
	}

	return img
}

// drawLine 画线（Bresenham算法简化版）
func drawLine(img *image.RGBA, x1, y1, x2, y2 int, c color.Color) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	steps := max(dx, dy)
	if steps == 0 {
		return
	}
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		x := int(float64(x1) + t*float64(x2-x1))
		y := int(float64(y1) + t*float64(y2-y1))
		if x >= 0 && x < img.Bounds().Dx() && y >= 0 && y < img.Bounds().Dy() {
			img.Set(x, y, c)
		}
	}
}

// drawChar 用简单点阵绘制字符
func drawChar(img *image.RGBA, x, y int, ch rune, c color.Color) {
	// 简单的5x7点阵字体定义（大写字母和数字）
	font := map[rune][]string{
		'2': {"01100", "10010", "10010", "00100", "01000", "10000", "11110"},
		'3': {"01110", "10001", "00001", "00110", "00001", "10001", "01110"},
		'4': {"00100", "01100", "10100", "10100", "11111", "00100", "00100"},
		'5': {"11111", "10000", "11110", "00001", "00001", "10001", "01110"},
		'6': {"00110", "01000", "10000", "11110", "10001", "10001", "01110"},
		'7': {"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
		'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
		'9': {"01110", "10001", "10001", "01111", "00001", "00010", "01100"},
		'A': {"01110", "10001", "10001", "11111", "10001", "10001", "10001"},
		'B': {"11110", "10001", "10001", "11110", "10001", "10001", "11110"},
		'C': {"01110", "10001", "10000", "10000", "10000", "10001", "01110"},
		'D': {"11100", "10010", "10001", "10001", "10001", "10010", "11100"},
		'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
		'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"},
		'G': {"01110", "10001", "10000", "10111", "10001", "10001", "01110"},
		'H': {"10001", "10001", "10001", "11111", "10001", "10001", "10001"},
		'J': {"00111", "00010", "00010", "00010", "00010", "10010", "01100"},
		'K': {"10001", "10010", "10100", "11000", "10100", "10010", "10001"},
		'L': {"10000", "10000", "10000", "10000", "10000", "10000", "11111"},
		'M': {"10001", "11011", "10101", "10101", "10001", "10001", "10001"},
		'N': {"10001", "11001", "10101", "10011", "10001", "10001", "10001"},
		'P': {"11110", "10001", "10001", "11110", "10000", "10000", "10000"},
		'Q': {"01110", "10001", "10001", "10001", "10101", "10010", "01101"},
		'R': {"11110", "10001", "10001", "11110", "10100", "10010", "10001"},
		'S': {"01110", "10001", "10000", "01110", "00001", "10001", "01110"},
		'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"},
		'U': {"10001", "10001", "10001", "10001", "10001", "10001", "01110"},
		'V': {"10001", "10001", "10001", "10001", "01010", "01010", "00100"},
		'W': {"10001", "10001", "10001", "10101", "10101", "11011", "10001"},
		'X': {"10001", "10001", "01010", "00100", "01010", "10001", "10001"},
		'Y': {"10001", "10001", "01010", "00100", "00100", "00100", "00100"},
		'Z': {"11111", "00001", "00010", "00100", "01000", "10000", "11111"},
	}

	rows, ok := font[ch]
	if !ok {
		return
	}

	scale := 3 // 每个点的像素大小
	for rowIdx, row := range rows {
		for colIdx, bit := range row {
			if bit == '1' {
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						px := x + colIdx*scale + dx
						py := y + rowIdx*scale + dy
						if px >= 0 && px < img.Bounds().Dx() && py >= 0 && py < img.Bounds().Dy() {
							img.Set(px, py, c)
						}
					}
				}
			}
		}
	}
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// CaptchaHandler 验证码图片接口
func CaptchaHandler(w http.ResponseWriter, r *http.Request) {
	captchaID, answer := generateCaptcha()
	img := drawCaptchaImage(answer)

	// 设置captchaID到Cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "captcha_id",
		Value:    captchaID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	png.Encode(w, img)
}

func InitHandlers(c *config.Config, engine *rules.Engine, bm *backend.Manager, mm *metrics.Manager, pcm *proxyconfig.Manager) {
	cfg = c
	RuleEngine = engine
	BackendManager = bm
	MetricsManager = mm
	ProxyConfigManager = pcm
}

// SetWAFProxy 设置WAF代理实例
func SetWAFProxy(wp interface {
	ApplyDetectorConfig(detectorType string, enabled bool)
}) {
	WAFProxyInstance = wp
}

// SetProxyServerManager 设置代理服务器管理器
func SetProxyServerManager(psm interface {
	AddProxy(cfg *proxyconfig.ProxyConfig) error
	UpdateProxy(cfg *proxyconfig.ProxyConfig) error
	DeleteProxy(id string) error
	ReloadAll() error
}) {
	ProxyServerManager = psm
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		clientIP := getClientIP(r)
		blocked := isLoginBlocked(clientIP)

		html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 · GoWAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
            width: 400px;
            padding: 40px;
            text-align: center;
        }
        h1 { font-weight: 500; color: #333; margin-bottom: 10px; }
        .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
        .input-group { margin-bottom: 20px; text-align: left; }
        .input-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        .input-group input { width: 100%; padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; transition: border 0.2s; }
        .input-group input:focus { outline: none; border-color: #667eea; }
        .captcha-group { margin-bottom: 20px; text-align: left; }
        .captcha-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        .captcha-row { display: flex; gap: 8px; align-items: center; }
        .captcha-row input { width: 120px; padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; letter-spacing: 4px; text-transform: uppercase; }
        .captcha-row input:focus { outline: none; border-color: #667eea; }
        .captcha-img { border-radius: 8px; cursor: pointer; height: 46px; border: 1px solid #ddd; }
        .captcha-refresh { color: #667eea; cursor: pointer; font-size: 22px; width: 36px; height: 46px; display: flex; align-items: center; justify-content: center; border: 1px solid #ddd; border-radius: 8px; background: #f8f9fa; }
        .captcha-refresh:hover { color: #5a67d8; background: #eef; border-color: #667eea; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #5a67d8; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .footer { margin-top: 20px; color: #999; font-size: 12px; }
        .blocked { color: #e53e3e; margin-bottom: 15px; font-size: 14px; font-weight: 500; }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>GoWAF</h1>
        <div class="subtitle">Web 应用防火墙</div>`
		if blocked {
			html += `<div class="blocked">登录尝试过多，请15分钟后再试</div>
        <form method="POST" onsubmit="return false;">
            <div class="input-group">
                <label>用户名</label>
                <input type="text" name="username" disabled>
            </div>
            <div class="input-group">
                <label>密码</label>
                <input type="password" name="password" disabled>
            </div>
            <button type="submit" disabled>登录</button>
        </form>`
		} else {
			html += `<form method="POST">
            <div class="input-group">
                <label>用户名</label>
                <input type="text" name="username" placeholder="请输入用户名" required autofocus>
            </div>
            <div class="input-group">
                <label>密码</label>
                <input type="password" name="password" placeholder="请输入密码" required>
            </div>
            <div class="captcha-group">
                <label>验证码</label>
                <div class="captcha-row">
                    <input type="text" name="captcha" placeholder="请输入验证码" required maxlength="4" autocomplete="off">
                    <img class="captcha-img" id="captchaImg" src="/captcha" onclick="refreshCaptcha()" title="点击刷新验证码">
                    <span class="captcha-refresh" onclick="refreshCaptcha()" title="刷新验证码">&#x21bb;</span>
                </div>
            </div>
            <button type="submit">登录</button>
        </form>
        <script>
            function refreshCaptcha() {
                document.getElementById('captchaImg').src = '/captcha?t=' + Date.now();
            }
        </script>`
		}
		html += `<div class="footer">请使用管理员账户登录</div>
    </div>
</body>
</html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(html))
		return
	}

	// POST 登录
	clientIP := getClientIP(r)

	if isLoginBlocked(clientIP) {
		renderLoginError(w, "登录尝试过多，请15分钟后再试")
		return
	}

	r.ParseForm()

	// 验证验证码
	captchaIDCookie, err := r.Cookie("captcha_id")
	if err != nil {
		renderLoginError(w, "请先获取验证码")
		return
	}
	captchaInput := r.FormValue("captcha")
	if !validateCaptcha(captchaIDCookie.Value, captchaInput) {
		recordLoginFailure(clientIP)
		renderLoginError(w, "验证码错误或已过期")
		return
	}

	user := r.FormValue("username")
	pass := r.FormValue("password")
	if user == cfg.Auth.Username && pass == cfg.Auth.Password {
		clearLoginAttempts(clientIP)
		token := middleware.GenerateSessionToken()
		middleware.AddSession(token)
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   3600,
		})
		csrfToken := middleware.GenerateSessionToken()
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrfToken,
			Path:     "/",
			HttpOnly: false,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteStrictMode,
			MaxAge:   3600,
		})
		// 清除captcha_id cookie
		http.SetCookie(w, &http.Cookie{Name: "captcha_id", MaxAge: -1, Path: "/"})
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		recordLoginFailure(clientIP)
		renderLoginError(w, "用户名或密码错误")
	}
}

func Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session"); err == nil {
		middleware.RemoveSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "session", MaxAge: -1, Path: "/"})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// StartSessionCleaner 启动 session 和 captcha 清理器
func StartSessionCleaner() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			middleware.CleanExpiredSessions()
			cleanExpiredCaptchas()
		}
	}()
}

// renderLoginError 渲染带错误提示的登录页面
func renderLoginError(w http.ResponseWriter, errorMsg string) {
	html := `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 · GoWAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
            width: 400px;
            padding: 40px;
            text-align: center;
        }
        h1 { font-weight: 500; color: #333; margin-bottom: 10px; }
        .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
        .input-group { margin-bottom: 20px; text-align: left; }
        .input-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        .input-group input { width: 100%; padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; transition: border 0.2s; }
        .input-group input:focus { outline: none; border-color: #667eea; }
        .captcha-group { margin-bottom: 20px; text-align: left; }
        .captcha-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        .captcha-row { display: flex; gap: 8px; align-items: center; }
        .captcha-row input { width: 120px; padding: 12px 16px; border: 1px solid #ddd; border-radius: 8px; font-size: 14px; letter-spacing: 4px; text-transform: uppercase; }
        .captcha-row input:focus { outline: none; border-color: #667eea; }
        .captcha-img { border-radius: 8px; cursor: pointer; height: 46px; border: 1px solid #ddd; }
        .captcha-refresh { color: #667eea; cursor: pointer; font-size: 22px; width: 36px; height: 46px; display: flex; align-items: center; justify-content: center; border: 1px solid #ddd; border-radius: 8px; background: #f8f9fa; }
        .captcha-refresh:hover { color: #5a67d8; background: #eef; border-color: #667eea; }
        button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #5a67d8; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .footer { margin-top: 20px; color: #999; font-size: 12px; }
        .error-msg {
            background: #fee;
            border: 1px solid #fcc;
            color: #c00;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            animation: fadeOut 0.5s ease-in 3s forwards;
        }
        @keyframes fadeOut {
            from { opacity: 1; max-height: 100px; margin-bottom: 20px; padding: 12px; }
            to { opacity: 0; max-height: 0; margin-bottom: 0; padding: 0; border: none; }
        }
    </style>
</head>
<body>
    <div class="login-card">
        <h1>GoWAF</h1>
        <div class="subtitle">Web 应用防火墙</div>
        <div class="error-msg" id="errorMsg">` + errorMsg + `</div>
        <form method="POST">
            <div class="input-group">
                <label>用户名</label>
                <input type="text" name="username" placeholder="请输入用户名" required autofocus>
            </div>
            <div class="input-group">
                <label>密码</label>
                <input type="password" name="password" placeholder="请输入密码" required>
            </div>
            <div class="captcha-group">
                <label>验证码</label>
                <div class="captcha-row">
                    <input type="text" name="captcha" placeholder="请输入验证码" required maxlength="4" autocomplete="off">
                    <img class="captcha-img" id="captchaImg" src="/captcha" onclick="refreshCaptcha()" title="点击刷新验证码">
                    <span class="captcha-refresh" onclick="refreshCaptcha()" title="刷新验证码">&#x21bb;</span>
                </div>
            </div>
            <button type="submit">登录</button>
        </form>
        <script>
            function refreshCaptcha() {
                document.getElementById('captchaImg').src = '/captcha?t=' + Date.now();
            }
            // 3秒后自动隐藏错误提示
            setTimeout(function() {
                var errorMsgEl = document.getElementById('errorMsg');
                if (errorMsgEl) {
                    errorMsgEl.style.display = 'none';
                }
            }, 3500);
        </script>
        <div class="footer">请使用管理员账户登录</div>
    </div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}
