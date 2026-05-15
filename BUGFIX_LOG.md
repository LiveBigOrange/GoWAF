# GoWAF 问题修复记录

## 问题一：默认密码登录失败

**现象**：初始化项目后，使用默认密码 `admin` 登录提示账号密码错误。

**原因**：`config.yaml` 中 `auth.password` 为空（`""`），启动时 `cmd/waf/main.go:343-356` 的逻辑是：先从数据库查找 `admin_password_hash`，找不到时才用 `auth.password`（明文）生成哈希。由于 `auth.password` 为空，不会生成任何哈希，导致 `passwordHash` 为空，登录验证永远返回 `false`。

**修复方法**：在 `config.yaml` 中设置明文密码：

```yaml
auth:
    username: admin
    password: admin
```

启动后系统自动将明文转为 bcrypt 哈希存入数据库，之后即可用 `admin/admin` 登录。登录成功后建议立即修改密码。

**相关代码**：
- 配置文件：`config.yaml:35-37`
- 密码哈希初始化：`cmd/waf/main.go:336-388`
- 凭证验证：`internal/web/handler/users.go:33-56`
- 弱口令校验：`internal/config/validator.go:120-123`

---

## 问题二：非本机 IP 无法登录（页面闪回登录页）

**现象**：使用 `127.0.0.1:9090` 可正常登录，但使用 `192.168.200.133:9090` 登录后页面闪一下又回到登录页，无法进入后台。

**原因**：登录成功后设置的 session 和 csrf_token cookie 硬编码了 `Secure: true` 和 `SameSite: StrictMode`。

- `Secure: true`：浏览器在 HTTP 连接下不会发送该 cookie，只有 HTTPS 才发送。`127.0.0.1` 能登录是因为浏览器对 localhost 有特殊豁免。
- `SameSite: StrictMode`：严格模式下跨站请求不发送 cookie，在某些浏览器/场景下也会导致问题。

**修复方法**：将 cookie 的 `Secure` 改为根据是否使用 TLS 动态判断（`r.TLS != nil`），`SameSite` 改为 `LaxMode`。与项目中 captcha cookie 的处理方式保持一致（`auth.go:443-444` 已使用此模式）。

**修改文件**：

### 1. `internal/web/handler/auth.go`（登录成功后设置 cookie）

修改前：
```go
Secure:   true,
SameSite: http.SameSiteStrictMode,
```

修改后：
```go
Secure:   r.TLS != nil,
SameSite: http.SameSiteLaxMode,
```

涉及 session cookie（第 646-647 行）和 csrf_token cookie（第 655-656 行）。

### 2. `internal/web/middleware/auth.go`（Auth 中间件 CSRF cookie 续期/新建）

修改前：
```go
Secure:   true,
SameSite: http.SameSiteStrictMode,
```

修改后：
```go
Secure:   r.TLS != nil,
SameSite: http.SameSiteLaxMode,
```

涉及两处 CSRF cookie 设置（续期第 335-336 行、新建第 350-351 行）。

---

## 问题三：allowed_cidrs 为空时的行为说明

**现象**：`config.yaml` 中 `admin.allowed_cidrs` 为空时，误以为允许所有 IP 访问。

**实际行为**：`allowed_cidrs` 为空时，默认只允许 `127.0.0.1/8` 和 `::1/128`（本机）访问管理后台，**不是全部允许**。

**代码逻辑**（`internal/web/middleware/auth.go:50-56`）：
```go
if len(cidrs) == 0 {
    adminAllowAll = false
    cidrs = []string{"127.0.0.1/8", "::1/128"}
}
```

**如需允许所有 IP 访问**，显式配置：
```yaml
admin:
    allowed_cidrs: ["0.0.0.0/0", "::/0"]
```
