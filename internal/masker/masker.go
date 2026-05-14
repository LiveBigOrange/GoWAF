package masker

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// 敏感参数名黑名单（大小写不敏感）
	sensitiveKeys = map[string]bool{
		"password": true, "passwd": true, "pwd": true, "pass": true,
		"secret": true, "token": true, "key": true, "api_key": true, "apikey": true,
		"auth": true, "authorization": true, "sign": true, "signature": true,
		"credential": true, "credentials": true, "jwt": true,
		"access_token": true, "refresh_token": true, "bearer": true,
		"private_key": true, "privatekey": true, "secret_key": true,
		"session": true, "sess": true, "sessionid": true, "sid": true,
		"cookie": true, "csrf": true, "csrf_token": true, "xsrf": true,
		"ssn": true, "social_security": true,
		"passport": true, "passport_no": true,
		"answer": true, "security_answer": true,
	}

	// JWT Token 模式
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

	// 身份证号（中国）
	cnIDPattern = regexp.MustCompile(`\b[1-9]\d{5}(?:1[89]|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`)

	// 信用卡号（Luhn算法可校验，这里先用正则粗筛）
	creditCardPattern = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)

	// GitHub Token
	githubTokenPattern = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{36,251}\b`)

	// 通用 API Key 模式 (hex 32+ 或 base64)
	apiKeyPattern = regexp.MustCompile(`\b[A-Za-z0-9+/]{40,}[=]{0,2}\b`)

	// 手机号（中国）
	cnPhonePattern = regexp.MustCompile(`\b1[3-9]\d{9}\b`)

	// 邮箱
	emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)

	// AWS/云服务密钥模式
	awsAccessKeyPattern = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	// hex 格式长 token（48-128 字符）
	hexTokenPattern = regexp.MustCompile(`\b[A-Fa-f0-9]{48,128}\b`)

	// 预编译的敏感键匹配正则（避免热循环中重复编译）
	sensitiveKeyJSONPatterns    map[string]*regexp.Regexp
	sensitiveKeyURLPatterns     map[string]*regexp.Regexp
	sensitiveKeyGeneralPatterns map[string]*regexp.Regexp
)

const maskedPlaceholder = "***"

func init() {
	sensitiveKeyJSONPatterns = make(map[string]*regexp.Regexp)
	sensitiveKeyURLPatterns = make(map[string]*regexp.Regexp)
	sensitiveKeyGeneralPatterns = make(map[string]*regexp.Regexp)
	for key := range sensitiveKeys {
		quoted := regexp.QuoteMeta(key)
		sensitiveKeyJSONPatterns[key] = regexp.MustCompile(`(?i)"` + quoted + `"\s*:\s*"[^"]*"`)
		sensitiveKeyURLPatterns[key] = regexp.MustCompile(`(?i)\b` + quoted + `\s*=\s*[^&\s]+`)
		sensitiveKeyGeneralPatterns[key] = regexp.MustCompile(`(?i)` + quoted + `\s*[:=]\s*([^\s&,;]+)`)
	}
}

// MaskQuery 对URL查询字符串中的敏感参数值进行脱敏
// 返回脱敏后的查询字符串
func MaskQuery(rawQuery string) string {
	if rawQuery == "" {
		return rawQuery
	}

	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// 解析失败，对原始字符串做内容级脱敏
		return maskContent(rawQuery)
	}

	masked := false
	for key := range values {
		lowerKey := strings.ToLower(key)
		if sensitiveKeys[lowerKey] {
			values.Set(key, maskedPlaceholder)
			masked = true
		} else {
			// 对非敏感参数的值也做内容级脱敏（检测Token/身份证等）
			for i, v := range values[key] {
				if maskedVal := maskValue(v); maskedVal != v {
					values[key][i] = maskedVal
				}
			}
		}
	}

	if masked {
		return values.Encode()
	}

	// 对原始字符串做内容级脱敏
	return maskContent(rawQuery)
}

// MaskPath 对URL路径中的敏感信息进行脱敏
func MaskPath(path string) string {
	return maskContent(path)
}

// MaskMatchDetail 对检测匹配详情进行脱敏
func MaskMatchDetail(detail string) string {
	return maskContent(detail)
}

// maskContent 对任意文本中的敏感内容进行脱敏
func maskContent(s string) string {
	if s == "" {
		return s
	}

	// 脱敏优先级：JWT > 身份证 > 信用卡 > GitHub Token > AWS Key > 通用API Key

	result := jwtPattern.ReplaceAllString(s, maskedPlaceholder)
	result = cnIDPattern.ReplaceAllString(result, maskedPlaceholder)
	result = creditCardPattern.ReplaceAllString(result, maskedPlaceholder)
	result = githubTokenPattern.ReplaceAllString(result, maskedPlaceholder)
	result = awsAccessKeyPattern.ReplaceAllString(result, maskedPlaceholder)
	result = cnPhonePattern.ReplaceAllString(result, maskedPlaceholder)
	result = emailPattern.ReplaceAllString(result, maskedPlaceholder)

	// 对 key=value 模式中的敏感 key 进行脱敏
	result = maskKeyValuePairs(result)

	// 最后对通用长 token 进行脱敏（避免误伤少数字符串）
	result = maskLongTokens(result)

	// 检查是否有其它敏感 key 出现
	result = maskSensitiveKeyAppearances(result)

	return result
}

// maskValue 对单个值进行内容级脱敏
func maskValue(v string) string {
	return maskContent(v)
}

// maskKeyValuePairs 脱敏文本中的 key=value 或 key:value 模式
func maskKeyValuePairs(s string) string {
	for key := range sensitiveKeys {
		s = sensitiveKeyJSONPatterns[key].ReplaceAllString(s, `"`+key+`":"`+maskedPlaceholder+`"`)
		s = sensitiveKeyURLPatterns[key].ReplaceAllString(s, key+"="+maskedPlaceholder)
	}
	return s
}

// maskLongTokens 对看起来像 token/密钥的长字符串进行脱敏
func maskLongTokens(s string) string {
	// 匹配长度超过 32 的字母数字混合串（但排除掉 URL 路径、HTML tags 等）
	result := apiKeyPattern.ReplaceAllStringFunc(s, func(match string) string {
		// 排除常见的无害长字符串
		if looksLikeBase64URL(match) {
			return maskedPlaceholder
		}
		return match
	})

	// 对 hex 格式的长 token 进行脱敏（48-128 字符长的 hex）
	result = hexTokenPattern.ReplaceAllString(result, maskedPlaceholder)

	return result
}

// looksLikeBase64URL 判断字符串是否像 Base64 编码的内容（不是正常词）
func looksLikeBase64URL(s string) bool {
	// 如果包含特殊字符 `/` `+`，且长度超过 30，很可能是 token
	hasSpecial := strings.ContainsAny(s, "/+")
	long := len(s) >= 32
	return hasSpecial && long
}

// maskSensitiveKeyAppearances 脱敏文本中出现的敏感键名（如 password=xxx 但不标准格式）
func maskSensitiveKeyAppearances(s string) string {
	lower := strings.ToLower(s)
	for key := range sensitiveKeys {
		if strings.Contains(lower, key) {
			s = sensitiveKeyGeneralPatterns[key].ReplaceAllString(s, key+"="+maskedPlaceholder)
		}
	}
	return s
}
