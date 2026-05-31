package rules

import (
	"net/url"
	"strings"

	"gowaf/internal/infra/logger"
)

const maxPathLength = 4096

// PathDecoder 路径URL解码器，用于在路径规则匹配前对请求路径进行解码和规范化
type PathDecoder struct {
	enabled         bool
	maxDecodeRounds int
}

// NewPathDecoder 创建路径解码器，maxRounds 上限为3，默认2
func NewPathDecoder(enabled bool, maxRounds int) *PathDecoder {
	if maxRounds <= 0 {
		maxRounds = 2
	}
	if maxRounds > 3 {
		maxRounds = 3
	}
	return &PathDecoder{
		enabled:         enabled,
		maxDecodeRounds: maxRounds,
	}
}

// Decode 对路径执行URL解码和规范化处理
// 解码失败时返回原始路径和错误；解码后超长截断并记录警告日志
func (d *PathDecoder) Decode(path string) (string, error) {
	if !d.enabled {
		return normalizePath(path), nil
	}

	decoded := path
	var lastErr error
	for i := 0; i < d.maxDecodeRounds; i++ {
		if !strings.Contains(decoded, "%") {
			break
		}
		newDecoded, err := url.PathUnescape(decoded)
		if err != nil {
			lastErr = err
			break
		}
		if newDecoded == decoded {
			break
		}
		decoded = newDecoded
	}

	if lastErr != nil {
		logger.Warn("URL解码失败，使用已解码路径", "original", path, "decoded", decoded, "err", lastErr)
	}

	return normalizePath(decoded), lastErr
}

// normalizePath 路径遍历规范化：处理 /../、/./、双斜杠合并、长度截断
func normalizePath(path string) string {
	if len(path) == 0 {
		return path
	}

	if len(path) > maxPathLength {
		path = path[:maxPathLength]
		logger.Warn("路径超长截断", "original_len", len(path), "max", maxPathLength)
	}

	parts := strings.Split(path, "/")
	var stack []string
	for _, part := range parts {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, part)
		}
	}

	if strings.HasPrefix(path, "/") {
		return "/" + strings.Join(stack, "/")
	}
	return strings.Join(stack, "/")
}

// Enabled 返回解码器是否启用
func (d *PathDecoder) Enabled() bool {
	return d.enabled
}
