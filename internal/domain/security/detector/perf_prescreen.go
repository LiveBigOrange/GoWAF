package detector

import "strings"

type riskFlags uint8

const (
	riskSQL    riskFlags = 1 << iota // 0b00001
	riskXSS                          // 0b00010
	riskCMD                          // 0b00100
	riskPath                         // 0b01000
	riskHeader                       // 0b10000
	riskAll    riskFlags = riskSQL | riskXSS | riskCMD | riskPath | riskHeader
)

func (f riskFlags) hasRisk(r riskFlags) bool { return f&r != 0 }
func (f riskFlags) hasAnyRisk() bool         { return f != 0 }

// preScreenRiskChars 单次遍历识别所有风险特征，替代原来的5次 ContainsAny 调用
// 字符映射精确对应原 detectWithDetectors 中的字符集：
//   - SQL:  ' " ; ( ) - = * / \
//   - XSS:  < > & " '
//   - CMD:  ; | ` $ & > < \n
//   - Path: .. 或 ContainsAny(lower, "/etc\\windows") 即 / \ e t c w i n d o s 等字符
//   - Header: \r \n
func preScreenRiskChars(combined, lowerCombined string) riskFlags {
	var flags riskFlags
	prevDot := false
	for i := 0; i < len(combined); i++ {
		switch combined[i] {
		case '\'':
			flags |= riskSQL | riskXSS
		case '"':
			flags |= riskSQL | riskXSS
		case ';':
			flags |= riskSQL | riskCMD
		case '(', ')', '-', '=', '*':
			flags |= riskSQL
		case '/':
			flags |= riskSQL | riskPath
		case '\\':
			flags |= riskSQL | riskPath
		case '<':
			flags |= riskXSS | riskCMD
		case '>':
			flags |= riskXSS | riskCMD
		case '&':
			flags |= riskXSS | riskCMD
		case '|', '`', '$':
			flags |= riskCMD
		case '\n':
			flags |= riskCMD | riskHeader
		case '\r':
			flags |= riskHeader
		case '.':
			if prevDot {
				flags |= riskPath
			}
			prevDot = true
			continue
		default:
			prevDot = false
			continue
		}
		prevDot = false
		if flags == riskAll {
			break
		}
	}
	// 原代码 ContainsAny(lowerCombined, "/etc\\windows") 是字符集匹配
	// / 和 \ 已在遍历中处理，还需检查 e t c w i n d o s 是否在 lowerCombined 中
	// 但由于 ContainsAny 是字符集匹配，任何一个字符命中即可
	// / \ 已处理，剩余字符 e t c w i n d o s 都极常见，几乎必命中
	// 所以只要 lowerCombined 非空且含这些字符之一就触发
	// 为了精确等价，直接用 ContainsAny 补偿遍历中未覆盖的路径风险字符
	if flags&riskPath == 0 && strings.ContainsAny(lowerCombined, "etcwindows") {
		flags |= riskPath
	}
	if flags&riskXSS == 0 && strings.ContainsAny(lowerCombined, "javascript:on") {
		flags |= riskXSS
	}
	return flags
}
