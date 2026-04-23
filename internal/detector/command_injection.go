package detector

import (
	"regexp"
	"strings"
	"sync"
)

// CommandInjectionDetector 命令注入检测器
type CommandInjectionDetector struct {
	patterns []*regexp.Regexp
	mu       sync.RWMutex
}

// NewCommandInjectionDetector 创建命令注入检测器
func NewCommandInjectionDetector() *CommandInjectionDetector {
	d := &CommandInjectionDetector{}
	d.compilePatterns()
	return d
}

// compilePatterns 预编译命令注入检测规则
func (d *CommandInjectionDetector) compilePatterns() {
	patternStrs := []string{
		// 管道符
		`\|.*\|`,
		`\|\s*\w+`,
		
		// 分号执行多条命令
		`;\s*\w+`,
		`;\s*/`,
		
		// 反引号执行
		"`.*`",
		
		// $()执行
		`\$\([^)]+\)`,
		
		// 重定向
		`>\s*/`,
		`>>\s*/`,
		`<\s*/`,
		
		// 常见危险命令
		`(?i)\bcat\s+`,
		`(?i)\bls\s+`,
		`(?i)\bdir\s+`,
		`(?i)\btype\s+`,
		`(?i)\bmore\s+`,
		`(?i)\bless\s+`,
		`(?i)\bhead\s+`,
		`(?i)\btail\s+`,
		`(?i)\bwget\s+`,
		`(?i)\bcurl\s+`,
		`(?i)\bnc\s+`,
		`(?i)\bnetcat\s+`,
		`(?i)\btelnet\s+`,
		`(?i)\bftp\s+`,
		`(?i)\btftp\s+`,
		`(?i)\brsh\s+`,
		`(?i)\bssh\s+`,
		`(?i)\bscp\s+`,
		`(?i)\brsync\s+`,
		`(?i)\bfind\s+`,
		`(?i)\bgrep\s+`,
		`(?i)\bsed\s+`,
		`(?i)\bawk\s+`,
		`(?i)\bcut\s+`,
		`(?i)\bsort\s+`,
		`(?i)\buniq\s+`,
		`(?i)\bwc\s+`,
		`(?i)\bxargs\s+`,
		`(?i)\bchmod\s+`,
		`(?i)\bchown\s+`,
		`(?i)\brm\s+`,
		`(?i)\bmv\s+`,
		`(?i)\bcp\s+`,
		`(?i)\btar\s+`,
		`(?i)\bgzip\s+`,
		`(?i)\bzip\s+`,
		`(?i)\bunzip\s+`,
		`(?i)\bkill\s+`,
		`(?i)\bkillall\s+`,
		`(?i)\bps\s+`,
		`(?i)\btop\s+`,
		`(?i)\bfree\s+`,
		`(?i)\bdf\s+`,
		`(?i)\bdu\s+`,
		`(?i)\bmount\s+`,
		`(?i)\bumount\s+`,
		`(?i)\bfdisk\s+`,
		`(?i)\bmkfs\s+`,
		`(?i)\bcrontab\s+`,
		`(?i)\bat\s+`,
		`(?i)\bnohup\s+`,
		`(?i)\bscreen\s+`,
		`(?i)\btmux\s+`,
		`(?i)\benv\s+`,
		`(?i)\bexport\s+`,
		`(?i)\bset\s+`,
		`(?i)\bunset\s+`,
		`(?i)\becho\s+`,
		`(?i)\bprintf\s+`,
		`(?i)\bsource\s+`,
		`(?i)\bexec\s+`,
		`(?i)\beval\s+`,
		
		// Windows命令
		`(?i)\bcmd\.exe`,
		`(?i)\bpowershell\.exe`,
		`(?i)\bpowershell\s+`,
		`(?i)\bwscript\.exe`,
		`(?i)\bcscript\.exe`,
		`(?i)\bmshta\.exe`,
		`(?i)\bregsvr32\.exe`,
		`(?i)\brundll32\.exe`,
		`(?i)\bnet\.exe`,
		`(?i)\bnetsh\.exe`,
		`(?i)\bipconfig\.exe`,
		`(?i)\bwhoami\.exe`,
		`(?i)\btasklist\.exe`,
		`(?i)\btaskkill\.exe`,
		`(?i)\bschtasks\.exe`,
		`(?i)\bat\.exe`,
		`(?i)\bwmic\.exe`,
		`(?i)\btypeperf\.exe`,
		`(?i)\bquery\.exe`,
		`(?i)\baddusers\.exe`,
		`(?i)\bcacls\.exe`,
		`(?i)\bicacls\.exe`,
		`(?i)\bcd\.exe`,
		`(?i)\bcopy\.exe`,
		`(?i)\bxcopy\.exe`,
		`(?i)\bmove\.exe`,
		`(?i)\bdel\.exe`,
		`(?i)\berase\.exe`,
		`(?i)\bformat\.exe`,
		`(?i)\bfsutil\.exe`,
		`(?i)\bassoc\.exe`,
		`(?i)\bftype\.exe`,
		`(?i)\bfind\.exe`,
		`(?i)\bfindstr\.exe`,
		`(?i)\bmore\.exe`,
		`(?i)\bsort\.exe`,
		`(?i)\bcomp\.exe`,
		`(?i)\bfc\.exe`,
		`(?i)\btree\.exe`,
		`(?i)\bdir\s+`,
		`(?i)\bver\.exe`,
		`(?i)\bvol\.exe`,
		`(?i)\blabel\.exe`,
		`(?i)\bmd\.exe`,
		`(?i)\bmkdir\.exe`,
		`(?i)\brd\.exe`,
		`(?i)\brmdir\.exe`,
		`(?i)\bren\.exe`,
		`(?i)\brename\.exe`,
		`(?i)\breplace\.exe`,
		`(?i)\battrib\.exe`,
		`(?i)\btime\.exe`,
		`(?i)\bdate\.exe`,
		`(?i)\bhostname\.exe`,
		`(?i)\bnslookup\.exe`,
		`(?i)\bping\.exe`,
		`(?i)\btracert\.exe`,
		`(?i)\bpathping\.exe`,
		`(?i)\broute\.exe`,
		`(?i)\barp\.exe`,
		`(?i)\bnbtstat\.exe`,
		`(?i)\bnetstat\.exe`,
		`(?i)\bgetmac\.exe`,
		`(?i)\bsysteminfo\.exe`,
		`(?i)\bdriverquery\.exe`,
		`(?i)\bpnputil\.exe`,
		`(?i)\bsc\.exe`,
		`(?i)\breg\.exe`,
		`(?i)\bregedit\.exe`,
		`(?i)\bregini\.exe`,
		`(?i)\bsetx\.exe`,
		`(?i)\bset\.exe`,
		`(?i)\becho\s+`,
		`(?i)\btype\s+`,
		`(?i)\bcopy\s+`,
		`(?i)\bmove\s+`,
		`(?i)\bdel\s+`,
		`(?i)\bformat\s+`,
		`(?i)\bshutdown\.exe`,
		`(?i)\brestart\.exe`,
		`(?i)\blogoff\.exe`,
		`(?i)\bmsg\.exe`,
		`(?i)\bstart\.exe`,
		`(?i)\brunas\.exe`,
		`(?i)\bsu\.exe`,
		`(?i)\bprint\.exe`,
		`(?i)\bmode\.exe`,
		`(?i)\bcolor\.exe`,
		`(?i)\btitle\.exe`,
		`(?i)\bprompt\.exe`,
		`(?i)\bpushd\.exe`,
		`(?i)\bpopd\.exe`,
		`(?i)\bfor\.exe`,
		`(?i)\bif\.exe`,
		`(?i)\bgoto\.exe`,
		`(?i)\bcall\.exe`,
		`(?i)\bexit\.exe`,
		`(?i)\bbreak\.exe`,
		`(?i)\bcls\.exe`,
		`(?i)\bhelp\.exe`,
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.patterns = make([]*regexp.Regexp, 0, len(patternStrs))
	for _, pattern := range patternStrs {
		re, err := regexp.Compile(pattern)
		if err == nil {
			d.patterns = append(d.patterns, re)
		}
	}
}

// Detect 检测命令注入
func (d *CommandInjectionDetector) Detect(input string) (bool, string) {
	if input == "" {
		return false, ""
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// 检测每个模式
	for _, pattern := range d.patterns {
		if pattern.MatchString(input) {
			return true, pattern.String()
		}
	}

	// 启发式检测
	if d.heuristicCheck(input) {
		return true, "heuristic_detection"
	}

	return false, ""
}

// heuristicCheck 启发式检测
func (d *CommandInjectionDetector) heuristicCheck(input string) bool {
	// 检测路径遍历（更严格：必须是连续的../或..\）
	if strings.Contains(input, "../") || strings.Contains(input, "..\\") {
		// 排除URL编码中的合法使用（如%2e%2e%2f）
		// 只在路径部分检测路径遍历
		return true
	}

	// 检测环境变量访问（${}格式，排除合法的模板语法）
	// 只检测shell风格的变量替换，要求后面跟着命令字符
	if strings.Contains(input, "${") && strings.Contains(input, "}") {
		// 检查是否包含常见的shell变量模式
		shellVars := []string{"${IFS}", "${PATH}", "${HOME}", "${SHELL}", "${USER}"}
		lower := strings.ToLower(input)
		for _, v := range shellVars {
			if strings.Contains(lower, strings.ToLower(v)) {
				return true
			}
		}
	}

	return false
}

// DetectRequest 检测HTTP请求中的命令注入
func (d *CommandInjectionDetector) DetectRequest(method, path, query, body string, headers map[string][]string) (bool, string, string) {
	// 检测URL路径
	if detected, pattern := d.Detect(path); detected {
		return true, pattern, "path"
	}

	// 检测查询参数
	if detected, pattern := d.Detect(query); detected {
		return true, pattern, "query"
	}

	// 检测请求体
	if method == "POST" || method == "PUT" || method == "PATCH" {
		if detected, pattern := d.Detect(body); detected {
			return true, pattern, "body"
		}
	}

	return false, "", ""
}

// GetPatternCount 获取规则数量
func (d *CommandInjectionDetector) GetPatternCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.patterns)
}
