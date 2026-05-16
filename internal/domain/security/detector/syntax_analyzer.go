package detector

import (
	"regexp"
	"strings"
	"unicode"
)

type SyntaxAnalyzer struct {
	sqlKeywords    map[string]bool
	sqlFunctions   map[string]bool
	dangerousChars map[rune]bool
}

func NewSyntaxAnalyzer() *SyntaxAnalyzer {
	sa := &SyntaxAnalyzer{
		sqlKeywords:    make(map[string]bool),
		sqlFunctions:   make(map[string]bool),
		dangerousChars: make(map[rune]bool),
	}
	keywords := []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
		"UNION", "JOIN", "WHERE", "FROM", "INTO", "SET", "VALUES",
		"EXEC", "EXECUTE", "HAVING", "GROUP", "ORDER", "LIMIT",
		"TRUNCATE", "REPLACE", "MERGE", "GRANT", "REVOKE",
	}
	for _, kw := range keywords {
		sa.sqlKeywords[kw] = true
	}
	functions := []string{
		"CONCAT", "CHAR", "HEX", "UNHEX", "BASE64", "LOAD_FILE",
		"INTO_OUTFILE", "INTO_DUMPFILE", "BENCHMARK", "SLEEP",
		"WAITFOR", "DELAY", "PG_SLEEP", "DBMS_PIPE",
		"INFORMATION_SCHEMA", "VERSION", "DATABASE", "USER",
		"CURRENT_USER", "SESSION_USER", "SYSTEM_USER",
	}
	for _, fn := range functions {
		sa.sqlFunctions[fn] = true
	}
	for _, ch := range `'";--#` {
		sa.dangerousChars[ch] = true
	}
	return sa
}

func (sa *SyntaxAnalyzer) AnalyzeSQLInjection(input string) SQLAnalysisResult {
	result := SQLAnalysisResult{}
	upper := strings.ToUpper(input)

	if sa.hasUnmatchedQuotes(input) {
		result.HasUnmatchedQuotes = true
		result.RiskScore += 0.3
		result.Reasons = append(result.Reasons, "引号不配对")
	}

	if sa.hasSQLKeywordAfterBreak(input, upper) {
		result.HasKeywordAfterBreak = true
		result.RiskScore += 0.4
		result.Reasons = append(result.Reasons, "分隔符后跟随SQL关键字")
	}

	if sa.hasUnionSelect(upper) {
		result.HasUnionSelect = true
		result.RiskScore += 0.5
		result.Reasons = append(result.Reasons, "UNION SELECT模式")
	}

	if sa.hasBooleanCondition(input, upper) {
		result.HasBooleanCondition = true
		result.RiskScore += 0.3
		result.Reasons = append(result.Reasons, "布尔条件注入模式")
	}

	if sa.hasNestedParentheses(input) > 3 {
		result.HasNestedParens = true
		result.RiskScore += 0.3
		result.Reasons = append(result.Reasons, "深层嵌套括号")
	}

	if sa.hasDangerousFunction(upper) {
		result.HasDangerousFunc = true
		result.RiskScore += 0.5
		result.Reasons = append(result.Reasons, "危险SQL函数")
	}

	if result.RiskScore > 1.0 {
		result.RiskScore = 1.0
	}
	result.IsLikelyInjection = result.RiskScore >= 0.4
	return result
}

func (sa *SyntaxAnalyzer) AnalyzeCommandInjection(input string) CMDAnalysisResult {
	result := CMDAnalysisResult{}

	if sa.hasShellMetacharSpacing(input) {
		result.HasMetacharSpacing = true
		result.RiskScore += 0.4
		result.Reasons = append(result.Reasons, "Shell元字符连接命令")
	}

	if sa.hasCommandSubstitution(input) {
		result.HasSubstitution = true
		result.RiskScore += 0.5
		result.Reasons = append(result.Reasons, "命令替换$(...)或`...`")
	}

	if sa.hasRedirectionWithSensitivePath(input) {
		result.HasRedirection = true
		result.RiskScore += 0.4
		result.Reasons = append(result.Reasons, "重定向到敏感路径")
	}

	if result.RiskScore > 1.0 {
		result.RiskScore = 1.0
	}
	result.IsLikelyInjection = result.RiskScore >= 0.4
	return result
}

type SQLAnalysisResult struct {
	HasUnmatchedQuotes   bool
	HasKeywordAfterBreak bool
	HasUnionSelect       bool
	HasBooleanCondition  bool
	HasNestedParens      bool
	HasDangerousFunc     bool
	IsLikelyInjection    bool
	RiskScore            float64
	Reasons              []string
}

type CMDAnalysisResult struct {
	HasMetacharSpacing bool
	HasSubstitution    bool
	HasRedirection     bool
	IsLikelyInjection  bool
	RiskScore          float64
	Reasons            []string
}

func (sa *SyntaxAnalyzer) hasUnmatchedQuotes(input string) bool {
	singleCount := 0
	doubleCount := 0
	escaped := false
	for _, ch := range input {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\'' {
			singleCount++
		} else if ch == '"' {
			doubleCount++
		}
	}
	return singleCount%2 != 0 || doubleCount%2 != 0
}

var breakPattern = regexp.MustCompile(`(?:'|"|;|--|#|/\*)\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC|HAVING|FROM|WHERE)`)

func (sa *SyntaxAnalyzer) hasSQLKeywordAfterBreak(input, upper string) bool {
	return breakPattern.MatchString(upper)
}

var unionSelectPattern = regexp.MustCompile(`(?i)UNION\s+(?:ALL\s+)?SELECT`)

func (sa *SyntaxAnalyzer) hasUnionSelect(upper string) bool {
	return unionSelectPattern.MatchString(upper)
}

var booleanPattern = regexp.MustCompile(`(?i)(?:OR|AND)\s+(?:\d+\s*=\s*\d+|'?1'?\s*=\s*'?1'?|TRUE|FALSE|[a-zA-Z_]\w*\s*=\s*\d+)`)

func (sa *SyntaxAnalyzer) hasBooleanCondition(input, upper string) bool {
	return booleanPattern.MatchString(upper)
}

func (sa *SyntaxAnalyzer) hasNestedParentheses(input string) int {
	maxDepth := 0
	depth := 0
	for _, ch := range input {
		if ch == '(' {
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		} else if ch == ')' {
			depth--
		}
	}
	return maxDepth
}

var dangerousFuncPattern = regexp.MustCompile(`(?i)(?:LOAD_FILE|INTO_OUTFILE|INTO_DUMPFILE|BENCHMARK|SLEEP|WAITFOR\s+DELAY|PG_SLEEP|DBMS_PIPE|INFORMATION_SCHEMA|DATABASE\(\)|USER\(\)|VERSION\(\)|CURRENT_USER|SESSION_USER|SYSTEM_USER)`)

func (sa *SyntaxAnalyzer) hasDangerousFunction(upper string) bool {
	return dangerousFuncPattern.MatchString(upper)
}

var metacharCmdPattern = regexp.MustCompile(`[;|&]\s*(?:cat|ls|id|whoami|pwd|uname|wget|curl|nc|bash|sh|python|perl|ruby|php|powershell|cmd|dir|net)\b`)

func (sa *SyntaxAnalyzer) hasShellMetacharSpacing(input string) bool {
	return metacharCmdPattern.MatchString(input)
}

var cmdSubstPattern = regexp.MustCompile(`(?:\$\([^)]+\)|` + "`" + `[^` + "`" + `]+` + "`" + `)`)

func (sa *SyntaxAnalyzer) hasCommandSubstitution(input string) bool {
	return cmdSubstPattern.MatchString(input)
}

var redirectSensitivePattern = regexp.MustCompile(`(?:>|>>)\s*(?:/etc/|/proc/|/var/log|/tmp/|C:\\Windows\\|C:\\inetpub\\)`)

func (sa *SyntaxAnalyzer) hasRedirectionWithSensitivePath(input string) bool {
	return redirectSensitivePattern.MatchString(input)
}

func IsLikelyNormalInput(input string) bool {
	if len(input) > 200 {
		return false
	}
	nonPrintable := 0
	for _, ch := range input {
		if !unicode.IsPrint(ch) && ch != ' ' && ch != '\t' && ch != '\n' {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(input)) <= 0.3
}
