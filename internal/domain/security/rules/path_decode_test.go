package rules

import (
	"testing"
)

func TestNewPathDecoder(t *testing.T) {
	t.Helper()
	tests := []struct {
		name       string
		enabled    bool
		maxRounds  int
		wantEn     bool
		wantRounds int
	}{
		{"默认参数", true, 2, true, 2},
		{"禁用", false, 2, false, 2},
		{"零轮次修正为2", true, 0, true, 2},
		{"负数轮次修正为2", true, -1, true, 2},
		{"超过3轮次修正为3", true, 5, true, 3},
		{"恰好3轮", true, 3, true, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewPathDecoder(tt.enabled, tt.maxRounds)
			if d.Enabled() != tt.wantEn {
				t.Errorf("Enabled() = %v, want %v", d.Enabled(), tt.wantEn)
			}
			if d.maxDecodeRounds != tt.wantRounds {
				t.Errorf("maxDecodeRounds = %v, want %v", d.maxDecodeRounds, tt.wantRounds)
			}
		})
	}
}

func TestPathDecoder_Decode_SingleEncoding(t *testing.T) {
	t.Helper()
	d := NewPathDecoder(true, 2)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"单重编码路径", "%2fadmin", "/admin"},
		{"编码斜杠和内容", "/%2e%67%69%74", "/.git"},
		{"无需解码", "/admin", "/admin"},
		{"空路径", "", ""},
		{"编码空格", "/path%20name", "/path name"},
		{"编码点号", "/.env%2fconfig", "/.env/config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Decode(tt.input)
			if err != nil {
				t.Errorf("Decode() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Decode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPathDecoder_Decode_DoubleEncoding(t *testing.T) {
	t.Helper()
	d := NewPathDecoder(true, 2)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"双重编码斜杠", "%252fadmin", "/admin"},
		{"双重编码点号", "/%252e%2567%2569%2574", "/.git"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Decode(tt.input)
			if err != nil {
				t.Errorf("Decode() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Decode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPathDecoder_Decode_TripleEncoding(t *testing.T) {
	t.Helper()
	d := NewPathDecoder(true, 2)
	got, err := d.Decode("%25252fadmin")
	if err != nil {
		t.Errorf("Decode() error = %v", err)
	}
	if got != "%2fadmin" {
		t.Errorf("Triple encoding with maxRounds=2: got %q, want %q", got, "%2fadmin")
	}

	d3 := NewPathDecoder(true, 3)
	got3, err3 := d3.Decode("%25252fadmin")
	if err3 != nil {
		t.Errorf("Decode() error = %v", err3)
	}
	if got3 != "/admin" {
		t.Errorf("Triple encoding with maxRounds=3: got %q, want %q", got3, "/admin")
	}
}

func TestPathDecoder_Decode_InvalidEncoding(t *testing.T) {
	t.Helper()
	d := NewPathDecoder(true, 2)
	got, err := d.Decode("/path%ZZtest")
	if err == nil {
		t.Error("Expected error for invalid encoding, got nil")
	}
	if got != "/path%ZZtest" {
		t.Errorf("Invalid encoding should return original path, got %q", got)
	}
}

func TestPathDecoder_Decode_Disabled(t *testing.T) {
	t.Helper()
	d := NewPathDecoder(false, 2)
	got, err := d.Decode("%2fadmin")
	if err != nil {
		t.Errorf("Decode() error = %v", err)
	}
	if got != "%2fadmin" {
		t.Errorf("Disabled decoder should not decode, got %q, want %q", got, "%2fadmin")
	}

	got2, err2 := d.Decode("/a/b/../c")
	if err2 != nil {
		t.Errorf("Decode() error = %v", err2)
	}
	if got2 != "/a/c" {
		t.Errorf("Disabled decoder should still normalize, got %q, want %q", got2, "/a/c")
	}
}

func TestNormalizePath(t *testing.T) {
	t.Helper()
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"遍历上级", "/a/b/../c", "/a/c"},
		{"连续遍历", "/a/../../b", "/b"},
		{"当前目录", "/a/./b", "/a/b"},
		{"双斜杠", "//a//b", "/a/b"},
		{"混合", "/a/b/./../c/./d", "/a/c/d"},
		{"超出根目录", "/../../../etc/passwd", "/etc/passwd"},
		{"空路径", "", ""},
		{"单斜杠", "/", "/"},
		{"无前导斜杠", "a/b/../c", "a/c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePath(tt.input)
			if got != tt.want {
				t.Errorf("normalizePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizePath_Truncation(t *testing.T) {
	t.Helper()
	longPath := "/a"
	for i := 0; i < 2500; i++ {
		longPath += "/segment"
	}
	if len(longPath) <= maxPathLength {
		t.Skip("path not long enough to test truncation")
	}
	got := normalizePath(longPath)
	if len(got) > maxPathLength {
		t.Errorf("normalizePath() result length %d exceeds max %d", len(got), maxPathLength)
	}
}

func TestPathDecoder_Decode_RealWorldAttack(t *testing.T) {
	t.Helper()
	d := NewPathDecoder(true, 2)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"编码绕过.git", "/.git%2fHEAD", "/.git/HEAD"},
		{"编码绕过.env", "/.env%2flocal", "/.env/local"},
		{"路径遍历编码", "/%2e%2e/%2e%2e/etc/passwd", "/etc/passwd"},
		{"双重编码遍历", "/%252e%252e/%252e%252e/etc/passwd", "/etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Decode(tt.input)
			if err != nil {
				t.Errorf("Decode() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Decode() = %q, want %q", got, tt.want)
			}
		})
	}
}
