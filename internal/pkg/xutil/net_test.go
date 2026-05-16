package xutil

import "testing"

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"fc00::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.1", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tt := range tests {
		got := IsPrivateIP(tt.ip)
		if got != tt.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsURLHostPrivate(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1/admin", true},
		{"http://10.0.0.1:8080/api", true},
		{"http://169.254.169.254/latest/meta-data/", true},
		{"http://192.168.1.1/secret", true},
		{"https://8.8.8.8/dns", false},
		{"https://example.com/api", false},
		{"not-a-url", false},
		{"", false},
	}
	for _, tt := range tests {
		got := IsURLHostPrivate(tt.url)
		if got != tt.want {
			t.Errorf("IsURLHostPrivate(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}
