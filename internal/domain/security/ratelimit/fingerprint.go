package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

type FingerprintTracker struct {
	mu            sync.RWMutex
	fpToIPs       map[string]map[string]time.Time
	ipToFP        map[string]string
	blockedFPs    map[string]bool
	suspectFPs    map[string]bool
	fpTransitions map[string]map[string]time.Time
	lastCleanup   time.Time
}

func NewFingerprintTracker() *FingerprintTracker {
	return &FingerprintTracker{
		fpToIPs:       make(map[string]map[string]time.Time),
		ipToFP:        make(map[string]string),
		blockedFPs:    make(map[string]bool),
		suspectFPs:    make(map[string]bool),
		fpTransitions: make(map[string]map[string]time.Time),
		lastCleanup:   time.Now(),
	}
}

func HashFingerprint(headers map[string]string) string {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var sb strings.Builder
	sb.WriteString("fp:")
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(headers[k])
		sb.WriteString(";")
	}

	h := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(h[:16])
}

func BuildFingerprintFromRequest(ua, acceptLang, acceptEncoding, secChUa, secChPlatform, secChUaMobile string) string {
	return HashFingerprint(map[string]string{
		"ua":               ua,
		"accept_lang":      acceptLang,
		"accept_enc":       acceptEncoding,
		"sec_ch_ua":        secChUa,
		"sec_ch_platform":  secChPlatform,
		"sec_ch_ua_mobile": secChUaMobile,
	})
}

func (t *FingerprintTracker) Record(ip, fingerprint string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if oldFP, exists := t.ipToFP[ip]; exists && oldFP == fingerprint {
		if ips, ok := t.fpToIPs[oldFP]; ok {
			ips[ip] = time.Now()
		}
		return
	}

	if oldFP, exists := t.ipToFP[ip]; exists && oldFP != fingerprint {
		if ips, ok := t.fpToIPs[oldFP]; ok {
			delete(ips, ip)
		}
		if t.fpTransitions[oldFP] == nil {
			t.fpTransitions[oldFP] = make(map[string]time.Time)
		}
		t.fpTransitions[oldFP][fingerprint] = time.Now()
	}

	t.ipToFP[ip] = fingerprint

	if t.fpToIPs[fingerprint] == nil {
		t.fpToIPs[fingerprint] = make(map[string]time.Time)
	}
	t.fpToIPs[fingerprint][ip] = time.Now()
}

func (t *FingerprintTracker) GetSharedIPs(ip string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	fp, exists := t.ipToFP[ip]
	if !exists {
		return nil
	}

	ips, ok := t.fpToIPs[fp]
	if !ok {
		return nil
	}

	result := make([]string, 0, len(ips)-1)
	for otherIP := range ips {
		if otherIP != ip {
			result = append(result, otherIP)
		}
	}
	return result
}

func (t *FingerprintTracker) IsFingerprintBlocked(fp string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.blockedFPs[fp]
}

func (t *FingerprintTracker) MarkFingerprintBlocked(fp string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.blockedFPs[fp] = true
}

func (t *FingerprintTracker) UnmarkFingerprint(fp string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.blockedFPs, fp)
}

func (t *FingerprintTracker) GetSharedRiskScore(ip string) float64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	fp, exists := t.ipToFP[ip]
	if !exists {
		return 0
	}

	if t.blockedFPs[fp] {
		return 0.6
	}
	if t.suspectFPs[fp] {
		return 0.4
	}

	for srcFP := range t.fpTransitions {
		if t.blockedFPs[srcFP] {
			if dst, ok := t.fpTransitions[srcFP][fp]; ok && time.Since(dst) < 30*time.Minute {
				return 0.45
			}
		}
	}

	ips := t.fpToIPs[fp]
	count := len(ips)
	if count > 3 {
		return math.Min(float64(count-3)*0.05, 1.0)
	}

	return 0
}

func (t *FingerprintTracker) GetFingerprint(ip string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.ipToFP[ip]
}

func (t *FingerprintTracker) IsSuspect(fp string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.suspectFPs[fp]
}

func (t *FingerprintTracker) MarkSuspect(fp string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.suspectFPs[fp] = true
}

func (t *FingerprintTracker) GetFingerprintIPCount(fp string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.fpToIPs[fp])
}

func (t *FingerprintTracker) Cleanup(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if time.Since(t.lastCleanup) < maxAge/2 {
		return
	}
	t.lastCleanup = time.Now()

	now := time.Now()
	for fp, ips := range t.fpToIPs {
		for ip, lastSeen := range ips {
			if now.Sub(lastSeen) > maxAge {
				delete(ips, ip)
				if t.ipToFP[ip] == fp {
					delete(t.ipToFP, ip)
				}
			}
		}
		if len(ips) == 0 {
			delete(t.fpToIPs, fp)
			delete(t.blockedFPs, fp)
			delete(t.suspectFPs, fp)
		}
	}
	for ip, fp := range t.ipToFP {
		if ips, ok := t.fpToIPs[fp]; !ok || len(ips) == 0 {
			delete(t.ipToFP, ip)
		}
	}
}
