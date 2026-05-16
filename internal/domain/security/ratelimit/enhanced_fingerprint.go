package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type EnhancedFingerprint struct {
	HTTPFingerprint string
	JA3Fingerprint  string
	CombinedHash    string
}

func BuildEnhancedFingerprintFromRequest(
	userAgent, acceptLang, acceptEnc, accept, secChUa, secChUaPlatform string,
	ja3Hash string,
) EnhancedFingerprint {
	httpFP := BuildFingerprintFromRequest(userAgent, acceptLang, acceptEnc, secChUa, secChUaPlatform, accept)

	ef := EnhancedFingerprint{
		HTTPFingerprint: httpFP,
		JA3Fingerprint:  ja3Hash,
	}

	if ja3Hash != "" {
		h := sha256.New()
		h.Write([]byte(httpFP))
		h.Write([]byte("|"))
		h.Write([]byte(ja3Hash))
		ef.CombinedHash = hex.EncodeToString(h.Sum(nil))[:32]
	} else {
		ef.CombinedHash = httpFP
	}

	return ef
}

func (ef EnhancedFingerprint) IsEmpty() bool {
	return ef.CombinedHash == ""
}

func (ef EnhancedFingerprint) Similarity(other EnhancedFingerprint) float64 {
	if ef.CombinedHash == other.CombinedHash {
		return 1.0
	}
	score := 0.0
	if ef.HTTPFingerprint != "" && ef.HTTPFingerprint == other.HTTPFingerprint {
		score += 0.6
	} else if ef.HTTPFingerprint != "" && other.HTTPFingerprint != "" {
		if jaccardSimilarity(ef.HTTPFingerprint, other.HTTPFingerprint) > 0.7 {
			score += 0.4
		}
	}
	if ef.JA3Fingerprint != "" && ef.JA3Fingerprint == other.JA3Fingerprint {
		score += 0.4
	}
	return score
}

func jaccardSimilarity(a, b string) float64 {
	setA := make(map[rune]bool)
	setB := make(map[rune]bool)
	for _, ch := range a {
		setA[ch] = true
	}
	for _, ch := range b {
		setB[ch] = true
	}
	intersection := 0
	for ch := range setA {
		if setB[ch] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

type AttackerProfile struct {
	ID          string
	Fingerprint EnhancedFingerprint
	IPs         map[string]bool
	FirstSeen   int64
	LastSeen    int64
	BlockCount  int64
	IsBlocked   bool
	BlockReason string
	AttackTypes map[string]int
}

func NewAttackerProfile(id string, fp EnhancedFingerprint, now int64) *AttackerProfile {
	return &AttackerProfile{
		ID:          id,
		Fingerprint: fp,
		IPs:         make(map[string]bool),
		FirstSeen:   now,
		LastSeen:    now,
		AttackTypes: make(map[string]int),
	}
}

func (ap *AttackerProfile) AddIP(ip string) {
	ap.IPs[ip] = true
}

func (ap *AttackerProfile) IPCount() int {
	return len(ap.IPs)
}

func (ap *AttackerProfile) RecordAttack(attackType string) {
	ap.AttackTypes[attackType]++
	ap.BlockCount++
}

func (ap *AttackerProfile) ShouldBlockByAttacker() (bool, string) {
	if ap.IsBlocked {
		return true, ap.BlockReason
	}
	if ap.IPCount() > 10 && ap.BlockCount > 5 {
		return true, "攻击者画像:多IP+高拦截"
	}
	return false, ""
}

func NormalizeUserAgent(ua string) string {
	ua = strings.ToLower(ua)
	replacements := []struct {
		old string
		new string
	}{
		{"mozilla/5.0 ", ""},
		{"(compatible; ", ""},
		{"windows nt ", "win"},
		{"macintosh; ", "mac;"},
		{"linux; ", "lin;"},
		{"x11; ", "x11;"},
	}
	for _, r := range replacements {
		ua = strings.ReplaceAll(ua, r.old, r.new)
	}
	return ua
}
