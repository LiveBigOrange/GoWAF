package ratelimit

import (
	"strings"
	"sync"
	"time"
)

type AttackChainStage int

const (
	StageNone  AttackChainStage = -1
	StageRecon AttackChainStage = iota
	StageScan
	StageExploit
	StageExfil
)

var attackChainPatterns = map[string][]AttackChainStage{
	"recon_to_sqli":   {StageRecon, StageExploit},
	"recon_to_scan":   {StageRecon, StageScan},
	"scan_to_exploit": {StageScan, StageExploit},
	"full_kill_chain": {StageRecon, StageScan, StageExploit, StageExfil},
}

var reconPaths = []string{"/.env", "/.git", "/robots.txt", "/admin", "/wp-admin", "/phpinfo.php", "/.DS_Store"}
var scanPaths = []string{"/api/", "/v1/", "/v2/", "/actuator", "/swagger", "/graphql", "/debug", "/console"}
var exploitIndicators = []string{"sql_injection", "xss", "command_injection", "path_traversal", "ssrf", "file_upload"}
var exfilIndicators = []string{"sensitive_data", "outbound_connection"}

type AttackChainTracker struct {
	mu        sync.RWMutex
	ipStages  map[string]map[AttackChainStage]time.Time
	ipAttacks map[string][]string
}

func NewAttackChainTracker() *AttackChainTracker {
	return &AttackChainTracker{
		ipStages:  make(map[string]map[AttackChainStage]time.Time),
		ipAttacks: make(map[string][]string),
	}
}

func (a *AttackChainTracker) Record(ip, path, attackType string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.ipStages[ip] == nil {
		a.ipStages[ip] = make(map[AttackChainStage]time.Time)
	}

	stage := a.detectStage(path, attackType)
	if stage != StageNone {
		a.ipStages[ip][stage] = time.Now()
	}

	if attackType != "" {
		a.ipAttacks[ip] = append(a.ipAttacks[ip], attackType)
		if len(a.ipAttacks[ip]) > 50 {
			a.ipAttacks[ip] = a.ipAttacks[ip][len(a.ipAttacks[ip])-50:]
		}
	}
}

func (a *AttackChainTracker) detectStage(path, attackType string) AttackChainStage {
	for _, p := range reconPaths {
		if strings.Contains(path, p) {
			return StageRecon
		}
	}
	for _, p := range scanPaths {
		if strings.Contains(path, p) {
			return StageScan
		}
	}
	for _, at := range exploitIndicators {
		if strings.Contains(attackType, at) {
			return StageExploit
		}
	}
	for _, at := range exfilIndicators {
		if strings.Contains(attackType, at) {
			return StageExfil
		}
	}
	return StageNone
}

func (a *AttackChainTracker) GetChainScore(ip string) float64 {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stages := a.ipStages[ip]
	if len(stages) < 2 {
		return 0
	}

	maxScore := 0.0
	now := time.Now()
	window := 10 * time.Minute

	for _, pattern := range attackChainPatterns {
		matched := 0
		lastTime := time.Time{}
		inOrder := true
		for _, stage := range pattern {
			t, ok := stages[stage]
			if ok && now.Sub(t) < window {
				matched++
				if !lastTime.IsZero() && t.Before(lastTime) {
					inOrder = false
				}
				lastTime = t
			}
		}
		if matched >= 2 {
			score := float64(matched) / float64(len(pattern))
			if !inOrder {
				score *= 0.5
			}
			if score > maxScore {
				maxScore = score
			}
		}
	}

	return maxScore
}

func (a *AttackChainTracker) GetRecentAttackTypes(ip string) []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.ipAttacks[ip]
}

type GlobalAttackStats struct {
	mu           sync.RWMutex
	typeCounts   map[string]int64
	totalAttacks int64
	lastReset    time.Time
}

func NewGlobalAttackStats() *GlobalAttackStats {
	return &GlobalAttackStats{
		typeCounts: make(map[string]int64),
		lastReset:  time.Now(),
	}
}

func (g *GlobalAttackStats) Record(attackType string) {
	if attackType == "" {
		return
	}
	g.mu.Lock()
	g.typeCounts[attackType]++
	g.totalAttacks++
	g.mu.Unlock()
}

func (g *GlobalAttackStats) GetWeights(allTypes []string) map[string]float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	weights := make(map[string]float64)
	for _, t := range allTypes {
		weights[t] = 0
	}

	if g.totalAttacks < 10 {
		return weights
	}

	for at, count := range g.typeCounts {
		ratio := float64(count) / float64(g.totalAttacks)
		for _, t := range allTypes {
			if strings.Contains(at, t) {
				if ratio > weights[t] {
					weights[t] = ratio
				}
			}
		}
	}

	return weights
}

func (g *GlobalAttackStats) ResetIfNeeded() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Since(g.lastReset) > time.Hour {
		g.typeCounts = make(map[string]int64)
		g.totalAttacks = 0
		g.lastReset = time.Now()
	}
}
