package ratelimit

import (
	"log"
	"sync"
	"time"
)

type IPRuleManager interface {
	AddIPRule(ruleType, ip string) error
	RemoveIPRule(ruleType, ip string) error
}

type AutoBlocker struct {
	mu            sync.Mutex
	failCount     map[string]int
	blockedUntil  map[string]time.Time
	ruleEngine    IPRuleManager
	maxFails      int
	blockDuration time.Duration
}

func NewAutoBlocker(ruleEngine IPRuleManager, maxFails int, blockDuration time.Duration) *AutoBlocker {
	return &AutoBlocker{
		failCount:     make(map[string]int),
		blockedUntil:  make(map[string]time.Time),
		ruleEngine:    ruleEngine,
		maxFails:      maxFails,
		blockDuration: blockDuration,
	}
}

func (a *AutoBlocker) RecordChallengeFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, blocked := a.blockedUntil[ip]; blocked {
		return
	}

	if a.failCount[ip] >= a.maxFails-1 {
		a.blockedUntil[ip] = time.Now().Add(a.blockDuration)
		if err := a.ruleEngine.AddIPRule("blacklist", ip); err != nil {
			log.Printf("[autoblock] 自动封禁IP %s 失败: %v", ip, err)
			delete(a.blockedUntil, ip)
		} else {
			log.Printf("[autoblock] 自动封禁IP %s (持续%v)", ip, a.blockDuration)
			a.failCount[ip] = 0
		}
	} else {
		a.failCount[ip]++
	}
}

func (a *AutoBlocker) RecordChallengePass(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failCount[ip] = 0
}

func (a *AutoBlocker) IsBlocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, exists := a.blockedUntil[ip]
	if !exists {
		return false
	}
	if time.Now().After(until) {
		delete(a.blockedUntil, ip)
		a.failCount[ip] = 0
		if err := a.ruleEngine.RemoveIPRule("blacklist", ip); err != nil {
			log.Printf("[autoblock] 自动解封IP %s 失败: %v", ip, err)
		} else {
			log.Printf("[autoblock] 自动解封IP %s (已过期)", ip)
		}
		return false
	}
	return true
}

func (a *AutoBlocker) ExpireBlocks() {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	for ip, until := range a.blockedUntil {
		if now.After(until) {
			delete(a.blockedUntil, ip)
			a.failCount[ip] = 0
			if err := a.ruleEngine.RemoveIPRule("blacklist", ip); err != nil {
				log.Printf("[autoblock] 自动解封IP %s 失败: %v", ip, err)
			} else {
				log.Printf("[autoblock] 自动解封IP %s (已过期)", ip)
			}
		}
	}
}
