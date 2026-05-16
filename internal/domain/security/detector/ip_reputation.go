package detector

import (
	"net"
	"sync"
	"time"
)

type IPReputationChecker struct {
	mu          sync.RWMutex
	cache       map[string]*reputationEntry
	cacheTTL    time.Duration
	torExits    map[string]bool
	privateNets []*net.IPNet
}

type reputationEntry struct {
	isBad    bool
	reason   string
	cachedAt time.Time
}

func NewIPReputationChecker() *IPReputationChecker {
	c := &IPReputationChecker{
		cache:    make(map[string]*reputationEntry),
		cacheTTL: 10 * time.Minute,
		torExits: make(map[string]bool),
	}
	c.initPrivateNets()
	c.initKnownTorExits()
	return c
}

func (c *IPReputationChecker) initPrivateNets() {
	nets := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"0.0.0.0/8",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}
	for _, cidr := range nets {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			c.privateNets = append(c.privateNets, ipNet)
		}
	}
}

func (c *IPReputationChecker) initKnownTorExits() {
	c.torExits = make(map[string]bool)
}

func (c *IPReputationChecker) IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	for _, n := range c.privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (c *IPReputationChecker) IsTorExit(ipStr string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.torExits[ipStr]
}

func (c *IPReputationChecker) LoadTorExits(exits []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.torExits = make(map[string]bool, len(exits))
	for _, e := range exits {
		c.torExits[e] = true
	}
}

func (c *IPReputationChecker) Check(ip string) (bool, string) {
	if c.IsPrivateIP(ip) {
		return false, ""
	}
	c.mu.RLock()
	entry, exists := c.cache[ip]
	c.mu.RUnlock()
	if exists && time.Since(entry.cachedAt) < c.cacheTTL {
		return entry.isBad, entry.reason
	}
	if c.IsTorExit(ip) {
		c.setCache(ip, true, "Tor出口节点")
		return true, "Tor出口节点"
	}
	return false, ""
}

func (c *IPReputationChecker) setCache(ip string, isBad bool, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ip] = &reputationEntry{
		isBad:    isBad,
		reason:   reason,
		cachedAt: time.Now(),
	}
}

func (c *IPReputationChecker) SetReputation(ip string, isBad bool, reason string) {
	c.setCache(ip, isBad, reason)
}
