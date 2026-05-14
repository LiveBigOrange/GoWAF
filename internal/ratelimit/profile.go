package ratelimit

import (
	"sync"
	"time"
)

type Action int

const (
	Allow Action = iota
	Slowdown
	Throttle
	Challenge
	Block
)

func (a Action) String() string {
	switch a {
	case Allow:
		return "allow"
	case Slowdown:
		return "slowdown"
	case Throttle:
		return "throttle"
	case Challenge:
		return "challenge"
	case Block:
		return "block"
	default:
		return "allow"
	}
}

func (a Action) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}

type RequestInfo struct {
	IP         string
	Method     string
	Path       string
	UserAgent  string
	StatusCode int
	RuleID     string
	IsBlocked  bool
	BodySize   int64
	Upstream   string
	Cookie     string
	Referer    string
	CountryISO string
}

type IPProfile struct {
	mu sync.RWMutex
	ip string

	RequestRate *SlidingWindow
	BlockRate   *SlidingWindow
	ErrorRatio  *RatioWindow
	PathDiv     *UniqueCounter
	UADiv       *UniqueCounter
	RuleHitDiv  *UniqueCounter
	Interval    *IntervalTracker

	PathRate     map[string]*SlidingWindow
	SensitiveHit *SlidingWindow

	MethodDiv    *UniqueCounter
	NoCookieWin  *RatioWindow
	NoRefererWin *RatioWindow
	BodySizeWin  *SlidingWindow

	firstCountryISO    string
	countryChangeCount int
	lastUA             string

	lastActive time.Time
	blockCount int64
	totalCount int64
	trustScore float64

	fingerprintHash string
	hourCounts      [24]int64
	hourErrors      [24]int64
	lastFeedback    time.Time
	consecutivePass int
	attackTypes     map[string]int
}

const maxPathRates = 200

func NewIPProfile(ip string, cfg *Config) *IPProfile {
	return &IPProfile{
		ip:           ip,
		RequestRate:  NewSlidingWindow(cfg.WindowSize, cfg.SubInterval(), cfg.IPRequestThreshold),
		BlockRate:    NewSlidingWindow(cfg.WindowSize, cfg.SubInterval(), cfg.IPBlockThreshold),
		ErrorRatio:   NewRatioWindow(cfg.WindowSize, cfg.SubInterval()),
		PathDiv:      NewUniqueCounter(cfg.WindowSize, cfg.SubInterval(), cfg.PathDivMax),
		UADiv:        NewUniqueCounter(cfg.WindowSize, cfg.SubInterval(), cfg.UADivMax),
		RuleHitDiv:   NewUniqueCounter(cfg.WindowSize, cfg.SubInterval(), cfg.RuleDivMax),
		Interval:     NewIntervalTracker(cfg.MaxSamples),
		PathRate:     make(map[string]*SlidingWindow),
		SensitiveHit: NewSlidingWindow(cfg.WindowSize, cfg.SubInterval(), cfg.SensitivePathThreshold),
		MethodDiv:    NewUniqueCounter(cfg.WindowSize, cfg.SubInterval(), 10),
		NoCookieWin:  NewRatioWindow(cfg.WindowSize, cfg.SubInterval()),
		NoRefererWin: NewRatioWindow(cfg.WindowSize, cfg.SubInterval()),
		BodySizeWin:  NewSlidingWindow(cfg.WindowSize, cfg.SubInterval(), cfg.BodySizeThreshold),
		lastActive:   time.Now(),
		attackTypes:  make(map[string]int),
	}
}

func (p *IPProfile) Record(req RequestInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	p.lastActive = now
	p.totalCount++
	p.Interval.Record()

	p.RequestRate.Incr()

	isError := req.StatusCode >= 400

	if req.IsBlocked {
		p.BlockRate.Incr()
		p.blockCount++
		p.trustScore -= 2.0
	} else if isError {
		if p.totalCount > 1 {
			p.trustScore -= 1.0
		}
	} else {
		if p.totalCount > 1 {
			p.trustScore += 0.1
			if p.totalCount%10 == 0 {
				p.trustScore += 1.0
			}
		}
	}
	if p.trustScore > 100 {
		p.trustScore = 100
	}
	if p.trustScore < -50 {
		p.trustScore = -50
	}

	p.ErrorRatio.Record(isError)

	p.PathDiv.Add(req.Path)
	p.UADiv.Add(req.UserAgent)
	p.MethodDiv.Add(req.Method)
	p.lastUA = req.UserAgent

	if req.RuleID != "" {
		p.RuleHitDiv.Add(req.RuleID)
	}

	if isError || req.IsBlocked {
		pathRate, exists := p.PathRate[req.Path]
		if !exists && len(p.PathRate) < maxPathRates {
			pathRate = NewSlidingWindow(60, time.Second, 20)
			p.PathRate[req.Path] = pathRate
		}
		if pathRate != nil {
			pathRate.Incr()
		}
	}

	if isSensitivePath(req.Path) {
		p.SensitiveHit.Incr()
	}

	p.NoCookieWin.Record(req.Cookie == "")
	p.NoRefererWin.Record(req.Referer == "")

	if req.BodySize > 0 {
		p.BodySizeWin.Incr()
	}

	if req.CountryISO != "" {
		if p.firstCountryISO == "" {
			p.firstCountryISO = req.CountryISO
		} else if req.CountryISO != p.firstCountryISO {
			p.countryChangeCount++
		}
	}

	if req.RuleID != "" {
		p.attackTypes[req.RuleID]++
	}

	hour := now.Hour()
	p.hourCounts[hour]++
	if isError || req.IsBlocked {
		p.hourErrors[hour]++
	}

	p.lastFeedback = now
	if !isError && !req.IsBlocked {
		p.consecutivePass++
	} else {
		p.consecutivePass = 0
	}
}

func (p *IPProfile) SetFingerprint(fp string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fingerprintHash = fp
}

func (p *IPProfile) GetHourAnomaly(trustedHours map[int]bool) float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	currentHour := time.Now().Hour()
	if trustedHours != nil && trustedHours[currentHour] {
		return 0
	}

	var avgRequests float64
	nonZeroCount := 0
	for _, c := range p.hourCounts {
		if c > 0 {
			avgRequests += float64(c)
			nonZeroCount++
		}
	}
	if nonZeroCount < 2 {
		return 0
	}
	avgRequests /= float64(nonZeroCount)

	currentRequests := float64(p.hourCounts[currentHour])
	if currentRequests > avgRequests*3 && currentRequests > 20 {
		return (currentRequests - avgRequests*3) / (avgRequests * 7)
	}

	return 0
}

func (p *IPProfile) Expire(maxAge time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.PathDiv.Expire(maxAge)
	p.UADiv.Expire(maxAge)
	p.RuleHitDiv.Expire(maxAge)
	p.MethodDiv.Expire(maxAge)

	for k, w := range p.PathRate {
		if w.Sum() == 0 {
			delete(p.PathRate, k)
		}
	}
}

func (p *IPProfile) Snapshot() ProfileSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	pathRates := make(map[string]int64)
	for path, w := range p.PathRate {
		pathRates[path] = w.Sum()
	}

	attackTypesCopy := make(map[string]int, len(p.attackTypes))
	for k, v := range p.attackTypes {
		attackTypesCopy[k] = v
	}

	return ProfileSnapshot{
		IP:                p.ip,
		RequestRate:       p.RequestRate.Sum(),
		RequestThreshold:  p.RequestRate.GetThreshold(),
		BlockRate:         p.BlockRate.Sum(),
		ErrorRatio:        p.ErrorRatio.Ratio(),
		PathDiversity:     p.PathDiv.Count(),
		UADiversity:       p.UADiv.Count(),
		RuleDiversity:     p.RuleHitDiv.Count(),
		IntervalVariance:  p.Interval.Variance(),
		IntervalMean:      p.Interval.Mean(),
		SensitiveHitCount: p.SensitiveHit.Sum(),
		PathRates:         pathRates,
		TotalCount:        p.totalCount,
		BlockCount:        p.blockCount,
		LastActive:        p.lastActive,
		MethodDiversity:   p.MethodDiv.Count(),
		NoCookieRatio:     p.NoCookieWin.Ratio(),
		NoRefererRatio:    p.NoRefererWin.Ratio(),
		BodySizeCount:     p.BodySizeWin.Sum(),
		ASNChangeCount:    p.countryChangeCount,
		FirstASN:          p.firstCountryISO,
		LastUA:            p.lastUA,
		TrustScore:        p.trustScore,
		FingerprintHash:   p.fingerprintHash,
		ConsecutivePass:   p.consecutivePass,
		AttackTypeCounts:  attackTypesCopy,
	}
}

type ProfileSnapshot struct {
	IP                string           `json:"ip"`
	RequestRate       int64            `json:"request_rate"`
	RequestThreshold  int64            `json:"request_threshold"`
	BlockRate         int64            `json:"block_rate"`
	ErrorRatio        float64          `json:"error_ratio"`
	PathDiversity     int              `json:"path_diversity"`
	UADiversity       int              `json:"ua_diversity"`
	RuleDiversity     int              `json:"rule_diversity"`
	IntervalVariance  float64          `json:"interval_variance"`
	IntervalMean      float64          `json:"interval_mean"`
	SensitiveHitCount int64            `json:"sensitive_hit_count"`
	PathRates         map[string]int64 `json:"path_rates,omitempty"`
	TotalCount        int64            `json:"total_count"`
	BlockCount        int64            `json:"block_count"`
	LastActive        time.Time        `json:"last_active"`
	MethodDiversity   int              `json:"method_diversity"`
	NoCookieRatio     float64          `json:"no_cookie_ratio"`
	NoRefererRatio    float64          `json:"no_referer_ratio"`
	BodySizeCount     int64            `json:"body_size_count"`
	ASNChangeCount    int              `json:"asn_change_count"`
	FirstASN          string           `json:"first_asn"`
	LastUA            string           `json:"last_ua"`
	TrustScore        float64          `json:"trust_score"`
	FingerprintHash   string           `json:"fingerprint_hash"`
	ConsecutivePass   int              `json:"consecutive_pass"`
	HourAnomalyScore  float64          `json:"hour_anomaly_score"`
	AttackTypeCounts  map[string]int   `json:"attack_type_counts"`
}

var sensitivePathExact = map[string]bool{
	"/.env": true, "/.git": true, "/.svn": true, "/.htaccess": true, "/.htpasswd": true,
	"/wp-admin": true, "/wp-login": true, "/wp-config": true,
	"/admin": true, "/phpmyadmin": true, "/pma": true,
	"/config": true, "/backup": true, "/database": true,
	"/.DS_Store": true, "/robots.txt": true, "/sitemap.xml": true,
	"/api/v1/users": true, "/actuator": true, "/debug": true,
	"/console": true, "/shell": true, "/cmd": true,
}

var sensitivePathPrefixes = []string{"/admin/", "/config/", "/backup/", "/database/", "/debug/", "/console/", "/shell/", "/cmd/"}

func isSensitivePath(path string) bool {
	if sensitivePathExact[path] {
		return true
	}
	for _, sp := range sensitivePathPrefixes {
		pl := len(sp)
		if len(path) > pl && path[:pl] == sp {
			return true
		}
	}
	return false
}

const profileShardCount = 64

type profileShard struct {
	mu       sync.RWMutex
	profiles map[string]*IPProfile
}

type ProfileStore struct {
	shards [profileShardCount]profileShard
	cfg    *Config
}

func (s *ProfileStore) getShard(ip string) *profileShard {
	h := uint32(2166136261)
	for i := 0; i < len(ip); i++ {
		h ^= uint32(ip[i])
		h *= 16777619
	}
	return &s.shards[h%profileShardCount]
}

func NewProfileStore(cfg *Config) *ProfileStore {
	s := &ProfileStore{cfg: cfg}
	for i := range s.shards {
		s.shards[i].profiles = make(map[string]*IPProfile)
	}
	return s
}

func (s *ProfileStore) GetOrCreate(ip string) *IPProfile {
	shard := s.getShard(ip)
	shard.mu.RLock()
	p, exists := shard.profiles[ip]
	shard.mu.RUnlock()

	if exists {
		return p
	}

	shard.mu.Lock()
	defer shard.mu.Unlock()

	p, exists = shard.profiles[ip]
	if exists {
		return p
	}

	p = NewIPProfile(ip, s.cfg)
	shard.profiles[ip] = p
	return p
}

func (s *ProfileStore) Get(ip string) (*IPProfile, bool) {
	shard := s.getShard(ip)
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	p, exists := shard.profiles[ip]
	return p, exists
}

func (s *ProfileStore) Record(req RequestInfo) {
	profile := s.GetOrCreate(req.IP)
	profile.Record(req)
}

func (s *ProfileStore) GetOrCreateSnapshot(ip string) (ProfileSnapshot, bool) {
	shard := s.getShard(ip)
	shard.mu.RLock()
	p, exists := shard.profiles[ip]
	shard.mu.RUnlock()

	if exists {
		return p.Snapshot(), true
	}

	shard.mu.Lock()
	p, exists = shard.profiles[ip]
	if !exists {
		p = NewIPProfile(ip, s.cfg)
		shard.profiles[ip] = p
	}
	shard.mu.Unlock()

	return p.Snapshot(), true
}

func (s *ProfileStore) Snapshot(ip string) (ProfileSnapshot, bool) {
	shard := s.getShard(ip)
	shard.mu.RLock()
	p, exists := shard.profiles[ip]
	shard.mu.RUnlock()

	if !exists {
		return ProfileSnapshot{}, false
	}
	return p.Snapshot(), true
}

func (s *ProfileStore) AllSnapshots() []ProfileSnapshot {
	var ips []string
	for i := range s.shards {
		s.shards[i].mu.RLock()
		for ip := range s.shards[i].profiles {
			ips = append(ips, ip)
		}
		s.shards[i].mu.RUnlock()
	}

	snapshots := make([]ProfileSnapshot, 0, len(ips))
	for _, ip := range ips {
		shard := s.getShard(ip)
		shard.mu.RLock()
		p, exists := shard.profiles[ip]
		shard.mu.RUnlock()
		if exists {
			snapshots = append(snapshots, p.Snapshot())
		}
	}
	return snapshots
}

func (s *ProfileStore) Cleanup(maxAge time.Duration) int {
	now := time.Now()
	cleaned := 0
	for i := range s.shards {
		s.shards[i].mu.Lock()
		for ip, p := range s.shards[i].profiles {
			p.mu.Lock()
			lastActive := p.lastActive
			p.mu.Unlock()

			if now.Sub(lastActive) > maxAge {
				delete(s.shards[i].profiles, ip)
				cleaned++
			} else {
				p.Expire(maxAge)
			}
		}
		s.shards[i].mu.Unlock()
	}
	return cleaned
}

func (s *ProfileStore) Count() int {
	total := 0
	for i := range s.shards {
		s.shards[i].mu.RLock()
		total += len(s.shards[i].profiles)
		s.shards[i].mu.RUnlock()
	}
	return total
}

func (s *ProfileStore) UpdateConfig(cfg *Config) {
	s.cfg = cfg
}
