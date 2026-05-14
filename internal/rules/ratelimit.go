package rules

import (
	"regexp"

	"golang.org/x/time/rate"
)

// ---------- 路径限流 ----------

type PathRateLimitRow struct {
	ID          int     `json:"id"`
	PathPattern string  `json:"path_pattern"`
	Rate        float64 `json:"rate"`
	Burst       int     `json:"burst"`
	Enabled     bool    `json:"enabled"`
}

func (e *Engine) AddPathRateLimit(pathPattern string, rate float64, burst int, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("INSERT INTO path_rate_limits(path_pattern, rate, burst, enabled) VALUES(?,?,?,?)", pathPattern, rate, burst, enc)
	return err
}

func (e *Engine) UpdatePathRateLimit(id int, pathPattern string, rate float64, burst int, enabled bool) error {
	enc := 0
	if enabled {
		enc = 1
	}
	_, err := e.db.Exec("UPDATE path_rate_limits SET path_pattern=?, rate=?, burst=?, enabled=? WHERE id=?", pathPattern, rate, burst, enc, id)
	return err
}

func (e *Engine) RemovePathRateLimit(id int) error {
	_, err := e.db.Exec("DELETE FROM path_rate_limits WHERE id=?", id)
	return err
}

func (e *Engine) ListPathRateLimits() ([]PathRateLimitRow, error) {
	rows, err := e.db.Query("SELECT id, path_pattern, rate, burst, enabled FROM path_rate_limits ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PathRateLimitRow
	for rows.Next() {
		var r PathRateLimitRow
		var enc int
		if err := rows.Scan(&r.ID, &r.PathPattern, &r.Rate, &r.Burst, &enc); err == nil {
			r.Enabled = enc == 1
			rules = append(rules, r)
		}
	}
	return rules, nil
}

func (e *Engine) buildPathRateLimits() map[string]*pathLimiterEntry {
	pathRateLimiters := make(map[string]*pathLimiterEntry)
	rows, err := e.db.Query("SELECT path_pattern, rate, burst FROM path_rate_limits WHERE enabled = 1")
	if err != nil {
		return pathRateLimiters
	}
	defer rows.Close()
	for rows.Next() {
		var pattern string
		var r float64
		var burst int
		if err := rows.Scan(&pattern, &r, &burst); err != nil {
			continue
		}
		regex, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if r <= 0 {
			r = 10
		}
		if burst <= 0 {
			burst = 20
		}
		pathRateLimiters[pattern] = &pathLimiterEntry{
			pattern: regex,
			limiter: rate.NewLimiter(rate.Limit(r), burst),
		}
	}
	return pathRateLimiters
}

func (e *Engine) CheckPathRateLimit(path string) bool {
	snap := e.loadSnapshot()
	for _, entry := range snap.pathRateLimiters {
		if entry.pattern.MatchString(path) {
			return entry.limiter.Allow()
		}
	}
	return true
}
