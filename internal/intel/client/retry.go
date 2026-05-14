package client

import (
	"math"
	"net/http"
	"time"
)

type RetryPolicy struct {
	MaxRetries int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
}

func DefaultRetryPolicy() *RetryPolicy {
	return &RetryPolicy{
		MaxRetries: 3,
		BaseDelay:  1 * time.Second,
		MaxDelay:   30 * time.Second,
	}
}

func (p *RetryPolicy) backoff(attempt int) time.Duration {
	delay := time.Duration(math.Pow(3, float64(attempt))) * p.BaseDelay
	if delay > p.MaxDelay {
		delay = p.MaxDelay
	}
	return delay
}

func (p *RetryPolicy) Execute(client *http.Client, req *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= p.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(p.backoff(attempt - 1))
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			retryAfter := resp.Header.Get("Retry-After")
			resp.Body.Close()
			lastErr = &IntelError{Code: "429", Message: "rate limited", Retryable: true}
			if attempt < p.MaxRetries && retryAfter != "" {
				if d, parseErr := time.ParseDuration(retryAfter + "s"); parseErr == nil {
					time.Sleep(d + time.Second)
				}
			}
			continue

		case resp.StatusCode >= 500:
			resp.Body.Close()
			lastErr = &IntelError{Code: "5xx", Message: "server error", Retryable: true}
			if attempt >= 2 {
				return nil, lastErr
			}
			continue

		case resp.StatusCode >= 400 && resp.StatusCode != http.StatusTooManyRequests:
			return resp, nil

		default:
			return resp, nil
		}
	}

	return nil, lastErr
}
