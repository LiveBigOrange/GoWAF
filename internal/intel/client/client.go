package client

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"gowaf/internal/intel/config"
)

var (
	ErrRateLimited  = &IntelError{Code: "rate_limited", Message: "local rate limit exceeded", Retryable: true}
	ErrNotConnected = &IntelError{Code: "not_connected", Message: "intel center not connected", Retryable: false}
	ErrUnauthorized = &IntelError{Code: "unauthorized", Message: "invalid license key", Retryable: false}
)

type IntelClient struct {
	serverURL   string
	licenseKey  string
	httpClient  *http.Client
	rateLimiter *RateLimitTracker
	mu          sync.RWMutex
	connected   bool
}

func NewIntelClient(cfg *config.IntelConfig) (*IntelClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("intel config is nil or disabled")
	}

	baseURL := strings.TrimRight(cfg.ServerURL, "/")
	tlsConfig, err := buildTLSConfig(&cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to build tls config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          10,
		MaxIdleConnsPerHost:   5,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: time.Duration(cfg.RequestTimeout) * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.RequestTimeout) * time.Second,
	}

	return &IntelClient{
		serverURL:   baseURL,
		licenseKey:  cfg.LicenseKey,
		httpClient:  httpClient,
		rateLimiter: NewRateLimitTracker(60, time.Minute),
		connected:   false,
	}, nil
}

func (c *IntelClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

func (c *IntelClient) SetConnected(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.connected = v
}

func (c *IntelClient) doRequest(req *http.Request) (*http.Response, error) {
	if !c.rateLimiter.Allow() {
		return nil, ErrRateLimited
	}

	req.Header.Set("Authorization", "Bearer "+c.licenseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GoWAF-IntelClient/1.0")

	policy := DefaultRetryPolicy()
	resp, err := policy.Execute(c.httpClient, req)
	if err != nil {
		c.SetConnected(false)
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, ErrUnauthorized
	}

	c.SetConnected(true)
	return resp, nil
}
