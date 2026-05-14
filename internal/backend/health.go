package backend

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"gowaf/internal/logger"
	"gowaf/internal/netutil"
	"gowaf/internal/timeutil"
)

const maxConcurrentChecks = 32

type HealthChecker struct {
	manager       *Manager
	client        *http.Client
	stopChan      chan struct{}
	stopped       atomic.Bool
	wg            sync.WaitGroup
	checkWg       sync.WaitGroup
	checkInterval int
	checkSem      chan struct{}
}

func NewHealthChecker(manager *Manager, checkInterval int) *HealthChecker {
	if checkInterval <= 0 {
		checkInterval = 5
	}
	return &HealthChecker{
		manager: manager,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				IdleConnTimeout: 30 * time.Second,
			},
		},
		stopChan:      make(chan struct{}),
		checkInterval: checkInterval,
		checkSem:      make(chan struct{}, maxConcurrentChecks),
	}
}

func (hc *HealthChecker) Start() {
	hc.wg.Add(1)
	go hc.run()
}

func (hc *HealthChecker) Stop() {
	if !hc.stopped.CompareAndSwap(false, true) {
		return
	}
	close(hc.stopChan)
	hc.wg.Wait()
	hc.checkWg.Wait()
}

func (hc *HealthChecker) run() {
	defer hc.wg.Done()

	ticker := time.NewTicker(time.Duration(hc.checkInterval) * time.Second)
	defer ticker.Stop()

	hc.checkAll()

	for {
		select {
		case <-hc.stopChan:
			return
		case <-ticker.C:
			hc.checkAll()
		}
	}
}

func (hc *HealthChecker) checkAll() {
	backends := hc.manager.GetBackends()
	for _, b := range backends {
		if !b.Enabled || !b.HealthCheck {
			continue
		}
		hc.checkWg.Add(1)
		go func(backend *Backend) {
			hc.checkSem <- struct{}{}
			defer func() {
				<-hc.checkSem
				hc.checkWg.Done()
			}()
			hc.checkBackend(backend)
		}(b)
	}
}

func (hc *HealthChecker) checkBackend(b *Backend) {
	timeout := time.Duration(b.CheckTimeout) * time.Second
	if timeout < 1*time.Second {
		timeout = 5 * time.Second
	}

	scheme := b.GetScheme()
	if scheme == "wss" {
		scheme = "https"
	} else if scheme == "ws" {
		scheme = "http"
	}
	url := scheme + "://" + b.Address + b.CheckPath

	host, _, err := net.SplitHostPort(b.Address)
	if err != nil {
		host = b.Address
	}
	if netutil.IsPrivateIP(host) {
		logger.Debug("[Backend] 健康检查跳过私有IP地址: %s", b.Address)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		hc.handleFail(b)
		return
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		hc.handleFail(b)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		hc.handleSuccess(b)
	} else {
		hc.handleFail(b)
	}
}

func (hc *HealthChecker) handleSuccess(b *Backend) {
	hc.manager.mu.Lock()

	var recoverThreshold int
	var isHealthy bool
	for _, mb := range hc.manager.backends {
		if mb.ID == b.ID {
			recoverThreshold = mb.RecoverThreshold
			if recoverThreshold <= 0 {
				recoverThreshold = 2
			}
			isHealthy = mb.Healthy
			break
		}
	}

	if !isHealthy {
		hc.manager.recoverCount[b.ID]++
		rc := hc.manager.recoverCount[b.ID]
		if hc.manager.failCount[b.ID] > 0 {
			hc.manager.failCount[b.ID]--
		}

		if rc >= recoverThreshold {
			for _, mb := range hc.manager.backends {
				if mb.ID == b.ID {
					mb.Healthy = true
					mb.LastCheck = timeutil.FormatRFC3339(time.Now())
					break
				}
			}
			hc.manager.failCount[b.ID] = 0
			hc.manager.recoverCount[b.ID] = 0
			hc.manager.refreshAvailable()
			hc.manager.rebuildGroupCacheLocked()
			logger.Info("[Backend] 后端 %s 已恢复健康 (连续成功 %d 次)", b.Address, rc)
		}
	} else {
		hc.manager.failCount[b.ID]--
		if hc.manager.failCount[b.ID] < 0 {
			hc.manager.failCount[b.ID] = 0
		}
		hc.manager.recoverCount[b.ID] = 0
	}
	hc.manager.mu.Unlock()
}

func (hc *HealthChecker) handleFail(b *Backend) {
	hc.manager.mu.Lock()
	hc.manager.failCount[b.ID]++
	count := hc.manager.failCount[b.ID]
	hc.manager.recoverCount[b.ID] = 0

	var failThreshold int
	var isHealthy bool
	for _, mb := range hc.manager.backends {
		if mb.ID == b.ID {
			failThreshold = mb.FailThreshold
			if failThreshold <= 0 {
				failThreshold = 3
			}
			isHealthy = mb.Healthy
			break
		}
	}

	if count >= failThreshold && isHealthy {
		for _, mb := range hc.manager.backends {
			if mb.ID == b.ID {
				mb.Healthy = false
				mb.LastCheck = timeutil.FormatRFC3339(time.Now())
				break
			}
		}
		hc.manager.failCount[b.ID] = 0
		hc.manager.refreshAvailable()
		hc.manager.rebuildGroupCacheLocked()
		logger.Warn("[Backend] 后端 %s 标记为不健康 (连续失败 %d 次)", b.Address, count)
	}
	hc.manager.mu.Unlock()
}
