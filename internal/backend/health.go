package backend

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// HealthChecker 健康检查器
type HealthChecker struct {
	manager       *Manager
	client        *http.Client
	stopChan      chan struct{}
	wg            sync.WaitGroup
	checkWg       sync.WaitGroup // 跟踪正在执行的检查goroutine
	checkInterval int            // 健康检查间隔(秒)
}

// NewHealthChecker 创建健康检查器
func NewHealthChecker(manager *Manager, checkInterval int) *HealthChecker {
	if checkInterval <= 0 {
		checkInterval = 5 // 默认5秒
	}
	return &HealthChecker{
		manager: manager,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		stopChan:      make(chan struct{}),
		checkInterval: checkInterval,
	}
}

// Start 启动健康检查
func (hc *HealthChecker) Start() {
	hc.wg.Add(1)
	go hc.run()
}

// Stop 停止健康检查
func (hc *HealthChecker) Stop() {
	close(hc.stopChan)
	hc.wg.Wait()
	hc.checkWg.Wait() // 等待所有正在执行的检查完成
}

// run 运行健康检查循环
func (hc *HealthChecker) run() {
	defer hc.wg.Done()

	ticker := time.NewTicker(time.Duration(hc.checkInterval) * time.Second)
	defer ticker.Stop()

	// 立即执行一次
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

// checkAll 检查所有后端
func (hc *HealthChecker) checkAll() {
	backends := hc.manager.GetBackends()
	for _, b := range backends {
		if !b.Enabled || !b.HealthCheck {
			continue
		}
		hc.checkWg.Add(1)
		go func(backend *Backend) {
			defer hc.checkWg.Done()
			hc.checkBackend(backend)
		}(b)
	}
}

// checkBackend 检查单个后端
func (hc *HealthChecker) checkBackend(b *Backend) {
	// 使用后端自己的健康检查配置
	timeout := time.Duration(b.CheckTimeout) * time.Second
	if timeout < 1*time.Second {
		timeout = 5 * time.Second
	}

	url := "http://" + b.Address + b.CheckPath

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client := &http.Client{
		Timeout: timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		hc.handleFail(b)
		return
	}

	resp, err := client.Do(req)
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

// handleSuccess 处理检查成功
func (hc *HealthChecker) handleSuccess(b *Backend) {
	hc.manager.mu.Lock()
	count := hc.manager.failCount[b.ID] - 1
	if count < 0 {
		count = 0
	}
	hc.manager.failCount[b.ID] = count
	hc.manager.mu.Unlock()

	// 连续成功达到阈值，标记为健康
	if count == 0 && !b.Healthy {
		hc.manager.MarkHealthy(b.ID, true)
	}
}

// handleFail 处理检查失败
func (hc *HealthChecker) handleFail(b *Backend) {
	hc.manager.mu.Lock()
	hc.manager.failCount[b.ID]++
	count := hc.manager.failCount[b.ID]
	hc.manager.mu.Unlock()

	// 连续失败达到阈值，标记为不健康
	if count >= b.FailThreshold && b.Healthy {
		hc.manager.MarkHealthy(b.ID, false)
	}
}
