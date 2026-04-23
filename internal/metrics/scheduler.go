package metrics

import (
	"sync"
	"time"
)

// Scheduler 定时任务调度器
type Scheduler struct {
	manager   *Manager
	stopChan  chan struct{}
	wg        sync.WaitGroup
	retention int // 数据保留天数
}

// NewScheduler 创建调度器
func NewScheduler(manager *Manager, retentionDays int) *Scheduler {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	return &Scheduler{
		manager:   manager,
		stopChan:  make(chan struct{}),
		retention: retentionDays,
	}
}

// Start 启动定时任务
func (s *Scheduler) Start() {
	s.wg.Add(1)
	go s.run()
}

// Stop 停止定时任务
func (s *Scheduler) Stop() {
	close(s.stopChan)
	s.wg.Wait()
}

// run 运行定时任务循环
func (s *Scheduler) run() {
	defer s.wg.Done()

	// 每小时执行一次数据清理
	cleanupTicker := time.NewTicker(1 * time.Hour)
	defer cleanupTicker.Stop()

	// 立即执行一次清理
	s.cleanup()

	for {
		select {
		case <-s.stopChan:
			return
		case <-cleanupTicker.C:
			s.cleanup()
		}
	}
}

// cleanup 执行数据清理
func (s *Scheduler) cleanup() {
	if err := s.manager.CleanupOldData(s.retention); err != nil {
		// 静默处理错误
	}
}
