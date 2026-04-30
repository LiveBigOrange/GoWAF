package metrics

import (
	"log"
	"sync"
	"time"
)

type Scheduler struct {
	manager       *Manager
	stopChan      chan struct{}
	wg            sync.WaitGroup
	retention     int
	cleanupPeriod time.Duration
}

func NewScheduler(manager *Manager, retentionDays int) *Scheduler {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	return &Scheduler{
		manager:       manager,
		stopChan:      make(chan struct{}),
		retention:     retentionDays,
		cleanupPeriod: 1 * time.Hour,
	}
}

func NewSchedulerWithPeriod(manager *Manager, retentionDays int, cleanupPeriod time.Duration) *Scheduler {
	if retentionDays <= 0 {
		retentionDays = 7
	}
	if cleanupPeriod <= 0 {
		cleanupPeriod = 1 * time.Hour
	}
	return &Scheduler{
		manager:       manager,
		stopChan:      make(chan struct{}),
		retention:     retentionDays,
		cleanupPeriod: cleanupPeriod,
	}
}

func (s *Scheduler) Start() {
	s.wg.Add(1)
	go s.run()
}

func (s *Scheduler) Stop() {
	close(s.stopChan)
	s.wg.Wait()
}

func (s *Scheduler) run() {
	defer s.wg.Done()

	cleanupTicker := time.NewTicker(s.cleanupPeriod)
	defer cleanupTicker.Stop()

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

func (s *Scheduler) cleanup() {
	if err := s.manager.CleanupOldData(s.retention); err != nil {
		log.Printf("[WARN] 数据清理失败: %v", err)
	}
	if err := s.manager.CleanupMinuteStats(); err != nil {
		log.Printf("[WARN] 分钟数据清理失败: %v", err)
	}
}
