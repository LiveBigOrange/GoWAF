package ratelimit

import (
	"math"
	"sort"
	"sync"
	"time"
)

type BaselineManager struct {
	mu         sync.RWMutex
	baselines  map[string]*MetricBaseline
	windowSize int
	maxSamples int
}

type MetricBaseline struct {
	samples    []float64
	p50        float64
	p95        float64
	p99        float64
	mean       float64
	stdDev     float64
	lastUpdate time.Time
}

func NewBaselineManager(windowSize, maxSamples int) *BaselineManager {
	return &BaselineManager{
		baselines:  make(map[string]*MetricBaseline),
		windowSize: windowSize,
		maxSamples: maxSamples,
	}
}

func (bm *BaselineManager) AddSample(metric string, value float64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bl, exists := bm.baselines[metric]
	if !exists {
		bl = &MetricBaseline{
			samples: make([]float64, 0, bm.maxSamples),
		}
		bm.baselines[metric] = bl
	}

	bl.samples = append(bl.samples, value)
	if len(bl.samples) > bm.maxSamples {
		bl.samples = bl.samples[len(bl.samples)-bm.maxSamples:]
	}
}

func (bm *BaselineManager) RecalculateAll() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	for _, bl := range bm.baselines {
		bm.recalculate(bl)
	}
}

func (bm *BaselineManager) recalculate(bl *MetricBaseline) {
	n := len(bl.samples)
	if n == 0 {
		return
	}

	sorted := make([]float64, n)
	copy(sorted, bl.samples)
	sort.Float64s(sorted)

	bl.p50 = sorted[n*50/100]
	bl.p95 = sorted[n*95/100]
	if n > 1 {
		bl.p99 = sorted[(n-1)*99/100]
	} else {
		bl.p99 = sorted[0]
	}

	var sum float64
	for _, v := range bl.samples {
		sum += v
	}
	bl.mean = sum / float64(n)

	var variance float64
	for _, v := range bl.samples {
		diff := v - bl.mean
		variance += diff * diff
	}
	bl.stdDev = math.Sqrt(variance / float64(n))
	bl.lastUpdate = time.Now()
}

func (bm *BaselineManager) GetBaseline(metric string) (p50, p95, p99, mean, stdDev float64, ok bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	bl, exists := bm.baselines[metric]
	if !exists || len(bl.samples) == 0 {
		return 0, 0, 0, 0, 0, false
	}
	return bl.p50, bl.p95, bl.p99, bl.mean, bl.stdDev, true
}

func (bm *BaselineManager) IsAnomaly(metric string, value float64) (bool, float64) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	bl, exists := bm.baselines[metric]
	if !exists || len(bl.samples) < 30 {
		return false, 0
	}

	if bl.stdDev == 0 {
		if value > bl.mean*3 && bl.mean > 0 {
			return true, (value - bl.mean*3) / bl.mean
		}
		return false, 0
	}

	zscore := (value - bl.mean) / bl.stdDev
	if zscore > 3.0 {
		return true, (zscore - 3.0) / 7.0
	}
	return false, 0
}

func (bm *BaselineManager) GetDynamicThreshold(metric string, sensitivity float64) (float64, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	bl, exists := bm.baselines[metric]
	if !exists || len(bl.samples) < 30 {
		return 0, false
	}

	threshold := bl.p95 + sensitivity*bl.stdDev
	return threshold, true
}

func (bm *BaselineManager) IsPeriodAnomaly(hourCounts [24]int64, currentHour int) (bool, float64) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	var sum int64
	var count int
	for _, c := range hourCounts {
		if c > 0 {
			sum += c
			count++
		}
	}
	if count < 6 {
		return false, 0
	}

	mean := float64(sum) / float64(count)
	current := float64(hourCounts[currentHour])

	if mean == 0 {
		return current > 10, 0
	}

	ratio := current / mean
	if ratio > 5.0 {
		return true, (ratio - 5.0) / 10.0
	}
	return false, 0
}

func (bm *BaselineManager) BaselineCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.baselines)
}
