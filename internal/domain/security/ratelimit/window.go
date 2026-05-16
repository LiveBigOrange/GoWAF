package ratelimit

import (
	"sync"
	"time"
)

type SlidingWindow struct {
	mu        sync.RWMutex
	slots     []int64
	size      int
	interval  time.Duration
	cursor    int
	lastTime  time.Time
	threshold int64
	total     int64
}

func NewSlidingWindow(size int, interval time.Duration, threshold int64) *SlidingWindow {
	return &SlidingWindow{
		slots:     make([]int64, size),
		size:      size,
		interval:  interval,
		cursor:    0,
		lastTime:  time.Now(),
		threshold: threshold,
	}
}

func (sw *SlidingWindow) Allow(n int64) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.advance()
	sw.slots[sw.cursor] += n
	sw.total += n

	return sw.total <= sw.threshold
}

func (sw *SlidingWindow) Incr() int64 {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.advance()
	sw.slots[sw.cursor]++
	sw.total++

	return sw.total
}

func (sw *SlidingWindow) Sum() int64 {
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	return sw.total
}

func (sw *SlidingWindow) SetThreshold(threshold int64) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.threshold = threshold
}

func (sw *SlidingWindow) GetThreshold() int64 {
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	return sw.threshold
}

func (sw *SlidingWindow) Reset() {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	for i := range sw.slots {
		sw.slots[i] = 0
	}
	sw.total = 0
	sw.cursor = 0
	sw.lastTime = time.Now()
}

func (sw *SlidingWindow) advance() {
	now := time.Now()
	elapsed := now.Sub(sw.lastTime)

	if elapsed < sw.interval {
		return
	}

	slotsToAdvance := int(elapsed / sw.interval)
	if slotsToAdvance >= sw.size {
		for i := range sw.slots {
			sw.slots[i] = 0
		}
		sw.total = 0
		sw.cursor = 0
		sw.lastTime = now
		return
	}

	for i := 0; i < slotsToAdvance; i++ {
		sw.cursor = (sw.cursor + 1) % sw.size
		sw.total -= sw.slots[sw.cursor]
		if sw.total < 0 {
			sw.total = 0
		}
		sw.slots[sw.cursor] = 0
	}

	remainder := elapsed % sw.interval
	sw.lastTime = now.Add(-remainder)
}

type RatioWindow struct {
	total    *SlidingWindow
	errorWin *SlidingWindow
}

func NewRatioWindow(size int, interval time.Duration) *RatioWindow {
	return &RatioWindow{
		total:    NewSlidingWindow(size, interval, int64(size)*1000),
		errorWin: NewSlidingWindow(size, interval, int64(size)*1000),
	}
}

func (rw *RatioWindow) Record(isError bool) {
	rw.total.Incr()
	if isError {
		rw.errorWin.Incr()
	}
}

func (rw *RatioWindow) Ratio() float64 {
	total := rw.total.Sum()
	if total == 0 {
		return 0
	}
	return float64(rw.errorWin.Sum()) / float64(total)
}

type UniqueCounter struct {
	mu     sync.RWMutex
	items  map[string]time.Time
	window *SlidingWindow
	max    int
}

func NewUniqueCounter(windowSize int, interval time.Duration, maxUnique int) *UniqueCounter {
	return &UniqueCounter{
		items:  make(map[string]time.Time),
		window: NewSlidingWindow(windowSize, interval, int64(maxUnique)),
		max:    maxUnique,
	}
}

func (uc *UniqueCounter) Add(item string) int {
	uc.mu.Lock()
	defer uc.mu.Unlock()

	if _, exists := uc.items[item]; !exists {
		uc.items[item] = time.Now()
		uc.window.Incr()
	} else {
		uc.items[item] = time.Now()
	}
	return int(uc.window.Sum())
}

func (uc *UniqueCounter) Count() int {
	uc.mu.RLock()
	defer uc.mu.RUnlock()
	return len(uc.items)
}

func (uc *UniqueCounter) Expire(maxAge time.Duration) int {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	now := time.Now()
	expired := 0
	for k, t := range uc.items {
		if now.Sub(t) > maxAge {
			delete(uc.items, k)
			expired++
		}
	}
	return expired
}

func (uc *UniqueCounter) Reset() {
	uc.mu.Lock()
	defer uc.mu.Unlock()
	uc.items = make(map[string]time.Time)
	uc.window.Reset()
}

type IntervalTracker struct {
	mu        sync.RWMutex
	lastTime  time.Time
	variance  float64
	mean      float64
	samples   []float64
	maxSample int
	writeIdx  int
	full      bool
}

func NewIntervalTracker(maxSample int) *IntervalTracker {
	return &IntervalTracker{
		samples:   make([]float64, maxSample),
		maxSample: maxSample,
	}
}

func (it *IntervalTracker) Record() {
	it.mu.Lock()
	defer it.mu.Unlock()

	now := time.Now()
	if it.lastTime.IsZero() {
		it.lastTime = now
		return
	}

	interval := now.Sub(it.lastTime).Seconds()
	it.lastTime = now

	it.samples[it.writeIdx] = interval
	it.writeIdx++
	if it.writeIdx >= it.maxSample {
		it.writeIdx = 0
		it.full = true
	}

	it.computeStats()
}

func (it *IntervalTracker) computeStats() {
	count := it.writeIdx
	if it.full {
		count = it.maxSample
	}
	if count == 0 {
		return
	}

	var sum, sumSq float64
	for i := 0; i < count; i++ {
		s := it.samples[i]
		sum += s
		sumSq += s * s
	}

	it.mean = sum / float64(count)
	it.variance = sumSq/float64(count) - it.mean*it.mean
	if it.variance < 0 {
		it.variance = 0
	}
}

func (it *IntervalTracker) Variance() float64 {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.variance
}

func (it *IntervalTracker) Mean() float64 {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.mean
}

func (it *IntervalTracker) SampleCount() int {
	it.mu.RLock()
	defer it.mu.RUnlock()
	if it.full {
		return it.maxSample
	}
	return it.writeIdx
}
