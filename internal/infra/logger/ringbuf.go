package logger

import (
	"sync"
)

const ringBufferSize = 5000

var (
	ringMu    sync.RWMutex
	ringBuf   = make([]string, 0, ringBufferSize)
	ringStart int
	ringFull  bool
)

func addRingEntry(line string) {
	ringMu.Lock()
	defer ringMu.Unlock()
	if cap(ringBuf) == 0 {
		return
	}
	if ringFull {
		ringBuf[ringStart] = line
		ringStart = (ringStart + 1) % cap(ringBuf)
	} else {
		ringBuf = append(ringBuf, line)
		if len(ringBuf) == cap(ringBuf) {
			ringFull = true
			ringStart = 0
		}
	}
}

func GetRecentLogLines(n int) []string {
	if n <= 0 {
		n = 100
	}
	ringMu.RLock()
	defer ringMu.RUnlock()
	size := len(ringBuf)
	if size == 0 {
		return nil
	}
	if n > size {
		n = size
	}
	result := make([]string, 0, n)
	if ringFull {
		for i := 0; i < n; i++ {
			idx := (ringStart - n + i + cap(ringBuf)) % cap(ringBuf)
			result = append(result, ringBuf[idx])
		}
	} else {
		start := size - n
		result = append(result, ringBuf[start:]...)
	}
	return result
}
