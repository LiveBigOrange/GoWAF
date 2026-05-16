package detector

import "sync"

var detectionResultPool = sync.Pool{
	New: func() interface{} {
		s := make([]DetectionResult, 0, 4)
		return &s
	},
}

func acquireResults() *[]DetectionResult {
	ptr := detectionResultPool.Get().(*[]DetectionResult)
	*ptr = (*ptr)[:0]
	return ptr
}

func releaseResults(ptr *[]DetectionResult) {
	if cap(*ptr) <= 16 {
		detectionResultPool.Put(ptr)
	}
}
