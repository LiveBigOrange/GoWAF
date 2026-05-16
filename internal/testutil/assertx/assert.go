package assertx

import (
	"testing"
)

// Equal 断言两个值相等
func Equal[T comparable](t *testing.T, got, want T, msg ...string) {
	t.Helper()
	if got != want {
		if len(msg) > 0 {
			t.Errorf("%s: got %v, want %v", msg[0], got, want)
		} else {
			t.Errorf("got %v, want %v", got, want)
		}
	}
}

// NotNil 断言值不为 nil
func NotNil(t *testing.T, v interface{}, msg ...string) {
	t.Helper()
	if v == nil {
		if len(msg) > 0 {
			t.Errorf("%s: expected non-nil", msg[0])
		} else {
			t.Errorf("expected non-nil")
		}
	}
}
