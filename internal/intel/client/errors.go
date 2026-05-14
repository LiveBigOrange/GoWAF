package client

import "fmt"

type IntelError struct {
	Code      string
	Message   string
	Retryable bool
}

func (e *IntelError) Error() string {
	return fmt.Sprintf("intel error [%s]: %s", e.Code, e.Message)
}

func (e *IntelError) IsRetryable() bool {
	return e.Retryable
}
