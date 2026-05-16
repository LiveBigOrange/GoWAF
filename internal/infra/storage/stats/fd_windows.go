package stats

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32               = syscall.NewLazyDLL("kernel32.dll")
	procGetProcessHandleCount = modkernel32.NewProc("GetProcessHandleCount")
)

func getFDCount() int {
	if procGetProcessHandleCount.Find() != nil {
		return 0
	}
	currentProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	var handleCount uint32
	ret, _, _ := procGetProcessHandleCount.Call(uintptr(currentProcess), uintptr(unsafe.Pointer(&handleCount)))
	if ret == 0 {
		return 0
	}
	return int(handleCount)
}
