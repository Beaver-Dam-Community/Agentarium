//go:build !(linux && (amd64 || arm64))

package isolation

import (
	"errors"
	"runtime"
)

// Apply is unsupported outside linux/amd64 and linux/arm64; the worker then
// reports the failure and takes no work (COMMON WORKER_ISOLATION_NOT_READY).
func Apply() (Report, error) {
	return Report{Profile: Expected(), Arch: runtime.GOARCH, Checks: map[string]string{}},
		errors.New("isolation: process_baseline controls need linux/amd64 or linux/arm64")
}

// ProtectSupervisor fails closed on unsupported runtime platforms.
func ProtectSupervisor() error {
	return errors.New("isolation: supervisor controls need linux/amd64 or linux/arm64")
}
