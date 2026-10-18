//go:build linux

package spawn

import "syscall"

// sysProcAttr kills the worker if the supervisor thread that started it
// dies, so no orphan worker survives a supervisor restart (TASK-15: orphan
// workers are never adopted). It sets no credentials or namespaces.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
