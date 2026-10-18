//go:build !linux

package spawn

import "syscall"

func sysProcAttr() *syscall.SysProcAttr { return nil }
