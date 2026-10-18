//go:build linux && amd64

package isolation

import "golang.org/x/sys/unix"

const (
	auditArch      = unix.AUDIT_ARCH_X86_64
	foreignABIMask = 0x40000000 // __X32_SYSCALL_BIT
)
