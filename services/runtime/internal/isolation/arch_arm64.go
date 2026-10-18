//go:build linux && arm64

package isolation

import "golang.org/x/sys/unix"

const (
	auditArch      = unix.AUDIT_ARCH_AARCH64
	foreignABIMask = 0 // the arch check already refuses AArch32
)
