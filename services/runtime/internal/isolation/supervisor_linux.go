//go:build linux && (amd64 || arm64)

package isolation

import (
	"fmt"
	"golang.org/x/sys/unix"
)

// ProtectSupervisor prevents same-UID workers from reading supervisor secrets
// through procfs and disables core dumps. Unlike Apply it permits worker exec.
// Call before loading credentials; any failure must abort startup.
func ProtectSupervisor() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("isolation: supervisor RLIMIT_CORE: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("isolation: supervisor PR_SET_DUMPABLE: %w", err)
	}
	return nil
}
