// Package isolation is the worker bootstrap's required process_baseline
// controls (TASK-15 session isolation scope table, COMMON session-dedicated worker contract 2):
// after its final exec and before any user payload the worker sets
// RLIMIT_CORE=0, PR_SET_DUMPABLE=0 and no_new_privs, then installs a seccomp
// filter (synchronised to every thread) that refuses ptrace,
// process_vm_readv/writev, kcmp, pidfd_getfd, execve/execveat, UID/GID
// changes, new namespaces (unshare, setns, clone with CLONE_NEW*, clone3) and
// prctl(PR_SET_DUMPABLE), and kills any other syscall ABI.
//
// This is the baseline profile only: it does not isolate files, signals or
// the shared identity mount between workers of the same UID (TASK-15).
package isolation

import (
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// ProfileName is the default profile (TASK-15 session isolation scope).
const ProfileName = "process_baseline"

// DeniedSyscalls are refused with EPERM; clone3 is refused with ENOSYS so
// callers fall back to clone, whose flags the filter checks.
var DeniedSyscalls = []string{
	"execve", "execveat", "kcmp", "pidfd_getfd", "process_vm_readv", "process_vm_writev", "ptrace",
	"setfsgid", "setfsuid", "setgid", "setgroups", "setns", "setregid", "setresgid", "setresuid",
	"setreuid", "setuid", "unshare",
}

// Profile is the expected control set; its canonical digest is the
// registration's isolation_profile_digest.
// SPEC-QUESTION: the specs fix neither the profile document nor the
// controls_report fields; both are this runtime's.
type Profile struct {
	Profile        string   `json:"profile"`
	RlimitCore     int      `json:"rlimit_core"`
	Dumpable       int      `json:"dumpable"`
	NoNewPrivs     bool     `json:"no_new_privs"`
	Seccomp        string   `json:"seccomp"`
	SeccompTSync   bool     `json:"seccomp_tsync"`
	DeniedSyscalls []string `json:"denied_syscalls"`
	DeniedPrctl    []string `json:"denied_prctl"`
	DeniedClone    []string `json:"denied_clone_flags"`
	ENOSYSSyscalls []string `json:"enosys_syscalls"`
	ForeignABI     string   `json:"foreign_abi"`
}

// Expected returns the process_baseline profile.
func Expected() Profile {
	return Profile{
		Profile: ProfileName, RlimitCore: 0, Dumpable: 0, NoNewPrivs: true,
		Seccomp: "filter", SeccompTSync: true,
		DeniedSyscalls: append([]string(nil), DeniedSyscalls...),
		DeniedPrctl:    []string{"PR_SET_DUMPABLE"},
		DeniedClone: []string{"CLONE_NEWCGROUP", "CLONE_NEWIPC", "CLONE_NEWNET", "CLONE_NEWNS",
			"CLONE_NEWPID", "CLONE_NEWTIME", "CLONE_NEWUSER", "CLONE_NEWUTS"},
		ENOSYSSyscalls: []string{"clone3"},
		ForeignABI:     "kill_process",
	}
}

// Digest is the lowercase hex SHA-256 of the canonical JSON of Expected().
func Digest() (string, error) { return canonical.CanonicalDigest(Expected()) }

// Report is the worker's controls report (registration controls_report):
// the profile it applied, the machine architecture and the self-checks it
// ran after installing the filter.
type Report struct {
	Profile
	Arch   string            `json:"arch"`
	Checks map[string]string `json:"checks"`
}
