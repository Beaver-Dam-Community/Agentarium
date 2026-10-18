//go:build linux && (amd64 || arm64)

package isolation

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

var deniedNumbers = map[string]uintptr{
	"execve": unix.SYS_EXECVE, "execveat": unix.SYS_EXECVEAT, "kcmp": unix.SYS_KCMP,
	"pidfd_getfd": unix.SYS_PIDFD_GETFD, "process_vm_readv": unix.SYS_PROCESS_VM_READV,
	"process_vm_writev": unix.SYS_PROCESS_VM_WRITEV, "ptrace": unix.SYS_PTRACE,
	"setfsgid": unix.SYS_SETFSGID, "setfsuid": unix.SYS_SETFSUID, "setgid": unix.SYS_SETGID,
	"setgroups": unix.SYS_SETGROUPS, "setns": unix.SYS_SETNS, "setregid": unix.SYS_SETREGID,
	"setresgid": unix.SYS_SETRESGID, "setresuid": unix.SYS_SETRESUID, "setreuid": unix.SYS_SETREUID,
	"setuid": unix.SYS_SETUID, "unshare": unix.SYS_UNSHARE,
}

const cloneNewMask = unix.CLONE_NEWCGROUP | unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWNS |
	unix.CLONE_NEWPID | unix.CLONE_NEWTIME | unix.CLONE_NEWUSER | unix.CLONE_NEWUTS

// seccomp_data offsets (linux/seccomp.h): nr u32 at 0, arch u32 at 4,
// args u64 from 16. Both supported architectures are little-endian, so the
// low 32 bits of args[0] are at 16.
const (
	offNr    = 0
	offArch  = 4
	offArg0  = 16
	retAllow = unix.SECCOMP_RET_ALLOW
	retKill  = unix.SECCOMP_RET_KILL_PROCESS
	retEPERM = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	retNOSYS = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
)

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jeq(k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: jt, Jf: jf, K: k}
}

// program builds the filter. Order: architecture, foreign ABI, plain
// denials, clone3, then the two argument checks that reload data.
func program() ([]unix.SockFilter, error) {
	ld := func(off uint32) unix.SockFilter { return stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, off) }
	ret := func(k uint32) unix.SockFilter { return stmt(unix.BPF_RET|unix.BPF_K, k) }
	p := []unix.SockFilter{ld(offArch), jeq(auditArch, 1, 0), ret(retKill), ld(offNr)}
	if foreignABIMask != 0 {
		// x32 syscalls on amd64 carry __X32_SYSCALL_BIT.
		p = append(p, unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jt: 0, Jf: 1, K: foreignABIMask}, ret(retKill))
	}
	for _, name := range DeniedSyscalls {
		nr, ok := deniedNumbers[name]
		if !ok {
			return nil, fmt.Errorf("isolation: no syscall number for %s", name)
		}
		p = append(p, jeq(uint32(nr), 0, 1), ret(retEPERM))
	}
	p = append(p, jeq(uint32(unix.SYS_CLONE3), 0, 1), ret(retNOSYS))
	// prctl(PR_SET_DUMPABLE, ...) → EPERM; other prctl allowed.
	p = append(p, jeq(uint32(unix.SYS_PRCTL), 0, 4), ld(offArg0), jeq(unix.PR_SET_DUMPABLE, 0, 1), ret(retEPERM), ret(retAllow))
	// clone(flags & CLONE_NEW*) → EPERM (flags are args[0] on amd64 and arm64).
	p = append(p, jeq(uint32(unix.SYS_CLONE), 0, 3), ld(offArg0),
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 0, Jf: 1, K: cloneNewMask}, ret(retEPERM))
	p = append(p, ret(retAllow))
	return p, nil
}

// Apply sets the process_baseline controls on the calling process and
// returns the report. Any failure is returned and the worker must not take
// work (COMMON: a failed required setting is WORKER_ISOLATION_NOT_READY).
func Apply() (Report, error) {
	rep := Report{Profile: Expected(), Arch: runtime.GOARCH, Checks: map[string]string{}}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return rep, fmt.Errorf("isolation: RLIMIT_CORE: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return rep, fmt.Errorf("isolation: PR_SET_DUMPABLE: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return rep, fmt.Errorf("isolation: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	prog, err := program()
	if err != nil {
		return rep, err
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	// TSYNC applies the filter to every thread the Go runtime already
	// started; a non-zero return is the TID of a thread that could not sync.
	r, _, errno := unix.RawSyscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if errno != 0 || r != 0 {
		return rep, fmt.Errorf("isolation: seccomp filter: r=%d errno=%v", r, errno)
	}
	if err := selfCheck(rep.Checks); err != nil {
		return rep, err
	}
	return rep, nil
}

// selfCheck confirms the controls took effect.
func selfCheck(out map[string]string) error {
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil || d != 0 {
		return fmt.Errorf("isolation: dumpable is %d (%v)", d, err)
	}
	out["dumpable"] = "0"
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return fmt.Errorf("isolation: no_new_privs is %d (%v)", nnp, err)
	}
	out["no_new_privs"] = "1"
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil || rl.Cur != 0 || rl.Max != 0 {
		return fmt.Errorf("isolation: RLIMIT_CORE is %d/%d (%v)", rl.Cur, rl.Max, err)
	}
	out["rlimit_core"] = "0"
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("isolation: PR_SET_DUMPABLE not refused: %v", err)
	}
	out["prctl_set_dumpable"] = "EPERM"
	if _, _, e := unix.RawSyscall(unix.SYS_KCMP, 0, 0, 0); e != unix.EPERM {
		return fmt.Errorf("isolation: kcmp not refused: %v", e)
	}
	out["kcmp"] = "EPERM"
	if _, _, e := unix.RawSyscall(unix.SYS_PTRACE, unix.PTRACE_ATTACH, 0, 0); e != unix.EPERM {
		return fmt.Errorf("isolation: ptrace not refused: %v", e)
	}
	out["ptrace"] = "EPERM"
	if _, _, e := unix.RawSyscall(unix.SYS_UNSHARE, 0, 0, 0); e != unix.EPERM {
		return fmt.Errorf("isolation: unshare not refused: %v", e)
	}
	out["unshare"] = "EPERM"
	return nil
}
