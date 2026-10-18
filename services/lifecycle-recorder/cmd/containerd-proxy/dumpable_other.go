//go:build !linux

package main

import "errors"

// nonDumpable fails closed off Linux: the proxy holds a node socket only on
// GKE nodes, and nothing else can confirm the process is non-dumpable.
func nonDumpable() error {
	return errors.New("PR_SET_DUMPABLE is Linux-only; containerd-proxy runs only on Linux")
}
