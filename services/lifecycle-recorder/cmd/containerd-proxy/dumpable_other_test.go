//go:build !linux

package main

import "testing"

func TestNonDumpableFailsClosedOffLinux(t *testing.T) {
	if err := nonDumpable(); err == nil {
		t.Fatal("nonDumpable must fail off Linux")
	}
}
