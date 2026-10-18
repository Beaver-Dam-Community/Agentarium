package run

import "os/exec"

func Run() error { return exec.Command("true").Run() }
