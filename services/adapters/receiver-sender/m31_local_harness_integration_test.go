//go:build integration

package main

// Local M3-1 end-to-end harness (tests/m3-1/run-local.sh). It runs the real
// run() with the flags the driver passes, with one test-only change confined
// to this file and the transportConfig seam: Netns returns a fixed
// netns_inode, because a macOS host has no /proc/self/ns/net and the
// coordinator refuses a dispatched observation whose connection key lacks it
// (TASK-05 3.4). On GKE the binary reads the real inode. It runs only when
// M31_RECEIVER_SENDER_HARNESS_ARGS is set and serves until SIGTERM.

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"strconv"
	"testing"
)

func TestM31LocalReceiverSenderHarness(t *testing.T) {
	raw := os.Getenv("M31_RECEIVER_SENDER_HARNESS_ARGS")
	if raw == "" {
		t.Skip("M31_RECEIVER_SENDER_HARNESS_ARGS not set (tests/m3-1/run-local.sh)")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatalf("M31_RECEIVER_SENDER_HARNESS_ARGS: %v", err)
	}
	inode, err := strconv.ParseUint(os.Getenv("M31_RECEIVER_SENDER_NETNS_INODE"), 10, 64)
	if err != nil || inode == 0 {
		t.Fatalf("M31_RECEIVER_SENDER_NETNS_INODE must be a positive integer: %v", err)
	}
	transportConfig.Netns = func() *uint64 { return &inode }
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger, parseFlags(flag.NewFlagSet("receiver-sender", flag.ContinueOnError), args)); err != nil {
		t.Fatal(err)
	}
}
