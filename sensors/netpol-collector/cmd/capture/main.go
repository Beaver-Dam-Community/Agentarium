// capture reads verified ordered node files into a separate durable local spool.
// No network, ACK, gap event, lease or hold is emitted by this command.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	collector "github.com/Beaver-Dam-Community/Agentarium/sensors/netpol-collector"
)

type paths []string

func (p *paths) String() string     { return fmt.Sprint([]string(*p)) }
func (p *paths) Set(v string) error { *p = append(*p, v); return nil }
func run() error {
	var files paths
	flag.Var(&files, "file", "verified source path, repeated oldest backup to live; no automatic discovery")
	dir := flag.String("spool", "", "dedicated owner-only netpol spool (not an exporter spool)")
	epoch := flag.String("epoch", "", "caller-supplied local capture epoch; not a finalized wire identity")
	cluster := flag.String("cluster-uid", "", "source cluster UUID")
	node := flag.String("node-uid", "", "source node UUID")
	nodeName := flag.String("node-name", "", "exact expected dataplane node_name")
	version := flag.String("normalization-version", "", "operator-selected local normalizer version")
	capacity := flag.Int64("capacity", wal.DefaultCapacity, "maximum local spool bytes")
	lineLimit := flag.Int("max-line-bytes", wal.MaxRecordBytes, "maximum complete input line bytes")
	follow := flag.Bool("follow", false, "poll live EOF until interrupted; stop if rotation invalidates supplied inventory")
	flag.Parse()
	if *dir == "" || *epoch == "" || len(files) == 0 || *capacity < 1 || flag.NArg() != 0 {
		return errors.New("explicit source files, spool, epoch and positive capacity are required")
	}
	journal, e := wal.Open(*dir, *epoch, *capacity)
	if e != nil {
		return e
	}
	defer journal.Close()
	capture, e := collector.New(collector.Config{Journal: journal, Reader: collector.Reader{Inventory: func() ([]string, error) { return append([]string(nil), files...), nil }, MaxFiles: 64, MaxLineBytes: *lineLimit}, ClusterUID: *cluster, NodeUID: *node, NodeName: *nodeName, NormalizationVersion: *version})
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	e = capture.Run(ctx, *follow)
	if errors.Is(e, context.Canceled) {
		return nil
	}
	return e
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "netpol capture stopped: %v; source checkpoint not skipped and unacknowledged WAL retained\n", err)
		os.Exit(1)
	}
}
