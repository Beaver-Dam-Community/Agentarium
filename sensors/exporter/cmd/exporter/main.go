// Command exporter is the Tetragon sidecar of TASK-09 3.3. It tails the
// pinned JSON export file, normalizes and filters events through the node's
// read-only Pod API view, fsyncs KernelEvents to the AGW1 WAL, delivers them to
// TASK-07 `POST /internal/kernel/events:batch` and reports the node-sensors
// lease/hold to TASK-10.
//
//	exporter --config /etc/agentarium/exporter/config.json
//	exporter inspect-wal /var/lib/agentarium/sensor-spool/journal
//
// inspect-wal prints the fsynced, not yet acknowledged KernelEvents as NDJSON
// without taking the journal lock (used by tests/kernel/probes).
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/acquire"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/capture"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/delivery"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/nodeid"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/normalize"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/observe"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/podmeta"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/walread"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/workloadcert"
	"github.com/google/uuid"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// SensorSAN is the exporter's identity: KSA tetragon in agent-sensors
// (TASK-09 3.1, COMMON KSA table). It is also the KernelEvent sensor_id.
const SensorSAN = "spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon"

type Config struct {
	Version            string `json:"version"`
	ExportFile         string `json:"export_file"`
	ExportMaxFiles     int    `json:"export_max_files"`
	MaxLineBytes       int    `json:"max_line_bytes"`
	SpoolDir           string `json:"spool_dir"`
	SpoolCapacityBytes int64  `json:"spool_capacity_bytes"`
	BootIDPath         string `json:"boot_id_path"`
	Kubeconfig         string `json:"kubeconfig,omitempty"`
	CollectorOrigin    string `json:"collector_origin"`
	HealthOrigin       string `json:"health_origin"`
	IdentityOrigin     string `json:"identity_origin"`
	// IdentityPeerSAN is the TLS identity of identity_origin: the gateway
	// relay for this hostNetwork sidecar (TASK-03 3.3), or the identity
	// service when connected directly.
	IdentityPeerSAN   string `json:"identity_peer_san"`
	TokenFile         string `json:"token_file"`
	CAFile            string `json:"ca_file"`
	MetricsEndpoint   string `json:"metrics_endpoint"`
	TetragonConfigDir string `json:"tetragon_config_dir"`
	// TetragonSettings are the rendered tetragon-config values of every
	// export/filter key (TASK-09 3.5 capture check 3).
	TetragonSettings     map[string]string `json:"tetragon_settings"`
	TetragonVersion      string            `json:"tetragon_version"`
	SensorGeneration     int64             `json:"sensor_generation"`
	RuleHash             string            `json:"rule_hash"`
	NormalizationVersion string            `json:"normalization_version"`
	RecoveryReason       string            `json:"recovery_reason"`
	AllowedBinaries      []string          `json:"allowed_binaries"`
	ProtectedPaths       []string          `json:"protected_paths"`
	ObservedNamespaces   []string          `json:"observed_namespaces"`
	MetadataGraceSeconds int               `json:"metadata_grace_seconds"`
	PodRetentionSeconds  int               `json:"pod_retention_seconds"`
	// Node nonce responder (TASK-09 independent session worker observation, Pod observation readiness check):
	// host procfs and cgroup2 mounts (read-only) and the approved runtime
	// image's fixed worker executables. All three or none: without them the
	// responder does not run and every node challenge times out (no worker
	// is observed, no check becomes ready). The exporter hostPath mounts need
	// the TASK-01 3.2.1 allowlist change first.
	ProcRoot       string   `json:"proc_root,omitempty"`
	CgroupRoot     string   `json:"cgroup_root,omitempty"`
	WorkerBinaries []string `json:"worker_binaries,omitempty"`
}

func loadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, errors.New("cannot read exporter configuration")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid exporter configuration")
	}
	for _, p := range []string{c.ExportFile, c.SpoolDir, c.BootIDPath, c.TokenFile, c.CAFile, c.TetragonConfigDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("configuration paths must be absolute and clean")
		}
	}
	if c.Version == "" || c.CollectorOrigin == "" || c.HealthOrigin == "" || c.IdentityOrigin == "" || c.RecoveryReason == "" || c.MetadataGraceSeconds < 1 || c.PodRetentionSeconds < c.MetadataGraceSeconds {
		return c, errors.New("incomplete exporter configuration")
	}
	if c.observes() {
		if c.ProcRoot == "" || c.CgroupRoot == "" || len(c.WorkerBinaries) == 0 {
			return c, errors.New("incomplete node observation configuration")
		}
		for _, p := range append([]string{c.ProcRoot, c.CgroupRoot}, c.WorkerBinaries...) {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p {
				return c, errors.New("configuration paths must be absolute and clean")
			}
		}
	}
	return c, nil
}

func (c Config) observes() bool {
	return c.ProcRoot != "" || c.CgroupRoot != "" || len(c.WorkerBinaries) != 0
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "inspect-wal" {
		if err := inspect(os.Args[2], os.Stdout); err != nil {
			log.Print("inspect-wal: ", err)
			os.Exit(1)
		}
		return
	}
	configPath := flag.String("config", "/etc/agentarium/exporter/config.json", "exporter configuration JSON")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *configPath); err != nil && !errors.Is(err, context.Canceled) {
		log.Print("exporter stopped: ", err)
		os.Exit(1)
	}
}

func inspect(dir string, out io.Writer) error {
	w := bufio.NewWriter(out)
	if err := walread.Each(dir, func(_ string, p []byte) error {
		if _, err := w.Write(p); err != nil {
			return err
		}
		return w.WriteByte('\n')
	}); err != nil {
		return err
	}
	return w.Flush()
}

func restConfig(c Config) (*rest.Config, error) {
	var rc *rest.Config
	var err error
	if c.Kubeconfig != "" {
		rc, err = clientcmd.BuildConfigFromFlags("", c.Kubeconfig)
	} else {
		rc, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}
	rc.UserAgent = "agentarium-sensor-exporter"
	return rc, nil
}

// retry repeats a startup step until it succeeds or ctx ends. Startup inputs
// (Node status bootID, identity service) may lag the sidecar start.
func retry(ctx context.Context, what string, f func(context.Context) error) error {
	delay := time.Second
	for {
		call, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := f(call)
		cancel()
		if err == nil {
			return nil
		}
		log.Printf("%s not ready: %v", what, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(2*delay, 30*time.Second)
	}
}

func run(ctx context.Context, configPath string) error {
	c, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return errors.New("NODE_NAME is required (downward API spec.nodeName)")
	}
	rc, err := restConfig(c)
	if err != nil {
		return errors.New("kubernetes client unavailable")
	}
	client, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	policies, err := dynamic.NewForConfig(rc)
	if err != nil {
		return err
	}
	verifier, err := capture.NewVerifier(policies, c.RuleHash, c.TetragonSettings, c.TetragonConfigDir, c.ExportFile, c.MetricsEndpoint)
	if err != nil {
		return err
	}
	var id nodeid.Identity
	if err := retry(ctx, "node identity", func(ctx context.Context) error {
		id, err = nodeid.Resolve(ctx, client, nodeName, c.BootIDPath)
		return err
	}); err != nil {
		return err
	}
	instance := uuid.New()
	epoch, err := nodeid.Epoch(id, instance)
	if err != nil {
		return err
	}
	resolver, err := podmeta.New(podmeta.Config{NodeName: nodeName, Observed: c.ObservedNamespaces, Grace: time.Duration(c.MetadataGraceSeconds) * time.Second, Retain: time.Duration(c.PodRetentionSeconds) * time.Second, PodCIDRs: id.PodCIDRs})
	if err != nil {
		return err
	}
	// Committed process_exec/exit rows for the node nonce witness.
	execs := observe.NewIndex(nil)
	normalizer, err := normalize.New(normalize.Config{SensorID: SensorSAN, ExporterInstanceID: instance.String(), NodeUID: id.NodeUID, BootID: id.BootID, NodeName: nodeName, SensorGeneration: c.SensorGeneration, RuleHash: c.RuleHash, NormalizationVersion: c.NormalizationVersion, AllowedBinaries: c.AllowedBinaries, ProtectedPaths: c.ProtectedPaths, Resolver: resolver, ExecNamespace: execs.Namespace})
	if err != nil {
		return err
	}
	certs := &workloadcert.Manager{URL: c.IdentityOrigin, PeerSAN: c.IdentityPeerSAN, TokenFile: c.TokenFile, CAFile: c.CAFile, SAN: SensorSAN}
	if err := retry(ctx, "workload certificate", certs.Refresh); err != nil {
		return err
	}
	roots, err := certs.Roots()
	if err != nil {
		return err
	}
	collector, err := batch.NewClient(c.CollectorOrigin, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, GetClientCertificate: certs.GetClientCertificate})
	if err != nil {
		return err
	}
	defer collector.Close()
	health, err := healthreport.NewClient(c.HealthOrigin, roots, certs.GetClientCertificate)
	if err != nil {
		return err
	}
	defer health.Close()
	metrics, err := healthreport.NewMetricsScraper(c.MetricsEndpoint, c.TetragonVersion)
	if err != nil {
		return err
	}
	journal, err := wal.Open(c.SpoolDir, epoch, c.SpoolCapacityBytes)
	if err != nil {
		return fmt.Errorf("spool unavailable: %w", err)
	}
	defer journal.Close()
	supervisor, err := healthreport.NewSupervisor(healthreport.SupervisorConfig{
		Journal:     journal,
		Acquisition: acquire.Config{LiveFile: c.ExportFile, MaxFiles: c.ExportMaxFiles, MaxLineBytes: c.MaxLineBytes, Normalize: normalizer.Prepare},
		Delivery:    delivery.Config{Client: collector, SourceID: SensorSAN, Stream: batch.Kernel, RecoveryReason: c.RecoveryReason, Committed: execs.Committed},
		Metrics:     metrics,
		// TASK-09 3.5 capture check (PR #185): loaded policies from the
		// loopback policy metrics, rule_hash from the policy objects, and the
		// exact export/filter settings.
		Capture: verifier,
		// Node-scoped lease: per-node source_id (COMMON ControlHealthLease).
		// The SAN is the same on every node and would collide on the
		// (source_id, component) lease key.
		// active_version carries the verified rule_hash: control-health
		// issues it as the challenges' expected rule_hash (#228
		// expectedRuleHash). SPEC-QUESTION: no spec field names it.
		Reporting: healthreport.Config{SourceID: "tetragon-node/" + id.NodeUID, NodeUID: id.NodeUID, Version: c.RuleHash, SensorGeneration: c.SensorGeneration, Sink: health},
	})
	if err != nil {
		return err
	}
	var responder *observe.Responder
	if c.observes() {
		responder, err = observe.New(observe.Config{NodeUID: id.NodeUID, BootID: id.BootID, RuleHash: c.RuleHash, SensorGeneration: c.SensorGeneration,
			WorkerBinaries: c.WorkerBinaries, Health: health, Proc: observe.HostProc{Root: c.ProcRoot, CgroupRoot: c.CgroupRoot}, Containers: resolver, Index: execs,
			Ready: supervisor.Healthy, Log: func(s string) { log.Print(s) }})
		if err != nil {
			return err
		}
	} else {
		log.Print("node observation responder disabled: node challenges will time out")
	}
	workers, cancel := context.WithCancel(ctx)
	defer cancel()
	resolved := make(chan error, 1)
	go func() { resolved <- resolver.Run(workers, client) }()
	go certs.Run(workers, func() { log.Print("client certificate renewal failed") })
	answered := make(chan error, 1)
	if responder != nil {
		go func() { answered <- responder.Run(workers) }()
	} else {
		answered <- nil
	}
	log.Printf("exporter started node=%s epoch=%s", id.NodeUID, epoch)
	err = supervisor.Run(workers, func(e error) { log.Print(e) })
	cancel()
	<-resolved
	<-answered
	return err
}
