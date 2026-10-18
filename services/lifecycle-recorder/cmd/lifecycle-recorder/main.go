// Command lifecycle-recorder is the TASK-09 3.6 runtime lifecycle recorder
// DaemonSet: containerd task events -> LifecycleRecords (mapping_version 1,
// PR #207) -> TASK-07 `POST /internal/lifecycle/events:batch`, with
// RUNTIME_RECORD_MISSING gaps to control-health and a 5-second
// `lifecycle-recorder` lease.
//
//	lifecycle-recorder --config /etc/agentarium/lifecycle-recorder/config.json
//
// The recorder runs as a non-root user and reaches containerd only through
// the containerd-proxy socket of its Pod (TASK-09 3.6 containerd access boundary).
// The spool-owner init container runs
//
//	lifecycle-recorder --prepare-spool /var/lib/agentarium/lifecycle-spool --spool-owner 65532 --spool-group 65532
//
// with only CAP_CHOWN to hand the hostPath spool to that user.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/nodeid"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/recorder"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
	Version          string `json:"version"`
	ContainerdSocket string `json:"containerd_socket"`
	CgroupRoot       string `json:"cgroup_root"`
	SpoolDir         string `json:"spool_dir"`
	SpoolCapacity    int64  `json:"spool_capacity_bytes"`
	BootIDPath       string `json:"boot_id_path"`
	ClusterUID       string `json:"cluster_uid"`
	CollectorOrigin  string `json:"collector_origin"`
	HealthOrigin     string `json:"health_origin"`
	IdentityOrigin   string `json:"identity_origin"`
	// IdentityPeerSAN: the identity service; the recorder is on the Pod
	// network and connects to it directly (TASK-03 3.3, TASK-06 3.1).
	IdentityPeerSAN string `json:"identity_peer_san"`
	TokenFile       string `json:"token_file"`
	CAFile          string `json:"ca_file"`
	Kubeconfig      string `json:"kubeconfig,omitempty"`
}

func loadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, errors.New("cannot read recorder configuration")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid recorder configuration")
	}
	for _, p := range []string{c.ContainerdSocket, c.CgroupRoot, c.SpoolDir, c.BootIDPath, c.TokenFile, c.CAFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("configuration paths must be absolute and clean")
		}
	}
	if c.Version == "" || c.CollectorOrigin == "" || c.HealthOrigin == "" || c.IdentityOrigin == "" {
		return c, errors.New("incomplete recorder configuration")
	}
	return c, nil
}

func main() {
	path := flag.String("config", "/etc/agentarium/lifecycle-recorder/config.json", "recorder configuration JSON")
	spool := flag.String("prepare-spool", "", "chown this spool directory to --spool-owner, set it to 0700 and exit")
	owner := flag.Int("spool-owner", 65532, "uid that owns the spool")
	group := flag.Int("spool-group", 65532, "gid that owns the spool")
	flag.Parse()
	if *spool != "" {
		if err := prepareSpool(*spool, *owner, *group); err != nil {
			log.Fatal("prepare spool: ", err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *path); err != nil && !errors.Is(err, context.Canceled) {
		log.Print("lifecycle-recorder stopped: ", err)
		os.Exit(1)
	}
}

// prepareSpool gives the spool directory and everything in it to uid:gid
// and makes the directory owner-only. Symbolic links are re-owned, not
// followed.
func prepareSpool(dir string, uid, gid int) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || uid <= 0 || gid < 0 {
		return errors.New("spool must be an absolute clean path and the owner non-root")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return errors.New("spool is not a directory")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("spool ownership unavailable")
	}
	// On restart the non-root recorder owns a private directory. CAP_CHOWN
	// does not permit root to traverse it or chmod it; leave it untouched.
	if int(st.Uid) == uid && int(st.Gid) == gid && fi.Mode().Perm() == 0o700 {
		return nil
	}
	// Tighten access while we still own the directory. Enumerate before
	// transferring ownership, then chown children before their parents so
	// private subdirectories remain traversable without DAC_OVERRIDE.
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	var paths []string
	if err := filepath.WalkDir(dir, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// A previous init may have stopped after finishing a private subtree
		// but before chowning its parent. Children are always transferred first,
		// so an already-transferred directory is complete and need not be read.
		// CAP_CHOWN alone cannot traverse that directory on restart.
		if p != dir && entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && int(stat.Uid) == uid && int(stat.Gid) == gid && info.Mode().Perm() == 0o700 {
				return filepath.SkipDir
			}
		}
		paths = append(paths, p)
		return nil
	}); err != nil {
		return err
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if err := os.Lchown(paths[i], uid, gid); err != nil {
			return err
		}
	}
	return nil
}

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

func run(ctx context.Context, path string) error {
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return errors.New("NODE_NAME is required")
	}
	var rc *rest.Config
	if c.Kubeconfig != "" {
		rc, err = clientcmd.BuildConfigFromFlags("", c.Kubeconfig)
	} else {
		rc, err = rest.InClusterConfig()
	}
	if err != nil {
		return errors.New("kubernetes client unavailable")
	}
	rc.ContentType, rc.AcceptContentTypes = "application/json", "application/json"
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	var id nodeid.Identity
	if err := retry(ctx, "node identity", func(ctx context.Context) error {
		id, err = nodeid.Resolve(ctx, kube, nodeName, c.BootIDPath)
		return err
	}); err != nil {
		return err
	}
	epoch, err := nodeid.Epoch(id, uuid.New())
	if err != nil {
		return err
	}
	certs := &workloadcert.Manager{URL: c.IdentityOrigin, PeerSAN: c.IdentityPeerSAN, TokenFile: c.TokenFile, CAFile: c.CAFile, SAN: recorder.SourceSAN}
	if err := retry(ctx, "workload certificate", certs.Refresh); err != nil {
		return err
	}
	go certs.Run(ctx, func() { log.Print("client certificate renewal failed") })
	roots, err := certs.Roots()
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, GetClientCertificate: certs.GetClientCertificate}
	collector, err := batch.NewClient(c.CollectorOrigin, tlsConfig)
	if err != nil {
		return err
	}
	defer collector.Close()
	gapClient, err := recorder.NewControlHealthClient(tlsConfig)
	if err != nil {
		return err
	}
	leases, err := healthreport.NewClient(c.HealthOrigin, roots, certs.GetClientCertificate)
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient("unix://"+c.ContainerdSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	sink := &recorder.HTTPGapSink{Directory: c.SpoolDir, Origin: c.HealthOrigin, Client: gapClient}
	rec, err := recorder.Open(recorder.Config{Directory: c.SpoolDir, ClusterUID: c.ClusterUID, NodeUID: id.NodeUID, BootID: id.BootID, Epoch: epoch,
		Source: recorder.GRPCSource{Conn: conn}, Collector: collector, GapSink: sink.Report, CgroupRoot: c.CgroupRoot, Capacity: c.SpoolCapacity})
	if err != nil {
		return err
	}
	defer rec.Close()
	go reportLeases(ctx, leases, rec, id.NodeUID, c.Version)
	log.Printf("lifecycle-recorder started node=%s epoch=%s", id.NodeUID, epoch)
	return rec.Run(ctx)
}

// reportLeases sends the 5-second lifecycle-recorder lease (TASK-09 4). It is
// healthy only while subscribed, not failed, and the pending backlog has made
// ACK progress within 30 s.
func reportLeases(ctx context.Context, client *healthreport.Client, rec *recorder.Recorder, nodeUID, version string) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var lastProgress uint64
	var stalledSince time.Time
	for {
		now := time.Now()
		st := rec.Status()
		healthy := st.Subscribed && !st.Failed
		if snap, err := rec.Journal().HealthSnapshot(); err != nil {
			healthy = false
		} else {
			switch {
			case !snap.Pending:
				stalledSince = time.Time{}
			case stalledSince.IsZero() || snap.AckProgress > lastProgress:
				stalledSince = now
			}
			lastProgress = snap.AckProgress
			if !stalledSince.IsZero() && now.Sub(stalledSince) >= 30*time.Second {
				healthy = false
			}
		}
		state := "unhealthy"
		if healthy {
			state = "healthy"
		}
		lease := healthreport.Lease{SourceID: "lifecycle-node/" + nodeUID, Component: "lifecycle-recorder", Scope: "node", ScopeID: nodeUID, ActiveVersion: &version, LeaseUntil: now.UTC().Add(15 * time.Second), ObservedState: state, ReportedAt: now.UTC()}
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		if err := client.ReportLease(call, lease); err != nil && ctx.Err() == nil {
			log.Print("lease report failed: ", err)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
