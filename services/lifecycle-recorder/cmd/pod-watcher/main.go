// Command pod-watcher is the TASK-09 3.6 Pod watcher: a single-replica
// agent-observe Deployment with leader election. The leader opens the durable
// watcher spool, LISTs/WATCHes Pods of one Namespace with the mapping_version 1
// normalizer, delivers LifecycleRecords to TASK-07
// `POST /internal/lifecycle/events:batch`, and reports watch-history gaps to
// `POST /internal/control-health/observation-gaps` (#178).
//
//	pod-watcher --config /etc/agentarium/pod-watcher/config.json
//
// Losing leadership stops the process so a new leader starts from the
// TASK-07 checkpoint; the spool (a PersistentVolume) carries unacknowledged
// records to the next leader.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/workloadcert"
	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

type Config struct {
	Namespace       string `json:"namespace"`
	ClusterUID      string `json:"cluster_uid"`
	Directory       string `json:"directory"`
	CapacityBytes   int64  `json:"capacity_bytes"`
	PageSize        int64  `json:"page_size"`
	CollectorOrigin string `json:"collector_origin"`
	HealthOrigin    string `json:"health_origin"`
	IdentityOrigin  string `json:"identity_origin"`
	TokenFile       string `json:"token_file"`
	CAFile          string `json:"ca_file"`
	LeaseNamespace  string `json:"lease_namespace"`
	LeaseName       string `json:"lease_name"`
	Kubeconfig      string `json:"kubeconfig,omitempty"`
}

func loadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, errors.New("cannot read pod-watcher configuration")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid pod-watcher configuration")
	}
	for _, p := range []string{c.Directory, c.TokenFile, c.CAFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("configuration paths must be absolute and clean")
		}
	}
	if c.Namespace == "" || c.CollectorOrigin == "" || c.HealthOrigin == "" || c.IdentityOrigin == "" || c.LeaseNamespace == "" || c.LeaseName == "" {
		return c, errors.New("incomplete pod-watcher configuration")
	}
	if id, err := uuid.Parse(c.ClusterUID); err != nil || id == uuid.Nil || id.String() != c.ClusterUID {
		return c, errors.New("cluster_uid must be a canonical nonzero UUID")
	}
	return c, nil
}

func main() {
	path := flag.String("config", "/etc/agentarium/pod-watcher/config.json", "pod-watcher configuration JSON")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *path); err != nil && !errors.Is(err, context.Canceled) {
		log.Print("pod-watcher stopped: ", err)
		os.Exit(1)
	}
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
	identity := os.Getenv("POD_NAME")
	if identity == "" {
		return errors.New("POD_NAME is required (downward API metadata.name)")
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
	rc.UserAgent = "agentarium-pod-watcher"
	// JSON keeps the wire inspectable and independent of client-go's
	// protobuf/CBOR negotiation defaults.
	rc.ContentType, rc.AcceptContentTypes = "application/json", "application/json"
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	// The watcher is a regular agent-observe service: it bootstraps directly
	// from the identity service (TASK-03 3.3).
	certs := &workloadcert.Manager{URL: c.IdentityOrigin, TokenFile: c.TokenFile, CAFile: c.CAFile, SAN: batch.PodWatcherSource}
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
	health, err := watcher.NewControlHealthClient(tlsConfig)
	if err != nil {
		return err
	}
	lock := &resourcelock.LeaseLock{LeaseMeta: metav1.ObjectMeta{Namespace: c.LeaseNamespace, Name: c.LeaseName}, Client: kube.CoordinationV1(), LockConfig: resourcelock.ResourceLockConfig{Identity: identity}}
	result := make(chan error, 1)
	var stateMu sync.Mutex
	var started, stopped bool
	var leadErr error
	leaderCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock: lock, LeaseDuration: 15 * time.Second, RenewDeadline: 10 * time.Second, RetryPeriod: 2 * time.Second,
		ReleaseOnCancel: false, Name: c.LeaseName,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(lctx context.Context) {
				stateMu.Lock()
				if stopped {
					stateMu.Unlock()
					return
				}
				started = true
				stateMu.Unlock()
				result <- lead(lctx, c, kube, collector, health)
				cancel()
			},
			OnStoppedLeading: func() {
				cancel()
				// Fence a delayed OnStartedLeading callback and wait for an
				// active producer to flush/close its WAL before returning.
				stateMu.Lock()
				stopped = true
				wasStarted := started
				stateMu.Unlock()
				if wasStarted {
					leadErr = <-result
				} else {
					leadErr = ctx.Err()
				}
				if ctx.Err() == nil && (leadErr == nil || errors.Is(leadErr, context.Canceled)) {
					leadErr = errors.New("leadership lost; restarting from the TASK-07 checkpoint")
				}

			},
		},
	})
	if err != nil {
		return err
	}
	log.Printf("pod-watcher %s waiting for leadership of %s/%s", identity, c.LeaseNamespace, c.LeaseName)
	elector.Run(leaderCtx)
	return leadErr
}

// lead runs one producer while this replica holds the lease.
func lead(ctx context.Context, c Config, kube kubernetes.Interface, collector *batch.Client, health *http.Client) error {
	sink := &watcher.HTTPGapSink{Directory: c.Directory, Origin: c.HealthOrigin, Client: health}
	p, err := watcher.Open(watcher.Config{Directory: c.Directory, Namespace: c.Namespace, ClusterUID: c.ClusterUID, Core: kube.CoreV1(), Collector: collector,
		Normalize: watcher.Normalize, GapSink: sink.Report, PageSize: c.PageSize, Capacity: c.CapacityBytes})
	if err != nil {
		return err
	}
	log.Printf("pod-watcher leading: namespace=%s", c.Namespace)
	err = p.Run(ctx)
	if cerr := p.Close(); err == nil || errors.Is(err, context.Canceled) {
		if cerr != nil {
			return cerr
		}
	}
	return err
}
