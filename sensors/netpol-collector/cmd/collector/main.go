// Command collector is the netpol-collector DaemonSet (TASK-09 6, TASK-10 3.7):
// it captures the node's Dataplane V2 policy-action file into its own WAL,
// delivers NetworkPolicyRecords to `POST /internal/network-policy/records:batch`,
// reports the 5-second `netpol-collector` lease with details, and on SIGTERM
// reads to the end of the file, sends everything and requests a final flush.
//
//	collector --config /etc/agentarium/netpol-collector/config.json
//
// A lost checkpoint (rotation while stopped) is reported once as
// rotation_loss and collection stops for operator recovery; the cursor is
// never moved silently. No hold is requested (TASK-09 6).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/nodeid"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/workloadcert"
	collector "github.com/Beaver-Dam-Community/Agentarium/sensors/netpol-collector"
	"github.com/google/uuid"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
	Version              string `json:"version"`
	LiveFile             string `json:"live_file"`
	MaxLineBytes         int    `json:"max_line_bytes"`
	SpoolDir             string `json:"spool_dir"`
	SpoolCapacityBytes   int64  `json:"spool_capacity_bytes"`
	BootIDPath           string `json:"boot_id_path"`
	Kubeconfig           string `json:"kubeconfig,omitempty"`
	ClusterUID           string `json:"cluster_uid"`
	NormalizationVersion string `json:"normalization_version"`
	ReceiverOrigin       string `json:"receiver_origin"`
	HealthOrigin         string `json:"health_origin"`
	IdentityOrigin       string `json:"identity_origin"`
	// IdentityPeerSAN: the gateway relay for this hostNetwork DaemonSet
	// (TASK-03 3.3) or the identity service when connected directly.
	IdentityPeerSAN   string `json:"identity_peer_san"`
	TokenFile         string `json:"token_file"`
	CAFile            string `json:"ca_file"`
	FinalFlushSeconds int    `json:"final_flush_seconds"`
}

func loadConfig(path string) (Config, error) {
	var c Config
	raw, err := os.ReadFile(path)
	if err != nil {
		return c, errors.New("cannot read collector configuration")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF {
		return c, errors.New("invalid collector configuration")
	}
	for _, p := range []string{c.LiveFile, c.SpoolDir, c.BootIDPath, c.TokenFile, c.CAFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("configuration paths must be absolute and clean")
		}
	}
	if c.Version == "" || c.ReceiverOrigin == "" || c.HealthOrigin == "" || c.IdentityOrigin == "" || c.FinalFlushSeconds < 1 || c.MaxLineBytes < 1 || c.MaxLineBytes > wal.MaxRecordBytes {
		return c, errors.New("incomplete collector configuration")
	}
	return c, nil
}

func main() {
	path := flag.String("config", "/etc/agentarium/netpol-collector/config.json", "collector configuration JSON")
	flag.Parse()
	term, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(term, *path); err != nil {
		log.Print("netpol collector stopped: ", err)
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

type status struct {
	mu       sync.Mutex
	acked    uint64
	caughtUp *time.Time
	healthy  bool
	// stalledSince is when the current unacknowledged backlog last made no
	// progress; zero when nothing is pending. A quiet node is not stalled.
	stalledSince time.Time
	// missingSince is when the live file was last found missing.
	missingSince time.Time
}

// observe updates the backlog clock from the journal's real state.
func (st *status) observe(journal *wal.Journal, epoch string, now time.Time) {
	pending, err := journal.Pending()
	acked, _, _ := journal.Position(epoch)
	st.mu.Lock()
	defer st.mu.Unlock()
	if err != nil {
		st.healthy = false
		return
	}
	progressed := acked > st.acked
	if acked > st.acked {
		st.acked = acked // never lowered
	}
	switch {
	case len(pending) == 0:
		st.stalledSince = time.Time{}
	case st.stalledSince.IsZero() || progressed:
		st.stalledSince = now
	}
}

func (st *status) leaseHealthy(now time.Time) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	stalled := !st.stalledSince.IsZero() && now.Sub(st.stalledSince) >= 30*time.Second
	missing := !st.missingSince.IsZero() && now.Sub(st.missingSince) >= 10*time.Second
	return st.healthy && !stalled && !missing
}

func run(term context.Context, path string) error {
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
	kube, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return err
	}
	var id nodeid.Identity
	if err := retry(term, "node identity", func(ctx context.Context) error {
		id, err = nodeid.Resolve(ctx, kube, nodeName, c.BootIDPath)
		return err
	}); err != nil {
		return err
	}
	epoch, err := nodeid.Epoch(id, uuid.New())
	if err != nil {
		return err
	}
	certs := &workloadcert.Manager{URL: c.IdentityOrigin, PeerSAN: c.IdentityPeerSAN, TokenFile: c.TokenFile, CAFile: c.CAFile, SAN: collector.CollectorSAN}
	if err := retry(term, "workload certificate", certs.Refresh); err != nil {
		return err
	}
	journal, err := wal.Open(c.SpoolDir, epoch, c.SpoolCapacityBytes)
	if err != nil {
		return err
	}
	defer journal.Close()
	capture, err := collector.New(collector.Config{Journal: journal, Reader: collector.Reader{Inventory: func() ([]string, error) { return []string{c.LiveFile}, nil }, MaxFiles: 1, MaxLineBytes: c.MaxLineBytes}, ClusterUID: c.ClusterUID, NodeUID: id.NodeUID, NodeName: nodeName, NormalizationVersion: c.NormalizationVersion})
	if err != nil {
		return err
	}
	sender := &collector.Sender{Journal: journal, Epoch: epoch, Client: collector.HTTPSClient(collector.ReceiverSAN, certs.Roots, certs.GetClientCertificate), Origin: c.ReceiverOrigin}
	health := collector.HTTPSClient("spiffe://agentarium.internal/ns/agent-observe/sa/control-health", certs.Roots, certs.GetClientCertificate)

	// Background work (lease, certificate renewal) outlives SIGTERM until the
	// final flush finishes or times out.
	bg, cancelBG := context.WithCancel(context.Background())
	defer cancelBG()
	go certs.Run(bg, func() { log.Print("client certificate renewal failed") })
	st := &status{healthy: true}
	var leaseWG sync.WaitGroup
	leaseWG.Add(1)
	go func() {
		defer leaseWG.Done()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			st.mu.Lock()
			rejected, _ := journal.SchemaRejections()
			d := collector.Details{SourceEpoch: epoch, FileOffset: journal.Checkpoint().Offset, AckedThrough: st.acked, SchemaRejectedCount: rejected}
			if st.caughtUp != nil {
				t := st.caughtUp.UTC().Format(time.RFC3339Nano)
				d.CaughtUpAt = &t
			}
			st.mu.Unlock()
			st.observe(journal, epoch, time.Now())
			healthy := st.leaseHealthy(time.Now())
			call, cancel := context.WithTimeout(bg, 4*time.Second)
			if err := collector.ReportLease(call, health, c.HealthOrigin, collector.NewLease(id.NodeUID, c.Version, healthy, d, time.Now())); err != nil && bg.Err() == nil {
				log.Print("lease report failed: ", err)
			}
			cancel()
			select {
			case <-bg.Done():
				return
			case <-tick.C:
			}
		}
	}()
	log.Printf("netpol collector started node=%s epoch=%s", id.NodeUID, epoch)

	var lossAt *time.Time
	lossReported, capturing, dirty := false, true, true
	delay := time.Second
	// drain reads to EOF. It returns true when the file end was reached.
	drain := func(ctx context.Context) (bool, error) {
		for capturing {
			_, err := capture.Step(ctx)
			if !errors.Is(err, collector.ErrInventoryChanged) {
				st.mu.Lock()
				st.missingSince = time.Time{}
				st.mu.Unlock()
			}
			switch {
			case err == nil:
				dirty = true
			case errors.Is(err, io.EOF):
				return true, nil
			case errors.Is(err, collector.ErrInventoryChanged):
				// Also returned while the live file is missing; a lasting
				// absence turns the lease unhealthy instead of looping silently.
				st.mu.Lock()
				if st.missingSince.IsZero() {
					st.missingSince = time.Now()
				}
				st.mu.Unlock()
				return false, nil
			case errors.Is(err, collector.ErrSourceLoss):
				now := time.Now()
				lossAt, capturing = &now, false
				st.mu.Lock()
				st.healthy = false
				st.mu.Unlock()
				log.Print("policy-action checkpoint lost; reporting rotation_loss and stopping capture")
				return false, nil
			case ctx.Err() != nil:
				return false, ctx.Err()
			default:
				// An oversized line or another permanent read failure stops
				// capture but not the process: delivery, final flush and the
				// unhealthy lease continue instead of a crash loop.
				capturing = false
				st.mu.Lock()
				st.healthy = false
				st.mu.Unlock()
				log.Print("policy-action capture stopped: ", err)
				return false, nil
			}
		}
		return false, nil
	}
	send := func(ctx context.Context, final bool, eof bool) (collector.Result, error) {
		sig := collector.Signals{FinalFlush: final}
		// A batch reporting rotation loss never claims caught_up_at (#170).
		if eof && (dirty || final) && lossAt == nil {
			now := time.Now()
			sig.CaughtUpAt = &now
		}
		if lossAt != nil && !lossReported {
			sig.RotationLoss = lossAt
		}
		res, err := sender.Send(ctx, sig)
		if err != nil {
			return res, err
		}
		st.observe(journal, epoch, time.Now())
		st.mu.Lock()
		if res.CaughtUpSent {
			st.caughtUp, dirty = sig.CaughtUpAt, false
		}
		st.mu.Unlock()
		if res.RotationLossSent {
			lossReported = true
		}
		return res, nil
	}
	for term.Err() == nil {
		eof, err := drain(term)
		if err != nil && term.Err() == nil {
			st.mu.Lock()
			st.healthy = false
			st.mu.Unlock()
			return err
		}
		res, err := send(term, false, eof || !capturing)
		if err != nil {
			if term.Err() != nil {
				break
			}
			log.Print("delivery: ", err)
			var h *collector.HTTPError
			var rejected *collector.RejectedError
			if errors.As(err, &rejected) {
				// Permanent non-schema rejection: resending the same bytes
				// cannot succeed. Keep the WAL and report unhealthy.
				st.mu.Lock()
				st.healthy = false
				st.mu.Unlock()
				select {
				case <-term.Done():
				case <-time.After(30 * time.Second):
				}
				continue
			}
			if !errors.As(err, &h) || h.Retryable() {
				select {
				case <-term.Done():
				case <-time.After(delay):
				}
				delay = min(2*delay, 30*time.Second)
				continue
			}
			st.mu.Lock()
			st.healthy = false
			st.mu.Unlock()
			return err
		}
		delay = time.Second
		if res.Idle || res.Complete {
			select {
			case <-term.Done():
			case <-time.After(time.Second):
			}
		}
	}

	// SIGTERM: read to the end, send everything, request the final flush.
	// After a rotation loss or a stopped capture the collector cannot claim
	// it read to the end, so it sends the backlog without a final flush and
	// TASK-10 keeps the collector-stopped rules.
	final, cancelFinal := context.WithTimeout(context.Background(), time.Duration(c.FinalFlushSeconds)*time.Second)
	defer cancelFinal()
	for {
		eof, err := drain(final)
		if err != nil {
			return err
		}
		if !capturing {
			res, err := send(final, false, false)
			if err == nil && (res.Idle || res.Complete) && pendingEmpty(journal) {
				log.Print("capture stopped earlier; backlog sent without final flush")
				cancelBG()
				leaseWG.Wait()
				return nil
			}
			if final.Err() != nil {
				cancelBG()
				leaseWG.Wait()
				return errors.New("backlog not acknowledged before the termination deadline")
			}
			if err != nil {
				time.Sleep(200 * time.Millisecond)
			}
			continue
		}
		res, err := send(final, eof, eof)
		if err == nil && res.FinalRecorded {
			log.Print("final flush recorded")
			cancelBG()
			leaseWG.Wait()
			return nil
		}
		if final.Err() != nil {
			cancelBG()
			leaseWG.Wait()
			return errors.New("final flush not acknowledged before the termination deadline")
		}
		if err != nil {
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func pendingEmpty(j *wal.Journal) bool {
	p, err := j.Pending()
	return err == nil && len(p) == 0
}
