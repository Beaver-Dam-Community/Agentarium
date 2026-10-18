package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/normalize"
)

func kernelWire(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	id, _ := canonical.KernelEventID("sensor", "epoch", 1)
	m := map[string]any{"source_event_id": id, "sensor_id": "sensor", "source_epoch": "epoch", "source_sequence": 1,
		"exporter_instance_id": "exporter", "sensor_generation": 1, "node_uid": "30000000-0000-4000-8000-000000000001", "boot_id": "boot",
		"source_time": "2026-10-17T00:00:00Z", "spooled_at": "2026-10-17T00:00:01Z", "event_type": "process_exec", "process_exec_id": "exec",
		"metadata_status": "resolved", "normalization_version": "v1", "safe_attributes": map[string]any{}, "rule_hash": strings.Repeat("a", 64), "coverage": "complete"}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := canonical.DigestWithoutKeys(raw, "record_digest", "received_at")
	if err != nil {
		t.Fatal(err)
	}
	m["record_digest"] = digest
	raw, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestKernelRecord(t *testing.T) {
	raw := kernelWire(t, nil)
	if _, err := DecodeKernelRecord(raw, "sensor", "epoch"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"process_exec", "process_exit", "tcp_connect", "file_open", "openat", "tcp_state"} {
		t.Run(kind, func(t *testing.T) {
			wire := kernelWire(t, func(m map[string]any) {
				m["event_type"] = kind
				if kind == "tcp_state" {
					m["process_exec_id"] = nil
					m["tcp_new_state"] = 1
				}
				m["sock_ptr"] = "ffffffffffffffff"
			})
			r, err := DecodeKernelRecord(wire, "sensor", "epoch")
			if err != nil || r.SockPtr == nil || *r.SockPtr != "ffffffffffffffff" {
				t.Fatalf("valid %s rejected: %v", kind, err)
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"wrong source":     func(m map[string]any) { m["sensor_id"] = "other" },
		"wrong epoch":      func(m map[string]any) { m["source_epoch"] = "other" },
		"wrong UUID":       func(m map[string]any) { m["source_event_id"] = "30000000-0000-4000-8000-000000000002" },
		"zero sequence":    func(m map[string]any) { m["source_sequence"] = 0 },
		"missing process":  func(m map[string]any) { delete(m, "process_exec_id") },
		"null process":     func(m map[string]any) { m["process_exec_id"] = nil },
		"missing state":    func(m map[string]any) { m["event_type"] = "tcp_state" },
		"unobserved state": func(m map[string]any) { m["event_type"] = "tcp_state"; m["tcp_new_state"] = 3 },
		"unknown event":    func(m map[string]any) { m["event_type"] = "made_up" },
		"received_at":      func(m map[string]any) { m["received_at"] = nil },
		"source_id":        func(m map[string]any) { m["source_id"] = "injected" },
		"session_id":       func(m map[string]any) { m["session_id"] = "inferred" },
		"pointer number":   func(m map[string]any) { m["sock_ptr"] = 123 },
		"pointer prefix":   func(m map[string]any) { m["sock_ptr"] = "0xffffffffffffffff" },
		"pointer case":     func(m map[string]any) { m["sock_ptr"] = "FFFFFFFFFFFFFFFF" },
		"bad pod":          func(m map[string]any) { m["pod_uid"] = "bad" },
		"zero pid":         func(m map[string]any) { m["host_pid"] = 0 },
		"bad timestamp":    func(m map[string]any) { m["spooled_at"] = "yesterday" },
		"null generation":  func(m map[string]any) { m["sensor_generation"] = nil },
		"null attributes":  func(m map[string]any) { m["safe_attributes"] = nil },
		"case alias":       func(m map[string]any) { m["EVENT_TYPE"] = m["event_type"]; delete(m, "event_type") },
		"long string":      func(m map[string]any) { m["upstream_event_ref"] = strings.Repeat("x", 16385) },
		"tuple null port": func(m map[string]any) {
			m["socket_tuple"] = map[string]any{"saddr": "10.0.0.1", "sport": nil, "daddr": "10.0.0.2", "dport": 443}
		},
		"tuple alias": func(m map[string]any) {
			m["socket_tuple"] = map[string]any{"SADDR": "10.0.0.1", "sport": 80, "daddr": "10.0.0.2", "dport": 443}
		},
		"tuple overflow": func(m map[string]any) {
			m["socket_tuple"] = map[string]any{"saddr": "10.0.0.1", "sport": 65536, "daddr": "10.0.0.2", "dport": 443}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeKernelRecord(kernelWire(t, mutate), "sensor", "epoch"); !errors.Is(err, ErrSchema) {
				t.Fatalf("accepted %s: %v", name, err)
			}
		})
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"source_sequence":1`), []byte(`"source_sequence":9007199254740992`), 1),
		bytes.Replace(raw, []byte(`"source_sequence":1`), []byte(`"source_sequence":1e0`), 1),
		bytes.Replace(raw, []byte(`"sensor_id":"sensor"`), []byte(`"sensor_id":"sensor","sensor_id":"other"`), 1),
		bytes.Replace(raw, []byte(`"boot_id":"boot"`), []byte(`"boot_id":"changed"`), 1),
	} {
		if _, err := DecodeKernelRecord(bad, "sensor", "epoch"); err == nil {
			t.Fatal("accepted malformed or digest-mutated record")
		}
	}
	nullable := kernelWire(t, func(m map[string]any) { m["pod_uid"] = nil })
	r, _ := DecodeKernelRecord(raw, "sensor", "epoch")
	n, err := DecodeKernelRecord(nullable, "sensor", "epoch")
	if err != nil || r.Digest == n.Digest {
		t.Fatal("absent and null collapsed", err)
	}
	if _, err := DecodeKernelRecord(bytes.Replace(nullable, []byte(n.Digest), []byte(r.Digest), 1), "sensor", "epoch"); err == nil {
		t.Fatal("digest used re-marshalled struct")
	}
}

func TestKernelTCPStateProcessIdentity(t *testing.T) {
	for name, identity := range map[string]any{"null": nil, "nonempty": "exec-id", "empty": ""} {
		t.Run(name, func(t *testing.T) {
			raw := kernelWire(t, func(m map[string]any) {
				m["event_type"] = "tcp_state"
				m["tcp_new_state"] = 1
				m["process_exec_id"] = identity
			})
			record, err := DecodeKernelRecord(raw, "sensor", "epoch")
			if name == "empty" {
				if !errors.Is(err, ErrSchema) {
					t.Fatalf("empty process identity accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if name == "null" && record.ProcessExecID != nil {
				t.Fatal("null process identity was rewritten")
			}
			if name == "nonempty" && (record.ProcessExecID == nil || *record.ProcessExecID != "exec-id") {
				t.Fatal("process identity was rewritten")
			}
		})
	}
}

type kernelResolver struct{}

// COMMON metadata_status values (#185, enforced since #165): tcp_state is
// tuple-scoped without container identity; the rest resolve to the fixture Pod.
func (kernelResolver) Resolve(_ context.Context, q normalize.Query) (normalize.Resolution, error) {
	if q.EventType == "tcp_state" {
		return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataTupleScoped}, nil
	}
	return normalize.Resolution{Scope: normalize.Include, MetadataStatus: normalize.MetadataResolved, ContainerID: "fixture-container", PodUID: "10000000-0000-4000-8000-000000000001", LifecycleRecordID: "20000000-0000-4000-8000-000000000001"}, nil
}

// Exercise the actual producer and batch encoder with tracked Q0 input, not a
// second implementation of their wire format. Resolution is a fixture here.
func TestKernelProducerReceiverWire(t *testing.T) {
	events := map[string][]byte{}
	for _, file := range []string{"20261015-task01-q0-min-2/raw/run3-events.relevant.jsonl", "20261014-task01-q0-min/raw/run1-events.relevant.jsonl"} {
		raw, err := os.ReadFile(filepath.Join("../../../../evidence/gcp/runs", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.Split(raw, []byte{'\n'}) {
			var e struct {
				Exec   json.RawMessage `json:"process_exec"`
				Exit   json.RawMessage `json:"process_exit"`
				Kprobe *struct {
					Function string `json:"function_name"`
				} `json:"process_kprobe"`
			}
			if json.Unmarshal(line, &e) != nil {
				continue
			}
			kind := ""
			if len(e.Exec) > 0 {
				kind = "process_exec"
			} else if len(e.Exit) > 0 {
				kind = "process_exit"
			} else if e.Kprobe != nil {
				kind = e.Kprobe.Function
			}
			if _, ok := events[kind]; !ok && kind != "" {
				events[kind] = bytes.Clone(line)
			}
		}
	}
	for _, kind := range []string{"process_exec", "process_exit", "tcp_connect", "tcp_set_state", "security_file_open", "__x64_sys_openat"} {
		t.Run(kind, func(t *testing.T) {
			raw, ok := events[kind]
			if !ok {
				t.Fatal("tracked Q0 event missing")
			}
			var source struct {
				Node string `json:"node_name"`
			}
			if err := json.Unmarshal(raw, &source); err != nil {
				t.Fatal(err)
			}
			n, err := normalize.New(normalize.Config{SensorID: "sensor", ExporterInstanceID: "exporter", NodeUID: "30000000-0000-4000-8000-000000000001", BootID: "boot", NodeName: source.Node, SensorGeneration: 1, RuleHash: strings.Repeat("a", 64), Coverage: normalize.CoverageComplete, NormalizationVersion: "v1", AllowedBinaries: []string{"/app/bin/probe-runner"}, ProtectedPaths: []string{"/work/protected-fixture"}, Resolver: kernelResolver{}, Now: func() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) }})
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := n.Prepare(context.Background(), raw)
			if err != nil || prepared.Build == nil {
				t.Fatalf("prepare: %v", err)
			}
			wire, err := prepared.Build("epoch", 1)
			if err != nil {
				t.Fatal(err)
			}
			producer, err := batch.New(batch.Input{Stream: batch.Kernel, SourceID: "sensor", Epoch: "epoch", BatchID: "40000000-0000-4000-8000-000000000001", Records: []json.RawMessage{wire}})
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := DecodeKernelEnvelope(producer.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			record, err := DecodeKernelRecord(envelope.Records[0], "sensor", envelope.Epoch)
			if err != nil {
				t.Fatal(err)
			}
			if record.Sequence != 1 || !bytes.Equal(wire, envelope.Records[0]) {
				t.Fatal("producer bytes changed")
			}
		})
	}
}

func TestKernelEnvelope(t *testing.T) {
	valid := func(mutate func(map[string]any)) []byte {
		m := map[string]any{"batch_id": "40000000-0000-4000-8000-000000000001", "source_epoch": "epoch", "records": []any{json.RawMessage(kernelWire(t, nil))}, "sequence_range_abandoned": []any{}}
		if mutate != nil {
			mutate(m)
		}
		digest, err := canonical.CanonicalDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		m["batch_digest"] = digest
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, mutate := range map[string]func(map[string]any){
		"cursor": func(m map[string]any) { m["cursor"] = nil }, "scope": func(m map[string]any) { m["scope"] = "namespace/agent-exec" },
		"count": func(m map[string]any) { m["records"] = make([]any, 101) }, "null records": func(m map[string]any) { m["records"] = nil },
		"null range sequence": func(m map[string]any) {
			m["sequence_range_abandoned"] = []any{map[string]any{"from_seq": nil, "to_seq": 3, "reason": "wal_segment_corrupt", "range_digest": strings.Repeat("a", 64)}}
		},
		"alias": func(m map[string]any) { m["BATCH_ID"] = m["batch_id"]; delete(m, "batch_id") },
		"nested keys": func(m map[string]any) {
			v := map[string]any{}
			for i := 0; i < 257; i++ {
				v[fmt.Sprint(i)] = true
			}
			m["records"] = []any{v}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeKernelEnvelope(valid(mutate)); !errors.Is(err, ErrSchema) {
				t.Fatal("invalid envelope accepted", err)
			}
		})
	}
	raw := valid(nil)
	if _, err := DecodeKernelEnvelope(raw); err != nil {
		t.Fatal(err)
	}
	badRecord := valid(func(m map[string]any) {
		m["records"] = []any{map[string]any{"source_event_id": "bad"}, json.RawMessage(kernelWire(t, nil))}
	})
	b, err := DecodeKernelEnvelope(badRecord)
	if err != nil || len(b.Records) != 2 {
		t.Fatal("per-record error rejected whole envelope", err)
	}
	if _, err = DecodeKernelRecord(b.Records[0], "sensor", "epoch"); err == nil {
		t.Fatal("bad record accepted")
	}
	if _, err = DecodeKernelRecord(b.Records[1], "sensor", "epoch"); err != nil {
		t.Fatal("valid sibling rejected", err)
	}
	if _, err = DecodeKernelEnvelope(bytes.Replace(raw, []byte(`"source_epoch":"epoch"`), []byte(`"source_epoch":"mutated"`), 1)); err == nil {
		t.Fatal("tampered batch accepted")
	}
}

func TestKernelAbandonedRangeIdentity(t *testing.T) {
	digest, err := canonical.AbandonedRangeDigest("source", "kernel", "epoch", 1, 10, "wal_segment_corrupt")
	if err != nil {
		t.Fatal(err)
	}
	a := KernelRange{From: 1, To: 10, Reason: "wal_segment_corrupt", Digest: digest}
	if err := CheckKernelRange(a, "source", "epoch"); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"other", ""} {
		if err := CheckKernelRange(a, source, "epoch"); err == nil {
			t.Fatal("wrong range source accepted")
		}
	}
	if err := CheckKernelRange(a, "source", "other"); err == nil {
		t.Fatal("wrong range epoch accepted")
	}
	lifecycle, _ := canonical.AbandonedRangeDigest("source", "lifecycle", "epoch", 1, 10, a.Reason)
	a.Digest = lifecycle
	if err := CheckKernelRange(a, "source", "epoch"); err == nil {
		t.Fatal("wrong range stream accepted")
	}
}
