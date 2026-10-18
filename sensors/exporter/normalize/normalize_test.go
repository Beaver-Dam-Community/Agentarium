package normalize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/acquire"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

type resolverFunc func(context.Context, Query) (Resolution, error)

func (f resolverFunc) Resolve(ctx context.Context, q Query) (Resolution, error) { return f(ctx, q) }
func resolved(_ context.Context, q Query) (Resolution, error) {
	if q.EventType == "tcp_state" {
		return Resolution{Scope: Include, MetadataStatus: MetadataTupleScoped}, nil
	}
	return Resolution{Scope: Include, MetadataStatus: MetadataResolved, ContainerID: "fixture-container", PodUID: "10000000-0000-4000-8000-000000000001", LifecycleRecordID: "20000000-0000-4000-8000-000000000001"}, nil
}

// Read the actual tracked Q0 file export. Do not duplicate production IDs or
// raw arguments into new fixtures. Test mutations use synthetic private data.
func q0(t *testing.T, kind string) []byte {
	t.Helper()
	paths := []string{"20261015-task01-q0-min-2/raw/run3-events.relevant.jsonl", "20261014-task01-q0-min/raw/run1-events.relevant.jsonl"}
	for _, p := range paths {
		b, e := os.ReadFile(filepath.Join("../../../evidence/gcp/runs", p))
		if e != nil {
			t.Fatal(e)
		}
		for _, line := range bytes.Split(b, []byte{'\n'}) {
			var event rawEvent
			if json.Unmarshal(line, &event) != nil {
				continue
			}
			match := kind == "process_exec" && event.Exec != nil || kind == "process_exit" && event.Exit != nil || event.Kprobe != nil && event.Kprobe.Function == kind
			if match {
				return bytes.Clone(line)
			}
		}
	}
	t.Fatal("Q0 event missing", kind)
	return nil
}
func normalizer(t *testing.T, raw []byte) *Normalizer {
	t.Helper()
	var e rawEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	n, err := New(Config{SensorID: "fixture-sensor", ExporterInstanceID: "fixture-exporter", NodeUID: "30000000-0000-4000-8000-000000000001", BootID: "fixture-boot", NodeName: e.NodeName, SensorGeneration: 1, RuleHash: strings.Repeat("a", 64), NormalizationVersion: "fixture-v1", AllowedBinaries: []string{"/app/bin/probe-runner"}, ProtectedPaths: []string{"/work/protected-fixture"}, Resolver: resolverFunc(resolved), Now: func() time.Time { return time.Date(2026, 10, 16, 1, 2, 3, 4, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func buildEvent(t *testing.T, n *Normalizer, raw []byte) ([]byte, map[string]any) {
	t.Helper()
	p, e := n.Prepare(context.Background(), raw)
	if e != nil || p.Excluded || p.Build == nil {
		t.Fatal("prepare failed", e)
	}
	wire, e := p.Build("fixture-epoch", 1)
	if e != nil {
		t.Fatal(e)
	}
	var event map[string]any
	if e := json.Unmarshal(wire, &event); e != nil {
		t.Fatal(e)
	}
	return wire, event
}
func mutate(t *testing.T, raw []byte, f func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := d.Decode(&m); e != nil {
		t.Fatal(e)
	}
	f(m)
	b, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestActualQ0EventsUseOnlyAllowedWireFields(t *testing.T) {
	for _, kind := range []string{"process_exec", "process_exit", "tcp_connect", "tcp_set_state", "security_file_open", "__x64_sys_openat"} {
		t.Run(kind, func(t *testing.T) {
			raw := q0(t, kind)
			n := normalizer(t, raw)
			wire, event := buildEvent(t, n, raw)
			if _, exists := event["received_at"]; exists {
				t.Fatal("server timestamp leaked into request")
			}
			digest, e := canonical.DigestWithoutKeys(wire, "record_digest", "received_at")
			if e != nil || event["record_digest"] != digest {
				t.Fatal("record digest mismatch")
			}
			id, e := canonical.KernelEventID("fixture-sensor", "fixture-epoch", 1)
			if e != nil || event["source_event_id"] != id {
				t.Fatal("UUID mismatch")
			}
			if canonical.CheckStrictJSON(wire) != nil {
				t.Fatal("wire exceeds COMMON constraints")
			}
			if kind == "tcp_connect" && event["tcp_new_state"] != nil {
				t.Fatal("connect promoted to established")
			}
			if kind == "security_file_open" {
				if _, ok := event["safe_attributes"].(map[string]any)["flags"]; ok {
					t.Fatal("invented f_flags")
				}
			}
			if kind == "__x64_sys_openat" {
				if _, ok := event["safe_attributes"].(map[string]any)["return_errno"]; ok {
					t.Fatal("successful fd treated as errno")
				}
			}
		})
	}
}
func TestUint64SockPointerNoFloat64AndSoftIRQNoPod(t *testing.T) {
	raw := q0(t, "tcp_set_state")
	for _, cookie := range []any{"18446744073709551615", json.Number("18446744073709551615"), "9007199254740993", json.Number("9007199254740993")} {
		changed := mutate(t, raw, func(m map[string]any) {
			k := m["process_kprobe"].(map[string]any)
			k["args"].([]any)[0].(map[string]any)["sock_arg"].(map[string]any)["cookie"] = cookie
			p := k["process"].(map[string]any)
			p["exec_id"] = "wrong-softirq-exec"
			p["pod"] = map[string]any{"namespace": "kube-system", "uid": "wrong-softirq-pod"}
			p["docker"] = "wrong-softirq-container"
		})
		n := normalizer(t, changed)
		n.c.Resolver = resolverFunc(func(_ context.Context, q Query) (Resolution, error) {
			if q.ProcessExecID != "" || q.DockerPrefix != "" || q.NetNS != nil || q.Socket == nil || q.SockPtr == "" {
				t.Fatal("softirq process used in authoritative query")
			}
			return resolved(context.Background(), q)
		})
		wire, event := buildEvent(t, n, changed)
		expected := "ffffffffffffffff"
		if strings.Contains(stringMust(cookie), "900719925") {
			expected = "0020000000000001"
		}
		if event["sock_ptr"] != expected || event["tcp_new_state"] != float64(1) {
			t.Fatal("lossy socket/state mapping", event["sock_ptr"])
		}
		for _, key := range []string{"process_exec_id", "parent_exec_id", "process_start", "host_pid", "container_id", "docker_id_prefix", "pod_uid", "netns_inode", "lifecycle_record_id"} {
			if event[key] != nil {
				t.Fatal("softirq field not null", key)
			}
		}
		if bytes.Contains(wire, []byte("wrong-softirq")) {
			t.Fatal("softirq metadata leaked")
		}
	}
}
func stringMust(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	}
	return ""
}
func TestPrivacyAllowlistAndNoArgsDigest(t *testing.T) {
	raw := q0(t, "process_exec")
	changed := mutate(t, raw, func(m map[string]any) {
		p := m["process_exec"].(map[string]any)["process"].(map[string]any)
		p["binary"] = "/private/customer/task"
		p["cwd"] = "/private/customer/cwd"
		p["arguments"] = "SECRET_TASK_ARGS"
		p["environment_variables"] = []any{map[string]any{"key": "API_KEY", "value": "SECRET_ENV"}}
		p["pod"] = map[string]any{"uid": "untrusted-raw-pod", "container": map[string]any{"id": "untrusted-raw-container"}}
	})
	wire, event := buildEvent(t, normalizer(t, changed), changed)
	for _, secret := range []string{"SECRET_TASK_ARGS", "SECRET_ENV", "/private/customer/task", "/private/customer/cwd", "untrusted-raw-pod", "untrusted-raw-container"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("private material persisted")
		}
	}
	safe := event["safe_attributes"].(map[string]any)
	if safe["binary"] != canonical.SHA256Hex([]byte("/private/customer/task")) || safe["cwd_digest"] != canonical.SHA256Hex([]byte("/private/customer/cwd")) {
		t.Fatal("privacy digest mismatch")
	}
	if _, ok := safe["args_digest"]; ok {
		t.Fatal("task argv digested")
	}
	if event["pod_uid"] != "10000000-0000-4000-8000-000000000001" || event["container_id"] != "fixture-container" {
		t.Fatal("trusted lifecycle adapter not used")
	}
	if len(event["docker_id_prefix"].(string)) != 15 {
		t.Fatal("noncanonical docker prefix")
	}
}
func TestProtectedPathAndOpenatErrno(t *testing.T) {
	raw := q0(t, "__x64_sys_openat")
	for _, ret := range []int{4, 0, -13} {
		changed := mutate(t, raw, func(m map[string]any) {
			m["process_kprobe"].(map[string]any)["return"] = map[string]any{"int_arg": ret}
		})
		_, event := buildEvent(t, normalizer(t, changed), changed)
		safe := event["safe_attributes"].(map[string]any)
		got, exists := safe["return_errno"]
		if (ret < 0) != exists || ret < 0 && got != float64(ret) {
			t.Fatal("fd/errno confusion", ret, got)
		}
	}
	changed := mutate(t, raw, func(m map[string]any) {
		m["process_kprobe"].(map[string]any)["args"].([]any)[0].(map[string]any)["string_arg"] = "/private/secret"
	})
	n := normalizer(t, changed)
	n.c.Resolver = nil
	p, e := n.Prepare(context.Background(), changed)
	if e != nil || !p.Excluded || p.Build != nil {
		t.Fatal("non-protected path not excluded")
	}
}
func TestUnknownMetadataPreservesCheckpointAndFilteringConsumesNoSequence(t *testing.T) {
	raw := q0(t, "tcp_set_state")
	n := normalizer(t, raw)
	spool := t.TempDir()
	if e := os.Chmod(spool, 0700); e != nil {
		t.Fatal(e)
	}
	j, e := wal.Open(spool, "fixture-epoch", 0)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	live := filepath.Join(t.TempDir(), "tetragon.log")
	if e := os.WriteFile(live, append(append(bytes.Clone(raw), '\n'), append(raw, '\n')...), 0600); e != nil {
		t.Fatal(e)
	}
	collector, e := acquire.New(acquire.Config{Journal: j, LiveFile: live, MaxFiles: 2, MaxLineBytes: wal.MaxRecordBytes, Normalize: n.Prepare})
	if e != nil {
		t.Fatal(e)
	}
	n.c.Resolver = nil
	if _, e := collector.Step(context.Background()); !errors.Is(e, ErrMetadataUnavailable) {
		t.Fatal("nil metadata became exclusion", e)
	}
	if j.Checkpoint().Offset != 0 {
		t.Fatal("unknown metadata advanced checkpoint")
	}
	n.c.Resolver = resolverFunc(func(context.Context, Query) (Resolution, error) { return Resolution{Scope: Exclude}, nil })
	result, e := collector.Step(context.Background())
	if e != nil || !result.Filtered {
		t.Fatal("positive filter failed", e)
	}
	if pending, e := j.Pending(); e != nil || len(pending) != 0 {
		t.Fatal("filtered event reserved a sequence")
	}
	n.c.Resolver = resolverFunc(resolved)
	result, e = collector.Step(context.Background())
	if e != nil || result.Record == nil || result.Record.Sequence != 1 {
		t.Fatal("first included event not sequence 1", e)
	}
}
func TestRejectMalformedDuplicateAndInvalidPointers(t *testing.T) {
	raw := q0(t, "tcp_set_state")
	n := normalizer(t, raw)
	for _, cookie := range []any{"18446744073709551616", "-1", "0x123", "1e3", json.Number("1.5"), json.Number("18446744073709551616")} {
		changed := mutate(t, raw, func(m map[string]any) {
			m["process_kprobe"].(map[string]any)["args"].([]any)[0].(map[string]any)["sock_arg"].(map[string]any)["cookie"] = cookie
		})
		if _, e := n.Prepare(context.Background(), changed); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid pointer accepted", cookie, e)
		}
	}
	for _, bad := range [][]byte{[]byte(`{"x":1,"x":2}`), []byte(`{"x":"\ud800"}`), []byte(`{"x":1} {"x":2}`), append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"time":"2026-10-16T00:00:00Z"}`)...)} {
		if e := checkRaw(bad); e == nil {
			t.Fatal("invalid original JSON accepted")
		}
	}
	changed := mutate(t, raw, func(m map[string]any) {
		m["process_kprobe"].(map[string]any)["args"].([]any)[1].(map[string]any)["int_arg"] = 2
	})
	if _, e := n.Prepare(context.Background(), changed); !errors.Is(e, ErrInvalid) {
		t.Fatal("unsupported TCP state accepted")
	}
	changed = mutate(t, raw, func(m map[string]any) { m["node_name"] = "other-node" })
	if _, e := n.Prepare(context.Background(), changed); !errors.Is(e, ErrInvalid) {
		t.Fatal("foreign node accepted")
	}
	changed = mutate(t, raw, func(m map[string]any) { m["aggregation_info"] = map[string]any{"count": 2} })
	if _, e := n.Prepare(context.Background(), changed); !errors.Is(e, ErrUnsupported) {
		t.Fatal("aggregate accepted")
	}
}
func TestPreparedCallbackDoesNotRetainMutableResolverFields(t *testing.T) {
	raw := q0(t, "tcp_connect")
	n := normalizer(t, raw)
	n.c.Resolver = resolverFunc(func(_ context.Context, q Query) (Resolution, error) {
		q.Socket.SAddr = "private-mutation"
		if q.NetNS != nil {
			*q.NetNS = 1
		}
		return resolved(context.Background(), q)
	})
	p, e := n.Prepare(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := uint64(1); i <= 12; i++ {
		wg.Add(1)
		go func(seq uint64) {
			defer wg.Done()
			wire, e := p.Build("fixture-epoch", seq)
			if e != nil || bytes.Contains(wire, []byte("private-mutation")) {
				t.Error("mutable resolver data leaked", e)
			}
		}(i)
	}
	wg.Wait()
}

func TestRejectMixedEventAndArgumentOneofs(t *testing.T) {
	raw := q0(t, "tcp_connect")
	n := normalizer(t, raw)
	mixedEvent := mutate(t, raw, func(m map[string]any) { m["process_loader"] = map[string]any{"unexpected": true} })
	if _, e := n.Prepare(context.Background(), mixedEvent); !errors.Is(e, ErrUnsupported) {
		t.Fatal("mixed event oneof accepted", e)
	}
	mixedArg := mutate(t, raw, func(m map[string]any) {
		m["process_kprobe"].(map[string]any)["args"].([]any)[0].(map[string]any)["int_arg"] = 1
	})
	if _, e := n.Prepare(context.Background(), mixedArg); !errors.Is(e, ErrInvalid) {
		t.Fatal("mixed argument oneof accepted", e)
	}
}

func TestUUIDPIDAndUnknownMetadataFailClosed(t *testing.T) {
	raw := q0(t, "process_exec")
	n := normalizer(t, raw)
	bad := n.c
	bad.NodeUID = "not-a-node-uuid"
	if _, err := New(bad); err == nil {
		t.Fatal("invalid node UUID accepted")
	}
	for _, id := range []string{"not-a-uuid", "ABCDEF00-0000-4000-8000-000000000001"} {
		for _, field := range []string{"pod", "lifecycle"} {
			n.c.Resolver = resolverFunc(func(ctx context.Context, q Query) (Resolution, error) {
				r, _ := resolved(ctx, q)
				if field == "pod" {
					r.PodUID = id
				} else {
					r.LifecycleRecordID = id
				}
				return r, nil
			})
			if _, err := n.Prepare(context.Background(), raw); !errors.Is(err, ErrMetadataUnavailable) {
				t.Fatal("invalid resolver UUID accepted", err)
			}
		}
	}
	n.c.Resolver = resolverFunc(resolved)
	for _, pid := range []uint64{0, 2147483648, 4294967295} {
		changed := mutate(t, raw, func(m map[string]any) { m["process_exec"].(map[string]any)["process"].(map[string]any)["pid"] = pid })
		if _, err := n.Prepare(context.Background(), changed); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid host PID accepted", pid, err)
		}
	}
	for _, resolution := range []Resolution{{Scope: Unknown}, {Scope: Include}, {Scope: Scope(99), MetadataStatus: MetadataResolved}, {Scope: Include, MetadataStatus: "fixture-status"}, {Scope: Include, MetadataStatus: MetadataUnresolved, PodUID: "10000000-0000-4000-8000-000000000001"}} {
		n.c.Resolver = resolverFunc(func(context.Context, Query) (Resolution, error) { return resolution, nil })
		p, err := n.Prepare(context.Background(), raw)
		if !errors.Is(err, ErrMetadataUnavailable) || p.Excluded || p.Build != nil {
			t.Fatal("missing metadata authorized a skip", err)
		}
	}
}
func TestKernelPseudoProcessIsExcluded(t *testing.T) {
	raw := q0(t, "process_exec")
	set := func(binary string, pid int) []byte {
		return mutate(t, raw, func(m map[string]any) {
			p := m["process_exec"].(map[string]any)["process"].(map[string]any)
			p["binary"], p["pid"] = binary, pid
		})
	}
	kernel := set("<kernel>", 0)
	if p, err := normalizer(t, kernel).Prepare(context.Background(), kernel); err != nil || !p.Excluded {
		t.Fatalf("kernel pseudo-process not excluded: %v", err)
	}
	spoofed := set("<kernel>", 42)
	if _, err := normalizer(t, spoofed).Prepare(context.Background(), spoofed); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-zero pid <kernel> accepted: %v", err)
	}
}
func TestDualStackSocketKeepsIPv4Tuple(t *testing.T) {
	raw := q0(t, "tcp_set_state")
	setSock := func(family, saddr, daddr string) []byte {
		return mutate(t, raw, func(m map[string]any) {
			sk := m["process_kprobe"].(map[string]any)["args"].([]any)[0].(map[string]any)["sock_arg"].(map[string]any)
			sk["family"], sk["saddr"], sk["daddr"] = family, saddr, daddr
		})
	}
	mapped := setSock("AF_INET6", "::ffff:10.20.2.7", "::ffff:169.254.4.6")
	var got *Tuple
	n := normalizer(t, mapped)
	n.c.Resolver = resolverFunc(func(_ context.Context, q Query) (Resolution, error) {
		got = q.Socket
		return Resolution{Scope: Exclude}, nil
	})
	if _, err := n.Prepare(context.Background(), mapped); err != nil || got == nil || got.SAddr != "10.20.2.7" || got.DAddr != "169.254.4.6" {
		t.Fatalf("IPv4-mapped peer rejected or not unmapped: %v %+v", err, got)
	}
	listener := setSock("AF_INET6", "::", "::")
	if _, err := n.Prepare(context.Background(), listener); err != nil || got.SAddr != "0.0.0.0" || got.DAddr != "0.0.0.0" {
		t.Fatalf("dual-stack wildcard listener rejected or not 0.0.0.0: %v %+v", err, got)
	}
	for _, bad := range [][]byte{setSock("AF_INET6", "fd00::1", "::ffff:10.0.0.1"), setSock("AF_INET6", "::1", "::"), setSock("AF_INET", "::ffff:10.0.0.1", "10.0.0.2"), setSock("AF_UNIX", "10.0.0.1", "10.0.0.2")} {
		if _, err := normalizer(t, bad).Prepare(context.Background(), bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("non-IPv4 TCP accepted: %v", err)
		}
	}
}
func TestTCPCloseHasOnlyTopLevelState(t *testing.T) {
	raw := q0(t, "tcp_set_state")
	changed := mutate(t, raw, func(m map[string]any) {
		m["process_kprobe"].(map[string]any)["args"].([]any)[1].(map[string]any)["int_arg"] = 7
	})
	_, event := buildEvent(t, normalizer(t, changed), changed)
	if event["tcp_new_state"] != float64(7) {
		t.Fatal("CLOSE lost")
	}
	if _, exists := event["safe_attributes"].(map[string]any)["new_state"]; exists {
		t.Fatal("duplicate state authority")
	}
}

// COMMON KernelEvent.coverage (PR #185): complete only when every identity
// field of the event type was observed; metadata_status follows the resolver.
func TestCoverageAndMetadataStatusEnums(t *testing.T) {
	for _, kind := range []string{"process_exec", "process_exit", "tcp_connect", "tcp_set_state", "security_file_open", "__x64_sys_openat"} {
		raw := q0(t, kind)
		_, event := buildEvent(t, normalizer(t, raw), raw)
		want := MetadataResolved
		if kind == "tcp_set_state" {
			want = MetadataTupleScoped
		}
		if event["coverage"] != CoverageComplete || event["metadata_status"] != want {
			t.Fatalf("%s: coverage=%v status=%v", kind, event["coverage"], event["metadata_status"])
		}
	}
	raw := mutate(t, q0(t, "process_exec"), func(m map[string]any) {
		delete(m["process_exec"].(map[string]any)["process"].(map[string]any), "pid")
	})
	if _, event := buildEvent(t, normalizer(t, raw), raw); event["coverage"] != CoveragePartial {
		t.Fatalf("missing host PID must be partial: %v", event["coverage"])
	}
	unresolved := func(context.Context, Query) (Resolution, error) {
		return Resolution{Scope: Include, MetadataStatus: MetadataUnresolved}, nil
	}
	raw = q0(t, "tcp_connect")
	n := normalizer(t, raw)
	n.c.Resolver = resolverFunc(unresolved)
	if _, event := buildEvent(t, n, raw); event["coverage"] != CoveragePartial || event["metadata_status"] != MetadataUnresolved || event["pod_uid"] != nil {
		t.Fatalf("unresolved connect: %v", event)
	}
	for _, bad := range []Resolution{{Scope: Include, MetadataStatus: MetadataTupleScoped}, {Scope: Include, MetadataStatus: MetadataResolved}} {
		n.c.Resolver = resolverFunc(func(context.Context, Query) (Resolution, error) { return bad, nil })
		if _, err := n.Prepare(context.Background(), raw); !errors.Is(err, ErrMetadataUnavailable) {
			t.Fatalf("status %q without its fields accepted: %v", bad.MetadataStatus, err)
		}
	}
}
