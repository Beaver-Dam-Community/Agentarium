// Package normalize implements the pinned Tetragon 1.7.1 file-export adapter.
// It emits only allowlisted KernelEvent fields. Scope and lifecycle metadata
// require an authoritative caller-supplied resolver; raw Pod metadata is never
// promoted to that authority and softirq process metadata is never used.
package normalize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/acquire"
)

var ErrMetadataUnavailable = errors.New("trusted observation metadata unavailable")
var ErrUnsupported = errors.New("unsupported Tetragon event or hook")

// COMMON KernelEvent.metadata_status (PR #185).
const (
	MetadataResolved    = "resolved"
	MetadataTupleScoped = "tuple_scoped"
	MetadataUnresolved  = "unresolved"
)

// validStatus binds each status to the fields it may carry: resolved needs
// API container and Pod IDs; tuple_scoped is only for softirq tcp_state;
// unresolved carries no IDs.
func validStatus(kind string, r Resolution) bool {
	ids := r.ContainerID != "" && r.PodUID != ""
	none := r.ContainerID == "" && r.PodUID == "" && r.LifecycleRecordID == ""
	switch r.MetadataStatus {
	case MetadataResolved:
		return kind != "tcp_state" && ids
	case MetadataTupleScoped:
		return kind == "tcp_state" && none
	case MetadataUnresolved:
		return none
	}
	return false
}

// COMMON KernelEvent.coverage (PR #185): complete when every identity field
// the event type can carry was observed (TASK-09 4 field table).
const (
	CoverageComplete = "complete"
	CoveragePartial  = "partial"
)

var processIdentity = []string{"process_exec_id", "process_start", "host_pid", "container_id", "pod_uid", "netns_inode"}

func coverage(kind string, record map[string]any) string {
	var fields []string
	switch kind {
	case "tcp_state":
		fields = []string{"socket_tuple", "sock_ptr", "tcp_new_state"}
	case "tcp_connect":
		fields = append(append([]string{}, processIdentity...), "socket_tuple", "sock_ptr")
	default:
		fields = processIdentity
	}
	for _, f := range fields {
		v := record[f]
		if v == nil {
			return CoveragePartial
		}
		switch x := v.(type) {
		case *uint32:
			if x == nil {
				return CoveragePartial
			}
		case *int32:
			if x == nil {
				return CoveragePartial
			}
		case *Tuple:
			if x == nil {
				return CoveragePartial
			}
		}
	}
	return CoverageComplete
}

var ErrInvalid = errors.New("invalid Tetragon event")
var canonicalUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var hexPrefix = regexp.MustCompile(`^[0-9a-f]{15,64}$`)

// Scope is an internal adapter decision, not a new wire enum. Unknown never
// skips input or reserves a sequence. Exclude requires positive scope evidence.
type Scope int

const (
	Unknown Scope = iota
	Include
	Exclude
)

type Tuple struct {
	SAddr string `json:"saddr"`
	SPort uint32 `json:"sport"`
	DAddr string `json:"daddr"`
	DPort uint32 `json:"dport"`
}
type Query struct {
	NodeUID, BootID, EventType  string
	SourceTime                  time.Time
	ProcessExecID, DockerPrefix string
	NetNS                       *uint32
	Socket                      *Tuple
	SockPtr                     string
}
type Resolution struct {
	Scope Scope
	// Exact version/status vocabulary belongs to the installed metadata adapter.
	// This normalizer neither invents values nor derives completeness from labels.
	MetadataStatus                         string
	ContainerID, PodUID, LifecycleRecordID string
}
type Resolver interface {
	Resolve(context.Context, Query) (Resolution, error)
}
type Config struct {
	SensorID, ExporterInstanceID, NodeUID, BootID, NodeName string
	SensorGeneration                                        int64
	RuleHash, NormalizationVersion                          string
	// Deprecated: ignored. coverage is computed per event from the COMMON
	// enum (PR #185); kept only so existing callers still compile.
	Coverage                        string
	AllowedBinaries, ProtectedPaths []string
	Resolver                        Resolver
	Now                             func() time.Time
	// ExecNamespace, when set, receives the Tetragon PID namespace inode of
	// each included process_exec before its WAL append. It is in-memory
	// witness input (TASK-09 independent session worker observation), never exported.
	ExecNamespace func(execID string, pidNS uint32)
}
type Normalizer struct {
	c                   Config
	binaries, protected map[string]bool
}

func New(c Config) (*Normalizer, error) {
	for _, s := range []string{c.SensorID, c.ExporterInstanceID, c.NodeUID, c.BootID, c.NodeName, c.NormalizationVersion} {
		if !textValid(s) {
			return nil, errors.New("incomplete normalizer configuration")
		}
	}
	if !canonicalUUID.MatchString(c.NodeUID) || c.SensorGeneration < 1 || c.SensorGeneration > 9007199254740991 || !hex64.MatchString(c.RuleHash) {
		return nil, errors.New("invalid normalizer identity")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	n := &Normalizer{c: c, binaries: map[string]bool{}, protected: map[string]bool{}}
	for _, entry := range []struct {
		values []string
		dest   map[string]bool
	}{{c.AllowedBinaries, n.binaries}, {c.ProtectedPaths, n.protected}} {
		for _, p := range entry.values {
			if !safePath(p) {
				return nil, errors.New("allowlist paths must be absolute and clean")
			}
			entry.dest[p] = true
		}
	}
	return n, nil
}
func textValid(s string) bool {
	return s != "" && len(s) <= 16384 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}
func safePath(s string) bool { return textValid(s) && path.IsAbs(s) && path.Clean(s) == s }
func optional(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func stamp(s string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339Nano, s)
	if e != nil || t.IsZero() {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

// Prepare plugs directly into acquire.Config.Normalize. Filtering and metadata
// resolution complete before returning Build; Collector calls Build before WAL
// sequence reservation. No task arguments or environment are retained/digested.
func (n *Normalizer) Prepare(ctx context.Context, raw []byte) (acquire.Prepared, error) {
	if ctx.Err() != nil {
		return acquire.Prepared{}, ctx.Err()
	}
	if checkRaw(raw) != nil {
		return acquire.Prepared{}, ErrInvalid
	}
	// Reject multiple protobuf event alternatives, including unsupported ones.
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return acquire.Prepared{}, ErrInvalid
	}
	alternatives := 0
	for key, value := range envelope {
		if (strings.HasPrefix(key, "process_") || key == "test" || key == "rate_limit_info") && string(value) != "null" {
			alternatives++
		}
	}
	if alternatives != 1 {
		return acquire.Prepared{}, ErrUnsupported
	}
	var e rawEvent
	if json.Unmarshal(raw, &e) != nil || e.NodeName != n.c.NodeName {
		return acquire.Prepared{}, ErrInvalid
	}
	if len(e.Aggregation) > 0 && string(e.Aggregation) != "null" {
		return acquire.Prepared{}, ErrUnsupported
	}
	sourceTime, err := stamp(e.Time)
	if err != nil {
		return acquire.Prepared{}, err
	}
	count := 0
	for _, v := range []bool{e.Exec != nil, e.Exit != nil, e.Kprobe != nil} {
		if v {
			count++
		}
	}
	if count != 1 {
		return acquire.Prepared{}, ErrUnsupported
	}
	kind := ""
	safe := map[string]any{}
	var process *rawProcess
	var socket *Tuple
	var sockPtr string
	var newState *int32
	switch {
	case e.Exec != nil:
		kind, process = "process_exec", e.Exec.Process
		// Tetragon's startup procfs walk reports the kernel itself as pid 0
		// "<kernel>"; it is never a workload process.
		if process != nil && process.Binary == "<kernel>" && process.PID != nil && *process.PID == 0 {
			return acquire.Prepared{Excluded: true}, nil
		}
		if process == nil || !safePath(process.Binary) {
			return acquire.Prepared{}, ErrInvalid
		}
		if n.binaries[process.Binary] {
			safe["binary"] = process.Binary
		} else {
			safe["binary"] = canonical.SHA256Hex([]byte(process.Binary))
		}
		if process.UID != nil {
			safe["uid"] = *process.UID
		}
		if process.CWD != "" {
			safe["cwd_digest"] = canonical.SHA256Hex([]byte(process.CWD))
		}
		if process.InInitTree != nil {
			safe["in_init_tree"] = *process.InInitTree
		}
	case e.Exit != nil:
		kind, process = "process_exit", e.Exit.Process
		safe["exit_code"] = e.Exit.Status
		if e.Exit.Signal != "" {
			safe["signal"] = e.Exit.Signal
		}
	case e.Kprobe != nil:
		k := e.Kprobe
		process = k.Process
		switch k.Function {
		case "tcp_connect", "tcp_set_state":
			expected := "agentarium-tcp-connect"
			kind = "tcp_connect"
			argc := 1
			if k.Function == "tcp_set_state" {
				kind = "tcp_state"
				expected = "agentarium-tcp-state"
				argc = 2
				process = nil
			}
			if k.Policy != expected || len(k.Args) != argc || k.Args[0].Sock == nil {
				return acquire.Prepared{}, ErrInvalid
			}
			sk := k.Args[0].Sock
			if (sk.Family != "AF_INET" && sk.Family != "AF_INET6") || sk.Protocol != "IPPROTO_TCP" || sk.Type != "SOCK_STREAM" || sk.Cookie == nil || *sk.Cookie == 0 || sk.SPort > 65535 || sk.DPort > 65535 {
				return acquire.Prepared{}, ErrInvalid
			}
			// The cluster is IPv4-only, but dual-stack listeners (Go's default
			// for ":port") are AF_INET6 sockets carrying IPv4-mapped peers.
			// Those are IPv4 TCP and keep an IPv4 tuple; the dual-stack
			// wildcard "::" of an unconnected listener is 0.0.0.0, as an
			// AF_INET listener reports it. Native IPv6 stays invalid.
			addresses := [2]string{}
			for i, address := range []string{sk.SAddr, sk.DAddr} {
				a, err := netip.ParseAddr(address)
				if err == nil && sk.Family == "AF_INET6" && a == netip.IPv6Unspecified() {
					a = netip.IPv4Unspecified()
				} else if err != nil || (sk.Family == "AF_INET" && !a.Is4()) || (sk.Family == "AF_INET6" && !a.Is4In6()) {
					return acquire.Prepared{}, ErrInvalid
				}
				addresses[i] = a.Unmap().String()
			}
			socket = &Tuple{addresses[0], sk.SPort, addresses[1], sk.DPort}
			sockPtr = fmt.Sprintf("%016x", uint64(*sk.Cookie))
			safe["family"] = sk.Family
			if kind == "tcp_connect" {
				safe["protocol"] = sk.Protocol
			} else {
				if k.Args[1].Int == nil || (*k.Args[1].Int != 1 && *k.Args[1].Int != 7) {
					return acquire.Prepared{}, ErrInvalid
				}
				newState = k.Args[1].Int
			}
		case "security_file_open", "__x64_sys_openat":
			if k.Policy != "agentarium-protected-file" || k.Return == nil || k.Return.Int == nil {
				return acquire.Prepared{}, ErrInvalid
			}
			var filePath string
			if k.Function == "security_file_open" {
				kind = "file_open"
				if len(k.Args) != 1 || k.Args[0].File == nil {
					return acquire.Prepared{}, ErrInvalid
				}
				filePath = k.Args[0].File.Path
				safe["return_code"] = *k.Return.Int
			} else {
				kind = "openat"
				if len(k.Args) != 2 || k.Args[0].String == nil || k.Args[1].Int == nil {
					return acquire.Prepared{}, ErrInvalid
				}
				filePath = *k.Args[0].String
				safe["flags"] = *k.Args[1].Int
				// A positive fd is not an errno. Retain observed negative errno only.
				if *k.Return.Int < 0 {
					safe["return_errno"] = *k.Return.Int
				}
			}
			if !n.protected[filePath] {
				return acquire.Prepared{Excluded: true}, nil
			}
			safe["path"] = filePath
		default:
			return acquire.Prepared{}, ErrUnsupported
		}
	}
	q := Query{NodeUID: n.c.NodeUID, BootID: n.c.BootID, EventType: kind, SourceTime: sourceTime, Socket: socket, SockPtr: sockPtr}
	if kind != "tcp_state" {
		if process == nil || !textValid(process.ExecID) {
			return acquire.Prepared{}, ErrInvalid
		}
		if process.PID != nil && (*process.PID == 0 || *process.PID > 2147483647) {
			return acquire.Prepared{}, ErrInvalid
		}
		q.ProcessExecID = process.ExecID
		if process.Docker != "" {
			if !hexPrefix.MatchString(process.Docker) {
				return acquire.Prepared{}, ErrInvalid
			}
			q.DockerPrefix = process.Docker[:15]
		}
		if process.NS.Net != nil {
			v := process.NS.Net.Inum
			q.NetNS = &v
		}
	}
	if n.c.Resolver == nil {
		return acquire.Prepared{}, ErrMetadataUnavailable
	}
	// Do not expose mutable record-owned pointers to the resolver.
	query := q
	if q.Socket != nil {
		x := *q.Socket
		query.Socket = &x
	}
	if q.NetNS != nil {
		x := *q.NetNS
		query.NetNS = &x
	}
	resolution, err := n.c.Resolver.Resolve(ctx, query)
	if ctx.Err() != nil {
		return acquire.Prepared{}, ctx.Err()
	}
	if err != nil || resolution.Scope == Unknown {
		return acquire.Prepared{}, ErrMetadataUnavailable
	}
	if resolution.Scope == Exclude {
		return acquire.Prepared{Excluded: true}, nil
	}
	if resolution.Scope != Include || !validStatus(kind, resolution) {
		return acquire.Prepared{}, ErrMetadataUnavailable
	}
	for _, s := range []string{resolution.ContainerID, resolution.PodUID, resolution.LifecycleRecordID} {
		if s != "" && !textValid(s) {
			return acquire.Prepared{}, ErrMetadataUnavailable
		}
	}
	for _, id := range []string{resolution.PodUID, resolution.LifecycleRecordID} {
		if id != "" && !canonicalUUID.MatchString(id) {
			return acquire.Prepared{}, ErrMetadataUnavailable
		}
	}
	record := map[string]any{
		"sensor_id": n.c.SensorID, "exporter_instance_id": n.c.ExporterInstanceID, "sensor_generation": n.c.SensorGeneration, "node_uid": n.c.NodeUID, "boot_id": n.c.BootID, "source_time": sourceTime.UTC().Format(time.RFC3339Nano), "event_type": kind, "safe_attributes": safe, "rule_hash": n.c.RuleHash, "metadata_status": resolution.MetadataStatus, "normalization_version": n.c.NormalizationVersion,
		"process_exec_id": nil, "parent_exec_id": nil, "process_start": nil, "host_pid": nil, "container_id": nil, "docker_id_prefix": nil, "pod_uid": nil, "netns_inode": nil, "socket_tuple": socket, "sock_ptr": optional(sockPtr), "tcp_new_state": newState, "lifecycle_record_id": nil, "upstream_event_ref": nil,
	}
	if kind != "tcp_state" {
		record["process_exec_id"] = process.ExecID
		record["parent_exec_id"] = optional(process.ParentExecID)
		record["host_pid"] = process.PID
		record["docker_id_prefix"] = optional(q.DockerPrefix)
		record["netns_inode"] = q.NetNS
		if process.StartTime != "" {
			t, e := stamp(process.StartTime)
			if e != nil {
				return acquire.Prepared{}, e
			}
			record["process_start"] = t.UTC().Format(time.RFC3339Nano)
		}
		record["container_id"] = optional(resolution.ContainerID)
		record["pod_uid"] = optional(resolution.PodUID)
		record["lifecycle_record_id"] = optional(resolution.LifecycleRecordID)
	}
	record["coverage"] = coverage(kind, record)
	if kind == "process_exec" && n.c.ExecNamespace != nil && process.NS.PID != nil && process.NS.PID.Inum != 0 {
		n.c.ExecNamespace(process.ExecID, process.NS.PID.Inum)
	}
	// Validate the privacy-filtered template before returning a WAL callback.
	if _, err := canonical.CanonicalJSON(record); err != nil {
		return acquire.Prepared{}, ErrInvalid
	}
	return acquire.Prepared{Build: func(epoch string, sequence uint64) ([]byte, error) {
		if sequence > 9007199254740991 {
			return nil, ErrInvalid
		}
		id, err := canonical.KernelEventID(n.c.SensorID, epoch, int64(sequence))
		if err != nil {
			return nil, ErrInvalid
		}
		out := maps.Clone(record)
		out["source_epoch"] = epoch
		out["source_sequence"] = sequence
		out["source_event_id"] = id
		now := n.c.Now()
		if now.IsZero() {
			return nil, ErrInvalid
		}
		out["spooled_at"] = now.UTC().Format(time.RFC3339Nano)
		wire, err := canonical.CanonicalJSON(out)
		if err != nil {
			return nil, ErrInvalid
		}
		digest, err := canonical.DigestWithoutKeys(wire, "record_digest", "received_at")
		if err != nil {
			return nil, ErrInvalid
		}
		out["record_digest"] = digest
		wire, err = canonical.CanonicalJSON(out)
		if err != nil || canonical.CheckStrictJSON(wire) != nil {
			return nil, ErrInvalid
		}
		return wire, nil
	}}, nil
}
