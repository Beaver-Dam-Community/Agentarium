package health

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func TestEvaluation(t *testing.T) {
	now := time.Now()
	unsupported := StartupUnsupported
	guarded := StartupGuarded
	for _, tt := range []struct {
		name    string
		capture *string
		missing []string
	}{
		{"unsupported", &unsupported, []string{"node-sensors", "lifecycle-recorder"}},
		{"guarded", &guarded, []string{"node-sensors", "lifecycle-recorder", "runtime-guard"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := Snapshot{Scope: "node", EvaluatedAt: now, StartupCapture: tt.capture}
			Evaluate(&s, false)
			if !slices.Equal(s.MissingComponents, tt.missing) || s.State != StateUnhealthy {
				t.Fatalf("%+v", s)
			}
			for _, c := range tt.missing {
				s.Leases = append(s.Leases, LeaseStatus{Lease: Lease{Component: c, ObservedState: StateHealthy, LeaseUntil: now.Add(time.Second)}})
			}
			s.Leases = append(s.Leases, LeaseStatus{Lease: Lease{Component: ComponentNetpol, ObservedState: StateUnhealthy, LeaseUntil: now.Add(-time.Second)}})
			Evaluate(&s, false)
			if s.State != StateHealthy {
				t.Fatalf("optional collector caused hold: %+v", s)
			}
			s.OpenHolds = []Hold{{Reason: "lease_expired"}}
			Evaluate(&s, false)
			if s.State != StateUnhealthy {
				t.Fatal("heartbeat cleared hold")
			}
		})
	}
	s := Snapshot{Scope: "global", EvaluatedAt: now}
	Evaluate(&s, false)
	if slices.Contains(s.MissingComponents, ComponentStartCoord) {
		t.Fatal("guard dependency on unsupported profile")
	}
	Evaluate(&s, true)
	if !slices.Contains(s.MissingComponents, ComponentStartCoord) {
		t.Fatal("missing guard dependency")
	}
}
func TestLeaseValidation(t *testing.T) {
	now := time.Now().UTC()
	l := Lease{SourceID: "gateway-1", Component: "gateway", Scope: "global", ScopeID: "*", LeaseUntil: now.Add(LeaseTTL), ObservedState: StateHealthy, ReportedAt: now}
	raw, _ := json.Marshal(l)
	got, err := DecodeLease(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Expiry(got, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Lease){func(l *Lease) { l.ReportedAt = now.Add(3 * time.Second) }, func(l *Lease) { l.LeaseUntil = now.Add(time.Hour) }, func(l *Lease) { l.ReportedAt = now.Add(-time.Minute) }, func(l *Lease) { l.LeaseUntil = now }} {
		bad := l
		mutate(&bad)
		if _, err := Expiry(bad, now); err == nil {
			t.Fatal("invalid freshness accepted")
		}
	}
	for _, raw := range []string{`null`, `{"source_id":"a","source_id":"b"}`, `{"Component":"gateway"}`, `{"source_id":9007199254740992}`, `{"x":1.0}`} {
		if _, err := DecodeLease([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	l.Scope = "node"
	l.ScopeID = "not-uuid"
	raw, _ = json.Marshal(l)
	if _, err := DecodeLease(raw); err == nil {
		t.Fatal("bad scope accepted")
	}
}

func TestExpiredReplicaDoesNotPoisonScope(t *testing.T) {
	now := time.Now()
	for _, state := range []string{StateUnhealthy, StateDegraded} {
		s := Snapshot{Scope: "global", EvaluatedAt: now}
		for _, component := range RequiredGlobal {
			s.Leases = append(s.Leases, LeaseStatus{Lease: Lease{Component: component, ObservedState: StateHealthy, LeaseUntil: now.Add(time.Second)}})
		}
		s.Leases = append(s.Leases, LeaseStatus{Lease: Lease{Component: "gateway", ObservedState: state, LeaseUntil: now}})
		Evaluate(&s, false)
		if s.State != StateHealthy {
			t.Fatalf("expired %s replica poisoned scope: %+v", state, s)
		}
		s.Leases[len(s.Leases)-1].LeaseUntil = now.Add(time.Second)
		Evaluate(&s, false)
		if s.State != state {
			t.Fatalf("live %s replica ignored: %+v", state, s)
		}
	}
}
