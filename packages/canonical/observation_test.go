package canonical

import (
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"testing"
)

func TestObservationVectors(t *testing.T) {
	var v struct {
		Namespaces map[string]string `json:"namespaces"`
		IDs        []struct {
			Source    string `json:"source_id"`
			Epoch     string `json:"source_epoch"`
			Sequence  int64  `json:"source_sequence"`
			Kernel    string `json:"kernel_id"`
			Lifecycle string `json:"lifecycle_id"`
		} `json:"ids"`
		Netpol []struct {
			Cluster  string `json:"cluster_uid"`
			Node     string `json:"node_uid"`
			Epoch    string `json:"source_epoch"`
			Sequence int64  `json:"source_sequence"`
			ID       string `json:"record_id"`
		} `json:"network_policy_ids"`
		Ranges []struct {
			Input struct {
				Source string `json:"source_id"`
				Stream string `json:"stream"`
				Epoch  string `json:"source_epoch"`
				From   int64  `json:"from_seq"`
				To     int64  `json:"to_seq"`
				Reason string `json:"reason"`
			} `json:"input"`
			JCS    string `json:"jcs"`
			Digest string `json:"digest"`
		} `json:"ranges"`
	}
	raw, e := os.ReadFile("testdata/observation_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	for stream, expected := range v.Namespaces {
		got := uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/Beaver-Dam-Community/Agentarium/"+stream)).String()
		if got != expected {
			t.Fatal(stream, got)
		}
	}
	for _, row := range v.IDs {
		got, e := KernelEventID(row.Source, row.Epoch, row.Sequence)
		if e != nil || got != row.Kernel {
			t.Fatal(got, e)
		}
		got, e = LifecycleEventID(row.Source, row.Epoch, row.Sequence)
		if e != nil || got != row.Lifecycle || got == row.Kernel {
			t.Fatal(got, e)
		}
	}
	if len(v.Netpol) == 0 {
		t.Fatal("missing network policy vectors")
	}
	for _, row := range v.Netpol {
		got, e := NetworkPolicyRecordID(row.Cluster, row.Node, row.Epoch, row.Sequence)
		if e != nil || got != row.ID {
			t.Fatal(got, e)
		}
	}
	for _, row := range v.Ranges {
		r := row.Input
		got, e := AbandonedRangeDigest(r.Source, r.Stream, r.Epoch, r.From, r.To, r.Reason)
		if e != nil || got != row.Digest {
			t.Fatal(got, e)
		}
		b, e := CanonicalJSON(r)
		if e != nil || string(b) != row.JCS {
			t.Fatal(string(b), e)
		}
	}
}
func TestObservationIdentityAndRangeRejectAmbiguity(t *testing.T) {
	for _, f := range []func(string, string, int64) (string, error){KernelEventID, LifecycleEventID} {
		for _, r := range []struct {
			s, e string
			n    int64
		}{{"", "e", 1}, {"s", "", 1}, {"s", "a/b", 1}, {"s", "e", 0}, {"s", "e", -1}, {"s", "e", 9007199254740992}, {string([]byte{255}), "e", 1}} {
			if _, e := f(r.s, r.e, r.n); e == nil {
				t.Fatal("invalid identity accepted", r.n)
			}
		}
	}
	for _, r := range []struct {
		stream   string
		from, to int64
		reason   string
	}{{"business", 1, 2, "x"}, {"kernel", 2, 1, "x"}, {"kernel", 1, 2, ""}, {"lifecycle", 1, 9007199254740992, "x"}} {
		if _, e := AbandonedRangeDigest("s", r.stream, "epoch", r.from, r.to, r.reason); e == nil {
			t.Fatal("invalid range accepted")
		}
	}
	base, _ := AbandonedRangeDigest("s", "kernel", "e", 1, 2, "record_rejected")
	for _, args := range [][4]string{{"other", "kernel", "e", "record_rejected"}, {"s", "lifecycle", "e", "record_rejected"}, {"s", "kernel", "next", "record_rejected"}, {"s", "kernel", "e", "other"}} {
		got, e := AbandonedRangeDigest(args[0], args[1], args[2], 1, 2, args[3])
		if e != nil || got == base {
			t.Fatal("context omitted from digest", e)
		}
	}
}

func TestNetworkPolicyRecordIDRejectsNonCanonicalIdentity(t *testing.T) {
	c, n := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	for _, r := range [][3]string{{"", n, "e"}, {c, "", "e"}, {"11111111-1111-4111-8111-11111111111A", n, "e"}, {c, "00000000-0000-0000-0000-000000000000", "e"}, {c, n, "a/b"}, {c, n, ""}} {
		if _, e := NetworkPolicyRecordID(r[0], r[1], r[2], 1); e == nil {
			t.Fatal("invalid identity accepted", r)
		}
	}
	if _, e := NetworkPolicyRecordID(c, n, "e", 0); e == nil {
		t.Fatal("sequence 0 accepted")
	}
	a, _ := NetworkPolicyRecordID(c, n, "e", 1)
	b, _ := NetworkPolicyRecordID(n, c, "e", 1)
	k, _ := KernelEventID(c+"/"+n, "e", 1)
	if a == b || a == k {
		t.Fatal("network policy IDs must bind order and namespace")
	}
}
