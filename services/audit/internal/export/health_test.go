package export

import (
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
)

func TestBacklogThresholds(t *testing.T) {
	node := "10000000-0000-4000-8000-000000000001"
	for _, tc := range []struct {
		class             string
		degraded, holdAge float64
		limit             int64
	}{
		{"business", 10, 120, 10000}, {"kernel", 30, 300, 200000}, {"lifecycle", 10, 120, 50000}, {"decision_input", 60, 0, 0},
	} {
		t.Run(tc.class, func(t *testing.T) {
			row := auditdb.ExportBacklogsRow{SourceClass: tc.class, NodeUid: node, PendingRecords: 1, PendingBytes: 1, OldestAgeSeconds: tc.degraded}
			state, holds, err := backlogState([]auditdb.ExportBacklogsRow{row})
			if err != nil || state != "healthy" || len(holds) != 0 {
				t.Fatalf("exact degraded boundary: %s %v %v", state, holds, err)
			}
			row.OldestAgeSeconds += 0.1
			state, holds, err = backlogState([]auditdb.ExportBacklogsRow{row})
			if err != nil || state != "degraded" || len(holds) != 0 {
				t.Fatalf("degraded: %s %v %v", state, holds, err)
			}
			if tc.holdAge == 0 {
				row.OldestAgeSeconds = 100000
				row.PendingRecords = 10000000
				row.PendingBytes = 1 << 40
				_, holds, err = backlogState([]auditdb.ExportBacklogsRow{row})
				if err != nil || len(holds) != 0 {
					t.Fatal("decision input export created a hold")
				}
				return
			}
			row.OldestAgeSeconds = tc.holdAge
			_, holds, err = backlogState([]auditdb.ExportBacklogsRow{row})
			if err != nil || len(holds) != 0 {
				t.Fatal("exact hold boundary")
			}
			row.OldestAgeSeconds += 0.1
			_, holds, err = backlogState([]auditdb.ExportBacklogsRow{row})
			if err != nil || len(holds) != 1 {
				t.Fatal("age threshold ignored")
			}
			want := holdScope{"node", node}
			if tc.class == "business" {
				want = holdScope{"global", "*"}
			}
			if holds[0] != want {
				t.Fatalf("hold scope: %v", holds)
			}
			row.OldestAgeSeconds = 0
			row.PendingRecords = tc.limit
			_, holds, _ = backlogState([]auditdb.ExportBacklogsRow{row})
			if len(holds) != 0 {
				t.Fatal("exact count boundary")
			}
			row.PendingRecords++
			state, holds, err = backlogState([]auditdb.ExportBacklogsRow{row})
			if err != nil || state != "degraded" || len(holds) != 1 {
				t.Fatal("fresh but excessive backlog ignored")
			}
		})
	}
	row := auditdb.ExportBacklogsRow{SourceClass: "kernel", NodeUid: node, PendingRecords: 1, PendingBytes: 512 * 1024 * 1024}
	_, holds, _ := backlogState([]auditdb.ExportBacklogsRow{row})
	if len(holds) != 0 {
		t.Fatal("exact byte boundary")
	}
	row.PendingBytes++
	_, holds, err := backlogState([]auditdb.ExportBacklogsRow{row})
	if err != nil || len(holds) != 1 {
		t.Fatal("kernel byte limit ignored")
	}
	second := row
	second.SourceClass = "lifecycle"
	second.OldestAgeSeconds = 121
	_, holds, err = backlogState([]auditdb.ExportBacklogsRow{row, second})
	if err != nil || len(holds) != 1 {
		t.Fatal("duplicate node hold")
	}
	row.NodeUid = ""
	state, _, err := backlogState([]auditdb.ExportBacklogsRow{row})
	if err == nil || state != "unhealthy" {
		t.Fatal("missing node was guessed")
	}
}
