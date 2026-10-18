package lifecycle

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fixture() History {
	k := Identity{Cluster: uuid.MustParse("00000000-0000-4000-8000-000000000001"), Pod: uuid.MustParse("00000000-0000-4000-8000-000000000002"), Node: uuid.MustParse("00000000-0000-4000-8000-000000000003"), Boot: "boot-a", Container: "container-full-001", Restart: ptr(int32(0))}
	t := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	return History{Identity: k, RuntimeContinuous: true, Events: []Event{
		{ID: uuid.MustParse("00000000-0000-4000-8000-000000000010"), Identity: k, Source: Runtime, Transition: RuntimeCreate, SourceTime: ptr(t.Add(-time.Second)), Cgroup: ptr(int64(42))},
		{ID: uuid.MustParse("00000000-0000-4000-8000-000000000011"), Identity: k, Source: Runtime, Transition: RuntimeStart, SourceTime: ptr(t)},
	}}
}
func ptr[T any](x T) *T { return &x }
func add(h *History, source Source, tr Transition, at *time.Time) {
	h.Events = append(h.Events, Event{ID: uuid.New(), Identity: h.Identity, Source: source, Transition: tr, SourceTime: at})
}
func TestDerive(t *testing.T) {
	for _, tt := range []struct {
		name       string
		alter      func(*History)
		quality    string
		start, end bool
		bad        bool
	}{
		{"start is open", func(*History) {}, "open", true, false, false},
		{"coverage unknown", func(h *History) { h.RuntimeContinuous = false }, "unknown", true, false, false},
		{"create is not start", func(h *History) { h.Events = h.Events[:1] }, "unknown", false, false, false},
		{"runtime delete is not exit", func(h *History) { add(h, Runtime, Deleted, ptr(h.Events[1].SourceTime.Add(time.Second))) }, "unknown", true, false, false},
		{"watch deletion is not exit", func(h *History) { add(h, Watcher, Deleted, ptr(h.Events[1].SourceTime.Add(time.Second))) }, "unknown", true, false, false},
		{"runtime gap", func(h *History) { add(h, Runtime, CaptureGap, nil) }, "unknown", true, false, false},
		{"watch gap runtime intact", func(h *History) { add(h, Watcher, CaptureGap, nil) }, "open", true, false, false},
		{"exit timestamp missing", func(h *History) { add(h, Runtime, RuntimeExit, nil) }, "unknown", true, false, false},
		{"observed exit despite gap", func(h *History) {
			add(h, Runtime, CaptureGap, nil)
			add(h, Runtime, RuntimeExit, ptr(h.Events[1].SourceTime.Add(time.Second)))
		}, "observed", true, true, false},
		{"exit without start", func(h *History) {
			h.Events = h.Events[:1]
			add(h, Runtime, RuntimeExit, ptr(h.Events[0].SourceTime.Add(time.Second)))
		}, "observed", false, true, false},
		{"duplicate source event", func(h *History) { h.Events = append(h.Events, h.Events[1]) }, "open", true, false, false},
		{"duplicate ID different fact", func(h *History) { e := h.Events[1]; e.Transition = RuntimeExit; h.Events = append(h.Events, e) }, "", false, false, true},
		{"start conflict", func(h *History) { add(h, Runtime, RuntimeStart, ptr(h.Events[1].SourceTime.Add(time.Second))) }, "", false, false, true},
		{"exit precedes start", func(h *History) { add(h, Runtime, RuntimeExit, ptr(h.Events[1].SourceTime.Add(-time.Second))) }, "", false, false, true},
		{"watcher cannot claim exit", func(h *History) { add(h, Watcher, RuntimeExit, ptr(h.Events[1].SourceTime.Add(time.Second))) }, "", false, false, true},
		{"other boot", func(h *History) { h.Events[1].Identity.Boot = "old-boot" }, "", false, false, true},
		{"reused container other pod", func(h *History) { h.Events[1].Identity.Pod = uuid.New() }, "", false, false, true},
		{"restart isolation", func(h *History) { h.Events[1].Identity.Restart = ptr(int32(1)) }, "", false, false, true},
		{"prefix not full container", func(h *History) { h.Events[1].Identity.Container = "container" }, "", false, false, true},
		{"metadata unresolved", func(h *History) { h.Identity.Node = uuid.Nil }, "", false, false, true},
		{"nanosecond boundary not rounded", func(h *History) { h.Events[1].SourceTime = ptr(h.Events[1].SourceTime.Add(time.Nanosecond)) }, "", false, false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := fixture()
			tt.alter(&h)
			got, err := Derive(h)
			if tt.bad {
				if err == nil {
					t.Fatal("accepted invalid evidence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.EndQuality != tt.quality || (got.StartedAt != nil) != tt.start || (got.EndedAt != nil) != tt.end {
				t.Fatalf("unexpected interval: %+v", got)
			}
			if tt.name == "duplicate source event" && len(got.SourceEventIDs) != 2 {
				t.Fatal("duplicate not coalesced")
			}
		})
	}
}

func TestOrderLateArrivalAndNoMutation(t *testing.T) {
	h := fixture()
	before, err := Derive(h)
	if err != nil {
		t.Fatal(err)
	}
	add(&h, Watcher, Deleted, ptr(h.Events[1].SourceTime.Add(10*time.Second)))
	unknown, _ := Derive(h)
	add(&h, Runtime, RuntimeExit, ptr(h.Events[1].SourceTime.Add(time.Second)))
	got, err := Derive(h)
	if err != nil {
		t.Fatal(err)
	}
	if before.EndQuality != "open" || unknown.EndQuality != "unknown" || got.EndQuality != "observed" || got.EndedAt.Equal(*h.Events[2].SourceTime) {
		t.Fatal("late exit overwrote history or used watcher time")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other, err := Derive(h)
			if err != nil || !reflect.DeepEqual(got, other) {
				t.Error("non-deterministic concurrent derivation")
			}
		}()
	}
	wg.Wait()
	for i, j := 0, len(h.Events)-1; i < j; i, j = i+1, j-1 {
		h.Events[i], h.Events[j] = h.Events[j], h.Events[i]
	}
	reverse, err := Derive(h)
	if err != nil || !reflect.DeepEqual(got, reverse) {
		t.Fatal("source arrival order changed interval")
	}
	*got.Cgroup = 999
	*got.Identity.Restart = 99
	*got.StartedAt = time.Time{}
	unchanged, err := Derive(h)
	if err != nil || !reflect.DeepEqual(reverse, unchanged) {
		t.Fatal("result aliases input")
	}
}

func TestConflictingCgroup(t *testing.T) {
	h := fixture()
	h.Events[1].Cgroup = ptr(int64(99))
	_, err := Derive(h)
	if !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
}
