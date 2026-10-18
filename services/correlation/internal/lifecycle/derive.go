// Package lifecycle derives immutable history from verified lifecycle facts.
// The types below are internal adapter inputs, not a lifecycle wire protocol.
package lifecycle

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
)

type Identity struct {
	Cluster, Pod, Node uuid.UUID
	Boot, Container    string
	Restart            *int32
}

type Source uint8

const (
	Runtime Source = iota + 1
	Watcher
)

// Transition is classified by a verified source adapter. In particular, Pod
// deletion is not RuntimeExit. No string-to-transition mapping is assumed here.
type Transition uint8

const (
	Metadata Transition = iota + 1
	RuntimeCreate
	RuntimeStart
	RuntimeExit
	Deleted
	CaptureGap
)

type Event struct {
	ID         uuid.UUID
	Identity   Identity
	Source     Source
	Transition Transition
	SourceTime *time.Time
	Cgroup     *int64
}

type History struct {
	Identity Identity
	Events   []Event
	// RuntimeContinuous is an upstream coverage assertion, not inferred from
	// the absence of a gap record. False cannot produce an open interval.
	RuntimeContinuous bool
}

type Interval struct {
	ID                 uuid.UUID
	Identity           Identity
	Cgroup, NetNS      *int64
	StartedAt, EndedAt *time.Time
	EndQuality         string
	Version            int32
	SourceEventIDs     []uuid.UUID
}

var ErrConflict = errors.New("conflicting lifecycle evidence")

func validIdentity(k Identity) bool {
	return k.Cluster != uuid.Nil && k.Pod != uuid.Nil && k.Node != uuid.Nil &&
		k.Boot != "" && k.Container != "" && (k.Restart == nil || *k.Restart >= 0)
}

// Derive requires complete retained history for exactly one boot/container
// instance. Missing identity must remain unresolved upstream: the DDL cannot
// represent a row with no Pod/node/boot/full container identity.
func Derive(h History) (Interval, error) {
	if !validIdentity(h.Identity) || len(h.Events) == 0 {
		return Interval{}, errors.New("complete identity and evidence required")
	}
	o := Interval{Identity: h.Identity, EndQuality: "unknown"}
	seen := make(map[uuid.UUID]Event)
	gap, deleted, missingExitTime := false, false, false
	for _, e := range h.Events {
		if e.ID == uuid.Nil || !reflect.DeepEqual(e.Identity, h.Identity) ||
			(e.Source != Runtime && e.Source != Watcher) || e.Transition < Metadata || e.Transition > CaptureGap {
			return Interval{}, errors.New("invalid event identity or classification")
		}
		if old, exists := seen[e.ID]; exists {
			if !reflect.DeepEqual(old, e) {
				return Interval{}, ErrConflict
			}
			continue
		}
		seen[e.ID] = e
		o.SourceEventIDs = append(o.SourceEventIDs, e.ID)
		if e.Cgroup != nil {
			if *e.Cgroup <= 0 {
				return Interval{}, errors.New("invalid cgroup inode")
			}
			if o.Cgroup != nil && *o.Cgroup != *e.Cgroup {
				return Interval{}, ErrConflict
			}
			o.Cgroup = copyPtr(e.Cgroup)
		}
		if e.Source == Watcher && (e.Transition == RuntimeCreate || e.Transition == RuntimeStart || e.Transition == RuntimeExit) {
			return Interval{}, errors.New("watcher cannot attest runtime transition")
		}
		switch e.Transition {
		case RuntimeStart:
			if err := mergeTime(&o.StartedAt, e.SourceTime); err != nil {
				return Interval{}, err
			}
		case RuntimeExit:
			missingExitTime = missingExitTime || e.SourceTime == nil
			if err := mergeTime(&o.EndedAt, e.SourceTime); err != nil {
				return Interval{}, err
			}
		case Deleted:
			deleted = true
		case CaptureGap:
			if e.Source == Runtime {
				gap = true
			}
		}
	}
	if o.StartedAt != nil && o.EndedAt != nil && o.EndedAt.Before(*o.StartedAt) {
		return Interval{}, fmt.Errorf("%w: exit precedes start", ErrConflict)
	}
	if o.EndedAt != nil {
		o.EndQuality = "observed"
	} else if o.StartedAt != nil && h.RuntimeContinuous && !gap && !deleted && !missingExitTime {
		o.EndQuality = "open"
	}
	slices.SortFunc(o.SourceEventIDs, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	o.Identity.Restart = copyPtr(o.Identity.Restart)
	return o, nil
}

func mergeTime(dst **time.Time, src *time.Time) error {
	if src == nil {
		return nil
	}
	if src.IsZero() {
		return errors.New("zero source timestamp")
	}
	// PostgreSQL timestamptz preserves microseconds. Reject rather than silently
	// round a boundary used by the matcher.
	if src.Nanosecond()%1000 != 0 {
		return errors.New("source timestamp exceeds database precision")
	}
	if *dst != nil && !(*dst).Equal(*src) {
		return ErrConflict
	}
	t := src.UTC()
	*dst = &t
	return nil
}

func copyPtr[T any](v *T) *T {
	if v == nil {
		return nil
	}
	x := *v
	return &x
}

func validateInterval(o Interval) error {
	if !validIdentity(o.Identity) || len(o.SourceEventIDs) == 0 {
		return errors.New("incomplete interval")
	}
	if o.EndQuality != "observed" && o.EndQuality != "unknown" && o.EndQuality != "open" {
		return errors.New("unsupported derived end quality")
	}
	if (o.EndQuality == "observed") != (o.EndedAt != nil) ||
		(o.EndQuality == "open" && o.StartedAt == nil) {
		return errors.New("inconsistent interval bounds")
	}
	var t *time.Time
	for _, v := range []*time.Time{o.StartedAt, o.EndedAt} {
		if err := mergeTime(&t, v); err != nil {
			return err
		}
		t = nil
	}
	if o.StartedAt != nil && o.EndedAt != nil && o.EndedAt.Before(*o.StartedAt) {
		return ErrConflict
	}
	for _, v := range []*int64{o.Cgroup, o.NetNS} {
		if v != nil && *v <= 0 {
			return errors.New("invalid inode")
		}
	}
	for n, id := range o.SourceEventIDs {
		if id == uuid.Nil || (n > 0 && slices.Compare(o.SourceEventIDs[n-1][:], id[:]) >= 0) {
			return errors.New("source IDs must be unique and sorted")
		}
	}
	return nil
}
