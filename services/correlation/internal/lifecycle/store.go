package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/internal/lifecycle/lifecycledb"
)

type Store struct{ Pool *pgxpool.Pool }

// Append uses sqlc-generated SELECT/INSERT with a bounded transaction advisory
// lock. The lock serializes per-container revisions across boots. UNIQUE also
// rejects competing writers that do not follow this protocol. No row-lock UPDATE
// privilege is required. The caller supplies complete retained instance history.
func (s Store) Append(ctx context.Context, in Interval) (Interval, bool, error) {
	if err := validateInterval(in); err != nil {
		return Interval{}, false, err
	}
	if in.ID != uuid.Nil || in.Version != 0 {
		return Interval{}, false, errors.New("store allocates interval ID and version")
	}
	var out Interval
	created := false
	err := pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := lifecycledb.New(tx)
		if err := q.LimitLockWait(ctx); err != nil {
			return err
		}
		if err := q.LockContainer(ctx, in.Identity.Container); err != nil {
			return err
		}
		row, err := q.LatestInstance(ctx, lifecycledb.LatestInstanceParams{
			Container: in.Identity.Container, Cluster: in.Identity.Cluster.String(), Pod: in.Identity.Pod.String(),
			Node: in.Identity.Node.String(), Boot: in.Identity.Boot, Restart: pgInt4(in.Identity.Restart),
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			old, err := fromDB(row)
			if err != nil {
				return err
			}
			for _, id := range old.SourceEventIDs {
				if !slices.Contains(in.SourceEventIDs, id) {
					return errors.New("history would discard retained evidence")
				}
			}
			if equivalent(old, in) {
				out = old
				return nil
			}
			if old.StartedAt != nil && (in.StartedAt == nil || !old.StartedAt.Equal(*in.StartedAt)) ||
				old.EndedAt != nil && (in.EndedAt == nil || !old.EndedAt.Equal(*in.EndedAt)) ||
				old.Cgroup != nil && (in.Cgroup == nil || *old.Cgroup != *in.Cgroup) ||
				old.NetNS != nil && (in.NetNS == nil || *old.NetNS != *in.NetNS) {
				return ErrConflict
			}
		}
		next, err := q.NextMappingVersion(ctx, in.Identity.Container)
		if err != nil {
			return err
		}
		if next > 2147483647 {
			return errors.New("mapping version exhausted")
		}
		out = in
		out.ID = uuid.New()
		out.Version = int32(next)
		ids := make([]string, len(out.SourceEventIDs))
		for i, id := range out.SourceEventIDs {
			ids[i] = id.String()
		}
		err = q.InsertInterval(ctx, lifecycledb.InsertIntervalParams{
			ID: out.ID.String(), Cluster: out.Identity.Cluster.String(), Pod: out.Identity.Pod.String(), Node: out.Identity.Node.String(),
			Boot: out.Identity.Boot, Container: out.Identity.Container, Restart: pgInt4(out.Identity.Restart),
			Cgroup: pgInt8(out.Cgroup), Netns: pgInt8(out.NetNS), StartedAt: pgTime(out.StartedAt), EndedAt: pgTime(out.EndedAt),
			EndQuality: out.EndQuality, MappingVersion: out.Version, SourceIds: ids,
		})
		created = err == nil
		return err
	})
	if err != nil {
		return Interval{}, false, err
	}
	return out, created, nil
}

// Latest restores each historical instance, not only the current boot. Old
// revisions remain in the table. The adapter still supplies workload identity
// and matcher time-boundary policy; this store does not infer either.
func (s Store) Latest(ctx context.Context, cluster uuid.UUID, container string) ([]Interval, error) {
	rows, err := lifecycledb.New(s.Pool).LatestHistory(ctx, lifecycledb.LatestHistoryParams{Cluster: cluster.String(), Container: container})
	if err != nil {
		return nil, err
	}
	out := make([]Interval, 0, len(rows))
	for _, row := range rows {
		v, err := fromDB(lifecycledb.LatestInstanceRow(row))
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func fromDB(row lifecycledb.LatestInstanceRow) (Interval, error) {
	v := Interval{Identity: Identity{Boot: row.BootID, Container: row.ContainerID}, EndQuality: row.EndQuality, Version: row.MappingVersion}
	for i, dst := range []*uuid.UUID{&v.ID, &v.Identity.Cluster, &v.Identity.Pod, &v.Identity.Node} {
		id, err := uuid.Parse([]string{row.IntervalID, row.ClusterUid, row.PodUid, row.NodeUid}[i])
		if err != nil {
			return v, err
		}
		*dst = id
	}
	if row.RestartInstance.Valid {
		v.Identity.Restart = copyPtr(&row.RestartInstance.Int32)
	}
	if row.CgroupInode.Valid {
		v.Cgroup = copyPtr(&row.CgroupInode.Int64)
	}
	if row.NetnsInode.Valid {
		v.NetNS = copyPtr(&row.NetnsInode.Int64)
	}
	if row.StartedAt.Valid {
		v.StartedAt = copyPtr(&row.StartedAt.Time)
	}
	if row.EndedAt.Valid {
		v.EndedAt = copyPtr(&row.EndedAt.Time)
	}
	for _, text := range row.SourceEventIds {
		id, err := uuid.Parse(text)
		if err != nil {
			return v, err
		}
		v.SourceEventIDs = append(v.SourceEventIDs, id)
	}
	return v, nil
}
func pgInt4(v *int32) pgtype.Int4 {
	if v == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: *v, Valid: true}
}
func pgInt8(v *int64) pgtype.Int8 {
	if v == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *v, Valid: true}
}
func pgTime(v *time.Time) pgtype.Timestamptz {
	if v == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *v, Valid: true}
}

func equivalent(a, b Interval) bool {
	a.ID = uuid.Nil
	a.Version = 0
	b.ID = uuid.Nil
	b.Version = 0
	if a.StartedAt != nil {
		t := a.StartedAt.UTC()
		a.StartedAt = &t
	}
	if a.EndedAt != nil {
		t := a.EndedAt.UTC()
		a.EndedAt = &t
	}
	if b.StartedAt != nil {
		t := b.StartedAt.UTC()
		b.StartedAt = &t
	}
	if b.EndedAt != nil {
		t := b.EndedAt.UTC()
		b.EndedAt = &t
	}
	return reflect.DeepEqual(a, b)
}
