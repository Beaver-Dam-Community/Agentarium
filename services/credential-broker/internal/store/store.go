package store

import (
	"context"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/broker"
	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/store/brokerdb"
	"github.com/jackc/pgx/v5/pgtype"
)

type Store struct{ Queries *brokerdb.Queries }

func (s Store) Resolve(ctx context.Context, ns, ksa string, r broker.Request) (broker.Binding, error) {
	if s.Queries == nil {
		return broker.Binding{}, broker.ErrUnavailable
	}
	var id pgtype.UUID
	if id.Scan(r.AttemptID) != nil {
		return broker.Binding{}, broker.ErrUnavailable
	}
	b, e := s.Queries.ResolveBinding(ctx, brokerdb.ResolveBindingParams{AttemptID: id, Namespace: ns, Ksa: ksa, Binding: r.Binding, AdapterID: r.AdapterID})
	if e != nil {
		return broker.Binding{}, broker.ErrUnavailable
	}
	return broker.Binding{Resource: b.SecretResource, Version: b.SecretVersion, HeaderName: b.HeaderName, Format: b.HeaderFormat}, nil
}
