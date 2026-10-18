package execute

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// sessionRefs is the RefStore a Resolver sees: rows of the envelope's own
// session only (TASK-05 3.1: a referenced row of another session, or a
// missing one, is PREFLIGHT_MISMATCH). A row of another session is never
// handed out, and the violation is remembered so the engine rejects the
// preflight even if the Resolver ignored the error.
type sessionRefs struct {
	inner    RefStore
	want     RefSession
	violated atomic.Bool
}

func (s *sessionRefs) own(got RefSession) error {
	if got != s.want {
		s.violated.Store(true)
		return ErrRefNotOwned
	}
	return nil
}

func (s *sessionRefs) ActionResult(ctx context.Context, actionID string) (RefResult, error) {
	r, err := s.inner.ActionResult(ctx, actionID)
	if err != nil {
		return RefResult{}, err
	}
	if err := s.own(r.Session); err != nil {
		return RefResult{}, fmt.Errorf("action_results %s: %w", actionID, err)
	}
	if r.Result.ActionID != actionID {
		return RefResult{}, fmt.Errorf("action_results %s: store returned action %s: %w", actionID, r.Result.ActionID, ErrNotFound)
	}
	return r, nil
}

func (s *sessionRefs) ModelTurn(ctx context.Context, conversationID string, turnIndex int64) (RefModelTurn, error) {
	t, err := s.inner.ModelTurn(ctx, conversationID, turnIndex)
	if err != nil {
		return RefModelTurn{}, err
	}
	if err := s.own(t.Session); err != nil {
		return RefModelTurn{}, fmt.Errorf("model_turns (%s, %d): %w", conversationID, turnIndex, err)
	}
	if t.ConversationID != conversationID || t.TurnIndex != turnIndex {
		return RefModelTurn{}, fmt.Errorf("model_turns (%s, %d): store returned another turn: %w", conversationID, turnIndex, ErrNotFound)
	}
	return t, nil
}

// resolve runs the adapter's Resolver with the session-bound RefStore.
func (e *Engine) resolve(ctx context.Context, r Resolver, in Inputs, b *Bundle) (any, *Rejection, error) {
	refs := &sessionRefs{inner: e.cfg.Refs, want: RefSession{Kind: in.Envelope.SessionKind, ID: in.Envelope.SessionID}}
	resolved, rej, err := r.ResolveRefs(ctx, in, b, refs)
	switch {
	case refs.violated.Load() || errors.Is(err, ErrRefNotOwned):
		return nil, &Rejection{ReasonCodes: []string{ReasonPreflightMismatch}, ComparedFields: []string{"references"}, Detail: "referenced row belongs to another session"}, nil
	case rej != nil:
		return nil, rej, nil
	case errors.Is(err, ErrNotFound):
		return nil, &Rejection{ReasonCodes: []string{ReasonPreflightMismatch}, ComparedFields: []string{"references"}, Detail: err.Error()}, nil
	case err != nil:
		return nil, nil, err
	}
	return resolved, nil, nil
}
