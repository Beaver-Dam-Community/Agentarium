package approvals

import (
	"net/http"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// Handler routes the approval APIs. All of them are console routes: without
// a ConsoleAuth every request is 401.
type Handler struct {
	Svc     *Service
	Console sessions.ConsoleAuth
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/approvals/pending", h.pending)
	mux.HandleFunc("GET /v1/actions/{action_id}/approval-contract", h.contract)
	mux.HandleFunc("POST /v1/approvals", h.approve)
	mux.HandleFunc("POST /v1/approvals/{approval_id}/revoke", h.revoke)
}

func (h *Handler) pending(w http.ResponseWriter, r *http.Request) {
	actor, ok := sessions.ConsoleActor(h.Console, w, r)
	if !ok {
		return
	}
	out, err := h.Svc.PendingFor(r.Context(), actor, r.URL.Query().Get("session_id"))
	sessions.Reply(w, map[string]any{"actions": out}, err)
}

func (h *Handler) contract(w http.ResponseWriter, r *http.Request) {
	actor, ok := sessions.ConsoleActor(h.Console, w, r)
	if !ok {
		return
	}
	out, err := h.Svc.Contract(r.Context(), actor, r.PathValue("action_id"))
	sessions.Reply(w, out, err)
}

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	actor, ok := sessions.ConsoleActor(h.Console, w, r)
	if !ok {
		return
	}
	var req ApproveRequest
	if !sessions.Decode(w, r, &req) {
		return
	}
	out, err := h.Svc.Approve(r.Context(), actor, req)
	sessions.Reply(w, out, err)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	actor, ok := sessions.ConsoleActor(h.Console, w, r)
	if !ok {
		return
	}
	out, err := h.Svc.Revoke(r.Context(), actor, r.PathValue("approval_id"))
	sessions.Reply(w, out, err)
}
