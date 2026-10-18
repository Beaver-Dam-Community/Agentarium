package sessions

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestReplyDatabaseFailure(t *testing.T) {
	for _, state := range []string{"42501", "22023", "40001", "P0001"} {
		t.Run(state, func(t *testing.T) {
			w := httptest.NewRecorder()
			reply(w, nil, fmt.Errorf("operation: %w", &pgconn.PgError{Code: state, Message: "private-database-detail", Detail: "private-tenant"}))
			var body errorBody
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if w.Code != 503 || w.Header().Get("Retry-After") != "2" || len(body.ReasonCodes) != 1 || body.ReasonCodes[0] != "STATE_STORE_UNAVAILABLE" || body.RequestID == "" {
				t.Fatalf("response: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "private-") || strings.Contains(w.Body.String(), state) {
				t.Fatal("SQL detail exposed")
			}
		})
	}
	w := httptest.NewRecorder()
	reply(w, nil, fail(http.StatusServiceUnavailable, "LOCK_TIMEOUT", "private-lock-detail"))
	if w.Code != 503 || w.Header().Get("Retry-After") != "2" || !strings.Contains(w.Body.String(), "LOCK_TIMEOUT") {
		t.Fatalf("typed failure changed: %s", w.Body.String())
	}
}
