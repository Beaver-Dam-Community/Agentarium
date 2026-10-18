package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/credential-broker/internal/broker"
	"google.golang.org/api/option"
	sm "google.golang.org/api/secretmanager/v1"
)

func TestFixedVersionAndCRC(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-version", "corrupt", "provider-error", "latest"} {
		t.Run(mode, func(t *testing.T) {
			name := "projects/123/secrets/synthetic/versions/7"
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/v1/"+name+":access" {
					t.Error("unfixed resource path")
					w.WriteHeader(400)
					return
				}
				if mode == "provider-error" {
					w.WriteHeader(403)
					_, _ = w.Write([]byte("synthetic-secret-provider-detail"))
					return
				}
				data := []byte("synthetic-secret")
				reply := sm.AccessSecretVersionResponse{Name: name, Payload: &sm.SecretPayload{Data: base64.StdEncoding.EncodeToString(data), DataCrc32c: int64(crc32.Checksum(data, crcTable))}}
				if mode == "wrong-version" {
					reply.Name += "8"
				}
				if mode == "corrupt" {
					reply.Payload.DataCrc32c++
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			service, e := sm.NewService(context.Background(), option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()))
			if e != nil {
				t.Fatal(e)
			}
			request := name
			if mode == "latest" {
				request = "projects/123/secrets/synthetic/versions/latest"
			}
			data, e := (Google{service}).Access(context.Background(), request)
			if mode == "valid" {
				if e != nil || string(data) != "synthetic-secret" {
					t.Fatal(e)
				}
			} else if e != broker.ErrUnavailable || len(data) != 0 {
				t.Fatal("unsafe provider result")
			}
			if mode == "latest" && calls != 0 {
				t.Fatal("alias sent to provider")
			}
		})
	}
}
