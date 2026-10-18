package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPermissionMatrix(t *testing.T) {
	for _, mode := range []string{"snapshot", "reader", "denied"} {
		for _, fault := range []string{"", "overprivileged", "precondition", "retention", "network-error", "wrong-object"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				object := payload
				requests := 0
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests++
					if r.URL.Path == "/token" {
						if r.Header.Get("Metadata-Flavor") != "Google" || r.Header.Get("Authorization") != "" {
							t.Error("metadata credential boundary")
						}
						fmt.Fprint(w, `{"access_token":"fixture-secret","token_type":"Bearer"}`)
						return
					}
					if r.Header.Get("Authorization") != "Bearer fixture-secret" {
						t.Error("missing Pod token")
					}
					permission, allowed := "", false
					switch r.Method {
					case "POST":
						permission = "storage.objects.create"
						if r.URL.Query().Get("ifGenerationMatch") == "0" {
							allowed = mode == "snapshot"
						} else {
							permission = "storage.objects.delete"
							if fault == "precondition" {
								w.WriteHeader(412)
								return
							}
							if fault == "retention" {
								w.WriteHeader(403)
								fmt.Fprint(w, `{"error":{"message":"retention","errors":[{"reason":"retentionPolicyNotMet"}]}}`)
								return
							}
							if fault == "network-error" {
								w.WriteHeader(503)
								return
							}
							if fault == "overprivileged" {
								allowed = true
								object = "changed"
							}
						}
					case "GET":
						permission = "storage.objects.get"
						if r.URL.Query().Has("prefix") {
							permission = "storage.objects.list"
						}
						allowed = mode != "denied"
					case "DELETE":
						permission = "storage.objects.delete"
					}
					if !allowed {
						w.WriteHeader(403)
						if r.URL.Query().Get("alt") == "media" {
							fmt.Fprint(w, "Caller does not have storage.objects.get access to the Google Cloud Storage object. Permission &#39;storage.objects.get&#39; denied on resource &#39;fixture&#39; (or it may not exist).")
							return
						}
						fmt.Fprintf(w, `{"error":{"message":%q,"errors":[{"reason":"forbidden"}]}}`, permission+" denied")
						return
					}
					if r.URL.Query().Has("prefix") {
						name := "snapshots/iam-check/test-run-123/fixture.txt"
						if fault == "wrong-object" {
							name = "unrelated"
						}
						fmt.Fprintf(w, `{"items":[{"name":%q}]}`, name)
					} else if r.Method == "GET" {
						fmt.Fprint(w, object)
					} else {
						fmt.Fprint(w, `{}`)
					}
				}))
				defer s.Close()
				p := probe{cfg: config{"example-bucket", "test-run-123", mode}, client: s.Client(), api: s.URL + "/storage/v1", upload: s.URL + "/upload/storage/v1", metadata: s.URL + "/token"}
				results, err := p.run(context.Background())
				wantPass := fault == "" || (fault == "wrong-object" && mode == "denied")
				if (err == nil) != wantPass {
					t.Fatalf("err=%v, wantPass=%v, results=%+v", err, wantPass, results)
				}
				if p.token != "" {
					t.Error("retained token")
				}
				out, _ := json.Marshal(results)
				if strings.Contains(string(out), "fixture-secret") {
					t.Error("token leaked")
				}
				if requests < 6 {
					t.Errorf("incomplete matrix: %d", requests)
				}
			})
		}
	}
}

func TestRejectNonIAMFailures(t *testing.T) {
	for _, status := range []int{0, 200, 401, 404, 412, 429, 500, 503} {
		if permissionDenied(status, []byte(`{"error":{"message":"storage.objects.delete denied","errors":[{"reason":"forbidden"}]}}`), "storage.objects.delete") {
			t.Fatalf("accepted status %d", status)
		}
	}
	if permissionDenied(403, []byte(`{"error":{"message":"serviceusage.services.use denied","errors":[{"reason":"forbidden"}]}}`), "storage.objects.delete") {
		t.Fatal("accepted unrelated IAM denial")
	}
	for _, body := range []string{"403 Forbidden", "storage.objects.get", "<html>access denied</html>", "Caller does not have storage.objects.get access to the Google Cloud Storage object."} {
		if permissionDenied(403, []byte(body), "storage.objects.get") {
			t.Fatalf("accepted generic error %q", body)
		}
	}
}

func TestConfiguration(t *testing.T) {
	t.Setenv("IAM_BUCKET", "example-bucket")
	t.Setenv("IAM_RUN_ID", "test-run-123")
	t.Setenv("IAM_MODE", "snapshot")
	if _, err := readConfig(); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"IAM_BUCKET", "IAM_RUN_ID", "IAM_MODE"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "../../production")
			if _, err := readConfig(); err == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}

func TestCancelledTransportIsNotDenial(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			fmt.Fprint(w, `{"access_token":"fixture-secret","token_type":"Bearer"}`)
			return
		}
		<-r.Context().Done()
	}))
	defer s.Close()
	p := probe{cfg: config{"example-bucket", "test-run-123", "denied"}, client: s.Client(), api: s.URL, upload: s.URL, metadata: s.URL + "/token"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := p.run(ctx)
	if err == nil {
		t.Fatal("cancelled transport passed")
	}
}
