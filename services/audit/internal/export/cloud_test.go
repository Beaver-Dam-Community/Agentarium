package export

import (
	"bytes"
	"cloud.google.com/go/storage"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	kms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

func TestKMSSigningRequestAndResponseIntegrity(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-key", "crc", "unverified", "signature"} {
		t.Run(mode, func(t *testing.T) {
			key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			name := "projects/test/locations/global/keyRings/test/cryptoKeys/audit/cryptoKeyVersions/1"
			digest := sha256.Sum256([]byte("manifest"))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/v1/"+name+":asymmetricSign" {
					t.Errorf("unexpected route %s", r.URL.Path)
					w.WriteHeader(400)
					return
				}
				var req kms.AsymmetricSignRequest
				if e := json.NewDecoder(r.Body).Decode(&req); e != nil {
					t.Error(e)
					w.WriteHeader(400)
					return
				}
				if req.Digest == nil || req.Digest.Sha256 != base64.StdEncoding.EncodeToString(digest[:]) || req.DigestCrc32c != int64(crc32.Checksum(digest[:], crcTable)) {
					t.Error("wrong digest request")
					w.WriteHeader(400)
					return
				}
				sig, e := ecdsa.SignASN1(rand.Reader, key, digest[:])
				if e != nil {
					t.Error(e)
					w.WriteHeader(500)
					return
				}
				if mode == "signature" {
					sig = []byte{1, 2, 3}
				}
				resp := kms.AsymmetricSignResponse{Name: name, Signature: base64.StdEncoding.EncodeToString(sig), SignatureCrc32c: int64(crc32.Checksum(sig, crcTable)), VerifiedDigestCrc32c: true}
				if mode == "wrong-key" {
					resp.Name += "2"
				}
				if mode == "crc" {
					resp.SignatureCrc32c++
				}
				if mode == "unverified" {
					resp.VerifiedDigestCrc32c = false
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer server.Close()
			service, e := kms.NewService(context.Background(), option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()))
			if e != nil {
				t.Fatal(e)
			}
			_, e = (KMS{service, name, &key.PublicKey}).Sign(context.Background(), digest[:])
			if (mode == "valid") != (e == nil) {
				t.Fatalf("mode=%s error=%v", mode, e)
			}
		})
	}
}

func TestGCSCreatePreconditionAndPinnedRead(t *testing.T) {
	for _, mode := range []string{"create", "retry", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			data := []byte("fixed batch\n")
			existing := data
			if mode == "conflict" {
				existing = []byte("different\n")
			}
			var server *httptest.Server
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if r.Method == "POST" {
					if q.Get("ifGenerationMatch") != "0" {
						t.Error("upload lacked create-only precondition")
					}
					if mode != "create" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(412)
						_, _ = w.Write([]byte(`{"error":{"code":412,"message":"exists"}}`))
						return
					}
					if q.Get("uploadType") == "resumable" {
						w.Header().Set("Location", server.URL+"/upload-session")
						w.WriteHeader(200)
						return
					}
					if q.Get("uploadType") == "multipart" {
						_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
						if err != nil {
							t.Error(err)
							w.WriteHeader(400)
							return
						}
						mr := multipart.NewReader(r.Body, params["boundary"])
						meta, err := mr.NextPart()
						if err != nil {
							t.Error(err)
							w.WriteHeader(400)
							return
						}
						_, _ = io.Copy(io.Discard, meta)
						part, err := mr.NextPart()
						if err != nil {
							t.Error(err)
							w.WriteHeader(400)
							return
						}
						got, err := io.ReadAll(part)
						if err != nil || !bytes.Equal(got, data) {
							t.Errorf("uploaded bytes %q %v", got, err)
						}
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"bucket":"test","name":"batch","generation":"123","size":"12"}`))
						return
					}
					t.Errorf("unexpected upload mode %q", q.Get("uploadType"))
					w.WriteHeader(400)
					return
				}
				if r.Method == "PUT" && r.URL.Path == "/upload-session" {
					got, e := io.ReadAll(r.Body)
					if e != nil || !bytes.Equal(got, data) {
						t.Errorf("uploaded bytes %q %v", got, e)
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"bucket":"test","name":"batch","generation":"123","size":"12"}`))
					return
				}
				if r.Method == "GET" && q.Get("alt") == "media" {
					if q.Get("generation") != "123" {
						t.Error("read did not pin generation")
					}
					w.Header().Set("X-Goog-Generation", "123")
					w.Header().Set("Content-Length", strconv.Itoa(len(existing)))
					_, _ = w.Write(existing)
					return
				}
				if r.Method == "GET" {
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]string{"bucket": "test", "name": "batch", "generation": "123", "size": strconv.Itoa(len(existing))})
					return
				}
				t.Errorf("unexpected request %s %s", r.Method, r.URL.String())
				w.WriteHeader(400)
			}))
			defer server.Close()
			client, e := storage.NewClient(ctx, option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()), storage.WithJSONReads())
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			gen, e := (GCS{client.Bucket("test")}).CreateFixed(ctx, "batch", "application/x-ndjson", data)
			if mode == "conflict" {
				if !errors.Is(e, ErrObjectConflict) {
					t.Fatalf("%d %v", gen, e)
				}
			} else if e != nil || gen != 123 {
				t.Fatalf("%d %v", gen, e)
			}
		})
	}
}
