package export

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/jackc/pgx/v5/pgxpool"
	kms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

type signerFunc func(context.Context, []byte) ([]byte, error)

func (f signerFunc) Sign(ctx context.Context, b []byte) ([]byte, error) { return f(ctx, b) }

type leaseFunc func(context.Context, string) (int64, error)

func (f leaseFunc) Check(ctx context.Context, chain string) (int64, error) { return f(ctx, chain) }

// testLeaseHolder is shared so direct fixture inserts can renew the same lease.
const testLeaseHolder = "export-test"

// liveLease holds a real PostgreSQL manifest lease, so the DB fencing trigger
// accepts this holder's intents and manifests. It (re)acquires only when the
// local lease is missing or near expiry, like the exporter's renewal loop;
// Check itself must not touch the lease row inside a fenced transaction.
func liveLease(pool *pgxpool.Pool) leaseFunc {
	l := &PGLease{Pool: pool, Holder: testLeaseHolder}
	return func(ctx context.Context, chain string) (int64, error) {
		if token, err := l.Check(ctx, chain); err == nil {
			return token, nil
		}
		if _, err := l.Acquire(ctx, chain); err != nil {
			return 0, err
		}
		return l.Check(ctx, chain)
	}
}

type fixtureObject struct {
	data       []byte
	generation int64
}
type publisherCloud struct {
	Objects GCS
	Signer  KMS
	Key     *ecdsa.PublicKey
	Version string
	mu      sync.Mutex
	objects map[string]fixtureObject
	signs   int
}

func newPublisherCloud(t *testing.T) *publisherCloud { return newPublisherCloudBucket(t, "test") }

func newPublisherCloudBucket(t *testing.T, bucket string) *publisherCloud {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &publisherCloud{Key: &key.PublicKey, Version: "projects/test/locations/global/keyRings/test/cryptoKeys/audit/cryptoKeyVersions/1", objects: map[string]fixtureObject{}}
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ":asymmetricSign") {
			var req kms.AsymmetricSignRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			digest, err := base64.StdEncoding.Strict().DecodeString(req.Digest.Sha256)
			if err != nil || req.DigestCrc32c != int64(crc32.Checksum(digest, crcTable)) {
				t.Error("KMS digest CRC mismatch")
				w.WriteHeader(400)
				return
			}
			sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
			if err != nil {
				t.Error(err)
				w.WriteHeader(500)
				return
			}
			f.mu.Lock()
			f.signs++
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(kms.AsymmetricSignResponse{Name: f.Version, Signature: base64.StdEncoding.EncodeToString(sig), SignatureCrc32c: int64(crc32.Checksum(sig, crcTable)), VerifiedDigestCrc32c: true})
			return
		}
		if !strings.Contains(r.URL.Path, "/b/"+bucket+"/o") {
			t.Errorf("wrong bucket request: %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		q := r.URL.Query()
		name := ""
		var data []byte
		if i := strings.Index(r.URL.Path, "/o/"); i >= 0 {
			name = r.URL.Path[i+3:]
		}
		if r.Method == "POST" {
			if q.Get("ifGenerationMatch") != "0" {
				t.Error("missing create-only precondition")
				w.WriteHeader(400)
				return
			}
			if q.Get("uploadType") == "resumable" {
				var meta struct {
					Name string `json:"name"`
				}
				if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Location", server.URL+"/upload-session?name="+url.QueryEscape(meta.Name))
				w.WriteHeader(200)
				return
			}
			_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			mr := multipart.NewReader(r.Body, params["boundary"])
			part, err := mr.NextPart()
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			var meta struct {
				Name string `json:"name"`
			}
			if err = json.NewDecoder(part).Decode(&meta); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			name = meta.Name
			part, err = mr.NextPart()
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			data, err = io.ReadAll(part)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
		} else if r.Method == "PUT" && r.URL.Path == "/upload-session" {
			name = q.Get("name")
			data, err = io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		existing, ok := f.objects[name]
		apiError := func(code int) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": http.StatusText(code)}})
		}
		if r.Method == "POST" || r.Method == "PUT" {
			if ok {
				apiError(412)
				return
			}
			existing = fixtureObject{data: append([]byte(nil), data...), generation: int64(100 + len(f.objects))}
			f.objects[name] = existing
			ok = true
		}
		if !ok {
			apiError(404)
			return
		}
		if r.Method == "GET" && q.Get("alt") == "media" {
			if q.Get("generation") != strconv.FormatInt(existing.generation, 10) {
				t.Error("object read did not pin generation")
				apiError(400)
				return
			}
			w.Header().Set("X-Goog-Generation", strconv.FormatInt(existing.generation, 10))
			w.Header().Set("Content-Length", strconv.Itoa(len(existing.data)))
			_, _ = w.Write(existing.data)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"bucket": "test", "name": name, "generation": strconv.FormatInt(existing.generation, 10), "size": strconv.Itoa(len(existing.data))})
	}))
	t.Cleanup(server.Close)
	ctx := context.Background()
	client, err := storage.NewClient(ctx, option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()), storage.WithJSONReads())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	service, err := kms.NewService(ctx, option.WithEndpoint(server.URL+"/"), option.WithoutAuthentication(), option.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	f.Objects = GCS{Bucket: client.Bucket(bucket)}
	f.Signer = KMS{Service: service, KeyVersion: f.Version, PublicKey: f.Key}
	return f
}
func (f *publisherCloud) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.objects), f.signs
}

func TestManifestPublisherRequiresLeaderLease(t *testing.T) {
	if _, err := (ManifestPublisher{}).Publish(context.Background(), nil, nil, nil); !errors.Is(err, ErrLeaderLeaseMissing) {
		t.Fatal(err)
	}
}
