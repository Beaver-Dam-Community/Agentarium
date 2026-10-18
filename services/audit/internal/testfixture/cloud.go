package testfixture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/uuid"
	kms "google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

// KeyVersion is the fixture's only KMS asymmetric signing key version.
const KeyVersion = "projects/test/locations/global/keyRings/audit/cryptoKeys/manifest/cryptoKeyVersions/1"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type Object struct {
	Data       []byte
	Generation int64
	Created    time.Time
}

type upload struct {
	bucket, name string
	createOnly   bool
	crc32c       string
}

// Cloud is a local GCS JSON/XML and Cloud KMS asymmetricSign endpoint for a
// fixed set of buckets. It enforces the contract the exporter and verifier rely
// on: create-only uploads (ifGenerationMatch=0, 412 on an existing object),
// CRC32C on upload, generation-pinned media reads, and an unlocked 30-day
// retention policy that rejects deletion or replacement (403
// retentionPolicyNotMet). FailUploads injects a storage outage.
type Cloud struct {
	Key       *ecdsa.PrivateKey
	server    *httptest.Server
	t         *testing.T
	mu        sync.Mutex
	buckets   map[string]map[string]Object
	sessions  map[string]upload
	next      int64
	failing   bool
	signs     int
	retention time.Duration
}

func NewCloud(t *testing.T, buckets ...string) *Cloud {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &Cloud{Key: key, t: t, buckets: map[string]map[string]Object{}, sessions: map[string]upload{}, next: 1700000000000000, retention: 30 * 24 * time.Hour}
	for _, b := range buckets {
		c.buckets[b] = map[string]Object{}
	}
	c.server = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.server.Close)
	return c
}

// Host is the value for STORAGE_EMULATOR_HOST.
func (c *Cloud) Host() string { return strings.TrimPrefix(c.server.URL, "http://") }

// KMSEndpoint is the base URL for the KMS client endpoint option.
func (c *Cloud) KMSEndpoint() string { return c.server.URL + "/" }

func (c *Cloud) FailUploads(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failing = on
}

func (c *Cloud) Signs() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signs
}

// PublicKeysJSON is the trusted key file format of cmd/verify and cmd/exporter.
func (c *Cloud) PublicKeysJSON(t *testing.T) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&c.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{KeyVersion: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	return raw
}

func (c *Cloud) StorageClient(t *testing.T) *storage.Client {
	t.Helper()
	sc, err := storage.NewClient(context.Background(), option.WithEndpoint(c.server.URL+"/storage/v1/"), option.WithoutAuthentication(), option.WithHTTPClient(c.server.Client()), storage.WithJSONReads())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	return sc
}

func (c *Cloud) KMSService(t *testing.T) *kms.Service {
	t.Helper()
	svc, err := kms.NewService(context.Background(), option.WithEndpoint(c.KMSEndpoint()), option.WithoutAuthentication(), option.WithHTTPClient(c.server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (c *Cloud) Snapshot(bucket string) map[string]Object {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]Object{}
	for k, v := range c.buckets[bucket] {
		out[k] = v
	}
	return out
}

// AdminRemove models a privileged bypass of retention (a stated trust boundary).
func (c *Cloud) AdminRemove(bucket, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.buckets[bucket], name)
}

// ExportedRecords parses batch objects and returns received_at by event_id.
func (c *Cloud) ExportedRecords(t *testing.T, bucket string) map[string]time.Time {
	t.Helper()
	out := map[string]time.Time{}
	for name, obj := range c.Snapshot(bucket) {
		if strings.HasPrefix(name, "manifests/") || strings.HasPrefix(name, "probes/") {
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(obj.Data))
		for scanner.Scan() {
			var line struct {
				Kind   string `json:"record_kind"`
				Record struct {
					EventID    string    `json:"event_id"`
					ReceivedAt time.Time `json:"received_at"`
				} `json:"record"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
				t.Fatalf("invalid export line %q: %v", scanner.Text(), err)
			}
			if line.Kind == "audit_event" {
				out[line.Record.EventID] = line.Record.ReceivedAt
			}
		}
	}
	return out
}

func apiError(w http.ResponseWriter, code int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": reason, "errors": []map[string]string{{"reason": reason, "message": reason}}}})
}

func crcBase64(data []byte) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], crc32.Checksum(data, castagnoli))
	return base64.StdEncoding.EncodeToString(b[:])
}

func (c *Cloud) resource(bucket, name string, o Object) map[string]string {
	return map[string]string{"kind": "storage#object", "bucket": bucket, "name": name, "generation": strconv.FormatInt(o.Generation, 10),
		"metageneration": "1", "size": strconv.Itoa(len(o.Data)), "crc32c": crcBase64(o.Data), "timeCreated": o.Created.Format(time.RFC3339Nano),
		"retentionExpirationTime": o.Created.Add(c.retention).Format(time.RFC3339Nano)}
}

// route returns the bucket and object name of a JSON or XML object path.
func (c *Cloud) route(path string) (bucket, name, kind string) {
	for b := range c.buckets {
		prefix := "/b/" + b + "/o"
		if i := strings.Index(path, prefix); i >= 0 {
			rest := path[i+len(prefix):]
			if strings.Contains(path, "/upload/") && rest == "" {
				return b, "", "upload"
			}
			if strings.HasPrefix(rest, "/") {
				return b, rest[1:], "json"
			}
		}
		if strings.HasPrefix(path, "/"+b+"/") {
			return b, strings.TrimPrefix(path, "/"+b+"/"), "xml"
		}
	}
	return "", "", ""
}

func (c *Cloud) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, ":asymmetricSign") {
		c.sign(w, r)
		return
	}
	q := r.URL.Query()
	if r.Method == http.MethodPut && r.URL.Path == "/upload-session" {
		c.mu.Lock()
		s, ok := c.sessions[q.Get("id")]
		delete(c.sessions, q.Get("id"))
		c.mu.Unlock()
		data, err := io.ReadAll(r.Body)
		if !ok || err != nil {
			apiError(w, 400, "invalid")
			return
		}
		c.create(w, s, data)
		return
	}
	bucket, name, kind := c.route(r.URL.Path)
	switch {
	case kind == "upload" && r.Method == http.MethodPost:
		c.upload(w, r, bucket)
	case kind == "json":
		c.object(w, r, bucket, name, q.Get("alt") == "media")
	case kind == "xml" && r.Method == http.MethodGet:
		c.object(w, r, bucket, name, true)
	default:
		c.t.Errorf("unexpected cloud request %s %s", r.Method, r.URL)
		apiError(w, 400, "unsupported")
	}
}

func (c *Cloud) upload(w http.ResponseWriter, r *http.Request, bucket string) {
	q := r.URL.Query()
	createOnly := q.Get("ifGenerationMatch") == "0"
	var meta struct {
		Name   string `json:"name"`
		CRC32C string `json:"crc32c"`
	}
	if q.Get("uploadType") == "resumable" {
		if err := json.NewDecoder(r.Body).Decode(&meta); err != nil {
			apiError(w, 400, "invalid")
			return
		}
		id := uuid.NewString()
		c.mu.Lock()
		c.sessions[id] = upload{bucket: bucket, name: meta.Name, createOnly: createOnly, crc32c: meta.CRC32C}
		c.mu.Unlock()
		w.Header().Set("Location", c.server.URL+"/upload-session?id="+id)
		return
	}
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		apiError(w, 400, "invalid")
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	part, err := mr.NextPart()
	if err != nil || json.NewDecoder(part).Decode(&meta) != nil {
		apiError(w, 400, "invalid")
		return
	}
	part, err = mr.NextPart()
	if err != nil {
		apiError(w, 400, "invalid")
		return
	}
	data, err := io.ReadAll(part)
	if err != nil {
		apiError(w, 400, "invalid")
		return
	}
	c.create(w, upload{bucket: bucket, name: meta.Name, createOnly: createOnly, crc32c: meta.CRC32C}, data)
}

func (c *Cloud) create(w http.ResponseWriter, s upload, data []byte) {
	if s.name == "" || len(data) == 0 {
		apiError(w, 400, "invalid")
		return
	}
	if s.crc32c != "" && s.crc32c != crcBase64(data) {
		apiError(w, 400, "invalid") // checksum mismatch: the object is not stored
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failing {
		apiError(w, 503, "backendError")
		return
	}
	objects := c.buckets[s.bucket]
	if existing, ok := objects[s.name]; ok {
		if s.createOnly {
			apiError(w, 412, "conditionNotMet")
		} else if time.Since(existing.Created) < c.retention {
			apiError(w, 403, "retentionPolicyNotMet")
		} else {
			apiError(w, 400, "unsupported")
		}
		return
	}
	c.next++
	o := Object{Data: append([]byte(nil), data...), Generation: c.next, Created: time.Now().UTC()}
	objects[s.name] = o
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.resource(s.bucket, s.name, o))
}

func (c *Cloud) object(w http.ResponseWriter, r *http.Request, bucket, name string, media bool) {
	c.mu.Lock()
	o, ok := c.buckets[bucket][name]
	if ok && r.Method == http.MethodDelete && time.Since(o.Created) < c.retention {
		c.mu.Unlock()
		apiError(w, 403, "retentionPolicyNotMet")
		return
	}
	c.mu.Unlock()
	if !ok {
		apiError(w, 404, "notFound")
		return
	}
	if r.Method != http.MethodGet {
		apiError(w, 400, "unsupported")
		return
	}
	if g := r.URL.Query().Get("generation"); g != "" && g != strconv.FormatInt(o.Generation, 10) {
		apiError(w, 404, "notFound")
		return
	}
	if !media {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(c.resource(bucket, name, o))
		return
	}
	if r.URL.Query().Get("generation") == "" {
		apiError(w, 400, "unpinned read") // exporter, probe and verifier must pin
		return
	}
	w.Header().Set("X-Goog-Generation", strconv.FormatInt(o.Generation, 10))
	w.Header().Set("X-Goog-Metageneration", "1")
	w.Header().Set("X-Goog-Hash", "crc32c="+crcBase64(o.Data))
	w.Header().Set("Content-Length", strconv.Itoa(len(o.Data)))
	_, _ = w.Write(o.Data)
}

func (c *Cloud) sign(w http.ResponseWriter, r *http.Request) {
	var req kms.AsymmetricSignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Digest == nil || !strings.HasPrefix(r.URL.Path, "/v1/"+KeyVersion) {
		apiError(w, 400, "invalid")
		return
	}
	digest, err := base64.StdEncoding.Strict().DecodeString(req.Digest.Sha256)
	if err != nil || len(digest) != sha256.Size || req.DigestCrc32c != int64(crc32.Checksum(digest, castagnoli)) {
		apiError(w, 400, "invalid digest")
		return
	}
	sig, err := ecdsa.SignASN1(rand.Reader, c.Key, digest)
	if err != nil {
		apiError(w, 500, "internal")
		return
	}
	c.mu.Lock()
	c.signs++
	c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(kms.AsymmetricSignResponse{Name: KeyVersion, Signature: base64.StdEncoding.EncodeToString(sig),
		SignatureCrc32c: int64(crc32.Checksum(sig, castagnoli)), VerifiedDigestCrc32c: true, ForceSendFields: []string{"VerifiedDigestCrc32c"}})
}
