package snapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/api/option"

	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/format"
	"github.com/Beaver-Dam-Community/Agentarium/tools/discovery-snapshot/internal/source"
)

// fakeGCS is a minimal Cloud Storage JSON/XML API for one bucket: multipart
// uploads honouring ifGenerationMatch=0, and media reads. No GCP is called.
type fakeGCS struct {
	t       *testing.T
	bucket  string
	mu      sync.Mutex
	objects map[string][]byte
	// preconditions records the ifGenerationMatch value of every upload.
	preconditions []string
	// sizes overrides the size reported by object metadata requests.
	sizes map[string]int64
	// mediaReads records every object content download.
	mediaReads []string
}

func (f *fakeGCS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.EscapedPath()
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/upload/storage/v1/b/"+f.bucket+"/o"):
		f.upload(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/storage/v1/b/"+f.bucket+"/o/") && r.URL.Query().Get("alt") != "media":
		f.attrs(w, strings.TrimPrefix(p, "/storage/v1/b/"+f.bucket+"/o/"))
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/storage/v1/b/"+f.bucket+"/o/"):
		f.read(w, strings.TrimPrefix(p, "/storage/v1/b/"+f.bucket+"/o/"))
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/download/storage/v1/b/"+f.bucket+"/o/"):
		f.read(w, strings.TrimPrefix(p, "/download/storage/v1/b/"+f.bucket+"/o/"))
	case r.Method == http.MethodGet && strings.HasPrefix(p, "/"+f.bucket+"/"):
		f.read(w, strings.TrimPrefix(p, "/"+f.bucket+"/"))
	default:
		f.t.Errorf("fake GCS: unhandled %s %s", r.Method, r.URL)
		http.Error(w, "unhandled", http.StatusNotImplemented)
	}
}

func (f *fakeGCS) read(w http.ResponseWriter, escaped string) {
	name, err := url.PathUnescape(escaped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, ok := f.objects[name]
	if !ok {
		gcsError(w, http.StatusNotFound, "No such object")
		return
	}
	f.mediaReads = append(f.mediaReads, name)
	w.Header().Set("X-Goog-Generation", "1")
	w.Header().Set("Content-Length", fmt.Sprint(len(data)))
	w.Write(data)
}

func (f *fakeGCS) attrs(w http.ResponseWriter, escaped string) {
	name, err := url.PathUnescape(escaped)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, ok := f.objects[name]
	if !ok {
		gcsError(w, http.StatusNotFound, "No such object")
		return
	}
	size := int64(len(data))
	if n, ok := f.sizes[name]; ok {
		size = n
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"bucket": f.bucket, "name": name, "generation": "1", "size": fmt.Sprint(size)})
}

func (f *fakeGCS) upload(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("uploadType") != "multipart" {
		f.t.Errorf("fake GCS: uploadType %q, want a single multipart request", q.Get("uploadType"))
	}
	f.preconditions = append(f.preconditions, q.Get("ifGenerationMatch"))
	_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mr := multipart.NewReader(r.Body, params["boundary"])
	metaPart, err := mr.NextPart()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var meta struct {
		Name string `json:"name"`
	}
	json.NewDecoder(metaPart).Decode(&meta)
	dataPart, err := mr.NextPart()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	data, _ := io.ReadAll(dataPart)
	name := meta.Name
	if name == "" {
		name = q.Get("name")
	}
	if _, exists := f.objects[name]; exists && q.Get("ifGenerationMatch") == "0" {
		gcsError(w, http.StatusPreconditionFailed, "conditionNotMet")
		return
	}
	f.objects[name] = data
	w.Header().Set("Content-Type", "application/json")
	// The client checks the CRC32C (Castagnoli, big-endian, base64) the server returns.
	sum := make([]byte, 4)
	binary.BigEndian.PutUint32(sum, crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
	json.NewEncoder(w).Encode(map[string]any{"bucket": f.bucket, "name": name, "generation": "1",
		"size": fmt.Sprint(len(data)), "crc32c": base64.StdEncoding.EncodeToString(sum)})
}

func gcsError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

func newFakeGCSStore(t *testing.T) (Store, *fakeGCS) {
	t.Helper()
	f := &fakeGCS{t: t, bucket: "discovery-test-bucket", objects: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	st, closeFn, err := OpenStore(context.Background(), "gs://"+f.bucket,
		option.WithEndpoint(srv.URL+"/storage/v1/"), option.WithoutAuthentication(), option.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeFn() })
	if _, ok := st.(GCSStore); !ok {
		t.Fatalf("gs:// root opened %T", st)
	}
	return st, f
}

func TestGCSStoreWriteOnce(t *testing.T) {
	var fakes []*fakeGCS
	writeOnceCases(t,
		func(t *testing.T) Store {
			st, f := newFakeGCSStore(t)
			fakes = append(fakes, f)
			return st
		},
		func(t *testing.T, st Store, key string, data []byte) {
			f := fakes[len(fakes)-1]
			f.mu.Lock()
			f.objects[key] = data
			f.mu.Unlock()
		})
	for _, f := range fakes {
		for i, p := range f.preconditions {
			if p != "0" {
				t.Errorf("upload %d sent ifGenerationMatch=%q, want 0", i, p)
			}
		}
	}
}

func TestGCSStoreLayout(t *testing.T) {
	st, f := newFakeGCSStore(t)
	src, m := srcTree(t)
	id, _, err := Write(context.Background(), st, src, m, format.Callgraph{}, emptySites, shaDigest)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"manifest.json", "callgraph.json", "call_sites.json", "src/a.py"} {
		if _, ok := f.objects["snapshots/"+id+"/"+k]; !ok {
			t.Errorf("missing object snapshots/%s/%s", id, k)
		}
	}
	if len(f.objects) != 4 {
		t.Errorf("objects: %d, want 4", len(f.objects))
	}
}

func stageGCSSource(t *testing.T, f *fakeGCS) (key, uri, digest string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("x = 1\n")
	tw.WriteHeader(&tar.Header{Name: "lib-1.0/lib/a.py", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write(body)
	tw.Close()
	gz.Close()
	sum := sha256.Sum256(buf.Bytes())
	digest = hex.EncodeToString(sum[:])
	key = "sources/" + digest + ".tar.gz"
	f.mu.Lock()
	f.objects[key] = buf.Bytes()
	f.mu.Unlock()
	return key, "gs://" + f.bucket + "/" + key, digest
}

func TestGCSSourceThroughStorageClient(t *testing.T) {
	ctx := context.Background()

	t.Run("staged_archive", func(t *testing.T) {
		st, f := newFakeGCSStore(t)
		_, uri, digest := stageGCSSource(t, f)
		root, err := source.Fetch(ctx, uri, digest, t.TempDir(), st.(source.Objects))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(root, "lib", "a.py")); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("wrong_bucket", func(t *testing.T) {
		st, f := newFakeGCSStore(t)
		_, uri, digest := stageGCSSource(t, f)
		uri = strings.Replace(uri, "gs://"+f.bucket+"/", "gs://another-bucket/", 1)
		if _, err := source.Fetch(ctx, uri, digest, t.TempDir(), st.(source.Objects)); err == nil {
			t.Fatal("want error")
		}
		if len(f.mediaReads) != 0 {
			t.Fatalf("downloaded %v", f.mediaReads)
		}
	})

	t.Run("wrong_digest_name", func(t *testing.T) {
		st, f := newFakeGCSStore(t)
		_, uri, _ := stageGCSSource(t, f)
		if _, err := source.Fetch(ctx, uri, strings.Repeat("e", 64), t.TempDir(), st.(source.Objects)); err == nil {
			t.Fatal("want error")
		}
		if len(f.mediaReads) != 0 {
			t.Fatalf("downloaded %v", f.mediaReads)
		}
	})

	t.Run("oversize_by_attrs", func(t *testing.T) {
		st, f := newFakeGCSStore(t)
		key, uri, digest := stageGCSSource(t, f)
		f.sizes = map[string]int64{key: source.DefaultLimits.ArchiveBytes + 1}
		_, err := source.Fetch(ctx, uri, digest, t.TempDir(), st.(source.Objects))
		var le *source.LimitError
		if !errors.As(err, &le) || le.Limit != source.LimitArchiveBytes {
			t.Fatalf("want archive_bytes, got %v", err)
		}
		if len(f.mediaReads) != 0 {
			t.Fatalf("oversize object was downloaded: %v", f.mediaReads)
		}
	})

	t.Run("oversize_by_stream", func(t *testing.T) {
		st, f := newFakeGCSStore(t)
		key, uri, digest := stageGCSSource(t, f)
		lim := source.DefaultLimits
		lim.ArchiveBytes = int64(len(f.objects[key])) - 1
		f.sizes = map[string]int64{key: 1}
		_, err := source.FetchWithLimits(ctx, uri, digest, t.TempDir(), st.(source.Objects), lim)
		var le *source.LimitError
		if !errors.As(err, &le) || le.Limit != source.LimitArchiveBytes {
			t.Fatalf("want archive_bytes, got %v", err)
		}
	})
}
