package snapshot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// ErrExists is returned by Store.CreateOnly when the object already exists.
var ErrExists = errors.New("object already exists")

// Store holds snapshot objects by key (snapshots/<snapshot_id>/<name>).
// Objects are write-once (TASK-02 3.4): CreateOnly never replaces an object.
type Store interface {
	// Get returns the object bytes, or an error wrapping fs.ErrNotExist.
	Get(ctx context.Context, key string) ([]byte, error)
	// CreateOnly writes the object only if it does not exist yet; otherwise it
	// returns an error wrapping ErrExists and leaves the object unchanged.
	CreateOnly(ctx context.Context, key string, data []byte) error
}

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)

// OpenStore returns the store for --out-root: gs://<bucket> writes through the
// Cloud Storage API with Application Default Credentials (the Job KSA's
// Workload Identity in GKE; no Cloud Storage FUSE, TASK-02 3.4 / PR #8).
// Anything else is a local directory, used for tests and development.
func OpenStore(ctx context.Context, outRoot string, opts ...option.ClientOption) (Store, func() error, error) {
	if !strings.HasPrefix(outRoot, "gs://") {
		return DirStore{Root: outRoot}, func() error { return nil }, nil
	}
	bucket := strings.TrimSuffix(strings.TrimPrefix(outRoot, "gs://"), "/")
	if !bucketRe.MatchString(bucket) {
		return nil, nil, fmt.Errorf("out-root must be gs://<bucket> without a path, got %q", outRoot)
	}
	c, err := storage.NewClient(ctx, opts...)
	if err != nil {
		return nil, nil, err
	}
	return GCSStore{Bucket: c.Bucket(bucket)}, c.Close, nil
}

// DirStore keeps objects as files under Root.
type DirStore struct{ Root string }

func (d DirStore) path(key string) string { return filepath.Join(d.Root, filepath.FromSlash(key)) }

func (d DirStore) Get(_ context.Context, key string) ([]byte, error) {
	return os.ReadFile(d.path(key))
}

// CreateOnly writes a temp file and hard-links it into place; link(2) fails
// when the target exists, so a complete object is never replaced.
func (d DirStore) CreateOnly(_ context.Context, key string, data []byte) error {
	dst := d.path(key)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	if err := os.Link(tmp.Name(), dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s: %w", key, ErrExists)
		}
		return err
	}
	return nil
}

// GCSStore keeps objects in a Cloud Storage bucket.
type GCSStore struct{ Bucket *storage.BucketHandle }

func (g GCSStore) Get(ctx context.Context, key string) ([]byte, error) {
	r, err := g.Bucket.Object(key).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, fmt.Errorf("%s: %w", key, fs.ErrNotExist)
		}
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

// BucketName, ObjectSize and OpenObject let internal/source read the staged
// archive gs://<bucket>/sources/<source_digest>.<ext> from the same bucket.
func (g GCSStore) BucketName() string { return g.Bucket.BucketName() }

func (g GCSStore) ObjectSize(ctx context.Context, key string) (int64, error) {
	a, err := g.Bucket.Object(key).Attrs(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return 0, fmt.Errorf("%s: %w", key, fs.ErrNotExist)
		}
		return 0, err
	}
	return a.Size, nil
}

func (g GCSStore) OpenObject(ctx context.Context, key string) (io.ReadCloser, error) {
	r, err := g.Bucket.Object(key).NewReader(ctx)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, fmt.Errorf("%s: %w", key, fs.ErrNotExist)
		}
		return nil, err
	}
	return r, nil
}

// CreateOnly uploads with the ifGenerationMatch=0 precondition; Cloud Storage
// answers 412 when the object already exists.
func (g GCSStore) CreateOnly(ctx context.Context, key string, data []byte) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // abandons the upload if Write fails before Close
	w := g.Bucket.Object(key).If(storage.Conditions{DoesNotExist: true}).NewWriter(ctx)
	w.ChunkSize = 0 // one request; objects are small and must not be left half-written
	w.ContentType = contentType(key)
	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		var ge *googleapi.Error
		if errors.As(err, &ge) && ge.Code == http.StatusPreconditionFailed {
			return fmt.Errorf("%s: %w", key, ErrExists)
		}
		return err
	}
	return nil
}

func contentType(key string) string {
	if strings.HasSuffix(key, ".json") && !strings.Contains(key, "/src/") {
		return "application/json"
	}
	return "application/octet-stream"
}
