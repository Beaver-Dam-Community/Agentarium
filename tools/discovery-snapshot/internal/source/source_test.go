package source

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// --- archive builders ---------------------------------------------------------

type tarEntry struct {
	name string
	body string
	typ  byte // 0 = regular file
	link string
}

func tarBytes(t *testing.T, gz bool, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.Writer = &buf
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(&buf)
		w = zw
	}
	tw := tar.NewWriter(w)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
			if strings.HasSuffix(e.name, "/") {
				typ = tar.TypeDir
			}
		}
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: typ, Linkname: e.link, Format: tar.FormatPAX}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	if zw != nil {
		zw.Close()
	}
	return buf.Bytes()
}

func files(m map[string]string) []tarEntry {
	var out []tarEntry
	for k, v := range m {
		out = append(out, tarEntry{name: k, body: v})
	}
	return out
}

type zipEntry struct {
	name string
	body []byte
	mode fs.FileMode // 0 = regular 0644
}

func zipBytes(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(e.body)
	}
	zw.Close()
	return buf.Bytes()
}

func stage(t *testing.T, name string, data []byte) (string, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return "file://" + p, hex.EncodeToString(sum[:])
}

func fetch(t *testing.T, name string, data []byte, lim Limits) (string, error) {
	t.Helper()
	uri, digest := stage(t, name, data)
	return FetchWithLimits(context.Background(), uri, digest, t.TempDir(), nil, lim)
}

func wantLimit(t *testing.T, err error, limit string) {
	t.Helper()
	var le *LimitError
	if !errors.As(err, &le) || le.Limit != limit {
		t.Fatalf("want limit %q, got %v", limit, err)
	}
}

// --- happy paths --------------------------------------------------------------

func TestFetchTarGzStripsTopDir(t *testing.T) {
	data := tarBytes(t, true,
		tarEntry{name: "httpx-0.27.0/", typ: tar.TypeDir},
		tarEntry{name: "httpx-0.27.0/httpx/_client.py", body: "x = 1\n"},
		tarEntry{name: "httpx-0.27.0/pyproject.toml", body: "[project]\n"})
	root, err := fetch(t, "src.tar.gz", data, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "httpx", "_client.py")); err != nil || string(b) != "x = 1\n" {
		t.Fatalf("missing extracted file: %v", err)
	}
	// The spooled archive is removed after extraction.
	if _, err := os.Stat(filepath.Join(filepath.Dir(filepath.Dir(root)), "archive")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("spooled archive left behind: %v", err)
	}
}

func TestFetchGoModuleZipStripsModuleVersionPrefix(t *testing.T) {
	data := zipBytes(t,
		zipEntry{name: "golang.org/x/oauth2@v0.20.0/go.mod", body: []byte("module x\n")},
		zipEntry{name: "golang.org/x/oauth2@v0.20.0/google/default.go", body: []byte("package x\n")})
	root, err := fetch(t, "m.zip", data, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "google", "default.go")); err != nil {
		t.Fatalf("prefix not stripped: %v", err)
	}
}

func TestFetchPlainTarAndWheel(t *testing.T) {
	if _, err := fetch(t, "s.tar", tarBytes(t, false, files(map[string]string{"p/a.py": "1"})...), DefaultLimits); err != nil {
		t.Fatal(err)
	}
	if _, err := fetch(t, "s.whl", zipBytes(t, zipEntry{name: "pkg/a.py", body: []byte("1")}), DefaultLimits); err != nil {
		t.Fatal(err)
	}
}

// --- digest -------------------------------------------------------------------

func TestDigestMismatchFailsBeforeExtraction(t *testing.T) {
	uri, _ := stage(t, "src.tar.gz", tarBytes(t, true, files(map[string]string{"a/b.py": "1"})...))
	dest := t.TempDir()
	_, err := FetchWithLimits(context.Background(), uri, strings.Repeat("0", 64), dest, nil, DefaultLimits)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("want ErrDigestMismatch, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "tree")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("nothing may be extracted before the digest is checked")
	}
}

// --- size limits ----------------------------------------------------------------

func TestArchiveBytesLimit(t *testing.T) {
	data := tarBytes(t, false, files(map[string]string{"p/a.py": "1"})...)
	n := int64(len(data))
	if _, err := fetch(t, "s.tar", data, Limits{ArchiveBytes: n, ExtractedBytes: 1 << 20, FileBytes: 1 << 20, Entries: 10, PathBytes: 512}); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	_, err := fetch(t, "s.tar", data, Limits{ArchiveBytes: n - 1, ExtractedBytes: 1 << 20, FileBytes: 1 << 20, Entries: 10, PathBytes: 512})
	wantLimit(t, err, LimitArchiveBytes)
}

func lim(mod func(*Limits)) Limits {
	l := Limits{ArchiveBytes: 1 << 30, ExtractedBytes: 1 << 20, FileBytes: 1 << 20, Entries: 100, PathBytes: 512}
	mod(&l)
	return l
}

func TestFileBytesLimit(t *testing.T) {
	data := tarBytes(t, true, tarEntry{name: "p/a.py", body: strings.Repeat("x", 100)})
	if _, err := fetch(t, "s.tgz", data, lim(func(l *Limits) { l.FileBytes = 100 })); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	_, err := fetch(t, "s.tgz", data, lim(func(l *Limits) { l.FileBytes = 99 }))
	wantLimit(t, err, LimitFileBytes)
}

func TestExtractedBytesLimitCountsWrittenBytes(t *testing.T) {
	data := tarBytes(t, true, tarEntry{name: "p/a.py", body: strings.Repeat("x", 60)},
		tarEntry{name: "p/b.py", body: strings.Repeat("y", 40)})
	if _, err := fetch(t, "s.tgz", data, lim(func(l *Limits) { l.ExtractedBytes = 100 })); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	_, err := fetch(t, "s.tgz", data, lim(func(l *Limits) { l.ExtractedBytes = 99 }))
	wantLimit(t, err, LimitExtractedBytes)
}

func TestZipBombStopsAtTheLimits(t *testing.T) {
	// 64MiB of zeros deflates to ~64KiB: the ratio is not limited, the bytes are.
	bomb := bytes.Repeat([]byte{0}, 64<<20)
	data := zipBytes(t, zipEntry{name: "p/bomb.bin", body: bomb})
	if len(data) > 1<<20 {
		t.Fatalf("test archive unexpectedly large: %d", len(data))
	}
	dest := t.TempDir()
	uri, digest := stage(t, "b.zip", data)
	_, err := FetchWithLimits(context.Background(), uri, digest, dest, nil, lim(func(l *Limits) { l.FileBytes = 1 << 20 }))
	wantLimit(t, err, LimitFileBytes)
	// Extraction stopped one byte past the file limit; it did not inflate the rest.
	if st, err := os.Stat(filepath.Join(dest, "tree", "p", "bomb.bin")); err != nil || st.Size() != 1<<20+1 {
		t.Fatalf("partial file: %v %v", st, err)
	}
	_, err = fetch(t, "b.zip", data, lim(func(l *Limits) { l.FileBytes = 128 << 20; l.ExtractedBytes = 2 << 20 }))
	wantLimit(t, err, LimitExtractedBytes)
}

// --- entries and paths --------------------------------------------------------

func TestEntriesLimitCountsDirectories(t *testing.T) {
	entries := []tarEntry{{name: "p/", typ: tar.TypeDir}, {name: "p/d/", typ: tar.TypeDir}, {name: "p/a.py", body: "1"}}
	data := tarBytes(t, false, entries...)
	if _, err := fetch(t, "s.tar", data, lim(func(l *Limits) { l.Entries = 3 })); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	_, err := fetch(t, "s.tar", data, lim(func(l *Limits) { l.Entries = 2 }))
	wantLimit(t, err, LimitEntries)
	zdata := zipBytes(t, zipEntry{name: "p/", mode: fs.ModeDir | 0o755}, zipEntry{name: "p/a.py", body: []byte("1")})
	_, err = fetch(t, "s.zip", zdata, lim(func(l *Limits) { l.Entries = 1 }))
	wantLimit(t, err, LimitEntries)
}

func TestEntriesLimitCountsRejectedTypesFirst(t *testing.T) {
	// The count is checked before the entry type: a symlink is still an entry.
	data := tarBytes(t, false, tarEntry{name: "p/a.py", body: "1"}, tarEntry{name: "p/l", typ: tar.TypeSymlink, link: "a.py"})
	_, err := fetch(t, "s.tar", data, lim(func(l *Limits) { l.Entries = 1 }))
	wantLimit(t, err, LimitEntries)
}

func TestPathBytesLimit(t *testing.T) {
	name := "p/" + strings.Repeat("a", 30) + ".py" // 35 bytes
	data := tarBytes(t, false, tarEntry{name: name, body: "1"})
	if _, err := fetch(t, "s.tar", data, lim(func(l *Limits) { l.PathBytes = 35 })); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	_, err := fetch(t, "s.tar", data, lim(func(l *Limits) { l.PathBytes = 34 }))
	wantLimit(t, err, LimitPathBytes)
}

var slipNames = []string{
	"../escape.py",
	"p/../../escape.py",
	"p/../escape.py", // any '..' component, even one that stays inside
	"/etc/passwd",
	"C:/windows/x.py",
	"..\\escape.py",
	"p/a\x00.py",
}

// rawPAXTar builds a tar whose PAX "path" record is raw (archive/tar's writer
// refuses NUL), followed by a regular file of one byte.
func rawPAXTar(path string) []byte {
	block := func(name string, typ byte, size int) []byte {
		b := make([]byte, 512)
		copy(b[0:], name)
		copy(b[100:], "0000644\x00")
		copy(b[108:], "0000000\x00")
		copy(b[116:], "0000000\x00")
		copy(b[124:], fmt.Sprintf("%011o\x00", size))
		copy(b[136:], "00000000000\x00")
		b[156] = typ
		copy(b[257:], "ustar\x0000")
		copy(b[148:], "        ")
		sum := 0
		for _, c := range b {
			sum += int(c)
		}
		copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
		return b
	}
	pad := func(n int) []byte { return make([]byte, (512-n%512)%512) }
	rec := " path=" + path + "\n"
	rec = fmt.Sprintf("%d%s", len(rec)+len(fmt.Sprint(len(rec)+2)), rec)
	var buf bytes.Buffer
	buf.Write(block("pax", 'x', len(rec)))
	buf.WriteString(rec)
	buf.Write(pad(len(rec)))
	buf.Write(block("placeholder", '0', 1))
	buf.WriteString("x")
	buf.Write(pad(1))
	buf.Write(make([]byte, 1024))
	return buf.Bytes()
}

func TestNULInTarPathFailsTheArchive(t *testing.T) {
	// Go's tar reader rejects a NUL in a PAX path itself (ErrHeader); the
	// archive fails either way and nothing is written for it.
	dest := t.TempDir()
	uri, digest := stage(t, "s.tar", rawPAXTar("p/a\x00.py"))
	if _, err := FetchWithLimits(context.Background(), uri, digest, dest, nil, DefaultLimits); err == nil {
		t.Fatal("NUL in a tar path must fail")
	}
	if _, err := os.Stat(filepath.Join(dest, "tree", "p")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("no entry may be written")
	}
	// The same raw writer with a clean path is accepted, so the rejection is the NUL.
	uri, digest = stage(t, "s.tar", rawPAXTar("p/a.py"))
	if _, err := FetchWithLimits(context.Background(), uri, digest, t.TempDir(), nil, DefaultLimits); err != nil {
		t.Fatalf("control archive: %v", err)
	}
}

func TestZipSlipTar(t *testing.T) {
	for _, gz := range []bool{false, true} {
		for _, name := range slipNames {
			if strings.ContainsRune(name, 0) {
				continue // archive/tar cannot write it; see TestNULInTarPathFailsTheArchive
			}
			data := tarBytes(t, gz, tarEntry{name: "p/ok.py", body: "1"}, tarEntry{name: name, body: "evil"})
			dest := t.TempDir()
			name := "s.tar"
			if gz {
				name = "s.tgz"
			}
			uri, digest := stage(t, name, data)
			_, err := FetchWithLimits(context.Background(), uri, digest, dest, nil, DefaultLimits)
			wantLimit(t, err, LimitPath)
			if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.py")); err == nil {
				t.Fatalf("%q escaped the work dir", name)
			}
		}
	}
}

func TestZipSlipZip(t *testing.T) {
	for _, name := range slipNames {
		data := zipBytes(t, zipEntry{name: "p/ok.py", body: []byte("1")}, zipEntry{name: name, body: []byte("evil")})
		_, err := fetch(t, "s.zip", data, DefaultLimits)
		wantLimit(t, err, LimitPath)
	}
}

func TestDuplicatePathsAfterNormalization(t *testing.T) {
	for _, pair := range [][2]string{
		{"p/a.py", "p/a.py"},
		{"p/a.py", "p/./a.py"},
		{"p/a.py", "p//a.py"},
		{"p/d/", "p/d"}, // directory twice
	} {
		tdata := tarBytes(t, false, tarEntry{name: pair[0], body: "1"}, tarEntry{name: pair[1], body: "2"})
		_, err := fetch(t, "s.tar", tdata, DefaultLimits)
		wantLimit(t, err, LimitPath)
		zdata := zipBytes(t, zipEntry{name: pair[0], body: []byte("1")}, zipEntry{name: pair[1], body: []byte("2")})
		_, err = fetch(t, "s.zip", zdata, DefaultLimits)
		wantLimit(t, err, LimitPath)
	}
}

func TestFileAndDirectoryCollision(t *testing.T) {
	// A file "p/a" and then a file below "p/a/" cannot both exist.
	data := tarBytes(t, false, tarEntry{name: "p/a", body: "1"}, tarEntry{name: "p/a/b.py", body: "2"})
	_, err := fetch(t, "s.tar", data, DefaultLimits)
	wantLimit(t, err, LimitPath)
}

// --- entry types --------------------------------------------------------------

func TestNonRegularTarEntriesRejectWholeArchive(t *testing.T) {
	for _, e := range []tarEntry{
		{name: "p/link", typ: tar.TypeSymlink, link: "/etc/passwd"},
		{name: "p/hard", typ: tar.TypeLink, link: "p/a.py"},
		{name: "p/chr", typ: tar.TypeChar},
		{name: "p/blk", typ: tar.TypeBlock},
		{name: "p/fifo", typ: tar.TypeFifo},
	} {
		data := tarBytes(t, true, tarEntry{name: "p/a.py", body: "1"}, e)
		_, err := fetch(t, "s.tgz", data, DefaultLimits)
		wantLimit(t, err, LimitEntryType)
	}
}

func TestNonRegularZipEntriesRejectWholeArchive(t *testing.T) {
	for _, mode := range []fs.FileMode{fs.ModeSymlink | 0o777, fs.ModeDevice | 0o600, fs.ModeNamedPipe | 0o600,
		fs.ModeDevice | fs.ModeCharDevice | 0o600, fs.ModeSocket | 0o600} {
		data := zipBytes(t, zipEntry{name: "p/a.py", body: []byte("1")}, zipEntry{name: "p/x", body: []byte("/etc/passwd"), mode: mode})
		_, err := fetch(t, "s.zip", data, DefaultLimits)
		wantLimit(t, err, LimitEntryType)
	}
}

// --- streaming ----------------------------------------------------------------

// genReader yields n bytes of a valid tar archive holding one large file,
// generated on the fly so the test itself never holds the archive.
func genTar(t *testing.T, size int64) (io.Reader, int64, string) {
	t.Helper()
	var hdr bytes.Buffer
	tw := tar.NewWriter(&hdr)
	tw.WriteHeader(&tar.Header{Name: "p/big.bin", Mode: 0o644, Size: size, Typeflag: tar.TypeReg})
	tw.Flush()
	header := append([]byte(nil), hdr.Bytes()...)
	pad := (512 - size%512) % 512
	trailer := make([]byte, pad+1024)
	body := io.LimitReader(zeroReader{}, size)
	r := io.MultiReader(bytes.NewReader(header), body, bytes.NewReader(trailer))
	total := int64(len(header)) + size + int64(len(trailer))
	h := sha256.New()
	io.Copy(h, io.MultiReader(bytes.NewReader(header), io.LimitReader(zeroReader{}, size), bytes.NewReader(trailer)))
	return r, total, hex.EncodeToString(h.Sum(nil))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// onceObjects serves one object from a reader that can be consumed only once.
type onceObjects struct {
	r     io.Reader
	size  int64
	opens int
}

func (o *onceObjects) BucketName() string { return "disc-bucket" }
func (o *onceObjects) ObjectSize(context.Context, string) (int64, error) {
	return o.size, nil
}
func (o *onceObjects) OpenObject(context.Context, string) (io.ReadCloser, error) {
	o.opens++
	if o.opens > 1 {
		return nil, errors.New("object opened twice")
	}
	return io.NopCloser(o.r), nil
}

func TestArchiveIsStreamedNotBuffered(t *testing.T) {
	const fileSize = 48 << 20
	r, total, digest := genTar(t, fileSize)
	objs := &onceObjects{r: r, size: total}
	uri := "gs://disc-bucket/sources/" + digest + ".tar"
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	root, err := FetchWithLimits(context.Background(), uri, digest, t.TempDir(), objs, lim(func(l *Limits) {
		l.FileBytes, l.ExtractedBytes = 64<<20, 64<<20
	}))
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(root, "big.bin")); err != nil || st.Size() != fileSize {
		t.Fatalf("extracted file: %v %v", st, err)
	}
	if objs.opens != 1 {
		t.Fatalf("object opened %d times", objs.opens)
	}
	// Buffering the archive or the entry would allocate at least 48MiB.
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 8<<20 {
		t.Fatalf("allocated %d bytes for a %d byte archive: not streamed", alloc, total)
	}
}

// --- gs:// sources --------------------------------------------------------------

// memObjects is an in-memory Objects; sizes overrides the reported size.
type memObjects struct {
	bucket  string
	objects map[string][]byte
	sizes   map[string]int64
	reads   []string
}

func (m *memObjects) BucketName() string { return m.bucket }

func (m *memObjects) ObjectSize(_ context.Context, key string) (int64, error) {
	data, ok := m.objects[key]
	if !ok {
		return 0, fs.ErrNotExist
	}
	if n, ok := m.sizes[key]; ok {
		return n, nil
	}
	return int64(len(data)), nil
}

func (m *memObjects) OpenObject(_ context.Context, key string) (io.ReadCloser, error) {
	m.reads = append(m.reads, key)
	data, ok := m.objects[key]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func stagedGS(t *testing.T, bucket string) (*memObjects, string, string) {
	t.Helper()
	data := tarBytes(t, true, tarEntry{name: "httpx-0.27.0/httpx/_client.py", body: "x = 1\n"})
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	objs := &memObjects{bucket: bucket, objects: map[string][]byte{"sources/" + digest + ".tar.gz": data}}
	return objs, "gs://" + bucket + "/sources/" + digest + ".tar.gz", digest
}

func TestFetchGCSStagedArchive(t *testing.T) {
	objs, uri, digest := stagedGS(t, "disc-bucket")
	root, err := Fetch(context.Background(), uri, digest, t.TempDir(), objs)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(root, "httpx", "_client.py")); err != nil || string(b) != "x = 1\n" {
		t.Fatalf("extracted: %q %v", b, err)
	}
}

func TestFetchRejectsBadInputs(t *testing.T) {
	ctx := context.Background()
	d := strings.Repeat("a", 64)
	objs := &memObjects{bucket: "disc-bucket", objects: map[string][]byte{}}
	for _, tc := range []struct{ uri, digest string }{
		{"file:///x.tar.gz", "ABC"},
		{"http://example.com/x.tar.gz", d},
		// No https or VCS fetching from the Job (SSRF; no Cloud NAT).
		{"https://example.com/x.tar.gz", d},
		{"git+https://example.com/r#" + strings.Repeat("a", 40), d},
		{"file:///x.rar", d},
	} {
		if _, err := Fetch(ctx, tc.uri, tc.digest, t.TempDir(), objs); err == nil {
			t.Errorf("%s: want error", tc.uri)
		}
	}
	if len(objs.reads) != 0 {
		t.Fatalf("no bucket object may be read: %v", objs.reads)
	}
}

func TestFetchGCSRejectsWrongBucketAndName(t *testing.T) {
	ctx := context.Background()
	objs, uri, digest := stagedGS(t, "disc-bucket")
	other := strings.Repeat("b", 64)
	for name, tc := range map[string]struct{ uri, digest string }{
		"other bucket":             {strings.Replace(uri, "gs://disc-bucket/", "gs://other-bucket/", 1), digest},
		"name digest differs":      {strings.Replace(uri, digest, other, 1), digest},
		"digest differs from name": {uri, other},
		"not under sources/":       {strings.Replace(uri, "/sources/", "/snapshots/", 1), digest},
		"nested path":              {strings.Replace(uri, "/sources/", "/sources/x/", 1), digest},
		"bad extension":            {strings.Replace(uri, ".tar.gz", ".rar", 1), digest},
	} {
		if _, err := Fetch(ctx, tc.uri, tc.digest, t.TempDir(), objs); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if len(objs.reads) != 0 {
		t.Fatalf("rejected URIs must not read the bucket: %v", objs.reads)
	}
	if _, err := Fetch(ctx, uri, digest, t.TempDir(), nil); err == nil {
		t.Error("gs:// without a gs:// out-root must fail")
	}
}

func TestFetchGCSSizeLimits(t *testing.T) {
	ctx := context.Background()

	// Oversize by the stored size: rejected before any download.
	objs, uri, digest := stagedGS(t, "disc-bucket")
	objs.sizes = map[string]int64{"sources/" + digest + ".tar.gz": DefaultLimits.ArchiveBytes + 1}
	_, err := Fetch(ctx, uri, digest, t.TempDir(), objs)
	wantLimit(t, err, LimitArchiveBytes)
	if len(objs.reads) != 0 {
		t.Fatal("oversize object must not be downloaded")
	}

	// Oversize by the stream (size reported small): the read is capped.
	objs, uri, digest = stagedGS(t, "disc-bucket")
	key := "sources/" + digest + ".tar.gz"
	objs.sizes = map[string]int64{key: 1}
	_, err = FetchWithLimits(ctx, uri, digest, t.TempDir(), objs, lim(func(l *Limits) {
		l.ArchiveBytes = int64(len(objs.objects[key])) - 1
	}))
	wantLimit(t, err, LimitArchiveBytes)
}

func TestDefaultLimitsMatchContract(t *testing.T) {
	want := Limits{ArchiveBytes: 256 << 20, ExtractedBytes: 1 << 30, FileBytes: 64 << 20, Entries: 50000, PathBytes: 512}
	if DefaultLimits != want {
		t.Fatalf("limits = %+v, want %+v", DefaultLimits, want)
	}
}

func TestEntriesLimitCountsImplicitDirectories(t *testing.T) {
	for _, format := range []string{"tar", "tgz", "zip"} {
		t.Run(format, func(t *testing.T) {
			data := tarBytes(t, format == "tgz", tarEntry{name: "p/a/b/c/f.py", body: "1"})
			if format == "zip" {
				data = zipBytes(t, zipEntry{name: "p/a/b/c/f.py", body: []byte("1")})
			}
			if _, err := fetch(t, "s."+format, data, lim(func(l *Limits) { l.Entries = 5 })); err != nil {
				t.Fatalf("at the limit: %v", err)
			}
			_, err := fetch(t, "s."+format, data, lim(func(l *Limits) { l.Entries = 4 }))
			wantLimit(t, err, LimitEntries)
		})
	}
}

func TestEntriesLimitReusesImplicitParents(t *testing.T) {
	data := tarBytes(t, false, tarEntry{name: "p/d/a.py", body: "1"}, tarEntry{name: "p/d/b.py", body: "2"})
	if _, err := fetch(t, "s.tar", data, lim(func(l *Limits) { l.Entries = 4 })); err != nil {
		t.Fatalf("shared implicit parents counted twice: %v", err)
	}
}

func TestDeepPathAmplificationStopsBeforeCreatingParents(t *testing.T) {
	var entries []tarEntry
	for i := 0; i < 40; i++ {
		entries = append(entries, tarEntry{name: fmt.Sprintf("p/%d/", i) + strings.Repeat("d/", 10) + "f", body: "x"})
	}
	uri, digest := stage(t, "s.tgz", tarBytes(t, true, entries...))
	dest := t.TempDir()
	_, err := FetchWithLimits(context.Background(), uri, digest, dest, nil, lim(func(l *Limits) { l.Entries = 100 }))
	wantLimit(t, err, LimitEntries)
	count := 0
	err = filepath.WalkDir(filepath.Join(dest, "tree"), func(_ string, _ fs.DirEntry, err error) error {
		if err == nil {
			count++
		}
		return err
	})
	if err != nil || count-1 > 100 {
		t.Fatalf("filesystem entries=%d, err=%v", count-1, err)
	}
}

func TestPAXGlobalHeaderRemainsRejected(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "abc123"}}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := fetch(t, "git.tar", buf.Bytes(), DefaultLimits)
	wantLimit(t, err, LimitEntryType)
}

func TestZipEntriesBoundedBeforeParsingForgedEOCD(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 65537; i++ {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprint(i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	// archive/zip accepts the low 16 bits of the directory count. An EOCD
	// precheck would see one entry, while the parser still allocates 65,537.
	eocd := bytes.LastIndex(data, []byte("PK\x05\x06"))
	copy(data[eocd+8:eocd+12], []byte{1, 0, 1, 0})
	uri, digest := stage(t, "s.zip", data)
	dest := t.TempDir()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := FetchWithLimits(context.Background(), uri, digest, dest, nil, DefaultLimits)
	runtime.ReadMemStats(&after)
	wantLimit(t, err, LimitEntries)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("allocated %d MiB before rejection", allocated>>20)
	}
}

func TestZipDirectorySignatureAcrossScanBufferBoundary(t *testing.T) {
	data := append(bytes.Repeat([]byte{'x'}, (1<<20)-2), []byte("PK\x01\x02")...)
	p := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := countZipDirectoryHeaders(p, 0); n != 1 || err != nil {
		t.Fatalf("count=%d, err=%v", n, err)
	}
}

func TestFilesystemNameTooLongReportsPathBytes(t *testing.T) {
	for _, name := range []string{strings.Repeat("a", 256), strings.Repeat("a", 256) + "/f"} {
		_, err := fetch(t, "s.tar", tarBytes(t, false, tarEntry{name: name, body: "1"}), DefaultLimits)
		wantLimit(t, err, LimitPathBytes)
	}
}

func TestRelativeColonPathsAllowed(t *testing.T) {
	for _, name := range []string{"a:b.py", "1:b.py", "1:/b.py"} {
		if _, err := fetch(t, "s.tar", tarBytes(t, false, tarEntry{name: name, body: "1"}), DefaultLimits); err != nil {
			t.Fatalf("relative path %q rejected: %v", name, err)
		}
	}
}
