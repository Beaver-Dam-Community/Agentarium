// Package source reads a pinned library source archive, checks source_digest
// and extracts it into a working directory.
//
// In GKE the operator stages the archive in the discovery bucket as
// gs://<discovery-bucket>/sources/<source_digest>.<ext> (TASK-02 3.4, PR #8).
// The Job never fetches over https or from a VCS: an outbound fetch could probe
// in-cluster HTTPS services (SSRF), and the private nodes have no Cloud NAT.
//
// The archive is untrusted input (TASK-02 3.4 "archive processing limits", PR #22):
// it is streamed to a file in the work dir while its SHA-256 is computed,
// checked against source_digest before anything is extracted, and extracted
// entry by entry straight to disk. Neither the archive nor an entry is held
// in memory, so peak memory does not grow with the archive. Any exceeded
// limit, unsafe path or non-regular entry fails the whole archive.
package source

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Limits are the archive limits of TASK-02 3.4.
type Limits struct {
	ArchiveBytes   int64 // staged archive size
	ExtractedBytes int64 // bytes actually written for all files
	FileBytes      int64 // bytes actually written for one file
	Entries        int   // every entry: files, directories and rejected types
	PathBytes      int   // entry path length
}

var DefaultLimits = Limits{
	ArchiveBytes:   256 << 20,
	ExtractedBytes: 1 << 30,
	FileBytes:      64 << 20,
	Entries:        50000,
	PathBytes:      512,
}

// Limit names reported in the failure (TASK-02 3.4).
const (
	LimitArchiveBytes   = "archive_bytes"
	LimitExtractedBytes = "extracted_bytes"
	LimitFileBytes      = "file_bytes"
	LimitEntries        = "entries"
	LimitPathBytes      = "path_bytes"
	LimitEntryType      = "entry_type"
	LimitPath           = "path"
)

// LimitError rejects the whole archive; Limit is one of the names above.
type LimitError struct {
	Limit  string
	Detail string
}

func (e *LimitError) Error() string { return "archive limit " + e.Limit + ": " + e.Detail }

func limitErr(limit, format string, args ...any) error {
	return &LimitError{Limit: limit, Detail: fmt.Sprintf(format, args...)}
}

var (
	digestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	gsRe     = regexp.MustCompile(`^gs://([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])/sources/([0-9a-f]{64})\.(tar\.gz|tgz|tar|zip|whl)$`)
)

var ErrDigestMismatch = errors.New("source_digest mismatch")

// Objects reads objects from the discovery bucket (the Job's out-root).
type Objects interface {
	// BucketName is the bucket the Job writes snapshots to.
	BucketName() string
	// ObjectSize returns the stored object size without downloading it.
	ObjectSize(ctx context.Context, key string) (int64, error)
	// OpenObject streams the object content.
	OpenObject(ctx context.Context, key string) (io.ReadCloser, error)
}

// Fetch is FetchWithLimits with DefaultLimits.
func Fetch(ctx context.Context, uri, want, dest string, objs Objects) (string, error) {
	return FetchWithLimits(ctx, uri, want, dest, objs, DefaultLimits)
}

// FetchWithLimits resolves uri, streams the archive to dest/archive while
// computing its SHA-256, checks it against want, and extracts it under
// dest/tree. It returns the extracted root (the archive's shared top-level
// directory stripped).
//
// Supported forms:
//
//	gs://<bucket>/sources/<want>.tar.gz|.tgz|.tar|.zip|.whl  staged archive;
//	    bucket must be the Job's own bucket (objs) and the name must carry want
//	file:///abs/path/x.tar.gz                                local archive (tests, local runs)
func FetchWithLimits(ctx context.Context, uri, want, dest string, objs Objects, lim Limits) (string, error) {
	if !digestRe.MatchString(want) {
		return "", fmt.Errorf("source_digest must be 64 lowercase hex")
	}
	r, size, kind, err := open(ctx, uri, want, objs)
	if err != nil {
		return "", err
	}
	defer r.Close()
	// The stored size is checked before reading anything.
	if size > lim.ArchiveBytes {
		return "", limitErr(LimitArchiveBytes, "archive is %d bytes, limit %d", size, lim.ArchiveBytes)
	}
	archive := filepath.Join(dest, "archive")
	sum, err := spool(r, archive, lim.ArchiveBytes)
	if err != nil {
		return "", err
	}
	if sum != want {
		return "", ErrDigestMismatch
	}
	tree := filepath.Join(dest, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		return "", err
	}
	x := &extractor{root: tree, lim: lim, names: map[string]bool{}, dirs: map[string]bool{}}
	switch kind {
	case "tgz", "tar":
		err = x.tarFile(archive, kind == "tgz")
	case "zip":
		err = x.zipFile(archive)
	}
	if err != nil {
		return "", err
	}
	// The spooled archive is no longer needed; free its disk budget for the scan.
	if err := os.Remove(archive); err != nil {
		return "", err
	}
	return filepath.Join(tree, filepath.FromSlash(x.prefix())), nil
}

// open returns the archive stream, its stored size and its kind.
func open(ctx context.Context, uri, want string, objs Objects) (io.ReadCloser, int64, string, error) {
	if strings.HasPrefix(uri, "gs://") {
		return openGCS(ctx, uri, want, objs)
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, 0, "", fmt.Errorf("source_uri: %w", err)
	}
	if u.Scheme != "file" {
		return nil, 0, "", fmt.Errorf("unsupported source_uri scheme %q: stage the archive at gs://<discovery-bucket>/sources/<source_digest>.<ext>", u.Scheme)
	}
	kind, err := archiveKind(u.Path)
	if err != nil {
		return nil, 0, "", err
	}
	f, err := os.Open(u.Path)
	if err != nil {
		return nil, 0, "", err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, "", err
	}
	return f, st.Size(), kind, nil
}

func openGCS(ctx context.Context, uri, want string, objs Objects) (io.ReadCloser, int64, string, error) {
	m := gsRe.FindStringSubmatch(uri)
	if m == nil {
		return nil, 0, "", fmt.Errorf("source_uri must be gs://<bucket>/sources/<source_digest>.<tar.gz|tgz|tar|zip|whl>")
	}
	bucket, nameDigest, ext := m[1], m[2], m[3]
	if objs == nil {
		return nil, 0, "", fmt.Errorf("gs:// source_uri needs a gs:// out-root")
	}
	if bucket != objs.BucketName() {
		return nil, 0, "", fmt.Errorf("source_uri bucket %q is not the discovery bucket %q", bucket, objs.BucketName())
	}
	if nameDigest != want {
		return nil, 0, "", fmt.Errorf("source_uri object name does not carry source_digest")
	}
	key := "sources/" + nameDigest + "." + ext
	kind, err := archiveKind(key)
	if err != nil {
		return nil, 0, "", err
	}
	size, err := objs.ObjectSize(ctx, key)
	if err != nil {
		return nil, 0, "", err
	}
	if size < 0 {
		return nil, 0, "", fmt.Errorf("object %s has no size", key)
	}
	// Opening is deferred to the caller's size check: an oversize object is
	// never downloaded.
	return &lazyObject{ctx: ctx, objs: objs, key: key}, size, kind, nil
}

// lazyObject opens the object on first Read, after the size check passed.
type lazyObject struct {
	ctx  context.Context
	objs Objects
	key  string
	r    io.ReadCloser
}

func (l *lazyObject) Read(p []byte) (int, error) {
	if l.r == nil {
		r, err := l.objs.OpenObject(l.ctx, l.key)
		if err != nil {
			return 0, err
		}
		l.r = r
	}
	return l.r.Read(p)
}

func (l *lazyObject) Close() error {
	if l.r == nil {
		return nil
	}
	return l.r.Close()
}

// spool copies r to path, at most limit bytes (enforced while reading, in
// case the object changed after the size check), and returns the SHA-256.
func spool(r io.Reader, dst string, limit int64) (string, error) {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", limitErr(LimitArchiveBytes, "archive is larger than %d bytes", limit)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func archiveKind(p string) (string, error) {
	switch {
	case strings.HasSuffix(p, ".tar.gz"), strings.HasSuffix(p, ".tgz"):
		return "tgz", nil
	case strings.HasSuffix(p, ".tar"):
		return "tar", nil
	case strings.HasSuffix(p, ".zip"), strings.HasSuffix(p, ".whl"):
		return "zip", nil
	}
	return "", fmt.Errorf("unsupported archive type: %s", p)
}

// extractor writes entries under root, enforcing Limits as it goes.
type extractor struct {
	root    string
	lim     Limits
	entries int
	total   int64
	names   map[string]bool // normalized names of all archive entries
	dirs    map[string]bool // explicit and implicit directories created so far
	files   []string        // normalized names of regular files, for prefix()
}

// entry checks one archive entry's name and the entry count; it returns the
// normalized name.
func (x *extractor) entry(name string) (string, error) {
	x.entries++
	if x.entries > x.lim.Entries {
		return "", limitErr(LimitEntries, "more than %d entries", x.lim.Entries)
	}
	if len(name) > x.lim.PathBytes {
		return "", limitErr(LimitPathBytes, "path of %d bytes, limit %d", len(name), x.lim.PathBytes)
	}
	if strings.ContainsRune(name, 0) {
		return "", limitErr(LimitPath, "NUL in path %q", name)
	}
	// Backslashes are treated as separators so "..\\x" cannot slip through.
	slashed := strings.ReplaceAll(name, "\\", "/")
	driveAbsolute := len(slashed) >= 3 && slashed[1:3] == ":/" &&
		((slashed[0] >= 'a' && slashed[0] <= 'z') || (slashed[0] >= 'A' && slashed[0] <= 'Z'))
	if strings.HasPrefix(slashed, "/") || driveAbsolute {
		return "", limitErr(LimitPath, "absolute path %q", name)
	}
	for _, part := range strings.Split(slashed, "/") {
		if part == ".." {
			return "", limitErr(LimitPath, "'..' in path %q", name)
		}
	}
	clean := path.Clean(slashed)
	if x.names[clean] {
		return "", limitErr(LimitPath, "duplicate path %q", clean)
	}
	x.names[clean] = true
	return clean, nil
}

func (x *extractor) dir(clean string) error {
	if clean == "." {
		return nil
	}
	return x.mkdir(clean)
}

func (x *extractor) mkdir(clean string) error {
	// Bound filesystem entries even when the archive omits parent headers.
	// Explicit directory headers were counted by entry(). A later explicit
	// header for an implicit directory is conservatively counted again.
	for d := clean; d != "." && !x.dirs[d]; d = path.Dir(d) {
		x.dirs[d] = true
		if d != clean || !x.names[d] {
			x.entries++
		}
		if x.entries > x.lim.Entries {
			return limitErr(LimitEntries, "more than %d entries", x.lim.Entries)
		}
	}
	dst := filepath.Join(x.root, filepath.FromSlash(clean))
	if err := os.MkdirAll(dst, 0o755); err != nil {
		if errors.Is(err, syscall.ENAMETOOLONG) {
			return limitErr(LimitPathBytes, "filesystem path too long: %q", clean)
		}
		// A file already holds part of this path.
		return limitErr(LimitPath, "path %q collides with a file", clean)
	}
	return nil
}

// file streams one regular file to disk, counting the bytes actually written.
func (x *extractor) file(clean string, r io.Reader) error {
	if clean == "." {
		return limitErr(LimitPath, "file without a name")
	}
	if dir := path.Dir(clean); dir != "." {
		if err := x.mkdir(dir); err != nil {
			return err
		}
	}
	dst := filepath.Join(x.root, filepath.FromSlash(clean))
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if errors.Is(err, syscall.ENAMETOOLONG) {
			return limitErr(LimitPathBytes, "filesystem path too long: %q", clean)
		}
		if errors.Is(err, fs.ErrExist) {
			return limitErr(LimitPath, "path %q collides with another entry", clean)
		}
		return err
	}
	// Read one byte past whichever limit is closer to tell which one was hit.
	room := x.lim.ExtractedBytes - x.total
	capBytes := min(x.lim.FileBytes, room)
	n, err := io.Copy(f, io.LimitReader(r, capBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > capBytes {
		if capBytes == x.lim.FileBytes {
			return limitErr(LimitFileBytes, "%s is larger than %d bytes", clean, x.lim.FileBytes)
		}
		return limitErr(LimitExtractedBytes, "extracted size larger than %d bytes", x.lim.ExtractedBytes)
	}
	x.total += n
	x.files = append(x.files, clean)
	return nil
}

func (x *extractor) tarFile(archive string, gz bool) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if gz {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		clean, err := x.entry(h.Name)
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeReg, tar.TypeRegA: //nolint:staticcheck // TypeRegA is still produced by old tar writers
			if err := x.file(clean, tr); err != nil {
				return err
			}
		case tar.TypeDir:
			if err := x.dir(clean); err != nil {
				return err
			}
		default:
			// Links, devices, fifos, sparse files and anything else (TASK-02 3.4).
			return limitErr(LimitEntryType, "%q has tar type %q", h.Name, string(h.Typeflag))
		}
	}
}

// countZipDirectoryHeaders bounds archive/zip's eager directory allocation.
// Scan signatures rather than trusting the EOCD count (which may wrap) or size.
// A signature in member data only raises the count, conservatively rejecting
// the archive. The spool is already bounded by ArchiveBytes.
func countZipDirectoryHeaders(name string, limit int) (int, error) {
	f, err := os.Open(name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<20)
	var window uint32
	n := 0
	for n <= limit {
		b, err := r.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, err
		}
		window = window>>8 | uint32(b)<<24
		if window == 0x02014b50 { // PK\x01\x02
			n++
		}
	}
	return n, nil
}

func (x *extractor) zipFile(archive string) error {
	n, err := countZipDirectoryHeaders(archive, x.lim.Entries)
	if err != nil {
		return err
	}
	if n > x.lim.Entries {
		return limitErr(LimitEntries, "more than %d entries", x.lim.Entries)
	}
	zr, err := zip.OpenReader(archive) // the on-disk spool is the ReaderAt
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		clean, err := x.entry(zf.Name)
		if err != nil {
			return err
		}
		mode := zf.Mode()
		switch {
		case mode.IsDir():
			if err := x.dir(clean); err != nil {
				return err
			}
		case mode.IsRegular():
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			err = x.file(clean, rc)
			rc.Close()
			if err != nil {
				return err
			}
		default:
			return limitErr(LimitEntryType, "%q has mode %v", zf.Name, mode)
		}
	}
	return nil
}

// prefix is the archive's top-level directory to strip: one shared first
// component (sdist "pkg-1.0/"), or everything through a shared
// "module@version" component (Go module zip). "" when there is none.
func (x *extractor) prefix() string {
	if len(x.files) == 0 {
		return ""
	}
	common := strings.Split(x.files[0], "/")
	common = common[:len(common)-1]
	for _, name := range x.files[1:] {
		parts := strings.Split(name, "/")
		parts = parts[:len(parts)-1]
		n := 0
		for n < len(common) && n < len(parts) && common[n] == parts[n] {
			n++
		}
		common = common[:n]
	}
	cut := 0
	for i, c := range common {
		if strings.Contains(c, "@") {
			cut = i + 1
		}
	}
	if cut == 0 && len(common) > 0 {
		cut = 1
	}
	return strings.Join(common[:cut], "/")
}
