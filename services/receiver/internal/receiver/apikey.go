package receiver

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Receiver API key (M3-1 contract for #169, not yet in COMMON):
//
//   - --api-key-dir holds one regular file per active Secret Manager version.
//     The file name is the decimal version, the content is the raw 43-char
//     unpadded base64url key (32 random bytes), with at most one trailing
//     newline. Entries whose names start with "." (CSI "..data" etc.) are
//     ignored; symlinks to regular files are followed; any other name is a
//     configuration error. Exactly 1 or 2 version files are allowed.
//   - The directory is re-read every KeyReloadInterval. A failed reload keeps
//     the last good set; a failed first load stops the receiver.
//   - POST /test/v1/submissions needs X-Agentarium-Receiver-Key. A missing or
//     wrong key is 401 RECEIVER_KEY_INVALID, checked after the mTLS SAN check
//     and before any DB write. The value is compared with every active key in
//     constant time without early exit. Only the matched version is logged.
//   - GET /test/v1/receipts/{action_id} uses mTLS only.
const (
	HeaderReceiverKey = "X-Agentarium-Receiver-Key"
	KeyReloadInterval = 30 * time.Second
	keyBytes          = 32
	keyChars          = 43 // base64url without padding of 32 bytes
	maxKeyFileBytes   = keyChars + 1
	maxKeyVersions    = 2
)

var versionName = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)

// apiKey is one active Secret Manager version.
type apiKey struct {
	version string
	key     [keyBytes]byte
}

// LoadKeyDir reads and validates the key directory. It never returns a
// partial set.
func LoadKeyDir(dir string) ([]apiKey, error) {
	if dir == "" {
		return nil, errors.New("receiver api key directory is required")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var keys []apiKey
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		if !versionName.MatchString(name) {
			return nil, fmt.Errorf("receiver api key directory: unexpected entry %q", name)
		}
		path := filepath.Join(dir, name)
		info, err := os.Stat(path) // follows a symlink to its target
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("receiver api key version %s is not a regular file", name)
		}
		if info.Size() > maxKeyFileBytes {
			return nil, fmt.Errorf("receiver api key version %s has an invalid length", name)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		k, ok := decodeKey(strings.TrimSuffix(string(raw), "\n"))
		if !ok {
			return nil, fmt.Errorf("receiver api key version %s is not a 43-char base64url key", name)
		}
		keys = append(keys, apiKey{version: name, key: k})
	}
	if len(keys) < 1 || len(keys) > maxKeyVersions {
		return nil, fmt.Errorf("receiver api key directory has %d versions, want 1 or 2", len(keys))
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].version < keys[j].version })
	return keys, nil
}

// decodeKey accepts only the canonical unpadded base64url form of 32 bytes.
func decodeKey(s string) ([keyBytes]byte, bool) {
	var out [keyBytes]byte
	if len(s) != keyChars {
		return out, false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != keyBytes {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

// KeySet is the receiver's active key set, safe for concurrent use.
type KeySet struct {
	dir  string
	mu   sync.RWMutex
	keys []apiKey
}

// NewKeySet loads dir once; an error must stop the receiver.
func NewKeySet(dir string) (*KeySet, error) {
	keys, err := LoadKeyDir(dir)
	if err != nil {
		return nil, err
	}
	return &KeySet{dir: dir, keys: keys}, nil
}

// Reload re-reads the directory. On error the last good set stays active.
func (s *KeySet) Reload() error {
	keys, err := LoadKeyDir(s.dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return nil
}

// Run reloads every interval until ctx ends.
func (s *KeySet) Run(ctx context.Context, interval time.Duration, log *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Reload(); err != nil && log != nil {
				log.Error("receiver api key reload failed; keeping the last good set", "err", err)
			}
		}
	}
}

// Versions returns the active versions (for logs; never key material).
func (s *KeySet) Versions() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.keys))
	for i, k := range s.keys {
		out[i] = k.version
	}
	return out
}

// Match returns the version whose key equals the request header, or false.
// Every active key is compared in constant time; there is no early exit.
func (s *KeySet) Match(h http.Header) (string, bool) {
	if s == nil {
		return "", false
	}
	vals := h.Values(HeaderReceiverKey)
	if len(vals) != 1 {
		return "", false
	}
	got, ok := decodeKey(vals[0])
	s.mu.RLock()
	keys := s.keys
	s.mu.RUnlock()
	matched := -1
	for i := range keys {
		eq := subtle.ConstantTimeCompare(got[:], keys[i].key[:])
		matched = subtle.ConstantTimeSelect(eq, i, matched)
	}
	if !ok || matched < 0 {
		return "", false
	}
	return keys[matched].version, true
}
