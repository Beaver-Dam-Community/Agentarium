package receiver

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newKey(t *testing.T) string {
	t.Helper()
	b := make([]byte, keyBytes)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func header(v ...string) http.Header {
	h := http.Header{}
	for _, s := range v {
		h.Add(HeaderReceiverKey, s)
	}
	return h
}

func TestLoadKeyDirAccepts(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	dir := t.TempDir()
	writeFile(t, dir, "7", k1+"\n") // one trailing newline is allowed
	writeFile(t, dir, "12", k2)
	writeFile(t, dir, "..data", "ignored")
	if err := os.Mkdir(filepath.Join(dir, "..2026_10_18"), 0o700); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadKeyDir(dir)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys %v err %v", keys, err)
	}
	s := &KeySet{dir: dir, keys: keys}
	for want, k := range map[string]string{"7": k1, "12": k2} {
		if v, ok := s.Match(header(k)); !ok || v != want {
			t.Fatalf("key %s matched %q %v", want, v, ok)
		}
	}
}

func TestLoadKeyDirFollowsSymlinkToRegularFile(t *testing.T) {
	// CSI layout: <dir>/3 -> ..data/3 -> ..<ts>/3.
	dir := t.TempDir()
	ts := filepath.Join(dir, "..2026_10_18_00_00_00.1")
	if err := os.Mkdir(ts, 0o700); err != nil {
		t.Fatal(err)
	}
	k := newKey(t)
	writeFile(t, ts, "3", k)
	if err := os.Symlink(filepath.Base(ts), filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "3"), filepath.Join(dir, "3")); err != nil {
		t.Fatal(err)
	}
	s, err := NewKeySet(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s.Match(header(k)); !ok || v != "3" {
		t.Fatalf("matched %q %v", v, ok)
	}
}

func TestLoadKeyDirRejects(t *testing.T) {
	good := newKey(t)
	cases := map[string]func(t *testing.T, dir string){
		"empty": func(*testing.T, string) {},
		"three versions": func(t *testing.T, d string) {
			writeFile(t, d, "1", good)
			writeFile(t, d, "2", good)
			writeFile(t, d, "3", good)
		},
		"leading zero":   func(t *testing.T, d string) { writeFile(t, d, "01", good) },
		"zero":           func(t *testing.T, d string) { writeFile(t, d, "0", good) },
		"eleven digits":  func(t *testing.T, d string) { writeFile(t, d, "12345678901", good) },
		"alias latest":   func(t *testing.T, d string) { writeFile(t, d, "latest", good) },
		"other name":     func(t *testing.T, d string) { writeFile(t, d, "1", good); writeFile(t, d, "key.txt", good) },
		"directory":      func(t *testing.T, d string) { _ = os.Mkdir(filepath.Join(d, "4"), 0o700) },
		"padded":         func(t *testing.T, d string) { writeFile(t, d, "1", good+"=") },
		"two newlines":   func(t *testing.T, d string) { writeFile(t, d, "1", good+"\n\n") },
		"crlf":           func(t *testing.T, d string) { writeFile(t, d, "1", good+"\r\n") },
		"std alphabet":   func(t *testing.T, d string) { writeFile(t, d, "1", strings.Repeat("+", keyChars)) },
		"short":          func(t *testing.T, d string) { writeFile(t, d, "1", good[:42]) },
		"non canonical":  func(t *testing.T, d string) { writeFile(t, d, "1", good[:42]+"B") }, // nonzero trailing bits unless good ends so
		"leading space":  func(t *testing.T, d string) { writeFile(t, d, "1", " "+good[:42]) },
		"dangling link":  func(t *testing.T, d string) { _ = os.Symlink("missing", filepath.Join(d, "5")) },
		"one bad of two": func(t *testing.T, d string) { writeFile(t, d, "1", good); writeFile(t, d, "2", "x") },
		"empty key file": func(t *testing.T, d string) { writeFile(t, d, "1", "") },
		"newline only":   func(t *testing.T, d string) { writeFile(t, d, "1", "\n") },
		"oversized file": func(t *testing.T, d string) { writeFile(t, d, "1", good+good) },
		"missing dir":    func(t *testing.T, d string) { _ = os.Remove(d) },
		"symlink to dir": func(t *testing.T, d string) {
			_ = os.Mkdir(filepath.Join(d, "..x"), 0o700)
			_ = os.Symlink("..x", filepath.Join(d, "6"))
		},
		"bad and dotfile": func(t *testing.T, d string) { writeFile(t, d, ".1", good) }, // only dot entries: zero versions
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "keys")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			setup(t, dir)
			if name == "non canonical" {
				if _, ok := decodeKey(good[:42] + "B"); ok {
					t.Skip("random key happens to accept B as the last char")
				}
			}
			if _, err := LoadKeyDir(dir); err == nil {
				t.Fatal("accepted")
			}
			if _, err := NewKeySet(dir); err == nil {
				t.Fatal("start accepted an invalid key directory")
			}
		})
	}
	if _, err := LoadKeyDir(""); err == nil {
		t.Fatal("empty dir flag accepted")
	}
}

func TestReloadRotationKeepsLastGoodSet(t *testing.T) {
	v1, v2, v3 := newKey(t), newKey(t), newKey(t)
	dir := t.TempDir()
	writeFile(t, dir, "1", v1)
	s, err := NewKeySet(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Rotation step 1: the new version is added; both are accepted.
	writeFile(t, dir, "2", v2)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	for want, k := range map[string]string{"1": v1, "2": v2} {
		if v, ok := s.Match(header(k)); !ok || v != want {
			t.Fatalf("during rotation %s: %q %v", want, v, ok)
		}
	}
	// A broken directory (a third version) is rejected; the two keys stay.
	writeFile(t, dir, "3", v3)
	if err := s.Reload(); err == nil {
		t.Fatal("three versions accepted on reload")
	}
	if _, ok := s.Match(header(v3)); ok {
		t.Fatal("rejected reload took effect")
	}
	if _, ok := s.Match(header(v1)); !ok {
		t.Fatal("last good set lost")
	}
	// Rotation step 2: the old version is removed.
	for _, n := range []string{"1", "3"} {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Match(header(v1)); ok {
		t.Fatal("retired version still accepted")
	}
	if v, ok := s.Match(header(v2)); !ok || v != "2" {
		t.Fatalf("current version: %q %v", v, ok)
	}
	if got := strings.Join(s.Versions(), ","); got != "2" {
		t.Fatalf("versions %s", got)
	}
}

func TestMatchRejects(t *testing.T) {
	k := newKey(t)
	dir := t.TempDir()
	writeFile(t, dir, "1", k)
	s, err := NewKeySet(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]http.Header{
		"missing":    {},
		"empty":      header(""),
		"wrong":      header(newKey(t)),
		"repeated":   header(k, k),
		"padded":     header(k + "="),
		"newline":    header(k + "\n"),
		"truncated":  header(k[:42]),
		"bearer":     header("Bearer " + k),
		"std base64": header(strings.NewReplacer("-", "+", "_", "/").Replace(k) + "x"),
	} {
		if v, ok := s.Match(h); ok {
			t.Fatalf("%s matched %q", name, v)
		}
	}
	var nilSet *KeySet
	if _, ok := nilSet.Match(header(k)); ok {
		t.Fatal("nil set matched")
	}
	if _, ok := (&KeySet{}).Match(header(k)); ok {
		t.Fatal("empty set matched")
	}
}

// The comparison visits every active key and does not stop at the first
// match: a key equal to the second version is found even when the first
// version compares first, and a value that matches neither visits both.
func TestMatchComparesAllKeys(t *testing.T) {
	a, b := newKey(t), newKey(t)
	ka, _ := decodeKey(a)
	kb, _ := decodeKey(b)
	s := &KeySet{keys: []apiKey{{version: "1", key: ka}, {version: "2", key: kb}}}
	if v, ok := s.Match(header(b)); !ok || v != "2" {
		t.Fatalf("second key: %q %v", v, ok)
	}
	if v, ok := s.Match(header(a)); !ok || v != "1" {
		t.Fatalf("first key: %q %v", v, ok)
	}
	// Two versions holding the same key: the last equal key is selected, which
	// shows that the loop did not exit at the first equal key.
	s = &KeySet{keys: []apiKey{{version: "1", key: ka}, {version: "2", key: ka}}}
	if v, ok := s.Match(header(a)); !ok || v != "2" {
		t.Fatalf("equal keys: %q %v", v, ok)
	}
}

func TestSubmitReceiverKey(t *testing.T) {
	for name, val := range map[string]string{"missing": "", "wrong": newKey(t), "malformed": "not-a-key"} {
		t.Run(name, func(t *testing.T) {
			st := &fakeStore{}
			w := post(newHandler(ModeIdempotent, st), SubmitterSAN, goodBody, map[string]string{HeaderIdempotencyKey: keyA, HeaderAttemptID: attemptA, HeaderReceiverKey: val})
			if w.Code != http.StatusUnauthorized || reasons(t, decodeMap(t, w)) != ReasonReceiverKeyInvalid {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
			if m := decodeMap(t, w); m["receipt_attempt_id"] != nil {
				t.Fatal("rejected key reported an attempt")
			}
			if len(st.submits)+len(st.missing) != 0 {
				t.Fatal("rejected key reached the store")
			}
		})
	}
	// A keyless idempotent submission with a wrong key is rejected before
	// key_missing_rejected is recorded.
	st := &fakeStore{}
	w := post(newHandler(ModeIdempotent, st), SubmitterSAN, goodBody, map[string]string{HeaderReceiverKey: newKey(t)})
	if w.Code != http.StatusUnauthorized || len(st.missing) != 0 {
		t.Fatalf("status %d missing %d", w.Code, len(st.missing))
	}
	// The SAN check comes first: a wrong caller gets AUTH_REQUIRED.
	w = post(newHandler(ModeIdempotent, &fakeStore{}), ReceiptReaderSAN, goodBody, map[string]string{HeaderReceiverKey: ""})
	if w.Code != http.StatusUnauthorized || reasons(t, decodeMap(t, w)) != ReasonAuthRequired {
		t.Fatalf("wrong SAN: %d %s", w.Code, w.Body.String())
	}
	// A handler without a key set rejects every submission.
	mux := http.NewServeMux()
	(&Handler{Store: &fakeStore{}, Cfg: Config{Mode: ModeIdempotent, TargetID: "t", RouteID: "r", TargetVersion: "v"}}).Register(mux)
	if w := post(mux, SubmitterSAN, goodBody, map[string]string{HeaderIdempotencyKey: keyA, HeaderAttemptID: attemptA}); w.Code != http.StatusUnauthorized {
		t.Fatalf("nil key set: %d", w.Code)
	}
}

func TestReceiptNeedsNoReceiverKey(t *testing.T) {
	st := &fakeStore{}
	r := withPeer(httptest.NewRequest(http.MethodGet, "/test/v1/receipts/"+keyA, nil), ReceiptReaderSAN)
	w := httptest.NewRecorder()
	newHandler(ModeIdempotent, st).ServeHTTP(w, r)
	if w.Code != http.StatusOK || st.receiptKey != keyA {
		t.Fatalf("receipt without key: %d", w.Code)
	}
}
