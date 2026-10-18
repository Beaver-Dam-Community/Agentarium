// Package format defines the snapshot files that services/discovery reads.
//
// Layout under <root>/snapshots/<snapshot_id>/ (TASK-02 3.4):
//
//	manifest.json   {"language", "scanner_version", "source_digest",
//	                 "files": [{"path", "sha256"}] sorted by path}
//	src/<path>      original files listed in the manifest
//	callgraph.json  {symbol: [callee, ...]}
//	call_sites.json CallSites
//
// snapshot_id = canonical digest(manifest.json).
package format

const (
	LanguageGo     = "go"
	LanguagePython = "python"

	// ScannerVersion names the scanner output format. Bump it whenever
	// callgraph.json or call_sites.json would change for the same source, so
	// a new scan never reuses an old snapshot.
	ScannerVersion = "discovery-snapshot/1"

	ManifestFile  = "manifest.json"
	CallgraphFile = "callgraph.json"
	CallSitesFile = "call_sites.json"
	SourceDir     = "src"
)

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest is manifest.json; snapshot_id = canonical digest of these bytes.
//
// Language, scanner version and source_digest are part of the manifest so the
// same archive scanned as python and as go (or by another scanner version)
// gets different snapshot_ids, and the service can check which request a
// returned snapshot belongs to (PR #12 review).
// SPEC-QUESTION: TASK-02 3.4 describes manifest.json as the file path and
// SHA-256 list only; these three fields are an addition to that wording.
type Manifest struct {
	Language       string          `json:"language"`
	ScannerVersion string          `json:"scanner_version"`
	SourceDigest   string          `json:"source_digest"`
	Files          []ManifestEntry `json:"files"`
}

type CallSite struct {
	Caller   string `json:"caller"`
	Callee   string `json:"callee"`
	Category string `json:"category"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	// ImportAlias is the local name used at the call site (Python only).
	ImportAlias *string `json:"import_alias"`
}

type ImportAlias struct {
	Path   string `json:"path"`
	Alias  string `json:"alias"`
	Target string `json:"target"`
	Line   int    `json:"line"`
}

type CallSites struct {
	Language    string        `json:"language"`
	Tool        string        `json:"tool"`
	CallSites   []CallSite    `json:"call_sites"`
	Imports     []ImportAlias `json:"imports"`
	Limitations []string      `json:"limitations"`
}

// Callgraph maps a symbol to its sorted callee list.
type Callgraph map[string][]string

// Result is written to the Job termination message.
type Result struct {
	SnapshotID string `json:"snapshot_id"`
	// Reused is true when a complete snapshot with this id already existed.
	Reused        bool `json:"reused"`
	FileCount     int  `json:"file_count"`
	CallSiteCount int  `json:"call_site_count"`
}
