package canonical

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type vectorFile struct {
	Catalog struct {
		Dir            string          `json:"dir"`
		CatalogVersion string          `json:"catalog_version"`
		JSONValue      json.RawMessage `json:"json_value"`
		JCS            string          `json:"jcs"`
		CatalogDigest  string          `json:"catalog_digest"`
	} `json:"catalog"`
	CatalogVariants []struct {
		ID            string `json:"id"`
		Note          string `json:"note"`
		TargetID      string `json:"target_id"`
		Origin        string `json:"origin"`
		CatalogDigest string `json:"catalog_digest"`
	} `json:"catalog_variants"`
	ModelProfiles  map[string]ModelProfileConfig `json:"model_profiles"`
	TrustedDefault json.RawMessage               `json:"trusted_default"`
	JCS            []struct {
		ID             string `json:"id"`
		Input          string `json:"input"`
		RFCExpected    string `json:"rfc_expected"`
		ExpectedJCS    string `json:"expected_jcs"`
		ExpectedSHA256 string `json:"expected_sha256"`
		LibraryOnly    bool   `json:"library_only"`
	} `json:"jcs"`
	JCSReject []struct {
		ID       string `json:"id"`
		Note     string `json:"note"`
		Input    string `json:"input"`
		InputHex string `json:"input_hex"`
	} `json:"jcs_reject"`
	StrictReject []vectorCase `json:"strict_reject"`
	Normalize    []vectorCase `json:"normalize"`
	Equivalence  []struct {
		ID    string   `json:"id"`
		Same  bool     `json:"same"`
		Cases []string `json:"cases"`
	} `json:"equivalence"`
}

type vectorCase struct {
	ID              string                     `json:"id"`
	Note            string                     `json:"note"`
	Raw             *string                    `json:"raw"`
	RawHex          string                     `json:"raw_hex"`
	CatalogVariant  string                     `json:"catalog_variant"`
	TrustedOverride map[string]json.RawMessage `json:"trusted_override"`
	Expect          struct {
		HTTPStatus     int      `json:"http_status"`
		ReasonCodes    []string `json:"reason_codes"`
		RuleID         string   `json:"rule_id"`
		ContentJCS     *string  `json:"content_jcs"`
		ContentDigest  *string  `json:"content_digest"`
		HashJCS        string   `json:"hash_jcs"`
		ActionDigest   string   `json:"action_digest"`
		Wire           *string  `json:"wire"`
		WireBodyDigest *string  `json:"wire_body_digest"`
	} `json:"expect"`
}

func (c vectorCase) rawBytes(t *testing.T) []byte {
	if c.Raw != nil {
		return []byte(*c.Raw)
	}
	b, err := hex.DecodeString(c.RawHex)
	if err != nil {
		t.Fatalf("%s: bad raw_hex: %v", c.ID, err)
	}
	return b
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func vectorCatalog(t *testing.T, v vectorFile) Catalog {
	t.Helper()
	cat, err := LoadCatalogDir("testdata/" + v.Catalog.Dir)
	if err != nil {
		t.Fatal(err)
	}
	cat.ModelProfiles = v.ModelProfiles
	return cat
}

// vectorCatalogs returns the base catalog under "" and every catalog variant
// (one target origin replaced, same catalog_version) under its id, checking
// each recomputed catalog_digest against the vector file.
func vectorCatalogs(t *testing.T, v vectorFile) map[string]Catalog {
	t.Helper()
	base := vectorCatalog(t, v)
	out := map[string]Catalog{"": base}
	for _, cv := range v.CatalogVariants {
		c := vectorCatalog(t, v)
		tg, ok := c.Targets[cv.TargetID]
		if !ok {
			t.Fatalf("catalog variant %s: unknown target %s", cv.ID, cv.TargetID)
		}
		tg.Origin = cv.Origin
		c.Targets[cv.TargetID] = tg
		if err := c.validate(); err != nil {
			t.Fatalf("catalog variant %s: %v", cv.ID, err)
		}
		d, err := c.ComputeDigest()
		if err != nil {
			t.Fatal(err)
		}
		if d != cv.CatalogDigest || d == base.CatalogDigest {
			t.Fatalf("catalog variant %s: digest %s, vectors %s, base %s", cv.ID, d, cv.CatalogDigest, base.CatalogDigest)
		}
		c.CatalogDigest = d
		out[cv.ID] = c
	}
	return out
}

func vectorTrusted(t *testing.T, v vectorFile, override map[string]json.RawMessage) TrustedContext {
	t.Helper()
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(v.TrustedDefault, &m); err != nil {
		t.Fatal(err)
	}
	for k, val := range override {
		m[k] = val
	}
	b, _ := json.Marshal(m)
	var tc TrustedContext
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tc); err != nil {
		t.Fatal(err)
	}
	return tc
}

func TestVectorsCatalog(t *testing.T) {
	v := loadVectors(t)
	cat := vectorCatalog(t, v)
	if cat.CatalogDigest != v.Catalog.CatalogDigest {
		t.Fatalf("catalog_digest %s, vectors %s", cat.CatalogDigest, v.Catalog.CatalogDigest)
	}
	if cat.CatalogVersion != v.Catalog.CatalogVersion {
		t.Fatalf("catalog_version %q", cat.CatalogVersion)
	}
	got, err := CanonicalJSON(cat.DigestInput())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != v.Catalog.JCS {
		t.Fatalf("catalog JCS differs from the independent YAML->JSON conversion\n got %s\nwant %s", got, v.Catalog.JCS)
	}
	ref, err := JCS(v.Catalog.JSONValue)
	if err != nil || string(ref) != v.Catalog.JCS {
		t.Fatalf("vendored JCS of json_value differs from the JS reference: %v", err)
	}
}

func TestVectorsJCS(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.JCS {
		jcsFn := JCS
		if c.LibraryOnly {
			// Serializer check only: the service contract rejects these
			// integral values beyond ±(2^53-1) (1E30).
			if _, err := JCS([]byte(c.Input)); err == nil {
				t.Errorf("%s: library-only vector accepted by the contract JCS", c.ID)
			}
			jcsFn = JCSLibrary
		}
		got, err := jcsFn([]byte(c.Input))
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		if string(got) != c.ExpectedJCS {
			t.Errorf("%s: got %q want %q", c.ID, got, c.ExpectedJCS)
		}
		if c.RFCExpected != "" && string(got) != c.RFCExpected {
			t.Errorf("%s: differs from RFC/upstream bytes", c.ID)
		}
		if SHA256Hex(got) != c.ExpectedSHA256 {
			t.Errorf("%s: sha256 mismatch", c.ID)
		}
	}
	for _, c := range v.JCSReject {
		in := []byte(c.Input)
		if c.InputHex != "" {
			in, _ = hex.DecodeString(c.InputHex)
		}
		if got, err := JCS(in); err == nil {
			t.Errorf("%s: accepted, got %q", c.ID, got)
		}
	}
}

func checkNormalizeError(t *testing.T, id string, err *NormalizeError, c vectorCase) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: accepted, want %d %v", id, c.Expect.HTTPStatus, c.Expect.ReasonCodes)
		return
	}
	if err.HTTPStatus != c.Expect.HTTPStatus || !reflect.DeepEqual(err.ReasonCodes, c.Expect.ReasonCodes) || err.RuleID != c.Expect.RuleID {
		t.Errorf("%s: got %d %v %q (%s), want %d %v %q", id, err.HTTPStatus, err.ReasonCodes, err.RuleID, err.Detail, c.Expect.HTTPStatus, c.Expect.ReasonCodes, c.Expect.RuleID)
	}
}

func TestVectorsStrictReject(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.StrictReject {
		_, err := DecodeClientAction(c.rawBytes(t))
		checkNormalizeError(t, c.ID, err, c)
	}
}

func TestVectorsNormalize(t *testing.T) {
	v := loadVectors(t)
	cats := vectorCatalogs(t, v)
	digests := map[string]string{}
	for _, c := range v.Normalize {
		cat, ok := cats[c.CatalogVariant]
		if !ok {
			t.Fatalf("%s: unknown catalog variant %q", c.ID, c.CatalogVariant)
		}
		raw := c.rawBytes(t)
		trusted := vectorTrusted(t, v, c.TrustedOverride)
		env, content, err := NormalizeRaw(raw, trusted, cat)
		if c.Expect.HTTPStatus != 0 {
			checkNormalizeError(t, c.ID, err, c)
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.ID, err)
			continue
		}
		hj, jerr := CanonicalJSON(env.HashObject())
		if jerr != nil {
			t.Fatal(jerr)
		}
		if string(hj) != c.Expect.HashJCS {
			t.Errorf("%s: hash object\n got %s\nwant %s", c.ID, hj, c.Expect.HashJCS)
		}
		if env.ActionDigest != c.Expect.ActionDigest {
			t.Errorf("%s: action_digest %s want %s", c.ID, env.ActionDigest, c.Expect.ActionDigest)
		}
		if c.Expect.ContentJCS == nil {
			if env.ContentDigest != nil || env.ContentRef != nil || len(content.ContentBytes) != 0 {
				t.Errorf("%s: unexpected content", c.ID)
			}
		} else {
			if string(content.ContentBytes) != *c.Expect.ContentJCS {
				t.Errorf("%s: content\n got %s\nwant %s", c.ID, content.ContentBytes, *c.Expect.ContentJCS)
			}
			if env.ContentDigest == nil || *env.ContentDigest != *c.Expect.ContentDigest || content.ContentDigest != *c.Expect.ContentDigest {
				t.Errorf("%s: content_digest mismatch", c.ID)
			}
			if env.ContentRef == nil || *env.ContentRef != *env.ContentDigest {
				t.Errorf("%s: content_ref must equal content_digest", c.ID)
			}
			if err := VerifyContent(env, content); err != nil {
				t.Errorf("%s: %v", c.ID, err)
			}
		}
		if c.Expect.WireBodyDigest != nil {
			body, err := ReceiverWireBody(env, content)
			if err != nil {
				t.Errorf("%s: %v", c.ID, err)
			} else if WireBodyDigest(body) != *c.Expect.WireBodyDigest {
				t.Errorf("%s: wire_body_digest mismatch", c.ID)
			}
		}
		if env.RawBodyDigest != SHA256Hex(raw) {
			t.Errorf("%s: raw_body_digest", c.ID)
		}
		if env.CatalogDigest != cat.CatalogDigest || env.CatalogVersion != cat.CatalogVersion {
			t.Errorf("%s: catalog fields", c.ID)
		}
		wantClass := trusted.WorkloadDataState.DataClassHighWater
		if env.DataClass != wantClass || !reflect.DeepEqual(env.DataSources, trusted.WorkloadDataState.DataSources) {
			t.Errorf("%s: data_class/data_sources not inherited from trusted context", c.ID)
		}
		if env.ActionID != trusted.ActionID || env.SessionID != trusted.SessionID || env.Environment != trusted.Environment || env.Tenant != trusted.Tenant {
			t.Errorf("%s: trusted fields not copied", c.ID)
		}
		digests[c.ID] = env.ActionDigest
	}
	for _, g := range v.Equivalence {
		seen := map[string]bool{}
		for _, id := range g.Cases {
			d, ok := digests[id]
			if !ok {
				t.Errorf("equivalence %s: missing case %s", g.ID, id)
				continue
			}
			seen[d] = true
		}
		if g.Same && len(seen) != 1 {
			t.Errorf("equivalence %s: expected identical digests, got %d distinct", g.ID, len(seen))
		}
		if !g.Same && len(seen) != len(g.Cases) {
			t.Errorf("equivalence %s: expected all distinct, got %d distinct of %d", g.ID, len(seen), len(g.Cases))
		}
	}
}
