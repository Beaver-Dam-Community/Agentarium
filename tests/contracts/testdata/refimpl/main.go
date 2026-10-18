// Command refimpl implements the tests/contracts "canonical-vectors" protocol
// directly with packages/canonical. It exists only to self-test the harness;
// it is not a gateway or adapter.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

type vectors struct {
	Catalog struct {
		Dir string `json:"dir"`
	} `json:"catalog"`
	CatalogVariants []struct {
		ID       string `json:"id"`
		TargetID string `json:"target_id"`
		Origin   string `json:"origin"`
	} `json:"catalog_variants"`
	ModelProfiles  map[string]canonical.ModelProfileConfig `json:"model_profiles"`
	TrustedDefault map[string]json.RawMessage              `json:"trusted_default"`
	Normalize      []struct {
		ID              string                     `json:"id"`
		Raw             *string                    `json:"raw"`
		RawHex          string                     `json:"raw_hex"`
		TrustedOverride map[string]json.RawMessage `json:"trusted_override"`
		CatalogVariant  string                     `json:"catalog_variant"`
	} `json:"normalize"`
}

type result struct {
	ID             string  `json:"id"`
	ActionDigest   *string `json:"action_digest"`
	WireBodyDigest *string `json:"wire_body_digest"`
}

func main() {
	if len(os.Args) != 3 || os.Args[1] != "canonical-vectors" {
		fmt.Fprintln(os.Stderr, "usage: refimpl canonical-vectors <vectors.json>")
		os.Exit(2)
	}
	if err := run(os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	cat, err := canonical.LoadCatalogDir(filepath.Join(filepath.Dir(path), v.Catalog.Dir))
	if err != nil {
		return err
	}
	cat.ModelProfiles = v.ModelProfiles
	cats := map[string]canonical.Catalog{"": cat}
	for _, cv := range v.CatalogVariants {
		c, err := canonical.LoadCatalogDir(filepath.Join(filepath.Dir(path), v.Catalog.Dir))
		if err != nil {
			return err
		}
		c.ModelProfiles = v.ModelProfiles
		tg, ok := c.Targets[cv.TargetID]
		if !ok {
			return fmt.Errorf("catalog variant %s: unknown target %s", cv.ID, cv.TargetID)
		}
		tg.Origin = cv.Origin
		c.Targets[cv.TargetID] = tg
		if c.CatalogDigest, err = c.ComputeDigest(); err != nil {
			return err
		}
		cats[cv.ID] = c
	}
	results := []result{}
	for _, c := range v.Normalize {
		raw := []byte{}
		if c.Raw != nil {
			raw = []byte(*c.Raw)
		} else if raw, err = hex.DecodeString(c.RawHex); err != nil {
			return err
		}
		m := map[string]json.RawMessage{}
		for k, val := range v.TrustedDefault {
			m[k] = val
		}
		for k, val := range c.TrustedOverride {
			m[k] = val
		}
		tb, _ := json.Marshal(m)
		var trusted canonical.TrustedContext
		dec := json.NewDecoder(bytes.NewReader(tb))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&trusted); err != nil {
			return err
		}
		r := result{ID: c.ID}
		cc, ok := cats[c.CatalogVariant]
		if !ok {
			return fmt.Errorf("%s: unknown catalog variant %q", c.ID, c.CatalogVariant)
		}
		env, content, nerr := canonical.NormalizeRaw(raw, trusted, cc)
		if nerr == nil {
			r.ActionDigest = &env.ActionDigest
			if env.OperationID == canonical.OpReceiverSubmit {
				body, err := canonical.ReceiverWireBody(env, content)
				if err != nil {
					return err
				}
				d := canonical.WireBodyDigest(body)
				r.WireBodyDigest = &d
			}
		}
		results = append(results, r)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"results": results})
}
