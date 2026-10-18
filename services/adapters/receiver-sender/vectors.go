package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/prepare"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// runVectors implements the tests/contracts protocol
//
//	receiver-sender canonical-vectors <vectors.json>
//
// action_digest comes from packages/canonical (the same package the gateway
// uses) and wire_body_digest from this adapter's own WirePlan mapper
// (prepare.ReceiverPlan), so the contract test compares the bytes the
// adapter would send with what the gateway approved. Only receiver.submit
// has a wire body; other operations report null.
func runVectors(path string, out io.Writer) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var v struct {
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
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	dir := filepath.Join(filepath.Dir(path), v.Catalog.Dir)
	load := func() (canonical.Catalog, error) {
		c, err := canonical.LoadCatalogDir(dir)
		if err != nil {
			return c, err
		}
		c.ModelProfiles = v.ModelProfiles
		return c, nil
	}
	base, err := load()
	if err != nil {
		return err
	}
	cats := map[string]canonical.Catalog{"": base}
	for _, cv := range v.CatalogVariants {
		c, err := load()
		if err != nil {
			return err
		}
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

	type result struct {
		ID             string  `json:"id"`
		ActionDigest   *string `json:"action_digest"`
		WireBodyDigest *string `json:"wire_body_digest"`
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
		tb, err := json.Marshal(m)
		if err != nil {
			return err
		}
		var trusted canonical.TrustedContext
		dec := json.NewDecoder(bytes.NewReader(tb))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&trusted); err != nil {
			return err
		}
		cat, ok := cats[c.CatalogVariant]
		if !ok {
			return fmt.Errorf("%s: unknown catalog variant %q", c.ID, c.CatalogVariant)
		}
		r := result{ID: c.ID}
		env, content, nerr := canonical.NormalizeRaw(raw, trusted, cat)
		if nerr == nil {
			r.ActionDigest = &env.ActionDigest
			if env.OperationID == canonical.OpReceiverSubmit {
				plan, _, _, mm := prepare.ReceiverPlan(env, content, cat)
				if mm != nil {
					return fmt.Errorf("%s: adapter mapper rejected a normalized receiver action: %v", c.ID, mm)
				}
				d := plan.WireBodyDigest
				r.WireBodyDigest = &d
			}
		}
		results = append(results, r)
	}
	return json.NewEncoder(out).Encode(map[string]any{"results": results})
}
