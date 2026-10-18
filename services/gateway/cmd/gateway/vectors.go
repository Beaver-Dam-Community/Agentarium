package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// runVectors implements the offline tests/contracts protocol:
//
//	gateway canonical-vectors <vectors.json>
//
// It calls DecodeClientAction and Normalize, the same canonical entry points
// as gateway.Submit. Fixtures supply the trusted context and catalog that the
// running service obtains from authenticated identity, DB and its policy bundle.
// ReceiverWireBody hashes the normalized receiver payload; the adapter binary
// independently runs its prepare.ReceiverPlan mapper for the parity comparison.
// This command does not verify authentication, policy decisions, persistence,
// submit/execute delivery, or any other service integration.
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
		action, decodeErr := canonical.DecodeClientAction(raw)
		if decodeErr != nil {
			results = append(results, r)
			continue
		}
		env, content, nerr := canonical.Normalize(action, raw, trusted, cat)
		if nerr == nil {
			r.ActionDigest = &env.ActionDigest
			if env.OperationID == canonical.OpReceiverSubmit {
				body, err := canonical.ReceiverWireBody(env, content)
				if err != nil {
					return fmt.Errorf("%s: receiver body rejected a normalized action: %w", c.ID, err)
				}
				d := canonical.WireBodyDigest(body)
				r.WireBodyDigest = &d
			}
		}
		results = append(results, r)
	}
	return json.NewEncoder(out).Encode(map[string]any{"results": results})
}
