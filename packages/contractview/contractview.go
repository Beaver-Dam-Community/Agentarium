// Package contractview renders the approval contract the console shows and
// the intent check reads (TASK-03 3.1, COMMON ContractView). The same package
// renders the contract at GET and again at POST, so the digest only changes
// when the action or the policy changes, never with time.
package contractview

import (
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Version is ContractView.contract_version.
const Version = "1"

// ApprovalTTLSeconds is the fixed approval lifetime shown as
// expires_in_seconds (TASK-03 3.1: an approval lasts 5 minutes from the POST).
const ApprovalTTLSeconds = 300

// MaxPreviewRunes bounds content_preview.text.
const MaxPreviewRunes = 2000

// View is the COMMON ContractView.
type View struct {
	ContractVersion  string   `json:"contract_version"`
	ActionID         string   `json:"action_id"`
	OperationID      string   `json:"operation_id"`
	OperationLabel   string   `json:"operation_label"`
	Target           Target   `json:"target"`
	DisclosureFields []string `json:"disclosure_fields"`
	ContentPreview   *Preview `json:"content_preview,omitempty"` // absent when the action sends no content
	MaxActions       int      `json:"max_actions"`
	ExpiresInSeconds int      `json:"expires_in_seconds"`
	Environment      string   `json:"environment"`
	Tenant           string   `json:"tenant"`
}

type Target struct {
	TargetID string `json:"target_id"`
	Label    string `json:"label"`
}

// Preview is the synthetic-data preview of the content.
// SPEC-QUESTION: COMMON names content_preview but not its fields.
type Preview struct {
	Text          string `json:"text"`
	Truncated     bool   `json:"truncated"`
	ContentDigest string `json:"content_digest"` // digest of the whole content, not of Text
}

// Input is what the renderer reads. Nothing written by the agent goes in.
type Input struct {
	ActionID         string
	OperationID      string
	TargetID         string
	DisclosureFields []string
	Environment      string
	Tenant           string
	Catalog          canonical.Catalog
	// ContentDigest is the envelope content_digest; empty when the operation
	// sends no content. Preview is required when it is set.
	ContentDigest string
	PreviewText   string
	PreviewCut    bool
}

// Render builds the View. The operation label is the catalog description and
// the target label is the target_id, because the catalog has no display name.
// SPEC-QUESTION: labels have no other source in the catalog.
func Render(in Input) (View, error) {
	op, ok := in.Catalog.Operations[in.OperationID]
	if !ok {
		return View{}, errors.New("contractview: operation not in catalog")
	}
	if _, ok := in.Catalog.Targets[in.TargetID]; !ok {
		return View{}, errors.New("contractview: target not in catalog")
	}
	fields := append([]string{}, in.DisclosureFields...)
	sort.Strings(fields)
	for i := 1; i < len(fields); i++ {
		if fields[i] == fields[i-1] {
			return View{}, errors.New("contractview: duplicate disclosure field")
		}
	}
	v := View{
		ContractVersion:  Version,
		ActionID:         in.ActionID,
		OperationID:      in.OperationID,
		OperationLabel:   op.Description,
		Target:           Target{TargetID: in.TargetID, Label: in.TargetID},
		DisclosureFields: fields,
		MaxActions:       1,
		ExpiresInSeconds: ApprovalTTLSeconds,
		Environment:      in.Environment,
		Tenant:           in.Tenant,
	}
	if in.ContentDigest != "" {
		if !utf8.ValidString(in.PreviewText) {
			return View{}, errors.New("contractview: preview is not valid UTF-8")
		}
		text, cut := in.PreviewText, in.PreviewCut
		if r := []rune(text); len(r) > MaxPreviewRunes {
			text, cut = string(r[:MaxPreviewRunes]), true
		}
		v.ContentPreview = &Preview{Text: text, Truncated: cut, ContentDigest: in.ContentDigest}
	}
	return v, nil
}

// Digest is contract_digest: the canonical digest (JCS + SHA-256) of v.
func Digest(v View) (string, error) {
	return canonical.CanonicalDigest(v)
}
