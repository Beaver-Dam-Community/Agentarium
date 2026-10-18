package contractview

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func input(t *testing.T) Input {
	t.Helper()
	cat, err := canonical.LoadCatalogDir("../canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		ActionID: "8c1e0000-0000-4000-8000-000000000001", OperationID: "receiver.submit", TargetID: "receiver-primary",
		DisclosureFields: []string{"summary"}, Environment: "test", Tenant: "hackathon", Catalog: cat,
		ContentDigest: strings.Repeat("1", 64), PreviewText: "synthetic summary 한글",
	}
}

// goldenJSON and goldenDigest freeze the rendered contract. A change here
// changes every contract_digest, so it must be deliberate.
const goldenJSON = `{"action_id":"8c1e0000-0000-4000-8000-000000000001","content_preview":{"content_digest":"1111111111111111111111111111111111111111111111111111111111111111","text":"synthetic summary 한글","truncated":false},"contract_version":"1","disclosure_fields":["summary"],"environment":"test","expires_in_seconds":300,"max_actions":1,"operation_id":"receiver.submit","operation_label":"@LABEL@","target":{"label":"receiver-primary","target_id":"receiver-primary"},"tenant":"hackathon"}`

func TestGolden(t *testing.T) {
	in := input(t)
	v, err := Render(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := canonical.CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	label, _ := json.Marshal(in.Catalog.Operations["receiver.submit"].Description)
	want := strings.Replace(goldenJSON, `"@LABEL@"`, string(label), 1)
	if string(got) != want {
		t.Fatalf("\n got  %s\n want %s", got, want)
	}
	d1, _ := Digest(v)
	d2, _ := canonical.CanonicalDigestJSON([]byte(want))
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("digest %s vs %s", d1, d2)
	}
}

func TestDigestStableAndSensitive(t *testing.T) {
	in := input(t)
	base, _ := Render(in)
	d0, _ := Digest(base)

	// Same contract regardless of disclosure field order; rendering twice
	// gives the same digest (no clock input).
	in2 := input(t)
	in2.DisclosureFields = []string{"summary"}
	again, _ := Render(in2)
	if d, _ := Digest(again); d != d0 {
		t.Fatal("re-render changed the digest")
	}
	multi := input(t)
	multi.DisclosureFields = []string{"title", "summary"}
	a, _ := Render(multi)
	multi.DisclosureFields = []string{"summary", "title"}
	b, _ := Render(multi)
	if da, _ := Digest(a); func() string { d, _ := Digest(b); return d }() != da {
		t.Fatal("disclosure field order changed the digest")
	}

	for name, mod := range map[string]func(*Input){
		"target":         func(i *Input) { i.TargetID = "receiver-probe" },
		"fields":         func(i *Input) { i.DisclosureFields = []string{"summary", "title"} },
		"content digest": func(i *Input) { i.ContentDigest = strings.Repeat("2", 64) },
		"preview":        func(i *Input) { i.PreviewText = "other" },
		"tenant":         func(i *Input) { i.Tenant = "other" },
		"action":         func(i *Input) { i.ActionID = "8c1e0000-0000-4000-8000-000000000002" },
	} {
		in := input(t)
		mod(&in)
		v, err := Render(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d, _ := Digest(v); d == d0 {
			t.Errorf("%s change kept the digest", name)
		}
	}
}

func TestPreviewTruncation(t *testing.T) {
	in := input(t)
	in.PreviewText = strings.Repeat("가", MaxPreviewRunes)
	v, _ := Render(in)
	if v.ContentPreview.Truncated || len([]rune(v.ContentPreview.Text)) != MaxPreviewRunes {
		t.Fatal("text at the limit was truncated")
	}
	in.PreviewText = strings.Repeat("가", MaxPreviewRunes+1)
	v, _ = Render(in)
	if !v.ContentPreview.Truncated || len([]rune(v.ContentPreview.Text)) != MaxPreviewRunes {
		t.Fatal("text over the limit not truncated")
	}
	if v.ContentPreview.ContentDigest != in.ContentDigest {
		t.Fatal("content_digest is not the whole-content digest")
	}
	in.PreviewText, in.PreviewCut = "short", true
	if v, _ := Render(in); !v.ContentPreview.Truncated {
		t.Fatal("source truncation flag dropped")
	}
}

func TestRenderRejects(t *testing.T) {
	for name, mod := range map[string]func(*Input){
		"unknown operation": func(i *Input) { i.OperationID = "x.y" },
		"unknown target":    func(i *Input) { i.TargetID = "nope" },
		"duplicate field":   func(i *Input) { i.DisclosureFields = []string{"summary", "summary"} },
		"invalid utf-8":     func(i *Input) { i.PreviewText = string([]byte{0xff}) },
	} {
		in := input(t)
		mod(&in)
		if _, err := Render(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	in := input(t)
	in.ContentDigest = ""
	v, err := Render(in)
	if err != nil || v.ContentPreview != nil {
		t.Fatal("no content should mean no preview")
	}
	b, _ := canonical.CanonicalJSON(v)
	if strings.Contains(string(b), "content_preview") {
		t.Fatalf("content_preview present without content: %s", b)
	}
}
