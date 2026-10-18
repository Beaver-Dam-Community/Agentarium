package redact_test

import (
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/redact"
)

func TestJSON(t *testing.T) {
	in := `{"items":[{"metadata":{"name":"a","managedFields":[1]},"spec":{"containers":[{"name":"c","env":[{"name":"K","value":"v"}]}]}},{"metadata":{"name":"b"}}],"n":12345678901234}`
	out, err := redact.JSON([]byte(in), []string{"/items/*/metadata/managedFields", "/items/*/spec/containers/*/env", "/missing/x"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"items":[{"metadata":{"name":"a"},"spec":{"containers":[{"name":"c"}]}},{"metadata":{"name":"b"}}],"n":12345678901234}`
	if string(out) != want {
		t.Fatalf("got  %s\nwant %s", out, want)
	}
	if _, err := redact.JSON([]byte(in), []string{""}); err == nil {
		t.Fatal("empty pointer accepted")
	}
	same, err := redact.JSON([]byte(`{"a":1}`), nil)
	if err != nil || string(same) != `{"a":1}` {
		t.Fatal("no pointers must keep the body")
	}
}
