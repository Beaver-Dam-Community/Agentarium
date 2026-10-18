package isolation

import (
	"regexp"
	"testing"
)

func TestDigestStable(t *testing.T) {
	a, err := Digest()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Digest()
	if a != b || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a) {
		t.Fatalf("digest %q / %q", a, b)
	}
}
