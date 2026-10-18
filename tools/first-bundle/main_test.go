package main

import "testing"

func TestCheckChangeID(t *testing.T) {
	if err := checkChangeID("0b4e7f8a-3c2d-4e5f-8a9b-0c1d2e3f4a5b"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		"",
		"bootstrap",
		"0B4E7F8A-3C2D-4E5F-8A9B-0C1D2E3F4A5B", // upper case
		"0b4e7f8a3c2d4e5f8a9b0c1d2e3f4a5b",     // no hyphens
		"{0b4e7f8a-3c2d-4e5f-8a9b-0c1d2e3f4a5b}",
		"urn:uuid:0b4e7f8a-3c2d-4e5f-8a9b-0c1d2e3f4a5b",
		" 0b4e7f8a-3c2d-4e5f-8a9b-0c1d2e3f4a5b",
		"0b4e7f8a-3c2d-4e5f-8a9b-0c1d2e3f4a5b\n",
	} {
		if err := checkChangeID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
