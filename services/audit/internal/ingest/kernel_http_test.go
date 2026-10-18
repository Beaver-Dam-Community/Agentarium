package ingest

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestValidateKernelAck(t *testing.T) {
	id := uuid.NewString()
	b := KernelEnvelope{BatchID: uuid.NewString(), Epoch: "ep", Records: []json.RawMessage{json.RawMessage(`{"source_event_id":"` + id + `"}`)}, Abandoned: []KernelRange{{From: 3, To: 4}}}
	ack := func(accepted, duplicates string, rejected string, through int) []byte {
		return []byte(`{"batch_id":"` + b.BatchID + `","accepted_ids":` + accepted + `,"duplicate_ids":` + duplicates + `,"rejected":` + rejected + `,"watermarks":[{"source_epoch":"ep","acked_through":` + strconv.Itoa(through) + `}]}`)
	}
	if err := ValidateKernelAck(ack(`["`+id+`"]`, `["ep:3-4"]`, `[]`, 4), b); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"missing record":   ack(`[]`, `["ep:3-4"]`, `[]`, 4),
		"twice":            ack(`["`+id+`"]`, `["`+id+`","ep:3-4"]`, `[]`, 4),
		"foreign id":       ack(`["`+id+`","`+uuid.NewString()+`"]`, `["ep:3-4"]`, `[]`, 4),
		"unknown reason":   ack(`["`+id+`"]`, `[]`, `[{"id":"ep:3-4","reason_codes":["OTHER"]}]`, 4),
		"negative through": ack(`["`+id+`"]`, `["ep:3-4"]`, `[]`, -1),
		"checkpoint field": []byte(strings.Replace(string(ack(`["`+id+`"]`, `["ep:3-4"]`, `[]`, 4)), `}]}`, `}],"checkpoint":null}`, 1)),
	} {
		if ValidateKernelAck(raw, b) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestKernelHandlerRequiresMutualTLSAndPost(t *testing.T) {
	h := KernelHandler{}
	for _, c := range []struct {
		method, path string
		want         int
	}{{"POST", "/internal/kernel/events:batch", 401}, {"GET", "/internal/kernel/events:batch", 405}, {"POST", "/internal/kernel/other", 404}} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, strings.NewReader("{}")))
		if rec.Code != c.want {
			t.Fatalf("%s %s: %d want %d", c.method, c.path, rec.Code, c.want)
		}
	}
}
