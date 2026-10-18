package netpolcollector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

func TestSchemaRejectionContinuesAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_action.log")
	valid := bytes.SplitAfter(q0(t), []byte("\n"))[0]
	invalid := []byte("{invalid json}\n")
	// Two different schema failures bracket an accepted record; neither allocates
	// sequence or prevents later valid input from being captured.
	raw := append(append(append(append([]byte{}, invalid...), valid...), []byte("{}\n")...), valid...)
	write(t, path, raw)
	spool := filepath.Join(dir, "spool")
	inventory := func() ([]string, error) { return []string{path}, nil }
	j := open(t, spool, "epoch", 0)
	c := capture(t, j, inventory)
	r, err := c.Step(context.Background())
	if err != nil || !reflect.DeepEqual(r, wal.Record{}) {
		t.Fatalf("schema rejection = %+v, %v", r, err)
	}
	if got, err := j.SchemaRejections(); err != nil || got != 1 {
		t.Fatalf("count = %d, %v", got, err)
	}
	if j.Checkpoint().Offset != int64(len(invalid)) {
		t.Fatal("rejection checkpoint not durable")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j = open(t, spool, "epoch", 0)
	c = capture(t, j, inventory)
	if err = c.Run(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got, err := j.SchemaRejections(); err != nil || got != 2 {
		t.Fatalf("count = %d, %v", got, err)
	}
	records, err := j.Pending()
	if err != nil || len(records) != 2 || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatalf("pending = %+v, %v", records, err)
	}
	if !bytes.Equal(records[0].Payload, bytes.Replace(records[1].Payload, []byte(`"source_sequence":2`), []byte(`"source_sequence":1`), 1)) {
		t.Fatal("valid observation changed")
	}
	if j.Checkpoint().Offset != int64(len(raw)) {
		t.Fatal("capture stopped before EOF")
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j = open(t, spool, "new_epoch", 0)
	c = capture(t, j, inventory)
	if _, err = c.Step(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("replayed source: %v", err)
	}
	if got, err := j.SchemaRejections(); err != nil || got != 2 {
		t.Fatalf("count replayed: %d, %v", got, err)
	}
	again, err := j.Pending()
	if err != nil || !reflect.DeepEqual(again, records) {
		t.Fatal("unacked data changed after restart")
	}
}

func TestSchemaRejectionDiskFailureStopsBeforeNextLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy_action.log")
	write(t, path, append([]byte("{invalid json}\n"), q0(t)...))
	spool := filepath.Join(dir, "spool")
	inventory := func() ([]string, error) { return []string{path}, nil }
	j := open(t, spool, "epoch", 0)
	c := capture(t, j, inventory)
	state := filepath.Join(spool, "state.json")
	saved := filepath.Join(spool, "saved-state")
	if err := os.Rename(state, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.Run(context.Background(), false); err == nil {
		t.Fatal("disk error silently skipped")
	}
	if j.Checkpoint() != (wal.Checkpoint{}) {
		t.Fatal("failed commit exposed advanced checkpoint")
	}
	if _, err := j.SchemaRejections(); err == nil {
		t.Fatal("failed journal advertised count")
	}
	if _, err := c.Step(context.Background()); err == nil {
		t.Fatal("failed journal resumed")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, state); err != nil {
		t.Fatal(err)
	}
	j = open(t, spool, "epoch", 0)
	if got, err := j.SchemaRejections(); err != nil || got != 0 {
		t.Fatalf("failed write survived: %d, %v", got, err)
	}
	c = capture(t, j, inventory)
	if err := c.Run(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if got, err := j.SchemaRejections(); err != nil || got != 1 {
		t.Fatalf("replayed count = %d, %v", got, err)
	}
	records, err := j.Pending()
	if err != nil || len(records) != 5 || records[0].Sequence != 1 {
		t.Fatal("failed rejection lost valid input")
	}
}
