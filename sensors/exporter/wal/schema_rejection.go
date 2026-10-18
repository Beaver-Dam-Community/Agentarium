package wal

import "errors"

// RejectSchema checkpoints one complete input line that the source contract
// explicitly excludes as schema-invalid, together with its durable rejection
// count. It must not skip lost data, identity failures or records already given
// a sequence. Network-policy capture uses this before sequence allocation;
// kernel parse failures and collector delivery rejections have other contracts.
// expected is the checkpoint used to read this line. Retrying the same committed
// checkpoint is idempotent; a stale expected checkpoint cannot move the cursor.
func (j *Journal) RejectSchema(expected, next Checkpoint) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return errors.New("spool unavailable")
	}
	if next.Inode == 0 || next.Offset <= 0 || next == expected ||
		(next.Inode == expected.Inode && next.Device == expected.Device && next.PrefixDigest == expected.PrefixDigest && next.Offset <= expected.Offset) {
		return errors.New("invalid rejection checkpoint")
	}
	if j.state.Checkpoint == next {
		return nil
	}
	if j.state.Checkpoint != expected {
		return errors.New("stale rejection checkpoint")
	}
	if j.state.SchemaRejected == MaxSequence {
		return errors.New("schema rejection count exhausted")
	}
	j.state.SchemaRejected++
	j.state.Checkpoint = next
	if err := j.persist(); err != nil {
		// A rename may already have committed the new state. Do not expose the
		// speculative values or allow retries on this instance: reopening reads
		// whichever complete state survived, keeping count and cursor together.
		j.state.SchemaRejected--
		j.state.Checkpoint = expected
		j.failed = true
		return err
	}
	return nil
}

// SchemaRejections returns the durable local-spool lifetime count, across
// epochs. A legacy spool without this field starts at zero; that says nothing
// about malformed input before counting was implemented. This is not a lease
// wire field, an ACK, or a healthy/caught-up signal.
func (j *Journal) SchemaRejections() (uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.failed {
		return 0, errors.New("spool unavailable")
	}
	return j.state.SchemaRejected, nil
}
