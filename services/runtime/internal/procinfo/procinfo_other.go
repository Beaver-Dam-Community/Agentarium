//go:build !linux

package procinfo

// Of is unavailable without Linux /proc; the supervisor then refuses to
// register a worker.
func Of(string, int) (Hint, error) { return Hint{}, ErrUnsupported }
