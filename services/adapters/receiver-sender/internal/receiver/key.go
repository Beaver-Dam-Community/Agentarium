package receiver

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
)

// Receiver API key contract (#169 proposal as agreed for M3-1, TASK-08
// receiver --api-key-dir): every POST /test/v1/submissions carries
// X-Agentarium-Receiver-Key with the raw key, 32 random bytes as 43
// characters of unpadded base64url. The credential broker binding
// receiver-api-key gives the current Secret Manager version of the same
// secret the receiver reads, raw (header_format raw).
const (
	CredentialBinding = "receiver-api-key"
	KeyHeader         = "X-Agentarium-Receiver-Key"
	keyLength         = 43
	keyBytes          = 32
)

var _ execute.CredentialChecker = Adapter{}

// CheckCredential refuses a broker answer that is not the receiver key: a
// different binding, header or value form. The receiver would answer 401
// RECEIVER_KEY_INVALID, so the adapter releases the attempt before the claim
// instead of sending. The error never contains the value.
func (Adapter) CheckCredential(binding string, c execute.Credential) error {
	if binding != CredentialBinding {
		return errors.New("receiver: unexpected credential binding")
	}
	if http.CanonicalHeaderKey(c.HeaderName) != http.CanonicalHeaderKey(KeyHeader) {
		return errors.New("receiver: broker header_name is not " + KeyHeader)
	}
	if !ValidKey(c.HeaderValue) {
		return errors.New("receiver: broker value is not a 43-character base64url receiver key")
	}
	return nil
}

// ValidKey reports whether v is 32 bytes as unpadded base64url (43
// characters, no padding, no whitespace).
func ValidKey(v string) bool {
	if len(v) != keyLength {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(v)
	return err == nil && len(b) == keyBytes
}
