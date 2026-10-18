package canonical

import (
	"fmt"
	"regexp"
	"strings"
)

// EmailPattern is the RE2 pattern of the receiver content checker (TASK-02 3.3 step 4).
// It is a deterministic synthetic-data check, not a general DLP.
var EmailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// CheckReceiverContent applies the operation's content_checks to the payload.
// SPEC-QUESTION: Appendix A makes content_checks.fields optional; when it is
// absent this checks "summary" (the field named in 3.3 step 4). Synthetic
// identifiers match as case-sensitive substrings. A field name other than
// summary/email is a catalog defect and fails closed as ENDPOINT_NOT_REGISTERED.
func CheckReceiverContent(op CatalogOperation, p ReceiverPayload) *NormalizeError {
	cc := op.ContentChecks
	if cc == nil {
		return nil
	}
	fields := []string{"summary"}
	if cc.Fields != nil {
		fields = *cc.Fields
	}
	for _, f := range fields {
		var value *string
		switch f {
		case "summary":
			value = &p.Summary
		case "email":
			value = p.Email
		default:
			return notRegisteredErr("content_checks.fields has unknown receiver field %q", f)
		}
		if value == nil {
			continue
		}
		if cc.EmailPattern != nil && *cc.EmailPattern && EmailPattern.MatchString(*value) {
			return contentDenied("payload.%s matches the email pattern", f)
		}
		if cc.SyntheticIdentifiers != nil {
			for _, id := range *cc.SyntheticIdentifiers {
				if id != "" && strings.Contains(*value, id) {
					return contentDenied("payload.%s contains a registered synthetic identifier", f)
				}
			}
		}
	}
	return nil
}

func contentDenied(format string, a ...any) *NormalizeError {
	return &NormalizeError{ReasonCodes: []string{ReasonContentPatternDenied}, HTTPStatus: 403, RuleID: RuleContentPattern, Detail: fmt.Sprintf(format, a...)}
}
