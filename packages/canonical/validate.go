package canonical

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Identifier formats (TASK-02 3.2 field comments and "identifier rules").
var (
	reUUID             = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reDigest           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reClientRequestKey = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	reTargetID         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reDNS1123Label     = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	reFunctionName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
)

func isUUID(s string) bool   { return reUUID.MatchString(s) }
func isDigest(s string) bool { return reDigest.MatchString(s) }

// isDNS1123Subdomain: lowercase, 1..253 bytes, dot-separated DNS-1123 labels.
func isDNS1123Subdomain(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !reDNS1123Label.MatchString(label) {
			return false
		}
	}
	return true
}

func isDNS1123Label(s string) bool {
	return len(s) >= 1 && len(s) <= 63 && reDNS1123Label.MatchString(s)
}

func byteLenIn(s string, min, max int) bool { return len(s) >= min && len(s) <= max }

// hasControlOrSpace reports C0/C1 control characters, DEL and the space character.
func hasControlOrSpace(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == ' ' {
			return true
		}
	}
	return false
}

// validDiscoveryPath accepts a snapshot-relative path of 1..512 bytes.
// SPEC-QUESTION: 3.2 only says "relative path, 1..512 bytes, no '..'". This also
// rejects a leading '/', empty segments, '\', ':', '?', '#', '%' and
// control/space characters so that no URL, query or host change can be expressed.
func validDiscoveryPath(p string) bool {
	if !byteLenIn(p, 1, 512) || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return false
	}
	if strings.ContainsAny(p, `\:?#%`) || hasControlOrSpace(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." {
			return false
		}
	}
	return true
}

func validTargetID(id string) error {
	if !reTargetID.MatchString(id) {
		return fmt.Errorf("target_id %q has invalid format", id)
	}
	return nil
}

func validateK8sLogs(t K8sLogsTarget, a K8sLogsArgs) error {
	if err := validTargetID(t.TargetID); err != nil {
		return err
	}
	if !isDNS1123Subdomain(t.PodName) {
		return fmt.Errorf("pod_name is not a DNS-1123 subdomain")
	}
	if !isDNS1123Label(t.Container) {
		return fmt.Errorf("container is not a DNS-1123 label")
	}
	if a.TailLines < 1 || a.TailLines > 200 {
		return fmt.Errorf("tail_lines out of range 1..200")
	}
	if a.LimitBytes < 1 || a.LimitBytes > 1048576 {
		return fmt.Errorf("limit_bytes out of range 1..1048576")
	}
	return nil
}

func validateReceiver(t ReceiverTarget, a ReceiverArgs) error {
	if err := validTargetID(t.TargetID); err != nil {
		return err
	}
	if !byteLenIn(a.Payload.Summary, 1, 4096) {
		return fmt.Errorf("payload.summary must be 1..4096 bytes")
	}
	if a.Payload.Email != nil && !byteLenIn(*a.Payload.Email, 3, 254) {
		return fmt.Errorf("payload.email must be null or 3..254 bytes")
	}
	return nil
}

// MaxToolParametersBytes bounds the JCS serialization of a tool declaration's parameters.
const MaxToolParametersBytes = 4096

func validateModel(t ModelTarget, a ModelArgs) error {
	if err := validTargetID(t.TargetID); err != nil {
		return err
	}
	if !modelProfiles[t.Profile] {
		return fmt.Errorf("profile %q is not a model profile", t.Profile)
	}
	if t.Profile == "policy_proposal" {
		if a.Phase == nil || (*a.Phase != "exploration" && *a.Phase != "final") {
			return fmt.Errorf("policy_proposal requires phase exploration or final")
		}
	} else if a.Phase != nil {
		return fmt.Errorf("profile %q does not allow phase", t.Profile)
	}
	if !isUUID(a.ConversationID) {
		return fmt.Errorf("conversation_id must be a lowercase UUID")
	}
	if len(a.Messages) < 1 || len(a.Messages) > 64 {
		return fmt.Errorf("messages must have 1..64 entries")
	}
	for i, m := range a.Messages {
		if err := validateMessage(m); err != nil {
			return fmt.Errorf("messages[%d]: %w", i, err)
		}
	}
	if t.Profile == "agent" {
		if len(a.ToolDeclarations) > 8 {
			return fmt.Errorf("agent profile allows at most 8 tool_declarations")
		}
	} else if len(a.ToolDeclarations) != 0 {
		return fmt.Errorf("profile %q requires tool_declarations = []", t.Profile)
	}
	for i, d := range a.ToolDeclarations {
		if !reFunctionName.MatchString(d.Name) {
			return fmt.Errorf("tool_declarations[%d].name has invalid format", i)
		}
		if !byteLenIn(d.Description, 1, 1024) {
			return fmt.Errorf("tool_declarations[%d].description must be 1..1024 bytes", i)
		}
		c, err := JCS(d.Parameters)
		if err != nil {
			return fmt.Errorf("tool_declarations[%d].parameters: %w", i, err)
		}
		if len(c) > MaxToolParametersBytes {
			return fmt.Errorf("tool_declarations[%d].parameters exceeds %d bytes after JCS", i, MaxToolParametersBytes)
		}
	}
	return nil
}

func validateMessage(m ModelMessage) error {
	switch m.Kind {
	case "text":
		if m.Role != "user" {
			return fmt.Errorf("text message role must be user")
		}
		if m.Source == nil || (*m.Source != "user" && *m.Source != "system") {
			return fmt.Errorf("text message source must be user or system")
		}
		if m.Text == nil || !byteLenIn(*m.Text, 1, 16384) {
			return fmt.Errorf("text must be 1..16384 bytes")
		}
		if m.Ref != nil || m.FunctionName != nil {
			return fmt.Errorf("text message must have ref and function_name null")
		}
	case "tool_result":
		if m.Role != "user" {
			return fmt.Errorf("tool_result message role must be user")
		}
		if m.Source == nil || *m.Source != "tool_result" {
			return fmt.Errorf("tool_result message source must be tool_result")
		}
		if m.Text != nil {
			return fmt.Errorf("tool_result message text must be null")
		}
		if m.Ref == nil || m.Ref.Ref != "action_result" || m.Ref.ActionID == nil || !isUUID(*m.Ref.ActionID) || m.Ref.TurnIndex != nil {
			return fmt.Errorf("tool_result ref must be {ref: action_result, action_id: <uuid>, turn_index: null}")
		}
		if m.FunctionName == nil || !reFunctionName.MatchString(*m.FunctionName) {
			return fmt.Errorf("tool_result function_name has invalid format")
		}
	case "model_turn":
		if m.Role != "model" {
			return fmt.Errorf("model_turn role must be model")
		}
		if m.Source != nil || m.Text != nil || m.FunctionName != nil {
			return fmt.Errorf("model_turn must have source, text and function_name null")
		}
		// SPEC-QUESTION: the start value of turn_index is not specified; >= 0 is accepted.
		if m.Ref == nil || m.Ref.Ref != "model_turn" || m.Ref.TurnIndex == nil || *m.Ref.TurnIndex < 0 || m.Ref.ActionID != nil {
			return fmt.Errorf("model_turn ref must be {ref: model_turn, action_id: null, turn_index: >= 0}")
		}
	default:
		return fmt.Errorf("kind must be text, tool_result or model_turn")
	}
	return nil
}

func validateEvidence(t EvidenceTarget) error {
	if err := validTargetID(t.TargetID); err != nil {
		return err
	}
	if !isUUID(t.ResourceID) && !isDigest(t.ResourceID) {
		return fmt.Errorf("resource_id must be a lowercase UUID or 64 lowercase hex")
	}
	return nil
}

func validateDiscoverySource(t DiscoverySourceTarget, a DiscoverySourceArgs) error {
	if err := validTargetID(t.TargetID); err != nil {
		return err
	}
	if !isDigest(t.SnapshotID) {
		return fmt.Errorf("snapshot_id must be 64 lowercase hex")
	}
	if !validDiscoveryPath(t.Path) {
		return fmt.Errorf("path is not an allowed relative path")
	}
	if a.StartLine < 1 {
		return fmt.Errorf("start_line must be >= 1")
	}
	if a.EndLine < a.StartLine || a.EndLine > a.StartLine+400 {
		return fmt.Errorf("end_line must be within start_line..start_line+400")
	}
	return nil
}

func validateDiscoveryCallgraph(t DiscoveryCallgraphTarget, a DiscoveryCallgraphArgs) error {
	if err := validTargetID(t.TargetID); err != nil {
		return err
	}
	if !isDigest(t.SnapshotID) {
		return fmt.Errorf("snapshot_id must be 64 lowercase hex")
	}
	// Membership in the snapshot symbol list is checked where the snapshot is read (adapter/discovery).
	if !byteLenIn(t.Symbol, 1, 256) || hasControlOrSpace(t.Symbol) {
		return fmt.Errorf("symbol must be 1..256 bytes without control or space characters")
	}
	if a.Depth < 1 || a.Depth > 3 {
		return fmt.Errorf("depth out of range 1..3")
	}
	return nil
}

// marshalNoEscape is json.Marshal without HTML escaping (JCS re-serializes anyway).
func marshalNoEscape(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}
