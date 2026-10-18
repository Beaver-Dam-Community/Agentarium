package admission

import "testing"

const auditExporterImage = reg + "audit-exporter@" + digestB

// The TASK-07 audit exporter Deployment (deploy/gcp/base/audit-exporter)
// passes the agent-observe role contract and Pod Security with its digest on
// AGENT_OBSERVE_IMAGES; the same Pod is denied when the digest is missing.
func TestAuditExporterDeploymentAdmitted(t *testing.T) {
	values := deployValues()
	values["AUDIT_EXPORTER_IMAGE"] = auditExporterImage
	values["AUDIT_EXPORTER_DB_GSA"] = "audit-exporter-db@test-project.iam.gserviceaccount.com"
	values["AUDIT_EXPORTER_DB_USER"] = "audit-exporter-db@test-project.iam"
	values["AUDIT_EXPORTER_KMS_KEY_VERSION"] = "projects/test-project/locations/us-central1/keyRings/r/cryptoKeys/manifest-signing/cryptoKeyVersions/1"
	// JSON-escaped twice like render.py check_value(AUDIT_EXPORTER_PUBLIC_KEY_PEM).
	values["AUDIT_EXPORTER_PUBLIC_KEY_PEM"] = `-----BEGIN PUBLIC KEY-----\\nAAAA\\n-----END PUBLIC KEY-----\\n`
	values["AUDIT_EVIDENCE_BUCKET"], values["AUDIT_DECISION_INPUT_EXPORTS_BUCKET"] = "test-evidence", "test-decision-inputs"
	listed := values["AGENT_OBSERVE_IMAGES"]
	values["AGENT_OBSERVE_IMAGES"] = listed + "," + auditExporterImage
	pods := deploymentPods(t, "deploy/gcp/base/audit-exporter/audit-exporter.yaml", values)
	if len(pods) != 1 || pods[0].Name != "audit-exporter-0" || pods[0].Namespace != "agent-observe" {
		t.Fatalf("want one agent-observe/audit-exporter Deployment, got %d", len(pods))
	}
	expectExactly(t, newCluster(t, values).admit(t, create("agent-observe", pods[0])))
	values["AGENT_OBSERVE_IMAGES"] = listed
	expectExactly(t, newCluster(t, values).admit(t, create("agent-observe", pods[0])), "agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
}
