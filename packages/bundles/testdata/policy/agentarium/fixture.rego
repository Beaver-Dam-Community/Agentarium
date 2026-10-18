# Test fixture only. The production gateway policy is policies/gateway/decision.rego (TASK-04, M2-6).
package agentarium.fixture

default allowed := false

allowed if input.ok == true
