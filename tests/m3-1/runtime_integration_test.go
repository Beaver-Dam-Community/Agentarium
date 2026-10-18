//go:build integration

package m31

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// runtimeOutcome is the supervisor's one-line JSON run report
// (services/runtime/internal/supervisor.Outcome).
type runtimeOutcome struct {
	RuntimeProcessEpoch string   `json:"runtime_process_epoch"`
	SessionID           string   `json:"session_id"`
	WorkerBindingID     string   `json:"worker_binding_id"`
	RootExecID          string   `json:"root_exec_id"`
	WorkRunID           string   `json:"work_run_id"`
	CheckIDs            []string `json:"check_ids"`
	WorkStarted         bool     `json:"work_started"`
	ActionID            string   `json:"action_id"`
	DecisionID          string   `json:"decision_id"`
	Verdict             string   `json:"verdict"`
	ExecutionState      string   `json:"execution_state"`
	ReasonCodes         []string `json:"reason_codes"`
	Error               string   `json:"error"`
}

// runtimeRun is one agent-runtime container: the real linux supervisor and
// worker binaries in the pinned distroless base, run with the agent-exec
// admission settings that Docker can express (uid 10001, no capabilities,
// no-new-privileges, read-only root, tmpfs /work).
type runtimeRun struct {
	name, container string
}

func startRuntime(t *testing.T, e env, top topology, sim *nodeSim, name, gatewayPort, approvalPoll string) runtimeRun {
	t.Helper()
	ca, err := os.ReadFile(e.path("cfg", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cname := "m31e2e-" + name + "-" + randomHex(4)
	args := []string{"create", "--name", cname, "--label", "m31e2e.run=" + e.runTag, "--platform", e.runtimePlatform,
		"--user", "10001:10001", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
		"--tmpfs", "/work:rw,size=16m,mode=0700,uid=10001,gid=10001",
		"-v", e.rtBin + ":/app/bin:ro",
		"-v", e.path("tokens", name) + ":/run/agentarium/identity:ro",
		"--add-host", "host.docker.internal:host-gateway",
		"-e", "AGENTARIUM_GATEWAY_URL=https://host.docker.internal:" + gatewayPort,
		"-e", "AGENTARIUM_GATEWAY_SAN=" + sanPrefix + "agent-control/sa/policy-gateway",
		"-e", "AGENTARIUM_TRUST_BUNDLE_PEM=" + string(ca),
		"-e", "AGENTARIUM_TOKEN_FILE=/run/agentarium/identity/token",
		"-e", "AGENTARIUM_WORKER_PATH=/app/bin/agent-worker",
		"-e", "AGENTARIUM_SCRATCH_ROOT=/work",
		"-e", "AGENTARIUM_MAX_CONCURRENT_WORKERS=1",
		"-e", "AGENTARIUM_RUNTIME_VERSION=m31-local",
		"-e", "AGENTARIUM_DEMO_TARGET_ID=receiver-primary",
		"-e", "AGENTARIUM_DEMO_SUMMARY=M3-1 local e2e submission (" + name + ")",
		"-e", "AGENTARIUM_APPROVAL_POLL=" + approvalPoll,
		"-e", "AGENTARIUM_APPROVAL_TIMEOUT=5m",
		"-e", "AGENTARIUM_ASSIGNMENT_TIMEOUT=2m",
		"--entrypoint", "/app/bin/agent-runtime", e.runtimeImage}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker create %s: %v\n%s", name, err, out)
	}
	id := strings.TrimSpace(string(out))
	// The container interval exists before the container process starts, as
	// a lifecycle recorder would record it at container start.
	sim.addLifecycle(t, name, id)
	if out, err := exec.Command("docker", "start", cname).CombinedOutput(); err != nil {
		t.Fatalf("docker start %s: %v\n%s", name, err, out)
	}
	info("runtime container %s (%s) started for pod %s", cname, id[:12], top.pods[name].PodUID)
	return runtimeRun{name: name, container: id}
}

// wait blocks until the supervisor exits and returns its outcome line. The
// container log goes to logs/<name>.log.
func (r runtimeRun) wait(t *testing.T, e env, timeout time.Duration) runtimeOutcome {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- exec.Command("docker", "wait", r.container).Run() }()
	select {
	case <-done:
	case <-time.After(timeout):
		_ = exec.Command("docker", "stop", "-t", "5", r.container).Run()
		<-done
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("docker", "logs", r.container)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	_ = cmd.Run()
	_ = os.WriteFile(e.path("logs", r.name+".log"), append(append(stdout.Bytes(), []byte("--- stderr ---\n")...), stderr.Bytes()...), 0o600)
	var out runtimeOutcome
	s := bufio.NewScanner(bytes.NewReader(stdout.Bytes()))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "{") && json.Unmarshal([]byte(line), &out) == nil && out.RuntimeProcessEpoch != "" {
			break
		}
	}
	if out.RuntimeProcessEpoch == "" {
		t.Fatalf("%s produced no outcome line; see %s", r.name, e.path("logs", r.name+".log"))
	}
	b, _ := json.Marshal(out)
	info("%s outcome: %s", r.name, b)
	return out
}

func (r runtimeRun) remove() {
	_ = exec.Command("docker", "rm", "-f", r.container).Run()
}

func (o runtimeOutcome) String() string {
	return fmt.Sprintf("verdict=%s execution_state=%s reasons=%v error=%q", o.Verdict, o.ExecutionState, o.ReasonCodes, o.Error)
}
