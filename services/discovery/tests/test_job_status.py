"""Snapshot Job outcome (TASK-02 3.4, PR #22): our termination message first,
otherwise the reason Kubernetes reported."""

import json

import httpx
import pytest

from agentarium_discovery.clients import KubernetesJobs, kubernetes_failure_reason

IMAGE = "r.example/agentarium/discovery-snapshot@sha256:" + "0" * 64


def jobs_with(tmp_path, monkeypatch, job_status: dict, pods: list[dict]) -> KubernetesJobs:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/apis/batch/v1/" in request.url.path:
            return httpx.Response(200, json={"status": job_status})
        return httpx.Response(200, json={"items": pods})

    token = tmp_path / "token"
    token.write_text("t")
    monkeypatch.setattr(KubernetesJobs, "TOKEN", str(token))
    return KubernetesJobs("agent-observe", IMAGE, "bucket-1", client=httpx.Client(transport=httpx.MockTransport(handler)))


def pod(terminated: dict | None = None, **status) -> dict:
    cs = [{"state": {"terminated": terminated}}] if terminated is not None else []
    return {"status": {"containerStatuses": cs, **status}}


FAILED = {"failed": 1}


def test_limit_error_from_termination_message(tmp_path, monkeypatch):
    msg = json.dumps({"error": "archive limit entries: more than 50000 entries", "limit": "entries"})
    j = jobs_with(tmp_path, monkeypatch, FAILED, [pod({"reason": "Error", "exitCode": 1, "message": msg})])
    st = j.status("job-1")
    assert (st.state, st.error) == ("failed", "archive limit entries: more than 50000 entries")


@pytest.mark.parametrize("job_status,pods,expected", [
    # OOM: the container is killed before writing a termination message.
    (FAILED, [pod({"reason": "OOMKilled", "exitCode": 137})], "OOMKilled"),
    # emptyDir / ephemeral-storage over its limit: the kubelet evicts the Pod.
    (FAILED, [pod(None, phase="Failed", reason="Evicted",
                  message="Pod ephemeral local storage usage exceeds the total limit of containers 2560Mi.")],
     "Evicted: Pod ephemeral local storage usage exceeds the total limit of containers 2560Mi."),
    (FAILED, [pod({"reason": "ContainerStatusUnknown"}, reason="Evicted",
                  message="The node was low on resource: ephemeral-storage.")],
     "Evicted: The node was low on resource: ephemeral-storage."),
    # activeDeadlineSeconds: the Job controller deletes the Pod and sets a condition.
    ({"failed": 1, "conditions": [{"type": "Failed", "status": "True", "reason": "DeadlineExceeded",
                                   "message": "Job was active longer than specified deadline"}]}, [],
     "DeadlineExceeded: Job was active longer than specified deadline"),
    # Nothing known.
    (FAILED, [pod({"reason": "Error", "exitCode": 2})], "snapshot job failed"),
])
def test_kubernetes_reason_when_there_is_no_termination_message(tmp_path, monkeypatch, job_status, pods, expected):
    st = jobs_with(tmp_path, monkeypatch, job_status, pods).status("job-1")
    assert (st.state, st.error) == ("failed", expected)


def test_garbage_termination_message_falls_back_to_kubernetes_reason(tmp_path, monkeypatch):
    j = jobs_with(tmp_path, monkeypatch, FAILED, [pod({"reason": "OOMKilled", "exitCode": 137, "message": "[1,2"})])
    assert j.status("job-1").error == "OOMKilled"
    j = jobs_with(tmp_path, monkeypatch, FAILED, [pod({"reason": "OOMKilled", "exitCode": 137, "message": "[1,2]"})])
    assert j.status("job-1").error == "OOMKilled"


def test_reason_order_container_then_pod_then_job():
    job = {"conditions": [{"type": "Failed", "status": "True", "reason": "BackoffLimitExceeded"}]}
    assert kubernetes_failure_reason(job, [pod({"reason": "OOMKilled"}, reason="Evicted")]) == "OOMKilled"
    assert kubernetes_failure_reason(job, [pod({"reason": "Error"}, reason="Evicted")]) == "Evicted"
    assert kubernetes_failure_reason(job, [pod({"reason": "Error"})]) == "BackoffLimitExceeded"
    assert kubernetes_failure_reason({"conditions": [{"type": "Failed", "status": "False", "reason": "X"}]}, []) is None


def test_failed_request_records_the_reason(env):
    from agentarium_discovery.clients import JobStatus
    snap = {"library": "httpx", "library_version": "0.28.1", "language": "python",
            "source_uri": "gs://disc-bucket/sources/" + "e" * 64 + ".tar.gz", "source_digest": "e" * 64}
    h = {"X-Agentarium-Console-Actor": "google:op", "X-Agentarium-Console-Roles": "operator"}
    assert env.client.post("/internal/discovery/snapshots", json=snap, headers=h).status_code == 202
    env.jobs.result = JobStatus("failed", None, "OOMKilled")
    r = env.client.post("/internal/discovery/snapshots", json=snap, headers=h)
    assert r.status_code == 200 and r.json()["state"] == "failed"
    [req] = list(env.store.snapshot_requests.values())
    assert req.error == "OOMKilled"
