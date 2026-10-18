"""Container integration: actual fresh Python exec, native seccomp, ADK, IPC.

Run inside Dockerfile.adk built with the synthetic model-config fixture.
The parent emulates the supervisor's released task/action replies, not Gemini.
"""
import json
import os
import socket
import subprocess

SID = "00000000-0000-4000-8000-000000000001"
AID = "00000000-0000-4000-8000-000000000002"


def start():
    child, parent = socket.socketpair()
    assert child.fileno() == 3, "test must start without extra inherited descriptors"
    parent.settimeout(30)
    proc = subprocess.Popen(["/app/venv/bin/python", "-I", "-m", "agentarium_runtime.worker"],
                            pass_fds=(3,), close_fds=True, env={"HOME": "/tmp", "TMPDIR": "/tmp"},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    child.close()
    return proc, parent


def recv(channel):
    raw = bytearray()
    while True:
        part = channel.recv(1)
        assert part, "worker closed IPC early"
        if part == b"\n":
            return json.loads(raw)
        raw.extend(part)
        assert len(raw) <= 65536


def send(channel, value):
    channel.sendall(json.dumps(value).encode() + b"\n")


def ack(channel):
    message = recv(channel)
    assert message["type"] == "bootstrap_ack", message
    assert not message.get("error"), message
    report = message["controls"]
    assert report["profile"] == "process_baseline" and report["seccomp_tsync"] is True
    assert report["checks"]["dumpable"] == "0"
    assert report["checks"]["prctl_set_dumpable"] == "EPERM"
    assert "execve" in report["denied_syscalls"]
    assert report["checks"]["no_new_privs"] == "1"


proc, channel = start()
try:
    ack(channel)
    send(channel, {"type": "stop"})
    stdout, stderr = proc.communicate(timeout=15)
    assert proc.returncode == 0 and not stdout, (proc.returncode, stdout, stderr)
finally:
    channel.close()
    if proc.poll() is None:
        proc.kill(); proc.wait()

proc, channel = start()
try:
    ack(channel)
    send(channel, {"type": "go", "work_run_id": "run-test", "task": {
        "action_timeout_ms": 900000, "conversation_id": SID, "task_statement": "Send a synthetic summary", "target_id": "receiver-primary",
        "summary": "", "email": None}})
    assert recv(channel)["type"] == "started"
    first = recv(channel)
    assert first["action"]["operation_id"] == "model.generate"
    assert first["action"]["arguments"]["conversation_id"] == SID
    send(channel, {"type": "action_result", "result": {"execution_state": "accepted", "result_final": True, "result_body": {
        "conversation_id": SID, "turn_index": 0, "text": "", "function_calls": [{"name": "submit_action", "args": {
            "operation_id": "receiver.submit", "requested_target": {"target_id": "receiver-primary"},
            "arguments": {"payload": {"summary": "synthetic", "email": None}}}}]}}})
    tool = recv(channel)
    assert tool["action"]["operation_id"] == "receiver.submit"
    send(channel, {"type": "action_result", "result": {"action_id": AID, "execution_state": "accepted", "result_final": True}})
    second = recv(channel)
    assert second["action"]["operation_id"] == "model.generate"
    messages = second["action"]["arguments"]["messages"]
    assert messages[-2]["ref"]["turn_index"] == 0
    assert messages[-1]["ref"]["action_id"] == AID
    send(channel, {"type": "action_result", "result": {"execution_state": "accepted", "result_final": True, "result_body": {
        "conversation_id": SID, "turn_index": 1, "text": "Completed", "function_calls": []}}})
    assert recv(channel) == {"type": "done", "outcome": "accepted"}
    stdout, stderr = proc.communicate(timeout=15)
    assert proc.returncode == 0 and not stdout, (proc.returncode, stdout, stderr)
    assert b"Completed" not in stderr and b"synthetic" not in stderr
finally:
    channel.close()
    if proc.poll() is None:
        proc.kill(); proc.wait()
print("PASS: bootstrap stop + process_baseline + ADK model/tool/model over IPC")
