"""Fixed fresh-exec worker entry point. No user work before isolation + go.

The native library is built from the same Go isolation package as the demo
worker. It applies the filter with TSYNC, including native-library threads.
"""
import ctypes
import json
import os
import socket

MAX_MESSAGE = 64 << 10
LIBRARY = "/app/lib/agentarium-isolation.so"
CONFIG = "/app/model/runtime.json"
TOOLS = "/app/model/model-tools.json"


def send(channel, message):
    raw = json.dumps(message, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > MAX_MESSAGE:
        raise RuntimeError("IPC message too large")
    channel.sendall(raw + b"\n")


def receive(channel):
    # Bootstrap reads exactly through one newline, leaving no buffered bytes
    # when IPCActionPort takes ownership of the socket.
    raw = bytearray()
    while len(raw) <= MAX_MESSAGE:
        chunk = channel.recv(1)
        if not chunk:
            raise RuntimeError("supervisor closed bootstrap IPC")
        if chunk == b"\n":
            return json.loads(raw)
        raw.extend(chunk)
    raise RuntimeError("bootstrap message too large")


def controls():
    library = ctypes.CDLL(LIBRARY)
    library.ApplyIsolation.restype = ctypes.c_void_p
    library.FreeIsolationReport.argtypes = [ctypes.c_void_p]
    ptr = library.ApplyIsolation()
    if not ptr:
        raise RuntimeError("missing isolation report")
    try:
        return json.loads(ctypes.string_at(ptr))
    finally:
        library.FreeIsolationReport(ptr)


def main():
    os.umask(0o077)
    # Must precede ADK/OpenTelemetry imports. The supervisor supplies only
    # HOME/TMPDIR; inherited provider/telemetry credentials are not present.
    os.environ["OTEL_SDK_DISABLED"] = "true"
    os.environ["ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS"] = "false"
    os.environ["OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT"] = "NO_CONTENT"
    channel = socket.socket(fileno=3)
    try:
        report = controls()
        send(channel, {"type": "bootstrap_ack", **report})
        if report.get("error"):
            return 1
        message = receive(channel)
        if message.get("type") == "stop":
            return 0
        if message.get("type") != "go" or not isinstance(message.get("task"), dict):
            raise RuntimeError("unexpected bootstrap message")
        task = message["task"]
        # Fixed image files, never paths or templates chosen by the task.
        with open(CONFIG) as f:
            config = json.load(f)
        with open(TOOLS) as f:
            tool_profiles = json.load(f)
        if not isinstance(tool_profiles, dict) or set(tool_profiles) != {"agent", "policy_proposal", "intent_check", "discovery"}:
            raise RuntimeError("invalid installed model tool profiles")
        declarations = tool_profiles["agent"]
        import asyncio
        from .bridge import GatewayLlm
        from .ipc import IPCActionPort
        from .runner import run_task
        if set(config) != {"model_target_id", "max_model_calls", "system_template"}:
            raise RuntimeError("invalid installed runtime configuration")
        timeout_ms = task.get("action_timeout_ms")
        if type(timeout_ms) is not int or timeout_ms <= 0:
            raise RuntimeError("missing supervisor action timeout")
        bridge = GatewayLlm(conversation_id=task["conversation_id"], target_id=config["model_target_id"],
                            system_template=config["system_template"], declarations=declarations,
                            max_model_calls=config["max_model_calls"],
                            port=IPCActionPort(channel, timeout_ms / 1000))
        # The socket is nonblocking after IPCActionPort construction; no
        # bootstrap payload or model/tool calls happened before this ack.
        channel.setblocking(True)
        send(channel, {"type": "started", "work_run_id": message["work_run_id"]})
        channel.setblocking(False)
        asyncio.run(run_task(bridge, task["task_statement"]))
        channel.setblocking(True)
        send(channel, {"type": "done", "outcome": "accepted"})
        return 0
    except Exception:
        # No prompts, action bodies, model output, tokens or tracebacks in logs.
        try:
            channel.setblocking(True)
            send(channel, {"type": "done", "outcome": "failed"})
        except OSError:
            pass
        return 1
    finally:
        channel.close()


if __name__ == "__main__":
    raise SystemExit(main())
