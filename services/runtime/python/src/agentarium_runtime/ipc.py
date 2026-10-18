"""Bounded JSON-line action port for the supervisor-assigned socket.

The worker gets no token, certificate, HTTP client or routing session ID.
Cancellation/EOF/protocol errors close this channel; an action is never
resubmitted automatically after an uncertain result.
"""
import asyncio
import json
import socket

from .bridge import BridgeError

MAX_MESSAGE = 64 << 10


def _object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise BridgeError("duplicate IPC key")
        out[key] = value
    return out


class IPCActionPort:
    def __init__(self, channel: socket.socket, timeout: float):
        if timeout <= 0:
            raise ValueError("IPC timeout must be positive")
        self.channel = channel
        self.channel.setblocking(False)
        self.timeout = timeout
        self.lock = asyncio.Lock()
        self.broken = False

    async def submit(self, operation_id, target, arguments):
        packet = json.dumps({"type": "submit_action", "action": {
            "operation_id": operation_id, "requested_target": target, "arguments": arguments}},
            ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
        if len(packet) > MAX_MESSAGE:
            raise BridgeError("IPC request exceeds 64 KiB")
        async with self.lock:
            if self.broken:
                raise BridgeError("IPC channel is closed")
            loop = asyncio.get_running_loop()
            try:
                async with asyncio.timeout(self.timeout):
                    await loop.sock_sendall(self.channel, packet + b"\n")
                    raw = bytearray()
                    while b"\n" not in raw:
                        chunk = await loop.sock_recv(self.channel, min(4096, MAX_MESSAGE + 2 - len(raw)))
                        if not chunk:
                            raise BridgeError("supervisor closed IPC")
                        raw.extend(chunk)
                        if len(raw) > MAX_MESSAGE + 1:
                            raise BridgeError("IPC response exceeds 64 KiB")
                    if raw[-1:] != b"\n" or raw.count(b"\n") != 1:
                        raise BridgeError("unexpected extra IPC response")
                    message = json.loads(raw, object_pairs_hook=_object,
                                         parse_constant=lambda _: (_ for _ in ()).throw(BridgeError("invalid JSON constant")))
                    if not isinstance(message, dict) or set(message) != {"type", "result"} or message["type"] != "action_result" or not isinstance(message["result"], dict):
                        raise BridgeError("unexpected supervisor response")
                    return message["result"]
            except BaseException:
                self.broken = True
                self.channel.close()
                raise
