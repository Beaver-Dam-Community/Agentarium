import asyncio
import json
import socket

import pytest

from agentarium_runtime.bridge import BridgeError
from agentarium_runtime.ipc import IPCActionPort, MAX_MESSAGE


def test_socketpair_action_roundtrip_has_no_session_authority_or_token():
    async def run():
        a, b = socket.socketpair(); b.setblocking(False)
        port = IPCActionPort(a, timeout=1)
        async def supervisor():
            loop = asyncio.get_running_loop()
            message = json.loads(await loop.sock_recv(b, MAX_MESSAGE))
            assert set(message) == {"type", "action"}
            assert set(message["action"]) == {"operation_id", "requested_target", "arguments"}
            await loop.sock_sendall(b, b'{"type":"action_result","result":{"execution_state":"accepted","result_body":{"text":"ok"}}}\n')
        try:
            _, result = await asyncio.gather(supervisor(), port.submit("model.generate", {"profile": "agent"}, {}))
            assert result["result_body"]["text"] == "ok"
        finally:
            a.close(); b.close()
    asyncio.run(run())


def test_broken_channel_does_not_resubmit():
    async def run():
        a, b = socket.socketpair(); b.close()
        port = IPCActionPort(a, timeout=1)
        with pytest.raises((BrokenPipeError, ConnectionResetError, BridgeError)):
            await port.submit("receiver.submit", {}, {})
        assert port.broken
        with pytest.raises(BridgeError, match="closed"):
            await port.submit("receiver.submit", {}, {})
    asyncio.run(run())


def test_duplicate_response_key_is_rejected_and_channel_closed():
    async def run():
        a, b = socket.socketpair(); b.setblocking(False)
        port = IPCActionPort(a, timeout=1)
        async def supervisor():
            loop = asyncio.get_running_loop()
            await loop.sock_recv(b, MAX_MESSAGE)
            await loop.sock_sendall(b, b'{"type":"action_result","type":"stop","result":{}}\n')
        task = asyncio.create_task(supervisor())
        try:
            with pytest.raises(BridgeError, match="duplicate"):
                await port.submit("model.generate", {}, {})
            await task
            assert port.broken
        finally:
            a.close(); b.close()
    asyncio.run(run())
