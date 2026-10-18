"""TASK-15 ADK model/tool bridge. Only the supervisor performs HTTP.

One instance belongs to one released session worker; never share it between
sessions. The port returns a completed action after supervisor readiness,
approval and result polling. No model/provider SDK client is instantiated.
"""
from __future__ import annotations

import copy
import json
from typing import Protocol, runtime_checkable
from uuid import UUID

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.tools.base_tool import BaseTool
from google.genai import types
from jsonschema import Draft202012Validator
from pydantic import PrivateAttr

TOOL_NAMES = ("submit_action", "poll_action", "request_approval")


class BridgeError(RuntimeError):
    """A failed bridge boundary; messages intentionally omit prompt/results."""


@runtime_checkable
class ActionPort(Protocol):
    async def submit(self, operation_id: str, target: dict, arguments: dict) -> dict: ...


def _uuid(value: object) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise BridgeError("invalid action or conversation ID")
    return value


def _message(kind: str, *, text=None, source=None, ref=None, function_name=None) -> dict:
    return {"kind": kind, "role": "model" if kind == "model_turn" else "user",
            "source": source, "text": text, "ref": ref, "function_name": function_name}


def _content(content: types.Content) -> dict:
    return content.model_dump(mode="json", exclude_none=True)


class GatewayLlm(BaseLlm):
    model: str = "agentarium-gateway"
    conversation_id: str
    target_id: str
    system_template: str
    declarations: list[dict]
    port: ActionPort
    max_model_calls: int
    _turns: list[tuple[dict, int]] = PrivateAttr(default_factory=list)
    _calls: int = PrivateAttr(default=0)
    _owned_actions: dict[str, dict] = PrivateAttr(default_factory=dict)
    _busy: bool = PrivateAttr(default=False)

    def model_post_init(self, context) -> None:
        _uuid(self.conversation_id)
        if self.max_model_calls < 1 or not self.target_id or not self.system_template:
            raise BridgeError("missing model limits, target or registered template")
        if [d.get("name") for d in self.declarations] != list(TOOL_NAMES):
            raise BridgeError("the three registered tool declarations are required in order")
        for d in self.declarations:
            if set(d) != {"name", "description", "parameters"}:
                raise BridgeError("invalid registered declaration")
            Draft202012Validator.check_schema(d["parameters"])
        self.declarations = copy.deepcopy(self.declarations)

    def tools(self) -> list[BaseTool]:
        return [GatewayTool(self, d) for d in self.declarations]

    def _messages(self, request: LlmRequest) -> list[dict]:
        if request.config.system_instruction != self.system_template:
            raise BridgeError("system instruction differs from the registered template")
        expected = [GatewayTool(self, d)._get_declaration().model_dump(mode="json", exclude_none=True)
                    for d in self.declarations]
        actual = []
        for tool in request.config.tools or []:
            if not isinstance(tool, types.Tool) or set(tool.model_dump(exclude_none=True)) != {"function_declarations"}:
                raise BridgeError("only registered function tools are allowed")
            actual.extend(d.model_dump(mode="json", exclude_none=True) for d in tool.function_declarations or [])
        if actual != expected:
            raise BridgeError("tool declarations differ from the registered declarations")
        # Generation controls belong to the installed profile, never to ADK.
        configured = request.config.model_dump(exclude_none=True)
        if set(configured) - {"system_instruction", "tools", "labels"}:
            raise BridgeError("ADK generation overrides are not permitted: " + ",".join(sorted(set(configured) - {"system_instruction", "tools", "labels"})))
        messages = [_message("text", source="system", text=self.system_template)]
        turn = 0
        for content in request.contents:
            if content.role == "model":
                if turn >= len(self._turns) or _content(content) != self._turns[turn][0]:
                    raise BridgeError("unrecognized prior model turn")
                messages.append(_message("model_turn", ref={"ref": "model_turn", "action_id": None,
                                                            "turn_index": self._turns[turn][1]}))
                turn += 1
                continue
            if content.role not in ("user", "tool"):
                raise BridgeError("unsupported content role")
            for part in content.parts or []:
                data = part.model_dump(exclude_none=True)
                if set(data) == {"text"}:
                    if len(part.text.encode()) > 16384:
                        raise BridgeError("text exceeds the canonical limit")
                    messages.append(_message("text", source="user", text=part.text))
                elif set(data) == {"function_response"}:
                    fr = part.function_response
                    response = fr.response
                    if fr.name not in TOOL_NAMES or not isinstance(response, dict) or set(response) != {"ref", "action_id"}:
                        raise BridgeError("tool response must be a local action reference")
                    aid = response["action_id"]
                    if response["ref"] != "action_result" or aid not in self._owned_actions:
                        raise BridgeError("tool action is not owned by this bridge")
                    messages.append(_message("tool_result", source="tool_result", function_name=fr.name,
                                             ref={"ref": "action_result", "action_id": aid, "turn_index": None}))
                else:
                    raise BridgeError("unsupported content part")
        if turn != len(self._turns):
            raise BridgeError("prior model turn omitted")
        if len(messages) > 64:
            raise BridgeError("message count exceeds the canonical limit")
        return messages

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False):
        if stream or self._busy:
            raise BridgeError("streaming and concurrent turns are unsupported")
        if self._calls >= self.max_model_calls:
            raise BridgeError("model call limit reached")
        self._busy = True
        try:
            args = {"conversation_id": self.conversation_id, "messages": self._messages(llm_request),
                    "tool_declarations": self.declarations}
            if len(json.dumps(args, ensure_ascii=False).encode()) > 64 << 10:
                raise BridgeError("model request exceeds 64 KiB")
            self._calls += 1
            result = await self.port.submit("model.generate", {"target_id": self.target_id, "profile": "agent"}, args)
            if result.get("execution_state") not in ("accepted", "effect_verified") or result.get("truncated"):
                codes = result.get("reason_codes") or ["MODEL_SCHEMA_INVALID"]
                yield LlmResponse(error_code=str(codes[0]), error_message="model action did not complete successfully")
                return
            if result.get("result_final") is not True:
                raise BridgeError("model action has no stored final result")
            body = result.get("result_body")
            if not isinstance(body, dict) or body.get("conversation_id") != self.conversation_id:
                raise BridgeError("model result has another conversation")
            idx = body.get("turn_index")
            if type(idx) is not int or idx < 0 or (self._turns and idx <= self._turns[-1][1]):
                raise BridgeError("invalid or repeated model turn index")
            text, calls = body.get("text"), body.get("function_calls")
            if not isinstance(text, str) or not isinstance(calls, list):
                raise BridgeError("invalid model result")
            parts = [types.Part(text=text)] if text else []
            declarations = {d["name"]: d for d in self.declarations}
            for i, call in enumerate(calls):
                if not isinstance(call, dict) or set(call) != {"name", "args"} or call["name"] not in declarations:
                    raise BridgeError("unregistered function call")
                if not isinstance(call["args"], dict) or not Draft202012Validator(declarations[call["name"]]["parameters"]).is_valid(call["args"]):
                    raise BridgeError("invalid function arguments")
                parts.append(types.Part(function_call=types.FunctionCall(name=call["name"], args=call["args"],
                                     id=f"{self.conversation_id}:{idx}:{i}")))
            if not parts:
                raise BridgeError("empty model response")
            content = types.Content(role="model", parts=parts)
            self._turns.append((_content(content), idx))
            yield LlmResponse(content=content, turn_complete=True)
        finally:
            self._busy = False


class GatewayTool(BaseTool):
    def __init__(self, bridge: GatewayLlm, declaration: dict):
        super().__init__(name=declaration["name"], description=declaration["description"])
        self.bridge, self.declaration = bridge, declaration

    def _get_declaration(self):
        return types.FunctionDeclaration(name=self.name, description=self.description,
                                         parameters_json_schema=self.declaration["parameters"])

    async def run_async(self, *, args: dict, tool_context) -> dict:
        if not Draft202012Validator(self.declaration["parameters"]).is_valid(args):
            raise BridgeError("invalid tool arguments")
        if self.name == "submit_action":
            if set(args) != {"operation_id", "requested_target", "arguments"} or args["operation_id"] == "model.generate":
                raise BridgeError("invalid typed tool action")
            result = await self.bridge.port.submit(args["operation_id"], args["requested_target"], args["arguments"])
            if result.get("result_final") is not True:
                raise BridgeError("tool action has no stored final result")
            aid = _uuid(result.get("action_id"))
            self.bridge._owned_actions[aid] = copy.deepcopy(result)
        else:
            # submit waits for supervisor polling/approval. These tools only
            # refer to that same action; never mint approval or resubmit it.
            if set(args) != {"action_id"} or args["action_id"] not in self.bridge._owned_actions:
                raise BridgeError("action is not owned by this bridge")
            aid = args["action_id"]
        return {"ref": "action_result", "action_id": aid}
