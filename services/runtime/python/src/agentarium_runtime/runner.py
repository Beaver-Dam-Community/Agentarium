"""Run one task only after the supervisor has released this worker."""
from google.adk.agents import LlmAgent
from google.adk.agents.run_config import RunConfig
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.telemetry.context import ContentCapturingMode, TelemetryConfig
from google.genai import types

from .bridge import BridgeError, GatewayLlm

# ADK 2.12.0 appends this identity text to instruction. The fully expanded
# value, including this suffix, must be the server-registered template.
IDENTITY_SUFFIX = '\n\nYou are an agent. Your internal name is "agentarium".'


async def run_task(bridge: GatewayLlm, task_statement: str) -> str:
    if not bridge.system_template.endswith(IDENTITY_SUFFIX):
        raise BridgeError("registered template does not include the pinned ADK identity")
    agent = LlmAgent(name="agentarium", model=bridge, tools=bridge.tools(),
                     instruction=bridge.system_template.removesuffix(IDENTITY_SUFFIX))
    sessions = InMemorySessionService()
    await sessions.create_session(app_name="agentarium", user_id="worker", session_id=bridge.conversation_id)
    runner = Runner(agent=agent, app_name="agentarium", session_service=sessions)
    run_config = RunConfig(max_llm_calls=bridge.max_model_calls, telemetry=TelemetryConfig(
        capture_message_content=ContentCapturingMode.NO_CONTENT,
        genai_semconv_stability_opt_in="stable", adk_experimental_telemetry_opt_in=False,
        experimental_features_opt_in=frozenset()))
    answer = None
    try:
        async for event in runner.run_async(user_id="worker", session_id=bridge.conversation_id,
                new_message=types.Content(role="user", parts=[types.Part(text=task_statement)]), run_config=run_config):
            if event.error_code:
                raise BridgeError("model action failed")
            if event.is_final_response() and event.content:
                answer = "".join(p.text for p in event.content.parts or [] if p.text and not p.thought)
    finally:
        await runner.close()
    if answer is None:
        raise BridgeError("task ended without a final response")
    return answer
