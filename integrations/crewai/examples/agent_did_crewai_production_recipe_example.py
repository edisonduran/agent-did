from __future__ import annotations

import asyncio
import importlib
import logging
import os
from pprint import pprint

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_crewai import create_agent_did_crewai_integration
from agent_did_crewai.guardrails import create_identity_output_guardrail
from agent_did_crewai.observability import compose_event_handlers, create_json_logger_event_handler


async def main() -> None:
    if os.getenv("RUN_CREWAI_PRODUCTION_EXAMPLE") != "1":
        print("Set RUN_CREWAI_PRODUCTION_EXAMPLE=1 to execute this recipe.")
        return

    target_url = os.getenv("AGENT_DID_CREWAI_TARGET_URL", "https://api.example.com/orders")
    environment = os.getenv("AGENT_DID_ENVIRONMENT", "dev")

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x9895959595959595959595959595959595959595"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="crewai_production_assistant",
            description="Production-style CrewAI recipe for Agent-DID identities",
            core_model="gpt-4.1-mini",
            system_prompt="Operate with structured outputs, verifiable traceability and secure HTTP signing.",
            capabilities=["audit:trace", "http:sign", "verify:signature"],
        )
    )

    logger = logging.getLogger("agent_did_crewai.production")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.addHandler(logging.StreamHandler())

    local_events = []
    integration = create_agent_did_crewai_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_http": True, "sign_payload": True, "verify_signatures": True},
        additional_system_context="Return only structured outputs with did, audit_status and result.",
        observability_handler=compose_event_handlers(
            local_events.append,
            create_json_logger_event_handler(
                logger,
                extra_fields={"service": "agent-gateway", "environment": environment},
            ),
        ),
    )
    tools_by_name = {tool.name: tool for tool in integration.tools}

    signed_http = await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {"method": "POST", "url": target_url, "body": '{"order_id": 123, "status": "approved"}'}
    )
    signed_payload = await tools_by_name["agent_did_sign_payload"].ainvoke(
        {"payload": '{"audit_status": "signed", "result": "approved"}'}
    )

    output_guardrail = create_identity_output_guardrail(
        integration,
        required_fields=["audit_status", "result"],
    )
    allowed_output = {
        "did": runtime_identity.document.id,
        "audit_status": "signed",
        "result": "approved",
    }
    guardrail_allowed, guardrail_message = output_guardrail(allowed_output)

    task_kwargs = integration.create_task_kwargs(required_output_fields=["audit_status", "result"])
    crew_kwargs = integration.create_crew_kwargs()
    agent_kwargs = integration.create_agent_kwargs("Use Agent-DID tools only when they improve auditability.")

    try:
        crewai_module = importlib.import_module("crewai")
        crewai_agent_cls = getattr(crewai_module, "Agent")
        crewai_task_cls = getattr(crewai_module, "Task")
        crewai_crew_cls = getattr(crewai_module, "Crew")
    except ImportError:
        crewai_agent_cls = crewai_task_cls = crewai_crew_cls = None

    result = {
        "did": runtime_identity.document.id,
        "environment": environment,
        "target_url": target_url,
        "signed_http_headers": sorted(signed_http.get("headers", {}).keys()),
        "signed_payload_key_id": signed_payload.get("key_id"),
        "guardrail_allowed": guardrail_allowed,
        "guardrail_message": guardrail_message,
        "output_model_fields": sorted(task_kwargs["output_pydantic"].model_fields.keys()),
        "captured_event_types": [event.event_type for event in local_events],
        "crewai_runtime_available": crewai_agent_cls is not None,
    }

    if crewai_agent_cls is not None and crewai_task_cls is not None and crewai_crew_cls is not None:
        agent = crewai_agent_cls(role="Verifier", goal="Return structured verifiable output", **agent_kwargs)
        task = crewai_task_cls(
            description="Return a dictionary with did, audit_status and result.",
            expected_output="A dictionary with did, audit_status and result.",
            agent=agent,
            **task_kwargs,
        )
        crew = crewai_crew_cls(agents=[agent], tasks=[task], **crew_kwargs)
        result["crewai_objects"] = {
            "agent_type": type(agent).__name__,
            "task_type": type(task).__name__,
            "crew_type": type(crew).__name__,
        }

    pprint(result)


if __name__ == "__main__":
    asyncio.run(main())
