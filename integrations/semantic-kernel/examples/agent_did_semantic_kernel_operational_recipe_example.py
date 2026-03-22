from __future__ import annotations

import asyncio
import json
import logging

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry

from agent_did_semantic_kernel import create_agent_did_semantic_kernel_integration
from agent_did_semantic_kernel.observability import (
    compose_event_handlers,
    create_json_logger_event_handler,
    serialize_observability_event,
)


async def main() -> None:
    try:
        from semantic_kernel.agents.chat_completion.chat_completion_agent import ChatCompletionAgent
        from semantic_kernel.kernel import Kernel
    except ImportError as error:
        raise RuntimeError(
            "Install the runtime extra first: python -m pip install -e .[runtime]"
        ) from error

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("agent_did_semantic_kernel.operational_recipe")

    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x8484848484848484848484848484848484848484"))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="maf_operational_recipe",
            description="Operational recipe for semantic-kernel runtime plus observability",
            core_model="gpt-4.1-mini",
            system_prompt="Use Agent-DID tools when identity evidence is required.",
            capabilities=["identity:resolve", "signature:verify", "payload:sign"],
        )
    )

    events: list[dict[str, object]] = []
    integration = create_agent_did_semantic_kernel_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True, "document_history": True},
        observability_handler=compose_event_handlers(
            lambda event: events.append(serialize_observability_event(event)),
            create_json_logger_event_handler(logger, extra_fields={"scenario": "operational_recipe"}),
        ),
    )

    plugin = integration.create_semantic_kernel_plugin(plugin_name="agent_did_runtime")
    kernel = Kernel()
    kernel.add_plugin(plugin)
    agent = ChatCompletionAgent(
        name="OperationalVerifier",
        instructions=integration.compose_instructions(
            "Use Agent-DID tools for identity evidence and keep secrets outside model-visible context."
        ),
        kernel=kernel,
        plugins=[plugin],
    )

    result = await kernel.invoke(
        function_name="agent_did_sign_payload",
        plugin_name="agent_did_runtime",
        payload="payload-with-sensitive-business-context",
    )

    print("Agent runtime created:", type(agent).__name__)
    print("Plugin functions:", sorted(plugin.functions.keys()))
    print("Signed DID:", result.value["did"])
    print("Captured observability events:")
    print(json.dumps(events, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
