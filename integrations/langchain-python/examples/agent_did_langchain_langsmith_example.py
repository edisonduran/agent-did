"""LangSmith RunTree example for Agent-DID LangChain Python observability."""

from __future__ import annotations

import asyncio
import json

from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_langchain import create_agent_did_langchain_integration
from agent_did_langchain.observability import create_langsmith_event_handler, create_langsmith_run_tree


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())

    root_run = create_langsmith_run_tree(
        name="agent_did_langchain_demo",
        inputs={"scenario": "langsmith-local-demo"},
        tags=["example", "agent-did"],
    )

    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="langsmith_demo_bot",
            description="LangSmith local tracing demo for Agent-DID tools",
            core_model="gpt-4.1-mini",
            system_prompt="Trace every tool interaction as a local RunTree.",
            capabilities=["audit:events", "identity:trace"],
        )
    )

    integration = create_agent_did_langchain_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        expose={"sign_payload": True, "sign_http": True},
        observability_handler=create_langsmith_event_handler(
            root_run,
            extra_fields={"component": "example", "adapter": "langsmith"},
            tags=["local-demo"],
        ),
    )

    tools_by_name = {tool.name: tool for tool in integration.tools}
    await tools_by_name["agent_did_get_current_identity"].ainvoke({})
    await tools_by_name["agent_did_sign_payload"].ainvoke({"payload": "langsmith-demo-payload"})
    await tools_by_name["agent_did_sign_http_request"].ainvoke(
        {
            "method": "POST",
            "url": "https://api.example.com/v1/tasks?debug=true",
            "body": '{"taskId": 7, "secret": "hidden"}',
        }
    )

    root_run.end(outputs={"child_run_count": len(root_run.child_runs)})
    serialized = root_run.model_dump(exclude_none=True)

    print(json.dumps({"child_run_count": len(root_run.child_runs), "trace": serialized}, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
