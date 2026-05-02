"""End-to-end example for ``add_verified_handoff`` (issue #26).

Builds a 3-executor workflow with one verified handoff between the second and
third stages. Demonstrates:

- ``SignedHandoffMessage`` wiring (upstream wraps the message with signature
  metadata produced via the SDK).
- Default ``action_class="reversible"`` TTL semantics.
- Observability events emitted by the verifier (``handoff_verified``).

Reference threads:
- microsoft/agent-framework#4842
- edisonduran/agent-did#26
"""

from __future__ import annotations

import asyncio
import time

from agent_did_sdk import (
    AgentIdentity,
    AgentIdentityConfig,
    CreateAgentParams,
    InMemoryAgentRegistry,
)
from agent_framework import WorkflowContext

from agent_did_microsoft_agent_framework import (
    SignedHandoffMessage,
    create_agent_did_microsoft_agent_framework_integration,
)


async def main() -> None:
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(
        AgentIdentityConfig(signer_address="0x4242424242424242424242424242424242424242")
    )
    runtime_identity = await identity.create(
        CreateAgentParams(
            name="VerifiedHandoffDemo",
            core_model="gpt-4.1-mini",
            system_prompt="Demo agent for verified handoff.",
        )
    )

    events: list[dict] = []

    def on_event(event):
        events.append({"event_type": event.event_type, **event.attributes})

    integration = create_agent_did_microsoft_agent_framework_integration(
        agent_identity=identity,
        runtime_identity=runtime_identity,
        observability_handler=on_event,
    )

    # Stage 1 — intake. Forwards the raw payload via the workflow context.
    async def intake(payload: str, ctx: WorkflowContext[str]) -> None:
        await ctx.send_message(f"intake:{payload}")

    # Stage 2 — enrichment. Wraps its output as a SignedHandoffMessage so the
    # verifier can enforce identity at the next edge.
    async def enrichment(payload: str, ctx: WorkflowContext[SignedHandoffMessage]) -> None:
        signed_payload = f"enrichment:{payload}"
        signature = await identity.sign_message(signed_payload, runtime_identity.agent_private_key)
        await ctx.send_message(
            SignedHandoffMessage(
                payload=signed_payload,
                did=runtime_identity.document.id,
                signature=signature,
                signed_at=time.time(),
                key_id=f"{runtime_identity.document.id}#key-1",
            )
        )

    # Stage 3 — execution. Receives the inner payload after verification and
    # yields it as the workflow's final output.
    async def execution(payload: str, ctx: WorkflowContext[str, str]) -> None:
        await ctx.yield_output(f"execution:{payload}")

    intake_executor = integration.create_function_executor(
        intake, executor_id="intake", input_type=str, output_type=str
    )
    enrichment_executor = integration.create_function_executor(
        enrichment, executor_id="enrichment", input_type=str, output_type=SignedHandoffMessage
    )
    execution_executor = integration.create_function_executor(
        execution,
        executor_id="execution",
        input_type=str,
        output_type=str,
        workflow_output_type=str,
    )

    builder = integration.create_workflow_builder(
        intake_executor,
        name="verified_handoff_demo",
        output_executors=[execution_executor],
    )
    builder.add_edge(intake_executor, enrichment_executor)
    builder.add_verified_handoff(
        from_executor=enrichment_executor,
        to_executor=execution_executor,
        action_class="reversible",
        allowed_dids=[runtime_identity.document.id],
        output_type=str,
    )
    workflow = builder.build()

    await workflow.run("approve:order-42")

    verified = [e for e in events if e["event_type"] == "agent_did.workflow.handoff_verified"]
    print(f"Workflow completed. Verified handoffs emitted: {len(verified)}")
    if verified:
        print(f"  from_did={verified[0]['from_did']}")
        print(f"  action_class={verified[0]['action_class']} ttl_seconds={verified[0]['ttl_seconds']}")


if __name__ == "__main__":
    asyncio.run(main())
