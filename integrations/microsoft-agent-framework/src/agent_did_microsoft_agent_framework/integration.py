"""Public integration assembly for Agent-DID and Microsoft Agent Framework."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from agent_did_sdk import AgentDIDDocument, AgentIdentity
from agent_framework import Agent, AgentExecutor, Case, Default, FunctionExecutor, WorkflowBuilder

from .config import AgentDidExposureConfig, AgentDidMicrosoftAgentFrameworkConfig
from .context import compose_instructions
from .handoff import (
    ActionClass,
    VerificationBlockedCallback,
    build_handoff_verifier_executor,
)
from .observability import AgentDidEventHandler, AgentDidObserver
from .snapshot import AgentDidIdentitySnapshot, RuntimeIdentity, build_agent_did_identity_snapshot
from .tools import create_agent_framework_tools


class AgentDidWorkflowBuilder(WorkflowBuilder):
    """`WorkflowBuilder` subclass exposing Agent-DID-aware handoff helpers.

    The only behavioural addition is :py:meth:`add_verified_handoff`, which inserts
    a verification ``FunctionExecutor`` between two existing executors. All other
    methods inherit from the upstream ``WorkflowBuilder`` unchanged.
    """

    _agent_did_observer: AgentDidObserver | None = None

    def add_verified_handoff(
        self,
        from_executor: Any,
        to_executor: Any,
        *,
        action_class: ActionClass = "reversible",
        allowed_dids: Sequence[str] | None = None,
        require_signature: bool = True,
        on_verification_blocked: VerificationBlockedCallback | None = None,
        ttl_seconds: int | None = None,
        cross_domain: bool | None = None,
        executor_id: str | None = None,
        output_type: Any = object,
    ) -> AgentDidWorkflowBuilder:
        """Insert an Agent-DID verifier between ``from_executor`` and ``to_executor``.

        See ``handoff.py`` for the full design contract. This method only wires
        the verifier executor into the workflow graph; verification semantics
        (TTL, key rotation, signature checks) live in the helper module.
        """

        if self._agent_did_observer is None:
            raise RuntimeError(
                "AgentDidWorkflowBuilder is missing an observer. "
                "Use AgentDidMicrosoftAgentFrameworkIntegration.create_workflow_builder(...) "
                "to obtain a properly wired builder."
            )

        verifier = build_handoff_verifier_executor(
            from_executor=from_executor,
            to_executor=to_executor,
            action_class=action_class,
            ttl_seconds=ttl_seconds,
            allowed_dids=allowed_dids,
            require_signature=require_signature,
            cross_domain=cross_domain,
            on_verification_blocked=on_verification_blocked,
            observer=self._agent_did_observer,
            executor_id=executor_id,
            output_type=output_type,
        )
        self.add_edge(from_executor, verifier)
        self.add_edge(verifier, to_executor)
        return self


@dataclass(slots=True)
class AgentDidMicrosoftAgentFrameworkIntegration:
    agent_identity: AgentIdentity
    runtime_identity_ref: list[RuntimeIdentity]
    config: AgentDidMicrosoftAgentFrameworkConfig
    observer: AgentDidObserver
    tools: list[Any]

    @property
    def runtime_identity(self) -> RuntimeIdentity:
        return self.runtime_identity_ref[0]

    def _capture_identity_snapshot(self, reason: str) -> AgentDidIdentitySnapshot:
        snapshot = build_agent_did_identity_snapshot(self.runtime_identity)
        self.observer.emit(
            "agent_did.identity_snapshot.refreshed",
            attributes={
                "did": snapshot.did,
                "authentication_key_id": snapshot.authentication_key_id,
                "reason": reason,
            },
        )
        return snapshot

    @property
    def identity_snapshot(self) -> AgentDidIdentitySnapshot:
        return self._capture_identity_snapshot("property_access")

    def get_current_identity(self) -> dict[str, Any]:
        return self._capture_identity_snapshot("get_current_identity").model_dump(exclude_none=True)

    def get_current_document(self) -> AgentDIDDocument:
        return self.runtime_identity.document

    def get_tool(self, tool_name: str) -> Any:
        for tool in self.tools:
            if tool.name == tool_name:
                return tool
        raise KeyError(f"Unknown Agent-DID tool: {tool_name}")

    def compose_instructions(
        self,
        base_instructions: str | None = None,
        additional_instructions: str | None = None,
    ) -> str:
        effective_additional = additional_instructions or self.config.additional_instructions
        return compose_instructions(
            base_instructions,
            self._capture_identity_snapshot("compose_instructions"),
            effective_additional,
        )

    def create_agent_kwargs(self, base_instructions: str | None = None) -> dict[str, Any]:
        return {
            "instructions": self.compose_instructions(base_instructions),
            "tools": self.tools,
        }

    def create_agent(
        self,
        client: Any,
        *,
        name: str | None = None,
        description: str | None = None,
        base_instructions: str | None = None,
        **kwargs: Any,
    ) -> Agent:
        agent_kwargs = self.create_agent_kwargs(base_instructions)
        agent_kwargs.update(kwargs)
        return Agent(
            client=client,
            name=name,
            description=description,
            **agent_kwargs,
        )

    def create_agent_executor(
        self,
        agent: Any,
        *,
        session: Any | None = None,
        executor_id: str | None = None,
    ) -> AgentExecutor:
        executor = AgentExecutor(agent=agent, session=session, id=executor_id)
        self.observer.emit(
            "agent_did.workflow.executor_created",
            attributes={
                "executor_id": executor_id or getattr(executor, "id", None) or getattr(agent, "name", None),
                "agent_name": getattr(agent, "name", None),
            },
        )
        return executor

    def create_function_executor(
        self,
        func: Any,
        *,
        executor_id: str | None = None,
        input_type: Any | None = None,
        output_type: Any | None = None,
        workflow_output_type: Any | None = None,
    ) -> FunctionExecutor:
        executor = FunctionExecutor(
            func,
            id=executor_id,
            input=input_type,
            output=output_type,
            workflow_output=workflow_output_type,
        )
        self.observer.emit(
            "agent_did.workflow.function_executor_created",
            attributes={
                "executor_id": executor_id or getattr(executor, "id", None),
                "callable_name": getattr(func, "__name__", type(func).__name__),
            },
        )
        return executor

    def create_workflow_builder(
        self,
        start_executor: Any,
        *,
        name: str | None = None,
        description: str | None = None,
        output_executors: Sequence[Any] | None = None,
        max_iterations: int = 100,
        checkpoint_storage: Any | None = None,
    ) -> WorkflowBuilder:
        builder = AgentDidWorkflowBuilder(
            max_iterations=max_iterations,
            name=name,
            description=description,
            start_executor=start_executor,
            checkpoint_storage=checkpoint_storage,
            output_executors=list(output_executors) if output_executors is not None else None,
        )
        builder._agent_did_observer = self.observer
        self.observer.emit(
            "agent_did.workflow.builder_created",
            attributes={
                "workflow_name": name or "agent_did_workflow",
                "max_iterations": max_iterations,
                "output_executor_count": len(output_executors or []),
            },
        )
        return builder

    def build_workflow_chain(
        self,
        executors: Sequence[Any],
        *,
        name: str = "agent_did_workflow",
        description: str | None = None,
        max_iterations: int = 100,
        checkpoint_storage: Any | None = None,
    ) -> Any:
        normalized_executors = list(executors)
        if not normalized_executors:
            raise ValueError("executors must not be empty")

        builder = self.create_workflow_builder(
            normalized_executors[0],
            name=name,
            description=description,
            output_executors=[normalized_executors[-1]],
            max_iterations=max_iterations,
            checkpoint_storage=checkpoint_storage,
        )
        builder.add_chain(normalized_executors)
        workflow = builder.build()
        self.observer.emit(
            "agent_did.workflow.chain_built",
            attributes={
                "workflow_name": name,
                "executor_count": len(normalized_executors),
            },
        )
        return workflow

    def build_fan_out_fan_in_workflow(
        self,
        source_executor: Any,
        parallel_executors: Sequence[Any],
        target_executor: Any,
        *,
        name: str = "agent_did_fan_out_fan_in_workflow",
        description: str | None = None,
        max_iterations: int = 100,
        checkpoint_storage: Any | None = None,
    ) -> Any:
        normalized_parallel = list(parallel_executors)
        if not normalized_parallel:
            raise ValueError("parallel_executors must not be empty")

        builder = self.create_workflow_builder(
            source_executor,
            name=name,
            description=description,
            output_executors=[target_executor],
            max_iterations=max_iterations,
            checkpoint_storage=checkpoint_storage,
        )
        builder.add_fan_out_edges(source_executor, normalized_parallel)
        builder.add_fan_in_edges(normalized_parallel, target_executor)
        workflow = builder.build()
        self.observer.emit(
            "agent_did.workflow.fan_out_fan_in_built",
            attributes={
                "workflow_name": name,
                "parallel_executor_count": len(normalized_parallel),
            },
        )
        return workflow

    def build_multi_selection_workflow(
        self,
        source_executor: Any,
        targets: Sequence[Any],
        selection_func: Any,
        *,
        name: str = "agent_did_multi_selection_workflow",
        description: str | None = None,
        output_executors: Sequence[Any] | None = None,
        max_iterations: int = 100,
        checkpoint_storage: Any | None = None,
    ) -> Any:
        normalized_targets = list(targets)
        if not normalized_targets:
            raise ValueError("targets must not be empty")

        builder = self.create_workflow_builder(
            source_executor,
            name=name,
            description=description,
            output_executors=output_executors or normalized_targets,
            max_iterations=max_iterations,
            checkpoint_storage=checkpoint_storage,
        )
        builder.add_multi_selection_edge_group(source_executor, normalized_targets, selection_func)
        workflow = builder.build()
        self.observer.emit(
            "agent_did.workflow.multi_selection_built",
            attributes={
                "workflow_name": name,
                "target_count": len(normalized_targets),
            },
        )
        return workflow

    def build_switch_case_workflow(
        self,
        source_executor: Any,
        cases: Sequence[tuple[Any, Any]],
        *,
        default_target: Any | None = None,
        name: str = "agent_did_switch_case_workflow",
        description: str | None = None,
        output_executors: Sequence[Any] | None = None,
        max_iterations: int = 100,
        checkpoint_storage: Any | None = None,
    ) -> Any:
        normalized_cases = [Case(condition=condition, target=target) for condition, target in cases]
        if not normalized_cases:
            raise ValueError("cases must not be empty")

        edge_cases: list[Any] = list(normalized_cases)
        if default_target is not None:
            edge_cases.append(Default(target=default_target))

        builder = self.create_workflow_builder(
            source_executor,
            name=name,
            description=description,
            output_executors=output_executors,
            max_iterations=max_iterations,
            checkpoint_storage=checkpoint_storage,
        )
        builder.add_switch_case_edge_group(source_executor, edge_cases)
        workflow = builder.build()
        self.observer.emit(
            "agent_did.workflow.switch_case_built",
            attributes={
                "workflow_name": name,
                "case_count": len(normalized_cases),
                "has_default": default_target is not None,
            },
        )
        return workflow


def create_agent_did_microsoft_agent_framework_integration(
    *,
    agent_identity: AgentIdentity,
    runtime_identity: RuntimeIdentity,
    expose: AgentDidExposureConfig | dict[str, Any] | None = None,
    tool_prefix: str = "agent_did",
    additional_instructions: str | None = None,
    allow_private_network_targets: bool = False,
    tool_approval_mode: Literal["always_require", "never_require"] = "never_require",
    observability_handler: AgentDidEventHandler | None = None,
    logger: logging.Logger | None = None,
) -> AgentDidMicrosoftAgentFrameworkIntegration:
    exposure = (
        expose if isinstance(expose, AgentDidExposureConfig) else AgentDidExposureConfig.model_validate(expose or {})
    )
    config = AgentDidMicrosoftAgentFrameworkConfig(
        expose=exposure,
        tool_prefix=tool_prefix,
        additional_instructions=additional_instructions,
        allow_private_network_targets=allow_private_network_targets,
        tool_approval_mode=tool_approval_mode,
    )
    runtime_identity_ref = [runtime_identity]
    observer = AgentDidObserver(event_handler=observability_handler, logger=logger)
    tools = create_agent_framework_tools(
        agent_identity=agent_identity,
        runtime_identity_ref=runtime_identity_ref,
        expose=config.expose,
        tool_prefix=config.tool_prefix,
        allow_private_network_targets=config.allow_private_network_targets,
        observer=observer,
        tool_approval_mode=config.tool_approval_mode,
    )

    return AgentDidMicrosoftAgentFrameworkIntegration(
        agent_identity=agent_identity,
        runtime_identity_ref=runtime_identity_ref,
        config=config,
        observer=observer,
        tools=tools,
    )
