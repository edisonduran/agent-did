"""Runs a real CrewAI task through ``Crew.kickoff`` with a fake LLM: the guardrail, the callbacks and the observer
must work on CrewAI's own ``TaskOutput`` objects, not only on dictionaries."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import pytest
from agent_did_sdk import AgentIdentity, AgentIdentityConfig, CreateAgentParams, InMemoryAgentRegistry, LocalKeySigner

from agent_did_crewai import create_agent_did_crewai_integration
from agent_did_crewai.observability import create_json_logger_event_handler

crewai = pytest.importorskip("crewai")
base_llm = pytest.importorskip("crewai.llms.base_llm")


class _FakeLLM(base_llm.BaseLLM):  # type: ignore[misc,name-defined]
    """Answers every call with a fixed final answer."""

    answer: str = ""

    def call(self, messages: Any, *args: Any, **kwargs: Any) -> str:
        return f"Thought: I know the answer.\nFinal Answer: {self.answer}"

    def supports_function_calling(self) -> bool:
        return False

    def supports_stop_words(self) -> bool:
        return False

    def get_context_window_size(self) -> int:
        return 8192


def _integration(**kwargs: Any) -> Any:
    # CrewAI refuses synchronous kickoff inside a running event loop, so the tests are synchronous.
    AgentIdentity.set_registry(InMemoryAgentRegistry())
    identity = AgentIdentity(AgentIdentityConfig(controller_signer=LocalKeySigner.generate()[0]))
    runtime_identity = asyncio.run(
        identity.create(CreateAgentParams(name="KickoffBot", core_model="fake", system_prompt="Answer with JSON."))
    )
    return create_agent_did_crewai_integration(agent_identity=identity, runtime_identity=runtime_identity, **kwargs)


def _crew(integration: Any, answer: str, *, required: list[str]) -> Any:
    agent = crewai.Agent(
        role="Reporter",
        goal="Report a result",
        llm=_FakeLLM(model="fake", answer=answer),
        **integration.create_agent_kwargs("Kickoff test"),
    )
    task = crewai.Task(
        description="Return a JSON object with did and result.",
        expected_output="A JSON object with did and result.",
        agent=agent,
        guardrail_max_retries=0,
        **integration.create_task_kwargs(required_output_fields=required, include_tools=False),
    )
    return crewai.Crew(agents=[agent], tasks=[task], **integration.create_crew_kwargs())


def test_a_task_whose_output_passes_the_guardrail_completes() -> None:
    integration = _integration()
    answer = json.dumps({"did": integration.identity_snapshot.did, "result": "done"})

    output = _crew(integration, answer, required=["result"]).kickoff()

    assert json.loads(output.raw) == {"did": integration.identity_snapshot.did, "result": "done"}


def test_a_task_whose_output_names_another_did_is_blocked() -> None:
    integration = _integration()
    answer = json.dumps({"did": "did:webvh:QmOther:example.com", "result": "done"})

    with pytest.raises(Exception, match="Unexpected DID in output"):
        _crew(integration, answer, required=["result"]).kickoff()


def test_a_task_missing_a_required_field_is_blocked() -> None:
    integration = _integration()
    answer = json.dumps({"did": integration.identity_snapshot.did})

    with pytest.raises(Exception, match="result"):
        _crew(integration, answer, required=["result"]).kickoff()


def test_callbacks_give_the_observer_sanitized_values_that_serialize(caplog: pytest.LogCaptureFixture) -> None:
    logger = logging.getLogger("agent_did_crewai.kickoff")
    integration = _integration(observability_handler=create_json_logger_event_handler(logger), logger=logger)
    answer = json.dumps({"did": integration.identity_snapshot.did, "result": "done", "signature": "secret-sig"})

    with caplog.at_level(logging.INFO, logger="agent_did_crewai.kickoff"):
        with pytest.raises(Exception, match="Sensitive output fields"):
            _crew(integration, answer, required=["result"]).kickoff()
        ok_answer = json.dumps({"did": integration.identity_snapshot.did, "result": "ok"})
        _crew(integration, ok_answer, required=[]).kickoff()

    json_records = [json.loads(r.getMessage()) for r in caplog.records if r.getMessage().startswith("{")]
    assert any(record["event_type"] == "agent_did.crewai.task" for record in json_records)
    assert "secret-sig" not in caplog.text
    assert "TaskOutput(" not in caplog.text
