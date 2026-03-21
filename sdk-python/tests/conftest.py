"""Shared fixtures for the agent-did-sdk test suite."""

from __future__ import annotations

import json
import pathlib

import pytest

from agent_did_sdk.core.identity import AgentIdentity
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver


@pytest.fixture(autouse=True)
def _reset_agent_identity() -> None:
    """Reset AgentIdentity class-level state before each test."""
    AgentIdentity._resolver = InMemoryDIDResolver()
    AgentIdentity._registry = InMemoryAgentRegistry()
    AgentIdentity._history_store = {}


@pytest.fixture()
def interop_vectors() -> dict:
    path = pathlib.Path(__file__).parent / "fixtures" / "interop-vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))
