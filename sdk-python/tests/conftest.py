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
    AgentIdentity.get_default_client()._resolver = InMemoryDIDResolver()
    AgentIdentity.get_default_client()._registry = InMemoryAgentRegistry()
    AgentIdentity.get_default_client()._history_store = {}
    AgentIdentity.get_default_client()._did_webvh_log_store = {}
    AgentIdentity.get_default_client()._did_webvh_state_cache = {}
    AgentIdentity.get_default_client()._did_webvh_signer_store = {}
    AgentIdentity.get_default_client()._bootstrap_controllers = {}


@pytest.fixture()
def interop_vectors() -> dict:
    path = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "interop-vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture()
def canonical_document_fixture() -> dict:
    path = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "canonical-document-reference.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture()
def jcs_vectors() -> dict:
    path = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "jcs-vectors.json"
    return json.loads(path.read_text(encoding="utf-8"))
