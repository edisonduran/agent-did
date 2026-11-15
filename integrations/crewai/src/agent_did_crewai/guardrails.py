"""Lightweight guardrail helpers for CrewAI outputs."""

import json
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Tuple, cast  # noqa: UP035

from pydantic import BaseModel

from .integration import AgentDidCrewAIIntegration
from .sanitization import find_sensitive_paths, normalize_output

GuardrailResult = Tuple[bool, Any]  # noqa: UP006


def extract_agent_output(output: Any) -> dict[str, Any] | None:
    """The agent's structured output as a dictionary, or ``None`` when it has none.

    A CrewAI ``TaskOutput`` carries it in ``pydantic`` (with ``output_pydantic``), ``json_dict`` (with
    ``output_json``) or ``raw`` (the model's text, used when it is a JSON object). A plain mapping or pydantic model
    is taken as the output itself.
    """
    if isinstance(output, Mapping):
        return {str(key): value for key, value in output.items()}
    if isinstance(output, BaseModel) and not hasattr(output, "raw"):
        return cast(dict[str, Any], normalize_output(output))
    structured = getattr(output, "pydantic", None)
    if isinstance(structured, BaseModel):
        return cast(dict[str, Any], normalize_output(structured))
    json_dict = getattr(output, "json_dict", None)
    if isinstance(json_dict, Mapping):
        return {str(key): value for key, value in json_dict.items()}
    raw = getattr(output, "raw", None)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def create_identity_output_guardrail(
    integration: AgentDidCrewAIIntegration,
    required_fields: Iterable[str] | None = None,
) -> Callable[[Any], GuardrailResult]:
    """A CrewAI task guardrail: the agent's output must be a JSON object without sensitive fields, with
    *required_fields*, and with ``did`` (when present) equal to the agent's DID. It returns ``(True, output)`` when the
    output passes, as CrewAI requires, and ``(False, reason)`` otherwise."""
    required = set(required_fields or [])

    # CrewAI validates callable annotations at runtime and rejects some otherwise
    # valid guardrail return annotations. We keep the static return annotation for
    # type-checking, then remove it from the runtime-visible signature below.
    def guardrail(output: Any) -> GuardrailResult:
        agent_output = extract_agent_output(output)
        if agent_output is None:
            return False, "The agent output must be a JSON object"

        sensitive_paths = find_sensitive_paths(agent_output)
        if sensitive_paths:
            return False, f"Sensitive output fields are not allowed: {', '.join(sensitive_paths)}"

        missing = sorted(field for field in required if field not in agent_output)
        if missing:
            return False, f"Missing required output fields: {', '.join(missing)}"

        output_did = agent_output.get("did")
        expected_did = integration.identity_snapshot.did
        if output_did is not None and output_did != expected_did:
            return False, f"Unexpected DID in output. Expected {expected_did}, got {output_did}"

        return True, output

    guardrail.__annotations__.pop("return", None)

    return cast(Callable[[Any], GuardrailResult], guardrail)
