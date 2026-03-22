"""Lightweight guardrail helpers for CrewAI outputs."""

from collections.abc import Callable, Iterable
from typing import Any, Tuple  # noqa: UP035

from .integration import AgentDidCrewAIIntegration
from .sanitization import find_sensitive_paths, normalize_output

GuardrailResult = Tuple[bool, Any]  # noqa: UP006


def create_identity_output_guardrail(
    integration: AgentDidCrewAIIntegration,
    required_fields: Iterable[str] | None = None,
) -> Callable[[Any], GuardrailResult]:
    required = set(required_fields or [])

    def guardrail(output: Any) -> Tuple[bool, Any]:  # noqa: UP006
        normalized_output = normalize_output(output)
        if not isinstance(normalized_output, dict):
            return False, "CrewAI guardrail expects a dictionary output"

        sensitive_paths = find_sensitive_paths(normalized_output)
        if sensitive_paths:
            return False, f"Sensitive output fields are not allowed: {', '.join(sensitive_paths)}"

        missing = sorted(field for field in required if field not in normalized_output)
        if missing:
            return False, f"Missing required output fields: {', '.join(missing)}"

        output_did = normalized_output.get("did")
        expected_did = integration.identity_snapshot.did
        if output_did is not None and output_did != expected_did:
            return False, f"Unexpected DID in output. Expected {expected_did}, got {output_did}"

        return True, None

    return guardrail
