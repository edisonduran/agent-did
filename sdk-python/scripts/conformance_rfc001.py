from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from agent_did_sdk.core.identity import AgentIdentity, AgentIdentityConfig
from agent_did_sdk.core.time_utils import iso_to_unix_string, normalize_timestamp_to_iso
from agent_did_sdk.core.types import (
    AgentDIDDocument,
    CreateAgentParams,
    RotateVerificationMethodResult,
    SignHttpRequestParams,
    UpdateAgentDocumentParams,
    VerifyHttpRequestSignatureParams,
)
from agent_did_sdk.registry.in_memory import InMemoryAgentRegistry
from agent_did_sdk.resolver.in_memory import InMemoryDIDResolver
from agent_did_sdk.resolver.types import UniversalResolverConfig
from agent_did_sdk.resolver.universal import UniversalResolverClient


@dataclass
class CheckResult:
    control_id: str
    status: str


def print_section(title: str, results: list[CheckResult]) -> None:
    print(f"\n{title}")
    for result in results:
        print(f"- {result.control_id}: {result.status}")


def summarize(results: list[CheckResult]) -> dict[str, int]:
    summary = {"PASS": 0, "PARTIAL": 0, "FAIL": 0, "UNKNOWN": 0}
    for result in results:
        summary[result.status] = summary.get(result.status, 0) + 1
    return summary


def build_identity() -> tuple[AgentIdentity, InMemoryAgentRegistry]:
    AgentIdentity.set_resolver(InMemoryDIDResolver())
    registry = InMemoryAgentRegistry()
    AgentIdentity.set_registry(registry)
    AgentIdentity._history_store = {}

    identity = AgentIdentity(AgentIdentityConfig(signer_address="0x1234567890abcdef1234567890abcdef12345678"))
    return identity, registry


async def build_document(identity: AgentIdentity):
    return await identity.create(
        CreateAgentParams(
            name="ConformanceBot",
            core_model="gpt-4.1",
            system_prompt="You validate RFC-001 conformance.",
            capabilities=["sign", "resolve", "verify"],
        )
    )


def evaluate_document_shape(document, result) -> list[CheckResult]:
    must_01_ok = all(
        [
            document.id.startswith("did:agent:"),
            bool(document.controller),
            bool(document.created),
            bool(document.updated),
            bool(document.agent_metadata.core_model_hash),
            bool(document.agent_metadata.system_prompt_hash),
            len(document.verification_method) >= 1,
            len(document.authentication) >= 1,
        ]
    )
    return [
        CheckResult("MUST-01", "PASS" if must_01_ok else "FAIL"),
        CheckResult("MUST-02", "PASS" if document.id == result.document.id else "FAIL"),
    ]


async def evaluate_signature_controls(
    identity: AgentIdentity,
    document,
    agent_private_key: str,
) -> tuple[list[CheckResult], str]:
    payload = "agent-did-python-conformance"
    signature = await identity.sign_message(payload, agent_private_key)

    headers = await identity.sign_http_request(
        SignHttpRequestParams(
            method="POST",
            url="https://api.example.com/v1/messages?draft=false",
            body='{"message":"hello"}',
            agent_private_key=agent_private_key,
            agent_did=document.id,
        )
    )
    http_valid = await AgentIdentity.verify_http_request_signature(
        VerifyHttpRequestSignatureParams(
            method="POST",
            url="https://api.example.com/v1/messages?draft=false",
            body='{"message":"hello"}',
            headers=headers,
            max_created_skew_seconds=300,
        )
    )

    return [
        CheckResult("MUST-03", "PASS" if len(signature) == 128 else "FAIL"),
        CheckResult("MUST-04", "PASS" if http_valid else "FAIL"),
    ], signature


async def evaluate_resolution_and_registry(
    document,
    registry: InMemoryAgentRegistry,
):
    resolved = await AgentIdentity.resolve(document.id)
    record_after_create = await registry.get_record(document.id)
    must_08_ok = bool(
        record_after_create
        and record_after_create.did == document.id
        and record_after_create.controller == document.controller
        and record_after_create.document_ref
        and not await registry.is_revoked(document.id)
    )
    return [
        CheckResult("MUST-05", "PASS" if resolved.id == document.id else "FAIL"),
        CheckResult("MUST-08", "PASS" if must_08_ok else "FAIL"),
    ], record_after_create


async def evaluate_lifecycle_controls(
    document,
    registry: InMemoryAgentRegistry,
) -> tuple[list[CheckResult], RotateVerificationMethodResult, list[CheckResult], object | None]:
    updated = await AgentIdentity.update_did_document(
        document.id,
        UpdateAgentDocumentParams(version="2.0.0", description="RFC-001 conformance updated"),
    )
    rotated = await AgentIdentity.rotate_verification_method(document.id)
    record_after_rotation = await registry.get_record(document.id)

    must_10_ok = (
        updated.updated != document.updated
        and updated.agent_metadata.version == "2.0.0"
        and rotated.verification_method_id.endswith("#key-2")
        and rotated.document.authentication == [rotated.verification_method_id]
    )
    return [CheckResult("MUST-10", "PASS" if must_10_ok else "FAIL")], rotated, [], record_after_rotation


async def evaluate_revocation_controls(
    document,
    identity: AgentIdentity,
    registry: InMemoryAgentRegistry,
    rotated: RotateVerificationMethodResult,
) -> tuple[list[CheckResult], list[CheckResult]]:
    payload = "agent-did-python-conformance"
    signature = await identity.sign_message(payload, rotated.agent_private_key)
    valid_before_revocation = await AgentIdentity.verify_signature(
        document.id,
        payload,
        signature,
        rotated.verification_method_id,
    )
    await AgentIdentity.revoke_did(document.id)
    revoked_record = await registry.get_record(document.id)
    valid_after_revocation = await AgentIdentity.verify_signature(
        document.id,
        payload,
        signature,
        rotated.verification_method_id,
    )

    should_05_ok = [entry.action for entry in AgentIdentity.get_document_history(document.id)] == [
        "created",
        "updated",
        "rotated-key",
        "revoked",
    ]

    return [
        CheckResult("MUST-06", "PASS" if not valid_after_revocation else "FAIL"),
        CheckResult("MUST-07", "PASS" if bool(revoked_record and revoked_record.revoked_at) else "FAIL"),
        CheckResult("MUST-09", "PASS" if valid_before_revocation and not valid_after_revocation else "FAIL"),
    ], [CheckResult("SHOULD-05", "PASS" if should_05_ok else "FAIL")]


def evaluate_document_reference_controls(record_after_create, record_after_rotation) -> list[CheckResult]:
    must_11_ok = bool(
        record_after_create
        and record_after_rotation
        and record_after_create.document_ref
        and record_after_rotation.document_ref
        and record_after_create.document_ref != record_after_rotation.document_ref
    )
    return [CheckResult("MUST-11", "PASS" if must_11_ok else "FAIL")]


def build_interop_document(interop_vectors: dict[str, object]) -> AgentDIDDocument:
    did = interop_vectors["did"]
    controller = interop_vectors["controller"]
    verification_method = interop_vectors["verificationMethod"]
    return AgentDIDDocument(
        **{
            "@context": ["https://www.w3.org/ns/did/v1", "https://agent-did.org/v1"],
            "id": did,
            "controller": controller,
            "created": "2024-01-01T00:00:00Z",
            "updated": "2024-01-01T00:00:00Z",
            "agentMetadata": {
                "name": "InteropFixture",
                "version": "1.0.0",
                "coreModelHash": "hash://sha256/interop",
                "systemPromptHash": "hash://sha256/interop",
            },
            "verificationMethod": [verification_method],
            "authentication": [verification_method["id"]],
        }
    )


async def evaluate_universal_resolver_should(document) -> CheckResult:
    class FakeSource:
        def __init__(self) -> None:
            self._documents: dict[str, object] = {}

        async def get_by_reference(self, document_ref: str):
            await asyncio.sleep(0)
            return self._documents.get(document_ref)

        async def store_by_reference(self, document_ref: str, stored_document) -> None:
            await asyncio.sleep(0)
            self._documents[document_ref] = stored_document.model_copy(deep=True)

    registry = InMemoryAgentRegistry()
    source = FakeSource()
    fallback = InMemoryDIDResolver()
    events = []

    document_ref = AgentIdentity._compute_document_reference(document)
    await registry.register(document.id, document.controller, document_ref)
    await source.store_by_reference(document_ref, document)

    fallback_document = document.model_copy(update={"id": "did:agent:polygon:fallback-only"}, deep=True)
    fallback.register_document(fallback_document)

    resolver = UniversalResolverClient(
        UniversalResolverConfig(
            registry=registry,
            document_source=source,
            fallback_resolver=fallback,
            cache_ttl_ms=60_000,
            on_resolution_event=events.append,
        )
    )

    first_resolution = await resolver.resolve(document.id)
    second_resolution = await resolver.resolve(document.id)
    fallback_resolution = await resolver.resolve(fallback_document.id)

    stats = resolver.get_cache_stats()
    observed_stages = {event.stage for event in events}
    should_01_ok = all(
        [
            first_resolution.id == document.id,
            second_resolution.id == document.id,
            fallback_resolution.id == fallback_document.id,
            stats.hits >= 1,
            stats.misses >= 1,
            {"cache-miss", "cache-hit", "source-fetch", "resolved", "fallback"}.issubset(observed_stages),
        ]
    )
    return CheckResult("SHOULD-01", "PASS" if should_01_ok else "FAIL")


async def evaluate_interop_should() -> CheckResult:
    fixture_path = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "interop-vectors.json"
    interop_vectors = json.loads(fixture_path.read_text(encoding="utf-8"))
    interop_document = build_interop_document(interop_vectors)
    AgentIdentity._resolver.register_document(interop_document)

    message_vector = interop_vectors["messageVector"]
    http_vector = interop_vectors["httpVector"]
    verification_method = interop_vectors["verificationMethod"]

    message_valid = await AgentIdentity.verify_signature(
        interop_document.id,
        message_vector["payload"],
        message_vector["signatureHex"],
        verification_method["id"],
    )
    http_valid = await AgentIdentity.verify_http_request_signature(
        VerifyHttpRequestSignatureParams(
            method=http_vector["method"],
            url=http_vector["url"],
            body=http_vector["body"],
            headers=http_vector["headers"],
            max_created_skew_seconds=http_vector.get("maxCreatedSkewSeconds", 999_999_999),
        )
    )
    return CheckResult("SHOULD-03", "PASS" if message_valid and http_valid else "FAIL")


def evaluate_contract_policy_should() -> CheckResult:
    contract_path = Path(__file__).resolve().parents[2] / "contracts" / "src" / "AgentRegistry.sol"
    if not contract_path.exists():
        return CheckResult("SHOULD-04", "UNKNOWN")

    contract_source = contract_path.read_text(encoding="utf-8")
    required_controls = [
        "mapping(string => mapping(address => bool)) private revocationDelegates;",
        (
            "function setRevocationDelegate(string calldata did, address delegate, "
            "bool authorized) external whenNotPaused {"
        ),
        (
            "function transferAgentOwnership(string calldata did, address newOwner) "
            "external whenNotPaused {"
        ),
        (
            "function isRevocationDelegate(string calldata did, address delegate) "
            "external view returns (bool) {"
        ),
        "require(_isAuthorizedRevoker(did, msg.sender), \"not authorized\");",
        "require(record.owner == msg.sender, \"only owner\");",
        "return record.owner == actor || revocationDelegates[did][actor];",
    ]
    return CheckResult(
        "SHOULD-04",
        "PASS" if all(control in contract_source for control in required_controls) else "FAIL",
    )


async def evaluate_should_controls(document) -> list[CheckResult]:
    should_02_ok = (
        normalize_timestamp_to_iso(iso_to_unix_string("2025-01-01T00:00:00+00:00"))
        == "2025-01-01T00:00:00.000Z"
    )
    return [
        await evaluate_universal_resolver_should(document),
        CheckResult("SHOULD-02", "PASS" if should_02_ok else "FAIL"),
        await evaluate_interop_should(),
        evaluate_contract_policy_should(),
    ]


async def run_conformance() -> int:
    identity, registry = build_identity()

    must_results: list[CheckResult] = []
    should_results: list[CheckResult] = []

    result = await build_document(identity)
    document = result.document

    must_results.extend(evaluate_document_shape(document, result))

    signature_results, _signature = await evaluate_signature_controls(
        identity, document, result.agent_private_key
    )
    must_results.extend(signature_results)

    resolution_results, record_after_create = await evaluate_resolution_and_registry(document, registry)
    must_results.extend(resolution_results)

    lifecycle_results, rotated, history_results, record_after_rotation = await evaluate_lifecycle_controls(
        document,
        registry,
    )
    must_results.extend(lifecycle_results)
    must_results.extend(evaluate_document_reference_controls(record_after_create, record_after_rotation))

    revocation_results, revocation_history_results = await evaluate_revocation_controls(
        document,
        identity,
        registry,
        rotated,
    )
    must_results.extend(revocation_results)

    should_results.extend(await evaluate_should_controls(document))
    should_results.extend(history_results)
    should_results.extend(revocation_history_results)

    print_section("MUST Controls", must_results)
    print_section("SHOULD Controls", should_results)

    must_summary = summarize(must_results)
    should_summary = summarize(should_results)

    print("\nSummary")
    print(f"- MUST: {must_summary['PASS']} PASS / {must_summary['PARTIAL']} PARTIAL / "
          f"{must_summary['FAIL']} FAIL / {must_summary['UNKNOWN']} UNKNOWN")
    print(f"- SHOULD: {should_summary['PASS']} PASS / {should_summary['PARTIAL']} PARTIAL / "
          f"{should_summary['FAIL']} FAIL / {should_summary['UNKNOWN']} UNKNOWN")

    if must_summary["FAIL"] > 0 or should_summary["FAIL"] > 0:
        print("\nFAIL: RFC-001 Python conformance failed.")
        return 1

    print("\nPASS: RFC-001 Python conformance passed.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run_conformance()))
