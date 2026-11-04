"""Pure builders for the lifecycle operations (update, rotate).

They compute the next document from the current one; authorization, did:webvh log
entries, registry and history are handled by ``AgentDidClient``.
TypeScript parity: ``sdk/src/lifecycle/documents.ts``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

from nacl.signing import SigningKey

from ..core.time_utils import normalize_timestamp_to_iso
from ..core.types import AgentDIDDocument, UpdateAgentDocumentParams, VerificationMethod
from ..crypto.hash import create_metadata_commitment
from ..crypto.multibase import encode_public_key_multibase


def next_document_timestamp(candidate: str, previous_timestamp: str | None = None) -> str:
    """Timestamp strictly after *previous_timestamp*, using *candidate* (now) unless it is not later."""
    if previous_timestamp:
        try:
            previous_normalized = normalize_timestamp_to_iso(previous_timestamp)
            if previous_normalized is None:
                return candidate
            previous_dt = datetime.fromisoformat(previous_normalized.replace("Z", "+00:00"))
        except ValueError:
            return candidate

        if candidate <= previous_normalized:
            next_timestamp = normalize_timestamp_to_iso((previous_dt + timedelta(milliseconds=1)).isoformat())
            return next_timestamp or candidate

    return candidate


def assert_update_patch(did: str, patch: UpdateAgentDocumentParams) -> None:
    if not did or not did.strip():
        raise ValueError("DID is required")

    if patch.core_model and not patch.core_model_salt:
        raise ValueError(
            "core_model_salt is required when updating core_model (use generate_commitment_salt() and keep it private)"
        )
    if patch.system_prompt and not patch.system_prompt_salt:
        raise ValueError(
            "system_prompt_salt is required when updating system_prompt "
            "(use generate_commitment_salt() and keep it private)"
        )


def build_updated_document(
    existing: AgentDIDDocument, patch: UpdateAgentDocumentParams, updated: str
) -> AgentDIDDocument:
    return AgentDIDDocument(
        **{
            "@context": existing.context,
            "id": existing.id,
            "controller": existing.controller,
            "created": existing.created,
            "updated": updated,
            "agentMetadata": {
                "name": existing.agent_metadata.name,
                "description": (
                    patch.description if patch.description is not None else existing.agent_metadata.description
                ),
                "version": (patch.version if patch.version is not None else existing.agent_metadata.version),
                "coreModelHash": (
                    create_metadata_commitment(patch.core_model, patch.core_model_salt or "")
                    if patch.core_model
                    else existing.agent_metadata.core_model_hash
                ),
                "systemPromptHash": (
                    create_metadata_commitment(patch.system_prompt, patch.system_prompt_salt or "")
                    if patch.system_prompt
                    else existing.agent_metadata.system_prompt_hash
                ),
                "capabilities": (
                    patch.capabilities if patch.capabilities is not None else existing.agent_metadata.capabilities
                ),
                "memberOf": (patch.member_of if patch.member_of is not None else existing.agent_metadata.member_of),
            },
            "complianceCertifications": (
                [c.model_dump(by_alias=True) for c in patch.compliance_certifications]
                if patch.compliance_certifications is not None
                else (
                    [c.model_dump(by_alias=True) for c in existing.compliance_certifications]
                    if existing.compliance_certifications
                    else None
                )
            ),
            "verificationMethod": [
                vm.model_dump(by_alias=True, exclude_none=True) for vm in existing.verification_method
            ],
            "authentication": existing.authentication,
            "assertionMethod": existing.assertion_method,
            "capabilityDelegation": existing.capability_delegation,
            "capabilityInvocation": existing.capability_invocation,
            "keyAgreement": existing.key_agreement,
        }
    )


def build_rotated_document(did: str, existing: AgentDIDDocument, updated: str) -> tuple[AgentDIDDocument, str, str]:
    """Deactivate every current key and add a fresh Ed25519 key as the active one.

    Returns ``(document, verification_method_id, agent_private_key_hex)``.
    """
    key_indexes: list[int] = []
    for m in existing.verification_method:
        match = re.search(r"#key-(\d+)$", m.id)
        key_indexes.append(int(match.group(1)) if match else 0)

    next_idx = (max(key_indexes) if key_indexes else 0) + 1
    vm_id = f"{did}#key-{next_idx}"

    signing_key = SigningKey.generate()
    private_key_hex = signing_key.encode().hex()
    new_vm = VerificationMethod(
        id=vm_id,
        type="Ed25519VerificationKey2020",
        controller=existing.controller,
        publicKeyMultibase=encode_public_key_multibase(bytes(signing_key.verify_key)),
    )

    all_vms = []
    for vm in existing.verification_method:
        d = vm.model_dump(by_alias=True, exclude_none=True)
        if "deactivated" not in d:
            d["deactivated"] = updated
        all_vms.append(d)
    all_vms.append(new_vm.model_dump(by_alias=True, exclude_none=True))

    document = AgentDIDDocument(
        **{
            "@context": existing.context,
            "id": existing.id,
            "controller": existing.controller,
            "created": existing.created,
            "updated": updated,
            "agentMetadata": existing.agent_metadata.model_dump(by_alias=True, exclude_none=True),
            "verificationMethod": all_vms,
            "authentication": [vm_id],
            "assertionMethod": list(dict.fromkeys([*(existing.assertion_method or []), vm_id])),
            "capabilityDelegation": existing.capability_delegation,
            "capabilityInvocation": existing.capability_invocation,
            "keyAgreement": existing.key_agreement,
        }
    )
    return document, vm_id, private_key_hex
