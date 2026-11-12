"""Pure builders for the lifecycle operations (update, rotate).

They compute the next document from the current one; authorization, did:webvh log
entries, registry and history are handled by ``AgentDidClient``.
TypeScript parity: ``sdk/src/lifecycle/documents.ts``.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime, timedelta

from nacl.signing import SigningKey

from ..core.identity_composition import ADDITIONAL_VERIFICATION_RELATIONSHIPS
from ..core.time_utils import normalize_timestamp_to_iso
from ..core.types import AgentDIDDocument, SigningVerificationPurpose, UpdateAgentDocumentParams, VerificationMethod
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


def _without_retired_keys_in_relationships(document: AgentDIDDocument) -> AgentDIDDocument:
    """Remove the keys of *document* that carry a ``deactivated`` time from every verification relationship.

    They stay in ``verificationMethod`` as the record of the retired key. Idempotent; an optional relationship
    (everything but ``authentication``) that ends up empty is omitted. A key id that is not a verification
    method of the document is left alone.
    """
    retired = {vm.id for vm in document.verification_method if vm.deactivated}
    if not retired:
        return document

    def kept(key_ids: list[str] | None) -> list[str] | None:
        if key_ids is None:
            return None
        remaining = [key_id for key_id in key_ids if key_id not in retired]
        return remaining or None

    return document.model_copy(
        update={
            "authentication": [key_id for key_id in document.authentication if key_id not in retired],
            "assertion_method": kept(document.assertion_method),
            "capability_delegation": kept(document.capability_delegation),
            "capability_invocation": kept(document.capability_invocation),
        }
    )


def build_updated_document(
    existing: AgentDIDDocument, patch: UpdateAgentDocumentParams, updated: str
) -> AgentDIDDocument:
    # Any update also normalizes a document written by an earlier release that still listed retired keys
    return _without_retired_keys_in_relationships(_build_updated_document(existing, patch, updated))


def _build_updated_document(
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


def _carried_capability_relationships(existing: AgentDIDDocument, new_vm_id: str) -> dict[str, list[str] | None]:
    """``capabilityDelegation`` / ``capabilityInvocation`` lists for a rotated document.

    The new key joins each list that names a key this rotation deactivates, so an agent that could delegate
    or invoke still can. The keys of this document are removed from every list (a rotated-out key is no longer a
    verification relationship of any kind); another party's key stays, and a list left empty is omitted.
    """
    active_key_ids = {vm.id for vm in existing.verification_method if not vm.deactivated}
    own_key_ids = {vm.id for vm in existing.verification_method}
    current: dict[str, list[str] | None] = {
        "capabilityDelegation": existing.capability_delegation,
        "capabilityInvocation": existing.capability_invocation,
    }
    carried: dict[str, list[str] | None] = {}
    for relationship in ADDITIONAL_VERIFICATION_RELATIONSHIPS:
        key_ids = current[relationship]
        if not key_ids:
            carried[relationship] = None
            continue
        kept = [key_id for key_id in key_ids if key_id not in own_key_ids]
        if any(key_id in active_key_ids for key_id in key_ids):
            kept = [*kept, new_vm_id]
        carried[relationship] = list(dict.fromkeys(kept)) or None
    return carried


def build_added_key_document(
    did: str,
    existing: AgentDIDDocument,
    updated: str,
    relationships: Sequence[SigningVerificationPurpose],
    new_public_key: bytes | None = None,
) -> tuple[AgentDIDDocument, str, str]:
    """Add an Ed25519 key to the document without retiring any other key, listed under *relationships*.

    The new key is *new_public_key* when the caller holds the key elsewhere (the private key hex is then empty),
    otherwise a freshly generated local key. Returns ``(document, verification_method_id, agent_private_key_hex)``.
    """
    if not relationships:
        raise ValueError("At least one relationship is required for the new key")
    if new_public_key is not None and len(new_public_key) != 32:
        raise ValueError("The new verification method key must be a 32-byte Ed25519 public key")
    key_indexes = []
    for m in existing.verification_method:
        match = re.search(r"#key-(\d+)$", m.id)
        key_indexes.append(int(match.group(1)) if match else 0)
    vm_id = f"{did}#key-{(max(key_indexes) if key_indexes else 0) + 1}"

    if new_public_key is None:
        signing_key = SigningKey.generate()
        private_key_hex = signing_key.encode().hex()
        public_key = bytes(signing_key.verify_key)
    else:
        private_key_hex = ""
        public_key = new_public_key
    new_vm = VerificationMethod(
        id=vm_id,
        type="Ed25519VerificationKey2020",
        controller=existing.controller,
        publicKeyMultibase=encode_public_key_multibase(public_key),
    )
    fields = {
        "authentication": existing.authentication,
        "assertion_method": existing.assertion_method,
        "capability_delegation": existing.capability_delegation,
        "capability_invocation": existing.capability_invocation,
    }
    for relationship in dict.fromkeys(relationships):
        attribute = {
            "authentication": "authentication",
            "assertionMethod": "assertion_method",
            "capabilityDelegation": "capability_delegation",
            "capabilityInvocation": "capability_invocation",
        }[relationship]
        fields[attribute] = [*(fields[attribute] or []), vm_id]
    document = existing.model_copy(
        update={"updated": updated, "verification_method": [*existing.verification_method, new_vm], **fields}
    )
    return document, vm_id, private_key_hex


def build_rotated_document(
    did: str, existing: AgentDIDDocument, updated: str, new_public_key: bytes | None = None
) -> tuple[AgentDIDDocument, str, str]:
    """Deactivate every current key and add an Ed25519 key as the active one.

    The new key is *new_public_key* when the caller holds the key elsewhere (the private key hex is then empty),
    otherwise a freshly generated local key.

    Returns ``(document, verification_method_id, agent_private_key_hex)``.
    """
    if new_public_key is not None and len(new_public_key) != 32:
        raise ValueError("The new verification method key must be a 32-byte Ed25519 public key")
    key_indexes: list[int] = []
    for m in existing.verification_method:
        match = re.search(r"#key-(\d+)$", m.id)
        key_indexes.append(int(match.group(1)) if match else 0)

    next_idx = (max(key_indexes) if key_indexes else 0) + 1
    vm_id = f"{did}#key-{next_idx}"

    if new_public_key is None:
        signing_key = SigningKey.generate()
        private_key_hex = signing_key.encode().hex()
        public_key = bytes(signing_key.verify_key)
    else:
        private_key_hex = ""
        public_key = new_public_key
    new_vm = VerificationMethod(
        id=vm_id,
        type="Ed25519VerificationKey2020",
        controller=existing.controller,
        publicKeyMultibase=encode_public_key_multibase(public_key),
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
            # Every key of the previous document is retired: none of them stays in a verification relationship
            "assertionMethod": [vm_id],
            **_carried_capability_relationships(existing, vm_id),
            "keyAgreement": existing.key_agreement,
        }
    )
    return document, vm_id, private_key_hex
