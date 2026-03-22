"""Instruction composition utilities for Agent-DID identity context."""

from __future__ import annotations

from .snapshot import AgentDidIdentitySnapshot


def build_agent_did_instructions(
    identity_snapshot: AgentDidIdentitySnapshot,
    additional_instructions: str | None = None,
) -> str:
    capabilities = ", ".join(identity_snapshot.capabilities) if identity_snapshot.capabilities else "none"
    lines = [
        "Agent-DID identity context:",
        f"- did: {identity_snapshot.did}",
        f"- controller: {identity_snapshot.controller}",
        f"- name: {identity_snapshot.name}",
        f"- version: {identity_snapshot.version}",
        f"- capabilities: {capabilities}",
        f"- member_of: {identity_snapshot.member_of or 'none'}",
        f"- authentication_key_id: {identity_snapshot.authentication_key_id or 'unknown'}",
        "Rules:",
        "- Treat this DID as the authoritative identity of this agent.",
        "- Never invent or substitute another DID for this agent.",
        "- Use the dedicated Agent-DID tools for DID resolution, verification and signing tasks.",
    ]

    if additional_instructions and additional_instructions.strip():
        lines.append(f"Additional identity policy: {additional_instructions.strip()}")

    return "\n".join(lines)


def compose_instructions(
    base_instructions: str | None,
    identity_snapshot: AgentDidIdentitySnapshot,
    additional_instructions: str | None = None,
) -> str:
    identity_section = build_agent_did_instructions(identity_snapshot, additional_instructions)
    if base_instructions and base_instructions.strip():
        return f"{base_instructions.strip()}\n\n{identity_section}"
    return identity_section
