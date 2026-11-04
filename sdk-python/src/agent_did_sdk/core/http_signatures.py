"""HTTP Message Signatures (RFC 9421) primitives.

Structured Field (RFC 8941) handling for ``Signature-Input`` / ``Signature`` (parsing is
delegated to the ``http-sf`` library) and the signature base of RFC 9421 §2.5. Agent-DID's request profile
is built on top of this in ``AgentIdentity``.

TypeScript parity: ``sdk/src/core/http-signatures.ts``.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit

import http_sf


@dataclass(frozen=True)
class Token:
    """An RFC 8941 token bare item."""

    value: str


SignatureParamValue = str | int | bool | Token


@dataclass
class SignatureInput:
    """A signature's covered components (names only) and its parameters, in order."""

    components: list[str]
    params: list[tuple[str, SignatureParamValue]] = field(default_factory=list)

    def get(self, name: str) -> SignatureParamValue | None:
        for key, value in self.params:
            if key == name:
                return value
        return None


@dataclass
class HttpRequestLike:
    method: str
    url: str
    headers: Mapping[str, str | Sequence[str]]
    """Header fields; names are matched case-insensitively."""


class HttpSignatureError(ValueError):
    """Malformed structured field or signature base."""


_KEY = re.compile(r"[a-z*][a-z0-9_\-.*]*")
_TOKEN = re.compile(r"[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*")


# ---------------------------------------------------------------------------
# Serialization (RFC 8941 §4.1)
# ---------------------------------------------------------------------------


def _serialize_string(value: str) -> str:
    if not all(0x20 <= ord(char) <= 0x7E for char in value):
        raise HttpSignatureError("Structured Field strings must be printable ASCII")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _serialize_bare_item(value: SignatureParamValue) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        if abs(value) > 999_999_999_999_999:
            raise HttpSignatureError("Structured Field integers must have at most 15 digits")
        return str(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if not _TOKEN.fullmatch(value.value):
        raise HttpSignatureError(f"Invalid Structured Field token: {value.value}")
    return value.value


def _serialize_params(params: Sequence[tuple[str, SignatureParamValue]]) -> str:
    out = []
    for name, value in params:
        if not _KEY.fullmatch(name):
            raise HttpSignatureError(f"Invalid Structured Field key: {name}")
        out.append(f";{name}" if value is True else f";{name}={_serialize_bare_item(value)}")
    return "".join(out)


def serialize_signature_input(signature_input: SignatureInput) -> str:
    """Serialize a signature's inner list (the ``@signature-params`` value and ``Signature-Input`` member)."""
    components = " ".join(_serialize_string(component) for component in signature_input.components)
    return f"({components}){_serialize_params(signature_input.params)}"


def serialize_signature(label: str, signature: bytes) -> str:
    if not _KEY.fullmatch(label):
        raise HttpSignatureError(f"Invalid signature label: {label}")
    return f"{label}=:{base64.b64encode(signature).decode('ascii')}:"


# ---------------------------------------------------------------------------
# Parsing (RFC 8941 §4.2) by the ``http-sf`` library, restricted to what
# Signature-Input / Signature use
# ---------------------------------------------------------------------------


def _parse_dictionary(value: str) -> dict[str, Any]:
    try:
        return http_sf.parse(value.strip().encode("ascii"), tltype="dictionary")  # type: ignore[return-value]
    except (http_sf.StructuredFieldError, UnicodeEncodeError, ValueError) as error:
        raise HttpSignatureError(f"Malformed Structured Field: {error}") from None


def _count_parameter_separators(value: str) -> int:
    """Count ``;`` separators outside strings and byte sequences.

    RFC 8941 lets a repeated parameter silently overwrite the earlier one, and the
    library does that; a signature parameter list must not contain duplicates
    (RFC 9421 §2.3), so a count mismatch against the parsed parameters means one was dropped.
    """
    count = 0
    in_string = False
    in_bytes = False
    skip = False
    for char in value:
        if skip:
            skip = False
        elif in_string:
            if char == "\\":
                skip = True
            elif char == '"':
                in_string = False
        elif in_bytes:
            in_bytes = char != ":"
        elif char == '"':
            in_string = True
        elif char == ":":
            in_bytes = True
        elif char == ";":
            count += 1
    return count


def _to_param_value(name: str, value: Any) -> SignatureParamValue:
    if isinstance(value, http_sf.Token):
        return Token(str(value))
    if isinstance(value, bool | str | int):
        return value
    if isinstance(value, Decimal):
        raise HttpSignatureError(f"Invalid integer (decimals are not used by signature parameters): {name}")
    raise HttpSignatureError(f"Unsupported value type for signature parameter: {name}")


def parse_signature_input_header(value: str) -> dict[str, SignatureInput]:
    """Parse a ``Signature-Input`` field value into its members (label → inner list)."""
    result: dict[str, SignatureInput] = {}
    separators = 0
    for label, member in _parse_dictionary(value).items():
        if not isinstance(member[0], list):
            raise HttpSignatureError(f"Signature-Input member {label} is not an inner list")
        items, params = member
        components: list[str] = []
        for component, component_params in items:
            if isinstance(component, http_sf.Token) or not isinstance(component, str):
                raise HttpSignatureError("Covered component identifiers must be strings")
            if component_params:
                raise HttpSignatureError("Component identifier parameters are not supported")
            components.append(component)
        separators += len(params)
        result[label] = SignatureInput(
            components=components,
            params=[(name, _to_param_value(name, item)) for name, item in params.items()],
        )
    if _count_parameter_separators(value) != separators:
        raise HttpSignatureError("Duplicate signature parameter")
    return result


def parse_signature_header(value: str) -> dict[str, bytes]:
    """Parse a ``Signature`` field value into its members (label → signature bytes)."""
    result: dict[str, bytes] = {}
    for label, (bare, params) in _parse_dictionary(value).items():
        if not isinstance(bare, bytes) or params:
            raise HttpSignatureError(f"Signature member {label} must be a byte sequence without parameters")
        result[label] = bare
    return result


# ---------------------------------------------------------------------------
# Signature base (RFC 9421 §2.5)
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"https": 443, "http": 80}


def _authority(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    if parts.port is not None and parts.port != _DEFAULT_PORTS.get(parts.scheme.lower()):
        return f"{host}:{parts.port}"
    return host


def _header_value(request: HttpRequestLike, name: str) -> str:
    values: list[str] = []
    for key, value in request.headers.items():
        if key.lower() != name or value is None:
            continue
        values.extend([value] if isinstance(value, str) else list(value))
    if not values:
        raise HttpSignatureError(f"Covered header field is missing: {name}")
    # RFC 9421 §2.1: strip leading/trailing whitespace, join multiple field lines with ", ".
    combined = ", ".join(re.sub(r"\r?\n[ \t]+", " ", value).strip() for value in values)
    if "\r" in combined or "\n" in combined:
        raise HttpSignatureError(f"Header field {name} contains line breaks")
    return combined


def _derived_component_value(request: HttpRequestLike, name: str) -> str:
    parts = urlsplit(request.url)
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    if name == "@method":
        return request.method
    if name == "@target-uri":
        return f"{parts.scheme.lower()}://{_authority(request.url)}{path}{query}"
    if name == "@authority":
        return _authority(request.url)
    if name == "@scheme":
        return parts.scheme.lower()
    if name == "@request-target":
        return f"{path}{query}"
    if name == "@path":
        return path
    if name == "@query":
        return query or "?"
    raise HttpSignatureError(f"Unsupported derived component: {name}")


def build_signature_base(request: HttpRequestLike, signature_input: SignatureInput) -> str:
    """Build the RFC 9421 signature base for *signature_input* over *request*."""
    seen: set[str] = set()
    lines: list[str] = []
    for component in signature_input.components:
        if component in seen:
            raise HttpSignatureError(f"Duplicate covered component: {component}")
        seen.add(component)
        if component != component.lower():
            raise HttpSignatureError(f"Component names must be lowercase: {component}")
        value = (
            _derived_component_value(request, component)
            if component.startswith("@")
            else _header_value(request, component)
        )
        lines.append(f"{_serialize_string(component)}: {value}")
    lines.append(f'"@signature-params": {serialize_signature_input(signature_input)}')
    return "\n".join(lines)
