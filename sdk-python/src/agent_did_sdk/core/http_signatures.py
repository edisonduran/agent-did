"""HTTP Message Signatures (RFC 9421) primitives.

Structured Field (RFC 8941) handling for ``Signature-Input`` / ``Signature`` (parsing is
delegated to the ``http-sf`` library) and the signature base of RFC 9421 §2.5. Agent-DID's request profile
is built on top of this in ``AgentIdentity``.

TypeScript parity: ``sdk/src/core/http-signatures.ts``.
"""

from __future__ import annotations

import base64
import ipaddress
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


# The request URL must already be in the form every URL parser derives the same components from (RFC-001 §6.5
# item 4): an http(s) URL with a lowercase scheme and host, no user info and no fragment, a path and query of
# unreserved, sub-delimiter, ':' and '@' characters and percent-encoded octets (no "'" in the query), no dot
# segments, and an IP address host only in canonical form. Anything else is refused, never normalized.
_REQUEST_URL_FORM = re.compile(
    r"^(https?)://([a-z0-9._-]+|\[[0-9a-f:]+\])(?::([1-9][0-9]{0,4}))?"
    r"((?:/[A-Za-z0-9\-._~!$&'()*+,;=:@%]*)*)(\?[A-Za-z0-9\-._~!$&()*+,;=:@%/?]*)?$"
)
_DOT_SEGMENTS = frozenset({".", "..", "%2e", "%2e%2e", ".%2e", "%2e."})
_CANONICAL_IPV4 = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$"
)
_NUMERIC_LABEL = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _canonical_ipv6(literal: str) -> str | None:
    """RFC 5952 text of an IPv6 address (lowercase, no leading zeros, the first longest run of two or more zero
    groups compressed), as the WHATWG URL serializer writes it; ``None`` when *literal* is not an address."""
    try:
        groups = [group.lstrip("0") or "0" for group in ipaddress.IPv6Address(literal).exploded.split(":")]
    except ValueError:
        return None
    best_start, best_len, start = -1, 0, -1
    for index, group in enumerate([*groups, "x"]):
        if group == "0":
            start = index if start < 0 else start
            continue
        if start >= 0 and index - start > best_len:
            best_start, best_len = start, index - start
        start = -1
    if best_len < 2:
        return ":".join(groups)
    return ":".join(groups[:best_start]) + "::" + ":".join(groups[best_start + best_len:])


def request_url_form_problem(url: str) -> str | None:
    """Why *url* is not a request URL in normalized form (RFC-001 §6.5 item 4), or ``None`` when it is."""
    if "#" in url:
        return "it has a fragment"
    match = _REQUEST_URL_FORM.fullmatch(url)
    if match is None:
        return (
            "it is not an http(s) URL with a lowercase scheme and ASCII host, no user info, and only unreserved, "
            "sub-delimiter, ':', '@' and percent-encoded characters in the path and query"
        )
    _, host, port, path, query = match.groups()
    if _BAD_PERCENT.search(url):
        return "it has a '%' that is not followed by two hex digits"
    if any(segment.lower() in _DOT_SEGMENTS for segment in path.split("/")):
        return "it has a '.' or '..' path segment"
    if query == "?":
        return "it has an empty query"
    if port is not None and int(port) > 65535:
        return "its port is out of range"
    if host.startswith("["):
        return None if _canonical_ipv6(host[1:-1]) == host[1:-1] else "its IPv6 host is not in canonical form"
    labels = host.split(".")
    if any(not label for label in labels):
        return "its host has an empty label"
    if _NUMERIC_LABEL.fullmatch(labels[-1]) and not _CANONICAL_IPV4.fullmatch(host):
        return "its IPv4 host is not in canonical dotted-decimal form"
    return None


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
    if any(component.startswith("@") and component != "@method" for component in signature_input.components):
        problem = request_url_form_problem(request.url)
        if problem is not None:
            raise HttpSignatureError(f"The request URL is not in normalized form: {problem}")
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
