"""HTTP Message Signatures (RFC 9421) primitives.

Strict Structured Field (RFC 8941) handling for ``Signature-Input`` / ``Signature`` and the
signature base of RFC 9421 §2.5. Agent-DID's request profile is built on top of this in
``AgentIdentity``.

TypeScript parity: ``sdk/src/core/http-signatures.ts``.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TypeVar
from urllib.parse import urlsplit

_T = TypeVar("_T")


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
_INTEGER = re.compile(r"-?[0-9]{1,15}")
_BASE64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


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
# Parsing (RFC 8941 §4.2), restricted to what Signature-Input / Signature use
# ---------------------------------------------------------------------------


class _Parser:
    def __init__(self, text: str) -> None:
        self._text = text
        self._i = 0

    def parse_dictionary(self, parse_member: Callable[[], _T]) -> dict[str, _T]:
        result: dict[str, _T] = {}
        self._skip_spaces()
        while not self._done():
            key = self._parse_key()
            if self._peek() != "=":
                raise HttpSignatureError(f"Dictionary member {key} has no value")
            self._i += 1
            result[key] = parse_member()
            self._skip_ows()
            if self._done():
                break
            self._expect(",")
            self._skip_ows()
            if self._done():
                raise HttpSignatureError("Trailing comma in dictionary")
        return result

    def parse_inner_list(self) -> SignatureInput:
        self._expect("(")
        components: list[str] = []
        while True:
            self._skip_spaces()
            if self._peek() == ")":
                self._i += 1
                break
            components.append(self._parse_string())
            if self._peek() == ";":
                raise HttpSignatureError("Component identifier parameters are not supported")
            if self._peek() not in (" ", ")"):
                raise HttpSignatureError("Malformed inner list")
        return SignatureInput(components=components, params=self._parse_params())

    def parse_byte_sequence(self) -> bytes:
        self._expect(":")
        end = self._text.find(":", self._i)
        if end == -1:
            raise HttpSignatureError("Unterminated byte sequence")
        encoded = self._text[self._i:end]
        if not _BASE64.fullmatch(encoded) or len(encoded) % 4 != 0:
            raise HttpSignatureError("Invalid base64 in byte sequence")
        self._i = end + 1
        try:
            return base64.b64decode(encoded, validate=True)
        except binascii.Error:
            raise HttpSignatureError("Invalid base64 in byte sequence") from None

    def _parse_params(self) -> list[tuple[str, SignatureParamValue]]:
        params: list[tuple[str, SignatureParamValue]] = []
        while self._peek() == ";":
            self._i += 1
            self._skip_spaces()
            name = self._parse_key()
            value: SignatureParamValue = True
            if self._peek() == "=":
                self._i += 1
                value = self._parse_bare_item()
            if any(key == name for key, _ in params):
                raise HttpSignatureError(f"Duplicate signature parameter: {name}")
            params.append((name, value))
        return params

    def _parse_bare_item(self) -> SignatureParamValue:
        char = self._peek()
        if char == '"':
            return self._parse_string()
        if char == "?":
            value = self._text[self._i:self._i + 2]
            if value not in ("?0", "?1"):
                raise HttpSignatureError("Invalid boolean")
            self._i += 2
            return value == "?1"
        if char == "-" or char.isdigit():
            match = _INTEGER.match(self._text, self._i)
            following = self._text[match.end():match.end() + 1] if match else ""
            if match is None or following == "." or following.isdigit():
                raise HttpSignatureError("Invalid integer (decimals are not used by signature parameters)")
            self._i = match.end()
            return int(match.group(0))
        match = _TOKEN.match(self._text, self._i)
        if match is None:
            raise HttpSignatureError("Invalid bare item")
        self._i = match.end()
        return Token(match.group(0))

    def _parse_string(self) -> str:
        self._expect('"')
        out: list[str] = []
        while True:
            if self._done():
                raise HttpSignatureError("Unterminated string")
            char = self._text[self._i]
            self._i += 1
            if char == "\\":
                following = self._text[self._i:self._i + 1]
                if following not in ('"', "\\"):
                    raise HttpSignatureError("Invalid escape in string")
                out.append(following)
                self._i += 1
            elif char == '"':
                return "".join(out)
            elif not 0x20 <= ord(char) <= 0x7E:
                raise HttpSignatureError("Strings must be printable ASCII")
            else:
                out.append(char)

    def _parse_key(self) -> str:
        match = _KEY.match(self._text, self._i)
        if match is None:
            raise HttpSignatureError("Invalid dictionary or parameter key")
        self._i = match.end()
        return match.group(0)

    def _expect(self, char: str) -> None:
        if self._peek() != char:
            raise HttpSignatureError(f'Expected "{char}"')
        self._i += 1

    def _peek(self) -> str:
        return self._text[self._i:self._i + 1]

    def _skip_spaces(self) -> None:
        while self._peek() == " ":
            self._i += 1

    def _skip_ows(self) -> None:
        while self._peek() in (" ", "\t") and self._peek():
            self._i += 1

    def _done(self) -> bool:
        return self._i >= len(self._text)


def parse_signature_input_header(value: str) -> dict[str, SignatureInput]:
    """Parse a ``Signature-Input`` field value into its members (label → inner list)."""
    parser = _Parser(value.strip())
    return parser.parse_dictionary(parser.parse_inner_list)


def parse_signature_header(value: str) -> dict[str, bytes]:
    """Parse a ``Signature`` field value into its members (label → signature bytes)."""
    parser = _Parser(value.strip())
    return parser.parse_dictionary(parser.parse_byte_sequence)


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
