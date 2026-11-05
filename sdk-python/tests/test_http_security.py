"""Tests for http_security — SSRF protection."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from agent_did_sdk.core.http_security import (
    HttpTargetValidationOptions,
    assert_resolved_target_allowed,
    is_non_global_address,
    validate_http_target,
)
from agent_did_sdk.core.safe_client import create_safe_client


class TestValidateHttpTarget:
    # ── Allowed URLs ─────────────────────────────────────────────────
    def test_allows_public_https(self) -> None:
        validate_http_target("https://api.example.com/v1")

    def test_allows_public_http(self) -> None:
        validate_http_target("http://api.example.com/v1")

    # ── Blocked protocols ────────────────────────────────────────────
    def test_rejects_ftp(self) -> None:
        with pytest.raises(ValueError, match="Unsupported protocol"):
            validate_http_target("ftp://files.example.com/doc")

    def test_rejects_file(self) -> None:
        with pytest.raises(ValueError, match="Unsupported protocol"):
            validate_http_target("file:///etc/passwd")

    # ── Embedded credentials ─────────────────────────────────────────
    def test_rejects_embedded_credentials(self) -> None:
        with pytest.raises(ValueError, match="embedded credentials"):
            validate_http_target("https://user:pass@example.com/")

    # ── Loopback ─────────────────────────────────────────────────────
    def test_blocks_127_0_0_1(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("https://127.0.0.1/api")

    def test_blocks_127_0_0_2(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("https://127.0.0.2/api")

    def test_blocks_localhost(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://localhost:3000/")

    def test_blocks_ipv6_loopback(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://[::1]:8080/api")

    def test_blocks_ipv6_mapped_loopback(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://[::ffff:127.0.0.1]/api")

    # ── Zero address ─────────────────────────────────────────────────
    def test_blocks_0_0_0_0(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://0.0.0.0/")

    # ── Private ranges ───────────────────────────────────────────────
    def test_blocks_10_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://10.0.1.5/api")

    def test_blocks_172_16_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://172.16.0.1/api")

    def test_blocks_172_31_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://172.31.255.255/api")

    def test_blocks_192_168_x(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://192.168.1.100/")

    # ── Metadata endpoint (link-local) ──────────────────────────────
    def test_blocks_metadata_endpoint(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://169.254.169.254/latest/meta-data/")

    def test_blocks_ipv6_mapped_metadata_endpoint(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            validate_http_target("http://[::ffff:169.254.169.254]/metadata/instance")

    # ── allowPrivateTargets flag ─────────────────────────────────────
    def test_allows_private_when_flag_set(self) -> None:
        opts = HttpTargetValidationOptions(allow_private_targets=True)
        validate_http_target("http://127.0.0.1/api", opts)
        validate_http_target("http://10.0.0.1/api", opts)
        validate_http_target("http://192.168.1.1/api", opts)
        validate_http_target("http://169.254.169.254/latest/", opts)

    def test_still_blocks_credentials_with_flag(self) -> None:
        opts = HttpTargetValidationOptions(allow_private_targets=True)
        with pytest.raises(ValueError, match="embedded credentials"):
            validate_http_target("https://user:pass@127.0.0.1/", opts)

    def test_still_blocks_bad_protocol_with_flag(self) -> None:
        opts = HttpTargetValidationOptions(allow_private_targets=True)
        with pytest.raises(ValueError, match="Unsupported protocol"):
            validate_http_target("ftp://127.0.0.1/", opts)


BLOCKED_URLS = [
    "http://[fc00::1]/", "http://[fd12:3456::1]/", "http://[fe80::1]/", "http://[::]/",
    "http://[ff02::1]/", "http://[::ffff:7f00:1]/", "http://[::ffff:a9fe:a9fe]/",
    "http://[64:ff9b::a9fe:a9fe]/", "http://[2002:a9fe:a9fe::1]/", "http://[2001:db8::1]/",
    "http://0.1.2.3/", "http://100.64.0.1/", "http://100.127.255.255/", "http://192.0.0.1/",
    "http://198.18.0.1/", "http://224.0.0.1/", "http://240.0.0.1/", "http://255.255.255.255/",
    "http://localhost./", "http://app.localhost/", "http://2130706433/", "http://0x7f.1/",
]

ALLOWED_URLS = [
    "http://[2606:4700:4700::1111]/", "http://8.8.8.8/", "http://100.63.255.255/",
    "http://100.128.0.1/", "http://172.32.0.1/", "https://localhost.example.com/",
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_blocks_non_global_targets(url: str) -> None:
    with pytest.raises(ValueError, match="private/reserved"):
        validate_http_target(url)


@pytest.mark.parametrize("url", ALLOWED_URLS)
def test_allows_public_targets(url: str) -> None:
    validate_http_target(url)


class TestResolvedTargets:
    @staticmethod
    def _lookup(*addresses: str):  # type: ignore[no-untyped-def]
        async def lookup(hostname: str) -> list[str]:
            return list(addresses)

        return lookup

    @pytest.mark.parametrize(
        "address",
        ["10.0.0.5", "127.0.0.1", "100.64.0.1", "169.254.169.254", "fd00::1", "fe80::1", "::1", "::ffff:10.0.0.1"],
    )
    async def test_rejects_name_resolving_to_non_global_address(self, address: str) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            await assert_resolved_target_allowed("https://app.example.com/", None, self._lookup(address))

    async def test_rejects_when_any_address_is_private(self) -> None:
        with pytest.raises(ValueError, match="private/reserved"):
            await assert_resolved_target_allowed(
                "https://app.example.com/", None, self._lookup("93.184.216.34", "10.0.0.5")
            )

    async def test_allows_only_public_addresses(self) -> None:
        await assert_resolved_target_allowed(
            "https://app.example.com/", None, self._lookup("93.184.216.34", "2606:4700:4700::1111")
        )

    async def test_fails_closed_on_resolution_error_or_no_addresses(self) -> None:
        async def failing(hostname: str) -> list[str]:
            raise OSError("not found")

        with pytest.raises(ValueError, match="could not resolve"):
            await assert_resolved_target_allowed("https://nope.example.com/", None, failing)
        with pytest.raises(ValueError, match="private/reserved"):
            await assert_resolved_target_allowed("https://nope.example.com/", None, self._lookup())

    async def test_skips_lookup_for_literals_and_when_private_allowed(self) -> None:
        async def boom(hostname: str) -> list[str]:
            raise AssertionError("lookup must not run")

        await assert_resolved_target_allowed("https://93.184.216.34/", None, boom)
        await assert_resolved_target_allowed("https://[2606:4700:4700::1111]/", None, boom)
        await assert_resolved_target_allowed(
            "https://internal.example.com/", HttpTargetValidationOptions(allow_private_targets=True), boom
        )

    async def test_safe_client_blocks_request_before_connecting(self) -> None:
        client = create_safe_client(None, self._lookup("169.254.169.254"))
        try:
            with pytest.raises(ValueError, match="private/reserved"):
                await client.get("https://metadata.example.com/latest")
        finally:
            await client.aclose()


class TestAddressPinning:
    async def test_connects_to_the_validated_address_and_resolves_once(self) -> None:
        resolutions = 0

        async def lookup(hostname: str) -> list[str]:
            nonlocal resolutions
            resolutions += 1
            return ["93.184.216.34"]

        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, text="ok")

        client = create_safe_client(None, lookup, httpx.MockTransport(handler))
        try:
            response = await client.get("https://app.example.com:8443/doc?x=1")
        finally:
            await client.aclose()

        assert response.text == "ok"
        assert resolutions == 1
        assert seen[0].url.host == "93.184.216.34"
        assert seen[0].url.port == 8443
        assert seen[0].headers["host"] == "app.example.com:8443"
        assert seen[0].extensions["sni_hostname"] == "app.example.com"

    async def test_pins_ipv6_addresses(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200)

        lookup = TestResolvedTargets._lookup("2606:4700:4700::1111")
        client = create_safe_client(None, lookup, httpx.MockTransport(handler))
        try:
            await client.get("https://app.example.com/")
        finally:
            await client.aclose()

        assert seen[0].url.host == "2606:4700:4700::1111"
        assert seen[0].headers["host"] == "app.example.com"

    async def test_fails_over_to_the_next_validated_address_on_connect_error(self) -> None:
        attempts: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            attempts.append(request.url.host)
            if request.url.host == "93.184.216.34":
                raise httpx.ConnectError("refused", request=request)
            return httpx.Response(200, text="second")

        client = create_safe_client(
            None, TestResolvedTargets._lookup("93.184.216.34", "93.184.216.35"), httpx.MockTransport(handler)
        )
        try:
            response = await client.get("https://app.example.com/")
        finally:
            await client.aclose()

        assert response.text == "second"
        assert attempts == ["93.184.216.34", "93.184.216.35"]

    async def test_does_not_pin_ip_literals_or_allowed_private_targets(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200)

        async def boom(hostname: str) -> list[str]:
            raise AssertionError("lookup must not run")

        literal = create_safe_client(None, boom, httpx.MockTransport(handler))
        allow_private = HttpTargetValidationOptions(allow_private_targets=True)
        private = create_safe_client(allow_private, boom, httpx.MockTransport(handler))
        try:
            await literal.get("https://93.184.216.34/")
            await private.get("http://internal.example.com/")
        finally:
            await literal.aclose()
            await private.aclose()

        assert [r.url.host for r in seen] == ["93.184.216.34", "internal.example.com"]
        assert all("sni_hostname" not in r.extensions for r in seen)


_VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "http-target-vectors.json").read_text(encoding="utf-8")
)


class TestSharedVectors:
    """Cross-SDK vectors (fixtures/http-target-vectors.json): the TypeScript SDK must agree on every entry."""

    @pytest.mark.parametrize("vector", _VECTORS["addresses"], ids=lambda v: v["address"])
    def test_address_classification(self, vector: dict[str, object]) -> None:
        assert is_non_global_address(str(vector["address"])) is vector["blocked"]

    @pytest.mark.parametrize("vector", _VECTORS["urls"], ids=lambda v: v["url"])
    def test_url_validation(self, vector: dict[str, object]) -> None:
        if vector["allowed"]:
            validate_http_target(str(vector["url"]))
        else:
            with pytest.raises(ValueError):
                validate_http_target(str(vector["url"]))
