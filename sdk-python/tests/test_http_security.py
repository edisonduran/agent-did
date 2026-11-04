"""Tests for http_security — SSRF protection."""

from __future__ import annotations

import pytest

from agent_did_sdk.core.http_security import HttpTargetValidationOptions, validate_http_target


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
