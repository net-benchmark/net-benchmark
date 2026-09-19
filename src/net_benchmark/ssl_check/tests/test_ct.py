"""Tests for `net_benchmark.ssl_check.ct`.

`SAMPLE_LOG_LIST` below is a trimmed, real excerpt of
https://www.gstatic.com/ct/log_list/v3/all_logs_list.json (fetched directly
to verify the schema before writing `ct.py`, then trimmed to a handful of
entries covering usable/rejected/readonly/pending/no-state logs) -- not
synthetic data, so the parser is proven against the actual shape Google
publishes, not an assumption about it. No test fetches this live; the
mocked transport below serves the same bytes.
"""

from __future__ import annotations

import base64
import datetime
import json

import httpx
import pytest

from net_benchmark.ssl_check.certificate import SignedCertificateTimestampInfo
from net_benchmark.ssl_check.ct import (
    LogState,
    check_ct_logs,
    fetch_log_registry,
    parse_log_list,
    resolve_sct_trust,
)

UTC = datetime.timezone.utc

# Real entries, trimmed from a live fetch of all_logs_list.json (see module
# docstring). Covers: usable (Cloudflare Nimbus2026), rejected (Google
# Argon2026h1), readonly-with-final_tree_head (Sectigo Mammoth2026h2),
# pending (Sectigo monument2027h1, a tiled_log), and no `state` key at all
# (Google Submariner).
SAMPLE_LOG_LIST = {
    "is_all_logs": True,
    "version": "91.3",
    "log_list_timestamp": "2026-09-12T13:38:59Z",
    "operators": [
        {
            "name": "Google",
            "email": ["google-ct-logs@googlegroups.com"],
            "logs": [
                {
                    "description": "Google 'Argon2026h1' log",
                    "log_id": "DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE=",
                    "key": "MFkw...",
                    "url": "https://ct.googleapis.com/logs/us1/argon2026h1/",
                    "mmd": 86400,
                    "state": {"rejected": {"timestamp": "2026-07-09T13:40:00Z"}},
                },
                {
                    "description": "Google 'Submariner' log",
                    "log_id": "qJnYeAySkKr0YvMYgMz71SRR6XDQ+/WR73Ww2ZtkVoE=",
                    "key": "MFkw...",
                    "url": "https://ct.googleapis.com/submariner/",
                    "mmd": 86400,
                },
            ],
            "tiled_logs": [],
        },
        {
            "name": "Cloudflare",
            "email": ["ct-logs@cloudflare.com"],
            "logs": [
                {
                    "description": "Cloudflare 'Nimbus2026'",
                    "log_id": "yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=",
                    "key": "MFkw...",
                    "url": "https://ct.cloudflare.com/logs/nimbus2026/",
                    "mmd": 86400,
                    "state": {"usable": {"timestamp": "2024-11-08T18:00:00Z"}},
                },
            ],
            "tiled_logs": [],
        },
        {
            "name": "Sectigo",
            "email": ["ctops@sectigo.com"],
            "logs": [
                {
                    "description": "Sectigo 'Mammoth2026h2'",
                    "log_id": "lLHBirDQV8R74KwEDh8svI3DdXJ7yVHyClJhJoY7pzw=",
                    "key": "MFkw...",
                    "url": "https://mammoth2026h2.ct.sectigo.com/",
                    "mmd": 86400,
                    "state": {
                        "readonly": {
                            "timestamp": "2025-09-18T17:20:00Z",
                            "final_tree_head": {
                                "sha256_root_hash": "vJHecZC18lG3qp9lV2jZoi+7nkPHQx2SmM4VWglNsIk=",
                                "tree_size": 57634084,
                            },
                        }
                    },
                },
            ],
            "tiled_logs": [
                {
                    "log_id": "lU+RNjI2rVhXzDYVRyLcQOf5ugowsOdS+/DHSylmVrg=",
                    "key": "MFkw...",
                    "submission_url": "https://monument2027h1.sub.ct.sectigo.com/",
                    "monitoring_url": "https://monument2027h1.mon.ct.sectigo.com/",
                    "mmd": 60,
                    "state": {"pending": {"timestamp": "2026-09-12T17:30:00Z"}},
                },
            ],
        },
    ],
}


def _log_id_hex(b64: str) -> str:
    return base64.b64decode(b64).hex()


class TestParseLogList:
    def test_usable_log_parsed_trusted(self) -> None:
        registry = parse_log_list(
            SAMPLE_LOG_LIST, source_url="https://example/logs.json"
        )
        log = registry.get(_log_id_hex("yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc="))
        assert log is not None
        assert log.operator == "Cloudflare"
        assert log.description == "Cloudflare 'Nimbus2026'"
        assert log.state is LogState.USABLE
        assert log.state.trusted is True
        assert log.state_timestamp == datetime.datetime(
            2024, 11, 8, 18, 0, 0, tzinfo=UTC
        )

    def test_rejected_log_parsed_untrusted(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST)
        log = registry.get(_log_id_hex("DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE="))
        assert log is not None
        assert log.state is LogState.REJECTED
        assert log.state.trusted is False

    def test_readonly_with_final_tree_head_parsed_trusted(self) -> None:
        # The extra nested final_tree_head object must not break parsing.
        registry = parse_log_list(SAMPLE_LOG_LIST)
        log = registry.get(_log_id_hex("lLHBirDQV8R74KwEDh8svI3DdXJ7yVHyClJhJoY7pzw="))
        assert log is not None
        assert log.state is LogState.READONLY
        assert log.state.trusted is True

    def test_pending_tiled_log_parsed_untrusted(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST)
        log = registry.get(_log_id_hex("lU+RNjI2rVhXzDYVRyLcQOf5ugowsOdS+/DHSylmVrg="))
        assert log is not None
        assert log.operator == "Sectigo"
        assert log.state is LogState.PENDING
        assert log.state.trusted is False
        assert log.url == "https://monument2027h1.sub.ct.sectigo.com/"

    def test_log_with_no_state_key_is_unknown(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST)
        log = registry.get(_log_id_hex("qJnYeAySkKr0YvMYgMz71SRR6XDQ+/WR73Ww2ZtkVoE="))
        assert log is not None
        assert log.state is LogState.UNKNOWN
        assert log.state.trusted is False

    def test_unrecognised_log_id_not_found(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST)
        assert registry.get("00" * 32) is None

    def test_registry_records_version_and_source(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST, source_url="https://example/x.json")
        assert registry.list_version == "91.3"
        assert registry.source_url == "https://example/x.json"
        assert len(registry.logs) == 5


class TestResolveSctTrust:
    def _sct(self, log_id_b64: str) -> SignedCertificateTimestampInfo:
        return SignedCertificateTimestampInfo(
            log_id_hex=_log_id_hex(log_id_b64),
            timestamp=datetime.datetime(2026, 1, 1, tzinfo=UTC),
            version="v1",
            entry_type="PRE_CERTIFICATE",
            signature_algorithm="ECDSA",
        )

    def test_trusted_and_untrusted_scts(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST)
        scts = [
            self._sct("yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc="),  # usable
            self._sct("DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE="),  # rejected
        ]
        results = resolve_sct_trust(scts, registry)
        assert results[0].trusted is True
        assert results[1].trusted is False

    def test_sct_from_log_not_in_registry(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST)
        sct = self._sct(base64.b64encode(b"\x99" * 32).decode())
        results = resolve_sct_trust([sct], registry)
        assert results[0].log is None
        assert results[0].trusted is False

    def test_no_registry_gives_none_not_false(self) -> None:
        sct = self._sct("yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=")
        results = resolve_sct_trust([sct], None)
        assert results[0].trusted is None
        assert results[0].log is None


class TestFetchLogRegistry:
    @pytest.fixture(autouse=True)
    def _isolated_cache(self, tmp_path):
        self.cache_path = tmp_path / "log_list.json"

    async def test_fetch_and_parse(self) -> None:
        body = json.dumps(SAMPLE_LOG_LIST).encode()

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            registry, error = await fetch_log_registry(
                client, cache_path=self.cache_path
            )
        assert error is None
        assert registry is not None
        assert registry.from_cache is False
        assert len(registry.logs) == 5
        assert self.cache_path.exists()

    async def test_second_fetch_served_from_cache(self) -> None:
        body = json.dumps(SAMPLE_LOG_LIST).encode()
        call_count = {"n": 0}

        def handler(request: httpx.Request) -> httpx.Response:
            call_count["n"] += 1
            return httpx.Response(200, content=body)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            await fetch_log_registry(client, cache_path=self.cache_path)
            registry2, error2 = await fetch_log_registry(
                client, cache_path=self.cache_path
            )
        assert call_count["n"] == 1
        assert error2 is None
        assert registry2 is not None
        assert registry2.from_cache is True

    async def test_fetch_failure_returns_error_not_exception(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            registry, error = await fetch_log_registry(
                client, cache_path=self.cache_path
            )
        assert registry is None
        assert error is not None


class TestCheckCTLogs:
    async def test_no_scts_not_fetched(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("should not fetch when there are no SCTs")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            audit = await check_ct_logs([], client=client)
        assert audit.attempted is True
        assert audit.sct_trust == []
        assert audit.all_trusted is None

    async def test_end_to_end_with_provided_registry(self) -> None:
        registry = parse_log_list(SAMPLE_LOG_LIST)
        sct = SignedCertificateTimestampInfo(
            log_id_hex=_log_id_hex("yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc="),
            timestamp=datetime.datetime(2026, 1, 1, tzinfo=UTC),
            version="v1",
            entry_type="PRE_CERTIFICATE",
            signature_algorithm="ECDSA",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("should not fetch when a registry is provided")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            audit = await check_ct_logs([sct], client=client, registry=registry)
        assert audit.attempted is True
        assert audit.all_trusted is True
        assert len(audit.sct_trust) == 1
