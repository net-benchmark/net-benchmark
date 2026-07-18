"""Statistical analysis of HTTP benchmark results."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, cast

import numpy as np
import pandas as pd

from net_benchmark.dns_benchmark.core import QueryStatus
from net_benchmark.http_bench.core import HTTPProtocol, HTTPResult


@dataclass
class TargetStats:
    """Statistics for a single HTTP target URL.

    Field layout mirrors ResolverStats:
      target              ← resolver_name  (identity)
      method              ← (no DNS equivalent — HTTP-specific)
      total_requests      ← total_queries
      successful_requests ← successful_queries
      success_rate        ← success_rate
      min/max/avg/...     ← same latency stat fields, same formulas
      http2_rate          ← dnssec_validation_rate  (protocol quality signal)

    This is also what net_benchmark.http_bench.load_test.LoadTestSummary
    embeds for its overall and per-interval stats — one stats engine shared
    by the regular `http benchmark` path and the `http load-test` path,
    rather than two separate percentile implementations.
    """

    target: str
    method: str
    total_requests: int
    successful_requests: int
    success_rate: float
    # latency — identical field names and formulas as ResolverStats
    min_latency: float
    max_latency: float
    avg_latency: float
    median_latency: float
    std_latency: float
    p95_latency: float
    p99_latency: float
    jitter: float = 0.0
    consistency_score: float = 0.0
    # HTTP-specific timing
    avg_ttfb_ms: float = 0.0
    p95_ttfb_ms: float = 0.0
    # protocol
    http2_rate: float = 0.0  # requests that negotiated HTTP/2
    redirect_rate: float = 0.0  # requests with at least one redirect
    # response
    avg_response_size_bytes: float = 0.0
    avg_dns_ms: float = 0.0
    avg_tcp_ms: float = 0.0
    avg_tls_ms: float = 0.0
    avg_compressed_size_bytes: float = 0.0
    avg_redirect_time_ms: float = 0.0
    http2_downgrade_rate: float = 0.0
    cache_control_present: int = 0
    etag_present: int = 0
    last_modified_present: int = 0
    age_present: int = 0
    # security signals — counts across all requests for this target
    hsts_present: int = 0
    csp_present: int = 0
    cdn_fingerprint: Optional[str] = None  # most common CDN for this target
    server_header: Optional[str] = None  # most common server header
    cert_expiry_days_min: Optional[int] = None  # worst cert seen across requests
    alt_svc: Optional[str] = None
    ip_version: Optional[str] = None  # most common across requests

    # --- 0.5.1 additions ---
    # % of completed requests that reused an existing connection instead of
    # opening a new one. Requires enable_connection_reuse=True on the
    # engine; stays 0.0 otherwise.
    connection_reuse_rate: float = 0.0
    # % of completed requests whose TLS session ID had been seen before on
    # this origin. Best-effort resumption signal, not a certainty — see
    # TimingNetworkStream.start_tls in core.py.
    tls_resumption_rate: float = 0.0
    # Total HTTP/2 server pushes observed across all requests for this
    # target. 0 if push detection was off or the h2 package is unavailable.
    http2_push_total: int = 0
    # Average multipart upload throughput (Mbps), across requests that
    # actually uploaded (multipart_file_size > 0). 0.0 if none did.
    avg_upload_throughput_mbps: float = 0.0


class HTTPAnalyzer:
    """Analyse HTTP benchmark results and compute statistics.

    Mirrors BenchmarkAnalyzer structure exactly — same __init__, same
    _create_dataframe pattern, same public method signatures.
    """

    def __init__(self, results: List[HTTPResult]) -> None:
        self.results = results
        self.df = self._create_dataframe()

    def _create_dataframe(self) -> pd.DataFrame:
        """Convert HTTPResult list to DataFrame.

        Column mapping mirrors dns analysis.py _create_dataframe:
          latency_ms   → total_ms
          completed    → status == SUCCESS  (no DNSSEC_FAILED equivalent)
          resolver_name → target
          protocol.value → protocol
        """
        data = []
        for r in self.results:
            data.append(
                {
                    "target": r.target,
                    "method": r.method,
                    "total_ms": r.total_ms,
                    "ttfb_ms": r.ttfb_ms,
                    "dns_resolve_ms": r.dns_resolve_ms,
                    "dns_resolver_ip": r.dns_resolver_ip,
                    "tcp_connect_ms": r.tcp_connect_ms,
                    "tls_handshake_ms": r.tls_handshake_ms,
                    "status": r.status.value,
                    "completed": r.status == QueryStatus.SUCCESS,
                    "http_status_code": r.http_status_code,
                    "protocol": r.protocol.value,
                    "alpn_negotiated": r.alpn_negotiated or "",
                    "http2": r.protocol == HTTPProtocol.HTTP2,
                    "redirect_count": r.redirect_count,
                    "response_size_bytes": r.response_size_bytes or 0,
                    "compressed": r.compressed,
                    "compressed_size_bytes": r.compressed_size_bytes,
                    "redirect_timings": r.redirect_timings,
                    "http2_downgraded": r.http2_downgraded,
                    "hsts": r.security_headers.get("strict-transport-security")
                    is not None,
                    "csp": r.security_headers.get("content-security-policy")
                    is not None,
                    "cdn_fingerprint": r.cdn_fingerprint or "",
                    "server_header": r.server_header or "",
                    "cert_expiry_days": r.cert_expiry_days,
                    "alt_svc": r.alt_svc or "",
                    "ip_version": r.ip_version or "",
                    "error_message": r.error_message or "",
                    "attempt_number": r.attempt_number,
                    "iteration": r.iteration,
                    "query_id": r.query_id,
                    "start_time": r.start_time,
                    "cache_control": r.cache_control or "",
                    "etag": r.etag or "",
                    "last_modified": r.last_modified or "",
                    "age": r.age or "",
                    "assertion_results": r.assertion_results,
                    # --- 0.5.1 additions — previously collected on
                    # HTTPResult but silently dropped here, so
                    # get_target_statistics() had no way to surface them.
                    "connection_reused": r.connection_reused,
                    "connection_id": r.connection_id or "",
                    "tls_resumed": r.tls_resumed,
                    "tls_session_id": r.tls_session_id or "",
                    "session_ticket": r.session_ticket,
                    "http2_push_count": r.http2_push_count,
                    "upload_throughput_mbps": r.upload_throughput_mbps,
                    "websocket_handshake_ms": r.websocket_handshake_ms,
                }
            )
        return pd.DataFrame(data)

    def get_target_statistics(self) -> List[TargetStats]:
        """Compute per-target statistics. Mirrors get_resolver_statistics."""
        stats_list = []

        for target in self.df["target"].unique():
            td = self.df[self.df["target"] == target]
            method = td["method"].iloc[0]

            total = len(td)
            successful = int(td["completed"].sum())
            success_rate = (successful / total * 100) if total > 0 else 0.0

            latencies = td[td["completed"]]["total_ms"]
            ttfb_vals = td[td["completed"] & td["ttfb_ms"].notna()]["ttfb_ms"]

            # Timing breakdown averages
            dns_vals = td[td["completed"] & td["dns_resolve_ms"].notna()][
                "dns_resolve_ms"
            ]
            tcp_vals = td[td["completed"] & td["tcp_connect_ms"].notna()][
                "tcp_connect_ms"
            ]
            tls_vals = td[td["completed"] & td["tls_handshake_ms"].notna()][
                "tls_handshake_ms"
            ]

            avg_dns = float(dns_vals.mean()) if len(dns_vals) > 0 else 0.0
            avg_tcp = float(tcp_vals.mean()) if len(tcp_vals) > 0 else 0.0
            avg_tls = float(tls_vals.mean()) if len(tls_vals) > 0 else 0.0

            if len(latencies) > 0:
                arr = latencies.values
                min_l = float(latencies.min())
                max_l = float(latencies.max())
                avg_l = float(latencies.mean())
                med_l = float(latencies.median())
                std_l = float(latencies.std())
                p95_l = float(latencies.quantile(0.95))
                p99_l = float(latencies.quantile(0.99))

                if len(arr) == 1:
                    jitter = 0.0
                    consistency = 100.0
                else:
                    jitter = float(np.std(np.diff(arr)))
                    cv = std_l / avg_l if avg_l > 0 else 0.0
                    consistency = max(0.0, 100.0 - cv * 100.0)
            else:
                min_l = max_l = avg_l = med_l = std_l = float("nan")
                p95_l = p99_l = 0.0
                jitter = 0.0
                consistency = 0.0

            avg_ttfb = float(ttfb_vals.mean()) if len(ttfb_vals) > 0 else 0.0
            p95_ttfb = float(ttfb_vals.quantile(0.95)) if len(ttfb_vals) > 0 else 0.0

            # protocol signals
            http2_rate = (
                float(td[td["completed"]]["http2"].mean() * 100)
                if successful > 0
                else 0.0
            )
            redirect_rate = float((td["redirect_count"] > 0).mean() * 100)

            avg_size = (
                float(td[td["completed"]]["response_size_bytes"].mean())
                if successful > 0
                else 0.0
            )

            # security signals
            hsts_count = int(td["hsts"].sum())
            csp_count = int(td["csp"].sum())

            # Cache header presence (count non‑empty values among completed requests)
            cache_control_count = td[
                td["completed"] & (td["cache_control"] != "")
            ].shape[0]
            etag_count = td[td["completed"] & (td["etag"] != "")].shape[0]
            last_modified_count = td[
                td["completed"] & (td["last_modified"] != "")
            ].shape[0]
            age_count = td[td["completed"] & (td["age"] != "")].shape[0]

            # Compressed size average
            comp_vals = td[td["completed"] & td["compressed_size_bytes"].notna()][
                "compressed_size_bytes"
            ]
            avg_comp = float(comp_vals.mean()) if len(comp_vals) > 0 else 0.0

            # Average redirect time (flatten all hop timings)
            redirect_times = []
            for _, row in td[td["completed"]].iterrows():
                for hop in row.get("redirect_timings", []):
                    redirect_times.append(hop["duration_ms"])
            avg_redirect = (
                sum(redirect_times) / len(redirect_times) if redirect_times else 0.0
            )

            # HTTP/2 downgrade rate
            downgrade_count = int(
                td[(td["completed"]) & (td["http2_downgraded"] == True)].shape[0]
            )
            http2_downgrade_rate = (
                (downgrade_count / successful * 100) if successful > 0 else 0.0
            )

            # most common CDN and server header (mode, ignoring empty strings)
            cdn_vals = td[td["cdn_fingerprint"] != ""]["cdn_fingerprint"]
            cdn = str(cdn_vals.mode().iloc[0]) if len(cdn_vals) > 0 else None

            srv_vals = td[td["server_header"] != ""]["server_header"]
            srv = str(srv_vals.mode().iloc[0]) if len(srv_vals) > 0 else None

            # worst (minimum) cert expiry seen for this target
            cert_days_series = td["cert_expiry_days"].dropna()
            cert_min = (
                int(cert_days_series.min()) if len(cert_days_series) > 0 else None
            )
            alt_svc_vals = td[td["alt_svc"] != ""]["alt_svc"]
            alt_svc = (
                str(alt_svc_vals.mode().iloc[0]) if len(alt_svc_vals) > 0 else None
            )

            ip_vals = td[td["ip_version"] != ""]["ip_version"]
            ip_version = str(ip_vals.mode().iloc[0]) if len(ip_vals) > 0 else None

            # --- 0.5.1 additions ---
            reused_count = int(td[td["completed"]]["connection_reused"].sum())
            connection_reuse_rate = (
                (reused_count / successful * 100) if successful > 0 else 0.0
            )

            resumed_count = int(td[td["completed"]]["tls_resumed"].sum())
            tls_resumption_rate = (
                (resumed_count / successful * 100) if successful > 0 else 0.0
            )

            http2_push_total = int(td["http2_push_count"].sum())

            upload_vals = td[td["completed"] & td["upload_throughput_mbps"].notna()][
                "upload_throughput_mbps"
            ]
            avg_upload_throughput_mbps = (
                float(upload_vals.mean()) if len(upload_vals) > 0 else 0.0
            )

            stats_list.append(
                TargetStats(
                    target=target,
                    method=method,
                    total_requests=total,
                    successful_requests=successful,
                    success_rate=success_rate,
                    min_latency=min_l,
                    max_latency=max_l,
                    avg_latency=avg_l,
                    median_latency=med_l,
                    std_latency=std_l,
                    p95_latency=p95_l,
                    p99_latency=p99_l,
                    jitter=jitter,
                    consistency_score=consistency,
                    avg_ttfb_ms=avg_ttfb,
                    p95_ttfb_ms=p95_ttfb,
                    http2_rate=http2_rate,
                    redirect_rate=redirect_rate,
                    avg_response_size_bytes=avg_size,
                    avg_dns_ms=avg_dns,
                    avg_tcp_ms=avg_tcp,
                    avg_tls_ms=avg_tls,
                    avg_compressed_size_bytes=avg_comp,
                    avg_redirect_time_ms=avg_redirect,
                    http2_downgrade_rate=http2_downgrade_rate,
                    cache_control_present=cache_control_count,
                    etag_present=etag_count,
                    last_modified_present=last_modified_count,
                    age_present=age_count,
                    hsts_present=hsts_count,
                    csp_present=csp_count,
                    cdn_fingerprint=cdn,
                    server_header=srv,
                    cert_expiry_days_min=cert_min,
                    alt_svc=alt_svc,
                    ip_version=ip_version,
                    connection_reuse_rate=connection_reuse_rate,
                    tls_resumption_rate=tls_resumption_rate,
                    http2_push_total=http2_push_total,
                    avg_upload_throughput_mbps=avg_upload_throughput_mbps,
                )
            )

        return stats_list

    def get_overall_statistics(self) -> Dict[str, Any]:
        """Overall benchmark statistics. Mirrors BenchmarkAnalyzer.get_overall_statistics."""
        total = len(self.df)
        successful = int(self.df["completed"].sum())
        success_rate = (successful / total * 100) if total > 0 else 0.0

        latencies = self.df[self.df["completed"]]["total_ms"]
        ttfb_vals = self.df[self.df["completed"] & self.df["ttfb_ms"].notna()][
            "ttfb_ms"
        ]

        avg_l = float(latencies.mean()) if len(latencies) > 0 else 0.0
        med_l = float(latencies.median()) if len(latencies) > 0 else 0.0
        avg_ttfb = float(ttfb_vals.mean()) if len(ttfb_vals) > 0 else 0.0

        target_stats = self.get_target_statistics()
        ranked = sorted(
            [s for s in target_stats if s.successful_requests > 0],
            key=lambda s: s.avg_latency,
        )

        http2_rate = (
            float(self.df[self.df["completed"]]["http2"].mean() * 100)
            if successful > 0
            else 0.0
        )
        hsts_targets = sum(1 for s in target_stats if s.hsts_present > 0)
        resolver_ip = self.results[0].dns_resolver_ip if self.results else None

        assertion_pass_count = (
            sum(
                1
                for r in self.results
                if r.status == QueryStatus.SUCCESS and all(r.assertion_results.values())
            )
            if self.results
            else 0
        )
        assertion_pass_rate = (assertion_pass_count / total * 100) if total > 0 else 0.0

        # --- 0.5.1 additions ---
        reused_count = int(self.df[self.df["completed"]]["connection_reused"].sum())
        connection_reuse_rate = (
            (reused_count / successful * 100) if successful > 0 else 0.0
        )
        resumed_count = int(self.df[self.df["completed"]]["tls_resumed"].sum())
        tls_resumption_rate = (
            (resumed_count / successful * 100) if successful > 0 else 0.0
        )

        return {
            "total_requests": total,
            "successful_requests": successful,
            "overall_success_rate": success_rate,
            "overall_avg_latency": avg_l,
            "overall_median_latency": med_l,
            "overall_avg_ttfb": avg_ttfb,
            "fastest_target": ranked[0].target if ranked else "N/A",
            "slowest_target": ranked[-1].target if ranked else "N/A",
            "target_count": len(target_stats),
            "http2_rate": http2_rate,
            "hsts_coverage": (
                (hsts_targets / len(target_stats) * 100) if target_stats else 0.0
            ),
            "dns_resolver_ip": resolver_ip,
            "assertion_pass_rate": assertion_pass_rate,
            "connection_reuse_rate": connection_reuse_rate,
            "tls_resumption_rate": tls_resumption_rate,
        }

    def get_ttfb_statistics(self) -> List[Dict[str, Any]]:
        """Per-target TTFB breakdown. Mirrors get_domain_statistics."""
        result = []
        for target in self.df["target"].unique():
            td = self.df[self.df["target"] == target]
            vals = td[td["completed"] & td["ttfb_ms"].notna()]["ttfb_ms"]
            result.append(
                {
                    "target": target,
                    "avg_ttfb_ms": float(vals.mean()) if len(vals) > 0 else 0.0,
                    "median_ttfb_ms": float(vals.median()) if len(vals) > 0 else 0.0,
                    "p95_ttfb_ms": float(vals.quantile(0.95)) if len(vals) > 0 else 0.0,
                    "p99_ttfb_ms": float(vals.quantile(0.99)) if len(vals) > 0 else 0.0,
                    "min_ttfb_ms": float(vals.min()) if len(vals) > 0 else 0.0,
                    "max_ttfb_ms": float(vals.max()) if len(vals) > 0 else 0.0,
                }
            )
        return result

    def get_protocol_distribution(self) -> List[Dict[str, Any]]:
        """HTTP/1.1 vs HTTP/2 breakdown. Mirrors get_protocol_statistics."""
        result = []
        for proto in self.df["protocol"].unique():
            pd_ = self.df[self.df["protocol"] == proto]
            total = len(pd_)
            successful = int(pd_["completed"].sum())
            latencies = pd_[pd_["completed"]]["total_ms"]
            result.append(
                {
                    "protocol": proto,
                    "total_requests": total,
                    "successful_requests": successful,
                    "success_rate": (successful / total * 100) if total > 0 else 0.0,
                    "avg_latency": (
                        float(latencies.mean()) if len(latencies) > 0 else 0.0
                    ),
                    "median_latency": (
                        float(latencies.median()) if len(latencies) > 0 else 0.0
                    ),
                    "p95_latency": (
                        float(latencies.quantile(0.95)) if len(latencies) > 0 else 0.0
                    ),
                }
            )
        return result

    def get_security_summary(self) -> Dict[str, Any]:
        """Aggregate security signal counts across all results.
        Mirrors get_dnssec_statistics — the protocol-quality signal for HTTP.
        """
        total = len(self.df)
        completed = self.df[self.df["completed"]]

        # per-header presence counts
        header_counts: Dict[str, int] = {}
        for r in self.results:
            for h, v in r.security_headers.items():
                if v is not None:
                    header_counts[h] = header_counts.get(h, 0) + 1

        # CDN distribution
        cdn_vals = self.df[self.df["cdn_fingerprint"] != ""]["cdn_fingerprint"]
        cdn_dist = cdn_vals.value_counts().to_dict() if len(cdn_vals) > 0 else {}

        # server header leak count (present = potential info disclosure)
        server_leak_count = int((self.df["server_header"] != "").sum())

        # cert expiry — worst across all results
        cert_series = self.df["cert_expiry_days"].dropna()
        cert_min = int(cert_series.min()) if len(cert_series) > 0 else None

        return {
            "security_header_counts": header_counts,
            "cdn_distribution": cdn_dist,
            "server_header_leak_count": server_leak_count,
            "cert_expiry_days_min": cert_min,
            "total_requests": total,
            "completed_requests": int(completed["completed"].sum()),
        }

    def get_status_code_distribution(self) -> List[Dict[str, Any]]:
        """HTTP status code breakdown. No DNS equivalent — HTTP-only."""
        codes = self.df["http_status_code"].dropna().astype(int)
        dist = codes.value_counts().rename_axis("status_code").reset_index(name="count")
        dist["pct"] = (dist["count"] / len(self.df) * 100).round(2)
        return cast(List[Dict[str, Any]], dist.to_dict(orient="records"))

    def get_error_statistics(self) -> Dict[str, int]:
        """Error message counts. Mirrors BenchmarkAnalyzer.get_error_statistics."""
        errors = self.df[~self.df["completed"]]["error_message"]
        return cast(Dict[str, int], errors.value_counts().to_dict())
