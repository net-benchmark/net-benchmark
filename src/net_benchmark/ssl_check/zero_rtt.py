"""TLS 1.3 0-RTT (early data) timing (0.6.2 item 11).

Why the system `openssl` CLI, not a Python library
--------------------------------------------------------
Checked and ruled out, in order, before reaching for a subprocess:

- stdlib `ssl` exposes no early-data API at all — confirmed directly: zero
  `early`/`rtt`-named attributes anywhere on `SSLContext`, `SSLObject`, or
  `SSLSocket`. A known, long-standing CPython gap, not an oversight in this
  check.
- CryptoLyzer doesn't implement it either — confirmed: no "early_data" or
  "0rtt" reference anywhere in its installed source.
- `pyOpenSSL`, which wraps OpenSSL's C API more directly than stdlib does,
  also doesn't expose `SSL_write_early_data` — confirmed against the
  current release: `OpenSSL.SSL.Connection` has no early-data method.

The system `openssl` CLI (`s_client -early_data <file>`) does support it,
is Apache-2.0 licensed, and is what all three of the above ultimately link
against. Invoked as a subprocess here — the one place in this codebase
that does so — because the alternative is hand-rolling TLS 1.3's early-
traffic-secret key schedule and record-layer encryption from scratch: a
materially larger and riskier undertaking than one roadmap item warrants,
and a much bigger step than wrapping an existing, tested implementation.

This is a real portability tradeoff, not a free choice, and it's named
plainly rather than papered over: the `openssl` binary's presence,
version, and exact CLI flag/output-format behaviour aren't pinnable the
way a pip dependency's are (confirmed directly while building this — an
early version of this module's own local test setup failed twice on CLI
flag incompatibilities, e.g. `-early_data` rejecting `-www` mode, and
`s_server`'s default of exiting after one connection needing `-naccept`
before three sequential probes would even work). `available=False` is
returned plainly when the binary is missing, not assumed present; if a
future `openssl` version changes its output format in a way this module
doesn't recognise, results come back inconclusive rather than guessed at.

What's measured
------------------
Three timed connections to the same target:
1. A fresh, non-resumed handshake.
2. A resumed handshake using the session/ticket from (1), without early
   data.
3. A resumed handshake using the same session/ticket, with early data
   sent in the first flight.

Timing includes subprocess-spawn overhead for all three equally, so the
*comparison* between them (the actual point of this item) is meaningful
even though none of the three absolute numbers alone is a pure protocol-
level measurement — documented here rather than presented as more precise
than it is.

`early_data_status` reports whatever the target actually did — "accepted"
is not assumed to be the "correct" or expected outcome. Many real servers
reject 0-RTT deliberately (replay-safety, short ticket lifetimes,
operator policy); a rejection is a legitimate, meaningful result to
report accurately, not a failure of this probe.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_TIMEOUT = 10.0


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


@dataclass
class ZeroRttTimingResult:
    attempted: bool = False
    available: bool = False
    full_handshake_ms: Optional[float] = None
    resumed_no_early_data_ms: Optional[float] = None
    resumed_with_early_data_ms: Optional[float] = None
    # "accepted" | "rejected" | "not_sent" | "unknown"
    early_data_status: Optional[str] = None
    # full_handshake_ms - resumed_no_early_data_ms — the latency PSK
    # resumption alone saves, before early data's own additional saving.
    resumption_savings_ms: Optional[float] = None
    # resumed_no_early_data_ms - resumed_with_early_data_ms — early data's
    # own marginal saving on top of plain resumption. Only meaningful when
    # early_data_status == "accepted"; still recorded otherwise (it will
    # typically be near zero or negative when rejected), with the status
    # field being what tells a reader whether to trust it as a real save.
    early_data_savings_ms: Optional[float] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "available": self.available,
            "full_handshake_ms": self.full_handshake_ms,
            "resumed_no_early_data_ms": self.resumed_no_early_data_ms,
            "resumed_with_early_data_ms": self.resumed_with_early_data_ms,
            "early_data_status": self.early_data_status,
            "resumption_savings_ms": self.resumption_savings_ms,
            "early_data_savings_ms": self.early_data_savings_ms,
            "error": self.error,
        }


async def _run_openssl_capture_session(
    args: List[str], *, stdin_data: bytes, timeout: float, session_path: Path
) -> None:
    """Run one `openssl s_client` invocation that must leave behind a
    `-sess_out` file, then terminate it explicitly.

    `_run_openssl` cannot be used for this: `s_client` only writes the
    TLS 1.3 NewSessionTicket (and therefore the `-sess_out` file) after
    the handshake completes, which is after stdin EOF. With `-ign_eof`
    set, stdin EOF does not cause exit, so `communicate()` would wait
    forever; without it, the connection closes before the ticket
    arrives. So: feed stdin, wait for the session file to appear, kill.
    """
    process = await asyncio.create_subprocess_exec(
        "openssl",
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        try:
            # stdin is guaranteed a real StreamWriter, never None, here --
            # this call always passes stdin=asyncio.subprocess.PIPE above.
            # asyncio's own stubs type Process.stdin as Optional because
            # an *unpiped* subprocess has no stdin at all; mypy can't see
            # that this call site never takes that path.
            assert process.stdin is not None
            process.stdin.write(stdin_data)
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if session_path.exists() and session_path.stat().st_size > 0:
                return
            await asyncio.sleep(0.01)
        raise asyncio.TimeoutError()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def _run_openssl(
    args: List[str], *, stdin_data: bytes, timeout: float
) -> Tuple[str, Optional[int]]:
    """Run one `openssl` invocation, returning (combined_output,
    returncode). Never raises on a nonzero exit — that's a normal outcome
    for `s_client` against a bare TCP close, not this function's business
    to interpret.
    """
    process = await asyncio.create_subprocess_exec(
        "openssl",
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(
            process.communicate(input=stdin_data), timeout=timeout
        )
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise
    return stdout.decode(errors="replace"), process.returncode


def _parse_early_data_status(output: str) -> str:
    lower = output.lower()
    if "early data was accepted" in lower:
        return "accepted"
    if "early data was rejected" in lower:
        return "rejected"
    if "early data was not sent" in lower:
        return "not_sent"
    return "unknown"


async def measure_zero_rtt_timing(
    host: str, port: int, *, timeout: float = DEFAULT_TIMEOUT
) -> ZeroRttTimingResult:
    """Measure the three-connection sequence described in the module
    docstring against `host:port`. `available=False` (not an error) when
    the `openssl` binary isn't present at all.
    """
    result = ZeroRttTimingResult(attempted=True)
    result.available = openssl_available()
    if not result.available:
        result.error = (
            "the system openssl CLI was not found. 0-RTT timing needs it "
            "directly — no Python library (stdlib ssl, CryptoLyzer, "
            "pyOpenSSL) exposes early-data support"
        )
        return result

    tmpdir = Path(tempfile.mkdtemp(prefix="net-benchmark-0rtt-"))
    session_path = tmpdir / "session.pem"
    request_path = tmpdir / "request.bin"
    # Content is arbitrary — this only needs to be non-empty bytes for
    # -early_data to have something to send; it is never interpreted.
    request_path.write_bytes(b"GET / HTTP/1.0\r\n\r\n")

    try:
        connect_arg = f"{host}:{port}"

        # --- Connection 1: fresh handshake, capture the session ---------
        start = time.perf_counter()
        await _run_openssl_capture_session(
            [
                "s_client",
                "-connect",
                connect_arg,
                "-tls1_3",
                "-sess_out",
                str(session_path),
                "-ign_eof",
            ],
            stdin_data=request_path.read_bytes(),
            timeout=timeout,
            session_path=session_path,
        )
        result.full_handshake_ms = (time.perf_counter() - start) * 1000

        # --- Connection 2: resumed, no early data ------------------------
        start = time.perf_counter()
        await _run_openssl(
            [
                "s_client",
                "-connect",
                connect_arg,
                "-tls1_3",
                "-sess_in",
                str(session_path),
                "-no_ign_eof",
            ],
            stdin_data=request_path.read_bytes(),
            timeout=timeout,
        )
        result.resumed_no_early_data_ms = (time.perf_counter() - start) * 1000

        # Computed here, not after connection 3 — a timeout or failure on
        # connection 3 specifically should not also discard data this
        # engine already has from connections 1 and 2. Caught live: a
        # target whose connection 3 hung for the full timeout still had a
        # perfectly good resumption_savings_ms available, and the earlier
        # version of this function silently dropped it because the
        # computation lived after connection 3's block, inside the same
        # try that connection 3's exception unwound past.
        if (
            result.full_handshake_ms is not None
            and result.resumed_no_early_data_ms is not None
        ):
            result.resumption_savings_ms = (
                result.full_handshake_ms - result.resumed_no_early_data_ms
            )

        # --- Connection 3: resumed, with early data -----------------------
        start = time.perf_counter()
        output3, _code3 = await _run_openssl(
            [
                "s_client",
                "-connect",
                connect_arg,
                "-tls1_3",
                "-sess_in",
                str(session_path),
                "-early_data",
                str(request_path),
                "-no_ign_eof",
            ],
            stdin_data=b"",
            timeout=timeout,
        )
        result.resumed_with_early_data_ms = (time.perf_counter() - start) * 1000
        result.early_data_status = _parse_early_data_status(output3)

        if (
            result.resumed_no_early_data_ms is not None
            and result.resumed_with_early_data_ms is not None
        ):
            result.early_data_savings_ms = (
                result.resumed_no_early_data_ms - result.resumed_with_early_data_ms
            )
    except asyncio.TimeoutError:
        result.error = f"openssl subprocess did not complete within {timeout}s"
    except OSError as exc:
        result.error = f"could not run openssl: {type(exc).__name__}: {exc}"
    finally:
        with contextlib.suppress(OSError):
            request_path.unlink(missing_ok=True)
            session_path.unlink(missing_ok=True)
            tmpdir.rmdir()

    return result


__all__ = [
    "DEFAULT_TIMEOUT",
    "ZeroRttTimingResult",
    "openssl_available",
    "measure_zero_rtt_timing",
]
