"""Server Side TLS profile compliance (0.6.2 item 21): net-benchmark's own
comparison logic, evaluated against the actual published machine-readable
guidelines.

Publisher note — verified current, not assumed
----------------------------------------------------
The project this item's "Mozilla" name refers to has moved: Mozilla
archived `mozilla/ssl-config-generator` in 2026 (after this project's own
roadmap text was written), handing the project to an independent
organisation, TLSRef — confirmed directly by fetching the repository, not
assumed from training data. The machine-readable guidelines moved from
`ssl-config.mozilla.org` to `data.tlsref.org`, same original authors
(April King, Gene Wood, Julien Vehent, Glenn Strauss — Mozilla's own team),
same MPL-2.0 licence, same Modern/Intermediate/Old lineage. This module
fetches from the current, live location; `GUIDELINES_URL` names it
explicitly rather than leaving the source implicit.

The "Old" profile no longer exists in the current guidelines
------------------------------------------------------------------
Also verified directly, not assumed: as of guideline version 6.0 (the
current "latest" as of when this was written), the published JSON contains
only `modern` and `intermediate` — `old` has been dropped entirely. This
module evaluates whichever profiles the fetched guideline document actually
contains, never a hardcoded Modern/Intermediate/Old triple — asking for a
profile the current guidelines don't have produces an explicit "this
profile does not exist in guideline version 6.0", not silently-wrong or
stale data. The dataset is "versioned and permanent" by its own publisher's
design (old version files are never removed), so pinning an older guideline
version would bring "old" back for legacy-focused scanning; not wired as a
default here, since the roadmap's own ask is compliance against the
*current* recommendation.

What this evaluates, and what it can't
-------------------------------------------
Checked, from data this engine already collects elsewhere: TLS protocol
versions, TLS 1.3 cipher suites, TLS 1.2-and-below ciphers, negotiable
named groups (curve size), classic DHE parameter size, certificate type
(RSA/ECDSA), certificate curve, certificate signature algorithm,
certificate lifetime, and server cipher-suite preference order (0.6.1 item
21's own `CipherPreferenceResult`).

Not evaluated, named explicitly rather than assumed clean: OCSP stapling
(`ocsp_staple` in the guidelines) — blocked on the same confirmed `oscrypto`
bug `deep_introspection.py` documents; HSTS (`hsts_min_age`) — blocked on
the HTTP module, same as everywhere else in this project HSTS comes up.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

import httpx

from net_benchmark.ssl_check.grading import normalize_version

if TYPE_CHECKING:
    from net_benchmark.ssl_check.core import SSLResult

GUIDELINES_URL = "https://data.tlsref.org/guidelines/latest.json"
# The dataset changes infrequently (a handful of times a year); matching
# the same daily cadence chain.py/ct.py use for their own cached datasets.
DEFAULT_GUIDELINES_MAX_AGE = 3600.0 * 24
DEFAULT_GUIDELINES_TIMEOUT = 10.0

_NOT_EVALUATED = [
    "ocsp_staple — blocked on the same confirmed oscrypto bug deep_introspection.py documents",
    "hsts_min_age — needs the HTTP module, itself blocked (0.6.1 item 4)",
]

# cryptography's own EC curve naming (SEC, e.g. "secp256r1") differs from
# the guidelines' OpenSSL-style naming ("prime256v1") for the one curve
# where the two conventions disagree — confirmed by checking both
# directly, not assumed. secp384r1/secp521r1 have no such alias and need
# no mapping.
_CURVE_NAME_ALIASES = {"secp256r1": "prime256v1"}

# Native (not RSA-equivalent — grading.py's conversion is for a different
# table with different units) curve bit sizes, for comparison against the
# guidelines' own ecdh_param_size field.
_NATIVE_CURVE_BITS = {
    "SECP521R1": 521,
    "SECP384R1": 384,
    "X448": 448,
    "SECP256R1": 256,
    "PRIME256V1": 256,
    "X25519": 256,
}


def _native_curve_bits(name: str) -> Optional[int]:
    upper = name.upper()
    for key, bits in _NATIVE_CURVE_BITS.items():
        if key in upper:
            return bits
    return None


def default_guidelines_cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / "net-benchmark" / "tls-profiles" / "guidelines.json"


async def fetch_guidelines(
    client: httpx.AsyncClient,
    *,
    url: str = GUIDELINES_URL,
    cache_path: Optional[Path] = None,
    max_age: float = DEFAULT_GUIDELINES_MAX_AGE,
    timeout: float = DEFAULT_GUIDELINES_TIMEOUT,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Fetch the guidelines document, or use a cached copy younger than
    `max_age`. Returns (parsed_json_or_None, error_or_None). Same
    fetch-then-cache shape as `ct.py`'s `fetch_log_registry` — a cache
    write failure is never a fetch failure.
    """
    cache_path = (
        cache_path if cache_path is not None else default_guidelines_cache_path()
    )

    try:
        stat = cache_path.stat()
        if time.time() - stat.st_mtime <= max_age:
            return json.loads(cache_path.read_bytes()), None
    except (OSError, ValueError):
        pass

    try:
        response = await client.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        body = response.content
    except httpx.HTTPError as exc:
        return None, f"{url}: {type(exc).__name__}: {exc}"

    try:
        data: Dict[str, Any] = json.loads(body)
    except ValueError as exc:
        return None, f"{url}: response was not valid JSON: {exc}"

    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(body)
    except OSError:
        pass

    return data, None


@dataclass
class ProfileViolation:
    field: str
    expected: str
    observed: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "expected": self.expected,
            "observed": self.observed,
        }


@dataclass
class ProfileComplianceResult:
    profile_name: str
    # None: not enough data collected to judge this profile at all (e.g.
    # neither --enumerate-protocol nor --deep-introspection ran). False:
    # judged, and at least one violation found. True: judged, none found —
    # among the fields this module can check; see `not_evaluated`.
    compliant: Optional[bool] = None
    violations: List[ProfileViolation] = field(default_factory=list)
    not_evaluated: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_name": self.profile_name,
            "compliant": self.compliant,
            "violations": [v.to_dict() for v in self.violations],
            "not_evaluated": list(self.not_evaluated),
        }


@dataclass
class MozillaProfileAudit:
    attempted: bool = False
    guideline_version: Optional[str] = None
    guideline_url: Optional[str] = None
    available_profiles: List[str] = field(default_factory=list)
    results: Dict[str, ProfileComplianceResult] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attempted": self.attempted,
            "guideline_version": self.guideline_version,
            "guideline_url": self.guideline_url,
            "available_profiles": list(self.available_profiles),
            "results": {name: r.to_dict() for name, r in self.results.items()},
            "error": self.error,
        }


def evaluate_profile(
    profile_name: str, spec: Dict[str, Any], result: "SSLResult"
) -> ProfileComplianceResult:
    """Compare one target's already-collected data against one profile
    spec from the guidelines document.
    """
    violations: List[ProfileViolation] = []
    evaluated_anything = False

    # --- TLS versions ------------------------------------------------------
    observed_versions: Set[str] = set()
    if result.enumeration is not None:
        observed_versions |= {
            v.version.value for v in result.enumeration.versions if v.supported
        }
    if (
        result.deep_introspection is not None
        and result.deep_introspection.versions is not None
    ):
        observed_versions |= set(result.deep_introspection.versions.versions)
    required_versions: Set[str] = {
        n
        for v in spec.get("tls_versions", [])
        if (n := normalize_version(v)) is not None
    }
    if observed_versions:
        evaluated_anything = True
        normalised_observed = {
            v for raw in observed_versions if (v := normalize_version(raw))
        }
        extra = normalised_observed - required_versions
        missing = required_versions - normalised_observed
        if extra:
            violations.append(
                ProfileViolation(
                    "tls_versions",
                    ",".join(sorted(required_versions)),
                    "also offers " + ",".join(sorted(extra)),
                )
            )
        if missing:
            violations.append(
                ProfileViolation(
                    "tls_versions",
                    ",".join(sorted(required_versions)),
                    "missing " + ",".join(sorted(missing)),
                )
            )

    # --- TLS 1.2-and-below ciphers (Modern has none to check — TLS 1.3 only) --
    allowed_ciphers = set(spec.get("ciphers", {}).get("openssl", []))
    if allowed_ciphers and result.enumeration is not None:
        evaluated_anything = True
        observed_ciphers = {c.name for c in result.enumeration.supported_ciphers}
        disallowed = observed_ciphers - allowed_ciphers
        if disallowed:
            violations.append(
                ProfileViolation(
                    "ciphers",
                    ", ".join(sorted(allowed_ciphers)),
                    "also offers " + ", ".join(sorted(disallowed)),
                )
            )

    # --- TLS 1.3 cipher suites ---------------------------------------------
    allowed_suites = set(spec.get("ciphersuites", []))
    if (
        allowed_suites
        and result.deep_introspection is not None
        and result.deep_introspection.tls13_ciphers is not None
        and result.deep_introspection.tls13_ciphers.suites
    ):
        evaluated_anything = True
        observed_suites = set(result.deep_introspection.tls13_ciphers.suites)
        disallowed_suites = observed_suites - allowed_suites
        if disallowed_suites:
            violations.append(
                ProfileViolation(
                    "ciphersuites",
                    ", ".join(sorted(allowed_suites)),
                    "also offers " + ", ".join(sorted(disallowed_suites)),
                )
            )

    # --- Negotiable named groups / ECDH parameter size ----------------------
    required_ecdh_bits = spec.get("ecdh_param_size")
    if (
        required_ecdh_bits is not None
        and result.deep_introspection is not None
        and result.deep_introspection.named_groups is not None
        and result.deep_introspection.named_groups.groups
    ):
        evaluated_anything = True
        weakest = min(
            (
                b
                for g in result.deep_introspection.named_groups.groups
                if (b := _native_curve_bits(g)) is not None
            ),
            default=None,
        )
        if weakest is not None and weakest < required_ecdh_bits:
            violations.append(
                ProfileViolation(
                    "ecdh_param_size", f">={required_ecdh_bits} bits", f"{weakest} bits"
                )
            )

    # --- Classic DHE parameter size ------------------------------------------
    required_dh_bits = spec.get("dh_param_size")
    if (
        required_dh_bits is not None
        and result.deep_introspection is not None
        and result.deep_introspection.dh_params is not None
        and result.deep_introspection.dh_params.classic_dhe_key_size is not None
    ):
        evaluated_anything = True
        observed_dh_bits = result.deep_introspection.dh_params.classic_dhe_key_size
        if observed_dh_bits < required_dh_bits:
            violations.append(
                ProfileViolation(
                    "dh_param_size",
                    f">={required_dh_bits} bits",
                    f"{observed_dh_bits} bits",
                )
            )

    # --- Certificate: type, curve, signature, lifetime -----------------------
    certificate = result.certificate
    if certificate is not None and certificate.public_key is not None:
        evaluated_anything = True
        allowed_types = spec.get("certificate_types", [])
        if allowed_types and certificate.public_key.key_type.value not in allowed_types:
            violations.append(
                ProfileViolation(
                    "certificate_types",
                    ", ".join(allowed_types),
                    certificate.public_key.key_type.value,
                )
            )

        allowed_curves = spec.get("certificate_curves") or []
        if allowed_curves and certificate.public_key.curve_name is not None:
            observed_curve = certificate.public_key.curve_name.lower()
            aliased = _CURVE_NAME_ALIASES.get(observed_curve, observed_curve)
            if observed_curve not in allowed_curves and aliased not in allowed_curves:
                violations.append(
                    ProfileViolation(
                        "certificate_curves", ", ".join(allowed_curves), observed_curve
                    )
                )

        allowed_sigs = spec.get("certificate_signatures", [])
        if (
            allowed_sigs
            and certificate.signature_algorithm is not None
            and certificate.signature_algorithm not in allowed_sigs
        ):
            violations.append(
                ProfileViolation(
                    "certificate_signatures",
                    ", ".join(allowed_sigs),
                    certificate.signature_algorithm,
                )
            )

        max_lifespan = spec.get("maximum_certificate_lifespan")
        if max_lifespan is not None and certificate.lifetime is not None:
            if certificate.lifetime.lifetime_days > max_lifespan:
                violations.append(
                    ProfileViolation(
                        "maximum_certificate_lifespan",
                        f"<={max_lifespan} days",
                        f"{certificate.lifetime.lifetime_days} days",
                    )
                )

        if allowed_types and certificate.public_key.key_type.value == "rsa":
            required_rsa_bits = spec.get("rsa_key_size")
            if (
                required_rsa_bits is not None
                and certificate.public_key.key_size is not None
            ):
                if certificate.public_key.key_size < required_rsa_bits:
                    violations.append(
                        ProfileViolation(
                            "rsa_key_size",
                            f">={required_rsa_bits} bits",
                            f"{certificate.public_key.key_size} bits",
                        )
                    )

    # --- Server cipher-suite preference order (0.6.1 item 21's own data) ----
    required_preference = spec.get("server_preferred_order")
    if required_preference is True and result.cipher_preference is not None:
        if result.cipher_preference.server_enforces_order is False:
            evaluated_anything = True
            violations.append(
                ProfileViolation("server_preferred_order", "true", "false")
            )
        elif result.cipher_preference.server_enforces_order is True:
            evaluated_anything = True

    compliant = (not violations) if evaluated_anything else None
    return ProfileComplianceResult(
        profile_name=profile_name,
        compliant=compliant,
        violations=violations,
        not_evaluated=list(_NOT_EVALUATED),
    )


async def check_mozilla_profiles(
    result: "SSLResult",
    *,
    client: httpx.AsyncClient,
    profiles: Optional[List[str]] = None,
    guidelines: Optional[Dict[str, Any]] = None,
    cache_path: Optional[Path] = None,
    timeout: float = DEFAULT_GUIDELINES_TIMEOUT,
) -> MozillaProfileAudit:
    """Entry point. `profiles` defaults to every profile the fetched
    guidelines document actually contains (currently `["modern",
    "intermediate"]` — see the module docstring on why `"old"` isn't one
    of them). `guidelines` lets a caller share one fetched document across
    an entire scan, same reasoning as `ct.py`'s `registry` parameter.
    """
    audit = MozillaProfileAudit(attempted=True)

    if guidelines is None:
        guidelines, error = await fetch_guidelines(
            client, cache_path=cache_path, timeout=timeout
        )
        if error is not None:
            audit.error = error
            return audit
    if guidelines is None:
        audit.error = "guidelines document unavailable"
        return audit

    audit.guideline_version = str(guidelines.get("version"))
    audit.guideline_url = guidelines.get("href")
    configurations = guidelines.get("configurations", {})
    audit.available_profiles = sorted(configurations)

    requested = profiles if profiles is not None else audit.available_profiles
    for name in requested:
        if name not in configurations:
            audit.results[name] = ProfileComplianceResult(
                profile_name=name,
                compliant=None,
                not_evaluated=[
                    f"profile '{name}' does not exist in guideline version "
                    f"{audit.guideline_version} (available: {', '.join(audit.available_profiles)})"
                ],
            )
            continue
        audit.results[name] = evaluate_profile(name, configurations[name], result)

    return audit


__all__ = [
    "GUIDELINES_URL",
    "DEFAULT_GUIDELINES_MAX_AGE",
    "DEFAULT_GUIDELINES_TIMEOUT",
    "ProfileViolation",
    "ProfileComplianceResult",
    "MozillaProfileAudit",
    "default_guidelines_cache_path",
    "fetch_guidelines",
    "evaluate_profile",
    "check_mozilla_profiles",
]
