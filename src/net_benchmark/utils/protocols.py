from typing import Dict, List, Optional, Tuple, cast

import click

from net_benchmark.dns_benchmark.core import QueryProtocol, ResolverManager


def _resolve_protocol_and_doh_urls(
    doh: bool,
    dot: bool,
    doh_url: Optional[str],
    resolvers: List[Dict[str, str]],
) -> Tuple[QueryProtocol, Dict[str, str]]:
    """
    Validate protocol flags and build resolver_ip -> doh_url mapping.
    Fails fast with a clear message before any queries run.
    """

    if doh and dot:
        raise click.UsageError("--doh and --dot are mutually exclusive.")

    if not doh and not dot:
        return QueryProtocol.PLAIN, {}

    if dot:
        return QueryProtocol.DOT, {}

    # ── DoH path ──────────────────────────────────────────────────────────
    url_map: Dict[str, str] = {}

    if doh_url:
        # User supplied explicit list — must match resolver count 1:1
        urls = [u.strip() for u in doh_url.split(",") if u.strip()]
        if len(urls) != len(resolvers):
            raise click.UsageError(
                f"--doh-url has {len(urls)} URL(s) but --resolvers has "
                f"{len(resolvers)} resolver(s). Counts must match."
            )
        for resolver, url in zip(resolvers, urls):
            url_map[resolver["ip"]] = url
    else:
        # Fall back to db doh_url field — fail if any resolver is missing it
        missing = []
        for resolver in resolvers:
            db_entry = next(
                (
                    r
                    for r in ResolverManager.RESOLVERS_DATABASE
                    if r.get("ip") == resolver["ip"]
                    or str(r.get("name", "")).lower() == resolver["name"].lower()
                ),
                None,
            )
            url = cast(str, (db_entry or {}).get("doh_url", ""))
            if not url:
                missing.append(resolver["name"] or resolver["ip"])
            else:
                url_map[resolver["ip"]] = url

        if missing:
            raise click.UsageError(
                f"--doh requires a DoH URL for: {', '.join(missing)}. "
                "Use --doh-url to supply them explicitly."
            )

    return QueryProtocol.DOH, url_map
