"""Attack-surface discovery.

An organisation's quantum exposure is the union of everything it exposes,
not just its front page, and the hosts nobody remembers owning are usually
the ones running the oldest cryptography. Two independent sources are used
because they fail in different ways: Certificate Transparency sees hosts
that DNS guessing never would, while guessing still works when the CT API
is unreachable.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional, Set

from . import dns as dnsmod
from . import http as httpmod

# Names worth trying when Certificate Transparency is unavailable. Ordered
# roughly by how often they turn up something with weaker configuration
# than the main site.
COMMON_SUBDOMAINS = (
    "www", "mail", "webmail", "remote", "vpn", "portal", "api", "admin",
    "dev", "staging", "test", "uat", "app", "apps", "secure", "login",
    "sso", "auth", "id", "intranet", "internal", "legacy", "old", "backup",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence", "docs", "status",
    "shop", "store", "payments", "billing", "invoice", "files", "ftp", "sftp",
    "db", "database", "mysql", "cpanel", "whm", "plesk", "owa", "exchange",
    "autodiscover", "smtp", "imap", "pop", "ns1", "ns2", "cdn", "static",
    "assets", "media", "img", "beta", "demo", "sandbox", "partner", "vendor",
)


@dataclass
class Discovery:
    domain: str
    hosts: List[str] = field(default_factory=list)
    sources: dict = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.hosts)


def from_certificate_transparency(
    domain: str, *, timeout: float = 20.0, limit: int = 500
) -> tuple:
    """Query crt.sh for every name any CA has certified for this domain.

    Returns ``(hostnames, note)``. CT is the authoritative public record of
    issuance, so this finds forgotten and internal-sounding hosts that were
    never meant to be listed anywhere.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = httpmod.fetch(url, timeout=timeout, verify=False)
    if not response.reachable:
        return [], f"certificate transparency lookup failed: {response.error}"
    if response.status != 200:
        return [], f"certificate transparency returned HTTP {response.status}"

    try:
        entries = json.loads(response.body)
    except (ValueError, TypeError) as exc:
        return [], f"could not parse certificate transparency response: {exc}"

    names: Set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        for field_name in ("name_value", "common_name"):
            raw = entry.get(field_name) or ""
            for candidate in str(raw).split("\n"):
                candidate = candidate.strip().lower().lstrip("*.")
                if candidate.endswith(domain) and _is_hostname(candidate):
                    names.add(candidate)
        if len(names) >= limit:
            break
    return sorted(names), None


def _is_hostname(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?", value))


def by_guessing(
    domain: str, *, workers: int = 24, timeout: float = 3.0, extra: tuple = ()
) -> List[str]:
    """Resolve common subdomain names against the domain."""
    candidates = [f"{name}.{domain}" for name in COMMON_SUBDOMAINS + tuple(extra)]
    found: List[str] = []

    def check(host: str) -> None:
        if dnsmod.resolves(host, timeout=timeout):
            found.append(host)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(check, candidates))
    return sorted(found)


def discover(
    domain: str,
    *,
    use_ct: bool = True,
    use_guessing: bool = True,
    limit: int = 40,
    timeout: float = 20.0,
) -> Discovery:
    """Build the host list to scan, apex first.

    ``limit`` caps how many hosts are returned so that a domain with
    thousands of certified names cannot turn one scan into an unbounded
    one. The apex and ``www`` are always kept.
    """
    result = Discovery(domain=domain)
    collected: Set[str] = {domain}

    if use_ct:
        names, note = from_certificate_transparency(domain, timeout=timeout)
        result.sources["certificate_transparency"] = len(names)
        collected.update(names)
        if note:
            result.notes.append(note)

    if use_guessing and (not use_ct or len(collected) <= 1):
        guessed = by_guessing(domain)
        result.sources["dns_guessing"] = len(guessed)
        collected.update(guessed)
        if not use_ct:
            result.notes.append("certificate transparency lookup was disabled")
        else:
            result.notes.append(
                "fell back to DNS name guessing, which sees far less than "
                "Certificate Transparency"
            )

    # Prefer the apex and www, then shorter names, which tend to be the
    # production hosts rather than one-off certificate entries.
    def sort_key(host: str):
        return (host != domain, host != f"www.{domain}", len(host), host)

    ordered = sorted(collected, key=sort_key)
    if len(ordered) > limit:
        result.notes.append(
            f"{len(ordered)} hosts discovered; scanning the first {limit}. "
            "Raise --max-hosts for full coverage."
        )
        ordered = ordered[:limit]

    result.hosts = ordered
    return result


def filter_live(hosts: List[str], *, workers: int = 24, timeout: float = 3.0) -> List[str]:
    """Drop names that do not resolve, preserving order."""
    alive: Set[str] = set()

    def check(host: str) -> None:
        if dnsmod.resolves(host, timeout=timeout):
            alive.add(host)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(check, hosts))
    return [h for h in hosts if h in alive]
