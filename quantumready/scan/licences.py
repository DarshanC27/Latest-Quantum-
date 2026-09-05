"""Third-party component and licence discovery from a live site.

What this can and cannot see is worth stating plainly, because a licence
report that overstates its coverage is worse than none: it only observes
what a browser would load, so it finds front-end components and the
platform, never server-side dependencies. It is a starting inventory to
reconcile against the build system, not a substitute for one.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from ..data.licences import COMPONENTS, licence_for
from ..model import LicenceRecord
from . import http as httpmod

# Manifests that are sometimes served by accident and settle the licence
# question directly when present.
MANIFEST_PATHS = (
    "/package.json",
    "/composer.json",
    "/bower.json",
)

SCRIPT_PATTERN = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
LINK_PATTERN = re.compile(r"<link[^>]+href=[\"']([^\"']+)[\"']", re.I)
GENERATOR_PATTERN = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']", re.I
)


@dataclass
class ComponentHit:
    name: str
    version: Optional[str]
    licence: str
    evidence: str
    end_of_life: bool = False
    note: str = ""


@dataclass
class LicenceScan:
    host: str
    components: List[ComponentHit] = field(default_factory=list)
    generator: Optional[str] = None
    exposed_manifests: Dict[str, str] = field(default_factory=dict)
    third_party_origins: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def records(self) -> List[LicenceRecord]:
        out: List[LicenceRecord] = []
        for hit in self.components:
            licence = licence_for(hit.licence)
            out.append(
                LicenceRecord(
                    component=hit.name,
                    version=hit.version,
                    licence=licence.spdx,
                    category=licence.category,
                    obligation=licence.obligation,
                    risk=licence.commercial_risk,
                    where=self.host,
                    evidence=hit.evidence,
                )
            )
        return out


def _version_is_below(version: str, threshold: str) -> bool:
    """Compare dotted versions numerically, shortest-wins on a tie."""
    def parts(value: str) -> Tuple[int, ...]:
        return tuple(int(p) for p in re.findall(r"\d+", value)[:4])

    try:
        left, right = parts(version), parts(threshold)
    except ValueError:
        return False
    length = max(len(left), len(right))
    left += (0,) * (length - len(left))
    right += (0,) * (length - len(right))
    return left < right


def _is_end_of_life(component, version: Optional[str]) -> bool:
    if not component.end_of_life:
        return False
    if component.end_of_life == "all":
        return True
    if not version:
        return False
    if component.end_of_life.startswith("<"):
        return _version_is_below(version, component.end_of_life[1:])
    return False


def detect_components(html: str, urls: List[str]) -> List[ComponentHit]:
    """Match component signatures against markup and asset URLs."""
    haystack = "\n".join(urls) + "\n" + html
    hits: Dict[str, ComponentHit] = {}

    for component in COMPONENTS:
        for pattern in component.detect:
            match = re.search(pattern, haystack, re.I)
            if not match:
                continue
            version = None
            if component.version_group and match.groups():
                version = match.group(1)
            evidence = match.group(0)[:120]
            existing = hits.get(component.name)
            # Prefer the match that pinned down a version.
            if existing and (existing.version or not version):
                continue
            hits[component.name] = ComponentHit(
                name=component.name,
                version=version,
                licence=component.licence,
                evidence=evidence,
                end_of_life=_is_end_of_life(component, version),
                note=component.note,
            )
            break

    return sorted(hits.values(), key=lambda h: h.name.lower())


def _origins(urls: List[str], host: str) -> List[str]:
    seen: List[str] = []
    for url in urls:
        match = re.match(r"^https?://([^/:]+)", url, re.I)
        if not match:
            continue
        origin = match.group(1).lower()
        if origin == host or origin.endswith("." + host):
            continue
        if origin not in seen:
            seen.append(origin)
    return seen


def _fetch_manifests(host: str, timeout: float) -> Dict[str, str]:
    """Look for dependency manifests served from the web root.

    A manifest reachable over the public internet is both a licence
    windfall and a finding in its own right, since it enumerates the exact
    dependency versions an attacker would need to target.
    """
    found: Dict[str, str] = {}
    for path in MANIFEST_PATHS:
        response = httpmod.fetch(f"https://{host}{path}", timeout=timeout, max_redirects=1)
        if not response.reachable or response.status != 200:
            continue
        body = response.body.strip()
        if not body.startswith("{"):
            continue
        try:
            json.loads(body)
        except ValueError:
            continue
        found[path] = body[:8000]
    return found


def _components_from_manifest(body: str) -> List[ComponentHit]:
    try:
        data = json.loads(body)
    except ValueError:
        return []
    hits: List[ComponentHit] = []
    declared = data.get("license") or data.get("licence")
    if isinstance(declared, str) and data.get("name"):
        hits.append(
            ComponentHit(
                name=str(data["name"]),
                version=str(data.get("version") or "") or None,
                licence=declared,
                evidence="declared in exposed manifest",
                note="the application's own declared licence",
            )
        )
    for section in ("dependencies", "devDependencies", "require"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, version in list(block.items())[:100]:
            hits.append(
                ComponentHit(
                    name=str(name),
                    version=str(version).lstrip("^~>=< ") or None,
                    licence="UNKNOWN",
                    evidence=f"{section} in exposed manifest",
                    note="licence not stated in the manifest; resolve from the "
                         "package registry",
                )
            )
    return hits


def scan_licences(
    host: str,
    *,
    html: Optional[str] = None,
    timeout: float = 10.0,
    probe_manifests: bool = True,
) -> LicenceScan:
    """Inventory third-party components served by ``host``."""
    result = LicenceScan(host=host)

    if html is None:
        response = httpmod.fetch(f"https://{host}/", timeout=timeout)
        if not response.reachable:
            result.notes.append(f"could not retrieve markup: {response.error}")
            return result
        html = response.body

    urls = SCRIPT_PATTERN.findall(html) + LINK_PATTERN.findall(html)
    result.third_party_origins = _origins(urls, host)

    generator = GENERATOR_PATTERN.search(html)
    if generator:
        result.generator = generator.group(1)

    result.components = detect_components(html, urls)

    if probe_manifests:
        result.exposed_manifests = _fetch_manifests(host, timeout)
        for path, body in result.exposed_manifests.items():
            for hit in _components_from_manifest(body):
                if not any(c.name.lower() == hit.name.lower() for c in result.components):
                    result.components.append(hit)
            result.notes.append(
                f"{path} is publicly readable and enumerates dependency versions"
            )

    if not result.components:
        result.notes.append(
            "no known third-party components matched; the site may bundle its "
            "assets, which hides component identity from any external scan"
        )

    return result
