"""Shared result types.

Scanners collect facts; the rules engine turns facts into
:class:`Finding` objects. Keeping those two jobs apart means every verdict
in a report can be traced back to an observation, and the reasoning lives
in one auditable place instead of being scattered through the collectors.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Ordered worst-first; used for sorting and for the CI exit-code threshold.
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

# Contribution of a single finding to the deducted risk score.
SEVERITY_WEIGHT = {
    "critical": 40.0,
    "high": 20.0,
    "medium": 8.0,
    "low": 3.0,
    "info": 0.0,
}

CATEGORIES = (
    "post-quantum",
    "certificate",
    "tls",
    "http",
    "dns",
    "licence",
    "governance",
)


@dataclass
class Finding:
    """One issue, with everything a reader needs to act on it."""

    id: str  # stable slug, e.g. "tls.deprecated-version"
    title: str
    severity: str
    category: str
    target: str
    detail: str  # what was observed
    impact: str  # why it matters
    remediation: str  # what to do about it
    quantum_relevant: bool = False
    references: List[str] = field(default_factory=list)
    compliance: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category {self.category!r}")

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CryptoAsset:
    """One use of a cryptographic algorithm, for the inventory and CBOM.

    This is the artefact most organisations are missing entirely: NIST and
    NCSC both make a cryptographic inventory the first migration step,
    because you cannot replace what you cannot enumerate.
    """

    name: str  # "RSA-2048", "X25519", "AES-256-GCM"
    kind: str  # signature | key-exchange | key-encapsulation | cipher | hash
    where: str  # endpoint or artefact the algorithm was seen on
    context: str  # "TLS certificate key", "TLS key exchange", ...
    classical_bits: int = 0
    quantum_bits: int = 0  # security remaining against a CRQC
    quantum_safe: bool = False
    broken_by: Optional[str] = None  # "Shor" | "Grover" | None
    replacement: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LicenceRecord:
    """A third-party component and the licence obligation it carries."""

    component: str
    version: Optional[str]
    licence: str  # SPDX identifier where known
    category: str  # permissive | weak-copyleft | strong-copyleft | proprietary | unknown
    obligation: str
    risk: str  # severity-style rating of the legal exposure
    where: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanTarget:
    """The organisation being assessed."""

    organisation: str
    domain: str
    data_shelf_life_years: int = 10  # Mosca's X
    migration_years: int = 5  # Mosca's Y
    sector: str = "general"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """The complete output of one assessment."""

    target: ScanTarget
    started_at: _dt.datetime
    finished_at: Optional[_dt.datetime] = None
    endpoints: List[Any] = field(default_factory=list)  # TLSEndpoint
    http_results: List[Any] = field(default_factory=list)
    dns_result: Any = None
    discovered_hosts: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    crypto_assets: List[CryptoAsset] = field(default_factory=list)
    licences: List[LicenceRecord] = field(default_factory=list)
    scan_notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    # Filled in by the engine.
    risk_score: float = 100.0
    risk_grade: str = "A"
    readiness: Any = None  # QuantumReadiness
    mosca: Any = None  # MoscaResult
    compliance: List[Any] = field(default_factory=list)
    remediation: List[Any] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if not self.finished_at:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.category, f.target))

    def quantum_findings(self) -> List[Finding]:
        return [f for f in self.sorted_findings() if f.quantum_relevant]
