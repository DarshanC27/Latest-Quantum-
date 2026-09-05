"""Scoring.

Two numbers, because they answer different questions. The security score
is the conventional "how bad is it today". The quantum readiness score is
"how much of the post-quantum migration is already done", which is what
the 2031 and 2035 deadlines are actually measured against -- an estate can
score well on the first and near zero on the second.

Repeated findings are damped: the same misconfiguration on forty hosts is
one mistake made once, and letting host count dominate would make a large
estate's score meaningless.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from ..crypto import tlsparams as tp
from ..model import SEVERITY_WEIGHT, Finding
from ..scan.tls import TLSEndpoint

GRADE_BANDS = ((90, "A"), (80, "B"), (65, "C"), (50, "D"), (35, "E"), (0, "F"))


def grade_for(score: float) -> str:
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def security_score(findings: Sequence[Finding]) -> float:
    """Deduct from 100 by severity, damping repeats of the same issue."""
    groups: Dict[str, List[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.id, []).append(finding)

    deduction = 0.0
    for group in groups.values():
        severity = min(group, key=lambda f: f.rank).severity
        base = SEVERITY_WEIGHT[severity]
        hosts = len({f.target for f in group})
        # Breadth matters, but sub-linearly and with a ceiling at double.
        multiplier = min(2.0, 1.0 + 0.15 * (hosts - 1))
        deduction += base * multiplier

    return round(max(0.0, 100.0 - deduction), 1)


@dataclass
class QuantumReadiness:
    """A breakdown of migration progress, not just a number."""

    score: float
    grade: str
    components: Dict[str, float] = field(default_factory=dict)
    maximums: Dict[str, float] = field(default_factory=dict)
    narrative: str = ""

    def rows(self) -> List[tuple]:
        return [
            (name, self.components.get(name, 0.0), self.maximums[name])
            for name in self.maximums
        ]


# Weightings reflect how much each control contributes to surviving a
# CRQC, with hybrid key exchange dominating because it is the only one
# that defends against retrospective decryption.
_WEIGHTS = {
    "Hybrid post-quantum key exchange": 40.0,
    "Forward secrecy": 25.0,
    "TLS 1.3 available": 15.0,
    "256-bit symmetric strength": 10.0,
    "Certificate agility": 10.0,
}


def quantum_readiness(endpoints: Sequence[TLSEndpoint]) -> QuantumReadiness:
    live = [e for e in endpoints if e.reachable]
    if not live:
        return QuantumReadiness(
            score=0.0, grade="F", components={}, maximums=dict(_WEIGHTS),
            narrative="No endpoint could be assessed, so readiness is unknown.",
        )

    total = len(live)
    components: Dict[str, float] = {}

    with_pqc = sum(1 for e in live if e.pqc_ready)
    components["Hybrid post-quantum key exchange"] = _WEIGHTS[
        "Hybrid post-quantum key exchange"
    ] * (with_pqc / total)

    def has_forward_secrecy(endpoint: TLSEndpoint) -> bool:
        suites = endpoint.all_cipher_suites
        if not suites:
            # TLS 1.3 mandates ephemeral key exchange, so an endpoint we
            # could not enumerate but which speaks only 1.3 still qualifies.
            return endpoint.supported_versions == [tp.TLS_1_3]
        return all(
            tp.CIPHER_SUITES[c].forward_secret
            for c in suites
            if c in tp.CIPHER_SUITES
        )

    fs = sum(1 for e in live if has_forward_secrecy(e))
    components["Forward secrecy"] = _WEIGHTS["Forward secrecy"] * (fs / total)

    tls13 = sum(1 for e in live if tp.TLS_1_3 in e.supported_versions)
    components["TLS 1.3 available"] = _WEIGHTS["TLS 1.3 available"] * (tls13 / total)

    def has_aes256(endpoint: TLSEndpoint) -> bool:
        suites = [tp.CIPHER_SUITES[c] for c in endpoint.all_cipher_suites if c in tp.CIPHER_SUITES]
        if not suites:
            return tp.TLS_1_3 in endpoint.supported_versions
        return any(s.bits >= 256 for s in suites)

    aes = sum(1 for e in live if has_aes256(e))
    components["256-bit symmetric strength"] = _WEIGHTS["256-bit symmetric strength"] * (aes / total)

    def is_agile(endpoint: TLSEndpoint) -> bool:
        leaf = endpoint.leaf
        return bool(leaf and leaf.lifetime_days and leaf.lifetime_days <= 398)

    agile = sum(1 for e in live if is_agile(e))
    components["Certificate agility"] = _WEIGHTS["Certificate agility"] * (agile / total)

    score = round(sum(components.values()), 1)

    if with_pqc == 0:
        narrative = (
            f"None of the {total} endpoint(s) assessed offer post-quantum key "
            "exchange, so all traffic remains exposed to harvest-now-decrypt-later. "
            "This is the single change that moves the score most."
        )
    elif with_pqc == total:
        narrative = (
            f"All {total} endpoint(s) negotiate hybrid post-quantum key exchange. "
            "The remaining work is certificate signatures, which depends on "
            "certificate authority support."
        )
    else:
        narrative = (
            f"{with_pqc} of {total} endpoint(s) offer post-quantum key exchange. "
            "Coverage is partial, so the weakest endpoint sets the real exposure."
        )

    return QuantumReadiness(
        score=score,
        grade=grade_for(score),
        components=components,
        maximums=dict(_WEIGHTS),
        narrative=narrative,
    )
