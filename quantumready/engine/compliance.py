"""Mapping findings onto the regimes an organisation is actually judged by.

Each framework declares which finding ids count against it, so status is
derived from evidence rather than asserted. Dates and obligations are
summarised for orientation; they are not legal advice, and the wording of
the source documents governs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from ..model import Finding


@dataclass
class Control:
    reference: str
    requirement: str
    triggered_by: Tuple[str, ...]  # finding ids that fail this control
    status: str = "pass"  # pass | fail | attention | not-assessed
    evidence: List[str] = field(default_factory=list)


@dataclass
class Framework:
    key: str
    name: str
    authority: str
    applies_to: str
    deadline: str
    controls: List[Control] = field(default_factory=list)

    @property
    def status(self) -> str:
        if any(c.status == "fail" for c in self.controls):
            return "fail"
        if any(c.status == "attention" for c in self.controls):
            return "attention"
        return "pass"

    @property
    def failed_controls(self) -> List[Control]:
        return [c for c in self.controls if c.status == "fail"]


def _frameworks() -> List[Framework]:
    """The regimes assessed, with the finding ids that fail each control."""
    return [
        Framework(
            key="ncsc-pqc",
            name="NCSC Post-Quantum Migration Roadmap",
            authority="UK National Cyber Security Centre",
            applies_to="UK organisations, critical national infrastructure, and their suppliers",
            deadline="Discovery by 2028; high-priority migration by 2031; complete by 2035",
            controls=[
                Control(
                    "Phase 1 (by 2028)",
                    "Complete a discovery exercise identifying all systems and services "
                    "that depend on cryptography, and draft a migration plan.",
                    ("governance.cryptographic-inventory",),
                ),
                Control(
                    "Phase 2 (by 2031)",
                    "Complete the highest-priority migration activities, starting with "
                    "anything protecting long-lived confidential data.",
                    ("pqc.no-hybrid-key-exchange", "pqc.no-forward-secrecy"),
                ),
                Control(
                    "Phase 3 (by 2035)",
                    "Complete migration of all systems, services and products to "
                    "post-quantum cryptography.",
                    ("pqc.no-hybrid-key-exchange", "pqc.classical-certificate-key",
                     "tls.no-tls13"),
                ),
            ],
        ),
        Framework(
            key="nist-pqc",
            name="NIST Post-Quantum Cryptography Standards",
            authority="US National Institute of Standards and Technology",
            applies_to="Federal systems, and the de facto global baseline for algorithm choice",
            deadline="FIPS 203/204/205 final since August 2024; 112-bit classical algorithms "
                     "deprecated by 2030 and disallowed after 2035",
            controls=[
                Control(
                    "FIPS 203 (ML-KEM)",
                    "Use ML-KEM for key establishment, in a hybrid construction during transition.",
                    ("pqc.no-hybrid-key-exchange",),
                ),
                Control(
                    "FIPS 204 (ML-DSA)",
                    "Plan migration of digital signatures and certificates to ML-DSA.",
                    ("pqc.classical-certificate-key",),
                ),
                Control(
                    "SP 800-131A transition",
                    "Retire algorithms and key sizes below 112 bits of classical security.",
                    ("certificate.weak-key", "certificate.broken-signature-hash",
                     "tls.broken-ciphers", "certificate.weak-curve"),
                ),
            ],
        ),
        Framework(
            key="cnsa2",
            name="CNSA 2.0",
            authority="US National Security Agency",
            applies_to="National security systems and their vendors",
            deadline="Web/cloud services to support CNSA 2.0 by 2025; exclusive use by 2033",
            controls=[
                Control(
                    "Key establishment",
                    "ML-KEM-1024 for key establishment.",
                    ("pqc.no-hybrid-key-exchange",),
                ),
                Control(
                    "Symmetric strength",
                    "AES-256 and SHA-384 as the minimum symmetric and hash strength.",
                    ("pqc.symmetric-128-only",),
                ),
            ],
        ),
        Framework(
            key="pci-dss-4",
            name="PCI DSS 4.0",
            authority="PCI Security Standards Council",
            applies_to="Any organisation storing, processing or transmitting card data",
            deadline="In force since March 2024",
            controls=[
                Control(
                    "Requirement 4.2.1",
                    "Strong cryptography and security protocols must protect cardholder "
                    "data in transit over open networks.",
                    ("tls.deprecated-version", "tls.broken-ciphers",
                     "certificate.expired", "certificate.weak-key",
                     "certificate.broken-signature-hash", "http.no-https-redirect"),
                ),
                Control(
                    "Requirement 12.3.3",
                    "Maintain an inventory of cryptographic cipher suites and protocols, "
                    "reviewed at least annually, with a documented plan to respond to "
                    "changes in cryptographic vulnerabilities.",
                    ("governance.cryptographic-inventory",),
                ),
            ],
        ),
        Framework(
            key="uk-gdpr",
            name="UK GDPR / Data Protection Act 2018",
            authority="Information Commissioner's Office",
            applies_to="Any organisation processing personal data of UK residents",
            deadline="In force",
            controls=[
                Control(
                    "Article 32",
                    "Implement measures appropriate to the risk, including encryption of "
                    "personal data, taking account of the state of the art.",
                    ("pqc.no-forward-secrecy", "tls.broken-ciphers",
                     "tls.deprecated-version", "http.no-https-redirect",
                     "http.insecure-cookies"),
                ),
                Control(
                    "Article 5(1)(e) and 32 combined",
                    "Personal data retained for long periods must remain protected for the "
                    "whole retention period, which is precisely what harvest-now-decrypt-later "
                    "undermines.",
                    ("pqc.no-hybrid-key-exchange",),
                ),
            ],
        ),
        Framework(
            key="nis2",
            name="NIS2 Directive",
            authority="European Union",
            applies_to="Essential and important entities operating in the EU",
            deadline="National transposition since October 2024",
            controls=[
                Control(
                    "Article 21(2)(h)",
                    "Policies on the use of cryptography and, where appropriate, encryption.",
                    ("tls.broken-ciphers", "tls.deprecated-version",
                     "governance.cryptographic-inventory"),
                ),
                Control(
                    "Article 21(2)(d)",
                    "Supply chain security, including the security of third-party components.",
                    ("licence.end-of-life-component", "licence.undetermined"),
                ),
            ],
        ),
        Framework(
            key="iso27001",
            name="ISO/IEC 27001:2022",
            authority="International Organization for Standardization",
            applies_to="Certified organisations and their suppliers",
            deadline="Ongoing certification",
            controls=[
                Control(
                    "Annex A 8.24",
                    "Rules for the effective use of cryptography, including key management, "
                    "must be defined and implemented.",
                    ("certificate.expired", "certificate.weak-key",
                     "tls.broken-ciphers", "governance.cryptographic-inventory"),
                ),
                Control(
                    "Annex A 5.23",
                    "Information security for use of cloud and third-party services.",
                    ("licence.copyleft-obligation", "licence.commercial-restriction"),
                ),
            ],
        ),
        Framework(
            key="cyber-essentials",
            name="Cyber Essentials",
            authority="UK NCSC / IASME",
            applies_to="UK public sector suppliers and organisations seeking certification",
            deadline="Annual reassessment",
            controls=[
                Control(
                    "Secure configuration",
                    "Services must not offer insecure protocols or default configurations.",
                    ("tls.deprecated-version", "tls.broken-ciphers",
                     "http.version-disclosure"),
                ),
                Control(
                    "Security update management",
                    "Software must be supported and receiving security updates.",
                    ("licence.end-of-life-component",),
                ),
            ],
        ),
    ]


def assess(findings: Sequence[Finding]) -> List[Framework]:
    """Score every framework against the findings produced by this scan."""
    by_id: Dict[str, List[Finding]] = {}
    for finding in findings:
        by_id.setdefault(finding.id, []).append(finding)

    frameworks = _frameworks()
    for framework in frameworks:
        for control in framework.controls:
            hits = [f for fid in control.triggered_by for f in by_id.get(fid, [])]
            if not hits:
                control.status = "pass"
                continue
            worst = min(f.rank for f in hits)
            # A control fails on high or critical evidence; medium and below
            # flag it for attention rather than declaring non-compliance,
            # since materiality is a judgement the organisation must make.
            control.status = "fail" if worst <= 1 else "attention"
            control.evidence = sorted({f"{f.title} ({f.target})" for f in hits})[:6]

    return frameworks


def summary(frameworks: Sequence[Framework]) -> Dict[str, int]:
    counts = {"pass": 0, "attention": 0, "fail": 0}
    for framework in frameworks:
        counts[framework.status] += 1
    return counts
