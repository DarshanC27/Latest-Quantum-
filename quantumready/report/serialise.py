"""JSON, Markdown and CycloneDX CBOM output.

The JSON form is the canonical one: the HTML report and any downstream
pipeline are both views over it, so a consumer never has to scrape a
document to get at a result.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import uuid
from typing import Any, Dict, List

from ..crypto import tlsparams as tp
from ..model import ScanResult

SPEC_VERSION = "1.6"
TOOL_NAME = "Quantum.Ready"
TOOL_VERSION = "1.0.0"


def _iso(value) -> Any:
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    return value


def to_dict(result: ScanResult) -> Dict[str, Any]:
    """The full result as plain data."""
    readiness = result.readiness
    mosca = result.mosca

    endpoints = []
    for endpoint in result.endpoints:
        leaf = endpoint.leaf
        entry: Dict[str, Any] = {
            "host": endpoint.host,
            "port": endpoint.port,
            "reachable": endpoint.reachable,
            "error": endpoint.error,
            "trusted": endpoint.trusted,
            "trust_error": endpoint.trust_error,
            "hostname_matches": endpoint.hostname_matches,
            "chain_length": len(endpoint.chain),
            "chain_complete": endpoint.chain_complete,
            "negotiated_version": endpoint.negotiated_version,
            "negotiated_cipher": endpoint.negotiated_cipher,
            "alpn": endpoint.alpn,
            "supported_versions": [
                tp.VERSION_NAMES.get(v, str(v)) for v in endpoint.supported_versions
            ],
            "cipher_suites": {
                tp.VERSION_NAMES.get(v, str(v)): [tp.cipher_name(c) for c in suites]
                for v, suites in endpoint.cipher_suites.items()
            },
            "key_exchange_groups": [tp.group_name(g) for g in endpoint.classical_groups],
            "post_quantum_groups": [tp.group_name(g) for g in endpoint.pqc_groups],
            "pqc_ready": endpoint.pqc_ready,
            "interception_suspected": endpoint.interception_suspected,
            "interception_reasons": endpoint.interception_reasons,
            "notes": endpoint.notes,
        }
        if leaf:
            entry["certificate"] = {
                "subject": leaf.subject_display,
                "issuer": leaf.issuer_display,
                "serial": str(leaf.serial_number),
                "not_before": _iso(leaf.not_before),
                "not_after": _iso(leaf.not_after),
                "days_until_expiry": leaf.days_until_expiry(),
                "lifetime_days": leaf.lifetime_days,
                "public_key": leaf.public_key.display if leaf.public_key else None,
                "key_algorithm": leaf.public_key.algorithm if leaf.public_key else None,
                "key_bits": leaf.public_key.size_bits if leaf.public_key else None,
                "signature_algorithm": leaf.signature_algorithm,
                "san_dns": leaf.san_dns,
                "is_ca": leaf.is_ca,
                "self_signed": leaf.is_self_signed,
                "validation_level": leaf.validation_level,
                "has_sct": leaf.has_sct,
                "fingerprint_sha256": leaf.fingerprint_sha256,
                "ocsp_urls": leaf.ocsp_urls,
                "crl_urls": leaf.crl_urls,
                "warnings": leaf.warnings,
            }
        endpoints.append(entry)

    dns_block = None
    if result.dns_result is not None:
        posture = result.dns_result
        dns_block = {
            "available": posture.available,
            "a": posture.a_records,
            "aaaa": posture.aaaa_records,
            "ns": posture.ns_records,
            "mx": posture.mx_records,
            "caa": posture.caa_records,
            "spf": posture.spf,
            "dmarc": posture.dmarc,
            "dmarc_policy": posture.dmarc_policy,
            "dnssec": posture.dnssec,
            "undetermined": posture.undetermined,
            "errors": posture.errors,
        }

    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "target": result.target.to_dict(),
        "started_at": _iso(result.started_at),
        "finished_at": _iso(result.finished_at),
        "duration_seconds": round(result.duration_seconds, 2),
        "summary": {
            "risk_score": result.risk_score,
            "risk_grade": result.risk_grade,
            "quantum_readiness_score": readiness.score if readiness else None,
            "quantum_readiness_grade": readiness.grade if readiness else None,
            "quantum_readiness_narrative": readiness.narrative if readiness else None,
            "quantum_readiness_components": readiness.components if readiness else {},
            "counts": result.counts_by_severity(),
            "hosts_assessed": len(result.endpoints),
            "hosts_reachable": sum(1 for e in result.endpoints if e.reachable),
        },
        "mosca": {
            "verdict": mosca.verdict,
            "at_risk": mosca.at_risk,
            "formula": mosca.formula,
            "shelf_life_years": mosca.shelf_life_years,
            "migration_years": mosca.migration_years,
            "years_to_quantum": mosca.years_to_quantum,
            "quantum_year": mosca.quantum_year,
            "exposure_years": mosca.exposure_years,
            "deadline_year": mosca.deadline_year,
            "explanation": mosca.explanation,
            "assumptions": mosca.assumptions,
        } if mosca else None,
        "discovered_hosts": result.discovered_hosts,
        "endpoints": endpoints,
        "dns": dns_block,
        "findings": [f.to_dict() for f in result.sorted_findings()],
        "crypto_inventory": [a.to_dict() for a in result.crypto_assets],
        "licences": [l.to_dict() for l in result.licences],
        "compliance": [
            {
                "key": framework.key,
                "name": framework.name,
                "authority": framework.authority,
                "applies_to": framework.applies_to,
                "deadline": framework.deadline,
                "status": framework.status,
                "controls": [
                    {
                        "reference": c.reference,
                        "requirement": c.requirement,
                        "status": c.status,
                        "evidence": c.evidence,
                    }
                    for c in framework.controls
                ],
            }
            for framework in result.compliance
        ],
        "remediation": [a.to_dict() for a in result.remediation],
        "notes": result.scan_notes,
        "errors": result.errors,
    }


def to_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent, default=str)


# --- CycloneDX CBOM --------------------------------------------------------

# Mapping our asset kinds onto CycloneDX cryptographic primitives.
_PRIMITIVE = {
    "signature": "signature",
    "key-exchange": "key-agree",
    "key-encapsulation": "kem",
    "cipher": "block-cipher",
    "hash": "hash",
}

_FUNCTIONS = {
    "signature": ["keygen", "sign", "verify"],
    "key-exchange": ["keygen", "keyderive"],
    "key-encapsulation": ["keygen", "encapsulate", "decapsulate"],
    "cipher": ["encrypt", "decrypt"],
    "hash": ["digest"],
}


def to_cbom(result: ScanResult) -> Dict[str, Any]:
    """Export the cryptographic inventory as a CycloneDX 1.6 CBOM.

    A cryptographic bill of materials is what NCSC's 2028 discovery phase
    ultimately asks for, and CycloneDX is the format that existing SBOM
    tooling already understands, so this output drops into a pipeline
    rather than needing one built for it.
    """
    components: List[Dict[str, Any]] = []
    seen = set()

    for asset in result.crypto_assets:
        key = (asset.name, asset.kind, asset.where)
        if key in seen:
            continue
        seen.add(key)
        ref = "crypto:" + hashlib.sha256(
            f"{asset.name}|{asset.kind}|{asset.where}".encode()
        ).hexdigest()[:16]
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": asset.name,
            "description": f"{asset.context} on {asset.where}",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": _PRIMITIVE.get(asset.kind, "other"),
                    "executionEnvironment": "software-plain-ram",
                    "implementationPlatform": "generic",
                    "certificationLevel": ["none"],
                    "cryptoFunctions": _FUNCTIONS.get(asset.kind, []),
                    "classicalSecurityLevel": asset.classical_bits,
                    "nistQuantumSecurityLevel": 0 if not asset.quantum_safe else 3,
                },
            },
            "properties": [
                {"name": "quantumready:quantumSafe", "value": str(asset.quantum_safe).lower()},
                {"name": "quantumready:brokenBy", "value": asset.broken_by or "none"},
                {"name": "quantumready:recommendedReplacement", "value": asset.replacement or ""},
                {"name": "quantumready:observedOn", "value": asset.where},
            ],
        })

    for endpoint in result.endpoints:
        leaf = endpoint.leaf
        if not leaf:
            continue
        ref = "cert:" + leaf.fingerprint_sha256[:16]
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": leaf.subject_display,
            "description": f"TLS certificate served by {endpoint.label}",
            "cryptoProperties": {
                "assetType": "certificate",
                "certificateProperties": {
                    "subjectName": leaf.subject_display,
                    "issuerName": leaf.issuer_display,
                    "notValidBefore": _iso(leaf.not_before),
                    "notValidAfter": _iso(leaf.not_after),
                    "signatureAlgorithmRef": leaf.signature_algorithm,
                    "certificateFormat": "X.509",
                    "certificateExtension": "der",
                },
            },
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _iso(result.started_at),
            "tools": {
                "components": [
                    {"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}
                ]
            },
            "component": {
                "type": "application",
                "name": result.target.organisation or result.target.domain,
                "version": "observed",
            },
        },
        "components": components,
    }


def to_cbom_json(result: ScanResult, *, indent: int = 2) -> str:
    return json.dumps(to_cbom(result), indent=indent, default=str)


# --- Markdown --------------------------------------------------------------


def to_markdown(result: ScanResult) -> str:
    """A report that reads well in a pull request or a ticket."""
    counts = result.counts_by_severity()
    readiness = result.readiness
    mosca = result.mosca
    lines: List[str] = []

    lines.append(f"# Post-Quantum Readiness Report: {result.target.organisation}")
    lines.append("")
    lines.append(f"**Domain:** `{result.target.domain}`  ")
    lines.append(f"**Scanned:** {result.started_at:%d %B %Y %H:%M} UTC  ")
    lines.append(f"**Duration:** {result.duration_seconds:.1f}s  ")
    lines.append("")
    lines.append(f"| Security score | Quantum readiness | Critical | High | Medium | Low |")
    lines.append("|---|---|---|---|---|---|")
    lines.append(
        f"| **{result.risk_score}/100 ({result.risk_grade})** | "
        f"**{readiness.score if readiness else 0}/100 ({readiness.grade if readiness else '-'})** | "
        f"{counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |"
    )
    lines.append("")

    if mosca:
        lines.append("## Mosca's inequality")
        lines.append("")
        lines.append(f"**{mosca.verdict}** — `{mosca.formula}`")
        lines.append("")
        lines.append(mosca.explanation)
        lines.append("")
        for assumption in mosca.assumptions:
            lines.append(f"- {assumption}")
        lines.append("")

    if readiness:
        lines.append("## Quantum readiness breakdown")
        lines.append("")
        lines.append("| Control | Score | Maximum |")
        lines.append("|---|---:|---:|")
        for name, value, maximum in readiness.rows():
            lines.append(f"| {name} | {value:.1f} | {maximum:.0f} |")
        lines.append("")
        lines.append(readiness.narrative)
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    for finding in result.sorted_findings():
        if finding.severity == "info":
            continue
        flag = " `quantum`" if finding.quantum_relevant else ""
        lines.append(f"### [{finding.severity.upper()}] {finding.title}{flag}")
        lines.append("")
        lines.append(f"**Where:** `{finding.target}`  ")
        lines.append(f"**Observed:** {finding.detail}")
        lines.append("")
        lines.append(f"**Why it matters:** {finding.impact}")
        lines.append("")
        lines.append(f"**Fix:** {finding.remediation}")
        if finding.compliance:
            lines.append("")
            lines.append(f"**Compliance:** {', '.join(finding.compliance)}")
        lines.append("")

    if result.remediation:
        lines.append("## Remediation plan")
        lines.append("")
        lines.append("| # | Action | Effort | Phase |")
        lines.append("|---:|---|---|---|")
        for action in result.remediation:
            lines.append(
                f"| {action.priority} | {action.title} | {action.effort} | {action.phase} |"
            )
        lines.append("")

    if result.licences:
        lines.append("## Third-party components and licences")
        lines.append("")
        lines.append("| Component | Version | Licence | Category | Risk |")
        lines.append("|---|---|---|---|---|")
        for record in result.licences:
            lines.append(
                f"| {record.component} | {record.version or '—'} | {record.licence} "
                f"| {record.category} | {record.risk} |"
            )
        lines.append("")

    if result.compliance:
        lines.append("## Compliance position")
        lines.append("")
        lines.append("| Framework | Status | Deadline |")
        lines.append("|---|---|---|")
        for framework in result.compliance:
            lines.append(
                f"| {framework.name} | {framework.status.upper()} | {framework.deadline} |"
            )
        lines.append("")

    if result.scan_notes or result.errors:
        lines.append("## Scan notes")
        lines.append("")
        for note in result.scan_notes + result.errors:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        f"_Generated by {TOOL_NAME} {TOOL_VERSION}. This assesses the externally "
        "visible estate only; internal systems, VPNs, code signing and backups "
        "require a separate inventory._"
    )
    return "\n".join(lines)
