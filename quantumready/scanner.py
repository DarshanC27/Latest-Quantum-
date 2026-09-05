"""The scan pipeline.

Stages report progress through a callback so the same code drives the CLI
and the live web dashboard; nothing here knows which is attached. Failures
in one stage are recorded and the scan continues -- a DNS block or an
unreachable subdomain should degrade a report, not end it.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from .crypto import tlsparams as tp
from .engine import compliance, quantum, remediation, rules, scoring
from .model import CryptoAsset, Finding, ScanResult, ScanTarget
from .scan import discovery, dns as dnsmod, http as httpmod, licences as licmod, tls as tlsmod

ProgressFn = Callable[[str, str, dict], None]

# Stage weights, so the progress bar advances in proportion to real work.
STAGES = (
    ("discovery", "Discovering hosts", 10),
    ("tls", "Assessing TLS and certificates", 45),
    ("http", "Checking HTTP security controls", 15),
    ("dns", "Checking DNS posture", 10),
    ("licences", "Inventorying components and licences", 10),
    ("analysis", "Scoring and building the report", 10),
)


def normalise_domain(value: str) -> str:
    """Accept a URL, a bare domain, or something with stray whitespace."""
    value = (value or "").strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/")[0].split("?")[0]
    value = value.split("@")[-1]  # tolerate an email address
    if ":" in value and not value.count(":") > 1:
        value = value.split(":")[0]
    return value.strip(". ")


@dataclass
class ScanOptions:
    max_hosts: int = 12
    timeout: float = 7.0
    deep_tls: bool = True
    probe_ciphers: bool = True
    use_ct: bool = True
    check_licences: bool = True
    check_dns: bool = True
    workers: int = 8
    quantum_scenario: str = "central"
    quantum_year: Optional[int] = None


class Scanner:
    """Runs an assessment end to end."""

    def __init__(self, options: Optional[ScanOptions] = None, progress: Optional[ProgressFn] = None):
        self.options = options or ScanOptions()
        self._progress = progress

    def emit(self, stage: str, message: str, **data) -> None:
        if self._progress:
            try:
                self._progress(stage, message, data)
            except Exception:  # noqa: BLE001 - a broken listener must not stop a scan
                pass

    def run(self, target: ScanTarget) -> ScanResult:
        domain = normalise_domain(target.domain)
        target.domain = domain
        result = ScanResult(
            target=target, started_at=_dt.datetime.now(_dt.timezone.utc)
        )

        hosts = self._discover(domain, result)
        endpoints = self._scan_tls(hosts, result)
        self._scan_http(endpoints, result)
        self._scan_dns(domain, result)
        self._scan_licences(endpoints, result)
        self._analyse(result)

        result.finished_at = _dt.datetime.now(_dt.timezone.utc)
        self.emit(
            "done",
            f"Scan complete in {result.duration_seconds:.1f}s",
            progress=100,
            findings=len(result.findings),
            score=result.risk_score,
        )
        return result

    # -- stages ------------------------------------------------------------

    def _discover(self, domain: str, result: ScanResult) -> List[str]:
        self.emit("discovery", f"Discovering hosts for {domain}", progress=2)
        try:
            found = discovery.discover(
                domain,
                use_ct=self.options.use_ct,
                limit=self.options.max_hosts,
                timeout=min(self.options.timeout * 3, 25.0),
            )
            result.scan_notes.extend(found.notes)
            hosts = found.hosts
            self.emit(
                "discovery",
                f"{len(hosts)} host(s) to assess",
                progress=10,
                hosts=hosts,
                sources=found.sources,
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"host discovery failed: {exc}")
            hosts = [domain]
            self.emit("discovery", "Discovery failed; assessing the apex only", progress=10)

        # Only scan names that resolve, so the report is not padded with
        # certificate-transparency entries that no longer exist.
        live = discovery.filter_live(hosts, timeout=3.0)
        dropped = len(hosts) - len(live)
        if dropped:
            result.scan_notes.append(
                f"{dropped} discovered name(s) no longer resolve and were skipped"
            )
        if not live:
            live = [domain]
        result.discovered_hosts = live
        return live

    def _scan_tls(self, hosts: Sequence[str], result: ScanResult) -> List[tlsmod.TLSEndpoint]:
        self.emit("tls", f"Assessing TLS on {len(hosts)} host(s)", progress=12)
        completed = [0]
        total = max(1, len(hosts))

        def on_done(host: str, port: int, endpoint) -> None:
            completed[0] += 1
            share = completed[0] / total
            detail = "unreachable"
            if endpoint and endpoint.reachable:
                pqc = "PQC ready" if endpoint.pqc_ready else "no PQC"
                detail = f"{endpoint.negotiated_version or 'TLS'}, {pqc}"
            self.emit(
                "tls",
                f"{host}: {detail}",
                progress=12 + int(45 * share),
                host=host,
                reachable=bool(endpoint and endpoint.reachable),
                pqc_ready=bool(endpoint and endpoint.pqc_ready),
            )

        endpoints = tlsmod.scan_endpoints(
            [(host, 443) for host in hosts],
            timeout=self.options.timeout,
            deep=self.options.deep_tls,
            probe_ciphers=self.options.probe_ciphers,
            workers=self.options.workers,
            progress=on_done,
        )
        result.endpoints = endpoints
        return endpoints

    def _scan_http(self, endpoints: Sequence[tlsmod.TLSEndpoint], result: ScanResult) -> None:
        live = [e for e in endpoints if e.reachable]
        if not live:
            return
        self.emit("http", "Checking HTTP security controls", progress=60)
        for index, endpoint in enumerate(live[:6], start=1):
            try:
                http_result = httpmod.scan_http(endpoint.host, timeout=self.options.timeout)
                result.http_results.append(http_result)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"HTTP check failed for {endpoint.host}: {exc}")
            self.emit(
                "http",
                f"{endpoint.host}: headers checked",
                progress=60 + int(15 * index / min(len(live), 6)),
            )

    def _scan_dns(self, domain: str, result: ScanResult) -> None:
        if not self.options.check_dns:
            return
        self.emit("dns", f"Checking DNS posture for {domain}", progress=76)
        try:
            result.dns_result = dnsmod.scan_dns(domain, timeout=4.0)
            posture = result.dns_result
            self.emit(
                "dns",
                "DNS checked"
                + ("" if posture.available else " (resolver unreachable)"),
                progress=85,
                dnssec=posture.dnssec,
                caa=len(posture.caa_records),
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"DNS checks failed: {exc}")

    def _scan_licences(self, endpoints: Sequence[tlsmod.TLSEndpoint], result: ScanResult) -> None:
        if not self.options.check_licences:
            return
        self.emit("licences", "Inventorying components and licences", progress=86)
        primary = next((e for e in endpoints if e.reachable), None)
        if primary is None:
            return

        html = ""
        for http_result in result.http_results:
            if primary.host in http_result.url and http_result.body:
                html = http_result.body
                break
        try:
            scan = licmod.scan_licences(
                primary.host, html=html or None, timeout=self.options.timeout
            )
            result.licences = scan.records()
            result.scan_notes.extend(scan.notes)
            self._licence_scan = scan
            self.emit(
                "licences",
                f"{len(scan.components)} component(s) identified",
                progress=92,
                components=[c.name for c in scan.components],
            )
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"licence scan failed: {exc}")
            self._licence_scan = None

    def _analyse(self, result: ScanResult) -> None:
        self.emit("analysis", "Scoring and building the report", progress=93)
        now = _dt.datetime.now(_dt.timezone.utc)
        findings: List[Finding] = []

        for endpoint in result.endpoints:
            findings += rules.certificate_findings(endpoint, now)
            findings += rules.tls_findings(endpoint)
            findings += rules.pqc_findings(endpoint, result.target)

        for http_result in result.http_results:
            host = re.sub(r"^https?://", "", http_result.url).split("/")[0]
            findings += rules.http_findings(http_result, host)

        if result.dns_result is not None:
            findings += rules.dns_findings(result.dns_result)

        licence_scan = getattr(self, "_licence_scan", None)
        if licence_scan is not None:
            findings += rules.licence_findings(licence_scan, result.licences)

        result.crypto_assets = build_inventory(result.endpoints)
        findings += rules.governance_findings(result.target, result.crypto_assets)

        result.findings = findings
        result.risk_score = scoring.security_score(findings)
        result.risk_grade = scoring.grade_for(result.risk_score)
        result.mosca = quantum.assess_mosca(
            result.target.data_shelf_life_years,
            result.target.migration_years,
            scenario=self.options.quantum_scenario,
            quantum_year=self.options.quantum_year,
            now=now,
        )
        result.compliance = compliance.assess(findings)
        result.remediation = remediation.build_plan(findings)
        result.readiness = scoring.quantum_readiness(result.endpoints)


def build_inventory(endpoints: Sequence[tlsmod.TLSEndpoint]) -> List[CryptoAsset]:
    """Every algorithm observed in use, with its post-quantum standing."""
    assets: List[CryptoAsset] = []

    for endpoint in endpoints:
        if not endpoint.reachable:
            continue
        label = endpoint.label

        leaf = endpoint.leaf
        if leaf and leaf.public_key:
            key = leaf.public_key
            assessment = quantum.assess_public_key(key.algorithm, key.size_bits, key.curve)
            assets.append(CryptoAsset(
                name=assessment.algorithm, kind="signature", where=label,
                context="TLS certificate public key",
                classical_bits=assessment.classical_bits,
                quantum_bits=assessment.quantum_bits,
                quantum_safe=assessment.quantum_safe,
                broken_by=assessment.broken_by,
                replacement=assessment.replacement,
            ))
        if leaf and leaf.signature_hash:
            hash_assessment = quantum.assess_hash(leaf.signature_hash)
            assets.append(CryptoAsset(
                name=leaf.signature_hash, kind="hash", where=label,
                context="certificate signature hash",
                classical_bits=hash_assessment.classical_bits,
                quantum_bits=hash_assessment.quantum_bits,
                quantum_safe=hash_assessment.quantum_safe,
                broken_by=hash_assessment.broken_by,
                replacement=hash_assessment.replacement,
            ))

        for code in endpoint.classical_groups:
            group = tp.NAMED_GROUPS.get(code)
            if not group:
                continue
            assets.append(CryptoAsset(
                name=group.name, kind="key-exchange", where=label,
                context="TLS key exchange group",
                classical_bits=group.classical_bits, quantum_bits=0,
                quantum_safe=False, broken_by="Shor",
                replacement="X25519MLKEM768",
            ))

        for code in endpoint.pqc_groups:
            group = tp.NAMED_GROUPS.get(code)
            if not group:
                continue
            assets.append(CryptoAsset(
                name=group.name, kind="key-encapsulation", where=label,
                context="TLS hybrid key exchange group",
                classical_bits=group.classical_bits, quantum_bits=128,
                quantum_safe=True, broken_by=None,
            ))

        seen_ciphers = set()
        for code in endpoint.all_cipher_suites:
            suite = tp.CIPHER_SUITES.get(code)
            if not suite or suite.cipher in seen_ciphers:
                continue
            seen_ciphers.add(suite.cipher)
            symmetric = quantum.assess_symmetric(suite.cipher, suite.bits)
            assets.append(CryptoAsset(
                name=suite.cipher, kind="cipher", where=label,
                context="TLS record encryption",
                classical_bits=symmetric.classical_bits,
                quantum_bits=symmetric.quantum_bits,
                quantum_safe=symmetric.quantum_safe,
                broken_by=symmetric.broken_by,
                replacement=symmetric.replacement,
            ))

    return assets
