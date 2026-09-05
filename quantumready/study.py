"""Benchmark studies across a cohort of organisations.

This runs the ordinary scanner over many subjects and aggregates the
results into statistics that can be published. Three decisions shape the
whole module, and they are deliberate:

**Light touch.** Study mode scans the apex and ``www`` only. It does not
enumerate subdomains through Certificate Transparency, because doing that
across three hundred councils turns a measurement exercise into a
noticeable amount of traffic against public infrastructure. A study needs
comparable data points, not exhaustive ones.

**Polite by default.** Low concurrency, a pause between subjects, and an
identifying user agent. The defaults are chosen so an unattended run
looks like a research crawler rather than something worth blocking.

**Aggregate by default.** :func:`summarise` produces distributions and
percentages. Per-organisation detail is written to a separate annex meant
for coordinated disclosure, never to the published report. Naming an
exposed organisation before telling them is how a credible study becomes
a reputational problem -- for the researcher.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import statistics
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .crypto import tlsparams as tp
from .data.cohorts import Subject
from .engine import quantum, scoring
from .model import ScanResult, ScanTarget
from .scanner import ScanOptions, Scanner, normalise_domain

ProgressFn = Callable[[int, int, "SubjectResult"], None]


@dataclass
class StudyOptions:
    """Politeness and scope settings for a cohort run."""

    workers: int = 3           # concurrent subjects; deliberately low
    delay: float = 1.0         # seconds between subject starts
    timeout: float = 8.0
    max_hosts: int = 2         # apex + www only
    probe_ciphers: bool = True
    quantum_scenario: str = "central"
    resume_path: Optional[str] = None   # JSONL checkpoint


@dataclass
class SubjectResult:
    subject: Subject
    ok: bool
    error: Optional[str] = None
    duration: float = 0.0

    # Extracted facts. Kept flat so the checkpoint file stays readable and
    # a partial run can still be summarised.
    risk_score: Optional[float] = None
    risk_grade: Optional[str] = None
    readiness_score: Optional[float] = None
    readiness_grade: Optional[str] = None
    pqc_ready: bool = False
    pqc_groups: List[str] = field(default_factory=list)
    tls_versions: List[str] = field(default_factory=list)
    has_tls13: bool = False
    forward_secrecy: bool = True
    weak_ciphers: bool = False
    deprecated_tls: bool = False
    key_algorithms: List[str] = field(default_factory=list)
    signature_algorithms: List[str] = field(default_factory=list)
    cert_lifetime_days: Optional[int] = None
    caa: bool = False
    dnssec: bool = False
    dmarc_policy: Optional[str] = None
    hsts: bool = False
    finding_ids: List[str] = field(default_factory=list)
    critical: int = 0
    high: int = 0
    mosca_at_risk: Optional[bool] = None
    intercepted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        out = {k: v for k, v in self.__dict__.items() if k != "subject"}
        out["subject"] = {
            "name": self.subject.name, "domain": self.subject.domain,
            "sector": self.subject.sector, "region": self.subject.region,
        }
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SubjectResult":
        payload = dict(data)
        s = payload.pop("subject")
        return cls(subject=Subject(s["name"], s["domain"], s.get("sector", "general"),
                                   s.get("region", "")), **payload)


def _extract(subject: Subject, scan: ScanResult, duration: float) -> SubjectResult:
    """Reduce a full scan to the fields the statistics need."""
    result = SubjectResult(subject=subject, ok=True, duration=duration)
    readiness = scan.readiness

    result.risk_score = scan.risk_score
    result.risk_grade = scan.risk_grade
    if readiness:
        result.readiness_score = readiness.score
        result.readiness_grade = readiness.grade
    if scan.mosca:
        result.mosca_at_risk = scan.mosca.at_risk

    counts = scan.counts_by_severity()
    result.critical = counts["critical"]
    result.high = counts["high"]
    result.finding_ids = sorted({f.id for f in scan.findings})

    versions, keys, sigs = set(), [], []
    fs_everywhere = True
    for endpoint in scan.endpoints:
        if not endpoint.reachable:
            continue
        if endpoint.interception_suspected:
            result.intercepted = True
        if endpoint.pqc_ready:
            result.pqc_ready = True
            result.pqc_groups = sorted(
                set(result.pqc_groups) | {tp.group_name(g) for g in endpoint.pqc_groups}
            )
        for v in endpoint.supported_versions:
            versions.add(tp.VERSION_NAMES.get(v, str(v)))

        suites = endpoint.all_cipher_suites
        for code in suites:
            suite = tp.CIPHER_SUITES.get(code)
            if not suite:
                continue
            if not suite.forward_secret:
                fs_everywhere = False
            if suite.auth == "ANON" or suite.cipher == "NULL" or suite.bits < 112 \
               or suite.cipher.startswith(("RC4", "3DES", "DES")):
                result.weak_ciphers = True

        leaf = endpoint.leaf
        if leaf:
            if leaf.public_key:
                keys.append(leaf.public_key.display)
            sigs.append(leaf.signature_algorithm)
            if leaf.lifetime_days and result.cert_lifetime_days is None:
                result.cert_lifetime_days = leaf.lifetime_days

    result.tls_versions = sorted(versions)
    result.has_tls13 = "TLS 1.3" in versions
    result.deprecated_tls = bool(versions & {"SSLv3", "TLS 1.0", "TLS 1.1"})
    result.forward_secrecy = fs_everywhere
    result.key_algorithms = sorted(set(keys))
    result.signature_algorithms = sorted(set(sigs))

    posture = scan.dns_result
    if posture is not None and posture.available:
        result.caa = bool(posture.caa_records)
        result.dnssec = posture.dnssec
        result.dmarc_policy = posture.dmarc_policy

    for http in scan.http_results:
        if http.reachable and http.header("strict-transport-security"):
            result.hsts = True

    return result


def scan_subject(subject: Subject, options: StudyOptions) -> SubjectResult:
    """Scan one organisation. Never raises: a failure is a data point."""
    started = time.time()
    domain = normalise_domain(subject.domain)
    shelf_life, _ = quantum.suggested_shelf_life(subject.sector)

    try:
        scanner = Scanner(ScanOptions(
            max_hosts=options.max_hosts,
            timeout=options.timeout,
            deep_tls=True,
            probe_ciphers=options.probe_ciphers,
            use_ct=False,          # light touch: no CT enumeration in study mode
            check_licences=False,  # not comparable across a cohort
            check_dns=True,
            workers=2,
            quantum_scenario=options.quantum_scenario,
        ))
        scan = scanner.run(ScanTarget(
            organisation=subject.name, domain=domain,
            data_shelf_life_years=shelf_life, sector=subject.sector,
        ))
        return _extract(subject, scan, time.time() - started)
    except Exception as exc:  # noqa: BLE001 - one bad subject must not end the run
        return SubjectResult(
            subject=subject, ok=False, error=f"{type(exc).__name__}: {exc}",
            duration=time.time() - started,
        )


def run_study(
    subjects: Sequence[Subject],
    options: Optional[StudyOptions] = None,
    progress: Optional[ProgressFn] = None,
) -> List[SubjectResult]:
    """Scan a cohort, checkpointing as it goes so a long run can resume."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    options = options or StudyOptions()
    done: Dict[str, SubjectResult] = {}

    if options.resume_path and os.path.exists(options.resume_path):
        with open(options.resume_path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = SubjectResult.from_dict(json.loads(line))
                    done[entry.subject.domain] = entry
                except (ValueError, KeyError, TypeError):
                    continue  # a truncated last line is expected after a kill

    pending = [s for s in subjects if s.domain not in done]
    results: List[SubjectResult] = []
    total = len(subjects)
    completed = len(done)

    handle = open(options.resume_path, "a", encoding="utf-8") if options.resume_path else None

    try:
        with ThreadPoolExecutor(max_workers=max(1, options.workers)) as pool:
            futures = {}
            for subject in pending:
                futures[pool.submit(scan_subject, subject, options)] = subject
                # Stagger submissions rather than sleeping inside the worker,
                # so the delay throttles the whole run and not each thread.
                if options.delay:
                    time.sleep(options.delay)

            for future in as_completed(futures):
                entry = future.result()
                results.append(entry)
                completed += 1
                if handle:
                    handle.write(json.dumps(entry.to_dict(), default=str) + "\n")
                    handle.flush()
                if progress:
                    progress(completed, total, entry)
    finally:
        if handle:
            handle.close()

    # Preserve the cohort's input order in the output.
    by_domain = {r.subject.domain: r for r in results}
    by_domain.update({d: r for d, r in done.items()})
    return [by_domain[s.domain] for s in subjects if s.domain in by_domain]


# --- aggregation -----------------------------------------------------------


@dataclass
class StudySummary:
    """Cohort-level statistics. Contains no organisation names by design."""

    cohort: str
    total: int
    scanned: int
    failed: int
    started_at: _dt.datetime
    finished_at: _dt.datetime

    pqc_ready: int = 0
    tls13: int = 0
    forward_secrecy: int = 0
    weak_ciphers: int = 0
    deprecated_tls: int = 0
    caa: int = 0
    dnssec: int = 0
    dmarc_enforcing: int = 0
    hsts: int = 0
    intercepted: int = 0
    mosca_exposed: int = 0

    readiness_scores: List[float] = field(default_factory=list)
    risk_scores: List[float] = field(default_factory=list)
    grades: Counter = field(default_factory=Counter)
    key_algorithms: Counter = field(default_factory=Counter)
    signature_algorithms: Counter = field(default_factory=Counter)
    pqc_groups: Counter = field(default_factory=Counter)
    findings: Counter = field(default_factory=Counter)
    cert_lifetimes: List[int] = field(default_factory=list)
    errors: Counter = field(default_factory=Counter)

    def pct(self, count: int) -> float:
        return round(100.0 * count / self.scanned, 1) if self.scanned else 0.0

    @property
    def median_readiness(self) -> float:
        return round(statistics.median(self.readiness_scores), 1) if self.readiness_scores else 0.0

    @property
    def median_risk(self) -> float:
        return round(statistics.median(self.risk_scores), 1) if self.risk_scores else 0.0

    @property
    def median_cert_lifetime(self) -> Optional[int]:
        return int(statistics.median(self.cert_lifetimes)) if self.cert_lifetimes else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cohort": self.cohort,
            "total": self.total, "scanned": self.scanned, "failed": self.failed,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "headline": {
                "pqc_ready_pct": self.pct(self.pqc_ready),
                "tls13_pct": self.pct(self.tls13),
                "forward_secrecy_pct": self.pct(self.forward_secrecy),
                "weak_ciphers_pct": self.pct(self.weak_ciphers),
                "deprecated_tls_pct": self.pct(self.deprecated_tls),
                "caa_pct": self.pct(self.caa),
                "dnssec_pct": self.pct(self.dnssec),
                "dmarc_enforcing_pct": self.pct(self.dmarc_enforcing),
                "hsts_pct": self.pct(self.hsts),
                "mosca_exposed_pct": self.pct(self.mosca_exposed),
                "median_readiness": self.median_readiness,
                "median_risk": self.median_risk,
                "median_cert_lifetime_days": self.median_cert_lifetime,
            },
            "grades": dict(self.grades),
            "key_algorithms": dict(self.key_algorithms),
            "signature_algorithms": dict(self.signature_algorithms),
            "pqc_groups": dict(self.pqc_groups),
            "top_findings": self.findings.most_common(15),
            "scan_errors": dict(self.errors),
            "note": (
                "Aggregate figures only. No organisation is identified in this "
                "summary; per-subject detail is held separately for "
                "coordinated disclosure."
            ),
        }


def summarise(
    results: Iterable[SubjectResult],
    cohort: str,
    started_at: _dt.datetime,
    finished_at: Optional[_dt.datetime] = None,
) -> StudySummary:
    """Aggregate subject results. Deliberately drops every identifier."""
    results = list(results)
    ok = [r for r in results if r.ok]

    summary = StudySummary(
        cohort=cohort,
        total=len(results),
        scanned=len(ok),
        failed=len(results) - len(ok),
        started_at=started_at,
        finished_at=finished_at or _dt.datetime.now(_dt.timezone.utc),
    )

    for r in results:
        if not r.ok:
            summary.errors[(r.error or "unknown").split(":")[0]] += 1
            continue

        summary.pqc_ready += bool(r.pqc_ready)
        summary.tls13 += bool(r.has_tls13)
        summary.forward_secrecy += bool(r.forward_secrecy)
        summary.weak_ciphers += bool(r.weak_ciphers)
        summary.deprecated_tls += bool(r.deprecated_tls)
        summary.caa += bool(r.caa)
        summary.dnssec += bool(r.dnssec)
        summary.hsts += bool(r.hsts)
        summary.intercepted += bool(r.intercepted)
        if r.dmarc_policy in ("quarantine", "reject"):
            summary.dmarc_enforcing += 1
        if r.mosca_at_risk:
            summary.mosca_exposed += 1

        if r.readiness_score is not None:
            summary.readiness_scores.append(r.readiness_score)
        if r.risk_score is not None:
            summary.risk_scores.append(r.risk_score)
        if r.readiness_grade:
            summary.grades[r.readiness_grade] += 1
        if r.cert_lifetime_days:
            summary.cert_lifetimes.append(r.cert_lifetime_days)

        for algorithm in r.key_algorithms:
            summary.key_algorithms[algorithm] += 1
        for algorithm in r.signature_algorithms:
            summary.signature_algorithms[algorithm] += 1
        for group in r.pqc_groups:
            summary.pqc_groups[group] += 1
        for finding in r.finding_ids:
            summary.findings[finding] += 1

    return summary


def disclosure_annex(results: Iterable[SubjectResult]) -> List[Dict[str, Any]]:
    """Per-organisation detail, for private coordinated disclosure only.

    Sorted worst-first so the organisations that most need telling appear
    at the top of the list you work through.
    """
    rows = []
    for r in results:
        if not r.ok:
            rows.append({"organisation": r.subject.name, "domain": r.subject.domain,
                         "status": "scan failed", "error": r.error})
            continue
        rows.append({
            "organisation": r.subject.name,
            "domain": r.subject.domain,
            "sector": r.subject.sector,
            "region": r.subject.region,
            "readiness_score": r.readiness_score,
            "readiness_grade": r.readiness_grade,
            "risk_score": r.risk_score,
            "critical": r.critical,
            "high": r.high,
            "pqc_ready": r.pqc_ready,
            "deprecated_tls": r.deprecated_tls,
            "weak_ciphers": r.weak_ciphers,
            "forward_secrecy": r.forward_secrecy,
            "findings": r.finding_ids,
        })
    rows.sort(key=lambda row: (
        -(row.get("critical") or 0), -(row.get("high") or 0),
        row.get("readiness_score") if row.get("readiness_score") is not None else 999,
    ))
    return rows
