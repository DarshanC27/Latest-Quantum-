"""Tests for the cohort study harness.

Aggregation is tested against synthesised subject results rather than a
live cohort: the statistics need to be verified against known inputs, and
a measurement tool should not generate traffic to third parties just to
test its own arithmetic.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parents[0]))

from quantumready.data import cohorts  # noqa: E402
from quantumready.report import study_html  # noqa: E402
from quantumready.study import (  # noqa: E402
    StudyOptions, SubjectResult, disclosure_annex, summarise,
)

STARTED = dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc)


def subject(i: int) -> cohorts.Subject:
    return cohorts.Subject(f"Body {i}", f"body{i}.gov.uk", "government", "South East")


def result(i, *, ok=True, pqc=False, tls13=True, fs=True, weak=False,
           deprecated=False, readiness=40.0, grade="E", risk=70.0,
           caa=False, dnssec=False, dmarc=None, hsts=False,
           findings=(), critical=0, high=0, error=None) -> SubjectResult:
    if not ok:
        return SubjectResult(subject=subject(i), ok=False, error=error or "TimeoutError: x")
    return SubjectResult(
        subject=subject(i), ok=True, readiness_score=readiness, readiness_grade=grade,
        risk_score=risk, pqc_ready=pqc, pqc_groups=["X25519MLKEM768"] if pqc else [],
        has_tls13=tls13, forward_secrecy=fs, weak_ciphers=weak, deprecated_tls=deprecated,
        key_algorithms=["RSA 2048-bit"], signature_algorithms=["RSA-SHA256"],
        cert_lifetime_days=90, caa=caa, dnssec=dnssec, dmarc_policy=dmarc, hsts=hsts,
        finding_ids=list(findings), critical=critical, high=high, mosca_at_risk=not pqc,
    )


@pytest.fixture
def cohort():
    """Ten subjects: 3 PQC-ready, 2 with deprecated TLS, 1 failed."""
    return [
        result(1, pqc=True, readiness=95, grade="A", caa=True, dnssec=True, dmarc="reject", hsts=True),
        result(2, pqc=True, readiness=88, grade="B", caa=True, hsts=True),
        result(3, pqc=True, readiness=82, grade="B", caa=True, dmarc="quarantine"),
        result(4, readiness=55, grade="D", findings=["pqc.no-hybrid-key-exchange"]),
        result(5, readiness=48, grade="E", findings=["pqc.no-hybrid-key-exchange", "http.no-hsts"]),
        result(6, readiness=44, grade="E", deprecated=True,
               findings=["pqc.no-hybrid-key-exchange", "tls.deprecated-version"]),
        result(7, readiness=30, grade="F", deprecated=True, weak=True, critical=1,
               findings=["pqc.no-hybrid-key-exchange", "tls.broken-ciphers"]),
        result(8, readiness=25, grade="F", fs=False, critical=2, high=3,
               findings=["pqc.no-forward-secrecy"]),
        result(9, readiness=60, grade="D", findings=["pqc.no-hybrid-key-exchange"]),
        result(10, ok=False, error="TimeoutError: connection timed out"),
    ]


class TestSummary:
    def test_counts_scanned_and_failed(self, cohort):
        s = summarise(cohort, "Test cohort", STARTED)
        assert s.total == 10
        assert s.scanned == 9
        assert s.failed == 1

    def test_percentages_use_scanned_not_total(self, cohort):
        """A subject that could not be reached must not count as a failure
        of the control being measured."""
        s = summarise(cohort, "Test cohort", STARTED)
        assert s.pqc_ready == 3
        assert s.pct(s.pqc_ready) == pytest.approx(33.3, abs=0.1)  # 3/9, not 3/10

    def test_zero_scanned_does_not_divide_by_zero(self):
        s = summarise([result(1, ok=False)], "Empty", STARTED)
        assert s.scanned == 0
        assert s.pct(s.pqc_ready) == 0.0

    def test_dmarc_only_counts_enforcing_policies(self, cohort):
        s = summarise(cohort, "Test cohort", STARTED)
        # p=reject and p=quarantine count; p=none and absent do not.
        assert s.dmarc_enforcing == 2

    def test_medians(self, cohort):
        s = summarise(cohort, "Test cohort", STARTED)
        assert s.median_readiness == 55.0
        assert s.median_cert_lifetime == 90

    def test_grade_distribution(self, cohort):
        s = summarise(cohort, "Test cohort", STARTED)
        assert s.grades["A"] == 1
        assert s.grades["F"] == 2
        assert sum(s.grades.values()) == 9

    def test_findings_ranked_by_frequency(self, cohort):
        s = summarise(cohort, "Test cohort", STARTED)
        top = s.findings.most_common(1)[0]
        assert top[0] == "pqc.no-hybrid-key-exchange"
        assert top[1] == 5

    def test_errors_are_grouped_by_type(self, cohort):
        s = summarise(cohort, "Test cohort", STARTED)
        assert s.errors["TimeoutError"] == 1

    def test_summary_contains_no_organisation_names(self, cohort):
        """The published artefact must not identify anyone."""
        s = summarise(cohort, "Test cohort", STARTED)
        blob = json.dumps(s.to_dict())
        for i in range(1, 11):
            assert f"body{i}.gov.uk" not in blob
            assert f"Body {i}" not in blob


class TestDisclosureAnnex:
    def test_annex_does_identify_organisations(self, cohort):
        """The annex is the opposite artefact: it exists to name them."""
        rows = disclosure_annex(cohort)
        assert any(r["domain"] == "body1.gov.uk" for r in rows)

    def test_sorted_worst_first(self, cohort):
        rows = disclosure_annex(cohort)
        criticals = [r.get("critical") or 0 for r in rows if r.get("status") != "scan failed"]
        assert criticals == sorted(criticals, reverse=True)

    def test_failed_subjects_are_retained(self, cohort):
        rows = disclosure_annex(cohort)
        assert any(r.get("status") == "scan failed" for r in rows)


class TestReport:
    def test_renders_complete_document(self, cohort):
        html = study_html.render(summarise(cohort, "UK bodies", STARTED))
        assert html.startswith("<!doctype html>")
        assert html.rstrip().endswith("</html>")

    def test_report_names_nobody(self, cohort):
        html = study_html.render(summarise(cohort, "UK bodies", STARTED))
        for i in range(1, 11):
            assert f"body{i}.gov.uk" not in html
            assert f"Body {i}" not in html

    def test_report_states_the_aggregate_policy(self, cohort):
        html = study_html.render(summarise(cohort, "UK bodies", STARTED))
        assert "Aggregate figures only" in html
        assert "coordinated" in html.lower() or "private disclosure" in html.lower()

    def test_charts_are_inline_svg(self, cohort):
        html = study_html.render(summarise(cohort, "UK bodies", STARTED))
        assert "<svg" in html
        assert "<script" not in html          # no charting library, no scripts at all
        assert "cdn." not in html

    def test_empty_cohort_still_renders(self):
        html = study_html.render(summarise([], "Nobody", STARTED))
        assert "<!doctype html>" in html

    def test_headline_percentage_appears(self, cohort):
        s = summarise(cohort, "UK bodies", STARTED)
        html = study_html.render(s)
        assert f"{s.pct(s.pqc_ready)}%" in html


class TestCohorts:
    def test_presets_are_present_and_shaped(self):
        for name, group in cohorts.COHORTS.items():
            assert group, f"{name} is empty"
            assert name in cohorts.COHORT_LABELS
            for s in group:
                assert "." in s.domain
                assert not s.domain.startswith("http")
                assert s.name

    def test_domains_are_unique_within_a_cohort(self):
        for name, group in cohorts.COHORTS.items():
            domains = [s.domain for s in group]
            assert len(domains) == len(set(domains)), f"duplicate domain in {name}"

    def test_csv_loading_with_header(self, tmp_path):
        path = tmp_path / "t.csv"
        path.write_text("name,domain,sector\nAcme,acme.co.uk,finance\n", encoding="utf-8")
        subjects = cohorts.load_csv(str(path))
        assert subjects == [cohorts.Subject("Acme", "acme.co.uk", "finance", "")]

    def test_csv_loading_without_header(self, tmp_path):
        path = tmp_path / "t.csv"
        path.write_text("Acme,acme.co.uk\nBeta,beta.co.uk\n", encoding="utf-8")
        subjects = cohorts.load_csv(str(path))
        assert len(subjects) == 2
        assert subjects[1].domain == "beta.co.uk"

    def test_csv_single_column(self, tmp_path):
        path = tmp_path / "t.csv"
        path.write_text("acme.co.uk\nbeta.co.uk\n", encoding="utf-8")
        subjects = cohorts.load_csv(str(path))
        assert [s.domain for s in subjects] == ["acme.co.uk", "beta.co.uk"]


class TestPoliteDefaults:
    def test_defaults_are_light_touch(self):
        """These defaults are the difference between research and a nuisance."""
        o = StudyOptions()
        assert o.workers <= 3
        assert o.delay >= 1.0
        assert o.max_hosts <= 2   # apex + www, no subdomain enumeration


class TestCheckpoint:
    def test_result_round_trips_through_json(self, cohort):
        original = cohort[0]
        restored = SubjectResult.from_dict(json.loads(json.dumps(original.to_dict())))
        assert restored.subject == original.subject
        assert restored.readiness_score == original.readiness_score
        assert restored.finding_ids == original.finding_ids
