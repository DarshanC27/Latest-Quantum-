"""Tests for the analysis engine: quantum classification, Mosca, scoring."""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from quantumready.engine import compliance, quantum, remediation, scoring  # noqa: E402
from quantumready.model import Finding  # noqa: E402

NOW = dt.datetime(2026, 8, 6, tzinfo=dt.timezone.utc)


def finding(fid="tls.deprecated-version", severity="high", target="a.example.com",
            category="tls", quantum_relevant=False) -> Finding:
    return Finding(
        id=fid, title=fid, severity=severity, category=category, target=target,
        detail="d", impact="i", remediation="r", quantum_relevant=quantum_relevant,
    )


class TestPublicKeyAssessment:
    @pytest.mark.parametrize("bits,expected", [
        (1024, 80), (2048, 112), (3072, 128), (7680, 192), (15360, 256),
    ])
    def test_rsa_matches_nist_table(self, bits, expected):
        assert quantum.rsa_classical_bits(bits) == expected

    def test_rsa_interpolates_between_table_entries(self):
        # 4096 sits between the 3072 and 7680 rows.
        strength = quantum.rsa_classical_bits(4096)
        assert 128 < strength < 192

    def test_rsa_below_1024_scales_down(self):
        assert quantum.rsa_classical_bits(512) < 80

    @pytest.mark.parametrize("algorithm,bits,curve", [
        ("RSA", 2048, None), ("RSA", 4096, None), ("EC", 256, "P-256"),
        ("EC", 521, "P-521"), ("Ed25519", 256, None), ("X25519", 256, None),
        ("DSA", 2048, None),
    ])
    def test_every_classical_algorithm_is_zero_against_shor(self, algorithm, bits, curve):
        result = quantum.assess_public_key(algorithm, bits, curve)
        assert result.quantum_bits == 0
        assert result.quantum_safe is False
        assert result.broken_by == "Shor"
        assert result.replacement

    def test_larger_rsa_does_not_help_against_quantum(self):
        """The point that most surprises people: key size is irrelevant to Shor."""
        small = quantum.assess_public_key("RSA", 2048)
        large = quantum.assess_public_key("RSA", 15360)
        assert large.classical_bits > small.classical_bits
        assert large.quantum_bits == small.quantum_bits == 0

    def test_ml_kem_is_quantum_safe(self):
        result = quantum.assess_public_key("ML-KEM-768", 1184)
        assert result.quantum_safe is True
        assert result.broken_by is None

    def test_ml_dsa_is_quantum_safe(self):
        assert quantum.assess_public_key("ML-DSA-65", 1952).quantum_safe is True


class TestSymmetricAssessment:
    @pytest.mark.parametrize("bits,safe", [(128, False), (192, False), (256, True)])
    def test_grover_halves_strength(self, bits, safe):
        result = quantum.assess_symmetric("AES", bits)
        assert result.quantum_bits == bits // 2
        assert result.quantum_safe is safe

    def test_aes256_survives_but_aes128_does_not(self):
        assert quantum.assess_symmetric("AES-256-GCM", 256).quantum_safe
        assert not quantum.assess_symmetric("AES-128-GCM", 128).quantum_safe

    def test_null_cipher_has_no_security(self):
        assert quantum.assess_symmetric("NULL", 0).classical_bits == 0


class TestHashAssessment:
    @pytest.mark.parametrize("name", ["MD5", "SHA-1"])
    def test_broken_hashes_need_no_quantum_computer(self, name):
        result = quantum.assess_hash(name)
        assert result.quantum_safe is False
        assert result.broken_by is None  # already broken classically
        assert "classically" in result.rationale

    def test_sha256_survives_grover(self):
        assert quantum.assess_hash("SHA-256").quantum_safe is True


class TestMosca:
    def test_exposed_when_sum_exceeds_horizon(self):
        result = quantum.assess_mosca(25, 5, quantum_year=2035, now=NOW)
        assert result.at_risk is True
        assert result.verdict == "EXPOSED"
        assert result.exposure_years > 0
        assert ">" in result.formula

    def test_within_tolerance_when_sum_fits(self):
        result = quantum.assess_mosca(2, 2, quantum_year=2050, now=NOW)
        assert result.at_risk is False
        assert result.verdict == "WITHIN TOLERANCE"
        assert result.exposure_years < 0

    def test_boundary_is_not_at_risk(self):
        """X + Y exactly equal to Z is tolerable, not exposed."""
        start = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
        result = quantum.assess_mosca(5, 5, quantum_year=2036, now=start)
        assert result.at_risk is False

    def test_past_deadline_is_described_as_overdue(self):
        result = quantum.assess_mosca(30, 5, quantum_year=2035, now=NOW)
        assert result.deadline_year < NOW.year
        assert "overdue" in result.explanation

    def test_future_deadline_is_described_as_upcoming(self):
        # At risk (9 > 8.4) but the latest safe start date has not yet passed.
        result = quantum.assess_mosca(7, 2, quantum_year=2035, now=NOW)
        assert result.at_risk is True
        assert result.deadline_year >= NOW.year
        assert "must begin by" in result.explanation
        assert "overdue" not in result.explanation

    def test_scenario_changes_the_horizon(self):
        conservative = quantum.assess_mosca(10, 5, scenario="conservative", now=NOW)
        optimistic = quantum.assess_mosca(10, 5, scenario="optimistic", now=NOW)
        assert conservative.quantum_year < optimistic.quantum_year
        assert conservative.years_to_quantum < optimistic.years_to_quantum

    def test_explicit_year_overrides_scenario(self):
        result = quantum.assess_mosca(10, 5, scenario="optimistic", quantum_year=2029, now=NOW)
        assert result.quantum_year == 2029

    def test_assumptions_are_always_stated(self):
        result = quantum.assess_mosca(10, 5, now=NOW)
        assert len(result.assumptions) >= 3

    def test_sector_defaults_are_sane(self):
        for sector in quantum.SECTOR_SHELF_LIFE:
            years, reason = quantum.suggested_shelf_life(sector)
            assert 1 <= years <= 50
            assert reason

    def test_unknown_sector_falls_back(self):
        assert quantum.suggested_shelf_life("zzz") == quantum.SECTOR_SHELF_LIFE["general"]


class TestScoring:
    def test_clean_scan_scores_full_marks(self):
        assert scoring.security_score([]) == 100.0

    def test_critical_costs_more_than_high(self):
        critical = scoring.security_score([finding(severity="critical")])
        high = scoring.security_score([finding(severity="high")])
        assert critical < high < 100.0

    def test_info_findings_are_free(self):
        assert scoring.security_score([finding(fid="x.y", severity="info")]) == 100.0

    def test_score_never_goes_negative(self):
        many = [finding(fid=f"id.{i}", severity="critical") for i in range(20)]
        assert scoring.security_score(many) == 0.0

    def test_repeats_of_one_issue_are_damped(self):
        """Forty hosts with one misconfiguration is one mistake, not forty."""
        one = scoring.security_score([finding(target="a")])
        forty = scoring.security_score([
            finding(target=f"host{i}.example.com") for i in range(40)
        ])
        assert forty < one
        # Damped to at most double the single-host deduction.
        assert (100 - forty) <= (100 - one) * 2 + 0.01

    def test_distinct_issues_accumulate_faster_than_repeats(self):
        repeats = scoring.security_score([finding(target=f"h{i}") for i in range(4)])
        distinct = scoring.security_score([finding(fid=f"cat.{i}") for i in range(4)])
        assert distinct < repeats

    @pytest.mark.parametrize("score,grade", [
        (100, "A"), (90, "A"), (89.9, "B"), (80, "B"), (70, "C"),
        (50, "D"), (40, "E"), (10, "F"), (0, "F"),
    ])
    def test_grade_bands(self, score, grade):
        assert scoring.grade_for(score) == grade


class TestCompliance:
    def test_clean_scan_passes_everything(self):
        frameworks = compliance.assess([])
        assert all(f.status == "pass" for f in frameworks)

    def test_high_severity_fails_a_control(self):
        frameworks = compliance.assess([finding(fid="pqc.no-hybrid-key-exchange", severity="high")])
        ncsc = next(f for f in frameworks if f.key == "ncsc-pqc")
        assert ncsc.status == "fail"
        assert ncsc.failed_controls

    def test_medium_severity_only_flags_attention(self):
        frameworks = compliance.assess([
            finding(fid="governance.cryptographic-inventory", severity="medium",
                    category="governance")
        ])
        ncsc = next(f for f in frameworks if f.key == "ncsc-pqc")
        assert ncsc.status == "attention"

    def test_evidence_is_attached_to_failed_controls(self):
        frameworks = compliance.assess([finding(fid="tls.broken-ciphers", severity="critical")])
        pci = next(f for f in frameworks if f.key == "pci-dss-4")
        failed = pci.failed_controls
        assert failed and failed[0].evidence

    def test_every_referenced_finding_id_is_real(self):
        """Guards against a control that can never trigger due to a typo."""
        from quantumready.engine import rules

        known = set()
        import inspect
        source = inspect.getsource(rules)
        import re
        known.update(re.findall(r'id="([a-z0-9\.\-]+)"', source))

        for framework in compliance.assess([]):
            for control in framework.controls:
                for fid in control.triggered_by:
                    assert fid in known, f"{framework.key}/{control.reference} references unknown finding id {fid!r}"


class TestRemediation:
    def test_plan_is_ordered_by_severity_then_effort(self):
        plan = remediation.build_plan([
            finding(fid="pqc.classical-certificate-key", severity="high", category="post-quantum"),
            finding(fid="pqc.no-forward-secrecy", severity="critical", category="post-quantum"),
            finding(fid="http.no-hsts", severity="high", category="http"),
        ])
        assert plan[0].title.startswith("Disable static RSA")
        # Among the two highs, the one measured in hours comes first.
        efforts = [a.effort for a in plan[1:]]
        assert efforts.index("hours") < efforts.index("months")

    def test_duplicate_findings_yield_one_action(self):
        plan = remediation.build_plan([
            finding(fid="http.no-hsts", severity="high", category="http", target=f"h{i}")
            for i in range(5)
        ])
        assert len(plan) == 1
        assert "5 host(s)" in plan[0].addresses[0]

    def test_priorities_are_sequential(self):
        plan = remediation.build_plan([
            finding(fid="http.no-hsts", severity="high", category="http"),
            finding(fid="http.no-csp", severity="medium", category="http"),
            finding(fid="dns.no-caa", severity="medium", category="dns"),
        ])
        assert [a.priority for a in plan] == list(range(1, len(plan) + 1))

    def test_unmapped_finding_produces_no_action(self):
        assert remediation.build_plan([finding(fid="totally.unknown")]) == []

    def test_tools_referenced_by_actions_exist_in_catalogue(self):
        names = {
            tool.name
            for tools in remediation.PQC_TOOLING.values()
            for tool in tools
        }
        for template in remediation._TEMPLATES.values():
            for tool in template.get("tools", []):
                assert tool in names, f"unknown tool referenced: {tool!r}"

    def test_tools_for_returns_only_what_the_plan_needs(self):
        plan = remediation.build_plan([
            finding(fid="pqc.no-hybrid-key-exchange", severity="high", category="post-quantum")
        ])
        tools = remediation.tools_for(plan)
        assert tools
        assert all(t.url.startswith("http") for t in tools)
