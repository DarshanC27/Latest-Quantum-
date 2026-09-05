"""Report rendering, with emphasis on not trusting scanned content.

Certificate subjects, HTTP headers and component names all come from the
host being scanned. A scanner that renders them into HTML unescaped hands
whoever controls that host script execution in the browser of whoever
reads the report -- so injection is tested explicitly, not assumed.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parents[0]))

from quantumready.crypto.x509 import Certificate, PublicKeyInfo  # noqa: E402
from quantumready.engine import compliance, quantum, remediation, scoring  # noqa: E402
from quantumready.model import (  # noqa: E402
    CryptoAsset, Finding, LicenceRecord, ScanResult, ScanTarget,
)
from quantumready.report import html as html_report, serialise  # noqa: E402
from quantumready.scan.tls import TLSEndpoint  # noqa: E402

# A payload that would execute if any field were interpolated unescaped.
XSS = "<script>alert('xss')</script>"
BREAKOUT = '"><img src=x onerror=alert(1)>'


def build_result(*, hostile: bool = False) -> ScanResult:
    name = XSS if hostile else "Acme Ltd"
    host = BREAKOUT if hostile else "acme.example.com"

    target = ScanTarget(
        organisation=name, domain=host, data_shelf_life_years=15, migration_years=5
    )
    result = ScanResult(
        target=target,
        started_at=dt.datetime(2026, 8, 6, 9, 0, tzinfo=dt.timezone.utc),
        finished_at=dt.datetime(2026, 8, 6, 9, 0, 12, tzinfo=dt.timezone.utc),
    )

    certificate = Certificate(der_bytes=b"\x30\x00")
    certificate.subject = {"CN": [name]}
    certificate.issuer = {"CN": [name], "O": ["Test CA"]}
    certificate.not_before = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    certificate.not_after = dt.datetime(2026, 12, 31, tzinfo=dt.timezone.utc)
    certificate.public_key = PublicKeyInfo(
        algorithm="RSA", algorithm_oid="1.2.840.113549.1.1.1", size_bits=2048
    )
    certificate.signature_algorithm = "RSA-SHA256"
    certificate.san_dns = [host]

    endpoint = TLSEndpoint(host=host, port=443)
    endpoint.reachable = True
    endpoint.trusted = True
    endpoint.hostname_matches = True
    endpoint.chain = [certificate]
    endpoint.negotiated_version = "TLSv1.3"
    endpoint.negotiated_cipher = "TLS_AES_256_GCM_SHA384"
    endpoint.supported_versions = [0x0303, 0x0304]
    endpoint.classical_groups = [0x001D]
    endpoint.cipher_suites = {0x0304: [0x1302]}

    result.endpoints = [endpoint]
    result.discovered_hosts = [host]
    result.findings = [
        Finding(
            id="pqc.no-hybrid-key-exchange", title=f"No PQC {name}", severity="high",
            category="post-quantum", target=host, detail=name, impact=name,
            remediation=name, quantum_relevant=True,
            references=["NCSC https://www.ncsc.gov.uk/"], compliance=[name],
        ),
        Finding(
            id="http.no-hsts", title="No HSTS", severity="medium", category="http",
            target=host, detail="d", impact="i", remediation="r",
        ),
    ]
    result.crypto_assets = [
        CryptoAsset(
            name=f"RSA-2048{name if hostile else ''}", kind="signature", where=host,
            context="TLS certificate public key", classical_bits=112, quantum_bits=0,
            broken_by="Shor", replacement="ML-DSA-65",
        )
    ]
    result.licences = [
        LicenceRecord(
            component=name, version="1.0", licence="AGPL-3.0",
            category="strong-copyleft", obligation=name, risk="critical", where=host,
        )
    ]
    result.scan_notes = [name]
    result.risk_score = scoring.security_score(result.findings)
    result.risk_grade = scoring.grade_for(result.risk_score)
    result.readiness = scoring.quantum_readiness(result.endpoints)
    result.mosca = quantum.assess_mosca(15, 5, now=dt.datetime(2026, 8, 6, tzinfo=dt.timezone.utc))
    result.compliance = compliance.assess(result.findings)
    result.remediation = remediation.build_plan(result.findings)
    return result


@pytest.fixture(scope="module")
def result():
    return build_result()


@pytest.fixture(scope="module")
def hostile_result():
    return build_result(hostile=True)


class TestHTML:
    def test_renders_a_complete_document(self, result):
        page = html_report.render(result)
        assert page.startswith("<!doctype html>")
        assert page.rstrip().endswith("</html>")
        assert "<title>" in page

    def test_includes_the_main_sections(self, result):
        page = html_report.render(result)
        for section in (
            "Mosca", "Quantum readiness breakdown", "Findings",
            "Remediation plan", "Endpoints", "Cryptographic inventory",
            "licences", "Compliance position",
        ):
            assert section in page, f"missing section: {section}"

    def test_is_self_contained(self, result):
        """No external requests: the report must open on an offline machine."""
        page = html_report.render(result)
        assert "<script src=" not in page
        assert 'rel="stylesheet"' not in page
        assert "https://fonts." not in page
        assert "cdn." not in page.split("<footer>")[0].replace("cdn.example", "")

    def test_theme_aware(self, result):
        page = html_report.render(result)
        assert "prefers-color-scheme:dark" in page

    def test_wide_content_scrolls_rather_than_breaking_the_page(self, result):
        page = html_report.render(result)
        assert "overflow-x:auto" in page

    def test_no_unescaped_script_from_certificate_subject(self, hostile_result):
        page = html_report.render(hostile_result)
        assert "<script>alert" not in page
        # The payload must survive as inert text, entity-encoded.
        assert "&lt;script&gt;" in page

    def test_no_attribute_breakout_from_hostname(self, hostile_result):
        page = html_report.render(hostile_result)
        assert "<img src=x" not in page
        assert "&quot;&gt;&lt;img" in page

    def test_no_executable_tag_is_ever_constructed(self, hostile_result):
        """The decisive test: parse the output and look for real tags.

        Substring checks are easy to fool, because a payload rendered as
        inert text still contains its own characters. What matters is
        whether the browser's parser sees a tag, so we ask a parser.
        """
        from html.parser import HTMLParser

        # Never legitimate in this template, at any count. Anchors are not
        # listed: the report cites references, so <a> is expected. The risk
        # they carry is a script-bearing href, covered by js_urls below.
        forbidden = {"script", "img", "iframe", "object", "embed", "form"}
        # The report header carries one static brand mark. Its <svg> and the
        # shapes inside it are authored here, not derived from scan data, so
        # they are counted exactly rather than waved through: a second svg
        # would mean something injected one.
        BRAND_SVG = 1

        class Auditor(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forbidden = []
                self.svgs = 0
                self.event_handlers = []
                self.js_urls = []

            def handle_starttag(self, tag, attrs):
                if tag == "svg":
                    self.svgs += 1
                elif tag in forbidden:
                    self.forbidden.append(tag)
                for name, value in attrs:
                    if name.lower().startswith("on"):
                        self.event_handlers.append((tag, name))
                    if value and value.strip().lower().startswith(
                        ("javascript:", "data:text/html")
                    ):
                        self.js_urls.append((tag, name))

        auditor = Auditor()
        auditor.feed(html_report.render(hostile_result))
        assert auditor.forbidden == [], f"injected tags: {auditor.forbidden}"
        assert auditor.svgs == BRAND_SVG, (
            f"expected exactly {BRAND_SVG} authored svg, found {auditor.svgs}"
        )
        assert auditor.event_handlers == [], f"injected handlers: {auditor.event_handlers}"
        assert auditor.js_urls == [], f"script-bearing URLs: {auditor.js_urls}"

    def test_javascript_urls_are_not_emitted_as_links(self, hostile_result):
        page = html_report.render(hostile_result)
        assert 'href="javascript:' not in page.lower()


class TestJSON:
    def test_is_valid_json(self, result):
        json.loads(serialise.to_json(result))

    def test_contains_the_expected_top_level_keys(self, result):
        data = json.loads(serialise.to_json(result))
        for key in (
            "tool", "target", "summary", "mosca", "endpoints", "findings",
            "crypto_inventory", "licences", "compliance", "remediation",
        ):
            assert key in data, f"missing key: {key}"

    def test_summary_carries_both_scores(self, result):
        summary = json.loads(serialise.to_json(result))["summary"]
        assert isinstance(summary["risk_score"], (int, float))
        assert isinstance(summary["quantum_readiness_score"], (int, float))
        assert summary["risk_grade"] in "ABCDEF"

    def test_findings_are_ordered_worst_first(self, result):
        findings = json.loads(serialise.to_json(result))["findings"]
        order = ["critical", "high", "medium", "low", "info"]
        ranks = [order.index(f["severity"]) for f in findings]
        assert ranks == sorted(ranks)

    def test_hostile_content_survives_a_round_trip(self, hostile_result):
        data = json.loads(serialise.to_json(hostile_result))
        # JSON needs no escaping of HTML, but it must not corrupt the value.
        assert XSS in data["findings"][0]["detail"]


class TestCBOM:
    def test_is_valid_cyclonedx(self, result):
        cbom = json.loads(serialise.to_cbom_json(result))
        assert cbom["bomFormat"] == "CycloneDX"
        assert cbom["specVersion"] == "1.6"
        assert cbom["serialNumber"].startswith("urn:uuid:")
        assert cbom["version"] == 1

    def test_components_are_cryptographic_assets(self, result):
        cbom = json.loads(serialise.to_cbom_json(result))
        assert cbom["components"]
        for component in cbom["components"]:
            assert component["type"] == "cryptographic-asset"
            assert "bom-ref" in component
            assert "cryptoProperties" in component

    def test_algorithm_assets_carry_security_levels(self, result):
        cbom = json.loads(serialise.to_cbom_json(result))
        algorithms = [
            c for c in cbom["components"]
            if c["cryptoProperties"]["assetType"] == "algorithm"
        ]
        assert algorithms
        properties = algorithms[0]["cryptoProperties"]["algorithmProperties"]
        assert "classicalSecurityLevel" in properties
        assert "nistQuantumSecurityLevel" in properties
        assert properties["primitive"]

    def test_certificate_assets_are_included(self, result):
        cbom = json.loads(serialise.to_cbom_json(result))
        certificates = [
            c for c in cbom["components"]
            if c["cryptoProperties"]["assetType"] == "certificate"
        ]
        assert certificates
        assert "certificateProperties" in certificates[0]["cryptoProperties"]

    def test_bom_refs_are_unique(self, result):
        cbom = json.loads(serialise.to_cbom_json(result))
        refs = [c["bom-ref"] for c in cbom["components"]]
        assert len(refs) == len(set(refs))


class TestMarkdown:
    def test_renders_headings_and_tables(self, result):
        text = serialise.to_markdown(result)
        assert text.startswith("# Post-Quantum Readiness Report")
        assert "## Mosca's inequality" in text
        assert "## Findings" in text
        assert "|---|" in text

    def test_includes_scores(self, result):
        text = serialise.to_markdown(result)
        assert str(result.risk_score) in text

    def test_omits_informational_findings_from_the_detail_list(self, result):
        result.findings.append(
            Finding(id="x.info", title="Just so you know", severity="info",
                    category="tls", target="h", detail="d", impact="i", remediation="r")
        )
        text = serialise.to_markdown(result)
        assert "Just so you know" not in text
        result.findings.pop()


class TestEmptyResults:
    """A scan that found nothing must still produce every artefact."""

    def _empty(self) -> ScanResult:
        target = ScanTarget(organisation="Nobody", domain="nowhere.invalid")
        empty = ScanResult(
            target=target,
            started_at=dt.datetime(2026, 8, 6, tzinfo=dt.timezone.utc),
            finished_at=dt.datetime(2026, 8, 6, tzinfo=dt.timezone.utc),
        )
        empty.readiness = scoring.quantum_readiness([])
        empty.mosca = quantum.assess_mosca(10, 5)
        empty.compliance = compliance.assess([])
        empty.remediation = remediation.build_plan([])
        return empty

    def test_html_renders(self):
        page = html_report.render(self._empty())
        assert "No issues were identified." in page

    def test_json_renders(self):
        json.loads(serialise.to_json(self._empty()))

    def test_cbom_renders_with_no_components(self):
        cbom = json.loads(serialise.to_cbom_json(self._empty()))
        assert cbom["components"] == []

    def test_markdown_renders(self):
        assert "# Post-Quantum Readiness Report" in serialise.to_markdown(self._empty())
