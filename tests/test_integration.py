"""End-to-end tests against a local TLS server.

Everything here runs offline against loopback, so results do not depend on
the public internet, on network egress, or on somebody else's server
configuration staying the same.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import ssl
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parents[0]))
sys.path.insert(0, str(HERE))

import tlsserver  # noqa: E402

from quantumready.crypto import tlsparams as tp  # noqa: E402
from quantumready.engine import rules, scoring  # noqa: E402
from quantumready.model import ScanTarget  # noqa: E402
from quantumready.scan import tls as tlsmod, tls_client  # noqa: E402

FIXTURES = HERE / "fixtures"
TARGET = ScanTarget(organisation="Test Co", domain="scanner.test", data_shelf_life_years=15)


def pair(name: str):
    return str(FIXTURES / f"{name}.crt.pem"), str(FIXTURES / f"{name}.key.pem")


@pytest.fixture(scope="module")
def weak_server():
    """TLS 1.0-1.3, legacy ciphers, 1024-bit RSA key."""
    cert, key = pair("server-rsa1024")
    with tlsserver.running(
        cert, key, minimum_version=ssl.TLSVersion.TLSv1, ciphers="ALL:@SECLEVEL=0"
    ) as server:
        yield server


@pytest.fixture(scope="module")
def strong_server():
    """TLS 1.3 only, ECDSA P-256, modern suites."""
    cert, key = pair("server-ecdsa-p256")
    with tlsserver.running(
        cert, key, minimum_version=ssl.TLSVersion.TLSv1_3
    ) as server:
        yield server


class TestProtocolProbes:
    def test_detects_every_supported_version(self, weak_server):
        found = [
            version
            for version in (tp.SSL_3_0, tp.TLS_1_0, tp.TLS_1_1, tp.TLS_1_2, tp.TLS_1_3)
            if tls_client.probe_version("127.0.0.1", weak_server.port, version).accepted
        ]
        assert tp.TLS_1_0 in found
        assert tp.TLS_1_1 in found
        assert tp.TLS_1_2 in found
        assert tp.TLS_1_3 in found

    def test_tls13_only_server_refuses_older_versions(self, strong_server):
        for version in (tp.TLS_1_0, tp.TLS_1_1, tp.TLS_1_2):
            response = tls_client.probe_version("127.0.0.1", strong_server.port, version)
            assert not response.accepted, f"{tp.VERSION_NAMES[version]} should be refused"
        assert tls_client.probe_version("127.0.0.1", strong_server.port, tp.TLS_1_3).accepted

    def test_enumerates_groups_in_server_preference_order(self, weak_server):
        groups, note = tls_client.enumerate_groups(
            "127.0.0.1", weak_server.port, tp.CLASSICAL_GROUPS
        )
        assert note is None
        assert 0x001D in groups  # x25519
        assert 0x0017 in groups  # secp256r1

    def test_no_pqc_group_on_openssl3_server(self, weak_server):
        """OpenSSL 3.0 has no ML-KEM, so this must report absence, not error."""
        groups, note = tls_client.enumerate_groups(
            "127.0.0.1", weak_server.port, tp.PQC_GROUPS
        )
        assert groups == []
        assert note is None

    def test_enumerates_cipher_suites(self, weak_server):
        suites, note = tls_client.enumerate_cipher_suites(
            "127.0.0.1", weak_server.port, tp.TLS_1_2
        )
        assert note is None
        assert len(suites) > 3
        assert all(code in tp.CIPHER_SUITES for code in suites)

    def test_probe_on_closed_port_reports_error(self):
        response = tls_client.probe_version("127.0.0.1", 1, tp.TLS_1_2, timeout=2)
        assert response.kind == "error"
        assert response.error

    def test_probe_against_non_tls_service_does_not_hang(self):
        import socket
        import threading

        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def talk_plain_http():
            try:
                conn, _ = listener.accept()
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                conn.close()
            except OSError:
                pass

        threading.Thread(target=talk_plain_http, daemon=True).start()
        try:
            response = tls_client.probe_version("127.0.0.1", port, tp.TLS_1_2, timeout=3)
            assert response.kind == "error"
        finally:
            listener.close()


class TestEndpointScan:
    def test_weak_server_is_characterised(self, weak_server):
        endpoint = tlsmod.scan_endpoint("127.0.0.1", weak_server.port, timeout=5)
        assert endpoint.reachable
        assert endpoint.trusted is False  # self-signed
        assert endpoint.leaf is not None
        assert endpoint.leaf.public_key.algorithm == "RSA"
        assert endpoint.leaf.public_key.size_bits == 1024
        assert endpoint.pqc_ready is False

    def test_hostname_matching_uses_sans(self, weak_server):
        endpoint = tlsmod.scan_endpoint("127.0.0.1", weak_server.port, timeout=5)
        assert endpoint.leaf.matches_hostname("localhost")
        assert endpoint.leaf.matches_hostname("scanner.test")
        assert not endpoint.leaf.matches_hostname("evil.example.com")

    def test_unreachable_endpoint_is_recorded_not_raised(self):
        endpoint = tlsmod.scan_endpoint("127.0.0.1", 1, timeout=2, deep=False)
        assert endpoint.reachable is False
        assert endpoint.error


class TestRuleOutcomes:
    def _findings(self, server):
        endpoint = tlsmod.scan_endpoint("127.0.0.1", server.port, timeout=5)
        now = dt.datetime.now(dt.timezone.utc)
        return endpoint, (
            rules.certificate_findings(endpoint, now)
            + rules.tls_findings(endpoint)
            + rules.pqc_findings(endpoint, TARGET)
        )

    def test_weak_server_raises_the_expected_findings(self, weak_server):
        _, findings = self._findings(weak_server)
        ids = {f.id for f in findings}
        assert "certificate.weak-key" in ids
        assert "certificate.self-signed" in ids
        assert "tls.deprecated-version" in ids
        assert "pqc.no-hybrid-key-exchange" in ids
        assert "pqc.classical-certificate-key" in ids

    def test_weak_server_flags_missing_forward_secrecy(self, weak_server):
        _, findings = self._findings(weak_server)
        # OpenSSL at SECLEVEL=0 offers static RSA key transport, which is
        # the worst case for harvest-now-decrypt-later.
        assert "pqc.no-forward-secrecy" in {f.id for f in findings}

    def test_strong_server_has_no_critical_findings(self, strong_server):
        _, findings = self._findings(strong_server)
        criticals = [f for f in findings if f.severity == "critical"]
        assert not criticals, f"unexpected criticals: {[f.id for f in criticals]}"

    def test_strong_server_still_flags_quantum_exposure(self, strong_server):
        """A perfectly configured classical server is still not quantum-safe."""
        _, findings = self._findings(strong_server)
        ids = {f.id for f in findings}
        assert "pqc.no-hybrid-key-exchange" in ids
        assert "tls.deprecated-version" not in ids
        assert "tls.broken-ciphers" not in ids

    def test_strong_server_scores_better_than_weak(self, weak_server, strong_server):
        _, weak = self._findings(weak_server)
        _, strong = self._findings(strong_server)
        assert scoring.security_score(strong) > scoring.security_score(weak)

    def test_every_finding_is_actionable(self, weak_server):
        """A finding with no remediation is an alarm, not a finding."""
        _, findings = self._findings(weak_server)
        for finding in findings:
            assert finding.impact.strip(), f"{finding.id} has no impact text"
            assert finding.remediation.strip(), f"{finding.id} has no remediation"
            assert finding.title.strip()

    def test_readiness_reflects_missing_pqc(self, strong_server):
        endpoint = tlsmod.scan_endpoint("127.0.0.1", strong_server.port, timeout=5)
        readiness = scoring.quantum_readiness([endpoint])
        # TLS 1.3 only, so forward secrecy and version score full marks,
        # but the 40 points for hybrid key exchange are unearned.
        assert readiness.components["Hybrid post-quantum key exchange"] == 0
        assert readiness.components["Forward secrecy"] > 0
        assert readiness.score < 61


class TestCertificateFixtures:
    """Rules applied to the static certificate fixtures."""

    def _endpoint_with(self, name: str):
        from quantumready.crypto.x509 import parse_certificate

        endpoint = tlsmod.TLSEndpoint(host="fixture.test", port=443)
        endpoint.reachable = True
        endpoint.trusted = True
        endpoint.chain = [parse_certificate((FIXTURES / f"{name}.der").read_bytes())]
        endpoint.hostname_matches = True
        return endpoint

    def test_expired_certificate_is_critical(self):
        endpoint = self._endpoint_with("expired-rsa2048")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        expired = [f for f in findings if f.id == "certificate.expired"]
        assert expired and expired[0].severity == "critical"

    def test_expiring_soon_is_flagged(self):
        endpoint = self._endpoint_with("expiring-soon-rsa2048")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        assert "certificate.expiring-soon" in {f.id for f in findings}

    def test_sha1_signature_is_critical(self):
        endpoint = self._endpoint_with("rsa2048-sha1-legacy")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        broken = [f for f in findings if f.id == "certificate.broken-signature-hash"]
        assert broken and broken[0].severity == "critical"

    def test_md5_signature_is_critical(self):
        endpoint = self._endpoint_with("rsa2048-md5-legacy")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        assert "certificate.broken-signature-hash" in {f.id for f in findings}

    def test_excessive_lifetime_flagged_as_agility_problem(self):
        endpoint = self._endpoint_with("longlife-rsa2048")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        lifetime = [f for f in findings if f.id == "certificate.excessive-lifetime"]
        assert lifetime and lifetime[0].quantum_relevant

    def test_small_exponent_flagged(self):
        endpoint = self._endpoint_with("rsa-exp3")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        assert "certificate.small-rsa-exponent" in {f.id for f in findings}

    def test_healthy_certificate_produces_no_certificate_criticals(self):
        endpoint = self._endpoint_with("ecdsa-p256")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        assert not [f for f in findings if f.severity == "critical"]

    def test_ed25519_is_still_quantum_vulnerable(self):
        endpoint = self._endpoint_with("ed25519")
        findings = rules.certificate_findings(endpoint, dt.datetime(2026, 1, 15, tzinfo=dt.timezone.utc))
        pqc = [f for f in findings if f.id == "pqc.classical-certificate-key"]
        assert pqc, "Ed25519 is a modern choice but Shor's algorithm still applies"
