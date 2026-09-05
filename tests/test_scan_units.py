"""Unit tests for the collector modules that do not need a live host."""

from __future__ import annotations

import pathlib
import struct
import sys

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parents[0]))

from quantumready.crypto import tlsparams as tp  # noqa: E402
from quantumready.data.licences import LICENCES, licence_for  # noqa: E402
from quantumready.scan import dns as dnsmod, discovery, http as httpmod, tls_client  # noqa: E402
from quantumready.scan.licences import (  # noqa: E402
    LicenceScan, _components_from_manifest, _version_is_below, detect_components,
)
from quantumready.scanner import normalise_domain  # noqa: E402


class TestDomainNormalisation:
    @pytest.mark.parametrize("raw,expected", [
        ("acme.co.uk", "acme.co.uk"),
        ("https://acme.co.uk", "acme.co.uk"),
        ("http://acme.co.uk/path?x=1", "acme.co.uk"),
        ("HTTPS://ACME.CO.UK/", "acme.co.uk"),
        ("  acme.co.uk  ", "acme.co.uk"),
        ("acme.co.uk.", "acme.co.uk"),
        ("acme.co.uk:8443", "acme.co.uk"),
        ("someone@acme.co.uk", "acme.co.uk"),
        ("https://www.acme.co.uk/a/b/c", "www.acme.co.uk"),
    ])
    def test_accepts_the_shapes_people_actually_paste(self, raw, expected):
        assert normalise_domain(raw) == expected

    def test_empty_input_is_empty(self):
        assert normalise_domain("") == ""
        assert normalise_domain(None) == ""


class TestClientHello:
    def test_produces_a_well_formed_record(self):
        hello = tls_client.build_client_hello(
            "example.com", cipher_suites=[0x1301, 0x1302], groups=[0x001D]
        )
        assert hello[0] == tls_client.RECORD_HANDSHAKE
        declared = struct.unpack(">H", hello[3:5])[0]
        assert declared == len(hello) - 5
        assert hello[5] == tls_client.HANDSHAKE_CLIENT_HELLO
        body_length = int.from_bytes(hello[6:9], "big")
        assert body_length == len(hello) - 9

    def test_sni_is_present_for_a_hostname(self):
        hello = tls_client.build_client_hello("example.com", cipher_suites=[0x1301])
        assert b"example.com" in hello

    def test_sni_is_omitted_for_an_ip_literal(self):
        """RFC 6066 forbids an IP literal in SNI; sending one breaks servers."""
        hello = tls_client.build_client_hello("192.0.2.1", cipher_suites=[0x1301])
        assert b"192.0.2.1" not in hello

    def test_ipv6_literal_also_omitted(self):
        hello = tls_client.build_client_hello("2001:db8::1", cipher_suites=[0x1301])
        assert b"2001:db8::1" not in hello

    def test_tls13_hello_carries_supported_versions_and_key_share(self):
        hello = tls_client.build_client_hello(
            "example.com", supported_versions=(tp.TLS_1_3,),
            cipher_suites=[0x1301], groups=[0x11EC],
        )
        assert struct.pack(">H", tls_client.EXT_SUPPORTED_VERSIONS) in hello
        assert struct.pack(">H", tls_client.EXT_KEY_SHARE) in hello

    def test_pqc_group_codepoint_is_offered(self):
        hello = tls_client.build_client_hello(
            "example.com", supported_versions=(tp.TLS_1_3,),
            cipher_suites=[0x1301], groups=[0x11EC],
        )
        assert b"\x11\xec" in hello


class TestServerHelloParsing:
    def _server_hello(self, random_bytes: bytes, cipher: int = 0x1302, extensions: bytes = b"") -> bytes:
        body = struct.pack(">H", tp.TLS_1_2) + random_bytes
        body += b"\x20" + b"\x00" * 32  # session id
        body += struct.pack(">H", cipher) + b"\x00"
        body += struct.pack(">H", len(extensions)) + extensions
        return body

    def test_parses_a_plain_server_hello(self):
        response = tls_client.parse_server_hello(self._server_hello(b"\x01" * 32))
        assert response.kind == "server_hello"
        assert response.cipher_suite == 0x1302

    def test_recognises_hello_retry_request(self):
        """The fixed random value is what distinguishes an HRR from a hello."""
        body = self._server_hello(tp.HELLO_RETRY_REQUEST_RANDOM)
        response = tls_client.parse_server_hello(body)
        assert response.kind == "hello_retry_request"

    def test_extracts_selected_group_from_key_share(self):
        key_share = struct.pack(">HH", tls_client.EXT_KEY_SHARE, 2) + struct.pack(">H", 0x11EC)
        body = self._server_hello(tp.HELLO_RETRY_REQUEST_RANDOM, extensions=key_share)
        response = tls_client.parse_server_hello(body)
        assert response.selected_group == 0x11EC

    def test_supported_versions_overrides_legacy_version(self):
        extension = struct.pack(">HH", tls_client.EXT_SUPPORTED_VERSIONS, 2)
        extension += struct.pack(">H", tp.TLS_1_3)
        body = self._server_hello(b"\x02" * 32, extensions=extension)
        response = tls_client.parse_server_hello(body)
        assert response.version == tp.TLS_1_3

    def test_truncated_input_is_reported_not_raised(self):
        assert tls_client.parse_server_hello(b"\x03\x03").kind == "error"

    def test_garbage_does_not_raise(self):
        import random

        rng = random.Random(7)
        for _ in range(400):
            data = bytes(rng.randrange(256) for _ in range(rng.randint(0, 80)))
            response = tls_client.parse_server_hello(data)
            assert response.kind in ("server_hello", "hello_retry_request", "error")


class TestDNSWireFormat:
    def test_name_encoding_round_trips(self):
        encoded = dnsmod._encode_name("www.example.com")
        assert encoded == b"\x03www\x07example\x03com\x00"
        decoded, _ = dnsmod._decode_name(encoded, 0)
        assert decoded == "www.example.com"

    def test_oversized_label_rejected(self):
        with pytest.raises(dnsmod.DNSError, match="label too long"):
            dnsmod._encode_name("a" * 64 + ".example.com")

    def test_compression_pointer_is_followed(self):
        # A 12-byte header, then "example.com" at offset 12 occupying 13
        # bytes, so the pointer to it begins at offset 25.
        name_block = b"\x07example\x03com\x00"
        message = b"\x00" * 12 + name_block + b"\xc0\x0c"
        pointer_at = 12 + len(name_block)
        name, after = dnsmod._decode_name(message, pointer_at)
        assert name == "example.com"
        assert after == pointer_at + 2

    def test_forward_pointer_rejected(self):
        """A pointer that does not go backwards can be used to build a loop."""
        message = b"\x00" * 12 + b"\xc0\x20" + b"\x00" * 20
        with pytest.raises(dnsmod.DNSError, match="forward compression pointer"):
            dnsmod._decode_name(message, 12)

    def test_self_referential_pointer_rejected(self):
        message = b"\x00" * 12 + b"\xc0\x0c"
        with pytest.raises(dnsmod.DNSError):
            dnsmod._decode_name(message, 12)

    def test_query_has_correct_header(self):
        payload = dnsmod._build_query("example.com", dnsmod.TYPE_A, False)
        _, flags, qdcount, ancount, _, arcount = struct.unpack(">HHHHHH", payload[:12])
        assert flags & 0x0100  # recursion desired
        assert qdcount == 1 and ancount == 0 and arcount == 0

    def test_edns_query_adds_opt_record(self):
        payload = dnsmod._build_query("example.com", dnsmod.TYPE_A, True)
        arcount = struct.unpack(">H", payload[10:12])[0]
        assert arcount == 1

    def test_truncation_flag_is_read(self):
        header = struct.pack(">HHHHHH", 1, 0x8200, 0, 0, 0, 0)
        assert dnsmod._parse_response(header).truncated is True

    def test_short_response_rejected(self):
        with pytest.raises(dnsmod.DNSError):
            dnsmod._parse_response(b"\x00\x01")

    def test_dmarc_policy_extraction(self):
        posture = dnsmod.DNSPosture(domain="x.test")
        posture.dmarc = "v=DMARC1; p=reject; rua=mailto:a@x.test"
        assert posture.dmarc_policy == "reject"
        posture.dmarc = "v=DMARC1; p=none"
        assert posture.dmarc_policy == "none"
        posture.dmarc = None
        assert posture.dmarc_policy is None

    def test_spf_strictness(self):
        posture = dnsmod.DNSPosture(domain="x.test")
        posture.spf = "v=spf1 include:_spf.google.com -all"
        assert posture.spf_is_strict
        posture.spf = "v=spf1 include:_spf.google.com ?all"
        assert not posture.spf_is_strict


class TestHTTPParsing:
    def test_parses_status_and_headers(self):
        raw = (
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\n"
            b"Set-Cookie: a=1; Secure\r\nSet-Cookie: b=2\r\n\r\nbody"
        )
        status, headers, cookies, body = httpmod._parse_response(raw)
        assert status == 200
        assert headers["server"] == "nginx"
        assert len(cookies) == 2
        assert body == b"body"

    def test_repeated_headers_are_joined(self):
        raw = b"HTTP/1.1 200 OK\r\nVary: A\r\nVary: B\r\n\r\n"
        _, headers, _, _ = httpmod._parse_response(raw)
        assert headers["vary"] == "A, B"

    def test_non_http_response_yields_no_status(self):
        status, _, _, _ = httpmod._parse_response(b"garbage\r\n\r\n")
        assert status is None

    def test_dechunking(self):
        body = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        assert httpmod._dechunk(body) == b"hello world"

    def test_dechunking_stops_on_malformed_size(self):
        assert httpmod._dechunk(b"zz\r\nhello\r\n") == b""

    @pytest.mark.parametrize("value,max_age,subdomains,preload,adequate", [
        ("max-age=31536000; includeSubDomains; preload", 31536000, True, True, True),
        ("max-age=31536000", 31536000, False, False, True),
        ("max-age=300", 300, False, False, False),
        ("max-age=0", 0, False, False, False),
        (None, None, False, False, False),
    ])
    def test_hsts_parsing(self, value, max_age, subdomains, preload, adequate):
        hsts = httpmod.parse_hsts(value)
        assert hsts.max_age == max_age
        assert hsts.include_subdomains is subdomains
        assert hsts.preload is preload
        assert hsts.adequate is adequate

    @pytest.mark.parametrize("cookie,secure,httponly,samesite", [
        ("id=1; Secure; HttpOnly; SameSite=Strict", True, True, "strict"),
        ("id=1; HttpOnly", False, True, None),
        ("id=1", False, False, None),
        ("id=1; secure; samesite=lax", True, False, "lax"),
    ])
    def test_cookie_flags(self, cookie, secure, httponly, samesite):
        flags = httpmod.parse_cookie_flags(cookie)
        assert flags["secure"] is secure
        assert flags["httponly"] is httponly
        assert flags["samesite"] == samesite

    def test_url_splitting(self):
        assert httpmod._split_url("https://a.test/x") == ("https", "a.test", 443, "/x")
        assert httpmod._split_url("http://a.test") == ("http", "a.test", 80, "/")
        assert httpmod._split_url("https://a.test:8443/y") == ("https", "a.test", 8443, "/y")


class TestLicenceDetection:
    @pytest.mark.parametrize("markup,name,version", [
        ('<script src="/js/jquery-3.4.1.min.js">', "jQuery", "3.4.1"),
        ('<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js">', "jQuery", "3.7.1"),
        ('<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js">', "Bootstrap", "5.3.0"),
        ('<script src="/vendor/axios@1.6.2/axios.js">', "Axios", "1.6.2"),
    ])
    def test_version_capture_across_cdn_layouts(self, markup, name, version):
        hits = {h.name: h for h in detect_components(markup, [])}
        assert name in hits
        assert hits[name].version == version

    def test_end_of_life_detection(self):
        hits = {h.name: h for h in detect_components('<script src="jquery-3.4.1.js">', [])}
        assert hits["jQuery"].end_of_life is True
        hits = {h.name: h for h in detect_components('<script src="jquery-3.7.1.js">', [])}
        assert hits["jQuery"].end_of_life is False

    def test_permanently_end_of_life_component(self):
        hits = {h.name: h for h in detect_components('<script src="/angular.min.js">', [])}
        assert hits["AngularJS"].end_of_life is True

    def test_platform_detection_without_version(self):
        hits = {h.name: h for h in detect_components('<link href="/wp-content/x.css">', [])}
        assert "WordPress" in hits
        assert hits["WordPress"].licence == "GPL-2.0"

    def test_agpl_component_is_critical_risk(self):
        scan = LicenceScan(host="x.test")
        scan.components = detect_components('<script src="https://grafana.x/app.js">', [])
        records = scan.records()
        grafana = next(r for r in records if r.component == "Grafana")
        assert grafana.licence == "AGPL-3.0"
        assert grafana.risk == "critical"
        assert "network" in grafana.obligation.lower()

    @pytest.mark.parametrize("version,threshold,expected", [
        ("3.4.1", "3.5.0", True), ("3.5.0", "3.5.0", False), ("3.7.1", "3.5.0", False),
        ("1.9", "3.5.0", True), ("10.0.0", "9.0.0", False), ("2.1", "2.1.1", True),
    ])
    def test_version_comparison(self, version, threshold, expected):
        assert _version_is_below(version, threshold) is expected

    def test_manifest_parsing_extracts_dependencies(self):
        manifest = '{"name":"app","version":"2.0.0","license":"MIT","dependencies":{"left-pad":"^1.3.0"}}'
        hits = _components_from_manifest(manifest)
        names = {h.name for h in hits}
        assert "app" in names and "left-pad" in names
        assert next(h for h in hits if h.name == "app").licence == "MIT"

    def test_malformed_manifest_yields_nothing(self):
        assert _components_from_manifest("not json") == []

    def test_licence_aliases_resolve(self):
        assert licence_for("GPLv3").spdx == "GPL-3.0"
        assert licence_for("Apache 2.0").spdx == "Apache-2.0"
        assert licence_for("AGPL-3.0-or-later").spdx == "AGPL-3.0"
        assert licence_for("mit").spdx == "MIT"
        assert licence_for("").spdx == "UNKNOWN"
        assert licence_for("Nonsense-9.9").spdx == "UNKNOWN"

    def test_every_component_licence_resolves_to_a_known_entry(self):
        """Guards against a typo in the component table."""
        from quantumready.data.licences import COMPONENTS

        for component in COMPONENTS:
            resolved = licence_for(component.licence)
            assert resolved.spdx != "UNKNOWN" or component.licence == "UNKNOWN", (
                f"{component.name} declares unresolvable licence {component.licence!r}"
            )

    def test_licence_table_categories_are_valid(self):
        valid = {"permissive", "weak-copyleft", "strong-copyleft", "proprietary", "unknown"}
        for licence in LICENCES.values():
            assert licence.category in valid
            assert licence.commercial_risk in {"low", "medium", "high", "critical"}


class TestDiscovery:
    def test_hostname_validation(self):
        assert discovery._is_hostname("www.example.com")
        assert discovery._is_hostname("a-b.example.com")
        assert not discovery._is_hostname("*.example.com")
        assert not discovery._is_hostname("bad_host.example.com")
        assert not discovery._is_hostname("")

    def test_apex_is_always_first(self):
        result = discovery.discover(
            "example.com", use_ct=False, use_guessing=False, limit=5
        )
        assert result.hosts[0] == "example.com"

    def test_limit_is_respected_and_noted(self, monkeypatch):
        many = [f"host{i}.example.com" for i in range(100)]
        monkeypatch.setattr(
            discovery, "from_certificate_transparency", lambda *a, **k: (many, None)
        )
        result = discovery.discover("example.com", use_ct=True, limit=10)
        assert len(result.hosts) == 10
        assert any("Raise --max-hosts" in note for note in result.notes)

    def test_ct_failure_falls_back_to_guessing(self, monkeypatch):
        monkeypatch.setattr(
            discovery, "from_certificate_transparency",
            lambda *a, **k: ([], "lookup failed"),
        )
        monkeypatch.setattr(discovery, "by_guessing", lambda *a, **k: ["www.example.com"])
        result = discovery.discover("example.com", use_ct=True, limit=10)
        assert "www.example.com" in result.hosts
        assert any("fell back" in note for note in result.notes)


class TestTLSParameterTables:
    def test_cipher_suite_table_is_self_consistent(self):
        for code, suite in tp.CIPHER_SUITES.items():
            assert suite.forward_secret == (suite.kex in ("ECDHE", "DHE", "TLS1.3"))
            assert suite.aead == (suite.mac == "AEAD")
            assert 0 <= suite.bits <= 256
            assert suite.name

    def test_pqc_groups_are_marked_quantum_safe(self):
        for code in tp.PQC_GROUPS:
            assert tp.NAMED_GROUPS[code].quantum_safe is True

    def test_classical_groups_are_not_quantum_safe(self):
        for code in tp.CLASSICAL_GROUPS:
            assert tp.NAMED_GROUPS[code].quantum_safe is False

    def test_x25519mlkem768_codepoint(self):
        """0x11EC is the codepoint browsers actually negotiate."""
        assert tp.NAMED_GROUPS[0x11EC].name == "X25519MLKEM768"

    def test_deprecated_versions_are_named(self):
        for version in tp.DEPRECATED_VERSIONS:
            assert version in tp.VERSION_NAMES
