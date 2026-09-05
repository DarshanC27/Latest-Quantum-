"""DER reader tests, weighted towards hostile input.

This parser reads bytes supplied by whatever host is being scanned, so
"rejects malformed input cleanly" matters more than "parses valid input",
which the oracle test already covers.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from quantumready.crypto import der  # noqa: E402


class TestLengths:
    def test_short_form(self):
        node = der.parse(b"\x04\x03abc")
        assert node.content == b"abc"

    def test_long_form(self):
        payload = b"x" * 300
        node = der.parse(b"\x04\x82\x01\x2c" + payload)
        assert node.content == payload

    def test_indefinite_length_rejected(self):
        # Legal in BER, forbidden in DER; guessing at it would let an
        # attacker control where parsing stops.
        with pytest.raises(der.DERError, match="indefinite"):
            der.parse(b"\x30\x80\x04\x01a\x00\x00")

    def test_length_beyond_buffer_rejected(self):
        with pytest.raises(der.DERError, match="exceeds buffer"):
            der.parse(b"\x04\x7f" + b"short")

    def test_trailing_bytes_rejected(self):
        with pytest.raises(der.DERError, match="trailing"):
            der.parse(b"\x04\x01a\xff\xff")

    def test_oversized_length_field_rejected(self):
        with pytest.raises(der.DERError, match="too large"):
            der.parse(b"\x04\x89" + b"\xff" * 9)

    def test_empty_input_rejected(self):
        with pytest.raises(der.DERError):
            der.parse(b"")


class TestNesting:
    def test_nested_sequence(self):
        inner = b"\x02\x01\x05"
        node = der.parse(b"\x30" + bytes([len(inner)]) + inner)
        assert len(node) == 1
        assert node[0].as_int() == 5

    def test_depth_limit_enforced(self):
        # Build a structure deeper than MAX_DEPTH; it must be refused
        # rather than exhausting the interpreter stack.
        data = b"\x02\x01\x01"
        for _ in range(der.MAX_DEPTH + 5):
            data = b"\x30" + bytes([len(data)]) + data
        with pytest.raises(der.DERError, match="too deep"):
            der.parse(data)

    def test_missing_element_raises_der_error(self):
        node = der.parse(b"\x30\x03\x02\x01\x07")
        with pytest.raises(der.DERError, match="at least"):
            _ = node[3]


class TestIntegers:
    @pytest.mark.parametrize("raw,expected", [
        (b"\x02\x01\x00", 0),
        (b"\x02\x01\x7f", 127),
        (b"\x02\x02\x00\x80", 128),
        (b"\x02\x01\xff", -1),
        (b"\x02\x01\x80", -128),
    ])
    def test_signed_decoding(self, raw, expected):
        assert der.parse(raw).as_int() == expected

    def test_large_serial_number(self):
        raw = b"\x02\x10" + b"\x7f" * 16
        assert der.parse(raw).as_int() == int.from_bytes(b"\x7f" * 16, "big")


class TestOIDs:
    @pytest.mark.parametrize("raw,expected", [
        (bytes.fromhex("2a864886f70d010101"), "1.2.840.113549.1.1.1"),
        (bytes.fromhex("2a8648ce3d0201"), "1.2.840.10045.2.1"),
        (bytes.fromhex("550403"), "2.5.4.3"),
        (bytes.fromhex("2b6570"), "1.3.101.112"),
        (bytes.fromhex("608648016503040201"), "2.16.840.1.101.3.4.2.1"),
    ])
    def test_known_oids(self, raw, expected):
        assert der.decode_oid(raw) == expected

    def test_first_two_arcs_share_a_byte(self):
        assert der.decode_oid(b"\x00") == "0.0"
        assert der.decode_oid(b"\x27") == "0.39"
        assert der.decode_oid(b"\x28") == "1.0"
        assert der.decode_oid(b"\x50") == "2.0"

    def test_truncated_arc_rejected(self):
        with pytest.raises(der.DERError, match="truncated"):
            der.decode_oid(b"\x2a\x86")

    def test_non_minimal_encoding_rejected(self):
        with pytest.raises(der.DERError, match="non-minimal"):
            der.decode_oid(b"\x2a\x80\x01")

    def test_empty_oid_rejected(self):
        with pytest.raises(der.DERError):
            der.decode_oid(b"")


class TestTimes:
    def test_utctime_pivots_on_50(self):
        # RFC 5280: years 50-99 are 1900s, 00-49 are 2000s.
        assert der.decode_time(der.UTC_TIME, b"491231235959Z").year == 2049
        assert der.decode_time(der.UTC_TIME, b"500101000000Z").year == 1950

    def test_generalized_time(self):
        stamp = der.decode_time(der.GENERALIZED_TIME, b"20260115120000Z")
        assert stamp == dt.datetime(2026, 1, 15, 12, 0, tzinfo=dt.timezone.utc)

    def test_timezone_offset_applied(self):
        stamp = der.decode_time(der.GENERALIZED_TIME, b"20260115120000+0200")
        assert stamp == dt.datetime(2026, 1, 15, 10, 0, tzinfo=dt.timezone.utc)

    def test_leap_second_clamped_not_crashed(self):
        # Some CAs have emitted :60 seconds; datetime rejects it, so it is
        # clamped rather than failing the whole certificate.
        stamp = der.decode_time(der.UTC_TIME, b"261231235960Z")
        assert stamp.second == 59

    def test_malformed_time_rejected(self):
        with pytest.raises(der.DERError):
            der.decode_time(der.UTC_TIME, b"nonsense")


class TestBitStrings:
    def test_unused_bits_stripped(self):
        node = der.parse(b"\x03\x03\x04\xff\xf0")
        assert node.as_bit_string() == b"\xff\xf0"

    def test_flags_respect_unused_count(self):
        # 0x05 = 0000 0101, with 4 unused bits leaves the top 4.
        node = der.parse(b"\x03\x02\x04\x50")
        assert node.bit_string_flags() == [False, True, False, True]

    def test_invalid_unused_count_rejected(self):
        with pytest.raises(der.DERError, match="unused-bit"):
            der.parse(b"\x03\x02\x09\xff").as_bit_string()


class TestPEM:
    def test_extracts_multiple_blocks(self):
        text = (
            "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\n"
            "-----BEGIN CERTIFICATE-----\nZGVm\n-----END CERTIFICATE-----\n"
        )
        assert der.pem_to_der(text) == [b"abc", b"def"]

    def test_ignores_surrounding_text(self):
        text = "notes\n-----BEGIN X-----\nYWJj\n-----END X-----\nmore notes"
        assert der.pem_to_der(text) == [b"abc"]

    def test_invalid_base64_reported(self):
        with pytest.raises(der.DERError, match="base64"):
            der.pem_to_der("-----BEGIN X-----\n!!!!\n-----END X-----")


class TestFuzzing:
    def test_random_input_never_crashes_unexpectedly(self):
        """Malformed input must raise DERError, never anything else."""
        import random

        rng = random.Random(20260806)
        for _ in range(2000):
            size = rng.randint(1, 60)
            data = bytes(rng.randrange(256) for _ in range(size))
            try:
                node = der.parse(data)
                # Touching accessors must be equally safe.
                for child in node.children[:4]:
                    _ = child.tag, len(child.content)
            except der.DERError:
                pass
            except RecursionError:  # pragma: no cover
                pytest.fail(f"recursion error on {data.hex()}")

    def test_truncated_real_certificate_is_rejected(self):
        path = pathlib.Path(__file__).parent / "fixtures" / "rsa2048-sha256.der"
        data = path.read_bytes()
        for cut in (10, 100, len(data) // 2, len(data) - 1):
            with pytest.raises(der.DERError):
                der.parse(data[:cut])
