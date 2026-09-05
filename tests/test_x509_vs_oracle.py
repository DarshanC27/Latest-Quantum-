"""Cross-validate the in-tree X.509 parser against pyca/cryptography.

This test is skipped when ``cryptography`` is absent, which is the normal
case for the scanner itself -- it exists to prove the zero-dependency
parser agrees with a reference implementation field by field.

    .venv/bin/python -m pytest tests/test_x509_vs_oracle.py
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from quantumready.crypto import x509 as qr_x509  # noqa: E402

cryptography = pytest.importorskip("cryptography")

from cryptography import x509 as ref_x509  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa  # noqa: E402

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
# The legacy-OID fixtures carry a substituted algorithm identifier whose
# signature body no longer matches; the reference parser rejects them by
# design, so they are covered separately in test_scanner.py.
CERT_FILES = sorted(p for p in FIXTURES.glob("*.der") if "legacy" not in p.name)


def _ids(paths):
    return [p.stem for p in paths]


@pytest.mark.parametrize("path", CERT_FILES, ids=_ids(CERT_FILES))
def test_matches_reference_parser(path: pathlib.Path) -> None:
    data = path.read_bytes()
    mine = qr_x509.parse_certificate(data)
    theirs = ref_x509.load_der_x509_certificate(data)

    assert mine.serial_number == theirs.serial_number
    assert mine.version == theirs.version.value + 1
    assert mine.fingerprint_sha256 == theirs.fingerprint(hashes.SHA256()).hex()
    assert mine.signature_algorithm_oid == theirs.signature_algorithm_oid.dotted_string
    assert mine.not_before == theirs.not_valid_before_utc
    assert mine.not_after == theirs.not_valid_after_utc
    assert not mine.warnings, f"unexpected parser warnings: {mine.warnings}"


@pytest.mark.parametrize("path", CERT_FILES, ids=_ids(CERT_FILES))
def test_names_match_reference(path: pathlib.Path) -> None:
    mine = qr_x509.parse_certificate(path.read_bytes())
    theirs = ref_x509.load_der_x509_certificate(path.read_bytes())

    ref_cn = [a.value for a in theirs.subject.get_attributes_for_oid(ref_x509.oid.NameOID.COMMON_NAME)]
    assert mine.subject.get("CN", []) == ref_cn

    ref_org = [a.value for a in theirs.issuer.get_attributes_for_oid(ref_x509.oid.NameOID.ORGANIZATION_NAME)]
    assert mine.issuer.get("O", []) == ref_org

    ref_country = [a.value for a in theirs.subject.get_attributes_for_oid(ref_x509.oid.NameOID.COUNTRY_NAME)]
    assert mine.subject.get("C", []) == ref_country


@pytest.mark.parametrize("path", CERT_FILES, ids=_ids(CERT_FILES))
def test_public_key_matches_reference(path: pathlib.Path) -> None:
    mine = qr_x509.parse_certificate(path.read_bytes())
    theirs = ref_x509.load_der_x509_certificate(path.read_bytes()).public_key()
    key = mine.public_key
    assert key is not None

    if isinstance(theirs, rsa.RSAPublicKey):
        assert key.algorithm == "RSA"
        assert key.size_bits == theirs.key_size
        assert key.rsa_exponent == theirs.public_numbers().e
    elif isinstance(theirs, ec.EllipticCurvePublicKey):
        assert key.algorithm == "EC"
        assert key.size_bits == theirs.curve.key_size
        # cryptography reports P-256 as "secp256r1"; both names are accepted.
        assert key.curve in (theirs.curve.name, {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(theirs.curve.name))
    elif isinstance(theirs, ed25519.Ed25519PublicKey):
        assert key.algorithm == "Ed25519"
        assert key.size_bits == 256
    elif isinstance(theirs, dsa.DSAPublicKey):
        assert key.algorithm == "DSA"
        assert key.size_bits == theirs.key_size
    else:  # pragma: no cover - fixture set is fixed
        pytest.fail(f"unhandled reference key type {type(theirs)}")


@pytest.mark.parametrize("path", CERT_FILES, ids=_ids(CERT_FILES))
def test_extensions_match_reference(path: pathlib.Path) -> None:
    mine = qr_x509.parse_certificate(path.read_bytes())
    theirs = ref_x509.load_der_x509_certificate(path.read_bytes())

    try:
        ref_sans = theirs.extensions.get_extension_for_class(
            ref_x509.SubjectAlternativeName
        ).value.get_values_for_type(ref_x509.DNSName)
    except ref_x509.ExtensionNotFound:
        ref_sans = []
    assert mine.san_dns == list(ref_sans)

    try:
        ref_bc = theirs.extensions.get_extension_for_class(ref_x509.BasicConstraints).value
        assert mine.is_ca == ref_bc.ca
        assert mine.path_length == ref_bc.path_length
    except ref_x509.ExtensionNotFound:
        assert mine.is_ca is False

    try:
        ref_aia = theirs.extensions.get_extension_for_class(
            ref_x509.AuthorityInformationAccess
        ).value
        ref_ocsp = [
            d.access_location.value
            for d in ref_aia
            if d.access_method == ref_x509.oid.AuthorityInformationAccessOID.OCSP
        ]
    except ref_x509.ExtensionNotFound:
        ref_ocsp = []
    assert mine.ocsp_urls == ref_ocsp


def test_key_usage_matches_reference() -> None:
    path = FIXTURES / "ca-root-rsa4096.der"
    mine = qr_x509.parse_certificate(path.read_bytes())
    theirs = ref_x509.load_der_x509_certificate(path.read_bytes())
    ref_ku = theirs.extensions.get_extension_for_class(ref_x509.KeyUsage).value

    assert ("keyCertSign" in mine.key_usage) == ref_ku.key_cert_sign
    assert ("cRLSign" in mine.key_usage) == ref_ku.crl_sign
    assert ("digitalSignature" in mine.key_usage) == ref_ku.digital_signature


def test_many_san_certificate_is_complete() -> None:
    """A 60-SAN certificate exercises multi-byte lengths in the extension."""
    mine = qr_x509.parse_certificate((FIXTURES / "many-san-ecdsa.der").read_bytes())
    assert len(mine.san_dns) == 60
    assert mine.san_dns[0] == "host0.example.com"
    assert mine.san_dns[-1] == "host59.example.com"
