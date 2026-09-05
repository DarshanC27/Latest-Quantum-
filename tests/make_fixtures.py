"""Generate the certificate fixtures used by the offline test suite.

Run with an interpreter that has ``cryptography`` installed; the scanner
itself never needs it. Fixtures are committed so tests stay dependency-free
and deterministic.

    python tests/make_fixtures.py
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = pathlib.Path(__file__).parent
FIXTURES = HERE / "fixtures"
NOW = dt.datetime(2026, 1, 15, 12, 0, 0, tzinfo=dt.timezone.utc)


def _name(common_name: str, org: str = "Quantum Ready Test Co") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Surrey"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def build(
    name: str,
    key,
    *,
    hash_alg=hashes.SHA256(),
    not_before=NOW - dt.timedelta(days=30),
    not_after=NOW + dt.timedelta(days=335),
    sans=("test.example.com", "*.test.example.com"),
    is_ca=False,
    issuer_key=None,
    issuer_name=None,
    policy_oid=None,
    add_aia=True,
):
    subject = _name(name)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name or subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=not isinstance(key, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)),
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=is_ca,
            crl_sign=is_ca,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    if not is_ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    if add_aia:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.example.com"),
                    ),
                    x509.AccessDescription(
                        x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier("http://ca.example.com/ca.crt"),
                    ),
                ]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example.com/a.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    if policy_oid:
        builder = builder.add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(x509.ObjectIdentifier(policy_oid), None)]
            ),
            critical=False,
        )

    signing_key = issuer_key or key
    if isinstance(signing_key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(signing_key, None)
    else:
        cert = builder.sign(signing_key, hash_alg)
    path = FIXTURES / f"{name}.der"
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return cert


def main() -> None:
    FIXTURES.mkdir(exist_ok=True)
    manifest = {}

    cases = {
        "rsa2048-sha256": (rsa.generate_private_key(public_exponent=65537, key_size=2048), {}),
        "rsa4096-sha384": (
            rsa.generate_private_key(public_exponent=65537, key_size=4096),
            {"hash_alg": hashes.SHA384()},
        ),
        "rsa1024-weak": (rsa.generate_private_key(public_exponent=65537, key_size=1024), {}),
        "ecdsa-p256": (ec.generate_private_key(ec.SECP256R1()), {}),
        "ecdsa-p384": (ec.generate_private_key(ec.SECP384R1()), {"hash_alg": hashes.SHA384()}),
        "ecdsa-p521": (ec.generate_private_key(ec.SECP521R1()), {"hash_alg": hashes.SHA512()}),
        "ed25519": (ed25519.Ed25519PrivateKey.generate(), {}),
        "dsa2048": (dsa.generate_private_key(key_size=2048), {}),
        "expired-rsa2048": (
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            {
                "not_before": NOW - dt.timedelta(days=800),
                "not_after": NOW - dt.timedelta(days=40),
            },
        ),
        "expiring-soon-rsa2048": (
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            {"not_after": NOW + dt.timedelta(days=12)},
        ),
        "longlife-rsa2048": (
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            {
                "not_before": NOW - dt.timedelta(days=200),
                "not_after": NOW + dt.timedelta(days=1500),
            },
        ),
        "ca-root-rsa4096": (
            rsa.generate_private_key(public_exponent=65537, key_size=4096),
            {"is_ca": True, "sans": ()},
        ),
        "ev-rsa2048": (
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            {"policy_oid": "2.23.140.1.1"},
        ),
        "dv-ecdsa-p256": (
            ec.generate_private_key(ec.SECP256R1()),
            {"policy_oid": "2.23.140.1.2.1"},
        ),
        "no-san-rsa2048": (
            rsa.generate_private_key(public_exponent=65537, key_size=2048),
            {"sans": ()},
        ),
        "many-san-ecdsa": (
            ec.generate_private_key(ec.SECP256R1()),
            {"sans": tuple(f"host{i}.example.com" for i in range(60))},
        ),
        "rsa-exp3": (
            rsa.generate_private_key(public_exponent=3, key_size=2048),
            {},
        ),
    }

    for name, (key, kwargs) in cases.items():
        cert = build(name, key, **kwargs)
        manifest[name] = {  # noqa: F841 - filled in below
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "serial": str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "signature_oid": cert.signature_algorithm_oid.dotted_string,
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }
        print(f"  wrote {name}.der")

    # Modern cryptography refuses to sign with SHA-1 or MD5, but we still
    # need those certificates to prove the scanner flags them. The RSA
    # signature OIDs differ only in their final byte and encode to the same
    # length, so a byte substitution yields a structurally valid certificate
    # that advertises the legacy algorithm. Signatures are not verified by
    # the parser, so an invalid signature body is immaterial here.
    sha256_oid = bytes.fromhex("06092A864886F70D01010B")
    for label, final_byte, source in (
        ("rsa2048-sha1-legacy", 0x05, "rsa2048-sha256"),
        ("rsa2048-md5-legacy", 0x04, "rsa2048-sha256"),
    ):
        data = (FIXTURES / f"{source}.der").read_bytes()
        if data.count(sha256_oid) != 2:
            raise SystemExit(f"expected 2 signature OIDs in {source}, cannot derive {label}")
        patched = data.replace(sha256_oid, sha256_oid[:-1] + bytes([final_byte]))
        (FIXTURES / f"{label}.der").write_bytes(patched)
        manifest[label] = {
            "derived_from": source,
            "signature_oid": f"1.2.840.113549.1.1.{final_byte}",
        }
        print(f"  wrote {label}.der (derived from {source})")

    # Serving keypairs for the local TLS server used by the end-to-end
    # tests. Written as PEM because ssl.load_cert_chain wants files.
    for label, key in (
        ("server-rsa2048", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
        ("server-ecdsa-p256", ec.generate_private_key(ec.SECP256R1())),
        ("server-rsa1024", rsa.generate_private_key(public_exponent=65537, key_size=1024)),
    ):
        cert = build(
            label,
            key,
            sans=("localhost", "127.0.0.1", "scanner.test"),
            add_aia=False,
        )
        (FIXTURES / f"{label}.crt.pem").write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        (FIXTURES / f"{label}.key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        manifest[label] = {"role": "local test server keypair"}
        print(f"  wrote {label}.crt.pem / {label}.key.pem")

    (FIXTURES / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"\n{len(manifest)} fixtures written to {FIXTURES}")


if __name__ == "__main__":
    main()
