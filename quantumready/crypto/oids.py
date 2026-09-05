"""Object Identifier registry.

Everything the scanner needs to name what it finds inside a certificate,
without pulling in a dependency to do it. Unknown OIDs are surfaced as
dotted strings rather than swallowed -- an algorithm we cannot name is a
finding in its own right.
"""

from __future__ import annotations

# --- Public key algorithms -------------------------------------------------

PUBLIC_KEY_ALGORITHMS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.2.1": "EC",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.113549.1.3.1": "DH",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    # NIST post-quantum standards (FIPS 203 / 204 / 205)
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}

# --- Signature algorithms --------------------------------------------------
# Value is (algorithm family, hash function). A hash of None means the
# signature scheme specifies its own internal hashing (Ed25519, ML-DSA).

SIGNATURE_ALGORITHMS = {
    "1.2.840.113549.1.1.2": ("RSA", "MD2"),
    "1.2.840.113549.1.1.3": ("RSA", "MD4"),
    "1.2.840.113549.1.1.4": ("RSA", "MD5"),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512"),
    "1.2.840.113549.1.1.14": ("RSA", "SHA-224"),
    "1.2.840.113549.1.1.10": ("RSASSA-PSS", None),
    "1.2.840.10040.4.3": ("DSA", "SHA-1"),
    "2.16.840.1.101.3.4.3.1": ("DSA", "SHA-224"),
    "2.16.840.1.101.3.4.3.2": ("DSA", "SHA-256"),
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"),
    "1.2.840.10045.4.3.1": ("ECDSA", "SHA-224"),
    "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256"),
    "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512"),
    "1.3.101.112": ("Ed25519", None),
    "1.3.101.113": ("Ed448", None),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", None),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", None),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", None),
    "2.16.840.1.101.3.4.3.20": ("SLH-DSA-SHA2-128s", None),
    "2.16.840.1.101.3.4.3.21": ("SLH-DSA-SHA2-128f", None),
    "2.16.840.1.101.3.4.3.22": ("SLH-DSA-SHA2-192s", None),
    "2.16.840.1.101.3.4.3.23": ("SLH-DSA-SHA2-192f", None),
    "2.16.840.1.101.3.4.3.24": ("SLH-DSA-SHA2-256s", None),
    "2.16.840.1.101.3.4.3.25": ("SLH-DSA-SHA2-256f", None),
}

# --- Named elliptic curves -------------------------------------------------
# Value is (display name, field size in bits). Note the field size is not
# always a multiple of 8: P-521 encodes each coordinate in 66 padded bytes,
# so deriving the size from the encoded point over-reports it by 7 bits.

NAMED_CURVES = {
    "1.2.840.10045.3.1.1": ("secp192r1", 192),
    "1.3.132.0.33": ("secp224r1", 224),
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1", 256),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1", 384),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1", 512),
}

# --- Distinguished name attributes -----------------------------------------

NAME_ATTRIBUTES = {
    "2.5.4.3": "CN",
    "2.5.4.4": "SN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.15": "businessCategory",
    "2.5.4.17": "postalCode",
    "2.5.4.42": "givenName",
    "2.5.4.97": "organizationIdentifier",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
    "1.3.6.1.4.1.311.60.2.1.3": "jurisdictionC",
}

# --- Certificate extensions ------------------------------------------------

EXTENSIONS = {
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.37": "extKeyUsage",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.5.5.7.1.24": "tlsFeature",
    "1.3.6.1.4.1.11129.2.4.2": "signedCertificateTimestampList",
}

EXTENDED_KEY_USAGES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}

# KeyUsage BIT STRING positions, in order (RFC 5280 4.2.1.3).
KEY_USAGE_BITS = (
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
)

# Certificate Authority / Browser Forum policy OIDs that identify the
# validation tier a certificate was issued under.
VALIDATION_POLICIES = {
    "2.23.140.1.2.1": "Domain Validated (DV)",
    "2.23.140.1.2.2": "Organization Validated (OV)",
    "2.23.140.1.2.3": "Individual Validated (IV)",
    "2.23.140.1.1": "Extended Validation (EV)",
}


def public_key_algorithm(oid: str) -> str:
    return PUBLIC_KEY_ALGORITHMS.get(oid, f"unknown ({oid})")


def signature_algorithm(oid: str) -> str:
    """Human-readable signature algorithm, e.g. ``ECDSA-SHA256``."""
    entry = SIGNATURE_ALGORITHMS.get(oid)
    if entry is None:
        return f"unknown ({oid})"
    family, digest = entry
    return f"{family}-{digest.replace('-', '')}" if digest else family


def named_curve(oid: str) -> str:
    entry = NAMED_CURVES.get(oid)
    return entry[0] if entry else f"unknown curve ({oid})"


def curve_field_bits(oid: str) -> int:
    """Field size of a named curve, in bits. 0 if the curve is unknown."""
    entry = NAMED_CURVES.get(oid)
    return entry[1] if entry else 0


def curve_strength(oid: str) -> int:
    """Classical security level of a named curve, in bits.

    Against Pollard's rho the work factor is the square root of the group
    order, so a curve over an n-bit field offers about n/2 bits.
    """
    return curve_field_bits(oid) // 2
