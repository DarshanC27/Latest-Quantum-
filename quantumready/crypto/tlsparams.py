"""TLS wire constants, with the risk properties the engine scores on.

Cipher suites are described structurally (key exchange, authentication,
encryption, MAC) rather than by a hand-assigned grade, so the risk engine
can reason about *why* a suite is weak instead of restating a verdict.
"""

from __future__ import annotations

from typing import Dict, NamedTuple, Optional

# --- Protocol versions -----------------------------------------------------

SSL_3_0 = 0x0300
TLS_1_0 = 0x0301
TLS_1_1 = 0x0302
TLS_1_2 = 0x0303
TLS_1_3 = 0x0304

VERSION_NAMES = {
    SSL_3_0: "SSLv3",
    TLS_1_0: "TLS 1.0",
    TLS_1_1: "TLS 1.1",
    TLS_1_2: "TLS 1.2",
    TLS_1_3: "TLS 1.3",
}

# Versions that must not be accepted by a current service. SSLv3 fell to
# POODLE; TLS 1.0/1.1 were deprecated by RFC 8996 and are disallowed by
# PCI DSS and every major browser.
DEPRECATED_VERSIONS = (SSL_3_0, TLS_1_0, TLS_1_1)


class CipherSuite(NamedTuple):
    name: str
    kex: str  # key exchange: ECDHE, DHE, RSA, PSK, NULL, ANON, TLS1.3
    auth: str  # authentication: RSA, ECDSA, NULL, ANON
    cipher: str  # AES-128-GCM, 3DES-CBC, RC4, NULL, ...
    bits: int  # symmetric key size
    mac: str  # AEAD, SHA256, SHA1, MD5, NULL
    forward_secret: bool
    aead: bool


def _s(name, kex, auth, cipher, bits, mac):
    return CipherSuite(
        name=name,
        kex=kex,
        auth=auth,
        cipher=cipher,
        bits=bits,
        mac=mac,
        forward_secret=kex in ("ECDHE", "DHE", "TLS1.3"),
        aead=mac == "AEAD",
    )


CIPHER_SUITES: Dict[int, CipherSuite] = {
    # TLS 1.3 -- key exchange is negotiated separately, so the suite only
    # names the AEAD and the hash.
    0x1301: _s("TLS_AES_128_GCM_SHA256", "TLS1.3", "any", "AES-128-GCM", 128, "AEAD"),
    0x1302: _s("TLS_AES_256_GCM_SHA384", "TLS1.3", "any", "AES-256-GCM", 256, "AEAD"),
    0x1303: _s("TLS_CHACHA20_POLY1305_SHA256", "TLS1.3", "any", "ChaCha20-Poly1305", 256, "AEAD"),
    0x1304: _s("TLS_AES_128_CCM_SHA256", "TLS1.3", "any", "AES-128-CCM", 128, "AEAD"),
    0x1305: _s("TLS_AES_128_CCM_8_SHA256", "TLS1.3", "any", "AES-128-CCM-8", 128, "AEAD"),
    # TLS 1.2 ECDHE + AEAD -- the modern, healthy set.
    0xC02B: _s("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE", "ECDSA", "AES-128-GCM", 128, "AEAD"),
    0xC02C: _s("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE", "ECDSA", "AES-256-GCM", 256, "AEAD"),
    0xC02F: _s("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "RSA", "AES-128-GCM", 128, "AEAD"),
    0xC030: _s("ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", "RSA", "AES-256-GCM", 256, "AEAD"),
    0xCCA8: _s("ECDHE-RSA-CHACHA20-POLY1305", "ECDHE", "RSA", "ChaCha20-Poly1305", 256, "AEAD"),
    0xCCA9: _s("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE", "ECDSA", "ChaCha20-Poly1305", 256, "AEAD"),
    0xCCAA: _s("DHE-RSA-CHACHA20-POLY1305", "DHE", "RSA", "ChaCha20-Poly1305", 256, "AEAD"),
    0x009E: _s("DHE-RSA-AES128-GCM-SHA256", "DHE", "RSA", "AES-128-GCM", 128, "AEAD"),
    0x009F: _s("DHE-RSA-AES256-GCM-SHA384", "DHE", "RSA", "AES-256-GCM", 256, "AEAD"),
    # ECDHE with CBC -- forward secret, but CBC-mode in TLS carries the
    # Lucky13 family of padding-oracle problems.
    0xC023: _s("ECDHE-ECDSA-AES128-SHA256", "ECDHE", "ECDSA", "AES-128-CBC", 128, "SHA256"),
    0xC024: _s("ECDHE-ECDSA-AES256-SHA384", "ECDHE", "ECDSA", "AES-256-CBC", 256, "SHA384"),
    0xC027: _s("ECDHE-RSA-AES128-SHA256", "ECDHE", "RSA", "AES-128-CBC", 128, "SHA256"),
    0xC028: _s("ECDHE-RSA-AES256-SHA384", "ECDHE", "RSA", "AES-256-CBC", 256, "SHA384"),
    0xC009: _s("ECDHE-ECDSA-AES128-SHA", "ECDHE", "ECDSA", "AES-128-CBC", 128, "SHA1"),
    0xC00A: _s("ECDHE-ECDSA-AES256-SHA", "ECDHE", "ECDSA", "AES-256-CBC", 256, "SHA1"),
    0xC013: _s("ECDHE-RSA-AES128-SHA", "ECDHE", "RSA", "AES-128-CBC", 128, "SHA1"),
    0xC014: _s("ECDHE-RSA-AES256-SHA", "ECDHE", "RSA", "AES-256-CBC", 256, "SHA1"),
    0xC012: _s("ECDHE-RSA-DES-CBC3-SHA", "ECDHE", "RSA", "3DES-CBC", 112, "SHA1"),
    # DHE with CBC.
    0x0033: _s("DHE-RSA-AES128-SHA", "DHE", "RSA", "AES-128-CBC", 128, "SHA1"),
    0x0039: _s("DHE-RSA-AES256-SHA", "DHE", "RSA", "AES-256-CBC", 256, "SHA1"),
    0x0067: _s("DHE-RSA-AES128-SHA256", "DHE", "RSA", "AES-128-CBC", 128, "SHA256"),
    0x006B: _s("DHE-RSA-AES256-SHA256", "DHE", "RSA", "AES-256-CBC", 256, "SHA256"),
    0x0016: _s("DHE-RSA-DES-CBC3-SHA", "DHE", "RSA", "3DES-CBC", 112, "SHA1"),
    # Static RSA key transport -- no forward secrecy, so a future break of
    # the server key retroactively decrypts every recorded session. This is
    # the single most damaging pattern for harvest-now-decrypt-later.
    0x009C: _s("AES128-GCM-SHA256", "RSA", "RSA", "AES-128-GCM", 128, "AEAD"),
    0x009D: _s("AES256-GCM-SHA384", "RSA", "RSA", "AES-256-GCM", 256, "AEAD"),
    0x003C: _s("AES128-SHA256", "RSA", "RSA", "AES-128-CBC", 128, "SHA256"),
    0x003D: _s("AES256-SHA256", "RSA", "RSA", "AES-256-CBC", 256, "SHA256"),
    0x002F: _s("AES128-SHA", "RSA", "RSA", "AES-128-CBC", 128, "SHA1"),
    0x0035: _s("AES256-SHA", "RSA", "RSA", "AES-256-CBC", 256, "SHA1"),
    0x000A: _s("DES-CBC3-SHA", "RSA", "RSA", "3DES-CBC", 112, "SHA1"),
    0x0041: _s("CAMELLIA128-SHA", "RSA", "RSA", "Camellia-128-CBC", 128, "SHA1"),
    0x0084: _s("CAMELLIA256-SHA", "RSA", "RSA", "Camellia-256-CBC", 256, "SHA1"),
    0x0096: _s("SEED-SHA", "RSA", "RSA", "SEED-CBC", 128, "SHA1"),
    # Broken stream ciphers and hashes.
    0x0005: _s("RC4-SHA", "RSA", "RSA", "RC4-128", 128, "SHA1"),
    0x0004: _s("RC4-MD5", "RSA", "RSA", "RC4-128", 128, "MD5"),
    0xC011: _s("ECDHE-RSA-RC4-SHA", "ECDHE", "RSA", "RC4-128", 128, "SHA1"),
    0xC007: _s("ECDHE-ECDSA-RC4-SHA", "ECDHE", "ECDSA", "RC4-128", 128, "SHA1"),
    0x0009: _s("DES-CBC-SHA", "RSA", "RSA", "DES-CBC", 56, "SHA1"),
    0x0015: _s("EDH-RSA-DES-CBC-SHA", "DHE", "RSA", "DES-CBC", 56, "SHA1"),
    # Export-grade -- deliberately crippled in the 1990s, the root of
    # FREAK and Logjam. Any appearance here is critical.
    0x0003: _s("EXP-RC4-MD5", "RSA", "RSA", "RC4-40", 40, "MD5"),
    0x0006: _s("EXP-RC2-CBC-MD5", "RSA", "RSA", "RC2-40-CBC", 40, "MD5"),
    0x0008: _s("EXP-DES-CBC-SHA", "RSA", "RSA", "DES-40-CBC", 40, "SHA1"),
    0x0014: _s("EXP-EDH-RSA-DES-CBC-SHA", "DHE", "RSA", "DES-40-CBC", 40, "SHA1"),
    0x0011: _s("EXP-EDH-DSS-DES-CBC-SHA", "DHE", "DSS", "DES-40-CBC", 40, "SHA1"),
    # Anonymous -- no server authentication at all, trivially MITM'd.
    0x0018: _s("ADH-RC4-MD5", "DH", "ANON", "RC4-128", 128, "MD5"),
    0x001B: _s("ADH-DES-CBC3-SHA", "DH", "ANON", "3DES-CBC", 112, "SHA1"),
    0x0034: _s("ADH-AES128-SHA", "DH", "ANON", "AES-128-CBC", 128, "SHA1"),
    0x006C: _s("ADH-AES128-SHA256", "DH", "ANON", "AES-128-CBC", 128, "SHA256"),
    0xC016: _s("AECDH-RC4-SHA", "ECDH", "ANON", "RC4-128", 128, "SHA1"),
    0xC018: _s("AECDH-AES128-SHA", "ECDH", "ANON", "AES-128-CBC", 128, "SHA1"),
    # No encryption whatsoever.
    0x0001: _s("NULL-MD5", "RSA", "RSA", "NULL", 0, "MD5"),
    0x0002: _s("NULL-SHA", "RSA", "RSA", "NULL", 0, "SHA1"),
    0x003B: _s("NULL-SHA256", "RSA", "RSA", "NULL", 0, "SHA256"),
    0xC010: _s("ECDHE-RSA-NULL-SHA", "ECDHE", "RSA", "NULL", 0, "SHA1"),
}

# TLS 1.3 signals the negotiated version through an extension rather than
# the record header, and reuses this fixed random value to mark a
# HelloRetryRequest (RFC 8446 4.1.3).
HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
)


# --- Named groups (key exchange) -------------------------------------------


class NamedGroup(NamedTuple):
    name: str
    kind: str  # "ecdhe", "ffdhe", "hybrid-pqc", "pure-pqc"
    classical_bits: int  # classical security contribution, 0 if none
    quantum_safe: bool
    standard: str


NAMED_GROUPS: Dict[int, NamedGroup] = {
    0x0017: NamedGroup("secp256r1", "ecdhe", 128, False, "NIST P-256"),
    0x0018: NamedGroup("secp384r1", "ecdhe", 192, False, "NIST P-384"),
    0x0019: NamedGroup("secp521r1", "ecdhe", 260, False, "NIST P-521"),
    0x001D: NamedGroup("x25519", "ecdhe", 128, False, "RFC 7748"),
    0x001E: NamedGroup("x448", "ecdhe", 224, False, "RFC 7748"),
    0x0100: NamedGroup("ffdhe2048", "ffdhe", 112, False, "RFC 7919"),
    0x0101: NamedGroup("ffdhe3072", "ffdhe", 128, False, "RFC 7919"),
    0x0102: NamedGroup("ffdhe4096", "ffdhe", 152, False, "RFC 7919"),
    0x0103: NamedGroup("ffdhe6144", "ffdhe", 176, False, "RFC 7919"),
    0x0104: NamedGroup("ffdhe8192", "ffdhe", 200, False, "RFC 7919"),
    # Hybrid ECDHE + ML-KEM. These are what a server should be offering
    # today: quantum-resistant, while keeping a classical component so a
    # flaw in the new lattice maths cannot make things worse.
    0x11EB: NamedGroup("SecP256r1MLKEM768", "hybrid-pqc", 128, True, "draft-ietf-tls-ecdhe-mlkem"),
    0x11EC: NamedGroup("X25519MLKEM768", "hybrid-pqc", 128, True, "draft-ietf-tls-ecdhe-mlkem"),
    0x11ED: NamedGroup("SecP384r1MLKEM1024", "hybrid-pqc", 192, True, "draft-ietf-tls-ecdhe-mlkem"),
    # Pre-standard Kyber hybrids. Support for these alone means a server is
    # on a draft that has been superseded and needs re-pinning.
    0x6399: NamedGroup("X25519Kyber768Draft00", "hybrid-pqc", 128, True, "superseded draft"),
    0x639A: NamedGroup("SecP256r1Kyber768Draft00", "hybrid-pqc", 128, True, "superseded draft"),
    # Standalone ML-KEM, no classical hedge.
    0x0512: NamedGroup("MLKEM512", "pure-pqc", 0, True, "draft-connolly-tls-mlkem"),
    0x0768: NamedGroup("MLKEM768", "pure-pqc", 0, True, "draft-connolly-tls-mlkem"),
    0x1024: NamedGroup("MLKEM1024", "pure-pqc", 0, True, "draft-connolly-tls-mlkem"),
}

# Probed in preference order; the first hit is what a modern client gets.
PQC_GROUPS = (0x11EC, 0x11EB, 0x11ED, 0x6399, 0x639A, 0x0768, 0x0512, 0x1024)
CLASSICAL_GROUPS = (0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101, 0x0102)


# --- Signature algorithms (TLS extension 13) -------------------------------

SIGNATURE_SCHEMES: Dict[int, str] = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    0x0904: "mldsa44",
    0x0905: "mldsa65",
    0x0906: "mldsa87",
}

# Offered in ClientHello so a server is not forced onto a legacy fallback
# purely because we failed to advertise a modern option.
DEFAULT_SIGNATURE_SCHEMES = (
    0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
    0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
    0x0201, 0x0203,
)

# --- Alerts ----------------------------------------------------------------

ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    109: "missing_extension",
    112: "unrecognized_name",
    120: "no_application_protocol",
}


def cipher_name(code: int) -> str:
    suite = CIPHER_SUITES.get(code)
    return suite.name if suite else f"unknown (0x{code:04X})"


def group_name(code: int) -> str:
    group = NAMED_GROUPS.get(code)
    return group.name if group else f"unknown (0x{code:04X})"


def lookup_group(code: int) -> Optional[NamedGroup]:
    return NAMED_GROUPS.get(code)
