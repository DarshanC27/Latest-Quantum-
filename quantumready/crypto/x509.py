"""X.509 certificate parsing (RFC 5280) on top of the DER reader.

Only the fields that carry risk signal are decoded. Anything unparseable
is recorded on ``Certificate.warnings`` instead of raising, so one strange
certificate in a chain never aborts a scan -- a certificate we could not
fully read is itself worth reporting.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import der, oids

# AuthorityInfoAccess access methods.
_OID_OCSP = "1.3.6.1.5.5.7.48.1"
_OID_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"

# GeneralName CHOICE tags (context-specific).
_GN_RFC822 = 1
_GN_DNS = 2
_GN_URI = 6
_GN_IP = 7


@dataclass
class PublicKeyInfo:
    """The subject public key, reduced to what drives risk scoring."""

    algorithm: str  # "RSA", "EC", "Ed25519", "ML-DSA-65", ...
    algorithm_oid: str
    size_bits: int  # modulus bits for RSA/DSA, field size for EC
    curve: Optional[str] = None
    curve_oid: Optional[str] = None
    rsa_exponent: Optional[int] = None

    @property
    def display(self) -> str:
        if self.curve:
            return f"{self.algorithm} {self.curve}"
        if self.size_bits:
            return f"{self.algorithm} {self.size_bits}-bit"
        return self.algorithm


@dataclass
class Certificate:
    """A parsed X.509 certificate."""

    der_bytes: bytes
    version: int = 1
    serial_number: int = 0
    subject: Dict[str, List[str]] = field(default_factory=dict)
    issuer: Dict[str, List[str]] = field(default_factory=dict)
    not_before: Optional[_dt.datetime] = None
    not_after: Optional[_dt.datetime] = None
    public_key: Optional[PublicKeyInfo] = None
    signature_algorithm: str = "unknown"
    signature_algorithm_oid: str = ""
    signature_hash: Optional[str] = None
    san_dns: List[str] = field(default_factory=list)
    san_ip: List[str] = field(default_factory=list)
    san_email: List[str] = field(default_factory=list)
    san_uri: List[str] = field(default_factory=list)
    is_ca: bool = False
    path_length: Optional[int] = None
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    ocsp_urls: List[str] = field(default_factory=list)
    ca_issuer_urls: List[str] = field(default_factory=list)
    crl_urls: List[str] = field(default_factory=list)
    policy_oids: List[str] = field(default_factory=list)
    has_sct: bool = False
    critical_extensions: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # -- derived properties ------------------------------------------------

    @property
    def fingerprint_sha256(self) -> str:
        return hashlib.sha256(self.der_bytes).hexdigest()

    @property
    def subject_cn(self) -> str:
        values = self.subject.get("CN") or []
        return values[0] if values else ""

    @property
    def issuer_cn(self) -> str:
        values = self.issuer.get("CN") or []
        return values[0] if values else ""

    @property
    def issuer_org(self) -> str:
        values = self.issuer.get("O") or []
        return values[0] if values else ""

    @property
    def subject_display(self) -> str:
        return self.subject_cn or _format_name(self.subject) or "(no subject)"

    @property
    def issuer_display(self) -> str:
        parts = [p for p in (self.issuer_org, self.issuer_cn) if p]
        return " / ".join(parts) or "(no issuer)"

    @property
    def is_self_signed(self) -> bool:
        return bool(self.subject) and self.subject == self.issuer

    @property
    def validation_level(self) -> Optional[str]:
        for oid in self.policy_oids:
            label = oids.VALIDATION_POLICIES.get(oid)
            if label:
                return label
        return None

    @property
    def lifetime_days(self) -> Optional[int]:
        if not self.not_before or not self.not_after:
            return None
        return (self.not_after - self.not_before).days

    def days_until_expiry(self, now: Optional[_dt.datetime] = None) -> Optional[int]:
        if not self.not_after:
            return None
        now = now or _dt.datetime.now(_dt.timezone.utc)
        return (self.not_after - now).days

    def is_expired(self, now: Optional[_dt.datetime] = None) -> bool:
        if not self.not_after:
            return False
        return (now or _dt.datetime.now(_dt.timezone.utc)) > self.not_after

    def is_not_yet_valid(self, now: Optional[_dt.datetime] = None) -> bool:
        if not self.not_before:
            return False
        return (now or _dt.datetime.now(_dt.timezone.utc)) < self.not_before

    def matches_hostname(self, hostname: str) -> bool:
        """Check the hostname against SANs, with single-label wildcards."""
        host = hostname.lower().rstrip(".")
        names = [n.lower().rstrip(".") for n in self.san_dns]
        if not names and self.subject_cn:
            names = [self.subject_cn.lower().rstrip(".")]
        for name in names:
            if name == host:
                return True
            if name.startswith("*."):
                # A wildcard covers exactly one label, and never the apex.
                suffix = name[1:]
                if host.endswith(suffix) and "." not in host[: -len(suffix)]:
                    return True
        return False


def _format_name(name: Dict[str, List[str]]) -> str:
    order = ("CN", "OU", "O", "L", "ST", "C")
    parts = [f"{k}={v}" for k in order for v in name.get(k, [])]
    parts += [
        f"{k}={v}" for k, vs in sorted(name.items()) if k not in order for v in vs
    ]
    return ", ".join(parts)


def _parse_name(node: der.Node) -> Dict[str, List[str]]:
    """Name ::= SEQUENCE OF RelativeDistinguishedName."""
    result: Dict[str, List[str]] = {}
    for rdn in node:
        for attr in rdn:
            if len(attr) < 2:
                continue
            oid = attr[0].as_oid()
            label = oids.NAME_ATTRIBUTES.get(oid, oid)
            try:
                value = attr[1].as_text()
            except der.DERError:
                continue
            result.setdefault(label, []).append(value)
    return result


def _parse_public_key(spki: der.Node, warnings: List[str]) -> PublicKeyInfo:
    """SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }."""
    algorithm_node = spki[0]
    oid = algorithm_node[0].as_oid()
    name = oids.public_key_algorithm(oid)
    info = PublicKeyInfo(algorithm=name, algorithm_oid=oid, size_bits=0)

    try:
        key_bytes = spki[1].as_bit_string()
    except der.DERError as exc:
        warnings.append(f"unreadable public key: {exc}")
        return info

    if name in ("RSA", "RSASSA-PSS"):
        try:
            key = der.parse(key_bytes)
            modulus = key[0].as_int()
            info.size_bits = modulus.bit_length()
            info.rsa_exponent = key[1].as_int()
        except (der.DERError, IndexError) as exc:
            warnings.append(f"unreadable RSA key: {exc}")
    elif name == "EC":
        if len(algorithm_node) > 1 and algorithm_node[1].tag == der.OBJECT_IDENTIFIER:
            curve_oid = algorithm_node[1].as_oid()
            info.curve_oid = curve_oid
            info.curve = oids.named_curve(curve_oid)
            info.size_bits = oids.curve_field_bits(curve_oid)
            if not info.size_bits and len(key_bytes) > 1:
                # Unknown curve: fall back to the encoded point, which is
                # 0x04 || X || Y for the uncompressed form. This rounds up
                # to a byte boundary, so it is an upper bound only.
                info.size_bits = ((len(key_bytes) - 1) // 2) * 8
        else:
            warnings.append("EC key without a named curve parameter")
    elif name == "DSA":
        if len(algorithm_node) > 1:
            try:
                info.size_bits = algorithm_node[1][0].as_int().bit_length()
            except (der.DERError, IndexError):
                warnings.append("unreadable DSA parameters")
    elif name in ("Ed25519", "X25519"):
        info.size_bits = 256
    elif name in ("Ed448", "X448"):
        info.size_bits = 448
    else:
        info.size_bits = len(key_bytes) * 8

    return info


def _parse_general_names(node: der.Node) -> Tuple[List[str], List[str], List[str], List[str]]:
    """Split GeneralNames into (dns, ip, email, uri)."""
    dns: List[str] = []
    ips: List[str] = []
    emails: List[str] = []
    uris: List[str] = []
    for item in node:
        if item.tag_class != der.CLASS_CONTEXT:
            continue
        if item.tag == _GN_DNS:
            dns.append(item.content.decode("utf-8", errors="replace"))
        elif item.tag == _GN_RFC822:
            emails.append(item.content.decode("utf-8", errors="replace"))
        elif item.tag == _GN_URI:
            uris.append(item.content.decode("utf-8", errors="replace"))
        elif item.tag == _GN_IP:
            ips.append(_format_ip(item.content))
    return dns, ips, emails, uris


def _format_ip(raw: bytes) -> str:
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    if len(raw) == 16:
        groups = [raw[i : i + 2].hex() for i in range(0, 16, 2)]
        return ":".join(g.lstrip("0") or "0" for g in groups)
    return raw.hex()


def _uri_of(general_name: der.Node) -> Optional[str]:
    if general_name.tag_class == der.CLASS_CONTEXT and general_name.tag == _GN_URI:
        return general_name.content.decode("utf-8", errors="replace")
    return None


def _parse_extension(cert: Certificate, oid: str, value: bytes) -> None:
    """Decode one extension into the certificate. Errors become warnings."""
    name = oids.EXTENSIONS.get(oid)
    if name is None:
        return
    try:
        node = der.parse(value)
    except der.DERError as exc:
        cert.warnings.append(f"unreadable {name} extension: {exc}")
        return

    if name == "subjectAltName":
        dns, ips, emails, uris = _parse_general_names(node)
        cert.san_dns.extend(dns)
        cert.san_ip.extend(ips)
        cert.san_email.extend(emails)
        cert.san_uri.extend(uris)

    elif name == "basicConstraints":
        for child in node:
            if child.tag == der.BOOLEAN:
                cert.is_ca = child.as_bool()
            elif child.tag == der.INTEGER:
                cert.path_length = child.as_int()

    elif name == "keyUsage":
        flags = node.bit_string_flags()
        cert.key_usage = [
            label
            for label, on in zip(oids.KEY_USAGE_BITS, flags)
            if on
        ]

    elif name == "extKeyUsage":
        for child in node:
            usage_oid = child.as_oid()
            cert.extended_key_usage.append(
                oids.EXTENDED_KEY_USAGES.get(usage_oid, usage_oid)
            )

    elif name == "authorityInfoAccess":
        for description in node:
            if len(description) < 2:
                continue
            method = description[0].as_oid()
            url = _uri_of(description[1])
            if not url:
                continue
            if method == _OID_OCSP:
                cert.ocsp_urls.append(url)
            elif method == _OID_CA_ISSUERS:
                cert.ca_issuer_urls.append(url)

    elif name == "cRLDistributionPoints":
        for point in node:
            # DistributionPoint ::= SEQUENCE { [0] distributionPoint, ... }
            for child in point:
                if not child.is_context(0):
                    continue
                for full_name in child:
                    if not full_name.is_context(0):
                        continue
                    for general_name in full_name:
                        url = _uri_of(general_name)
                        if url:
                            cert.crl_urls.append(url)

    elif name == "certificatePolicies":
        for policy in node:
            if len(policy) >= 1:
                cert.policy_oids.append(policy[0].as_oid())

    elif name == "signedCertificateTimestampList":
        cert.has_sct = True


def parse_certificate(data: bytes) -> Certificate:
    """Parse a DER-encoded certificate.

    Raises :class:`der.DERError` only when the outer structure is so broken
    that no useful field can be recovered.
    """
    cert = Certificate(der_bytes=data)
    root = der.parse(data)
    if not root.constructed or len(root) < 3:
        raise der.DERError("not a Certificate SEQUENCE")

    tbs = root[0]
    signature_oid = root[1][0].as_oid()
    cert.signature_algorithm_oid = signature_oid
    cert.signature_algorithm = oids.signature_algorithm(signature_oid)
    entry = oids.SIGNATURE_ALGORITHMS.get(signature_oid)
    cert.signature_hash = entry[1] if entry else None

    index = 0
    if len(tbs) and tbs[0].is_context(0):
        try:
            cert.version = tbs[0][0].as_int() + 1
        except (der.DERError, IndexError):
            cert.warnings.append("unreadable version field")
        index = 1

    try:
        cert.serial_number = tbs[index].as_int()
        # tbs[index + 1] is the inner signature AlgorithmIdentifier, which
        # RFC 5280 requires to equal the outer one.
        inner_oid = tbs[index + 1][0].as_oid()
        if inner_oid != signature_oid:
            cert.warnings.append(
                "signature algorithm mismatch between tbsCertificate and Certificate"
            )
        cert.issuer = _parse_name(tbs[index + 2])
        validity = tbs[index + 3]
        cert.not_before = validity[0].as_datetime()
        cert.not_after = validity[1].as_datetime()
        cert.subject = _parse_name(tbs[index + 4])
        cert.public_key = _parse_public_key(tbs[index + 5], cert.warnings)
    except (der.DERError, IndexError) as exc:
        raise der.DERError(f"malformed tbsCertificate: {exc}") from exc

    for child in tbs.children[index + 6 :]:
        if not child.is_context(3):
            continue
        if not len(child):
            continue
        for extension in child[0]:
            try:
                ext_oid = extension[0].as_oid()
                critical = False
                value_node = extension[1]
                if value_node.tag == der.BOOLEAN:
                    critical = value_node.as_bool()
                    value_node = extension[2]
                if critical:
                    cert.critical_extensions.append(
                        oids.EXTENSIONS.get(ext_oid, ext_oid)
                    )
                _parse_extension(cert, ext_oid, value_node.content)
            except (der.DERError, IndexError) as exc:
                cert.warnings.append(f"skipped malformed extension: {exc}")

    return cert


def parse_chain(chain: List[bytes]) -> List[Certificate]:
    """Parse a list of DER certificates, skipping any that will not parse."""
    parsed: List[Certificate] = []
    for index, data in enumerate(chain):
        try:
            parsed.append(parse_certificate(data))
        except der.DERError:
            placeholder = Certificate(der_bytes=data)
            placeholder.warnings.append(
                f"certificate at chain position {index} could not be parsed"
            )
            parsed.append(placeholder)
    return parsed
