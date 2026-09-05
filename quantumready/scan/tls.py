"""Endpoint-level TLS assessment.

Combines a real handshake (for the certificate chain and trust decision)
with the hand-rolled probes in :mod:`tls_client` (for everything the local
OpenSSL is too old or too restricted to ask about).
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..crypto import der, tlsparams as tp
from ..crypto.x509 import Certificate, parse_certificate
from . import tls_client

# Issuer names that indicate a TLS-terminating middlebox rather than a
# public CA. Matched case-insensitively as substrings of issuer O or CN.
INTERCEPTOR_HINTS = (
    "zscaler", "bluecoat", "blue coat", "forcepoint", "netskope", "fortinet",
    "fortigate", "palo alto", "sophos", "sonicwall", "mcafee web gateway",
    "cisco umbrella", "checkpoint", "check point", "trend micro", "kaspersky",
    "eset", "bitdefender", "avast", "squid proxy", "mitmproxy", "charles proxy",
    "burp suite", "fiddler", "egress gateway", "corporate proxy", "ssl inspection",
)


@dataclass
class TLSEndpoint:
    """Everything learned about one host:port."""

    host: str
    port: int
    reachable: bool = False
    error: Optional[str] = None

    chain: List[Certificate] = field(default_factory=list)
    chain_complete: bool = True
    trusted: bool = False
    trust_error: Optional[str] = None
    hostname_matches: bool = False

    negotiated_version: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    alpn: Optional[str] = None

    supported_versions: List[int] = field(default_factory=list)
    cipher_suites: Dict[int, List[int]] = field(default_factory=dict)
    classical_groups: List[int] = field(default_factory=list)
    pqc_groups: List[int] = field(default_factory=list)
    pqc_probe_note: Optional[str] = None

    interception_suspected: bool = False
    interception_reasons: List[str] = field(default_factory=list)

    notes: List[str] = field(default_factory=list)

    @property
    def leaf(self) -> Optional[Certificate]:
        return self.chain[0] if self.chain else None

    @property
    def pqc_ready(self) -> bool:
        return bool(self.pqc_groups)

    @property
    def all_cipher_suites(self) -> List[int]:
        seen: List[int] = []
        for suites in self.cipher_suites.values():
            for suite in suites:
                if suite not in seen:
                    seen.append(suite)
        return seen

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"


def _get_chain(tls_sock: ssl.SSLSocket) -> List[bytes]:
    """Pull the DER chain the server sent, across Python versions.

    ``get_unverified_chain`` became public in 3.13 but has existed on the
    underlying object since 3.10; falling back to the peer certificate
    alone still yields a usable (if shallow) result on older builds.
    """
    for source in (tls_sock, getattr(tls_sock, "_sslobj", None)):
        getter = getattr(source, "get_unverified_chain", None)
        if getter is None:
            continue
        try:
            chain = getter()
        except (ValueError, OSError):
            continue
        if not chain:
            continue
        out: List[bytes] = []
        for entry in chain:
            # 3.13 returns Certificate objects; earlier builds return DER.
            if isinstance(entry, (bytes, bytearray)):
                out.append(bytes(entry))
            else:
                try:
                    out.append(entry.public_bytes(ssl._ssl.ENCODING_DER))  # type: ignore[attr-defined]
                except Exception:  # noqa: BLE001 - best effort across versions
                    continue
        if out:
            return out
    peer = tls_sock.getpeercert(binary_form=True)
    return [peer] if peer else []


def _handshake(
    host: str, port: int, timeout: float, verify: bool
) -> Tuple[Optional[ssl.SSLSocket], Optional[socket.socket], Optional[str]]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    # Accept whatever the server offers so we can inspect weak deployments
    # rather than refusing to look at them.
    context.minimum_version = ssl.TLSVersion.TLSv1
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        context.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass

    raw = None
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        tls = context.wrap_socket(raw, server_hostname=host)
        return tls, raw, None
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass
        return None, None, f"{type(exc).__name__}: {exc}"


def _assess_interception(endpoint: TLSEndpoint) -> None:
    """Flag a chain that looks like it was minted by a middlebox.

    Two independent signals. A publicly-trusted certificate has carried
    embedded Certificate Transparency timestamps since 2018 because major
    browsers require them, so a chain that the local trust store accepts
    but which has no SCTs was almost certainly issued by a private CA
    installed on this machine. Named vendor CAs are conclusive on their own.
    """
    leaf = endpoint.leaf
    if leaf is None:
        return

    issuer_text = " ".join(
        [leaf.issuer_cn, leaf.issuer_org]
        + [v for values in leaf.issuer.values() for v in values]
    ).lower()
    for hint in INTERCEPTOR_HINTS:
        if hint in issuer_text:
            endpoint.interception_suspected = True
            endpoint.interception_reasons.append(
                f"issuer matches known TLS-inspection vendor: {hint!r}"
            )
            break

    if endpoint.trusted and not leaf.has_sct and not leaf.is_self_signed:
        endpoint.interception_suspected = True
        endpoint.interception_reasons.append(
            "certificate is trusted locally but carries no Certificate "
            "Transparency SCTs, which public CAs have been required to embed "
            "since 2018"
        )

    if endpoint.interception_suspected:
        endpoint.notes.append(
            "Results describe the certificate presented to this scanner. An "
            "intercepting proxy sits in the path, so the origin server's own "
            "certificate and cipher configuration may differ. Re-run from a "
            "network without TLS inspection for an authoritative result."
        )


def scan_endpoint(
    host: str,
    port: int = 443,
    *,
    timeout: float = 7.0,
    deep: bool = True,
    probe_ciphers: bool = True,
) -> TLSEndpoint:
    """Assess a single TLS endpoint.

    ``deep`` enables the raw version and named-group probes, which cost
    roughly a dozen extra connections. ``probe_ciphers`` adds full cipher
    suite enumeration, which is the most expensive step.
    """
    endpoint = TLSEndpoint(host=host, port=port)

    # Verified handshake first: success is the trust decision. On failure we
    # retry unverified, because an untrusted certificate still needs reading.
    tls, raw, error = _handshake(host, port, timeout, verify=True)
    if tls is not None:
        endpoint.trusted = True
    else:
        endpoint.trust_error = error
        tls, raw, error = _handshake(host, port, timeout, verify=False)

    if tls is None:
        endpoint.error = error
        return endpoint

    endpoint.reachable = True
    try:
        endpoint.negotiated_version = tls.version()
        cipher = tls.cipher()
        if cipher:
            endpoint.negotiated_cipher = cipher[0]
        try:
            endpoint.alpn = tls.selected_alpn_protocol()
        except NotImplementedError:
            pass
        chain_der = _get_chain(tls)
    finally:
        try:
            tls.close()
        except OSError:
            pass
        if raw is not None:
            try:
                raw.close()
            except OSError:
                pass

    for index, data in enumerate(chain_der):
        try:
            endpoint.chain.append(parse_certificate(data))
        except der.DERError as exc:
            endpoint.notes.append(f"certificate {index} in chain is unparseable: {exc}")

    leaf = endpoint.leaf
    if leaf is not None:
        endpoint.hostname_matches = leaf.matches_hostname(host)
        # A server should send every intermediate up to (not including) the
        # root. A single non-self-signed certificate means clients must
        # find the issuer themselves, which many non-browser clients cannot.
        if len(endpoint.chain) == 1 and not leaf.is_self_signed:
            endpoint.chain_complete = False
            endpoint.notes.append(
                "server sent no intermediate certificates; clients that do not "
                "fetch issuers themselves will fail to build a path"
            )

    _assess_interception(endpoint)

    if deep:
        for version in (tp.SSL_3_0, tp.TLS_1_0, tp.TLS_1_1, tp.TLS_1_2, tp.TLS_1_3):
            response = tls_client.probe_version(host, port, version, timeout=timeout)
            if response.accepted:
                endpoint.supported_versions.append(version)

        endpoint.classical_groups, note = tls_client.enumerate_groups(
            host, port, tp.CLASSICAL_GROUPS, timeout=timeout
        )
        endpoint.pqc_groups, pqc_note = tls_client.enumerate_groups(
            host, port, tp.PQC_GROUPS, timeout=timeout
        )
        endpoint.pqc_probe_note = pqc_note or note

        if probe_ciphers:
            for version in endpoint.supported_versions:
                suites, _ = tls_client.enumerate_cipher_suites(
                    host, port, version, timeout=timeout
                )
                if suites:
                    endpoint.cipher_suites[version] = suites

    return endpoint


def scan_endpoints(
    targets: Sequence[Tuple[str, int]],
    *,
    timeout: float = 7.0,
    deep: bool = True,
    probe_ciphers: bool = True,
    workers: int = 8,
    progress=None,
) -> List[TLSEndpoint]:
    """Scan several endpoints concurrently, preserving input order."""
    from concurrent.futures import ThreadPoolExecutor

    results: List[Optional[TLSEndpoint]] = [None] * len(targets)

    def run(index: int, host: str, port: int) -> None:
        results[index] = scan_endpoint(
            host, port, timeout=timeout, deep=deep, probe_ciphers=probe_ciphers
        )
        if progress:
            progress(host, port, results[index])

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for index, (host, port) in enumerate(targets):
            pool.submit(run, index, host, port)

    return [r for r in results if r is not None]
