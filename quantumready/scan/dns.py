"""DNS posture checks, speaking the wire protocol directly.

The standard library resolves names but will not return MX, TXT, CAA or
DNSSEC records, and pulling in a resolver library for that would undercut
the zero-dependency design. The queries here are simple enough to build by
hand; responses are parsed with strict bounds checking, including a guard
against compression-pointer loops, since the response comes from the
network.
"""

from __future__ import annotations

import os
import random
import re
import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_DS = 43
TYPE_RRSIG = 46
TYPE_DNSKEY = 48
TYPE_CAA = 257

TYPE_NAMES = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA",
    TYPE_MX: "MX", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA", TYPE_DS: "DS",
    TYPE_RRSIG: "RRSIG", TYPE_DNSKEY: "DNSKEY", TYPE_CAA: "CAA",
}

FALLBACK_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")
MAX_MESSAGE = 4096


class DNSError(Exception):
    pass


def system_resolvers() -> List[str]:
    """Resolvers from /etc/resolv.conf, then well-known public ones."""
    found: List[str] = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                match = re.match(r"^\s*nameserver\s+(\S+)", line)
                if match:
                    found.append(match.group(1))
    except OSError:
        pass
    for server in FALLBACK_RESOLVERS:
        if server not in found:
            found.append(server)
    return found


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if len(encoded) > 63:
            raise DNSError(f"label too long: {label!r}")
        out += bytes([len(encoded)]) + encoded
    return bytes(out) + b"\x00"


def _decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Decode a possibly-compressed name. Returns (name, offset_after)."""
    labels: List[str] = []
    jumped = False
    after = offset
    steps = 0

    while True:
        steps += 1
        if steps > 128:
            # A compression pointer cycle would otherwise spin forever.
            raise DNSError("compression pointer loop")
        if offset >= len(data):
            raise DNSError("name runs past end of message")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                after = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                after = offset + 2
            if pointer >= offset:
                raise DNSError("forward compression pointer")
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(data):
            raise DNSError("truncated label")
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length

    return ".".join(labels), after


@dataclass
class DNSResponse:
    rcode: int = 0
    authenticated: bool = False  # AD bit -- resolver validated DNSSEC
    truncated: bool = False
    records: List[Tuple[int, str]] = field(default_factory=list)
    error: Optional[str] = None

    def of_type(self, rtype: int) -> List[str]:
        return [value for kind, value in self.records if kind == rtype]


def query(
    name: str,
    rtype: int,
    *,
    resolver: Optional[str] = None,
    timeout: float = 4.0,
    want_dnssec: bool = True,
) -> DNSResponse:
    """Send one DNS query over UDP and parse the answer section."""
    resolvers = [resolver] if resolver else system_resolvers()
    last_error = "no resolver reachable"

    for server in resolvers[:3]:
        try:
            payload = _build_query(name, rtype, want_dnssec)
        except DNSError as exc:
            return DNSResponse(error=str(exc))

        sock = None
        try:
            family = socket.AF_INET6 if ":" in server else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(payload, (server, 53))
            data, _ = sock.recvfrom(MAX_MESSAGE)
            if data[:2] != payload[:2]:
                last_error = "transaction id mismatch"
                continue
            response = _parse_response(data)
            if response.truncated:
                # Answer did not fit in a datagram. Domains with many TXT
                # records hit this routinely, and treating the empty reply
                # as "no SPF record" would be a false clean bill of health.
                retried = _query_tcp(server, payload, timeout)
                if retried is not None:
                    return retried
            return response
        except socket.timeout:
            last_error = f"timeout querying {server}"
        except OSError as exc:
            last_error = f"{server}: {exc}"
        except DNSError as exc:
            last_error = str(exc)
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    return DNSResponse(error=last_error)


def _query_tcp(server: str, payload: bytes, timeout: float) -> Optional[DNSResponse]:
    """Re-send a query over TCP, which DNS uses when an answer is truncated.

    Returns ``None`` if TCP is unavailable, so the caller can fall back to
    whatever the truncated UDP answer contained.
    """
    sock = None
    try:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.sendall(struct.pack(">H", len(payload)) + payload)

        header = _recv_exactly(sock, 2)
        if header is None:
            return None
        length = struct.unpack(">H", header)[0]
        if length == 0 or length > 65535:
            return None
        body = _recv_exactly(sock, length)
        if body is None or body[:2] != payload[:2]:
            return None
        return _parse_response(body)
    except (OSError, DNSError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _recv_exactly(sock: socket.socket, count: int) -> Optional[bytes]:
    chunks: List[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _build_query(name: str, rtype: int, want_dnssec: bool) -> bytes:
    transaction_id = random.SystemRandom().getrandbits(16)
    flags = 0x0120 if want_dnssec else 0x0100  # RD, plus AD to request validation
    header = struct.pack(">HHHHHH", transaction_id, flags, 1, 0, 0, 1 if want_dnssec else 0)
    question = _encode_name(name) + struct.pack(">HH", rtype, 1)
    if want_dnssec:
        # OPT pseudo-record advertising a larger buffer and the DO bit.
        opt = b"\x00" + struct.pack(">HHIH", 41, 4096, 0x00008000, 0)
        return header + question + opt
    return header + question


def _parse_response(data: bytes) -> DNSResponse:
    if len(data) < 12:
        raise DNSError("response shorter than a DNS header")
    _, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    response = DNSResponse(
        rcode=flags & 0x000F,
        authenticated=bool(flags & 0x0020),
        truncated=bool(flags & 0x0200),
    )

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4

    for _ in range(ancount):
        if offset >= len(data):
            break
        _, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _, _, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset : offset + rdlength]
        try:
            value = _format_rdata(rtype, rdata, data, offset)
        except DNSError:
            value = rdata.hex()
        if value is not None:
            response.records.append((rtype, value))
        offset += rdlength

    return response


def _format_rdata(rtype: int, rdata: bytes, message: bytes, offset: int) -> Optional[str]:
    if rtype == TYPE_A and len(rdata) == 4:
        return socket.inet_ntop(socket.AF_INET, rdata)
    if rtype == TYPE_AAAA and len(rdata) == 16:
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (TYPE_NS, TYPE_CNAME):
        return _decode_name(message, offset)[0]
    if rtype == TYPE_MX and len(rdata) >= 3:
        preference = struct.unpack(">H", rdata[:2])[0]
        host = _decode_name(message, offset + 2)[0]
        return f"{preference} {host}"
    if rtype == TYPE_TXT:
        parts: List[str] = []
        pos = 0
        while pos < len(rdata):
            length = rdata[pos]
            pos += 1
            parts.append(rdata[pos : pos + length].decode("utf-8", errors="replace"))
            pos += length
        return "".join(parts)
    if rtype == TYPE_CAA and len(rdata) >= 2:
        tag_length = rdata[1]
        tag = rdata[2 : 2 + tag_length].decode("ascii", errors="replace")
        value = rdata[2 + tag_length :].decode("utf-8", errors="replace").strip('"')
        return f"{tag} {value}"
    if rtype in (TYPE_DS, TYPE_DNSKEY, TYPE_RRSIG):
        return f"{TYPE_NAMES.get(rtype, rtype)} record present"
    return rdata.hex() if rdata else None


@dataclass
class DNSPosture:
    """The mail- and certificate-related DNS controls for a domain."""

    domain: str
    a_records: List[str] = field(default_factory=list)
    aaaa_records: List[str] = field(default_factory=list)
    ns_records: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    caa_records: List[str] = field(default_factory=list)
    spf: Optional[str] = None
    dmarc: Optional[str] = None
    dnssec: bool = False
    dnssec_authenticated: bool = False
    errors: List[str] = field(default_factory=list)
    available: bool = True
    # Controls we could not establish either way. A truncated answer with
    # no TCP retry available means "unknown", and reporting that as absent
    # would invent a finding.
    undetermined: List[str] = field(default_factory=list)

    @property
    def dmarc_policy(self) -> Optional[str]:
        if not self.dmarc:
            return None
        match = re.search(r"\bp\s*=\s*(none|quarantine|reject)", self.dmarc, re.I)
        return match.group(1).lower() if match else None

    @property
    def spf_is_strict(self) -> bool:
        return bool(self.spf and re.search(r"[-~]all\s*$", self.spf.strip()))


def scan_dns(domain: str, *, timeout: float = 4.0) -> DNSPosture:
    """Collect the DNS records that carry security signal."""
    posture = DNSPosture(domain=domain)

    lookups = (
        ("a_records", domain, TYPE_A),
        ("aaaa_records", domain, TYPE_AAAA),
        ("ns_records", domain, TYPE_NS),
        ("mx_records", domain, TYPE_MX),
        ("caa_records", domain, TYPE_CAA),
    )
    reachable = False
    for attribute, name, rtype in lookups:
        response = query(name, rtype, timeout=timeout)
        if response.error:
            posture.errors.append(f"{TYPE_NAMES.get(rtype, rtype)}: {response.error}")
            continue
        reachable = True
        setattr(posture, attribute, response.of_type(rtype))

    if not reachable:
        # UDP/53 is commonly blocked in container and CI networks. Say so
        # rather than reporting every control as missing, which would be
        # indistinguishable from a genuinely unprotected domain.
        posture.available = False
        return posture

    txt = query(domain, TYPE_TXT, timeout=timeout)
    for value in txt.of_type(TYPE_TXT):
        if value.lower().startswith("v=spf1"):
            posture.spf = value
    if posture.spf is None and (txt.truncated or txt.error):
        posture.undetermined.append("spf")
        posture.errors.append(
            "SPF could not be determined: TXT answer was truncated and no TCP "
            "retry succeeded (port 53/tcp may be blocked from this network)"
        )

    dmarc = query(f"_dmarc.{domain}", TYPE_TXT, timeout=timeout)
    for value in dmarc.of_type(TYPE_TXT):
        if value.lower().startswith("v=dmarc1"):
            posture.dmarc = value
    if posture.dmarc is None and (dmarc.truncated or dmarc.error):
        posture.undetermined.append("dmarc")

    ds = query(domain, TYPE_DS, timeout=timeout)
    dnskey = query(domain, TYPE_DNSKEY, timeout=timeout)
    posture.dnssec = bool(ds.of_type(TYPE_DS) or dnskey.of_type(TYPE_DNSKEY))
    posture.dnssec_authenticated = ds.authenticated or dnskey.authenticated

    return posture


def resolves(hostname: str, timeout: float = 3.0) -> bool:
    """Cheap existence check used by subdomain discovery."""
    original = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
        return True
    except (socket.gaierror, OSError):
        return False
    finally:
        socket.setdefaulttimeout(original)
