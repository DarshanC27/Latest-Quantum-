"""A minimal TLS client that speaks the handshake directly on a socket.

The scanner cannot rely on the local OpenSSL to answer questions about a
remote server: OpenSSL 3.0 has no ML-KEM, and distributions routinely
compile out SSLv3 and TLS 1.0. Asking through it would make the scanner
report "not supported" for anything the *client* cannot do, which is the
most dangerous kind of wrong answer a security tool can give.

So we build ClientHello messages by hand and read the ServerHello back.
Nothing here completes a handshake or moves application data -- it stops
at the first server flight, which is all that protocol, cipher and named
group negotiation needs.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..crypto import tlsparams as tp

RECORD_HANDSHAKE = 22
RECORD_ALERT = 21
HANDSHAKE_CLIENT_HELLO = 1
HANDSHAKE_SERVER_HELLO = 2

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_SESSION_TICKET = 35
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xFF01

MAX_RECORD = 16384 + 2048  # plaintext limit plus expansion allowance


class TLSProbeError(Exception):
    """A probe could not be completed (network-level, not a TLS rejection)."""


# --- encoding helpers ------------------------------------------------------


def _u16(value: int) -> bytes:
    return struct.pack(">H", value)


def _u24(value: int) -> bytes:
    return struct.pack(">I", value)[1:]


def _vector(body: bytes, length_bytes: int) -> bytes:
    """Prefix ``body`` with its length, as TLS variable-length vectors do."""
    if length_bytes == 1:
        return bytes([len(body)]) + body
    if length_bytes == 2:
        return _u16(len(body)) + body
    if length_bytes == 3:
        return _u24(len(body)) + body
    raise ValueError(f"unsupported vector length prefix: {length_bytes}")


def _extension(ext_type: int, body: bytes) -> bytes:
    return _u16(ext_type) + _vector(body, 2)


# --- ClientHello construction ---------------------------------------------


def build_client_hello(
    server_name: str,
    *,
    legacy_version: int = tp.TLS_1_2,
    supported_versions: Optional[Sequence[int]] = None,
    cipher_suites: Sequence[int],
    groups: Sequence[int] = (),
    signature_schemes: Sequence[int] = tp.DEFAULT_SIGNATURE_SCHEMES,
    key_shares: Sequence[Tuple[int, bytes]] = (),
    alpn: Sequence[str] = ("http/1.1",),
) -> bytes:
    """Assemble a complete ClientHello record.

    ``key_shares`` may be empty even when TLS 1.3 is offered. A server that
    supports one of our groups but received no usable share must answer
    with a HelloRetryRequest naming the group it wants (RFC 8446 4.1.4),
    which is exactly the signal the group probes rely on -- and it needs no
    real key material, so we never have to implement the key exchange.
    """
    body = bytearray()
    body += _u16(legacy_version)
    body += os.urandom(32)
    # A non-empty legacy session id keeps middleboxes that expect a
    # resumption-shaped hello from dropping the connection (RFC 8446 D.4).
    body += _vector(os.urandom(32), 1)
    body += _vector(b"".join(_u16(c) for c in cipher_suites), 2)
    body += _vector(b"\x00", 1)  # compression: null only

    extensions = bytearray()

    if server_name and not _is_ip_literal(server_name):
        # SNI carries host_name entries only; an IP literal must be omitted.
        entry = b"\x00" + _vector(server_name.encode("idna"), 2)
        extensions += _extension(EXT_SERVER_NAME, _vector(entry, 2))

    extensions += _extension(EXT_RENEGOTIATION_INFO, _vector(b"", 1))

    if groups:
        extensions += _extension(
            EXT_SUPPORTED_GROUPS, _vector(b"".join(_u16(g) for g in groups), 2)
        )
        extensions += _extension(EXT_EC_POINT_FORMATS, _vector(b"\x00", 1))

    if signature_schemes:
        extensions += _extension(
            EXT_SIGNATURE_ALGORITHMS,
            _vector(b"".join(_u16(s) for s in signature_schemes), 2),
        )

    if alpn:
        names = b"".join(_vector(p.encode("ascii"), 1) for p in alpn)
        extensions += _extension(EXT_ALPN, _vector(names, 2))

    extensions += _extension(EXT_SESSION_TICKET, b"")

    if supported_versions:
        extensions += _extension(
            EXT_SUPPORTED_VERSIONS,
            _vector(b"".join(_u16(v) for v in supported_versions), 1),
        )
        if tp.TLS_1_3 in supported_versions:
            extensions += _extension(EXT_PSK_KEY_EXCHANGE_MODES, _vector(b"\x01", 1))
            shares = b"".join(
                _u16(group) + _vector(key, 2) for group, key in key_shares
            )
            extensions += _extension(EXT_KEY_SHARE, _vector(shares, 2))

    body += _vector(bytes(extensions), 2)

    handshake = bytes([HANDSHAKE_CLIENT_HELLO]) + _vector(bytes(body), 3)
    # The record header always claims TLS 1.0 for maximum middlebox
    # compatibility; the real version lives in the hello.
    return bytes([RECORD_HANDSHAKE]) + _u16(tp.TLS_1_0) + _vector(handshake, 2)


def _is_ip_literal(value: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except (OSError, ValueError):
            continue
    return False


# --- ServerHello parsing ---------------------------------------------------


@dataclass
class ServerResponse:
    """What came back from a single ClientHello."""

    kind: str  # server_hello | hello_retry_request | alert | error
    version: Optional[int] = None
    cipher_suite: Optional[int] = None
    selected_group: Optional[int] = None
    extensions: Dict[int, bytes] = field(default_factory=dict)
    alert_level: Optional[int] = None
    alert_description: Optional[int] = None
    error: Optional[str] = None

    @property
    def accepted(self) -> bool:
        return self.kind in ("server_hello", "hello_retry_request")

    @property
    def alert_name(self) -> Optional[str]:
        if self.alert_description is None:
            return None
        return tp.ALERT_DESCRIPTIONS.get(
            self.alert_description, f"alert {self.alert_description}"
        )

    def describe(self) -> str:
        if self.kind == "alert":
            return f"rejected ({self.alert_name})"
        if self.kind == "error":
            return f"error ({self.error})"
        if self.kind == "hello_retry_request":
            return f"retry requesting {tp.group_name(self.selected_group or 0)}"
        return f"accepted {tp.VERSION_NAMES.get(self.version or 0, 'unknown')}"


def _parse_extensions(data: bytes) -> Dict[int, bytes]:
    extensions: Dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(data):
        ext_type, ext_len = struct.unpack(">HH", data[pos : pos + 4])
        pos += 4
        if pos + ext_len > len(data):
            break
        extensions[ext_type] = data[pos : pos + ext_len]
        pos += ext_len
    return extensions


def parse_server_hello(handshake: bytes) -> ServerResponse:
    """Parse a ServerHello handshake body (without the 4-byte header)."""
    if len(handshake) < 38:
        return ServerResponse(kind="error", error="truncated ServerHello")

    version = struct.unpack(">H", handshake[0:2])[0]
    random = handshake[2:34]
    pos = 34
    session_id_len = handshake[pos]
    pos += 1 + session_id_len
    if pos + 3 > len(handshake):
        return ServerResponse(kind="error", error="truncated ServerHello body")
    cipher_suite = struct.unpack(">H", handshake[pos : pos + 2])[0]
    pos += 3  # cipher suite, then the compression method byte

    extensions: Dict[int, bytes] = {}
    if pos + 2 <= len(handshake):
        ext_len = struct.unpack(">H", handshake[pos : pos + 2])[0]
        pos += 2
        extensions = _parse_extensions(handshake[pos : pos + ext_len])

    # TLS 1.3 keeps the legacy version at 1.2 and states the real one here.
    negotiated = version
    if EXT_SUPPORTED_VERSIONS in extensions:
        raw = extensions[EXT_SUPPORTED_VERSIONS]
        if len(raw) >= 2:
            negotiated = struct.unpack(">H", raw[0:2])[0]

    is_retry = random == tp.HELLO_RETRY_REQUEST_RANDOM
    selected_group = None
    key_share = extensions.get(EXT_KEY_SHARE)
    if key_share and len(key_share) >= 2:
        # In a HelloRetryRequest the extension holds only the group; in a
        # real ServerHello it holds the server's share, group first.
        selected_group = struct.unpack(">H", key_share[0:2])[0]

    return ServerResponse(
        kind="hello_retry_request" if is_retry else "server_hello",
        version=negotiated,
        cipher_suite=cipher_suite,
        selected_group=selected_group,
        extensions=extensions,
    )


def _read_server_flight(sock: socket.socket, deadline_bytes: int = 65536) -> ServerResponse:
    """Read until a full handshake message or an alert arrives."""
    buffer = b""
    handshake = b""
    while len(buffer) < deadline_bytes:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            return ServerResponse(kind="error", error="timeout waiting for ServerHello")
        except OSError as exc:
            return ServerResponse(kind="error", error=f"connection error: {exc}")
        if not chunk:
            if not buffer:
                return ServerResponse(kind="error", error="connection closed with no response")
            break
        buffer += chunk

        pos = 0
        while pos + 5 <= len(buffer):
            record_type = buffer[pos]
            length = struct.unpack(">H", buffer[pos + 3 : pos + 5])[0]
            if length > MAX_RECORD:
                return ServerResponse(kind="error", error="oversized TLS record")
            if pos + 5 + length > len(buffer):
                break  # record incomplete, read more
            payload = buffer[pos + 5 : pos + 5 + length]
            pos += 5 + length

            if record_type == RECORD_ALERT and len(payload) >= 2:
                return ServerResponse(
                    kind="alert",
                    alert_level=payload[0],
                    alert_description=payload[1],
                )
            if record_type == RECORD_HANDSHAKE:
                handshake += payload
                if len(handshake) >= 4:
                    msg_type = handshake[0]
                    msg_len = int.from_bytes(handshake[1:4], "big")
                    if len(handshake) >= 4 + msg_len:
                        if msg_type != HANDSHAKE_SERVER_HELLO:
                            return ServerResponse(
                                kind="error",
                                error=f"unexpected handshake message type {msg_type}",
                            )
                        return parse_server_hello(handshake[4 : 4 + msg_len])
            else:
                # Anything else this early (e.g. plain HTTP from a service
                # that is not speaking TLS at all) is not a TLS server.
                return ServerResponse(
                    kind="error", error=f"unexpected record type {record_type}"
                )
        buffer = buffer[pos:]
    return ServerResponse(kind="error", error="no complete ServerHello received")


def probe(
    host: str,
    port: int,
    hello: bytes,
    *,
    timeout: float = 7.0,
    source: Optional[str] = None,
) -> ServerResponse:
    """Send one ClientHello to ``host:port`` and parse the first response."""
    sock = None
    try:
        sock = socket.create_connection((source or host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(hello)
        return _read_server_flight(sock)
    except socket.timeout:
        return ServerResponse(kind="error", error="connection timed out")
    except socket.gaierror as exc:
        return ServerResponse(kind="error", error=f"DNS resolution failed: {exc}")
    except OSError as exc:
        return ServerResponse(kind="error", error=str(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# --- higher-level probes ---------------------------------------------------


def probe_version(host: str, port: int, version: int, timeout: float = 7.0) -> ServerResponse:
    """Test whether the server will negotiate exactly ``version``."""
    if version == tp.TLS_1_3:
        hello = build_client_hello(
            host,
            legacy_version=tp.TLS_1_2,
            supported_versions=(tp.TLS_1_3,),
            cipher_suites=list(range(0x1301, 0x1306)),
            groups=tp.CLASSICAL_GROUPS,
        )
        response = probe(host, port, hello, timeout=timeout)
        # Without a key share a 1.3 server answers HelloRetryRequest; that
        # still proves the version is supported.
        if response.accepted and response.version == tp.TLS_1_3:
            return response
        if response.accepted:
            return ServerResponse(
                kind="alert", alert_description=70, error="server declined TLS 1.3"
            )
        return response

    # For 1.2 and below the version is stated in the record and the hello,
    # and the server echoes what it selected.
    suites = [c for c in tp.CIPHER_SUITES if c < 0x1300]
    hello = build_client_hello(
        host,
        legacy_version=version,
        supported_versions=None,
        cipher_suites=suites,
        groups=tp.CLASSICAL_GROUPS if version >= tp.TLS_1_0 else (),
    )
    response = probe(host, port, hello, timeout=timeout)
    if response.kind == "server_hello" and response.version != version:
        # The server negotiated something else, so this version is refused.
        return ServerResponse(
            kind="alert",
            alert_description=70,
            error=f"server selected {tp.VERSION_NAMES.get(response.version or 0)}",
        )
    return response


def enumerate_groups(
    host: str,
    port: int,
    candidates: Sequence[int],
    *,
    timeout: float = 7.0,
    max_rounds: int = 12,
) -> Tuple[List[int], Optional[str]]:
    """Discover which of ``candidates`` the server will use, in its order.

    Each round offers only the groups not yet found and sends no key share,
    so a supporting server replies with a HelloRetryRequest naming its
    preferred remaining group. When nothing is left it rejects the hello,
    which ends the loop.

    Returns ``(groups_found, note)`` where ``note`` explains an early stop.
    """
    remaining = list(candidates)
    found: List[int] = []
    for _ in range(min(max_rounds, len(candidates))):
        if not remaining:
            break
        hello = build_client_hello(
            host,
            legacy_version=tp.TLS_1_2,
            supported_versions=(tp.TLS_1_3,),
            cipher_suites=list(range(0x1301, 0x1304)),
            groups=remaining,
            key_shares=(),
        )
        response = probe(host, port, hello, timeout=timeout)
        if response.kind == "error":
            return found, response.error
        if response.kind == "alert":
            break  # nothing left that the server accepts
        group = response.selected_group
        if group is None or group not in remaining:
            # A server that answers without naming a group from our list
            # tells us nothing further; stop rather than loop.
            break
        found.append(group)
        remaining.remove(group)
    return found, None


def enumerate_cipher_suites(
    host: str,
    port: int,
    version: int,
    *,
    timeout: float = 7.0,
    max_rounds: int = 40,
) -> Tuple[List[int], Optional[str]]:
    """Discover accepted cipher suites for one protocol version."""
    if version == tp.TLS_1_3:
        remaining = [c for c in tp.CIPHER_SUITES if 0x1301 <= c <= 0x1305]
    else:
        remaining = [c for c in tp.CIPHER_SUITES if c < 0x1300]
    found: List[int] = []

    for _ in range(min(max_rounds, len(remaining) + 1)):
        if not remaining:
            break
        if version == tp.TLS_1_3:
            hello = build_client_hello(
                host,
                supported_versions=(tp.TLS_1_3,),
                cipher_suites=remaining,
                groups=tp.CLASSICAL_GROUPS,
            )
        else:
            hello = build_client_hello(
                host,
                legacy_version=version,
                cipher_suites=remaining,
                groups=tp.CLASSICAL_GROUPS,
            )
        response = probe(host, port, hello, timeout=timeout)
        if response.kind == "error":
            return found, response.error
        if not response.accepted:
            break
        chosen = response.cipher_suite
        if chosen is None or chosen not in remaining:
            break
        found.append(chosen)
        remaining.remove(chosen)
    return found, None
