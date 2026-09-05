"""HTTP surface inspection, over a socket we control.

Requests go over a socket the scanner opens itself rather than through
``urllib`` so that proxy environment variables cannot silently redirect a
security assessment, and so the TLS state that produced a response stays
observable. Response bodies are read up to a cap: a scanner must not be
turned into a memory exhaustion vector by the host it is scanning.
"""

from __future__ import annotations

import gzip
import re
import socket
import ssl
import zlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MAX_BODY = 2 * 1024 * 1024  # 2 MiB is ample for markup and headers
MAX_REDIRECTS = 5
USER_AGENT = "QuantumReady-Scanner/1.0 (+https://github.com/DarshanC27/Quantum.Ready)"

# Headers whose presence and value we assess.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
)

# Headers that hand an attacker version information for free.
DISCLOSURE_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
)


@dataclass
class HTTPResult:
    url: str
    reachable: bool = False
    status: Optional[int] = None
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    body: str = ""
    final_url: str = ""
    redirect_chain: List[str] = field(default_factory=list)
    http_to_https_redirect: Optional[bool] = None
    plaintext_port_open: Optional[bool] = None

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    @property
    def missing_security_headers(self) -> List[str]:
        return [h for h in SECURITY_HEADERS if h not in self.headers]

    @property
    def disclosure(self) -> Dict[str, str]:
        return {h: self.headers[h] for h in DISCLOSURE_HEADERS if h in self.headers}


def _decode_body(raw: bytes, encoding: str, charset: str) -> str:
    encoding = (encoding or "").lower()
    try:
        if "gzip" in encoding:
            raw = gzip.decompress(raw)
        elif "deflate" in encoding:
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except (OSError, zlib.error):
        pass  # keep whatever we have; a body we cannot inflate is not fatal
    return raw.decode(charset or "utf-8", errors="replace")


def _parse_response(data: bytes) -> Tuple[Optional[int], Dict[str, str], List[str], bytes]:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        return None, {}, [], body

    try:
        status = int(lines[0].split(None, 2)[1])
    except (IndexError, ValueError):
        status = None

    headers: Dict[str, str] = {}
    cookies: List[str] = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        key = name.strip().lower()
        value = value.strip()
        if key == "set-cookie":
            cookies.append(value)
        elif key in headers:
            headers[key] += ", " + value
        else:
            headers[key] = value
    return status, headers, cookies, body


def _dechunk(body: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos < len(body) and len(out) < MAX_BODY:
        end = body.find(b"\r\n", pos)
        if end == -1:
            break
        try:
            size = int(body[pos:end].split(b";")[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        start = end + 2
        out += body[start : start + size]
        pos = start + size + 2
    return bytes(out)


def fetch(
    url: str,
    *,
    timeout: float = 10.0,
    verify: bool = False,
    max_redirects: int = MAX_REDIRECTS,
) -> HTTPResult:
    """Fetch ``url``, following same-scheme redirects up to a limit."""
    result = HTTPResult(url=url)
    current = url
    seen: List[str] = []

    for _ in range(max_redirects + 1):
        seen.append(current)
        scheme, host, port, path = _split_url(current)
        if host is None:
            result.error = f"could not parse URL: {current}"
            return result

        status, headers, cookies, body, error = _request(
            scheme, host, port, path, timeout, verify
        )
        if error:
            result.error = error
            result.redirect_chain = seen
            return result

        result.reachable = True
        result.status = status
        result.headers = headers
        result.cookies = cookies
        result.final_url = current
        result.redirect_chain = seen

        if status in (301, 302, 303, 307, 308) and "location" in headers:
            target = headers["location"]
            if target.startswith("/"):
                target = f"{scheme}://{host}:{port}{target}" if port else f"{scheme}://{host}{target}"
            elif not target.startswith(("http://", "https://")):
                break
            if target in seen:
                break  # redirect loop
            current = target
            continue

        result.body = _decode_body(
            body, headers.get("content-encoding", ""), _charset(headers)
        )
        break

    return result


def _charset(headers: Dict[str, str]) -> str:
    match = re.search(r"charset=([\w\-]+)", headers.get("content-type", ""), re.I)
    return match.group(1) if match else "utf-8"


def _split_url(url: str) -> Tuple[str, Optional[str], Optional[int], str]:
    match = re.match(r"^(https?)://([^/:\s]+)(?::(\d+))?(.*)$", url, re.I)
    if not match:
        return "https", None, None, "/"
    scheme = match.group(1).lower()
    host = match.group(2)
    port = int(match.group(3)) if match.group(3) else (443 if scheme == "https" else 80)
    path = match.group(4) or "/"
    return scheme, host, port, path


def _request(
    scheme: str,
    host: str,
    port: int,
    path: str,
    timeout: float,
    verify: bool,
) -> Tuple[Optional[int], Dict[str, str], List[str], bytes, Optional[str]]:
    sock = None
    stream = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if scheme == "https":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            if verify:
                context.load_default_certs(ssl.Purpose.SERVER_AUTH)
            else:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1
            try:
                context.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            stream = context.wrap_socket(sock, server_hostname=host)
        else:
            stream = sock

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {USER_AGENT}\r\n"
            "Accept: text/html,application/xhtml+xml,*/*\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: close\r\n\r\n"
        )
        stream.sendall(request.encode("ascii", errors="ignore"))

        chunks: List[bytes] = []
        total = 0
        while total < MAX_BODY:
            try:
                chunk = stream.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

        data = b"".join(chunks)
        status, headers, cookies, body = _parse_response(data)
        if headers.get("transfer-encoding", "").lower().startswith("chunked"):
            body = _dechunk(body)
        return status, headers, cookies, body, None

    except socket.timeout:
        return None, {}, [], b"", "connection timed out"
    except socket.gaierror as exc:
        return None, {}, [], b"", f"DNS resolution failed: {exc}"
    except ssl.SSLError as exc:
        return None, {}, [], b"", f"TLS error: {exc}"
    except OSError as exc:
        return None, {}, [], b"", str(exc)
    finally:
        for handle in (stream, sock):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass


def check_plaintext(host: str, timeout: float = 6.0) -> Tuple[Optional[bool], Optional[bool]]:
    """Probe port 80.

    Returns ``(port_open, redirects_to_https)``. A site that answers on 80
    without redirecting leaves a window in which credentials and session
    cookies travel in clear text, and gives an attacker somewhere to strip
    TLS from.
    """
    result = fetch(f"http://{host}/", timeout=timeout, max_redirects=0)
    if not result.reachable:
        return False, None
    location = result.header("location") or ""
    redirects = bool(
        result.status in (301, 302, 303, 307, 308)
        and location.lower().startswith("https://")
    )
    return True, redirects


def scan_http(host: str, *, timeout: float = 10.0) -> HTTPResult:
    """Full HTTP assessment for one host."""
    result = fetch(f"https://{host}/", timeout=timeout)
    open_80, redirects = check_plaintext(host, timeout=min(timeout, 6.0))
    result.plaintext_port_open = open_80
    result.http_to_https_redirect = redirects
    return result


# --- HSTS parsing ----------------------------------------------------------


@dataclass
class HSTS:
    present: bool
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False

    @property
    def adequate(self) -> bool:
        # The preload list requires at least one year.
        return self.present and (self.max_age or 0) >= 31536000


def parse_hsts(value: Optional[str]) -> HSTS:
    if not value:
        return HSTS(present=False)
    lowered = value.lower()
    match = re.search(r"max-age\s*=\s*\"?(\d+)", lowered)
    return HSTS(
        present=True,
        max_age=int(match.group(1)) if match else None,
        include_subdomains="includesubdomains" in lowered,
        preload="preload" in lowered,
    )


def parse_cookie_flags(cookie: str) -> Dict[str, object]:
    """Extract the security-relevant attributes of one Set-Cookie header."""
    lowered = cookie.lower()
    name = cookie.split("=", 1)[0].strip()
    same_site = None
    match = re.search(r"samesite\s*=\s*(\w+)", lowered)
    if match:
        same_site = match.group(1)
    return {
        "name": name,
        "secure": "; secure" in lowered or lowered.endswith("; secure"),
        "httponly": "httponly" in lowered,
        "samesite": same_site,
    }
