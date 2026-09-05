"""A configurable local TLS server, so the scanner can be tested offline.

Tests need a server whose protocol versions, cipher suites and certificate
are known exactly. Scanning the public internet would make results depend
on someone else's infrastructure and on network egress, and would be
antisocial besides.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from typing import Iterator, Optional


class LocalTLSServer:
    """Serves a fixed certificate on an ephemeral loopback port."""

    def __init__(
        self,
        certfile: str,
        keyfile: str,
        *,
        minimum_version: Optional[ssl.TLSVersion] = None,
        maximum_version: Optional[ssl.TLSVersion] = None,
        ciphers: Optional[str] = None,
        response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
    ) -> None:
        self.certfile = certfile
        self.keyfile = keyfile
        self.minimum_version = minimum_version
        self.maximum_version = maximum_version
        self.ciphers = ciphers
        self.response = response
        self.port = 0
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def _context(self) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if self.ciphers:
            # Must precede load_cert_chain: OpenSSL 3 enforces the security
            # level when the key is loaded, and refuses a 1024-bit RSA key
            # at the default level. The weak-key fixtures exist precisely to
            # confirm the scanner reports them.
            context.set_ciphers(self.ciphers)
        context.load_cert_chain(self.certfile, self.keyfile)
        if self.minimum_version is not None:
            context.minimum_version = self.minimum_version
        if self.maximum_version is not None:
            context.maximum_version = self.maximum_version
        return context

    def start(self) -> "LocalTLSServer":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.3)
        self.port = self._sock.getsockname()[1]
        context = self._context()

        def serve() -> None:
            while not self._stop.is_set():
                try:
                    client, _ = self._sock.accept()
                except (socket.timeout, OSError):
                    continue
                threading.Thread(
                    target=self._handle, args=(client, context), daemon=True
                ).start()

        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        return self

    def _handle(self, client: socket.socket, context: ssl.SSLContext) -> None:
        client.settimeout(3.0)
        try:
            with context.wrap_socket(client, server_side=True) as tls:
                try:
                    tls.recv(8192)
                    tls.sendall(self.response)
                except OSError:
                    pass
        except (ssl.SSLError, OSError):
            # Rejected handshakes are the point of several tests.
            pass
        finally:
            with contextlib.suppress(OSError):
                client.close()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


@contextlib.contextmanager
def running(certfile: str, keyfile: str, **kwargs) -> Iterator[LocalTLSServer]:
    server = LocalTLSServer(certfile, keyfile, **kwargs).start()
    try:
        yield server
    finally:
        server.stop()
