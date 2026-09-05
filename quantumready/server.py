"""Live web dashboard and JSON API.

Built on the standard library so `python -m quantumready serve` works on a
clean machine with nothing installed. Progress is streamed with
server-sent events, which need no client library and survive proxies that
would interfere with a websocket.

This binds to loopback by default. It is a scanning tool with no
authentication, so exposing it on a public interface would let anyone use
your network as the origin of a scan.
"""

from __future__ import annotations

import json
import queue
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from .engine import quantum, remediation
from .model import ScanTarget
from .report import html as html_report, serialise
from .scanner import ScanOptions, Scanner, normalise_domain
from .web import PAGE

MAX_CONCURRENT_SCANS = 4
MAX_RETAINED_SCANS = 40


@dataclass
class Job:
    """One scan, its event stream, and its result."""

    id: str
    domain: str
    organisation: str
    status: str = "queued"  # queued | running | done | error
    events: List[Dict[str, Any]] = field(default_factory=list)
    listeners: List["queue.Queue"] = field(default_factory=list)
    result: Any = None
    error: Optional[str] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    def publish(self, event: Dict[str, Any]) -> None:
        with self.lock:
            self.events.append(event)
            listeners = list(self.listeners)
        for listener in listeners:
            try:
                listener.put_nowait(event)
            except queue.Full:
                pass

    def subscribe(self) -> "queue.Queue":
        listener: "queue.Queue" = queue.Queue(maxsize=512)
        with self.lock:
            backlog = list(self.events)
            self.listeners.append(listener)
        for event in backlog:
            try:
                listener.put_nowait(event)
            except queue.Full:
                break
        return listener

    def unsubscribe(self, listener: "queue.Queue") -> None:
        with self.lock:
            if listener in self.listeners:
                self.listeners.remove(listener)


class JobStore:
    def __init__(self) -> None:
        self._jobs: Dict[str, Job] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()
        self._running = 0

    def create(self, domain: str, organisation: str) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], domain=domain, organisation=organisation)
        with self._lock:
            self._jobs[job.id] = job
            self._order.append(job.id)
            # Bound memory: a long-running server should not accumulate
            # every scan it has ever performed.
            while len(self._order) > MAX_RETAINED_SCANS:
                self._jobs.pop(self._order.pop(0), None)
        return job

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def acquire_slot(self) -> bool:
        with self._lock:
            if self._running >= MAX_CONCURRENT_SCANS:
                return False
            self._running += 1
            return True

    def release_slot(self) -> None:
        with self._lock:
            self._running = max(0, self._running - 1)


STORE = JobStore()


def _run_job(job: Job, target: ScanTarget, options: ScanOptions) -> None:
    def progress(stage: str, message: str, data: dict) -> None:
        job.publish({"type": "progress", "stage": stage, "message": message, **data})

    job.status = "running"
    job.publish({"type": "status", "status": "running"})
    try:
        scanner = Scanner(options, progress=progress)
        result = scanner.run(target)
        job.result = result
        job.status = "done"
        job.publish({"type": "result", "data": serialise.to_dict(result)})
    except Exception as exc:  # noqa: BLE001 - surfaced to the client
        job.status = "error"
        job.error = f"{type(exc).__name__}: {exc}"
        traceback.print_exc()
        job.publish({"type": "error", "message": job.error})
    finally:
        job.publish({"type": "status", "status": job.status})
        STORE.release_slot()


class Handler(BaseHTTPRequestHandler):
    server_version = "QuantumReady/1.0"
    protocol_version = "HTTP/1.1"

    # -- helpers -----------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        return  # the dashboard is noisy enough without a request log

    def _send(self, status: int, body: bytes, content_type: str, extra: Optional[dict] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # The dashboard is entirely self-contained, so it can afford the
        # strictest policy available.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'",
        )
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status: int, payload: Any) -> None:
        self._send(status, json.dumps(payload, default=str).encode(), "application/json")

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    # -- routes ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        if path == "/":
            self._send(200, PAGE.encode("utf-8"), "text/html; charset=utf-8")
        elif path == "/api/health":
            self._json(200, {"status": "ok", "version": serialise.TOOL_VERSION})
        elif path == "/api/tooling":
            self._json(200, {
                category: [tool._asdict() for tool in tools]
                for category, tools in remediation.PQC_TOOLING.items()
            })
        elif path == "/api/sectors":
            self._json(200, {
                name: {"years": years, "reason": reason}
                for name, (years, reason) in quantum.SECTOR_SHELF_LIFE.items()
            })
        elif path == "/api/scan/events":
            self._stream(params.get("id", [""])[0])
        elif path == "/api/scan/result":
            self._result(params.get("id", [""])[0], params.get("format", ["json"])[0])
        else:
            self._error(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path.rstrip("/") != "/api/scan":
            self._error(404, "not found")
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "invalid Content-Length")
            return
        if length > 8192:
            self._error(413, "request too large")
            return

        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._error(400, "invalid JSON body")
            return
        if not isinstance(payload, dict):
            self._error(400, "expected a JSON object")
            return

        domain = normalise_domain(str(payload.get("domain", "")))
        if not domain or "." not in domain:
            self._error(400, "a valid domain is required")
            return

        sector = str(payload.get("sector", "general"))
        shelf_life = payload.get("shelf_life")
        if not isinstance(shelf_life, int) or shelf_life <= 0:
            shelf_life = quantum.suggested_shelf_life(sector)[0]

        migration_years = payload.get("migration_years")
        if not isinstance(migration_years, int) or migration_years <= 0:
            migration_years = 5

        if not STORE.acquire_slot():
            self._error(429, "too many scans in progress; try again shortly")
            return

        organisation = str(payload.get("organisation") or domain)[:120]
        target = ScanTarget(
            organisation=organisation,
            domain=domain,
            data_shelf_life_years=min(shelf_life, 100),
            migration_years=min(migration_years, 50),
            sector=sector,
        )
        options = ScanOptions(
            max_hosts=max(1, min(int(payload.get("max_hosts") or 8), 30)),
            deep_tls=bool(payload.get("deep", True)),
            probe_ciphers=bool(payload.get("deep", True)),
            use_ct=bool(payload.get("use_ct", True)),
            check_licences=bool(payload.get("check_licences", True)),
            quantum_scenario=str(payload.get("scenario", "central")),
        )

        job = STORE.create(domain, organisation)
        threading.Thread(
            target=_run_job, args=(job, target, options), daemon=True
        ).start()
        self._json(202, {"id": job.id, "domain": domain})

    # -- streaming ---------------------------------------------------------

    def _stream(self, job_id: str) -> None:
        job = STORE.get(job_id)
        if job is None:
            self._error(404, "unknown scan id")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

        listener = job.subscribe()
        try:
            while True:
                try:
                    event = listener.get(timeout=15)
                except queue.Empty:
                    # A comment frame keeps intermediaries from timing out
                    # a stream that is simply between stages.
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    if job.status in ("done", "error"):
                        break
                    continue
                self.wfile.write(
                    f"data: {json.dumps(event, default=str)}\n\n".encode("utf-8")
                )
                self.wfile.flush()
                if event.get("type") == "status" and event.get("status") in ("done", "error"):
                    break
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            job.unsubscribe(listener)

    def _result(self, job_id: str, fmt: str) -> None:
        job = STORE.get(job_id)
        if job is None:
            self._error(404, "unknown scan id")
            return
        if job.status == "error":
            self._error(500, job.error or "scan failed")
            return
        if job.result is None:
            self._json(202, {"status": job.status})
            return

        if fmt == "html":
            body = html_report.render(job.result).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8", {
                "Content-Disposition": f'inline; filename="{job.domain}-report.html"',
            })
        elif fmt == "markdown":
            body = serialise.to_markdown(job.result).encode("utf-8")
            self._send(200, body, "text/markdown; charset=utf-8", {
                "Content-Disposition": f'attachment; filename="{job.domain}-report.md"',
            })
        elif fmt == "cbom":
            body = serialise.to_cbom_json(job.result).encode("utf-8")
            self._send(200, body, "application/json", {
                "Content-Disposition": f'attachment; filename="{job.domain}-cbom.json"',
            })
        else:
            self._json(200, serialise.to_dict(job.result))


def serve(host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True) -> None:
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    url = f"http://{host}:{port}/"

    print(f"Quantum.Ready dashboard on {url}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "  warning: bound to a non-loopback address. This service has no "
            "authentication and will scan any domain it is given."
        )
    print("  press Ctrl-C to stop")

    if open_browser:
        def launch() -> None:
            import webbrowser

            webbrowser.open(url)

        threading.Timer(0.6, launch).start()

    try:
        server.serve_forever()
    finally:
        server.server_close()
