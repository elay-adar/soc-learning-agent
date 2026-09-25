"""The local page server (spec section 10, D-011, D-023).

Standard library only. It serves one page that shows the revealed stages, and a JSON endpoint the
page polls. Security, because any web page open in the same browser can try to reach 127.0.0.1:

* it listens on 127.0.0.1 only, never on the network;
* every request needs the per-session token, sent as a cookie the first visit sets
  (the terminal prints the address with `?token=...`, and the server redirects it away);
* the Host header must be this server's own address (blocks DNS rebinding), and an Origin
  header, when the browser sends one, must be this server's own origin;
* only GET is accepted for now (the quiz POST comes in Milestone 5);
* only a fixed list of files is served, so no request can name a path on disk;
* a Content-Security-Policy stops the page loading or running anything not served from here.
"""

from __future__ import annotations

import hmac
import json
import secrets
import threading
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from src.stage_content import StageContent, StagesFile

WEB_DIR = Path(__file__).resolve().parents[1] / "web"
HOST = "127.0.0.1"
DEFAULT_PORT = 8765
COOKIE_NAME = "soc_session"

# The only files the server will ever send: URL path -> (file, content type).
STATIC_FILES = {
    "/": (WEB_DIR / "index.html", "text/html; charset=utf-8"),
    "/static/app.js": (WEB_DIR / "app.js", "text/javascript; charset=utf-8"),
    "/static/style.css": (WEB_DIR / "style.css", "text/css; charset=utf-8"),
    "/static/mermaid.min.js": (WEB_DIR / "vendor" / "mermaid.min.js", "text/javascript; charset=utf-8"),
}

# 'unsafe-inline' for styles only: Mermaid puts a <style> element inside each SVG it draws.
# Scripts stay limited to files served from this server.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class PageStateError(ValueError):
    """A terminal command that cannot be carried out, for example `repeat` on an unseen stage."""


@dataclass
class PageState:
    """What the page shows: the saved stages, how many are revealed, and the stage to scroll to.

    Written by the terminal loop, read by the server threads, so every access takes the lock.
    Nothing here calls a model: `next` and `repeat` only change what is shown.
    """

    file: StagesFile
    revealed: int = 0
    focus_stage: int = 0  # stage number `repeat` asked the page to scroll to and highlight
    focus_seq: int = 0  # grows on every `repeat`, so asking for the same stage twice still fires
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def stage_count(self) -> int:
        return len(self.file.stages)

    def reveal_next(self) -> StageContent | None:
        """Show one more stage. Returns it, or None when every written stage is already shown."""
        with self._lock:
            if self.revealed >= self.stage_count:
                return None
            self.revealed += 1
            return self.file.stages[self.revealed - 1]

    def repeat(self, stage_number: int) -> None:
        """Ask the page to scroll to and highlight a stage that is already shown."""
        with self._lock:
            if not 1 <= stage_number <= self.revealed:
                shown = f"1 to {self.revealed}" if self.revealed else "none yet"
                raise PageStateError(f"stage {stage_number} is not shown yet (shown: {shown})")
            self.focus_stage = stage_number
            self.focus_seq += 1

    def snapshot(self) -> dict:
        """The JSON the page polls. Only revealed stages are included."""
        with self._lock:
            return {
                "topic": self.file.topic,
                "planned": self.file.plan.stage_count,
                "written": self.stage_count,
                "revealed": self.revealed,
                "focus": {"stage": self.focus_stage, "seq": self.focus_seq},
                "stages": [s.model_dump(mode="json") for s in self.file.stages[: self.revealed]],
            }


class LocalServer:
    """Owns the HTTP server, the session token and the page state."""

    def __init__(self, state: PageState, port: int = DEFAULT_PORT, token: str | None = None):
        self.state = state
        self.token = token or secrets.token_urlsafe(32)
        self._static = _load_static()
        self._httpd = _bind(port, _make_handler(self))
        self.port = self._httpd.server_address[1]
        self._thread: threading.Thread | None = None

    @property
    def allowed_hosts(self) -> set[str]:
        return {f"{HOST}:{self.port}", f"localhost:{self.port}"}

    @property
    def allowed_origins(self) -> set[str]:
        return {f"http://{host}" for host in self.allowed_hosts}

    def url(self) -> str:
        """The address to open once. It carries the token, which the server then moves to a cookie."""
        return f"http://{HOST}:{self.port}/?token={self.token}"

    def start(self) -> None:
        self._thread = threading.Thread(target=lambda: self._httpd.serve_forever(poll_interval=0.05), daemon=True, name="page-server")
        self._thread.start()

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    def token_ok(self, candidate: str | None) -> bool:
        return bool(candidate) and hmac.compare_digest(candidate.encode(), self.token.encode())


def _load_static() -> dict[str, tuple[bytes, str]]:
    files = {}
    for path, (file, content_type) in STATIC_FILES.items():
        if not file.is_file():
            raise FileNotFoundError(f"the page needs {file}, which is missing")
        files[path] = (file.read_bytes(), content_type)
    return files


class _Server(ThreadingHTTPServer):
    # On Windows, address reuse would let a second server share a busy port silently, so the
    # fallback to a free port would never trigger.
    allow_reuse_address = False
    daemon_threads = True


def _bind(preferred: int, handler: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    """Listen on 127.0.0.1 at `preferred`, or on a free port chosen by the system if it is busy."""
    try:
        return _Server((HOST, preferred), handler)
    except OSError:
        if preferred == 0:
            raise
        return _Server((HOST, 0), handler)


def _make_handler(app: LocalServer) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "SocLearningAgent"
        sys_version = ""

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            pass  # the request line can hold the token, so nothing is logged

        # ---- helpers ----

        def _send(self, status: HTTPStatus, body: bytes, content_type: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _refuse(self, status: HTTPStatus) -> None:
            self._send(status, f"{status.value} {status.phrase}\n".encode(), "text/plain; charset=utf-8")

        def _cookie_token(self) -> str | None:
            jar = SimpleCookie()
            try:
                jar.load(self.headers.get("Cookie", ""))
            except Exception:  # a malformed Cookie header is just "no token"
                return None
            morsel = jar.get(COOKIE_NAME)
            return morsel.value if morsel else None

        def _headers_ok(self) -> bool:
            if self.headers.get("Host") not in app.allowed_hosts:
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin in app.allowed_origins

        # ---- requests ----

        def do_GET(self) -> None:
            if not self._headers_ok():
                return self._refuse(HTTPStatus.FORBIDDEN)
            # Split by hand: urlsplit would read '//static/app.js' as a host name.
            path, _, query = self.path.partition("?")

            if path == "/" and "token" in parse_qs(query):
                # First visit from the terminal's address: trade the token for a cookie, then
                # redirect so the token does not stay in the address bar or history.
                given = parse_qs(query)["token"][0]
                if not app.token_ok(given):
                    return self._refuse(HTTPStatus.FORBIDDEN)
                cookie = f"{COOKIE_NAME}={app.token}; Path=/; HttpOnly; SameSite=Strict"
                return self._send(HTTPStatus.FOUND, b"", "text/plain; charset=utf-8",
                                  {"Location": "/", "Set-Cookie": cookie})

            if not app.token_ok(self._cookie_token()):
                return self._refuse(HTTPStatus.FORBIDDEN)

            if path == "/api/state":
                body = json.dumps(app.state.snapshot()).encode()
                return self._send(HTTPStatus.OK, body, "application/json; charset=utf-8")
            served = app._static.get(path)
            if served is None:
                return self._refuse(HTTPStatus.NOT_FOUND)
            self._send(HTTPStatus.OK, *served)

        def _method_not_allowed(self) -> None:
            if not self._headers_ok() or not app.token_ok(self._cookie_token()):
                return self._refuse(HTTPStatus.FORBIDDEN)
            self._send(HTTPStatus.METHOD_NOT_ALLOWED, b"405 Method Not Allowed\n",
                       "text/plain; charset=utf-8", {"Allow": "GET"})

        do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _method_not_allowed

    return Handler
