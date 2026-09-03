"""
protocols/http.py
=================
HTTP honeypot handler.

Emulates an Apache web server with common attack surface endpoints
(WordPress login, phpMyAdmin, .env, path traversal, etc.).
"""

from __future__ import annotations

import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from protocols.base import ProtocolHandler

# ---------------------------------------------------------------------------
# Fake HTML responses
# ---------------------------------------------------------------------------

_DEFAULT_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>Apache2 Ubuntu Default Page</title></head>
<body>
<h1>Apache2 Ubuntu Default Page</h1>
<p>This is the default welcome page used to test the correct operation
of the Apache2 server after installation on Ubuntu systems.</p>
</body>
</html>"""

_WP_LOGIN_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>Log In &lsaquo; WordPress</title></head>
<body class="login">
<div id="login">
<h1><a href="https://wordpress.org/">WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" size="20" /></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" size="20" /></p>
<p class="submit"><input type="submit" name="wp-submit" value="Log In" /></p>
</form>
</div>
</body>
</html>"""

_404_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at {host} Port {port}</address>
</body>
</html>"""

_403_PAGE = """\
<!DOCTYPE html>
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
</body>
</html>"""


class HTTPHandler(ProtocolHandler):
    """HTTP honeypot emulating an Apache web server."""

    PROTOCOL_NAME = "http"

    def start(self) -> None:
        handler = self
        server_banner = self._config.banner or "Apache/2.4.41 (Ubuntu)"
        port = self._config.port

        class _RequestHandler(BaseHTTPRequestHandler):
            server_version = server_banner

            def log_message(self, format, *args):
                pass  # suppress default stderr logging

            def _emit_request(self, body: str = "") -> str:
                session_id = uuid.uuid4().hex[:10]
                ip = self.client_address[0]
                src_port = self.client_address[1]

                metadata = {
                    "method": self.command,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "user_agent": self.headers.get("User-Agent", ""),
                }

                handler._emit(handler._make_event(
                    ip, src_port, "request",
                    payload=f"{self.command} {self.path}",
                    metadata=metadata,
                    session_id=session_id,
                ))

                # Check for credential submission
                if body and self.command == "POST":
                    parsed = parse_qs(body)
                    user_keys = ("log", "username", "user", "email", "login")
                    pass_keys = ("pwd", "password", "pass", "passwd")
                    username = ""
                    password = ""
                    for k in user_keys:
                        if k in parsed:
                            username = parsed[k][0]
                            break
                    for k in pass_keys:
                        if k in parsed:
                            password = parsed[k][0]
                            break
                    if username or password:
                        handler._emit(handler._make_event(
                            ip, src_port, "credential_attempt",
                            credentials={"username": username, "password": password},
                            session_id=session_id,
                        ))

                return session_id

            def do_GET(self):
                self._emit_request()
                self._route_get()

            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = ""
                if content_length > 0:
                    raw = self.rfile.read(min(content_length, 8192))
                    body = raw.decode("utf-8", errors="ignore")
                self._emit_request(body)
                self._route_post(body)

            def do_HEAD(self):
                self._emit_request()
                self._send(200, "")

            def _route_get(self):
                path = urlparse(self.path).path

                if path == "/":
                    self._send(200, _DEFAULT_PAGE)
                elif path in ("/wp-login.php", "/wp-admin"):
                    self._send(200, _WP_LOGIN_PAGE)
                elif path in ("/phpmyadmin", "/phpMyAdmin", "/pma"):
                    self._send(403, _403_PAGE)
                elif path == "/robots.txt":
                    self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\n",
                               content_type="text/plain")
                elif ".." in path or path.startswith("/."):
                    self._send(403, _403_PAGE)
                else:
                    self._send(404, _404_PAGE.format(host="localhost", port=port))

            def _route_post(self, body: str):
                path = urlparse(self.path).path
                if path == "/wp-login.php":
                    # Redirect back to login (mimics failed auth)
                    self.send_response(302)
                    self.send_header("Location", "/wp-login.php?error=incorrect_password")
                    self.send_header("Server", server_banner)
                    self.end_headers()
                else:
                    self._send(404, _404_PAGE.format(host="localhost", port=port))

            def _send(self, code: int, body: str, content_type: str = "text/html"):
                self.send_response(code)
                self.send_header("Content-Type", f"{content_type}; charset=utf-8")
                self.send_header("Server", server_banner)
                self.end_headers()
                self.wfile.write(body.encode("utf-8"))

        server = HTTPServer(self.bind_address(), _RequestHandler)
        server.timeout = 1.0
        self._http_server = server

        while not self._stop_event.is_set():
            server.handle_request()

        server.server_close()

    def stop(self) -> None:
        self._stop_event.set()
        if hasattr(self, "_http_server"):
            try:
                self._http_server.server_close()
            except OSError:
                pass
