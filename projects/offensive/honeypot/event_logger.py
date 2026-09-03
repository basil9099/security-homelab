"""
event_logger.py
===============
Thread-safe JSON-lines event logger with a buffer for the live dashboard.
"""

from __future__ import annotations

import os
import threading
from collections import Counter, deque
from pathlib import Path

from models import HoneypotEvent, format_credentials


class EventLogger:
    """Central event pipeline.

    * Writes each event as a single JSON line to a ``.jsonl`` file.
    * Buffers events for the dashboard, dropping the oldest once full.
    * Tracks aggregate statistics for the summary panel.
    * Optionally echoes each event to stdout, as JSON or a readable line.
    """

    def __init__(
        self,
        log_file: str = "honeypot_events.jsonl",
        echo_json: bool = False,
        echo_console: bool = False,
    ) -> None:
        self._log_path = Path(log_file)
        self._secure_log_file()
        self._echo_json = echo_json
        self._echo_console = echo_console
        self._lock = threading.Lock()
        self._pending: deque[HoneypotEvent] = deque(maxlen=5000)

        # Running stats
        self._total: int = 0
        self._by_protocol: Counter = Counter()
        self._by_event_type: Counter = Counter()
        self._by_src_ip: Counter = Counter()
        self._usernames: Counter = Counter()

    # ---- public API -------------------------------------------------------

    def log(self, event: HoneypotEvent) -> None:
        """Write *event* to the JSONL file and buffer it for the dashboard."""
        line = event.to_json() + "\n"
        with self._lock:
            with open(self._log_path, "a") as fh:
                fh.write(line)
            self._update_stats(event)

        if self._echo_json:
            print(event.to_json(), flush=True)
        elif self._echo_console:
            print(self._console_line(event), flush=True)

        # deque(maxlen=...) evicts the oldest event once full; append is atomic.
        self._pending.append(event)

    def get_stats(self) -> dict:
        """Return current aggregate statistics."""
        with self._lock:
            return {
                "total": self._total,
                "by_protocol": dict(self._by_protocol.most_common()),
                "by_event_type": dict(self._by_event_type.most_common()),
                "top_ips": dict(self._by_src_ip.most_common(10)),
                "top_usernames": dict(self._usernames.most_common(10)),
            }

    def drain_queue(self, max_items: int = 50) -> list[HoneypotEvent]:
        """Non-blocking drain of pending events for the dashboard."""
        events: list[HoneypotEvent] = []
        for _ in range(max_items):
            try:
                events.append(self._pending.popleft())
            except IndexError:
                break
        return events

    # ---- internals --------------------------------------------------------

    def _secure_log_file(self) -> None:
        """Create the log owner-only.

        The file holds captured credentials, so it must not be world-readable.
        Created here, before the first attacker credential is ever written, and
        chmod'd explicitly because touch()'s mode is masked by the umask (and,
        for a pre-existing file, touch does not change the mode at all).
        """
        self._log_path.touch(mode=0o600, exist_ok=True)
        try:
            os.chmod(self._log_path, 0o600)
        except OSError:
            pass  # best-effort: exotic filesystems / platforms without POSIX modes

    @staticmethod
    def _console_line(event: HoneypotEvent) -> str:
        """Format an event as a single readable console line."""
        ts = event.timestamp
        if "T" in ts:
            ts = ts.split("T")[1][:8]

        detail = ""
        if event.credentials:
            detail = format_credentials(event.credentials)  # password masked
        elif event.payload:
            detail = event.payload[:80]

        return (
            f"[{ts}] {event.protocol.upper():<6s} {event.src_ip:>15s} "
            f"{event.event_type:<18s} {detail}"
        )

    def _update_stats(self, event: HoneypotEvent) -> None:
        self._total += 1
        self._by_protocol[event.protocol] += 1
        self._by_event_type[event.event_type] += 1
        self._by_src_ip[event.src_ip] += 1
        if event.credentials and event.credentials.get("username"):
            self._usernames[event.credentials["username"]] += 1
