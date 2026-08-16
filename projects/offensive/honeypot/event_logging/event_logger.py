"""
event_logging/event_logger.py
=============================
Thread-safe JSON-lines event logger with a queue for the live dashboard.
"""

from __future__ import annotations

import queue
import threading
from collections import Counter
from pathlib import Path

from models import HoneypotEvent


class EventLogger:
    """Central event pipeline.

    * Writes each event as a single JSON line to a ``.jsonl`` file.
    * Pushes events to a bounded queue consumed by the dashboard.
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
        self._echo_json = echo_json
        self._echo_console = echo_console
        self._lock = threading.Lock()
        self._event_queue: queue.Queue[HoneypotEvent] = queue.Queue(maxsize=5000)

        # Running stats
        self._total: int = 0
        self._by_protocol: Counter = Counter()
        self._by_event_type: Counter = Counter()
        self._by_src_ip: Counter = Counter()
        self._usernames: Counter = Counter()

    # ---- public API -------------------------------------------------------

    def log(self, event: HoneypotEvent) -> None:
        """Write *event* to the JSONL file and push to the dashboard queue."""
        line = event.to_json() + "\n"
        with self._lock:
            with open(self._log_path, "a") as fh:
                fh.write(line)
            self._update_stats(event)

        if self._echo_json:
            print(event.to_json(), flush=True)
        elif self._echo_console:
            print(self._console_line(event), flush=True)

        # Non-blocking put — drop oldest if full
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            try:
                self._event_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._event_queue.put_nowait(event)
            except queue.Full:
                pass

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
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    # ---- internals --------------------------------------------------------

    @staticmethod
    def _console_line(event: HoneypotEvent) -> str:
        """Format an event as a single readable console line."""
        ts = event.timestamp
        if "T" in ts:
            ts = ts.split("T")[1][:8]

        detail = ""
        if event.credentials:
            username = event.credentials.get("username", "")
            password = event.credentials.get("password", "")
            detail = f"{username}:{password}"
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
