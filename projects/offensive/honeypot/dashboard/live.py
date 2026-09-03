"""
dashboard/live.py
=================
Rich-based live terminal dashboard for honeypot activity.

Three-panel layout:
  - Top: summary statistics
  - Middle: scrolling event table
  - Bottom: top attackers and usernames
"""

from __future__ import annotations

import threading
import time
from collections import deque

from event_logger import EventLogger
from models import HoneypotEvent, format_credentials
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Protocol colour mapping
_PROTO_COLORS = {
    "ssh": "cyan",
    "http": "green",
    "ftp": "yellow",
    "telnet": "magenta",
}

_EVENT_COLORS = {
    "connection": "blue",
    "credential_attempt": "red",
    "command": "yellow",
    "request": "green",
    "disconnect": "dim",
}


class Dashboard:
    """Rich-based live terminal dashboard."""

    def __init__(self, logger: EventLogger, refresh_rate: float = 0.5) -> None:
        self._logger = logger
        self._refresh_rate = refresh_rate
        self._events: deque[HoneypotEvent] = deque(maxlen=200)
        self._start_time = time.time()

    def run(self, stop: threading.Event, duration: int | None = None) -> None:
        """Blocking loop using rich.live.Live."""
        console = Console()

        with Live(self._build_layout(), console=console, refresh_per_second=2, screen=True) as live:
            end_time = time.time() + duration if duration else None

            while not stop.is_set():
                # Drain new events
                new_events = self._logger.drain_queue()
                self._events.extend(new_events)

                live.update(self._build_layout())

                if end_time and time.time() >= end_time:
                    stop.set()
                    break

                stop.wait(timeout=self._refresh_rate)

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._stats_panel(), name="stats", size=7),
            Layout(self._events_table(), name="events"),
            Layout(self._bottom_panels(), name="bottom", size=14),
        )
        return layout

    def _stats_panel(self) -> Panel:
        stats = self._logger.get_stats()
        elapsed = int(time.time() - self._start_time)
        mins, secs = divmod(elapsed, 60)

        grid = Table.grid(padding=(0, 4))
        grid.add_column(justify="center")
        grid.add_column(justify="center")
        grid.add_column(justify="center")
        grid.add_column(justify="center")
        grid.add_column(justify="center")
        grid.add_column(justify="center")

        proto_counts = stats.get("by_protocol", {})
        grid.add_row(
            Text(f"Total: {stats['total']}", style="bold white"),
            Text(f"SSH: {proto_counts.get('ssh', 0)}", style="cyan"),
            Text(f"HTTP: {proto_counts.get('http', 0)}", style="green"),
            Text(f"FTP: {proto_counts.get('ftp', 0)}", style="yellow"),
            Text(f"Telnet: {proto_counts.get('telnet', 0)}", style="magenta"),
            Text(f"Uptime: {mins:02d}:{secs:02d}", style="dim"),
        )

        event_counts = stats.get("by_event_type", {})
        grid.add_row(
            Text(f"Connections: {event_counts.get('connection', 0)}", style="blue"),
            Text(f"Cred Attempts: {event_counts.get('credential_attempt', 0)}", style="red bold"),
            Text(f"Commands: {event_counts.get('command', 0)}", style="yellow"),
            Text(f"Requests: {event_counts.get('request', 0)}", style="green"),
            Text(f"Unique IPs: {len(stats.get('top_ips', {}))}", style="white"),
            "",
        )

        return Panel(grid, title="[bold]Honeypot Dashboard[/bold]", border_style="bright_blue")

    def _events_table(self) -> Panel:
        table = Table(expand=True, show_edge=False, pad_edge=False)
        table.add_column("Time", width=10, style="dim")
        table.add_column("Proto", width=7)
        table.add_column("Source IP", width=18)
        table.add_column("Type", width=20)
        table.add_column("Detail", ratio=1)

        # Show last 30 events (most recent first)
        recent = list(self._events)[-30:]
        for event in reversed(recent):
            ts = event.timestamp
            if "T" in ts:
                ts = ts.split("T")[1][:8]

            proto_color = _PROTO_COLORS.get(event.protocol, "white")
            event_color = _EVENT_COLORS.get(event.event_type, "white")

            detail = ""
            if event.event_type == "credential_attempt" and event.credentials:
                detail = format_credentials(event.credentials)  # password masked
            elif event.payload:
                detail = event.payload[:60]

            table.add_row(
                ts,
                Text(event.protocol.upper(), style=proto_color),
                event.src_ip,
                Text(event.event_type, style=event_color),
                detail,
            )

        return Panel(table, title="[bold]Live Events[/bold]", border_style="green")

    def _bottom_panels(self) -> Layout:
        layout = Layout()
        layout.split_row(
            Layout(self._top_ips_panel(), name="ips"),
            Layout(self._top_usernames_panel(), name="users"),
        )
        return layout

    def _top_ips_panel(self) -> Panel:
        stats = self._logger.get_stats()
        table = Table(expand=True, show_edge=False)
        table.add_column("IP Address", style="bold")
        table.add_column("Events", justify="right", style="red")

        for ip, count in list(stats.get("top_ips", {}).items())[:8]:
            bar = "#" * min(count, 30)
            table.add_row(ip, f"{count} {bar}")

        return Panel(table, title="[bold]Top Attackers[/bold]", border_style="red")

    def _top_usernames_panel(self) -> Panel:
        stats = self._logger.get_stats()
        table = Table(expand=True, show_edge=False)
        table.add_column("Username", style="bold")
        table.add_column("Attempts", justify="right", style="yellow")

        for user, count in list(stats.get("top_usernames", {}).items())[:8]:
            bar = "#" * min(count, 30)
            table.add_row(user, f"{count} {bar}")

        return Panel(table, title="[bold]Top Usernames[/bold]", border_style="yellow")
