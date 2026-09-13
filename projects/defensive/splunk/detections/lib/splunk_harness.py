"""Ephemeral Splunk container used to execute detection searches.

The lab this repo documents is torn down, so detections cannot be validated
against it. This harness makes CI the execution environment instead: it starts
Splunk, loads a rule's fixture events, runs that rule's real SPL, and returns
the rows. What it proves is detection logic. It does not prove Windows Event
XML field extraction, which is the Splunk Add-on for Windows' job — see
README.md in this directory.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import subprocess
import time
import uuid

import requests
import urllib3

from lib.loader import substitute_index

IMAGE = "splunk/splunk:9.3.2"
CONTAINER_NAME = "splunk-detection-tests"

# Generated per run rather than hardcoded. A literal password here would be a
# secret committed to the repo — which the repo's own gitleaks hook exists to
# stop — even though this container is throwaway and never leaves the runner.
PASSWORD = os.environ.get("SPLUNK_TEST_PASSWORD") or secrets.token_urlsafe(16)
HEC_TOKEN = os.environ.get("SPLUNK_TEST_HEC_TOKEN") or str(uuid.uuid4())

MGMT = "https://localhost:8089"
HEC = "https://localhost:8088"
STARTUP_TIMEOUT_S = 600

# Absolute bounds bracketing the fixtures' 2026-09-01 timestamps. Epoch seconds
# are an unambiguous form of earliest_time/latest_time.
SEARCH_EARLIEST = str(int(dt.datetime(2026, 1, 1, tzinfo=dt.UTC).timestamp()))
SEARCH_LATEST = str(int(dt.datetime(2027, 1, 1, tzinfo=dt.UTC).timestamp()))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SplunkContainer:
    """Starts, populates and queries a throwaway Splunk Enterprise container."""

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.verify = False
        self._session.auth = ("admin", PASSWORD)

    def start(self) -> None:
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, check=False)
        try:
            subprocess.run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    CONTAINER_NAME,
                    "-p",
                    "8089:8089",
                    "-p",
                    "8088:8088",
                    "-e",
                    "SPLUNK_START_ARGS=--accept-license",
                    "-e",
                    f"SPLUNK_PASSWORD={PASSWORD}",
                    "-e",
                    f"SPLUNK_HEC_TOKEN={HEC_TOKEN}",
                    IMAGE,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"docker run failed (exit {e.returncode}): {e.stderr}") from None
        self._wait_until_ready()

    def _wait_until_ready(self) -> None:
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        health, hec = "unknown", "not probed (container never reported healthy)"
        while time.monotonic() < deadline:
            state = self._inspect("{{.State.Status}}")
            if state in ("exited", "dead"):
                raise RuntimeError(
                    f"Splunk container {state} during startup (provisioning failed).\n"
                    f"{self._tail_logs()}"
                )
            # "unhealthy" is not terminal: the image's HEALTHCHECK (start-period 3m,
            # 5 retries at 30s) can report it during slow provisioning, and it flips
            # back to "healthy" once provisioning finishes.
            health = self._inspect("{{if .State.Health}}{{.State.Health.Status}}{{end}}")
            if health == "healthy":
                ok, hec = self._probe_hec()
                if ok:
                    return
            time.sleep(5)
        raise TimeoutError(
            f"Splunk not ready in {STARTUP_TIMEOUT_S}s "
            f"(last health status: {health or 'none'}; last HEC probe: {hec}).\n{self._tail_logs()}"
        )

    def _inspect(self, template: str) -> str:
        result = subprocess.run(
            ["docker", "inspect", "--format", template, CONTAINER_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip()

    def _probe_hec(self) -> tuple[bool, str]:
        # A healthy container only proves splunkd is up. HEC is configured later
        # in provisioning, so probe it with the same request shape ingest() uses.
        try:
            r = requests.post(
                f"{HEC}/services/collector/event",
                headers={"Authorization": f"Splunk {HEC_TOKEN}"},
                data=json.dumps({"event": {"readiness_probe": True}}),
                verify=False,
                timeout=5,
            )
        except requests.RequestException as e:
            return False, f"{type(e).__name__}: {e}"
        return r.status_code == 200, f"{r.status_code} {r.text[:200]}"

    def _tail_logs(self) -> str:
        logs = subprocess.run(
            ["docker", "logs", "--tail", "50", CONTAINER_NAME],
            capture_output=True,
            text=True,
            check=False,
        )
        return f"Last container log lines:\n{logs.stdout}{logs.stderr}"

    def stop(self) -> None:
        subprocess.run(["docker", "rm", "-f", CONTAINER_NAME], capture_output=True, check=False)

    def create_index(self, name: str) -> None:
        r = self._session.post(
            f"{MGMT}/services/data/indexes",
            data={"name": name, "output_mode": "json"},
            timeout=30,
        )
        # 409 means the index already exists, which is fine.
        if r.status_code not in (200, 201, 409):
            raise RuntimeError(f"could not create index {name}: {r.status_code} {r.text}")

    def ingest(self, index: str, events: list[dict]) -> None:
        payload = "".join(
            json.dumps(
                {
                    "time": _epoch(event["_time"]),
                    "index": index,
                    "sourcetype": "XmlWinEventLog",
                    "source": "XmlWinEventLog:Security",
                    "event": {k: v for k, v in event.items() if k != "_time"},
                }
            )
            for event in events
        )
        r = requests.post(
            f"{HEC}/services/collector/event",
            headers={"Authorization": f"Splunk {HEC_TOKEN}"},
            data=payload,
            verify=False,
            timeout=30,
        )
        if r.status_code != 200:
            raise RuntimeError(f"HEC rejected events for {index}: {r.status_code} {r.text}")
        self._wait_for_event_count(index, len(events))

    def _wait_for_event_count(self, index: str, expected: int) -> None:
        """HEC acknowledges before indexing completes; poll until searchable."""
        deadline = time.monotonic() + 60
        seen = 0
        while time.monotonic() < deadline:
            rows = self._raw_search(f"search index={index} | stats count AS n")
            seen = int(rows[0]["n"]) if rows else 0
            if seen >= expected:
                return
            time.sleep(2)
        raise TimeoutError(f"{index}: only {seen} of {expected} events searchable after 60s")

    def search(self, spl: str, index: str) -> list[dict]:
        return self._raw_search(f"search {substitute_index(spl, index)}")

    def _raw_search(self, query: str) -> list[dict]:
        r = self._session.post(
            f"{MGMT}/services/search/jobs",
            data={
                "search": query,
                "exec_mode": "oneshot",
                "output_mode": "json",
                "earliest_time": SEARCH_EARLIEST,
                "latest_time": SEARCH_LATEST,
                "count": 0,
            },
            timeout=120,
        )
        if r.status_code != 200:
            raise RuntimeError(f"search failed: {r.status_code} {r.text}\nquery: {query}")
        if not r.text.strip():
            return []
        body = r.json()
        errors = [m for m in body.get("messages", []) if m.get("type") in ("FATAL", "ERROR")]
        if errors:
            raise RuntimeError(f"search reported errors: {errors}\nquery: {query}")
        return body.get("results", [])


def _epoch(timestamp: str) -> float:
    return dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
