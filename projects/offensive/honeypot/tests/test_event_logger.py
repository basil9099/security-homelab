"""Unit tests for the thread-safe JSONL event logger (event_logger.py)."""

import json

from event_logging.event_logger import EventLogger
from models import HoneypotEvent


def _event(**overrides):
    base = dict(
        protocol="ssh",
        src_ip="10.0.0.5",
        src_port=1,
        dst_port=2222,
        event_type="connection",
    )
    base.update(overrides)
    return HoneypotEvent(**base)


def test_log_writes_one_jsonl_line_per_event(tmp_path):
    log_file = tmp_path / "events.jsonl"
    logger = EventLogger(log_file=str(log_file))

    logger.log(_event())
    logger.log(_event(event_type="command", payload="id"))

    lines = log_file.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["event_type"] == "connection"
    assert json.loads(lines[1])["payload"] == "id"


def test_get_stats_aggregates_by_dimension(tmp_path):
    logger = EventLogger(log_file=str(tmp_path / "e.jsonl"))

    logger.log(_event(src_ip="1.1.1.1"))
    logger.log(_event(src_ip="1.1.1.1", protocol="http", event_type="request"))
    logger.log(
        _event(
            src_ip="2.2.2.2",
            event_type="credential_attempt",
            credentials={"username": "admin", "password": "admin"},
        )
    )

    stats = logger.get_stats()
    assert stats["total"] == 3
    assert stats["by_protocol"]["ssh"] == 2
    assert stats["by_protocol"]["http"] == 1
    assert stats["top_ips"]["1.1.1.1"] == 2
    assert stats["top_usernames"]["admin"] == 1


def test_credential_stats_ignore_events_without_username(tmp_path):
    logger = EventLogger(log_file=str(tmp_path / "e.jsonl"))
    logger.log(_event(credentials=None))
    logger.log(_event(credentials={"password": "x"}))  # no username key
    assert logger.get_stats()["top_usernames"] == {}


def test_drain_queue_respects_max_items(tmp_path):
    logger = EventLogger(log_file=str(tmp_path / "e.jsonl"))
    for _ in range(10):
        logger.log(_event())

    first = logger.drain_queue(max_items=4)
    assert len(first) == 4

    rest = logger.drain_queue(max_items=50)
    assert len(rest) == 6

    assert logger.drain_queue() == []  # queue now empty
