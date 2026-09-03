"""Tests for how captured credentials are stored and displayed.

Capturing attacker credentials is the honeypot's whole point, so the full value
must survive into the JSONL forensic record. What must NOT happen is plaintext
passwords landing in the live terminal and dashboard views — those end up in
scrollback, screen recordings and committed screenshots.
"""

import json
import os
import stat
import sys

import pytest
from event_logger import EventLogger
from models import HoneypotEvent, format_credentials, mask_password


def _cred_event(username="admin", password="hunter2"):
    return HoneypotEvent(
        protocol="ssh",
        src_ip="203.0.113.9",
        src_port=5,
        dst_port=2222,
        event_type="credential_attempt",
        credentials={"username": username, "password": password},
    )


# ---- masking helpers ------------------------------------------------------


def test_mask_password_hides_the_value():
    masked = mask_password("hunter2")
    assert "hunter2" not in masked
    assert masked != ""


def test_mask_password_reveals_no_length():
    # A fixed-width mask, so "was a password tried" leaks but not how long it was.
    assert mask_password("a") == mask_password("a-much-longer-password")


def test_mask_password_of_empty_is_empty():
    assert mask_password("") == ""


def test_mask_password_is_ascii_safe():
    # Console print() on a cp1252 Windows terminal must not raise on the mask.
    mask_password("x").encode("ascii")


def test_format_credentials_masks_by_default():
    out = format_credentials({"username": "root", "password": "toor"})
    assert "root" in out
    assert "toor" not in out


def test_format_credentials_can_show_full_for_machine_output():
    out = format_credentials({"username": "root", "password": "toor"}, mask=False)
    assert out == "root:toor"


def test_format_credentials_of_none_is_empty():
    assert format_credentials(None) == ""


# ---- console + dashboard views mask ---------------------------------------


def test_console_line_masks_the_password(tmp_path):
    logger = EventLogger(log_file=str(tmp_path / "e.jsonl"))
    line = logger._console_line(_cred_event(password="s3cr3t-pw"))
    assert "admin" in line
    assert "s3cr3t-pw" not in line


def test_dashboard_detail_masks_the_password():
    # The dashboard must route credentials through the same masking helper.
    from dashboard import live

    src = live.__file__
    with open(src, encoding="utf-8") as fh:
        code = fh.read()
    assert "format_credentials" in code
    assert "credentials.get('password'" not in code
    assert 'credentials.get("password"' not in code


# ---- the JSONL record keeps the full credential ---------------------------


def test_jsonl_record_keeps_the_full_password(tmp_path):
    log_file = tmp_path / "e.jsonl"
    logger = EventLogger(log_file=str(log_file))
    logger.log(_cred_event(password="fullValue123"))
    record = json.loads(log_file.read_text().splitlines()[0])
    assert record["credentials"]["password"] == "fullValue123"


# ---- the credential log is not world-readable -----------------------------


def test_log_file_is_created_before_first_write(tmp_path):
    log_file = tmp_path / "sub" / "e.jsonl"
    log_file.parent.mkdir()
    EventLogger(log_file=str(log_file))
    assert log_file.exists(), "log must exist (and be secured) before any write"


def test_log_permissions_are_restricted_via_chmod(tmp_path, monkeypatch):
    # Cross-platform: assert the logger asks the OS for owner-only perms.
    calls = []
    real_chmod = os.chmod
    monkeypatch.setattr(os, "chmod", lambda p, m: calls.append((str(p), m)) or real_chmod(p, m))
    log_file = tmp_path / "e.jsonl"
    EventLogger(log_file=str(log_file))
    assert any(str(log_file) == p and m == 0o600 for p, m in calls)


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX permission bits")
def test_log_permissions_are_owner_only_on_posix(tmp_path):
    log_file = tmp_path / "e.jsonl"
    EventLogger(log_file=str(log_file))
    mode = stat.S_IMODE(os.stat(log_file).st_mode)
    assert mode == 0o600, oct(mode)
