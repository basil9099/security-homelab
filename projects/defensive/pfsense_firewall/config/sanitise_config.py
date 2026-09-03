#!/usr/bin/env python3
"""
Sanitise a pfSense configuration export for public commit.

Usage:
    python sanitise_config.py /path/to/exported-config.xml > config.xml

Reads a real pfSense backup (Diagnostics -> Backup & Restore -> Download) and
replaces every secret-bearing field with a REDACTED placeholder, leaving the
lab facts (addresses, hostnames, rules) intact so the committed file is still a
usable restore template.

Stdlib only, so it runs on any machine with Python 3.11+ — including the
Windows box this repo is developed on, which is why the previous xmlstarlet
version drifted out of step with the file it was supposed to produce.

Every rule below is mirrored in REDACTIONS.md — keep the two in step.
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

HEADER = """<!--
  Sanitised pfSense config template for the homelab.
  This file is the source of truth for the initial restore. Ansible handles day-2 drift.

  Fields marked <REDACTED-*> MUST be re-populated locally before restore — see REDACTIONS.md.
  Do NOT commit a config.xml that contains real password hashes, certificates, or PPPoE creds.
-->"""

MAC_PLACEHOLDER = "REDACTED-MAC"


@dataclass(frozen=True)
class Redaction:
    """One field to strip.

    `tag` matches anywhere in the document unless `parent` or `ancestor`
    narrows it. Values in `keep` are left alone — used for `<ipaddr>dhcp</ipaddr>`,
    which is a mode rather than an address.
    """

    tag: str
    placeholder: str
    parent: str | None = None
    ancestor: str | None = None
    keep: frozenset[str] = field(default_factory=frozenset)


REDACTIONS: tuple[Redaction, ...] = (
    # Credentials
    Redaction("bcrypt-hash", "REDACTED-ADMIN-HASH"),
    Redaction("md5-hash", "REDACTED-MD5-HASH"),
    Redaction("sha1-hash", "REDACTED-SHA1-HASH"),
    Redaction("nt-hash", "REDACTED-NT-HASH"),
    Redaction("authorizedkeys", "REDACTED-AUTHORIZED-KEYS"),
    # Context-specific first — the placeholder names which credential to
    # re-enter. The bare `password` / `secret` rules below are the catch-all for
    # packages not enumerated here, so nothing slips through unredacted.
    Redaction("password", "REDACTED-PPPOE-PASSWORD", parent="ppp"),
    Redaction("password", "REDACTED-SMTP-PASSWORD", parent="smtp"),
    Redaction("password", "REDACTED-DYNDNS-PASSWORD", parent="dyndns"),
    Redaction("password", "REDACTED-PASSWORD"),
    Redaction("username", "REDACTED-PPPOE-USER", parent="ppp"),
    # Certificates and keys
    Redaction("crt", "REDACTED-CERT-BODY", parent="cert"),
    Redaction("prv", "REDACTED-PRIVATE-KEY", parent="cert"),
    Redaction("refid", "REDACTED-CERT-REF", parent="cert"),
    Redaction("ssl-certref", "REDACTED-CERT-REF"),
    Redaction("crt", "REDACTED-CA-BODY", parent="ca"),
    Redaction("prv", "REDACTED-CA-KEY", parent="ca"),
    # VPN / tunnel secrets
    Redaction("pre-shared-key", "REDACTED-IPSEC-PSK"),
    Redaction("shared_key", "REDACTED-OPENVPN-SHARED-KEY"),
    Redaction("tls", "REDACTED-OPENVPN-TLS-KEY"),
    Redaction("privatekey", "REDACTED-WIREGUARD-PRIVATE-KEY"),
    # Directory / RADIUS / SNMP
    Redaction("secret", "REDACTED-L2TP-SECRET", parent="l2tp"),
    Redaction("secret", "REDACTED-RADIUS-SECRET", parent="radius"),
    Redaction("secret", "REDACTED-SECRET"),
    Redaction("ldap_bindpw", "REDACTED-LDAP-BIND-PASSWORD"),
    Redaction("rocommunity", "REDACTED-SNMP-COMMUNITY"),
    # Package API credentials
    Redaction("apikey", "REDACTED-API-KEY"),
    Redaction("apitoken", "REDACTED-API-TOKEN"),
    # Network identifiers. "dhcp"/"pppoe" are modes, not addresses, so they stay.
    Redaction("ipaddr", "REDACTED-WAN-IP", parent="wan", keep=frozenset({"dhcp", "pppoe"})),
)


def _parent_map(root: ET.Element) -> dict[ET.Element, ET.Element]:
    return {child: parent for parent in root.iter() for child in parent}


def _matches(rule: Redaction, el: ET.Element, parents: dict[ET.Element, ET.Element]) -> bool:
    if el.tag != rule.tag:
        return False
    if (el.text or "").strip() in rule.keep:
        return False
    if rule.parent is not None:
        parent = parents.get(el)
        if parent is None or parent.tag != rule.parent:
            return False
    if rule.ancestor is not None:
        node = parents.get(el)
        while node is not None and node.tag != rule.ancestor:
            node = parents.get(node)
        if node is None:
            return False
    return True


def _mac_placeholder(staticmap: ET.Element) -> str:
    """Per-host placeholder so the restore notes say which VM's NIC to re-enter."""
    hostname = (staticmap.findtext("hostname") or "").strip()
    label = re.sub(r"[^A-Z0-9]", "-", hostname.upper())
    return f"REDACTED-{label}-MAC" if label else MAC_PLACEHOLDER


def sanitise(xml_text: str) -> str:
    """Return *xml_text* with every secret-bearing field replaced."""
    root = ET.fromstring(xml_text)
    parents = _parent_map(root)

    for el in root.iter():
        for rule in REDACTIONS:
            if _matches(rule, el, parents):
                el.text = rule.placeholder
                break

    for staticmap in root.iter("staticmap"):
        mac = staticmap.find("mac")
        if mac is not None:
            mac.text = _mac_placeholder(staticmap)

    body = ET.tostring(root, encoding="unicode")
    body = re.sub(r"\s+/>", "/>", body)  # match pfSense's own empty-tag style
    # A bare ">" is legal in XML text and is how pfSense writes rule
    # descriptions; re-escaping it would churn the committed file. "<" and
    # "&" stay escaped — without them the document is not well-formed.
    body = body.replace("&gt;", ">")
    return f'<?xml version="1.0"?>\n{HEADER}\n{body}\n'


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"Usage: {Path(argv[0]).name} <exported-config.xml>", file=sys.stderr)
        return 2

    src = Path(argv[1])
    if not src.is_file():
        print(f"File not found: {src}", file=sys.stderr)
        return 2

    try:
        # Build the whole document before writing anything: a parse error must
        # not leave a half-sanitised config on stdout.
        out = sanitise(src.read_text(encoding="utf-8"))
    except ET.ParseError as exc:
        print(f"Not valid XML: {exc}", file=sys.stderr)
        return 3

    # Write bytes, not text: stdout in text mode rewrites newlines to CRLF on
    # Windows, which would make a regenerated config.xml differ from the
    # committed one on every line. The output is always LF.
    sys.stdout.buffer.write(out.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
