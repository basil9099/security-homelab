"""Tests for the pfSense config sanitiser.

The sanitiser is the gatekeeper between a real firewall export and a public
repo, so these tests assert on the thing that matters: nothing secret survives.
"""

import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from config.sanitise_config import REDACTIONS, sanitise

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TOOL = PROJECT_ROOT / "config" / "sanitise_config.py"

# A realistic export: every secret-bearing field carries a live-looking value.
EXPORT = """<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>pfsense</hostname>
    <webgui><ssl-certref>6410ab3f9c2d1</ssl-certref></webgui>
    <user>
      <name>admin</name>
      <bcrypt-hash>$2y$10$REALHASHabcdefghijklmnopqrstuvwxyz01234</bcrypt-hash>
      <md5-hash>21232f297a57a5a743894a0e4a801fc3</md5-hash>
      <sha1-hash>d033e22ae348aeb5660fc2140aec35850c4da997</sha1-hash>
      <nt-hash>8846f7eaee8fb117ad06bdd830b7586c</nt-hash>
      <authorizedkeys>c3NoLXJzYSBBQUFBQjNOemFDMXljMkU=</authorizedkeys>
    </user>
    <snmpd><rocommunity>s3cr3t-community</rocommunity></snmpd>
  </system>
  <interfaces>
    <wan><ipaddr>203.0.113.44</ipaddr></wan>
    <lan><ipaddr>10.10.10.1</ipaddr></lan>
  </interfaces>
  <ppps><ppp><username>isp-user@example.net</username><password>ispPassw0rd</password></ppp></ppps>
  <l2tp><secret>l2tp-real-secret</secret></l2tp>
  <dhcpd><lan>
    <staticmap><mac>00:0c:29:5e:91:a1</mac><ipaddr>10.10.10.10</ipaddr><hostname>dc01</hostname></staticmap>
    <staticmap><mac>00:0c:29:7b:44:c2</mac><ipaddr>10.10.10.20</ipaddr><hostname>wkstn01</hostname></staticmap>
    <staticmap><mac>00:0c:29:aa:bb:cc</mac><ipaddr>10.10.10.30</ipaddr><hostname></hostname></staticmap>
  </lan></dhcpd>
  <cert><refid>6410ab3f9c2d1</refid><crt>TUlJRENlcnRCb2R5</crt><prv>TUlJRVBSSVZBVEU=</prv></cert>
  <ca><crt>TUlJRENBQm9keQ==</crt><prv>TUlJRUNBS0VZ</prv></ca>
  <ipsec><phase1><pre-shared-key>ipsec-psk-real</pre-shared-key></phase1></ipsec>
  <radius><secret>radius-real-secret</secret></radius>
  <authserver><ldap_bindpw>ldapBindPassw0rd</ldap_bindpw></authserver>
  <notifications><smtp><password>smtpPassw0rd</password></smtp></notifications>
  <dyndnses><dyndns><password>dyndnsPassw0rd</password></dyndns></dyndnses>
  <openvpn><server><shared_key>T1ZQTlNIQVJFRA==</shared_key><tls>T1ZQTlRMUw==</tls></server></openvpn>
  <wireguard><tunnel><privatekey>d2lyZWd1YXJkcHJpdg==</privatekey></tunnel></wireguard>
  <installedpackages><pfblockerng>
    <apikey>pfb-api-key-real</apikey><apitoken>pfb-api-token-real</apitoken>
  </pfblockerng></installedpackages>
</pfsense>
"""

LIVE_SECRETS = [
    "$2y$10$REALHASH", "21232f297a57a5a743894a0e4a801fc3",
    "d033e22ae348aeb5660fc2140aec35850c4da997", "8846f7eaee8fb117ad06bdd830b7586c",
    "c3NoLXJzYSBBQUFBQjNOemFDMXljMkU=", "s3cr3t-community", "203.0.113.44",
    "isp-user@example.net", "ispPassw0rd", "l2tp-real-secret", "00:0c:29",
    "TUlJRENlcnRCb2R5", "TUlJRVBSSVZBVEU=", "6410ab3f9c2d1", "TUlJRENBQm9keQ==",
    "TUlJRUNBS0VZ", "ipsec-psk-real", "radius-real-secret", "ldapBindPassw0rd",
    "smtpPassw0rd", "dyndnsPassw0rd", "T1ZQTlNIQVJFRA==", "T1ZQTlRMUw==",
    "d2lyZWd1YXJkcHJpdg==", "pfb-api-key-real", "pfb-api-token-real",
]


@pytest.fixture
def sanitised():
    return sanitise(EXPORT)


@pytest.mark.parametrize("secret", LIVE_SECRETS)
def test_no_live_secret_survives(sanitised, secret):
    assert secret not in sanitised


def test_output_is_well_formed_xml(sanitised):
    ET.fromstring(sanitised)


def test_non_secret_values_are_preserved(sanitised):
    root = ET.fromstring(sanitised)
    assert root.find("interfaces/lan/ipaddr").text == "10.10.10.1"
    assert root.find("system/hostname").text == "pfsense"
    assert root.find("system/user/name").text == "admin"
    # Static-map IPs and hostnames are lab facts, not secrets.
    assert [s.findtext("ipaddr") for s in root.iter("staticmap")] == [
        "10.10.10.10", "10.10.10.20", "10.10.10.30"
    ]


def test_static_map_macs_get_per_host_placeholders(sanitised):
    root = ET.fromstring(sanitised)
    assert [s.findtext("mac") for s in root.iter("staticmap")] == [
        "REDACTED-DC01-MAC", "REDACTED-WKSTN01-MAC", "REDACTED-MAC"
    ]


def test_static_wan_ip_is_redacted(sanitised):
    assert ET.fromstring(sanitised).find("interfaces/wan/ipaddr").text == "REDACTED-WAN-IP"


@pytest.mark.parametrize("mode", ["dhcp", "pppoe"])
def test_dynamic_wan_mode_is_not_treated_as_an_ip(mode):
    out = sanitise(EXPORT.replace("<ipaddr>203.0.113.44</ipaddr>", f"<ipaddr>{mode}</ipaddr>"))
    assert ET.fromstring(out).find("interfaces/wan/ipaddr").text == mode


def test_sanitising_is_idempotent(sanitised):
    assert sanitise(sanitised) == sanitised


def test_header_comment_is_emitted(sanitised):
    assert "REDACTIONS.md" in sanitised
    assert sanitised.startswith('<?xml version="1.0"?>')


def test_export_missing_optional_sections_does_not_error():
    out = sanitise('<?xml version="1.0"?>\n<pfsense><system><hostname>pf</hostname></system></pfsense>')
    assert ET.fromstring(out).find("system/hostname").text == "pf"


def test_every_redaction_rule_has_a_redacted_placeholder():
    for rule in REDACTIONS:
        assert rule.placeholder.startswith("REDACTED-"), rule


def test_cli_writes_sanitised_xml_to_stdout(tmp_path):
    src = tmp_path / "export.xml"
    src.write_text(EXPORT, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(TOOL), str(src)], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    assert "ispPassw0rd" not in result.stdout
    ET.fromstring(result.stdout)


def test_cli_fails_on_missing_file(tmp_path):
    result = subprocess.run(
        [sys.executable, str(TOOL), str(tmp_path / "nope.xml")], capture_output=True, text=True
    )
    assert result.returncode != 0
    assert result.stdout.strip() == ""      # never emit a partial config


def test_cli_emits_lf_line_endings_on_every_platform(tmp_path):
    # stdout in text mode translates \n to \r\n on Windows, which would make a
    # regenerated config.xml differ from the committed one on every single line.
    src = tmp_path / "export.xml"
    src.write_text(EXPORT, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(TOOL), str(src)], capture_output=True
    )
    assert result.returncode == 0, result.stderr
    assert b"\r\n" not in result.stdout


def test_output_ends_with_a_trailing_newline(sanitised):
    assert sanitised.endswith("\n")


def test_plain_angle_brackets_in_text_are_not_over_escaped():
    # pfSense writes rule descriptions like "Block LAN -> MGMT" unescaped, and a
    # bare ">" is legal in XML text. Escaping it churns the committed file.
    out = sanitise(
        '<?xml version="1.0"?>\n<pfsense><filter><rule>'
        "<descr>Block LAN -> MGMT</descr></rule></filter></pfsense>"
    )
    assert "Block LAN -> MGMT" in out
    assert "&gt;" not in out
    # "<" and "&" must still be escaped or the document stops being well-formed.
    nested = sanitise(
        '<?xml version="1.0"?>\n<pfsense><descr>a &lt; b &amp; c</descr></pfsense>'
    )
    assert ET.fromstring(nested).find("descr").text == "a < b & c"


def test_every_rule_is_documented_in_redactions_md():
    # REDACTIONS.md is the restore checklist: a field stripped but undocumented
    # is a field nobody knows to re-populate.
    doc = (PROJECT_ROOT / "config" / "REDACTIONS.md").read_text(encoding="utf-8")
    undocumented = [r.tag for r in REDACTIONS if r.tag not in doc]
    assert not undocumented, f"not documented in REDACTIONS.md: {undocumented}"


def test_every_documented_placeholder_is_one_the_tool_writes():
    doc = (PROJECT_ROOT / "config" / "REDACTIONS.md").read_text(encoding="utf-8")
    written = {r.placeholder for r in REDACTIONS} | {"REDACTED-MAC"}
    promised = set(re.findall(r"`(REDACTED-[A-Z-]+)`", doc))
    assert promised - written == set(), f"documented but never written: {promised - written}"


def test_committed_config_is_already_fully_sanitised():
    # The committed file must be a fixed point: if it is not, either the tool
    # drifted or the file was hand-edited.
    committed = (PROJECT_ROOT / "config" / "config.xml").read_text(encoding="utf-8")
    assert sanitise(committed) == committed
