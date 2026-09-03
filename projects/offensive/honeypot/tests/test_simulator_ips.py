"""The demo simulator must never invent traffic from real, routable addresses.

Labelling a real Tor exit or a live VPS as a "persistent attacker" in output
presented as findings is exactly the kind of thing that makes a portfolio piece
look careless. Source IPs must come from private (RFC 1918) or documentation
(RFC 5737 TEST-NET) ranges only.
"""

import ipaddress

from demo.simulator import _SOURCE_IPS


def test_no_simulated_source_ip_is_globally_routable():
    offenders = [ip for ip in _SOURCE_IPS if ipaddress.ip_address(ip).is_global]
    assert not offenders, f"real routable IPs used as fake attackers: {offenders}"


def test_source_ips_are_non_empty_and_valid():
    assert _SOURCE_IPS
    for ip in _SOURCE_IPS:
        ipaddress.ip_address(ip)  # raises if malformed
