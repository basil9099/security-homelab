#!/usr/bin/env bash
# Usage: ./config.sanitise.sh /path/to/exported-config.xml > config.xml
#
# Reads a real pfSense backup (from Diagnostics -> Backup & Restore -> Download)
# and strips everything that must never be committed:
#   - bcrypt password hashes and legacy user hashes
#   - certificates, CAs and private keys (<crt>, <prv>) and their refids
#   - PPPoE / L2TP credentials
#   - public WAN IPs if statically assigned
#   - MAC addresses on DHCP static maps (per-host REDACTED placeholders)
#   - IPsec pre-shared keys, RADIUS and LDAP bind secrets
#   - OpenVPN shared/TLS keys and WireGuard private keys
#   - SNMP communities, SMTP and dynamic-DNS passwords
#   - user SSH authorized_keys
#   - API keys / tokens for installed packages
#
# Every XPath here is mirrored in REDACTIONS.md — keep the two in step.
#
# Requires: xmlstarlet

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <exported-config.xml>" >&2
  exit 2
fi

SRC="$1"
if [[ ! -f "$SRC" ]]; then
  echo "File not found: $SRC" >&2
  exit 2
fi

command -v xmlstarlet >/dev/null || { echo "xmlstarlet not installed" >&2; exit 3; }

TMP="$(mktemp)"
trap 'rm -f "$TMP" "$TMP.new"' EXIT

# xmlstarlet leaves a -u alone when the node is absent, so listing a field that
# this particular export does not contain is harmless.
xmlstarlet ed \
  -u '//bcrypt-hash'                    -v 'REDACTED-ADMIN-HASH' \
  -u '//user/md5-hash'                  -v 'REDACTED-MD5-HASH' \
  -u '//user/sha1-hash'                 -v 'REDACTED-SHA1-HASH' \
  -u '//user/nt-hash'                   -v 'REDACTED-NT-HASH' \
  -u '//system/user/authorizedkeys'     -v 'REDACTED-AUTHORIZED-KEYS' \
  -u '//cert/crt'                       -v 'REDACTED-CERT-BODY' \
  -u '//cert/prv'                       -v 'REDACTED-PRIVATE-KEY' \
  -u '//cert/refid'                     -v 'REDACTED-CERT-REF' \
  -u '//ssl-certref'                    -v 'REDACTED-CERT-REF' \
  -u '//ca/crt'                         -v 'REDACTED-CA-BODY' \
  -u '//ca/prv'                         -v 'REDACTED-CA-KEY' \
  -u '//ppp/password'                   -v 'REDACTED-PPPOE-PASSWORD' \
  -u '//ppp/username'                   -v 'REDACTED-PPPOE-USER' \
  -u '//l2tp/secret'                    -v 'REDACTED-L2TP-SECRET' \
  -u '//ipsec//pre-shared-key'          -v 'REDACTED-IPSEC-PSK' \
  -u '//radius//secret'                 -v 'REDACTED-RADIUS-SECRET' \
  -u '//authserver/ldap_bindpw'         -v 'REDACTED-LDAP-BIND-PASSWORD' \
  -u '//notifications//smtp/password'   -v 'REDACTED-SMTP-PASSWORD' \
  -u '//dyndns//password'               -v 'REDACTED-DYNDNS-PASSWORD' \
  -u '//snmpd/rocommunity'              -v 'REDACTED-SNMP-COMMUNITY' \
  -u '//openvpn//shared_key'            -v 'REDACTED-OPENVPN-SHARED-KEY' \
  -u '//openvpn//tls'                   -v 'REDACTED-OPENVPN-TLS-KEY' \
  -u '//wireguard//privatekey'          -v 'REDACTED-WIREGUARD-PRIVATE-KEY' \
  -u '//wan/ipaddr[. != "dhcp"][. != "pppoe"]'  -v 'REDACTED-WAN-IP' \
  -u '//installedpackages//apikey'      -v 'REDACTED-API-KEY' \
  -u '//installedpackages//apitoken'    -v 'REDACTED-API-TOKEN' \
  "$SRC" > "$TMP"

# Static-map MACs carry a per-host placeholder (REDACTED-DC01-MAC) so the
# restore steps say which VM's NIC to re-enter, rather than a wall of
# indistinguishable REDACTED-MAC values.
count="$(xmlstarlet sel -t -v 'count(//staticmap)' "$TMP")"
for (( i = 1; i <= count; i++ )); do
  host="$(xmlstarlet sel -t -v "(//staticmap)[$i]/hostname" "$TMP" 2>/dev/null || true)"
  label="$(printf '%s' "$host" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9]/-/g')"
  if [[ -n "$label" ]]; then
    placeholder="REDACTED-${label}-MAC"
  else
    placeholder="REDACTED-MAC"
  fi
  xmlstarlet ed -u "(//staticmap)[$i]/mac" -v "$placeholder" "$TMP" > "$TMP.new"
  mv "$TMP.new" "$TMP"
done

cat "$TMP"
