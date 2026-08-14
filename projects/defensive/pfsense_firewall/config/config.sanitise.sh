#!/usr/bin/env bash
# Usage: ./config.sanitise.sh /path/to/exported-config.xml > config.xml
#
# Reads a real pfSense backup (from Diagnostics -> Backup & Restore -> Download)
# and strips everything that must never be committed:
#   - bcrypt password hashes (all <bcrypt-hash> nodes)
#   - certificates and private keys (<crt>, <prv>, <ca>)
#   - PPPoE / L2TP credentials
#   - public WAN IPs if statically assigned
#   - MAC addresses on DHCP static maps (replaced with REDACTED placeholders)
#   - IPsec pre-shared keys
#   - API keys / tokens for installed packages
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

xmlstarlet ed \
  -u '//bcrypt-hash'                    -v 'REDACTED-ADMIN-HASH' \
  -u '//cert/crt'                       -v 'REDACTED-CERT-BODY' \
  -u '//cert/prv'                       -v 'REDACTED-PRIVATE-KEY' \
  -u '//ca/crt'                         -v 'REDACTED-CA-BODY' \
  -u '//ca/prv'                         -v 'REDACTED-CA-KEY' \
  -u '//ppp/password'                   -v 'REDACTED-PPPOE-PASSWORD' \
  -u '//ppp/username'                   -v 'REDACTED-PPPOE-USER' \
  -u '//l2tp/secret'                    -v 'REDACTED-L2TP-SECRET' \
  -u '//ipsec//pre-shared-key'          -v 'REDACTED-IPSEC-PSK' \
  -u '//radius//secret'                 -v 'REDACTED-RADIUS-SECRET' \
  -u '//staticmap/mac'                  -v 'REDACTED-MAC' \
  -u '//wan/ipaddr[. != "dhcp"][. != "pppoe"]'  -v 'REDACTED-WAN-IP' \
  -u '//installedpackages//apikey'      -v 'REDACTED-API-KEY' \
  -u '//installedpackages//apitoken'    -v 'REDACTED-API-TOKEN' \
  "$SRC"
