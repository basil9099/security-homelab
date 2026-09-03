# What's redacted in `config.xml`

`config.xml` is the committed source-of-truth but it is **sanitised**. Before restoring it to a real
pfSense box you need to re-populate the following fields locally.

| XPath                                      | Placeholder                     | How to regenerate / re-enter                                          |
|--------------------------------------------|---------------------------------|-----------------------------------------------------------------------|
| `//bcrypt-hash`                            | `REDACTED-ADMIN-HASH`           | Leave as-is -> use console menu 3 to reset root password after boot    |
| `//user/md5-hash`, `sha1-hash`, `nt-hash`  | `REDACTED-*-HASH`               | Legacy user hashes; reset each user's password in *System -> User Manager* |
| `//system/user/authorizedkeys`             | `REDACTED-AUTHORIZED-KEYS`      | Re-paste each user's SSH public key in *System -> User Manager*        |
| `//cert/crt`, `//cert/prv`                 | `REDACTED-CERT-BODY` / `-PRIVATE-KEY` | Regenerated automatically on first boot (self-signed webConfigurator) |
| `//cert/refid`, `//ssl-certref`            | `REDACTED-CERT-REF`             | Rewritten when the webConfigurator certificate is regenerated          |
| `//ca/crt`, `//ca/prv`                     | `REDACTED-CA-BODY` / `-CA-KEY`  | Regenerate via *System -> Cert. Manager*                               |
| `//ppp/username`, `//ppp/password`         | `REDACTED-PPPOE-*`              | Re-enter ISP PPPoE credentials in *Interfaces -> WAN*                  |
| `//l2tp/secret`                            | `REDACTED-L2TP-SECRET`          | Re-enter in *VPN -> L2TP*                                              |
| `//ipsec//pre-shared-key`                  | `REDACTED-IPSEC-PSK`            | Re-enter in *VPN -> IPsec* for each tunnel                             |
| `//radius//secret`                         | `REDACTED-RADIUS-SECRET`        | Re-enter in *System -> User Manager -> Authentication Servers*         |
| `//authserver/ldap_bindpw`                 | `REDACTED-LDAP-BIND-PASSWORD`   | Re-enter the LDAP bind password in *Authentication Servers*            |
| `//notifications//smtp/password`           | `REDACTED-SMTP-PASSWORD`        | Re-enter in *System -> Advanced -> Notifications*                      |
| `//dyndns//password`                       | `REDACTED-DYNDNS-PASSWORD`      | Re-enter per provider in *Services -> Dynamic DNS*                     |
| `//snmpd/rocommunity`                      | `REDACTED-SNMP-COMMUNITY`       | Re-enter in *Services -> SNMP*                                         |
| `//openvpn//shared_key`, `//openvpn//tls`  | `REDACTED-OPENVPN-*`            | Regenerate per tunnel in *VPN -> OpenVPN*                              |
| `//wireguard//privatekey`                  | `REDACTED-WIREGUARD-PRIVATE-KEY`| Regenerate the tunnel keypair in *VPN -> WireGuard*                    |
| `//staticmap/mac`                          | `REDACTED-<HOSTNAME>-MAC`       | Re-enter the real NIC MAC from the named VM                            |
| `//wan/ipaddr` (static)                    | `REDACTED-WAN-IP`               | Only if your WAN isn't DHCP / PPPoE                                    |
| `//installedpackages//apikey`, `apitoken`  | `REDACTED-API-*`                | Regenerate in the package UI (pfBlockerNG, Suricata)                   |

Static-map MACs use a per-host placeholder derived from the entry's `<hostname>`
(`REDACTED-DC01-MAC`), so it is clear which VM's NIC each one belongs to. Entries
with no hostname fall back to `REDACTED-MAC`.

The `config.sanitise.sh` script in this directory automates the stripping — run it over any freshly
exported backup before committing. The table above and the script's XPath list are meant to stay in
step; if you add a field to one, add it to the other.

Two pre-commit hooks (`pfsense-bcrypt-redacted`, `pfsense-keys-redacted`) reject a commit whose
`config.xml` still carries a live hash, key or certificate — a backstop for the case where the
sanitiser was skipped, not a replacement for running it.

## Restoring

1. Install pfSense CE 2.7.x from ISO, assign WAN/LAN at the console wizard.
2. *Diagnostics → Backup & Restore → Restore configuration* → upload `config.xml`.
3. Box reboots.
4. Re-enter the credentials listed above.
5. Run `make -C ../ ansible-apply` to converge any drift.
