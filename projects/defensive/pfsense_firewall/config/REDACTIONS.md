# What's redacted in `config.xml`

`config.xml` is the committed source-of-truth but it is **sanitised**. Before restoring it to a real
pfSense box you need to re-populate the following fields locally.

| XPath                                      | Placeholder                | How to regenerate / re-enter                                        |
|--------------------------------------------|----------------------------|---------------------------------------------------------------------|
| `//bcrypt-hash`                            | `REDACTED-ADMIN-HASH`      | Leave as-is → use console menu 3 to reset root password after boot  |
| `//cert/crt`, `//cert/prv`                 | `REDACTED-CERT-*`          | Regenerated automatically on first boot (self-signed webConfigurator) |
| `//ca/crt`, `//ca/prv`                     | `REDACTED-CA-*`            | Regenerate via *System → Cert. Manager*                             |
| `//ppp/username`, `//ppp/password`         | `REDACTED-PPPOE-*`         | Re-enter ISP PPPoE credentials in *Interfaces → WAN*                |
| `//ipsec//pre-shared-key`                  | `REDACTED-IPSEC-PSK`       | Re-enter in *VPN → IPsec* for each tunnel                           |
| `//radius//secret`                         | `REDACTED-RADIUS-SECRET`   | Re-enter in *System → User Manager → Authentication Servers*        |
| `//staticmap/mac`                          | `REDACTED-MAC`             | Re-enter the real NIC MAC from each VM                              |
| `//wan/ipaddr` (static)                    | `REDACTED-WAN-IP`          | Only if your WAN isn't DHCP / PPPoE                                 |
| `//installedpackages//apikey`, `apitoken`  | `REDACTED-API-*`           | Regenerate in the package UI (pfBlockerNG, Suricata)                |

The `config.sanitise.sh` script in this directory automates the stripping — run it over any freshly
exported backup before committing.

## Restoring

1. Install pfSense CE 2.7.x from ISO, assign WAN/LAN at the console wizard.
2. *Diagnostics → Backup & Restore → Restore configuration* → upload `config.xml`.
3. Box reboots.
4. Re-enter the credentials listed above.
5. Run `make -C ../ ansible-apply` to converge any drift.
