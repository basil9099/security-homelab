# pfSense Firewall — IaC-driven perimeter

> Network perimeter for the homelab. `config.xml` is the committed source of truth for
> the initial restore; day-2 drift is managed with the `pfsensible.core` Ansible collection.

Part of the **Defensive Security** track. Segments the `10.10.10.0/24` user LAN from the
`10.10.20.0/24` admin/observability MGMT network, and wires directly into the Windows AD
lab (`projects/defensive/windows_server_with_AD/`).

---

## How the IaC works

```
┌────────────────────────────────────────────────┐
│  Initial bootstrap (once per fresh install)    │
│    1. Install pfSense CE 2.7.x from ISO        │
│    2. Assign WAN / LAN / OPT1 at console       │
│    3. Enable SSH + key-only auth in WebGUI     │
│    4. Restore config/config.xml                │
│       (docs/bootstrap.md walks through this)   │
└────────────────────────────────────────────────┘
                       │
                       ▼
┌────────────────────────────────────────────────┐
│  Day-2 management (every change from now on)   │
│    ansible-playbook playbooks/site.yml         │
│      • aliases + filter rules                  │
│      • DHCP scopes + static mappings           │
│      • pfBlockerNG + Suricata + ntopng         │
└────────────────────────────────────────────────┘
```

- `config/config.xml` — sanitised, committed. Captures interfaces, default rules, bootstrap DHCP.
- `config/sanitise_config.py` — strips password hashes, certs, PPPoE creds, MACs before commit.
- `config/REDACTIONS.md` — what's stripped and how to re-populate.
- `ansible/` — everything that changes during a lab session.

---

## Directory layout

```
pfsense_firewall/
├── config/
│   ├── config.xml              # committed source of truth (sanitised)
│   ├── sanitise_config.py      # strip secrets from an exported backup
│   └── REDACTIONS.md           # what the sanitiser removes + how to re-populate
├── tests/                      # pytest cover for the sanitiser
├── conftest.py
└── requirements-dev.txt
├── ansible/
│   ├── ansible.cfg
│   ├── requirements.yml        # pfsensible.core
│   ├── inventory.yml
│   ├── group_vars/all.yml      # network layout constants
│   ├── vars/
│   │   ├── aliases.yml         # reusable host / network / port groups
│   │   ├── rules.yml           # filter rules (ordered, top-matching)
│   │   ├── dhcp.yml            # scopes + static mappings
│   │   └── packages.yml        # pfBlockerNG, Suricata, ntopng
│   └── playbooks/
│       ├── site.yml            # full convergence
│       ├── firewall_baseline.yml
│       ├── dhcp_dns.yml
│       └── ids_packages.yml
└── docs/
    ├── topology.md             # Mermaid network diagram + segmentation rationale
    └── bootstrap.md            # step-by-step first install
```

---

## Lab hardware

| Component | Details |
|---|---|
| Hypervisor | VMware Workstation 17.x (Windows host) |
| Guest OS | pfSense CE 2.7.2-RELEASE |
| vCPU / RAM | 2 vCPU • 2 GiB RAM |
| Disk | 20 GB thin-provisioned `.vmdk` |
| NIC 1 (WAN) | Bridged → `vmnet0` |
| NIC 2 (LAN) | Host-Only → `vmnet2` (10.10.10.0/24) |
| NIC 3 (MGMT) | Host-Only → `vmnet3` (10.10.20.0/24) |
| NIC type | VMXNET 3 |

Full walkthrough in [`docs/bootstrap.md`](docs/bootstrap.md).

---

## Quick-start

```bash
# 1) Install + console wizard + enable SSH (key-only)  -> see docs/bootstrap.md
# 2) Restore committed config:
#      WebGUI -> Diagnostics -> Backup & Restore -> upload config/config.xml
# 3) Re-enter redacted fields                          -> see config/REDACTIONS.md
# 4) Converge with Ansible:
cd ansible
ansible-galaxy collection install -r requirements.yml -p ./.collections
ansible-playbook playbooks/site.yml --check   # dry-run
ansible-playbook playbooks/site.yml
```

## Making changes

Edit the YAML, re-run the playbook. Never click in the WebGUI for anything that's expressed in
`ansible/vars/` — the next apply will undo it.

| Change                 | Edit                                  | Apply                                               |
|------------------------|---------------------------------------|-----------------------------------------------------|
| Add a firewall rule    | `ansible/vars/rules.yml`              | `ansible-playbook playbooks/firewall_baseline.yml`  |
| New DHCP static map    | `ansible/vars/dhcp.yml`               | `ansible-playbook playbooks/dhcp_dns.yml`           |
| Install a package      | `ansible/vars/packages.yml`           | `ansible-playbook playbooks/ids_packages.yml`       |
| Everything             | —                                     | `ansible-playbook playbooks/site.yml`               |

## Segmentation model

See [`docs/topology.md`](docs/topology.md) — LAN is the everyday subnet, MGMT is locked
down, `LAN → MGMT` is explicitly blocked so detection engineering works against a
realistic segmented network.

---

## Updating the committed `config.xml`

Only do this when you've made a structural change that Ansible doesn't manage yet (interface
assignment, initial DHCP scope, unbound config). Round-trip:

```bash
# On the pfSense box: Diagnostics -> Backup & Restore -> Download configuration
# Save as /tmp/config-exported.xml
python config/sanitise_config.py /tmp/config-exported.xml > config/config.xml
git diff config/config.xml                                 # review every change
git add config/config.xml && git commit
```

The sanitiser is the gatekeeper — it must run before commit. It is stdlib-only Python, so it runs
anywhere without extra packages, and `pytest` in this directory covers it. Two pre-commit hooks
(`pfsense-bcrypt-redacted`, `pfsense-keys-redacted`) reject a commit whose `config.xml` still carries
a live hash, key or secret — a backstop for a skipped run, not a replacement for it.

The tool is idempotent: running it over the committed `config.xml` reproduces that file byte for
byte, so drift between the script and the file it is supposed to produce shows up as a diff.

---

## Suggested exercises

- Trigger a pfBlockerNG DNSBL hit from WKSTN01 → confirm it appears in the Suricata / pfBlockerNG logs (and in Splunk if you forward them)
- Port-scan across the LAN→MGMT boundary and verify the block rule + Suricata alerts
- Simulate a DNS tunnel from WKSTN01 and detect it with Suricata + the Unbound query log
- Use `../../offensive/network-vulnerability-scanner/` against the pfSense WAN — default deny should return nothing
