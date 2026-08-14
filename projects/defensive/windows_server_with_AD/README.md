# Windows Server + Active Directory

> IaC-driven Active Directory lab (`homelab.local`) for pentest / detection-engineering practice.
> Packer → Vagrant → Ansible stack — every OU, group, user and GPO lives in YAML under `ansible/vars/`.

Part of the **Defensive Security** track. Sits on the same `10.10.10.0/24` LAN as the pfSense lab, so the two wire together cleanly.

---

## Architecture

```
 ┌────────────────────────────────────────────────────────┐
 │                   Packer (optional)                    │
 │  autounattend.xml + scripts/enable-winrm.ps1           │
 │  └─► ws2022-homelab-{vmware,virtualbox}.box            │
 └────────────────────────────────────────────────────────┘
                          │
                          ▼
 ┌────────────────────────────────────────────────────────┐
 │                       Vagrant                          │
 │  DC01     (10.10.10.10)  — Windows Server 2022         │
 │  WKSTN01  (10.10.10.20)  — Windows 10/11 client        │
 │  host-only network: 10.10.10.0/24                      │
 └────────────────────────────────────────────────────────┘
                          │
                          ▼
 ┌────────────────────────────────────────────────────────┐
 │                       Ansible                          │
 │  windows_base        → hostname, static IP, WinRM      │
 │  ad_domain_controller → install AD-DS, dcpromo         │
 │  ad_users_groups     → OUs + groups + users from YAML  │
 │  ad_gpos             → password / audit / logon policy │
 │  domain_client       → DNS + domain-join               │
 └────────────────────────────────────────────────────────┘
```

See [`docs/topology.md`](docs/topology.md) for the full diagram.

---

## Directory layout

```
windows_server_with_AD/
├── Makefile                               # up / provision / users / smoke / destroy
├── packer/
│   ├── windows_server_2022.pkr.hcl        # WS2022 base box (optional)
│   ├── autounattend.xml
│   └── scripts/{enable-winrm,install-updates}.ps1
├── vagrant/
│   └── Vagrantfile                        # DC01 + WKSTN01, dual provider
├── ansible/
│   ├── ansible.cfg
│   ├── inventory.yml
│   ├── requirements.yml                   # microsoft.ad, ansible.windows, community.windows
│   ├── group_vars/all.yml
│   ├── host_vars/{dc01,wkstn01}.yml
│   ├── vars/                              # ← source of truth
│   │   ├── users.yml
│   │   ├── ous.yml
│   │   ├── groups.yml
│   │   └── gpos.yml
│   ├── playbooks/
│   │   ├── site.yml
│   │   ├── dc_promote.yml
│   │   ├── ad_baseline.yml
│   │   ├── client_join.yml
│   │   └── smoke.yml                      # read-only assertions
│   └── roles/
│       ├── windows_base/
│       ├── ad_domain_controller/
│       ├── ad_users_groups/
│       ├── ad_gpos/
│       └── domain_client/
└── docs/topology.md
```

---

## Quick-start

Prereqs on the host:
- **VMware Workstation 17** with the commercial `vagrant-vmware-desktop` provider + `vmware-desktop` plugin, **or** VirtualBox 7 as a free fallback
- Vagrant 2.4+, Packer 1.10+ (only if you want to rebuild the base box)
- Ansible 2.16+ running on WSL2 or a Linux VM (Ansible on Windows directly is not supported)
- `pywinrm` in the control host's Python (`pip install pywinrm`)

One-time:

```bash
cd ansible
# Create a vault file with the three required secrets.
ansible-vault create group_vars/all/vault.yml
# Inside the editor, write:
#   vault_domain_safe_mode_password: "<complex-string-14+-chars>"
#   vault_domain_admin_password:     "<complex-string-14+-chars>"
#   vault_user_initial_password:     "<complex-string-14+-chars>"
echo '<your-vault-password>' > .vault_pass       # git-ignored
export ANSIBLE_VAULT_PASSWORD_FILE=$(pwd)/.vault_pass
```

Boot and provision:

```bash
make collections        # pulls ansible collections into ansible/.collections
make up                 # boots DC01 + WKSTN01 and runs the provisioners
make smoke              # read-only assertions (users/OUs/groups/policy)
```

Change the provider with `make up PROVIDER=virtualbox`.

---

## Editing the lab

Everything that describes the lab's state is in `ansible/vars/`. Edit the YAML, re-apply:

```bash
make users              # re-runs ad_baseline.yml only (fast)
# or
make provision          # re-runs site.yml end-to-end
```

### Users

Defined in [`ansible/vars/users.yml`](ansible/vars/users.yml). The table below is derived from that file — if you edit one, update the other.

| Username        | Name          | Role               | OU       | Groups                                  |
|-----------------|---------------|--------------------|----------|-----------------------------------------|
| `alice.it`      | Alice Smith   | Helpdesk Analyst   | IT       | IT-Helpdesk                             |
| `bob.hr`        | Bob Johnson   | HR Assistant       | HR       | HR-Staff                                |
| `carol.finance` | Carol Bright  | Financial Analyst  | Finance  | Finance-Staff                           |
| `david.bright`  | David Bright  | Finance Manager    | Finance  | Finance-Staff, Finance-Managers         |

All users are created with `change_password_next_logon: true` and the initial password comes from the vault.

### OUs and groups

- `ansible/vars/ous.yml` — parents listed before children
- `ansible/vars/groups.yml` — `scope` (global/universal/domainlocal) + `category` (security/distribution)

### GPOs

`ansible/vars/gpos.yml` captures three baseline policies:

| Policy                       | Link target                    | What it enforces                                            |
|------------------------------|--------------------------------|-------------------------------------------------------------|
| Homelab - Password Policy    | `DC=homelab,DC=local`          | 14-char min, 24-entry history, 60-day max age, lockout @ 5  |
| Homelab - Login Restrictions | `OU=HQ,DC=homelab,DC=local`    | Screen-lock idle timeout, mandatory secure screen-saver      |
| Homelab - Audit Policy       | `DC=homelab,DC=local`          | Logon/logoff, account lockout, process creation, Kerberos   |

Password/lockout settings apply to the Default Domain Policy via `Set-ADDefaultDomainPasswordPolicy`. Registry-backed settings go through `Set-GPRegistryValue`. Advanced audit subcategories go through `AuditPol.exe`.

---

## Suggested exercises (what this lab unlocks)

Detection-side:
- Forward DC01's Security + Sysmon log to the `splunk/` or `siem_log_pipeline/` projects and write detections for the TTPs you run below.
- Use `attack_chain_correlator/` against the resulting event stream.

Attack-side:
- Password spraying from WKSTN01 → validate the lockout threshold (Homelab - Password Policy) kicks in at 5 failures.
- Kerberoasting: set an SPN on `carol.finance`, request a service ticket with Rubeus, crack offline.
- AS-REP roasting: toggle "Do not require Kerberos pre-authentication" on a test account, grab the hash with impacket `GetNPUsers.py`.
- LDAP reconnaissance with `projects/offensive/ad_enum/`.
- GPO abuse: write a malicious GPP XML, apply via SharpGPOAbuse.

---

## Troubleshooting

- **WinRM timeouts on Packer / first `vagrant up`**: the base box's WinRM listener is on 5986 with a self-signed cert — `ansible.cfg` already sets `ansible_winrm_server_cert_validation=ignore`. If you rebuilt the box yourself, verify `scripts/enable-winrm.ps1` ran by opening `C:\Windows\Panther\UnattendGC\setupact.log` inside the VM.
- **`The network path was not found` during domain-join**: WKSTN01 couldn't resolve `homelab.local` — check DC01 is booted *and* `ansible/group_vars/all.yml → dns_servers` is correctly pinned to the DC.
- **Vagrant + VMware Workstation on Windows 11 with Hyper-V enabled**: disable Hyper-V (`bcdedit /set hypervisorlaunchtype off` + reboot) or switch to VirtualBox. They can't share the virt layer.

---

## Next steps (out of scope here)

- Forward logs into `splunk/` and write detections for the exercises above
- Publish the Packer box to Vagrant Cloud for faster provisioning
- Add a second DC (DC02) and test replication break-fix
