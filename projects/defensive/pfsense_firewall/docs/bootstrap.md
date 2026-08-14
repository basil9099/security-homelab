# Bootstrap — ISO → running firewall

Step-by-step for a fresh pfSense CE 2.7.x install in VMware Workstation 17.

## 1. VM shell

| Setting | Value |
|---|---|
| vCPUs / RAM | 2 / 2 GiB |
| Disk | 20 GB thin-provisioned `.vmdk` |
| NIC 1 (WAN) | Bridged → `vmnet0` |
| NIC 2 (LAN) | Host-Only → `vmnet2` (10.10.10.0/24) |
| NIC 3 (MGMT) | Host-Only → `vmnet3` (10.10.20.0/24) |
| NIC type | **VMXNET 3** (VM → Settings → Advanced) |

Attach `pfSense-CE-2.7.2-RELEASE-amd64.iso` to the VM's CD/DVD drive and tick *Connected at power-on*.

## 2. Text installer prompts

| Prompt | Choice |
|---|---|
| Keymap | Default / US |
| Install mode | Guided — **UFS (GPT/UEFI Hybrid)** |
| Target disk | `da0` 20 GB *VMware Virtual S* |
| RAM warning | Proceed anyway (2 GiB is fine) |
| Root password | Set a strong password — you'll replace it on restore |
| Post-install | Eject the ISO → reboot |

## 3. Interface assignment (console menu 1)

| Role  | NIC   | VMware switch | Post-wizard IP |
|-------|-------|--------------|----------------|
| WAN   | `vmx0` | vmnet0 (Bridged) | DHCP from home router |
| LAN   | `vmx1` | vmnet2 (Host-Only) | 10.10.10.1/24 |
| OPT1  | `vmx2` | vmnet3 (Host-Only) | 10.10.20.1/24 (set via WebGUI) |

Console menu 2 → set LAN IP `10.10.10.1/24` and DHCP range `10.10.10.100 – 10.10.10.200`.

## 4. First WebGUI pass (bare-minimum, before restore)

Browse to `https://10.10.10.1/` from a host on the LAN:

1. Login with `admin` / root password you set.
2. Complete the setup wizard (hostname, domain, DNS, NTP).
3. *System → Advanced → Admin Access* → enable **Secure Shell** + **Authorized keys only**.
4. Paste the public half of `~/.ssh/homelab_pfsense_ed25519` into the `admin` user's authorized keys (*System → User Manager → admin → Edit*).

## 5. Restore the committed config

*Diagnostics → Backup & Restore → Restore configuration*

Upload `../config/config.xml`. The box reboots.

## 6. Fill in the redactions

See [`../config/REDACTIONS.md`](../config/REDACTIONS.md) — re-enter MAC addresses in DHCP static maps, regenerate the webConfigurator cert, re-enter PPPoE creds if you use PPPoE.

## 7. Hand off to Ansible

From your control host (WSL / Linux VM):

```bash
cd ../ansible
ansible-galaxy collection install -r requirements.yml -p ./.collections
ansible-playbook playbooks/site.yml --check     # dry-run — should show minimal drift
ansible-playbook playbooks/site.yml             # converge for real
```

From now on, any firewall rule / DHCP / package change goes through Ansible. Do NOT make changes
in the WebGUI — they will be overwritten on the next apply.
