# Security Homelab

> A hands-on lab where I build and break things to learn practical cybersecurity —
> detection engineering, Active Directory, network defense, and offensive tooling.

I'm building practical security skills as I move into the field. This repo collects
the projects and labs I've built and documented along the way, with a focus on the
blue-team side — getting telemetry into a SIEM, writing detections, and hardening
infrastructure — plus the offensive tooling I use to generate realistic activity to
detect against.

## Projects

### Defensive

| Project | What it is | Key tech |
|---|---|---|
| [Splunk Detection Engineering](projects/defensive/splunk/) | Onboarding Windows/Sysmon telemetry into Splunk, verifying ingestion, and building detections — including an end-to-end SMB brute-force detection | Splunk, Sysmon, Universal Forwarder, SPL |
| [Windows Server + Active Directory](projects/defensive/windows_server_with_AD/) | An AD domain built from scratch with infrastructure-as-code | Packer, Vagrant, Ansible |
| [pfSense Firewall](projects/defensive/pfsense_firewall/) | Network segmentation, firewall rules, and IDS managed as code, with a sanitized config as source of truth | pfSense, Ansible, Suricata |

### Offensive

| Project | What it is | Key tech |
|---|---|---|
| [Honeypot](projects/offensive/honeypot/) | Multi-protocol honeypot (SSH/HTTP/FTP/Telnet) with a live dashboard | Python, Paramiko |
| [Network Vulnerability Scanner](projects/offensive/vulnerability_scanner/) | Port scanning, banner grabbing, and CVE lookup with reporting | Python, Nmap, NVD |
| [HackTheBox Writeups](projects/offensive/htb_writeups/) | Documented walkthroughs of retired HTB machines and homelab exercises | — |

## The Lab

These projects are pieces of one lab. Offensive tools and AD attack chains — run
against a [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) deployment —
generate realistic activity, which flows through the network and endpoint sensors
into Splunk for detection.

- [Defensive architecture](docs/defensive-architecture.md) — how the pieces connect
- [Network topology](docs/diagrams/lab-network.mmd) — the physical VM/network layout

## Links

- **HackTheBox:** [basil9099](https://profile.hackthebox.com/profile/019d7feb-62bf-71b2-91b4-3f2626fb6acf)
- **Blog:** [basil9099.github.io](https://basil9099.github.io)
- **LinkedIn:** [Angus Dawson](https://www.linkedin.com/in/angus-dawson-92b035249)

---

> Everything here runs in an isolated home lab, for learning and educational purposes only.
