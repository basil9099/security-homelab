# Security Homelab

[![CI](https://github.com/basil9099/security-homelab/actions/workflows/ci.yml/badge.svg)](https://github.com/basil9099/security-homelab/actions/workflows/ci.yml)
[![Detection behaviour tests](https://github.com/basil9099/security-homelab/actions/workflows/detections.yml/badge.svg)](https://github.com/basil9099/security-homelab/actions/workflows/detections.yml)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)](https://github.com/pre-commit/pre-commit)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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
| [Splunk Detection Engineering](projects/defensive/splunk/) | Onboarding Windows telemetry into Splunk, verifying ingestion, and building detections as code — four ATT&CK-mapped rules with automated tests, plus an end-to-end SMB brute-force walkthrough | Splunk, Universal Forwarder, SPL |
| [Windows Server + Active Directory](projects/defensive/windows_server_with_AD/) | An AD domain built from scratch with infrastructure-as-code | Packer, Vagrant, Ansible |
| [pfSense Firewall](projects/defensive/pfsense_firewall/) | Network segmentation, firewall rules, and IDS managed as code, with a sanitized config as source of truth | pfSense, Ansible, Suricata |

### Offensive

| Project | What it is | Key tech |
|---|---|---|
| [Honeypot](projects/offensive/honeypot/) | Multi-protocol honeypot (SSH/HTTP/FTP/Telnet) with a live dashboard | Python, Paramiko |
| [Network Vulnerability Scanner](projects/offensive/network-vulnerability-scanner/) | Port scanning, banner grabbing, and CVE lookup with reporting | Python, Nmap, NVD |
| [LLM Injection Lab](https://github.com/basil9099/llm-injection-lab) | Prompt-injection red-team harness measuring LLM application defenses across three hardening tiers | Python, garak, Ollama, FastAPI |

## The Lab

These projects are pieces of one lab. Offensive tools and AD attack chains — run
against a [GOAD-Light](https://github.com/Orange-Cyberdefense/GOAD) deployment —
generate realistic activity, which flows through the network and endpoint sensors
into Splunk for detection.

![Layered defensive architecture: simulated adversary tooling feeds perimeter and endpoint sensors, which forward telemetry to Splunk. Only the Windows Security event log feed is implemented today; the other flows are illustrative.](docs/diagrams/defensive-architecture.svg)

- [Defensive architecture](docs/defensive-architecture.md) — how the pieces connect
- [Network topology](projects/defensive/pfsense_firewall/docs/topology.md) — the physical VM/network layout

## Links

- **HackTheBox:** [basil9099](https://profile.hackthebox.com/profile/019d7feb-62bf-71b2-91b4-3f2626fb6acf)
- **Blog:** [basil9099.github.io](https://basil9099.github.io)
- **LinkedIn:** [Angus Dawson](https://www.linkedin.com/in/angus-dawson-92b035249)

---

> Everything here runs in an isolated home lab, for learning and educational purposes only.
