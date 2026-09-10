# Topology

![Active Directory lab topology: a pfSense gateway fronts a single flat LAN holding the DC01 domain controller and the domain-joined WKSTN01 workstation, which authenticates against DC01 over Kerberos, LDAP and SMB.](diagrams/ad-topology.svg)

<sub>Source: [`diagrams/ad-topology.html`](diagrams/ad-topology.html)</sub>

## Host roles

| Host    | IP          | Role                    | OS                   |
|---------|-------------|-------------------------|----------------------|
| DC01    | 10.10.10.10 | Domain Controller       | Windows Server 2022  |
| WKSTN01 | 10.10.10.20 | Domain-joined client    | Windows 10/11        |
| pfSense | 10.10.10.1  | Gateway / DHCP / DNS    | pfSense CE 2.7.x     |

## Why 10.10.10.0/24

Matches the subnet defined in `projects/defensive/pfsense_firewall/` so the two labs
run side-by-side on a single VMware host-only network (`vmnet2`).
