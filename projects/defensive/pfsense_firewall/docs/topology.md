# pfSense Network Topology

```mermaid
flowchart LR
    INET((Internet)) --> WAN
    WAN["WAN<br/>vmx0 / vmnet0<br/>DHCP from home router"] --> PF{{pfSense CE 2.7.x}}
    PF --> LAN["LAN<br/>vmx1 / vmnet2<br/>10.10.10.0/24"]
    PF --> MGMT["OPT1 / MGMT<br/>vmx2 / vmnet3<br/>10.10.20.0/24"]

    LAN --> DC[DC01 10.10.10.10]
    LAN --> WS[WKSTN01 10.10.10.20]
    LAN --> DHCPPOOL["DHCP 10.10.10.100-200"]

    MGMT --> ADMIN[Admin jump host]
    MGMT --> SPLUNK[Splunk indexer 10.10.20.50]
```

## Segmentation rules (summary)

| From → To    | Default action | Notes                                                         |
|--------------|---------------|---------------------------------------------------------------|
| LAN  → WAN   | pass          | Default outbound                                              |
| LAN  → DC01  | pass (AD ports) | Kerberos, LDAP, SMB, GC — explicit allow                    |
| LAN  → MGMT  | **block**     | Users can't reach the admin network directly                 |
| MGMT → LAN   | pass          | Admin jump path                                               |
| MGMT → WAN   | pass          | Updates, threat-intel feeds                                   |
| WAN  → LAN   | block         | Default (no inbound NAT)                                     |
| WAN  → any RFC1918 source | block | Defence-in-depth with `blockpriv` on the WAN interface |

## Why two segments

Keeps detection/observability infra (SIEM, logs collector, admin browser) off the same broadcast
domain as the attack targets. Makes detection-engineering exercises realistic:
- Beacons from WKSTN01 have to egress *through* the firewall to reach C2, so they show up in Suricata + pfBlockerNG logs.
- An attacker who compromises WKSTN01 can't pivot to the Splunk indexer without punching through the LAN→MGMT block rule.
