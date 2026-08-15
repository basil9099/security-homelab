# Multi-Protocol Honeypot System

A modular, multi-protocol honeypot system designed for cybersecurity home labs. Emulates SSH, HTTP, FTP, and Telnet services to capture attacker behavior, credentials, and command sequences.

---

## Architecture

```
                    +------------------+
                    |    main.py       |
                    |  CLI / Banner    |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+          +--------v--------+
     |  Protocol        |          |  Demo            |
     |  Handlers        |          |  Simulator       |
     |  (threaded)      |          |  (fake traffic)  |
     +--------+---------+          +--------+---------+
              |                             |
              +-------------+---------------+
                            |
                   +--------v--------+
                   |  EventLogger     |
                   |  (JSONL + queue) |
                   +--------+--------+
                            |
              +-------------+-------------+
              |                           |
     +--------v--------+        +--------v--------+
     | honeypot_events  |        |  Dashboard      |
     | .jsonl log file   |        |  (Rich live)    |
     +------------------+        +-----------------+
```

## Project Structure

```
honeypot/
├── main.py                  # CLI entry point and orchestration
├── config.py                # YAML configuration loader
├── models.py                # HoneypotEvent dataclass
├── honeypot.yaml            # Default configuration
├── requirements.txt         # Python dependencies
├── protocols/
│   ├── base.py              # Abstract handler base + registry
│   ├── ssh.py               # SSH honeypot (paramiko)
│   ├── http.py              # HTTP honeypot (fake Apache)
│   ├── ftp.py               # FTP honeypot (state machine)
│   └── telnet.py            # Telnet honeypot (fake shell)
├── event_logging/
│   └── event_logger.py      # Thread-safe JSONL logger
├── dashboard/
│   └── live.py              # Rich terminal dashboard
└── demo/
    └── simulator.py         # Attack traffic simulator
```

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run with simulated attacks and live dashboard
python main.py --demo --dashboard

# Start all real protocol handlers
python main.py

# Start with dashboard
python main.py --dashboard

# Only enable specific protocols
python main.py --protocols ssh http
```

---

## Features

### Multi-Protocol Emulation

| Protocol | Port | Emulates | Captures |
|----------|------|----------|----------|
| SSH      | 2222 | OpenSSH 8.9 | Credentials, shell commands |
| HTTP     | 8080 | Apache 2.4 + WordPress | Requests, form credentials, scanning patterns |
| FTP      | 2121 | ProFTPD 1.3.5 | Credentials, file operations |
| Telnet   | 2323 | Ubuntu 22.04 | Credentials, shell commands |

### JSON Structured Logging

All events are logged as JSON lines (`.jsonl`) for easy parsing and SIEM ingestion:

```json
{
  "event_id": "a1b2c3d4e5f6",
  "timestamp": "2026-03-24T14:23:01.123456+00:00",
  "protocol": "ssh",
  "src_ip": "185.220.101.42",
  "src_port": 48221,
  "dst_port": 2222,
  "event_type": "credential_attempt",
  "credentials": {"username": "root", "password": "toor"},
  "payload": "",
  "session_id": "sess_abc123",
  "metadata": {"auth_method": "password"}
}
```

### Live Terminal Dashboard

Three-panel Rich dashboard showing:
- Summary statistics (total events, per-protocol counts, uptime)
- Scrolling event feed with color-coded protocols and event types
- Top attacker IPs and most-targeted usernames

### Demo Mode

Generate realistic simulated attack traffic without real attackers:
- SSH brute-force campaigns with common credential lists
- HTTP scanning and WordPress login attempts
- FTP credential stuffing and directory traversal
- Telnet botnet-style login attempts

### Plugin Architecture

Adding a new protocol handler is a single-file operation:

```python
from protocols.base import ProtocolHandler, register

@register
class MyProtocolHandler(ProtocolHandler):
    PROTOCOL_NAME = "myproto"

    def start(self) -> None:
        # Your listener implementation
        ...
```

---

## Configuration

Edit `honeypot.yaml` to customize ports, banners, and behavior:

```yaml
protocols:
  ssh:
    enabled: true
    port: 2222
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  http:
    enabled: true
    port: 8080
    banner: "Apache/2.4.41 (Ubuntu)"

logging:
  file: "honeypot_events.jsonl"

dashboard:
  refresh_rate: 0.5

demo:
  duration: 60
  rate: 2.0
```

---

## CLI Options

```
usage: main.py [-h] [--config CONFIG] [--demo] [--dashboard]
               [--protocols PROTO [PROTO ...]] [--log-file LOG_FILE]
               [--duration DURATION] [--json]

Options:
  --config, -c     Path to YAML config file (default: honeypot.yaml)
  --demo           Run with simulated attack traffic
  --dashboard      Enable live terminal dashboard
  --protocols      Only enable specific protocols (e.g. ssh http)
  --log-file       Override log file path
  --duration       Run for N seconds then exit
  --json           Print events as JSON to stdout
```

---

## Testing

```bash
# SSH: connect and try credentials
ssh -o StrictHostKeyChecking=no -p 2222 root@localhost

# HTTP: probe common attack paths
curl http://localhost:8080/wp-login.php
curl http://localhost:8080/.env
curl http://localhost:8080/phpmyadmin

# FTP: attempt login
ftp localhost 2121

# Telnet: connect and interact
nc localhost 2323

# Verify logs
cat honeypot_events.jsonl | python -m json.tool --no-ensure-ascii
```

---

## Port Forwarding (Optional)

To listen on standard ports without root, use iptables:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2323
```

---

## Dependencies

- **paramiko** - SSH protocol emulation
- **rich** - Terminal dashboard rendering
- **pyyaml** - Configuration file parsing
- **colorama** - Cross-platform colored output

---

## Legal Disclaimer

This tool is intended for authorized security testing and educational purposes only. Deploy only on networks you own or have explicit permission to monitor. Unauthorized use against systems you do not own is illegal.
