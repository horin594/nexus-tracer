# Nexus Tracer

Network Discovery Automation Suite

## Features

- Multi-vendor firewall support (Palo Alto Networks, Check Point)
- Autonomous network discovery
- L2/L3 MAC tracing through Cisco switches
- Unified reporting (CSV/TXT)

## Requirements

- Python 3.8+
- paramiko
- netmiko

## Installation

```bash
pip install paramiko netmiko
```

## Usage

1. Create `firewalls.txt` with IP addresses
2. Run: `python NexusTracer.py`
3. Select option 1 for autonomous discovery
4. Provide credentials when prompted

## Output

- `unified_discovery_report.txt` - Text report
- `unified_discovery_report.csv` - CSV data
- `nexus_tracer.log` - Application logs

## Changelog

See CHANGELOG.md for version history.
