# Nexus Tracer

**Network Discovery Automation Suite** — A comprehensive L2/L3 network tracing tool for enterprise firewalls (Palo Alto Networks, Check Point) that autonomously maps network topology and identifies edge devices.

## Features

- **Multi-Vendor Support**: Automatically detect and handle Palo Alto Networks and Check Point firewalls
- **Autonomous Discovery**: Scan multiple firewalls from a single input file with automatic vendor identification
- **L2/L3 MAC Tracing**: Trace MAC addresses through Cisco switch networks using MAC tables and CDP
- **Loop Detection & Mitigation**: Intelligent detection and handling of routing loops with ARP fallback
- **CDP Intelligence**: Leverage Cisco Discovery Protocol to identify adjacent devices
- **Interface Enumeration**: Automatic interface discovery on Check Point firewalls via Expert mode
- **Unified Reporting**: Generate comprehensive CSV reports with all discovery details
- **Credential Management**: Central vault system with support for multiple credentials per device type

## Requirements

- **Python**: 3.8+
- **Operating System**: macOS, Linux, Windows
- **Network Access**: SSH connectivity to firewalls and switches

### Dependencies

- `paramiko` - SSH client library
- `netmiko` - Network device connectivity
- `getpass` - Secure password input
- `logging` - Application logging
- `csv` - Report generation

## Installation

1. **Clone or download** the repository
2. **Create a virtual environment** (recommended):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # macOS/Linux
   # or
   .venv\Scripts\activate  # Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install paramiko netmiko
   ```

4. **Verify installation**:
   ```bash
   python NexusTracer.py
   ```

## Usage

### Quick Start

1. **Create firewall list** (`firewalls.txt`):
   ```
   # Comma-separated list of firewall IPs
   192.168.1.1
   192.168.1.2
   10.0.0.50
   ```

2. **Run the application**:
   ```bash
   python NexusTracer.py
   ```

3. **Select option 1** for "Autonomous Unified Discovery"

4. **Provide credentials** when prompted:
   - Check Point user and password
   - Expert password (for Check Point Expert mode)
   - Palo Alto user and password
   - Cisco switch user and password

5. **Review results**:
   - Console output displays scan progress
   - `unified_discovery_report.txt` - Human-readable report
   - `unified_discovery_report.csv` - Excel-compatible data

### Credential Handling

- Credentials are stored in memory during the session
- Application supports multiple credentials per device type
- Failed credentials trigger interactive prompts for new credentials
- All SSH sessions use timeout protection (15 seconds)

### Network Trace Flow

```
Firewall (PA/CP)
    ↓
[Extract MAC, Default Gateway]
    ↓
Default Gateway Switch (L2)
    ↓
[Query MAC Table]
    ↓
[Find CDP Neighbor]
    ↓
Next Switch in Chain
    ↓
[Loop Detection/Mitigation]
    ↓
Edge Switch Reached
    ↓
[Report Target Device Details]
```

## Output Files

### unified_discovery_report.txt
Human-readable formatted table with:
- Firewall IP and vendor
- Connection status
- Target device hostname and port
- Target device IP and model
- Target device version

### unified_discovery_report.csv
CSV export containing:
- FW_IP, FW_Hostname, Vendor, Status
- Target_Device, Target_Port, Target_IP
- Target_Model, Target_Version

### nexus_tracer.log
Application logs for debugging:
- Connection attempts
- Authentication events
- CDP discovery details
- Error traces

## Architecture

### Core Classes

**Utils**
- Screen clearing and buffer management
- User input validation
- MAC address formatting for Cisco
- Interactive prompts

**CredentialVault**
- Centralized credential storage
- Separate vaults for PA, Switches, Check Point
- Credential deduplication

**ReportGenerator**
- Unified CLI report formatting
- CSV export with field normalization
- File I/O for reports

**CiscoTracer**
- L2/L3 MAC address tracing
- Hop limit enforcement (20 max)
- Loop detection and mitigation
- CDP neighbor analysis
- Port-channel resolution
- Interface parsing and validation

**PaloAltoNode**
- SSH-based system info retrieval
- MAC and default gateway extraction
- Integration with CiscoTracer
- Keepalive ping support

**CheckPointNode**
- Expert mode authentication
- tcpdump-based CDP capture
- Session timeout handling
- Interface enumeration
- CDP packet parsing

**NexusTracerApp**
- Main application orchestrator
- Multi-firewall batch processing
- Automated vendor identification
- Credential retry logic
- Result aggregation

## Error Handling

The application includes comprehensive error handling for:
- **Authentication Failures**: Retry mechanism with credential prompt
- **Connection Timeouts**: Graceful timeout with user notification
- **Network Errors**: Error classification and reporting
- **Session Drops**: Automatic reconnection attempts
- **Parsing Failures**: Fallback mechanisms and detailed logging
- **Loop Detection**: Routing loop identification and mitigation
- **Resource Cleanup**: Guaranteed connection closure in all scenarios

## Troubleshooting

### Connection Refused
- Verify firewall IP is correct and reachable
- Check SSH service is enabled on firewall
- Confirm network connectivity

### Authentication Failed
- Verify username and password are correct
- Check user permissions for required commands
- Some commands may require admin level access

### No CDP Packets Found
- Verify switch has CDP enabled
- Check interface is not configured to drop CDP
- Try alternate interface selection when prompted
- Some enterprise networks may restrict CDP

### Timeout Errors
- Increase timeout values if network is slow
- Verify network latency to devices
- Check firewall response times

### Missing MAC/ARP
- Device may not have sent traffic recently
- Try triggering traffic (ping) from device
- Verify MAC address format is correct

## Logging

Enable detailed logging by checking `nexus_tracer.log`:
- Log level: INFO
- Format: `[TIMESTAMP] - [LEVEL] - MESSAGE`
- Rotate logs manually or use external log rotation

## Performance Considerations

- **Hop Limit**: Max 20 hops to prevent infinite loops
- **CDP Timeout**: 75 seconds per interface
- **SSH Timeout**: 15 seconds per connection attempt
- **Parallel Processing**: Processes one firewall at a time (sequential)

## Security Notes

- Passwords are **not** stored on disk
- Credentials remain in memory only during session
- All SSH connections use standard authentication (no key auth yet)
- Log file may contain IP addresses and device names

## Limitations

- Single-threaded execution (one firewall at a time)
- CDP dependency for switch-to-switch discovery
- Check Point requires Expert mode access
- No support for VPC or AWS environments
- Cisco IOS only (no IOS-XE/NX-OS optimization)

## Future Enhancements

- [ ] Parallel firewall scanning
- [ ] SSH key authentication support
- [ ] Multiple switch vendor support (Arista, Juniper)
- [ ] VPC and cloud network support
- [ ] Web UI dashboard
- [ ] Database backend for historical data
- [ ] API endpoint for automation
- [ ] Snapshot comparison and diff reporting

## Support

For issues or feature requests, check the application logs and verify:
1. Network connectivity to all devices
2. Correct credentials for all device types
3. SSH service availability on firewalls
4. CDP enabled on switches

## License

Created by Ariel

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.
