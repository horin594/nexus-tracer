# Changelog

All notable changes to Nexus Tracer will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-04-05

### Added
- Comprehensive error handling validation
- Session state verification before sending commands
- Interface retry limit (3 max attempts) to prevent infinite loops
- Automatic session reconnection on timeout
- Enhanced logging for troubleshooting

### Fixed
- **Critical**: Shell variable initialization in PaloAltoNode - prevents AttributeError on exception
- **Critical**: Connection cleanup in identify_vendor() - ensures all SSH sessions are properly closed
- **Critical**: Infinite loop in CheckPoint tcpdump interface selection
- **High**: Missing shell cleanup in Palo Alto exception handlers
- **High**: Uninitialized node variable check before execution
- **Medium**: Session alive verification before command transmission
- **Medium**: Race condition in loop mitigation (visited_ips set management)
- **Medium**: Command transmission error handling with reconnection fallback
- **Critical**: IndexError in CiscoTracer caused by naked network exceptions, fixed with safe splitlines fallback

### Changed
- identify_vendor() now creates client inside loop for better resource management
- CheckPoint execute_scan() tcpdump loop now enforces max interface attempts
- Added safety checks for all node assignments before execute_scan() calls
- Improved exception messages with specific error classifications

### Improved
- Resource cleanup guarantees (finally blocks on all SSH connections)
- Shell session state validation before operations
- Better timeout handling with reconnection logic
- Enhanced credential retry mechanism
- Optimized identify_vendor() speed by using micro-polling and instant shell transmission (up to 5x faster)
- Decreased identify_vendor timeout from 8s to 5s to avoid unnecessary hanging on failed auth attempts

## [1.0.0] - 2026-03-15

### Added
- Initial release of Nexus Tracer
- Multi-vendor firewall support (Palo Alto Networks, Check Point)
- Autonomous network discovery engine
- L2/L3 MAC address tracing through Cisco switches
- Unified credential vault system
- CSV report generation
- CDP-based device discovery
- Loop detection and mitigation
- Port-channel resolution
- Interface enumeration for Check Point
- Comprehensive logging system

### Features
- **Palo Alto Support**
  - SSH system info retrieval
  - MAC address extraction
  - Default gateway detection
  - Integration with Cisco tracer

- **Check Point Support**
  - Expert mode access
  - tcpdump CDP packet capture
  - Interface enumeration from sysfs
  - Session timeout handling

- **Cisco Switch Support**
  - MAC table querying
  - ARP table fallback
  - CDP neighbor discovery
  - Port-channel to physical port resolution
  - Loop detection with ARP mitigation

- **Reporting**
  - CLI formatted output
  - CSV exports for Excel
  - Detailed logging to file

### Known Limitations
- Single-threaded execution
- Requires CDP on Cisco switches
- Check Point Expert password required
- Maximum hop limit of 20
- 75-second timeout per CDP capture attempt

## [0.9.0] - 2026-03-01

### Added
- Beta version with core functionality
- Basic firewall identification
- Initial credential management
- Early version of report generator

### Fixed
- Shell buffer handling issues
- Early credential validation problems
- Initial connection timeout tuning

### Known Issues
- Occasional SSH session hangs
- Missing error handling in some code paths
- Incomplete resource cleanup
- No retry mechanism for failed interface attempts
- Potential race conditions in loop detection

---

## Migration Guide

### From 1.0.0 to 1.1.0

No breaking changes. Update is recommended for improved stability.

**Before updating:**
- Backup any existing `nexus_tracer.log` files if needed
- Note current credentials (they are not stored between sessions anyway)

**After updating:**
- Review log file for any errors from previous sessions
- All existing scripts and automations remain compatible

---

## Planned Releases

### [1.2.0] - Planned
- [ ] Parallel firewall scanning (threading)
- [ ] SSH key authentication support
- [ ] Extended switch vendor support
- [ ] Config file support (.ini/.yaml)
- [ ] Improved error messages

### [2.0.0] - Planned
- [ ] REST API endpoints
- [ ] Web UI dashboard
- [ ] Database backend (SQLite)
- [ ] Historical data tracking
- [ ] Advanced reporting and visualization
- [ ] Multi-protocol support

---

## Support

For issues related to specific versions, please reference the relevant section above.

- **Critical Issues**: Fix priority, included in next patch
- **High Issues**: Included in next minor release
- **Medium/Low Issues**: Included as time permits

---

## Contributors

- **Ariel** - Creator and lead developer

---

## Release Notes

### Version 1.1.0 Stability Notes

This version includes significant improvements to error handling and resource management:

1. **Connection Management**: All SSH connections are now guaranteed to close, even in error scenarios
2. **Session Verification**: Improved detection of dropped sessions with automatic reconnection
3. **Loop Prevention**: Interface retry limit prevents hanging on unresponsive firewalls
4. **Error Recovery**: Better handling of authentication failures and timeouts

**Testing Recommendations:**
- Test with multiple firewall types in sequence
- Verify log file generation and content
- Check report generation with varied device configurations
- Confirm cleanup of previous sessions

**Upgrade Recommendation**: ✅ **Highly Recommended** for production deployments
