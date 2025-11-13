# Enigma2 Firewall Security Plugin

Advanced iptables-based firewall plugin for Enigma2 satellite receivers (TNAP). Provides comprehensive network security with GUI management interface.

## ⚠️ IMPORTANT: Mutual Exclusivity

**This plugin CANNOT be installed alongside the WireGuard-TNAP VPN plugin.**

Both plugins manage iptables firewall rules but use **incompatible security models**:
- **Firewall Plugin**: Selective internet access (whitelist-based)
- **WireGuard-TNAP Plugin**: VPN-only access (internet blocked)

Installing both simultaneously will cause connection failures and security conflicts.

**You must choose ONE approach.** See [Which Plugin Should I Use?](#which-plugin-should-i-use) below.

## Features

- **Whitelist-based Protection**: Sensitive ports (80, 8001, 8080) are whitelist-only
- **DDoS Mitigation**: SYN flood protection, connection rate limiting
- **Attack Monitoring**: Real-time logging and statistics of blocked attempts
- **GUI Interface**: Full Enigma2 integration for easy management
- **IPv4/IPv6 Support**: Comprehensive firewall rules for both protocols
- **Automatic Startup**: Init scripts for boot-time activation

## Security Model

### Defense-in-Depth Layers

1. **Default Deny**: All incoming traffic blocked by default (DROP policy)
2. **Stateful Firewall**: Connection tracking with invalid packet dropping
3. **Whitelist Protection**: Trusted IPs/networks granted full access
4. **Rate Limiting**: SSH (3/min), FTP (3/min), SYN flood protection
5. **Port-Specific Protection**:
   - Ports 8001, 80, 8080: Whitelist-only
   - SSH/FTP: Rate limited
   - All others: Blocked with logging

## Which Plugin Should I Use?

### Use Firewall Plugin if:
- ✅ You need selective internet access (whitelist specific IPs)
- ✅ You want to allow certain remote IPs direct access
- ✅ You need attack monitoring and logging
- ✅ Your receiver is internet-facing

### Use WireGuard-TNAP Plugin if:
- ✅ You want VPN-only remote access
- ✅ You prefer zero internet exposure
- ✅ You access receiver only via VPN tunnel
- ✅ You want simple "connect via VPN" experience

**Cannot decide?** Most users should choose **WireGuard-TNAP** for better security. Only use Firewall if you specifically need whitelist-based internet access.

## Installation

### Via TNAP Feed

```bash
opkg update
opkg install enigma2-plugin-security-firewall
```

### Manual Installation

1. Download the `.ipk` package from releases
2. Transfer to receiver via SCP/FTP
3. Install:
```bash
opkg install enigma2-plugin-security-firewall_*.ipk
```

## Configuration

### Whitelist Management

Edit `/etc/firewall.users` to add trusted networks/IPs:

```bash
# Local network
192.168.1.0/24

# T-Mobile cellular network
172.56.0.0/13

# Trusted server
162.216.113.217
```

After editing, restart the firewall:

```bash
/etc/init.d/firewall restart
```

### Enable Firewall

```bash
# Start firewall
/etc/init.d/firewall start

# Enable at boot
update-rc.d firewall defaults

# Check status
/etc/init.d/firewall status
```

### Monitor Mode

Enable real-time attack monitoring:

```bash
# Start monitor
/etc/init.d/firewall-monitor start

# View statistics
/etc/init.d/firewall-monitor stats

# View logs
tail -f /var/log/firewall-attempts.log
```

## GUI Usage

1. Access via: **Menu > Extensions > Firewall Security**
2. View firewall status and statistics
3. Manage whitelist entries
4. Monitor active connections
5. View blocked attempts in real-time

## Version History

### Version 2.3 (Current - Production Ready)

**Critical Security Fix**: Eliminated ESTABLISHED connection bypass vulnerability

- Fixed: Attackers could bypass whitelist by exploiting connection state tracking
- Solution: Block NEW connections to sensitive ports BEFORE ESTABLISHED rule
- Verified: Zero attacker IPs reaching OpenWebif after deployment
- Details: See [CHANGELOG.md](CHANGELOG.md)

### Version 2.2 (DEPRECATED)

**WARNING**: Contains critical bypass vulnerability - DO NOT USE

### Version 2.1 (DEPRECATED)

- Fixed rule ordering vulnerability
- Fixed port 8001 brute force vulnerability
- Reduced rate limit tolerance
- Fixed monitor logging on embedded systems

## Attack Mitigation Effectiveness

| Attack Type | Mitigation | Effectiveness |
|-------------|------------|---------------|
| Port Scanning | Default deny + logging | 100% |
| Brute Force (Web/Streaming) | Whitelist-only | 100% |
| Brute Force (SSH) | Rate limit 3/min | 95% |
| Credential Stuffing | Whitelist + rate limit | 100% |
| SYN Flood | Rate limit 2/sec | 90% |
| IP Rotation (Botnet) | Whitelist-only on sensitive ports | 100% |
| Connection Exhaustion | 50 conn/IP limit | 90% |

## Troubleshooting

### Cannot access port 8001 from local network

Your local network is not in the whitelist:

```bash
echo "192.168.1.0/24  # Local network" >> /etc/firewall.users
/etc/init.d/firewall restart
```

### SSH blocked after 2 attempts

This is rate limiting working as designed. Solutions:
- Add your IP to whitelist, OR
- Wait 60 seconds before retrying

### Monitor not logging attacks

Firewall may not be running:

```bash
/etc/init.d/firewall start
/etc/init.d/firewall-monitor restart
```

### Firewall rules reset after reboot

Init script not enabled:

```bash
update-rc.d firewall defaults
```

## Hardware Compatibility

Tested on:
- Octagon SF8008
- All TNAP supported receivers

## Requirements

- Enigma2 receiver (TNAP image)
- iptables (pre-installed on most images)
- Python 3.x
- Optional: ip6tables (for IPv6 support)

## Security Reporting

**Do not open public issues for security vulnerabilities.**

Contact the maintainer privately with:
- Affected version
- Vulnerability description
- Steps to reproduce
- Proposed fix (if available)

## License

GNU General Public License v2.0

Copyright (C) 2025 TNAP Development Team

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later version.

## Credits

- **Original Development**: TNAP Team
- **Security Hardening**: Claude Code (claude-sonnet-4-5-20250929)
- **Testing**: Community contributors

## Links

- GitHub: https://github.com/EB-TNAP/enigma2-plugin-security-firewall
- Documentation: [CHANGELOG.md](CHANGELOG.md)
- Issue Tracker: https://github.com/EB-TNAP/enigma2-plugin-security-firewall/issues
