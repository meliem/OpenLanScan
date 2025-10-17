# Changelog

All notable changes to OpenLanScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-16

### Added
- **Network Scanning**
  - Multi-method scanning: ARP (Layer 2) + ICMP (Layer 3) running in parallel
  - Optimized batch processing (16 IPs per batch to avoid macOS FD_SET limits)
  - Fast concurrent ICMP ping (200 parallel pings)
  - Separate status indicators for ARP and ICMP responsiveness

- **Hostname Resolution**
  - Multi-protocol resolution running in parallel:
    - DNS reverse lookup (trust-dns-resolver)
    - mDNS/Bonjour discovery (mdns-sd crate + shell fallback)
    - NetBIOS/SMB name resolution (raw UDP + nmblookup fallback)
    - WSD (Web Services Discovery) for modern Windows devices
  - Cross-platform shell command fallbacks for maximum compatibility
  - 50 hosts resolved concurrently with optimized timeouts (150-300ms)

- **Host Information**
  - MAC address vendor lookup (IEEE OUI database)
  - IPv4 and IPv6 (link-local and global) addresses
  - Multiple hostname fields (DNS, mDNS, SMB, hostname priority)
  - Last seen timestamp
  - Open TCP ports list

- **Port Scanning**
  - On-demand port scanning (common/all/custom ranges)
  - Fast parallel TCP connect scanning
  - Real-time progress updates

- **User Interface**
  - Modern Svelte 5 + Tailwind CSS interface
  - Dark mode support
  - Real-time host discovery updates
  - Sortable host table with multiple columns
  - Detailed host information panel
  - Network interface selector
  - Configurable subnet range (auto-detected + manual override)
  - Progress bar with scan statistics
  - Stop scanning button

- **Cross-Platform Support**
  - macOS: Native dns-sd, ARP scanning, ICMP ping
  - Linux: Avahi-resolve, nmblookup, standard tools
  - Windows: Native NetBIOS/WSD, PowerShell integration

### Fixed
- **Critical Fixes**
  - Fixed FD_SET panic on macOS by reducing batch size from 128 to 16
  - Corrected ping status logic: separate ARP (green) vs ICMP (blue) indicators
  - Fixed hostname resolution returning 0 names by implementing proper multi-method approach
  - Optimized scan speed from 60+ seconds to ~15-25 seconds for 400 hosts

- **Architecture Improvements**
  - Rewrote resolver.rs (752 → 430 lines) with clean multi-platform code
  - Consolidated WSD functionality into resolver.rs (removed duplicate wsd.rs)
  - Proper separation of concerns: ARP scan → ICMP scan → hostname resolution
  - Removed unused modules (config.rs, logging.rs references)

### Performance
- ARP scan: ~3-5 seconds for 1000 IPs (16 per batch, 3 passes)
- ICMP scan: ~5-8 seconds (200 concurrent pings)
- Hostname resolution: ~5-10 seconds for 400 hosts (50 concurrent, 4 methods parallel)
- Total scan time: **15-25 seconds** for typical home network (400 devices)

### Technical Details
- Rust 2021 Edition
- Tauri 2.x framework
- Tokio async runtime with optimized concurrency
- pnet for low-level ARP packet manipulation
- trust-dns-resolver for DNS queries
- mdns-sd for mDNS/Bonjour
- Raw UDP sockets for NetBIOS/WSD protocols

### Known Issues
- Requires elevated privileges (sudo/admin) for ARP scanning
- macOS FD_SET limited to 1024 file descriptors (batch size workaround applied)
- IPv6 support currently limited to link-local detection
- mDNS requires Avahi on Linux systems
- Corporate firewalls may block ARP/NetBIOS/WSD traffic

---

## [Unreleased]

### Planned Features (Roadmap)
- Network topology visualization
- Export results (CSV, JSON, XML)
- Scheduled scanning
- Service detection on open ports
- Wake-on-LAN support
- Historical tracking with database
- Network performance monitoring
- Device categorization and tagging
- Custom notes and labels per device
- IPv6 full subnet scanning
- Plugin system for custom protocols

[0.1.0]: https://github.com/YOURUSERNAME/OpenLanScan/releases/tag/v0.1.0
