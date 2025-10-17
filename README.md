# OpenLanScan

An open-source, cross-platform network scanner built with Rust and Tauri. OpenLanScan provides powerful LAN discovery capabilities with an intuitive graphical interface.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)

## Features

### Network Discovery
- **Multi-technique scanning** for comprehensive host detection:
  - **ARP scanning** (Layer 2) - Most reliable for LAN discovery
  - **ICMP ping scanning** (Layer 3) - Detects responsive hosts
  - **mDNS discovery** - Automatic hostname resolution for Apple/Linux devices
  - **NetBIOS scanning** - Windows workgroup and hostname detection
  - **WSD (Web Services Discovery)** - Modern Windows device discovery

### Host Information
- IPv4 and IPv6 addresses (local-link and global)
- MAC address with vendor lookup (IEEE OUI database)
- Multiple hostname resolution methods:
  - DNS reverse lookup
  - mDNS/Bonjour
  - NetBIOS/SMB
  - WSD (Windows)
- Separate ARP and ICMP ping status indicators

### Port Scanning (On-Demand)
- Scan 1000 most common TCP ports
- Full port scan (1-65535)
- Custom port ranges
- Fast parallel scanning with configurable timeout

### User Interface
- Clean, modern interface built with Svelte + Tailwind CSS
- Real-time scan progress
- Sortable host table
- Detailed host information panel
- Dark mode support
- Network interface selector
- Configurable subnet ranges

## Architecture

### Backend (Rust)
```
src-tauri/
├── src/
│   ├── main.rs          # Tauri commands and app initialization
│   ├── types.rs         # Data structures
│   ├── scanner.rs       # Network scanning (ARP, TCP)
│   ├── resolver.rs      # Hostname resolution (DNS, mDNS, NetBIOS)
│   └── port_scanner.rs  # Port scanning engine
```

**Key dependencies:**
- `pnet` - Low-level network packet manipulation (ARP)
- `tokio` - Async runtime for parallel scanning
- `trust-dns-resolver` - DNS resolution
- `mdns-sd` - mDNS/Bonjour discovery
- `mac_oui` - MAC vendor lookup
- `if-addrs` - Network interface enumeration

### Frontend (Svelte + TypeScript)
```
src/
├── App.svelte              # Main application component
├── lib/
│   ├── tauri.ts           # Tauri API wrapper
│   ├── HostTable.svelte   # Host list table
│   ├── HostDetails.svelte # Selected host details
│   ├── ConfigDialog.svelte # Scan configuration
│   └── ProgressBar.svelte  # Scan progress indicator
```

## Technical Details

### Network Discovery Strategy

OpenLanScan uses a **layered discovery approach** to find all devices on the network, even those with strict firewall rules:

1. **ARP Scan** (Primary method)
   - Sends ARP requests to all IPs in subnet
   - Works at Layer 2, bypasses most firewalls
   - Directly obtains MAC addresses
   - Most reliable for local network discovery

2. **ICMP Ping Scan** (Parallel detection)
   - Fast ICMP echo requests to all subnet IPs
   - 200 concurrent pings for maximum speed
   - Detects hosts that respond to Layer 3 probes
   - Complements ARP for complete coverage

3. **mDNS Discovery**
   - Queries multicast DNS (224.0.0.251:5353)
   - Discovers Apple devices (macOS, iOS), Linux with Avahi
   - Provides human-readable hostnames

4. **NetBIOS Scanning**
   - Queries NetBIOS Name Service (port 137 UDP)
   - Discovers Windows machines
   - Retrieves workgroup/domain information

5. **WSD (Web Services Discovery)**
   - Modern Windows device discovery protocol
   - SOAP-based device enumeration (port 3702 UDP)
   - Complements NetBIOS for comprehensive Windows coverage

### Why This Approach Works

**Problem**: Many modern devices disable ICMP ping for security
**Solution**: Multi-layered scanning ensures detection even with:
- ICMP echo disabled
- Strict firewall rules
- Virtual network interfaces
- Docker containers
- IoT devices

### Port Scanning

Port scanning is **strictly on-demand** to:
- Minimize network traffic
- Respect privacy and security
- Avoid triggering IDS/IPS systems
- Provide faster initial discovery

## Installation

### Prerequisites

1. **Rust** (1.70+)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Node.js** (18+) and npm
   ```bash
   # macOS
   brew install node

   # Linux
   sudo apt install nodejs npm  # Debian/Ubuntu
   sudo dnf install nodejs npm  # Fedora

   # Windows
   # Download from nodejs.org
   ```

3. **Platform-specific dependencies**

   **macOS:**
   ```bash
   xcode-select --install
   ```

   **Linux:**
   ```bash
   # Debian/Ubuntu
   sudo apt install libwebkit2gtk-4.0-dev \
       build-essential \
       curl \
       wget \
       libssl-dev \
       libgtk-3-dev \
       libayatana-appindicator3-dev \
       librsvg2-dev \
       libpcap-dev

   # Fedora
   sudo dnf install webkit2gtk3-devel \
       openssl-devel \
       curl \
       wget \
       libappindicator-gtk3 \
       librsvg2-devel \
       libpcap-devel
   ```

   **Windows:**
   - Install [Microsoft Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - Install [WinPcap](https://www.winpcap.org/install/) or [Npcap](https://npcap.com/)

### Build & Run

1. **Clone the repository**
   ```bash
   cd OpenLanScan
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Run in development mode**
   ```bash
   npm run tauri:dev
   ```

4. **Build for production**
   ```bash
   npm run tauri:build
   ```

   The built application will be in `src-tauri/target/release/bundle/`.

## Usage

### Basic Workflow

1. **Launch OpenLanScan**
2. **Select network interface** (if multiple available)
3. **Configure subnet range** (optional - auto-detected by default)
4. **Click "Start LanScan"**
5. **Wait for discovery** to complete
6. **Select a host** to view details
7. **Click "Port Scan"** to scan ports (optional)

### Permissions

Network scanning requires elevated privileges on most systems:

**macOS:**
```bash
sudo /Applications/OpenLanScan.app/Contents/MacOS/openlanscan
```

**Linux:**
```bash
# Option 1: Run with sudo
sudo ./openlanscan

# Option 2: Grant capabilities (recommended)
sudo setcap cap_net_raw,cap_net_admin=eip ./openlanscan
```

**Windows:**
Run as Administrator (right-click → "Run as administrator")

## Known Issues & Limitations

- **Elevated privileges required**: ARP scanning requires root/administrator access on all platforms
- **macOS FD_SET limit**: Batch size reduced to 16 to avoid system limits (scan still fast)
- **Network segmentation**: Cannot detect devices on different VLANs without routing
- **Firewall restrictions**: Corporate firewalls may block ARP, NetBIOS, or WSD traffic
- **mDNS availability**: Requires Avahi on Linux, native support on macOS/Windows
- **IPv6 support**: Currently focuses on IPv4, limited IPv6 link-local detection

## Security Considerations

- **Use responsibly**: Only scan networks you own or have permission to scan
- **Privacy**: No data is collected or sent to external servers
- **Local only**: All scanning happens locally on your network
- **Firewall**: Some firewalls may block ARP or NetBIOS traffic
- **Detection**: Network administrators may detect scanning activity

## Development

### Project Structure
```
OpenLanScan/
├── src/                 # Frontend (Svelte)
├── src-tauri/          # Backend (Rust)
│   ├── src/            # Rust source code
│   ├── Cargo.toml      # Rust dependencies
│   └── tauri.conf.json # Tauri configuration
├── package.json        # npm dependencies
└── vite.config.ts     # Vite configuration
```

### Tech Stack

**Backend:**
- Rust 2021
- Tauri 2.x
- tokio (async runtime)
- pnet (network packets)

**Frontend:**
- Svelte 5
- TypeScript
- Tailwind CSS
- Vite

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Roadmap

- [ ] Network topology visualization
- [ ] Export results (CSV, JSON, XML)
- [ ] Scheduled scanning
- [ ] Service detection (identify services on open ports)
- [ ] Wake-on-LAN support
- [ ] Historical tracking
- [ ] Network performance monitoring
- [ ] Device categorization and tagging
- [ ] Custom notes and labels per device

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Inspired by LanScan by iwaxx
- Built with [Tauri](https://tauri.app)
- Network scanning powered by [pnet](https://github.com/libpnet/libpnet)

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check existing issues for solutions
- Read the documentation

---

**Warning**: Network scanning may be illegal in some jurisdictions without proper authorization. Always ensure you have permission to scan a network before using this tool.
