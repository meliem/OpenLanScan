# OpenLanScan - Quick Start Guide

## First Time Setup

### 1. Initial Compilation (5-10 minutes)
The first compilation will download and compile all Rust dependencies. This is normal and only happens once.

```bash
git clone https://github.com/YOUR_USERNAME/OpenLanScan.git
cd OpenLanScan
cargo build --manifest-path=src-tauri/Cargo.toml
```

### 2. Running the Application

#### Development Mode
```bash
npm run tauri:dev
```

This will:
- Start the Vite development server (frontend)
- Compile and launch the Tauri app (backend)
- Enable hot-reload for frontend changes

#### Running with Elevated Privileges (Required for Network Scanning)

**macOS:**
```bash
# After first build, run with sudo
npm run tauri:dev
# Then in another terminal when app opens:
# Find the PID and grant it privileges, or run the built binary:
sudo ./src-tauri/target/debug/openlanscan
```

**Linux:**
```bash
# Option 1: Run with sudo
sudo npm run tauri:dev

# Option 2 (Recommended): Grant capabilities to the binary
npm run tauri:dev  # First build
sudo setcap cap_net_raw,cap_net_admin=eip src-tauri/target/debug/openlanscan
./src-tauri/target/debug/openlanscan  # Then run without sudo
```

### 3. Production Build

```bash
npm run tauri:build
```

The binary will be in: `src-tauri/target/release/bundle/`

## Usage

1. **Launch the app**
2. **Select your network interface** (auto-selected if only one)
3. **Click "Start LanScan"**
4. **Wait for devices to be discovered**
5. **Click on any device** to see details
6. **Click "Port Scan"** in the details panel to scan ports

## Network Scanning Techniques

OpenLanScan uses multiple techniques to find ALL devices:

1. **ARP Scan** (Primary)
   - Layer 2 scanning
   - Bypasses most firewalls
   - Obtains MAC addresses directly

2. **TCP SYN Scan** (Fallback)
   - Detects hosts with ICMP disabled
   - Checks common ports: 22, 80, 443, 445, 3389, 8080

3. **mDNS Discovery**
   - Discovers Apple devices (macOS, iOS)
   - Discovers Linux with Avahi
   - Gets human-readable hostnames

4. **NetBIOS Scan**
   - Discovers Windows machines
   - Gets workgroup/domain names

## Troubleshooting

### "Permission denied" errors
- Make sure you're running with elevated privileges (sudo on macOS/Linux)
- On Linux, use `setcap` to grant capabilities

### "No devices found"
- Check that you selected the correct network interface
- Ensure you're on the same subnet as other devices
- Try running with sudo/administrator privileges

### Port scanning not working
- Port scanning is on-demand only
- Select a device first, then click "Port Scan"
- This is intentional to reduce network traffic

### Compilation errors
First time compilation can take 5-10 minutes. Common issues:

**macOS:**
```bash
# Install Xcode Command Line Tools
xcode-select --install
```

**Linux:**
```bash
# Install required development packages
sudo apt install libwebkit2gtk-4.0-dev build-essential libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libpcap-dev
```

## Development

### Project Structure
```
OpenLanScan/
├── src/                    # Svelte frontend
│   ├── App.svelte         # Main app component
│   ├── lib/               # UI components
│   └── main.ts            # Entry point
├── src-tauri/             # Rust backend
│   ├── src/
│   │   ├── main.rs        # Tauri commands
│   │   ├── scanner.rs     # Network scanning
│   │   ├── resolver.rs    # Hostname resolution
│   │   └── port_scanner.rs # Port scanning
│   └── Cargo.toml         # Rust dependencies
└── package.json           # npm dependencies
```

### Adding Features

1. **Backend (Rust)**: Edit files in `src-tauri/src/`
2. **Frontend (Svelte)**: Edit files in `src/`
3. **Tauri Commands**: Add to `src-tauri/src/main.rs`

### Hot Reload

- **Frontend changes**: Auto-reload (Vite HMR)
- **Backend changes**: Requires restart of `npm run tauri:dev`

## Performance Tips

1. **Subnet range**: Limit the scan range for faster results
2. **Port scanning**: Use "common ports" instead of "all ports"
3. **Background scanning**: The app scans in batches to avoid overwhelming the network

## Security Notes

- **Only scan networks you own or have permission to scan**
- Network administrators may detect your scanning activity
- Some IDS/IPS systems may trigger alerts
- Port scanning is intentionally limited to on-demand to reduce network footprint

## Next Steps

- Read the full [README.md](README.md) for detailed documentation
- Check the [roadmap](README.md#roadmap) for upcoming features
- Contribute on GitHub

---

**Note**: This is a security tool. Use responsibly and ethically.
