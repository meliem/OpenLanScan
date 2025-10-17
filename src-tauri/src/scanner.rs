use crate::types::{Host, ScanProgress};
use anyhow::Result;
use futures::stream::{self, StreamExt};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperation, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::task;
use tokio::time::timeout;

const ARP_READ_TIMEOUT: Duration = Duration::from_millis(10);
const ARP_WRITE_TIMEOUT: Duration = Duration::from_millis(10);
const BUFFER_SIZE: usize = 42;
const PING_TIMEOUT_MS: u64 = 200; // ICMP ping timeout - balanced for reliability and speed
const PING_CONCURRENCY: usize = 400; // High concurrency without overwhelming slower devices
const TCP_DISCOVERY_TIMEOUT_MS: u64 = 250; // TCP connection timeout for discovery scans

pub struct NetworkScanner {
    pub hosts: Arc<RwLock<HashMap<String, Host>>>,
}

type ProgressCallback = Arc<dyn Fn(ScanProgress) + Send + Sync>;
type HostCallback = Arc<dyn Fn(Host) + Send + Sync>;

enum ScanEvent {
    TargetProcessed(usize),
    HostDiscovered(Host),
}

impl NetworkScanner {
    pub fn new() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_hosts(&self) -> Vec<Host> {
        let hosts = self.hosts.read().await;
        hosts.values().cloned().collect()
    }

    pub async fn clear_hosts(&self) {
        let mut hosts = self.hosts.write().await;
        hosts.clear();
    }

    /// Scan network using ARP (most reliable for LAN discovery)
    pub async fn scan_arp(
        &self,
        interface_name: &str,
        subnet: &str,
        progress_callback: ProgressCallback,
        host_callback: HostCallback,
    ) -> Result<()> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface not found"))?;

        log::debug!("scan_arp: Received subnet={}", subnet);
        let (network_addr, prefix_len) = parse_subnet(subnet)?;
        log::debug!("scan_arp: Parsed network={}, prefix={}", network_addr, prefix_len);
        let ips = generate_ip_range(network_addr, prefix_len);
        let total = ips.len();
        log::debug!("scan_arp: Generated {} IPs to scan", total);

        progress_callback.as_ref()(ScanProgress {
            total,
            scanned: 0,
            found: 0,
            message: format!("Starting ARP scan on {} hosts", total),
        });

        let source_mac = interface.mac.unwrap_or(MacAddr::zero());
        let source_ip = interface
            .ips
            .iter()
            .find_map(|ip| {
                if let IpAddr::V4(ipv4) = ip.ip() {
                    Some(ipv4)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("No IPv4 address on interface"))?;

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let targets = ips.clone();
        let blocking_handle = task::spawn_blocking(move || {
            perform_arp_scan(interface, source_mac, source_ip, targets, event_tx)
        });

        let mut scanned = 0usize;
        let mut found = 0usize;

        while let Some(event) = event_rx.recv().await {
            match event {
                ScanEvent::TargetProcessed(count) => {
                    scanned = count;
                }
                ScanEvent::HostDiscovered(host) => {
                    let mut host_clone = host.clone();
                    if host_clone.mac.is_none() {
                        // Ensure MAC is always uppercase when present
                        if let Some(ref mac) = host.mac {
                            host_clone.mac = Some(mac.to_ascii_uppercase());
                        }
                    }

                    let key = host_clone
                        .ipv4
                        .clone()
                        .unwrap_or_else(|| host_clone.identifier());

                    let mut hosts_lock = self.hosts.write().await;
                    hosts_lock.insert(key, host_clone.clone());
                    found = hosts_lock.len();
                    drop(hosts_lock);

                    host_callback.as_ref()(host_clone);
                }
            }

            let message = if scanned == 0 {
                format!("Starting ARP scan on {} hosts", total)
            } else {
                format!("Scanned {}/{} hosts, found {} devices", scanned, total, found)
            };

            progress_callback.as_ref()(ScanProgress {
                total,
                scanned,
                found,
                message,
            });
        }

        blocking_handle
            .await
            .map_err(|e| anyhow::anyhow!("ARP worker join error: {}", e))??;

        progress_callback.as_ref()(ScanProgress {
            total,
            scanned: total,
            found,
            message: format!("ARP scan complete: {} devices", found),
        });

        Ok(())
    }

    /// Scan using ICMP ping (fast parallel discovery)
    pub async fn scan_icmp_ping(
        &self,
        subnet: &str,
        progress_callback: ProgressCallback,
        host_callback: HostCallback,
    ) -> Result<()> {
        let (network_addr, prefix_len) = parse_subnet(subnet)?;
        let ips = generate_ip_range(network_addr, prefix_len);
        let total = ips.len();

        log::debug!("Starting ICMP ping scan for {} hosts...", total);

        let hosts_ref = self.hosts.clone();
        let scanned_counter = Arc::new(AtomicUsize::new(0));

        // Launch all pings in parallel with massive concurrency
        stream::iter(ips.into_iter())
            .for_each_concurrent(PING_CONCURRENCY, |ip| {
                let hosts = hosts_ref.clone();
                let host_cb = host_callback.clone();
                let progress_cb = progress_callback.clone();
                let scanned = scanned_counter.clone();

                async move {
                    // Try ICMP ping - only process if host responds
                    if let Ok(true) = ping_host(ip).await {
                        let mut hosts_lock = hosts.write().await;

                        // Get existing host or create new one (some hosts only respond to ICMP)
                        let key = ip.to_string();
                        let host = hosts_lock.entry(key.clone()).or_insert_with(|| {
                            Host::new(IpAddr::V4(ip))
                        });

                        // Mark as ICMP responsive
                        host.icmp_responsive = true;
                        host.ipv4 = Some(ip.to_string());

                        // Try to resolve hostname if not already set
                        if host.hostname.is_none() {
                            if let Some(hostname) = resolve_hostname(IpAddr::V4(ip)).await {
                                host.hostname = Some(hostname.clone());
                                log::debug!("ICMP host {} resolved to {}", ip, hostname);
                            }
                        }

                        let host_clone = host.clone();
                        drop(hosts_lock);

                        // Only log every 10th ICMP response to reduce console spam
                        let current_found = hosts.read().await.len();
                        if current_found % 10 == 0 {
                            log::debug!("ICMP responses: {} devices found", current_found);
                        }
                        host_cb.as_ref()(host_clone);
                    }
                    // If ping fails, don't create/update anything

                    let scanned_now = scanned.fetch_add(1, Ordering::Relaxed) + 1;
                    if scanned_now % 50 == 0 || scanned_now == total {
                        let current_found = hosts.read().await.len();
                        progress_cb.as_ref()(ScanProgress {
                            total,
                            scanned: scanned_now,
                            found: current_found,
                            message: format!("ICMP ping: {}/{}", scanned_now, total),
                        });
                    }
                }
            })
            .await;

        let final_found = self.hosts.read().await.len();
        log::debug!("ICMP ping scan complete, {} total hosts found", final_found);

        Ok(())
    }

    /// Scan IPv6 link-local addresses (fe80::/10)
    /// This discovers devices that might not respond to IPv4 scans
    #[allow(dead_code)]
    pub async fn scan_ipv6_linklocal(
        &self,
        interface_name: &str,
        progress_callback: ProgressCallback,
        host_callback: HostCallback,
    ) -> Result<()> {
        log::debug!("Starting IPv6 link-local scan on interface {}", interface_name);

        // Get interface index for IPv6
        let interfaces = datalink::interfaces();
        let _interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface not found"))?;

        // Generate common IPv6 link-local addresses to try
        // fe80:: + interface suffix
        // Typically devices use EUI-64 format or random addresses
        let hosts_ref = self.hosts.clone();

        // Use NDP (Neighbor Discovery Protocol) to find IPv6 neighbors
        // This is similar to ARP for IPv4
        // For simplicity, we'll try pinging some common patterns

        let base_addrs: Vec<String> = vec![
            format!("fe80::1%{}", interface_name),
            format!("fe80::2%{}", interface_name),
            format!("fe80::ff:fe00:0%{}", interface_name),
        ];

        let scanned_counter = Arc::new(AtomicUsize::new(0));
        let total = base_addrs.len();

        for (_idx, addr) in base_addrs.iter().enumerate() {
            // Try to ping the IPv6 address
            if let Ok(true) = ping6_host(addr).await {
                let mut hosts_lock = hosts_ref.write().await;

                // Try to find existing host entry by looking at MAC addresses
                // For now, just create new entry with IPv6
                let ip6: std::net::Ipv6Addr = addr.split('%').next()
                    .unwrap_or("fe80::1")
                    .parse()
                    .unwrap_or_else(|_| {
                        "fe80::1".parse()
                            .expect("Hardcoded IPv6 address fe80::1 should always be valid")
                    });

                let host = Host::new(IpAddr::V6(ip6));
                let key = host.identifier();

                hosts_lock.entry(key.clone()).or_insert(host.clone());
                drop(hosts_lock);

                log::debug!("IPv6 link-local response from {}", addr);
                host_callback.as_ref()(host);
            }

            let scanned_now = scanned_counter.fetch_add(1, Ordering::Relaxed) + 1;
            progress_callback.as_ref()(ScanProgress {
                total,
                scanned: scanned_now,
                found: hosts_ref.read().await.len(),
                message: format!("IPv6 link-local scan: {}/{}", scanned_now, total),
            });
        }

        log::debug!("IPv6 link-local scan complete");
        Ok(())
    }

    /// Scan using TCP SYN on common ports (for hosts that don't respond to ARP/ping)
    #[allow(dead_code)]
    pub async fn scan_tcp_discovery(
        &self,
        subnet: &str,
        ports: &[u16],
        progress_callback: ProgressCallback,
        host_callback: HostCallback,
    ) -> Result<()> {
        let (network_addr, prefix_len) = parse_subnet(subnet)?;
        let ips = generate_ip_range(network_addr, prefix_len);
        let total = ips.len() * ports.len();

        let initial_found = self.hosts.read().await.len();
        progress_callback.as_ref()(ScanProgress {
            total,
            scanned: 0,
            found: initial_found,
            message: "Starting TCP discovery scan".to_string(),
        });

        if total == 0 {
            return Ok(());
        }

        let hosts_ref = self.hosts.clone();
        let scanned_counter = Arc::new(AtomicUsize::new(0));
        let progress_cb = progress_callback.clone();
        let host_cb = host_callback.clone();

        let targets: Vec<(Ipv4Addr, u16)> = ips
            .into_iter()
            .flat_map(|ip| ports.iter().copied().map(move |port| (ip, port)))
            .collect();

        let concurrency = 256;

        stream::iter(targets.into_iter())
            .for_each_concurrent(concurrency, |(ip, port)| {
                let hosts = hosts_ref.clone();
                let host_cb = host_cb.clone();
                let progress_cb = progress_cb.clone();
                let scanned_counter = scanned_counter.clone();
                async move {
                    let target = format!("{}:{}", ip, port);
                    if let Ok(Ok(_stream)) = timeout(
                        Duration::from_millis(TCP_DISCOVERY_TIMEOUT_MS),
                        tokio::net::TcpStream::connect(&target),
                    )
                    .await
                    {
                        let mut hosts_lock = hosts.write().await;
                        let host_entry = hosts_lock
                            .entry(ip.to_string())
                            .or_insert_with(|| Host::new(IpAddr::V4(ip)));

                        if !host_entry.tcp_ports_open.contains(&port) {
                            host_entry.tcp_ports_open.push(port);
                            host_entry.tcp_ports_open.sort_unstable();
                        }

                        let host_snapshot = host_entry.clone();
                        drop(hosts_lock);
                        host_cb.as_ref()(host_snapshot);
                    }

                    let scanned_now = scanned_counter.fetch_add(1, Ordering::Relaxed) + 1;
                    if scanned_now % 100 == 0 || scanned_now == total {
                        let current_found = hosts.read().await.len();
                        progress_cb.as_ref()(ScanProgress {
                            total,
                            scanned: scanned_now,
                            found: current_found,
                            message: format!(
                                "TCP scan progress: {}/{}",
                                scanned_now, total
                            ),
                        });
                    }
                }
            })
            .await;

        let final_found = self.hosts.read().await.len();
        progress_callback.as_ref()(ScanProgress {
            total,
            scanned: total,
            found: final_found,
            message: format!("TCP discovery complete: {} hosts updated", final_found),
        });

        Ok(())
    }
}

fn perform_arp_scan(
    interface: NetworkInterface,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    targets: Vec<Ipv4Addr>,
    event_tx: mpsc::UnboundedSender<ScanEvent>,
) -> Result<()> {
    use pnet::datalink::Channel::Ethernet;

    let mut config = datalink::Config::default();
    config.read_timeout = Some(ARP_READ_TIMEOUT);
    config.write_timeout = Some(ARP_WRITE_TIMEOUT);

    let (mut tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow::anyhow!("Unhandled channel type")),
        Err(e) => return Err(anyhow::anyhow!("Failed to create channel: {}", e)),
    };

    let total = targets.len();
    let start_time = Instant::now();

    log::debug!("Starting ARP scan for {} targets...", total);

    // Send ARP requests in batches - small batches to avoid FD_SET panic on macOS
    const BATCH_SIZE: usize = 16;  // Keep small to avoid FD_SET overflow (max 1024 FDs on macOS)
    let num_batches = (total + BATCH_SIZE - 1) / BATCH_SIZE;

    for batch_idx in 0..num_batches {
        let start = batch_idx * BATCH_SIZE;
        let end = ((batch_idx + 1) * BATCH_SIZE).min(total);
        let batch = &targets[start..end];

        // Send this batch 3 times for reliability (smaller batches allow more passes)
        for _pass in 0..3 {
            for &target_ip in batch {
                if let Err(e) = send_arp_packet(&mut tx, source_mac, source_ip, target_ip) {
                    log::debug!("ARP send error for {}: {}", target_ip, e);
                }
            }
            // Very small delay between passes
            thread::sleep(Duration::from_millis(1));
        }

        // Read responses from this batch - longer timeout for better detection
        let batch_deadline = Instant::now() + Duration::from_millis(100); // Increased for reliability
        while Instant::now() < batch_deadline {
            if let Ok(received) = drain_arp_responses(&mut rx, &event_tx) {
                if !received {
                    thread::sleep(Duration::from_millis(2)); // Small sleep when no data
                }
            }
        }

        let _ = event_tx.send(ScanEvent::TargetProcessed(end));
    }

    log::debug!("All ARP requests sent, final collection phase...");

    // Final collection phase - generous timeout to catch slow responders
    let collection_deadline = Instant::now() + Duration::from_millis(300);
    let mut consecutive_empty = 0;

    while Instant::now() < collection_deadline {
        let received = drain_arp_responses(&mut rx, &event_tx)?;

        if received {
            consecutive_empty = 0;
        } else {
            consecutive_empty += 1;
            if consecutive_empty > 10 {
                break; // No responses for 100ms, we're done
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    log::debug!("ARP scan complete in {:?}", start_time.elapsed());
    Ok(())
}

fn send_arp_packet(
    tx: &mut Box<dyn datalink::DataLinkSender>,
    source_mac: MacAddr,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Result<()> {
    let mut ethernet_buffer = [0u8; BUFFER_SIZE];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to create Ethernet packet"))?;

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer)
        .ok_or_else(|| anyhow::anyhow!("Failed to create ARP packet"))?;

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperation::new(1));
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet());

    tx.send_to(ethernet_packet.packet(), None)
        .ok_or_else(|| anyhow::anyhow!("Failed to send ARP request"))?
        .map_err(|e| anyhow::anyhow!("Send error: {}", e))?;

    Ok(())
}

fn drain_arp_responses(
    rx: &mut Box<dyn datalink::DataLinkReceiver>,
    event_tx: &mpsc::UnboundedSender<ScanEvent>,
) -> Result<bool> {
    let mut received_any = false;
    let mut count = 0;

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                            if arp.get_operation() == ArpOperation::new(2) {
                                let sender_ip = arp.get_sender_proto_addr();
                                let sender_mac = arp.get_sender_hw_addr();

                                let mut host = Host::new(IpAddr::V4(sender_ip));
                                host.mac = Some(format!("{}", sender_mac));
                                host.arp_responsive = true; // ARP response = device is alive at Layer 2

                                if let Some(vendor) = lookup_vendor(&sender_mac) {
                                    host.vendor = Some(vendor.clone());
                                }

                                // Resolve hostname using native system mechanisms
                                // This will query DNS, mDNS, NetBIOS, /etc/hosts, and all caches
                                // We do this in a non-blocking way to not slow down ARP collection
                                let ip_addr = IpAddr::V4(sender_ip);
                                let event_tx_clone = event_tx.clone();
                                let mut host_clone = host.clone();

                                std::thread::spawn(move || {
                                    // Sync resolution in a separate thread using cross-platform libc
                                    use std::ffi::CStr;
                                    use std::mem;

                                    let mut host_buf = vec![0u8; libc::NI_MAXHOST as usize];

                                    if let IpAddr::V4(ipv4) = ip_addr {
                                        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };

                                        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
                                        {
                                            addr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                                        }

                                        addr.sin_family = libc::AF_INET as libc::sa_family_t;
                                        addr.sin_port = 0;
                                        addr.sin_addr = libc::in_addr {
                                            s_addr: u32::from(ipv4).to_be(),
                                        };

                                        let result = unsafe {
                                            libc::getnameinfo(
                                                &addr as *const _ as *const libc::sockaddr,
                                                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                                                host_buf.as_mut_ptr() as *mut libc::c_char,
                                                host_buf.len() as libc::socklen_t,
                                                std::ptr::null_mut(),
                                                0,
                                                libc::NI_NAMEREQD,
                                            )
                                        };

                                        if result == 0 {
                                            if let Ok(hostname_cstr) = CStr::from_bytes_until_nul(&host_buf) {
                                                if let Ok(hostname) = hostname_cstr.to_str() {
                                                    let hostname = hostname.trim();
                                                    if !hostname.is_empty() && hostname != ip_addr.to_string() {
                                                        host_clone.hostname = Some(hostname.to_string());
                                                        log::debug!("Resolved {} -> {}", ip_addr, hostname);
                                                        let _ = event_tx_clone.send(ScanEvent::HostDiscovered(host_clone));
                                                        return;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                });

                                let _ = event_tx.send(ScanEvent::HostDiscovered(host));
                                received_any = true;
                                count += 1;
                            }
                        }
                    }
                }
            }
            Err(err) => {
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut {
                    break;
                }

                log::debug!("Receive error: {}", err);
                return Err(anyhow::anyhow!("Receive error: {}", err));
            }
        }
    }

    if count > 0 {
        log::debug!("Read {} ARP responses in this batch", count);
    }

    Ok(received_any)
}

fn parse_subnet(subnet: &str) -> Result<(Ipv4Addr, u8)> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!("Invalid subnet format"));
    }

    let addr: Ipv4Addr = parts[0].parse()?;
    let prefix: u8 = parts[1].parse()?;

    Ok((addr, prefix))
}

fn generate_ip_range(network: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    let network_u32 = u32::from(network);
    let host_bits = 32 - prefix_len;
    let num_hosts = (1u32 << host_bits).saturating_sub(2);

    (1..=num_hosts)
        .map(|i| Ipv4Addr::from(network_u32 + i))
        .collect()
}

fn lookup_vendor(mac: &MacAddr) -> Option<String> {
    let mac_str = format!("{}", mac);
    crate::vendor::lookup_vendor(&mac_str)
}

/// Fast ICMP ping using system ping command
async fn ping_host(ip: Ipv4Addr) -> Result<bool> {
    use tokio::process::Command;

    let result = timeout(
        Duration::from_millis(PING_TIMEOUT_MS),
        Command::new("ping")
            .arg("-c").arg("1")      // 1 packet
            .arg("-t").arg("64")     // TTL 64 (normal value, not 1!)
            .arg("-W").arg("200")    // 200ms timeout for the ping command itself
            .arg(ip.to_string())
            .output()
    ).await;

    match result {
        Ok(Ok(output)) => {
            // Check exit code - 0 means success, non-zero means failure
            let success = output.status.success();
            if !success {
                log::debug!("Ping failed for {} with exit code {:?}", ip, output.status.code());
            }
            Ok(success)
        }
        Ok(Err(e)) => {
            log::debug!("Ping command error for {}: {}", ip, e);
            Ok(false)
        }
        Err(_) => {
            log::debug!("Ping timeout for {}", ip);
            Ok(false)
        }
    }
}

/// Fast ICMPv6 ping using system ping6 command
#[allow(dead_code)]
async fn ping6_host(addr: &str) -> Result<bool> {
    use tokio::process::Command;

    let result = timeout(
        Duration::from_millis(PING_TIMEOUT_MS),
        Command::new("ping6")
            .arg("-c").arg("1")      // 1 packet
            .arg(addr)
            .output()
    ).await;

    match result {
        Ok(Ok(output)) => Ok(output.status.success()),
        _ => Ok(false),
    }
}

/// Resolve hostname using native OS mechanisms (DNS, mDNS, NetBIOS, /etc/hosts, cache, etc.)
/// This leverages the full system resolver stack automatically - cross-platform
async fn resolve_hostname(ip: IpAddr) -> Option<String> {
    // Use task::spawn_blocking since DNS resolution is synchronous
    let result = task::spawn_blocking(move || {
        use std::ffi::CStr;
        use std::mem;

        // Prepare hostname buffer
        let mut host = vec![0u8; libc::NI_MAXHOST as usize];

        let result = match ip {
            IpAddr::V4(ipv4) => {
                // Build sockaddr_in using libc types (cross-platform)
                let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };

                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
                {
                    addr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                }

                addr.sin_family = libc::AF_INET as libc::sa_family_t;
                addr.sin_port = 0;
                addr.sin_addr = libc::in_addr {
                    s_addr: u32::from(ipv4).to_be(),
                };

                unsafe {
                    libc::getnameinfo(
                        &addr as *const _ as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                        host.as_mut_ptr() as *mut libc::c_char,
                        host.len() as libc::socklen_t,
                        std::ptr::null_mut(),
                        0,
                        libc::NI_NAMEREQD, // Return error if name not found
                    )
                }
            }
            IpAddr::V6(ipv6) => {
                // Build sockaddr_in6 using libc types (cross-platform)
                let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };

                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
                {
                    addr.sin6_len = mem::size_of::<libc::sockaddr_in6>() as u8;
                }

                addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                addr.sin6_port = 0;
                addr.sin6_addr = libc::in6_addr {
                    s6_addr: ipv6.octets(),
                };
                addr.sin6_flowinfo = 0;
                addr.sin6_scope_id = 0;

                unsafe {
                    libc::getnameinfo(
                        &addr as *const _ as *const libc::sockaddr,
                        mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                        host.as_mut_ptr() as *mut libc::c_char,
                        host.len() as libc::socklen_t,
                        std::ptr::null_mut(),
                        0,
                        libc::NI_NAMEREQD,
                    )
                }
            }
        };

        if result == 0 {
            // Success - extract the hostname from C string
            if let Ok(hostname_cstr) = CStr::from_bytes_until_nul(&host) {
                if let Ok(hostname) = hostname_cstr.to_str() {
                    let hostname = hostname.trim();
                    if !hostname.is_empty() && hostname != ip.to_string() {
                        return Some(hostname.to_string());
                    }
                }
            }
        }

        None
    }).await;

    result.ok().flatten()
}
