use crate::types::Host;
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

// Timeout constants for hostname resolution
const DNS_TIMEOUT_MS: u64 = 300;      // DNS reverse lookup timeout
const MDNS_PTR_TIMEOUT_MS: u64 = 500; // mDNS PTR query timeout (longer for reliability)
const MDNS_TIMEOUT_MS: u64 = 300;     // Standard mDNS timeout
const NETBIOS_TIMEOUT_MS: u64 = 150;  // NetBIOS query timeout
const LLMNR_TIMEOUT_MS: u64 = 300;    // LLMNR query timeout
const WSD_TIMEOUT_MS: u64 = 150;      // WSD query timeout
const AVAHI_TIMEOUT_MS: u64 = 150;    // Linux avahi-resolve timeout

/// Host resolver using multiple methods for comprehensive hostname detection
pub struct HostResolver {
    pub dns_resolver: TokioAsyncResolver,
}

impl HostResolver {
    pub async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        Ok(Self {
            dns_resolver: resolver,
        })
    }

    /// Resolve all available information for a host using parallel methods
    pub async fn resolve_all(&self, host: &mut Host) -> Result<()> {
        if let Some(ref ipv4_str) = host.ipv4 {
            if let Ok(ip) = ipv4_str.parse::<IpAddr>() {
                // Launch all resolution methods in parallel
                let dns_future = self.query_dns(ip);
                let mdns_future = async {
                    if let Ok(ip4) = ipv4_str.parse::<Ipv4Addr>() {
                        query_mdns_fast(ip4).await.ok()
                    } else {
                        None
                    }
                };
                let netbios_future = async {
                    if let Ok(ip4) = ipv4_str.parse::<Ipv4Addr>() {
                        query_netbios_fast(ip4).await.ok()
                    } else {
                        None
                    }
                };

                let (dns_result, mdns_result, netbios_result) = tokio::join!(
                    dns_future,
                    mdns_future,
                    netbios_future
                );

                // Update host with results
                if let Some(dns_name) = dns_result {
                    host.dns_name = Some(dns_name.clone());
                    if host.hostname.is_none() {
                        host.hostname = Some(dns_name);
                    }
                }

                if let Some(mdns_name) = mdns_result {
                    host.mdns_name = Some(mdns_name.clone());
                    if host.hostname.is_none() {
                        host.hostname = Some(mdns_name);
                    }
                }

                if let Some((smb_name, smb_domain)) = netbios_result {
                    host.smb_name = Some(smb_name.clone());
                    host.smb_domain = smb_domain;
                    if host.hostname.is_none() {
                        host.hostname = Some(smb_name);
                    }
                }
            }
        }

        Ok(())
    }

    /// Query DNS using trust-dns-resolver (fast and reliable)
    async fn query_dns(&self, ip: IpAddr) -> Option<String> {
        if let Ok(Ok(names)) = tokio::time::timeout(
            Duration::from_millis(DNS_TIMEOUT_MS),
            self.dns_resolver.reverse_lookup(ip)
        ).await {
            if let Some(name) = names.iter().next() {
                return Some(name.to_string().trim_end_matches('.').to_string());
            }
        }
        None
    }
}

/// System-native hostname resolution using shell commands
/// Falls back to platform-specific tools for hostname lookup
pub async fn query_system_hostname(ip: Ipv4Addr) -> Result<String> {
    log::debug!("Attempting system hostname resolution for {}", ip);

    // Use shell commands for resolution
    query_mdns_shell(ip).await
}

/// Fast mDNS query using mdns-sd crate (legacy - kept as fallback)
pub async fn query_mdns_fast(ip: Ipv4Addr) -> Result<String> {
    // Try system resolution first - it's what LanScan uses!
    if let Ok(hostname) = query_system_hostname(ip).await {
        return Ok(hostname);
    }

    // If that fails, try shell commands
    query_mdns_shell(ip).await
}

/// Fallback mDNS query using shell commands (multi-platform)
async fn query_mdns_shell(ip: Ipv4Addr) -> Result<String> {
    use tokio::process::Command;

    #[cfg(target_os = "macos")]
    {
        // Try dns-sd with PTR query for reverse lookup (like LanScan does)
        // Convert IP to PTR format: 192.168.1.1 -> 1.1.168.192.in-addr.arpa
        let ip_str = ip.to_string();
        let octets: Vec<&str> = ip_str.split('.').collect();
        if octets.len() == 4 {
            let ptr_name = format!("{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]);

            if let Ok(output) = tokio::time::timeout(
                Duration::from_millis(MDNS_PTR_TIMEOUT_MS),
                Command::new("dns-sd")
                    .arg("-q")
                    .arg(&ptr_name)
                    .arg("PTR")
                    .output()
            ).await {
                if let Ok(output) = output {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    log::debug!("dns-sd PTR output for {}: {:?}", ip, stdout);

                    // Parse PTR response
                    for line in stdout.lines() {
                        if line.contains(&ptr_name) && !line.contains("STARTING") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            // PTR record format: timestamp A/R Flags if TTL hostname
                            if parts.len() >= 6 {
                                let hostname = parts[parts.len() - 1].trim_end_matches('.');
                                if !hostname.is_empty() && hostname != ptr_name {
                                    log::debug!("Found PTR hostname for {}: {}", ip, hostname);
                                    return Ok(hostname.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Also try standard getaddrinfo as fallback
        if let Ok(output) = tokio::time::timeout(
            Duration::from_millis(MDNS_TIMEOUT_MS),
            Command::new("dns-sd")
                .arg("-G")
                .arg("v4")
                .arg(ip.to_string())
                .output()
        ).await {
            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.contains(&ip.to_string()) {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() > 7 {
                                let hostname = parts[7].trim_end_matches('.');
                                if !hostname.is_empty() {
                                    return Ok(hostname.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        // Try avahi-resolve
        if let Ok(output) = tokio::time::timeout(
            Duration::from_millis(AVAHI_TIMEOUT_MS),
            Command::new("avahi-resolve")
                .arg("-a")
                .arg(ip.to_string())
                .output()
        ).await {
            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if let Some(line) = stdout.lines().next() {
                        if let Some(hostname) = line.split('\t').nth(1) {
                            let hostname = hostname.trim().trim_end_matches('.');
                            if !hostname.is_empty() {
                                return Ok(hostname.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows doesn't have good mDNS command line tools
        // Already tried mdns-sd crate above
        let _ = ip; // Suppress unused warning
    }

    Err(anyhow::anyhow!("mDNS resolution failed"))
}

/// Fast NetBIOS query using raw UDP (primary method)
pub async fn query_netbios_fast(ip: Ipv4Addr) -> Result<(String, Option<String>)> {
    use tokio::net::UdpSocket;

    log::debug!("Attempting NetBIOS query for {}", ip);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(format!("{}:137", ip)).await?;

    // NetBIOS Name Query packet
    let query = build_netbios_query();
    socket.send(&query).await?;

    let mut buf = [0u8; 512];

    if let Ok(Ok((len, _))) = tokio::time::timeout(
        Duration::from_millis(NETBIOS_TIMEOUT_MS),
        socket.recv_from(&mut buf)
    ).await {
        if let Ok((name, domain)) = parse_netbios_response(&buf[..len]) {
            return Ok((name, domain));
        }
    }

    // Fallback to shell commands
    query_netbios_shell(ip).await
}

/// Fallback NetBIOS query using shell commands (multi-platform)
async fn query_netbios_shell(ip: Ipv4Addr) -> Result<(String, Option<String>)> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        use tokio::process::Command;

        if let Ok(output) = tokio::time::timeout(
            Duration::from_millis(NETBIOS_TIMEOUT_MS),
            Command::new("nmblookup")
                .arg("-A")
                .arg(ip.to_string())
                .output()
        ).await {
            if let Ok(output) = output {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);

                    for line in stdout.lines() {
                        let line = line.trim();

                        if line.is_empty() || line.starts_with("Looking up") || line.contains("MAC Address") {
                            continue;
                        }

                        if line.contains("<00>") && !line.contains("<GROUP>") {
                            if let Some(name_part) = line.split("<00>").next() {
                                let hostname = name_part.trim();
                                if !hostname.is_empty() && !hostname.starts_with("__") {
                                    return Ok((hostname.to_string(), None));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows has native NetBIOS support, already tried raw UDP above
        let _ = ip;
    }

    Err(anyhow::anyhow!("NetBIOS resolution failed"))
}

fn build_netbios_query() -> Vec<u8> {
    vec![
        // Transaction ID
        0x00, 0x01,
        // Flags (Standard query)
        0x01, 0x10,
        // Questions: 1
        0x00, 0x01,
        // Answer RRs: 0
        0x00, 0x00,
        // Authority RRs: 0
        0x00, 0x00,
        // Additional RRs: 0
        0x00, 0x00,
        // Name length
        0x20,
        // Encoded "*" (broadcast query)
        0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
        // Terminator
        0x00,
        // Type: NB (0x0020)
        0x00, 0x20,
        // Class: IN (0x0001)
        0x00, 0x01,
    ]
}

fn parse_netbios_response(data: &[u8]) -> Result<(String, Option<String>)> {
    if data.len() < 56 {
        return Err(anyhow::anyhow!("Response too short"));
    }

    let mut name = String::new();
    let mut domain = None;

    for i in 0..data.len().saturating_sub(18) {
        if data[i] == 0x20 && i + 18 <= data.len() {
            let entry_type = data[i + 16];

            // Type 0x00 = Workstation name, Type 0x20 = File server
            if entry_type == 0x00 || entry_type == 0x20 {
                let name_bytes = &data[i+1..i+16];
                let potential_name: String = name_bytes
                    .iter()
                    .take_while(|&&b| b != 0x00 && b != 0x20)
                    .map(|&b| b as char)
                    .collect();

                if !potential_name.is_empty() && name.is_empty() {
                    name = potential_name.trim().to_string();
                }
            }

            // Type 0x1E = Browser elections (domain/workgroup)
            if entry_type == 0x1E {
                let domain_bytes = &data[i+1..i+16];
                let potential_domain: String = domain_bytes
                    .iter()
                    .take_while(|&&b| b != 0x00 && b != 0x20)
                    .map(|&b| b as char)
                    .collect();

                if !potential_domain.is_empty() {
                    domain = Some(potential_domain.trim().to_string());
                }
            }
        }
    }

    if !name.is_empty() {
        Ok((name, domain))
    } else {
        Err(anyhow::anyhow!("No name found in response"))
    }
}

/// Query LLMNR (Link-Local Multicast Name Resolution) for Windows/modern devices
pub async fn query_llmnr(ip: Ipv4Addr) -> Result<String> {
    use tokio::net::UdpSocket;

    log::debug!("Attempting LLMNR query for {}", ip);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(format!("{}:5355", ip)).await?; // LLMNR port

    // Build LLMNR query for reverse lookup (PTR)
    let octets: Vec<u8> = ip.to_string().split('.').map(|s| s.parse().unwrap_or(0)).collect();
    if octets.len() != 4 {
        return Err(anyhow::anyhow!("Invalid IP"));
    }

    // LLMNR PTR query packet
    let ptr_label = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
    let mut query = vec![
        0x00, 0x01, // Transaction ID
        0x00, 0x00, // Flags (standard query)
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ];

    // Encode PTR label
    for part in ptr_label.split('.') {
        if !part.is_empty() {
            query.push(part.len() as u8);
            query.extend_from_slice(part.as_bytes());
        }
    }
    query.push(0x00); // Terminator

    query.extend_from_slice(&[
        0x00, 0x0C, // Type: PTR
        0x00, 0x01, // Class: IN
    ]);

    socket.send(&query).await?;

    let mut buf = [0u8; 512];
    if let Ok(Ok((len, _))) = tokio::time::timeout(
        Duration::from_millis(LLMNR_TIMEOUT_MS),
        socket.recv_from(&mut buf)
    ).await {
        // Parse LLMNR response (similar to DNS)
        if len > 12 {
            // Skip header, look for answer section
            let response_str = String::from_utf8_lossy(&buf[..len]);
            log::debug!("LLMNR response: {:?}", response_str);
            // Note: LLMNR response parsing would require implementing DNS packet format parsing.
            // For now, this function returns an error since the response is not fully parsed.
            // Consider using a DNS parsing library like trust-dns-proto if LLMNR support is needed.
        }
    }

    Err(anyhow::anyhow!("LLMNR resolution failed"))
}

/// Query WSD (Web Services Discovery) for Windows devices
pub async fn query_wsd_fast(ip: Ipv4Addr) -> Result<String> {
    use tokio::net::UdpSocket;

    log::debug!("Attempting WSD query for {}", ip);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.set_broadcast(true)?;

    let probe = build_wsd_probe();
    let target = format!("{}:3702", ip);
    socket.send_to(&probe, &target).await?;

    let mut buf = [0u8; 4096];

    if let Ok(Ok((len, _))) = tokio::time::timeout(
        Duration::from_millis(WSD_TIMEOUT_MS),
        socket.recv_from(&mut buf)
    ).await {
        if let Ok(name) = parse_wsd_response(&buf[..len]) {
            return Ok(name);
        }
    }

    Err(anyhow::anyhow!("WSD resolution failed"))
}

fn build_wsd_probe() -> Vec<u8> {
    let probe = r#"<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <soap:Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>urn:uuid:00000000-0000-0000-0000-000000000000</wsa:MessageID>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
  </soap:Header>
  <soap:Body>
    <wsd:Probe/>
  </soap:Body>
</soap:Envelope>"#;

    probe.as_bytes().to_vec()
}

fn parse_wsd_response(data: &[u8]) -> Result<String> {
    let response = String::from_utf8_lossy(data);

    if let Some(start) = response.find("<wsd:Computer>") {
        if let Some(end) = response[start..].find("</wsd:Computer>") {
            let name_start = start + "<wsd:Computer>".len();
            let name_end = start + end;
            if name_end > name_start {
                let name = response[name_start..name_end].trim().to_string();
                if !name.is_empty() {
                    return Ok(name);
                }
            }
        }
    }

    if let Some(start) = response.find("<wsa:Address>") {
        if let Some(end) = response[start..].find("</wsa:Address>") {
            let addr_start = start + "<wsa:Address>".len();
            let addr_end = start + end;
            if addr_end > addr_start {
                let addr = response[addr_start..addr_end].trim();
                if let Some(hostname) = addr.split('/').last() {
                    let name = hostname.trim().to_string();
                    if !name.is_empty() && !name.starts_with("urn:") {
                        return Ok(name);
                    }
                }
            }
        }
    }

    Err(anyhow::anyhow!("No name found in WSD response"))
}
