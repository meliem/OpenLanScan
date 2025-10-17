use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub display_name: String,
    pub ip: String,
    pub netmask: String,
    pub mac: Option<String>,
    pub gateway: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ipv4: Option<String>,
    pub ipv6_local: Option<String>,
    pub ipv6_global: Vec<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub mdns_name: Option<String>,
    pub smb_name: Option<String>,
    pub smb_domain: Option<String>,
    pub dns_name: Option<String>,
    pub arp_responsive: bool,      // Responds to ARP (Layer 2)
    pub icmp_responsive: bool,     // Responds to ICMP ping (Layer 3)
    pub tcp_ports_open: Vec<u16>,
    pub last_seen: u64,
}

impl Host {
    pub fn new(ip: IpAddr) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();

        match ip {
            IpAddr::V4(ipv4) => Self {
                ipv4: Some(ipv4.to_string()),
                ipv6_local: None,
                ipv6_global: Vec::new(),
                mac: None,
                vendor: None,
                hostname: None,
                mdns_name: None,
                smb_name: None,
                smb_domain: None,
                dns_name: None,
                arp_responsive: false,
                icmp_responsive: false,
                tcp_ports_open: Vec::new(),
                last_seen: now,
            },
            IpAddr::V6(ipv6) => {
                if ipv6.is_loopback() || ipv6.segments()[0] & 0xffc0 == 0xfe80 {
                    // Link-local
                    Self {
                        ipv4: None,
                        ipv6_local: Some(ipv6.to_string()),
                        ipv6_global: Vec::new(),
                        mac: None,
                        vendor: None,
                        hostname: None,
                        mdns_name: None,
                        smb_name: None,
                        smb_domain: None,
                        dns_name: None,
                        arp_responsive: false,
                        icmp_responsive: false,
                        tcp_ports_open: Vec::new(),
                        last_seen: now,
                    }
                } else {
                    Self {
                        ipv4: None,
                        ipv6_local: None,
                        ipv6_global: vec![ipv6.to_string()],
                        mac: None,
                        vendor: None,
                        hostname: None,
                        mdns_name: None,
                        smb_name: None,
                        smb_domain: None,
                        dns_name: None,
                        arp_responsive: false,
                        icmp_responsive: false,
                        tcp_ports_open: Vec::new(),
                        last_seen: now,
                    }
                }
            }
        }
    }

    pub fn identifier(&self) -> String {
        if let Some(ref ipv4) = self.ipv4 {
            ipv4.clone()
        } else if let Some(ref ipv6) = self.ipv6_local {
            ipv6.clone()
        } else if !self.ipv6_global.is_empty() {
            self.ipv6_global[0].clone()
        } else if let Some(ref mac) = self.mac {
            mac.clone()
        } else {
            "unknown".to_string()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub total: usize,
    pub scanned: usize,
    pub found: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanResult {
    pub host_ip: String,
    pub open_ports: Vec<u16>,
    pub scan_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_host_ipv4_identifier() {
        let host = Host::new(IpAddr::V4("192.168.1.100".parse().unwrap()));
        assert_eq!(host.identifier(), "192.168.1.100");
    }

    #[test]
    fn test_host_ipv6_identifier() {
        let host = Host::new(IpAddr::V6("fe80::1".parse().unwrap()));
        assert_eq!(host.identifier(), "fe80::1");
    }

    #[test]
    fn test_host_mac_identifier() {
        let mut host = Host::new(IpAddr::V4("192.168.1.100".parse().unwrap()));
        host.mac = Some("00:11:22:33:44:55".to_string());
        assert_eq!(host.identifier(), "00:11:22:33:44:55");
    }

    #[test]
    fn test_host_unknown_identifier() {
        let host = Host {
            ipv4: None,
            ipv6_local: None,
            ipv6_global: vec![],
            mac: None,
            vendor: None,
            hostname: None,
            mdns_name: None,
            smb_name: None,
            smb_domain: None,
            dns_name: None,
            arp_responsive: false,
            icmp_responsive: false,
            tcp_ports_open: vec![],
            last_seen: 1234567890,
        };
        assert_eq!(host.identifier(), "unknown");
    }

    #[test]
    fn test_network_interface_creation() {
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            display_name: "eth0 - 192.168.1.1".to_string(),
            ip: "192.168.1.1".to_string(),
            netmask: "255.255.255.0".to_string(),
            mac: Some("00:11:22:33:44:55".to_string()),
            gateway: Some("192.168.1.1".to_string()),
        };

        assert_eq!(interface.name, "eth0");
        assert_eq!(interface.ip, "192.168.1.1");
    }

    #[test]
    fn test_scan_progress_creation() {
        let progress = ScanProgress {
            total: 100,
            scanned: 50,
            found: 10,
            message: "Scanning...".to_string(),
        };

        assert_eq!(progress.total, 100);
        assert_eq!(progress.scanned, 50);
        assert_eq!(progress.found, 10);
    }

    #[test]
    fn test_port_scan_result_creation() {
        let result = PortScanResult {
            host_ip: "192.168.1.1".to_string(),
            open_ports: vec![80, 443, 22],
            scan_type: "TCP Connect".to_string(),
        };

        assert_eq!(result.host_ip, "192.168.1.1");
        assert_eq!(result.open_ports, vec![80, 443, 22]);
        assert_eq!(result.scan_type, "TCP Connect");
    }
}
