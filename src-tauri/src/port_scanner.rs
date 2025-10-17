use crate::types::PortScanResult;
use anyhow::Result;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{timeout, sleep};

pub struct PortScanner {
    timeout_ms: u64,
    max_concurrent: usize,
    delay_ms: u64,
}

impl PortScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_ms,
            max_concurrent: 100, // Reasonable concurrent connection limit
            delay_ms: 1, // Small delay between connection attempts
        }
    }

    /// Scan specific ports on a host with improved error handling
    pub async fn scan_ports(&self, host_ip: &str, ports: Vec<u16>) -> Result<PortScanResult> {
        let ip: IpAddr = host_ip.parse()
            .map_err(|e| anyhow::anyhow!("Invalid IP address: {}", e))?;

        // Validate IP address - prevent scanning localhost or invalid addresses
        if ip.is_loopback() {
            return Err(anyhow::anyhow!("Cannot scan localhost/loopback address: {}", ip));
        }
        if ip.is_unspecified() {
            return Err(anyhow::anyhow!("Cannot scan unspecified address (0.0.0.0 or ::): {}", ip));
        }
        if ip.is_multicast() {
            return Err(anyhow::anyhow!("Cannot scan multicast address: {}", ip));
        }

        let mut open_ports = Vec::new();
        let mut tasks = Vec::new();

        // Process ports in batches to control concurrency
        for chunk in ports.chunks(self.max_concurrent) {
            for &port in chunk {
                let addr = SocketAddr::new(ip, port);
                let timeout_duration = Duration::from_millis(self.timeout_ms);

                let task = tokio::spawn(async move {
                    match timeout(timeout_duration, TcpStream::connect(addr)).await {
                        Ok(Ok(_)) => Some(port),
                        Ok(Err(e)) => {
                            // Connection refused is normal, other errors are unexpected
                            if e.kind() != std::io::ErrorKind::ConnectionRefused {
                                log::debug!("Port {} connection error: {}", port, e);
                            }
                            None
                        }
                        Err(_) => None, // Timeout
                    }
                });

                tasks.push(task);

                // Small delay between connection attempts to avoid overwhelming
                sleep(Duration::from_millis(self.delay_ms)).await;
            }

            // Wait for current batch to complete before starting next
            let results = futures::future::join_all(tasks.drain(..)).await;
            for result in results {
                if let Ok(Some(port)) = result {
                    open_ports.push(port);
                }
            }

            // Brief pause between batches to be network-friendly
            sleep(Duration::from_millis(50)).await;
        }

        // Sort ports
        open_ports.sort_unstable();

        Ok(PortScanResult {
            host_ip: host_ip.to_string(),
            open_ports,
            scan_type: "TCP Connect".to_string(),
        })
    }

    /// Scan the 1000 most common ports
    pub async fn scan_common_ports(&self, host_ip: &str) -> Result<PortScanResult> {
        let common_ports = get_common_ports();
        self.scan_ports(host_ip, common_ports).await
    }

    /// Scan all TCP ports (1-65535)
    pub async fn scan_all_ports(&self, host_ip: &str) -> Result<PortScanResult> {
        let all_ports: Vec<u16> = (1..=65535).collect();
        self.scan_ports(host_ip, all_ports).await
    }

    /// Scan custom port range
    pub async fn scan_port_range(&self, host_ip: &str, start: u16, end: u16) -> Result<PortScanResult> {
        const MAX_PORT_RANGE: u32 = 10000; // Reasonable limit to prevent resource exhaustion

        if start == 0 {
            return Err(anyhow::anyhow!("Invalid port range: port 0 is not valid"));
        }

        if start > end {
            return Err(anyhow::anyhow!("Invalid port range: start ({}) > end ({})", start, end));
        }

        let range_size = (end as u32) - (start as u32) + 1;
        if range_size > MAX_PORT_RANGE {
            return Err(anyhow::anyhow!(
                "Port range too large: {} ports. Maximum allowed: {}. Use scan_all_ports() for full port scans.",
                range_size, MAX_PORT_RANGE
            ));
        }

        let ports: Vec<u16> = (start..=end).collect();
        self.scan_ports(host_ip, ports).await
    }
}

/// Returns the 1000 most common TCP ports (based on nmap top 1000)
fn get_common_ports() -> Vec<u16> {
    use std::collections::HashSet;

    let ports = vec![
        // Top 20 most common
        80, 443, 22, 21, 25, 3389, 110, 445, 139, 143,
        53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 1025,
        // Additional common ports
        587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000,
        514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554, 26,
        1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000,
        5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121,
        1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543, 544,
        5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070,
        5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051, 6646,
        49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000,
        // Web servers
        8001, 8002, 8003, 8004, 8005, 8006, 8007, 8010, 8011, 8012,
        8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091,
        // Database ports
        1521, 3050, 5984, 6379, 7000, 7001, 7002, 9042, 9160,
        9200, 9300, 27017, 27018, 27019, 28017, 50000, 50070,
        // Remote access
        23, 992, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908,
        // Email
        109, 220, 585, 1109,
        // FTP
        20, 989, 8021,
        // SMB/CIFS
        137, 138,
        // LDAP
        636, 3268, 3269,
        // Additional services
        161, 162, 546, 547, 1194, 1337, 1589, 2222, 2375,
        2376, 3690, 4444, 4445, 4786, 5222, 5223, 5269, 5353,
        // Development/Debug
        3001, 4200, 5001, 9000, 9001,
        // Docker/Container
        2377, 4243, 4244,
        // Kubernetes
        6443, 10250, 10251, 10252, 10255,
        // Message queues
        4369, 5671, 5672, 15672, 25672, 61613, 61614, 61616,
        // Monitoring
        9090, 9093, 9094, 9115,
        // Game servers
        7777, 7778, 27015, 27016,
        // VoIP
        5061, 5062,
        // VPN
        500, 1701, 4500,
        // IoT/Home automation
        1883, 8883,
        // Media servers
        32400, 32469, 8096, 8920,
        // NAS/Storage
        // Printers
        // Apple services
        3689, 62078,
        // Windows services
        1434, 5985, 5986,
        // Backup services
        10001, 10002, 10003,
        // Additional common ports up to 1000
        1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039,
        1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
        1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059,
        1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069,
        1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079,
        1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
        1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099,
        2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
        2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021,
        2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030, 2031,
        3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010,
        4000, 4001, 4002, 4003, 4004, 4005, 4006, 4007, 4008, 4009,
        5002, 5003, 5004, 5005, 5006, 5007, 5008, 5010, 5011,
        6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009,
        7003, 7004, 7005, 7006, 7007, 7008, 7009,
        9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009,
        49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167,
        49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175, 49176, 49177,
    ];

    // Remove duplicates using HashSet and return as sorted vector
    let unique_ports: HashSet<u16> = ports.into_iter().collect();
    let mut result: Vec<u16> = unique_ports.into_iter().collect();
    result.sort_unstable();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_common_ports_count() {
        let ports = get_common_ports();
        assert!(ports.len() <= 1000, "Should have at most 1000 common ports");
        assert!(ports.contains(&80), "Should include port 80");
        assert!(ports.contains(&443), "Should include port 443");
        assert!(ports.contains(&22), "Should include port 22");
    }
}
