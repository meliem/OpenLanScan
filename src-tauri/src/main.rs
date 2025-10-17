// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod types;
mod scanner;
mod resolver;
mod port_scanner;
mod vendor;

use scanner::NetworkScanner;
use resolver::HostResolver;
use port_scanner::PortScanner;
use types::{NetworkInterface, Host, ScanProgress, PortScanResult};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tauri::{Emitter, State, Manager};
use futures::stream::StreamExt;

// Timeout constants
const PORT_SCANNER_TIMEOUT_MS: u64 = 500; // Port scanning timeout - reasonable for reliability

// Application state
pub struct AppState {
    scanner: Arc<RwLock<NetworkScanner>>,
    resolver: Arc<RwLock<Option<HostResolver>>>,
    scan_stop_flag: Arc<AtomicBool>,
}

#[tauri::command]
async fn get_network_interfaces() -> Result<Vec<NetworkInterface>, String> {
    let interfaces = if_addrs::get_if_addrs()
        .map_err(|e| format!("Failed to get interfaces: {}", e))?;

    let mut result = Vec::new();

    for iface in interfaces {
        if iface.is_loopback() {
            continue;
        }

        // Only keep IPv4 interfaces for now (IPv6 support can be added later)
        if let if_addrs::IfAddr::V4(ref v4) = iface.addr {
            let ip = v4.ip.to_string();
            let netmask = v4.netmask.to_string();

            // Get MAC address if available
            let mac = get_interface_mac(&iface.name);

            // Try to get gateway
            let gateway = get_default_gateway();

            result.push(NetworkInterface {
                name: iface.name.clone(),
                display_name: format!("{} - {}", iface.name, ip),
                ip,
                netmask,
                mac,
                gateway,
            });
        }
    }

    Ok(result)
}

#[tauri::command]
async fn stop_network_scan(
    state: State<'_, AppState>,
) -> Result<(), String> {
    // Set the stop flag to signal ongoing scans to stop
    state.scan_stop_flag.store(true, Ordering::Relaxed);
    log::info!("Stop scan requested");
    Ok(())
}

#[tauri::command]
async fn start_network_scan(
    interface_name: String,
    subnet: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    // Reset the stop flag at the start of a new scan
    state.scan_stop_flag.store(false, Ordering::Relaxed);

    let scanner = state.scanner.clone();
    let resolver_state = state.resolver.clone();
    let stop_flag = state.scan_stop_flag.clone();

    // Initialize resolver if not already done
    {
        let mut resolver_lock = resolver_state.write().await;
        if resolver_lock.is_none() {
            log::debug!("Attempting to initialize DNS resolver");
            match HostResolver::new().await {
                Ok(resolver) => {
                    log::info!("DNS resolver initialized successfully");
                    *resolver_lock = Some(resolver);
                }
                Err(e) => {
                    log::error!("Failed to initialize DNS resolver: {}", e);
                    log::warn!("Hostname resolution will be disabled");
                    // For now, continue without resolver - hostname resolution will be limited
                    // In production, you might want to return an error here
                }
            }
        } else {
            log::debug!("DNS resolver already initialized");
        }
    }

    // Start ARP scan in background
    tokio::spawn(async move {
        log::info!("Starting scan on interface: {} with subnet: {}", interface_name, subnet);

        // Clear existing hosts
        let scanner_lock = scanner.read().await;
        scanner_lock.clear_hosts().await;

        let progress_handler: Arc<dyn Fn(ScanProgress) + Send + Sync> = {
            let app_handle_progress = app_handle.clone();
            Arc::new(move |progress: ScanProgress| {
                let percent = if progress.total == 0 {
                    0
                } else {
                    (progress.scanned * 100) / progress.total
                };
                log::debug!(
                    "Scan progress: {}/{} ({}%) - {}",
                    progress.scanned,
                    progress.total,
                    percent,
                    progress.message
                );
                let _ = app_handle_progress.emit("scan-progress", &progress);
            })
        };

        // Simple host handler - just emit discovered hosts (minimal logging)
        let host_handler: Arc<dyn Fn(Host) + Send + Sync> = {
            let app_handle_host = app_handle.clone();
            let emit_counter = Arc::new(AtomicUsize::new(0));

            Arc::new(move |host: Host| {
                let count = emit_counter.fetch_add(1, Ordering::Relaxed) + 1;
                // Only log every 20th emission to reduce spam
                if count % 20 == 0 {
                    log::debug!("Emitted {} hosts to UI", count);
                }
                let _ = app_handle_host.emit("scan-host", &host);
            })
        };

        // Run ARP and ICMP ping scans IN PARALLEL for maximum speed and coverage
        let arp_future = scanner_lock.scan_arp(
            &interface_name,
            &subnet,
            progress_handler.clone(),
            host_handler.clone()
        );

        let icmp_future = scanner_lock.scan_icmp_ping(
            &subnet,
            progress_handler.clone(),
            host_handler.clone()
        );

        // Execute both scans in parallel
        let (arp_result, icmp_result) = tokio::join!(arp_future, icmp_future);

        if let Err(e) = arp_result {
            log::error!("ARP scan error: {}", e);
        }

        if let Err(e) = icmp_result {
            log::error!("ICMP scan error: {}", e);
        }

        log::info!("Both ARP and ICMP scans completed");

        // Note: TCP port discovery is NOT performed during network scan as it's too slow.
        // Users can explicitly scan ports on individual hosts using the "Port Scan" feature.

        // Second pass: Resolve hostnames using all methods (DNS, mDNS, NetBIOS, WSD)
        drop(scanner_lock);
        log::info!("Starting comprehensive hostname resolution");

        let hosts = {
            let scanner_read = scanner.read().await;
            scanner_read.get_hosts().await
        };

        log::info!("Resolving hostnames for {} hosts using DNS/mDNS/NetBIOS/WSD", hosts.len());

        // Get the resolver
        let resolver_opt = resolver_state.read().await;
        if let Some(resolver) = &*resolver_opt {
            use futures::stream;

            let resolver_arc = Arc::new(resolver.dns_resolver.clone());
            let stop_flag_clone = stop_flag.clone();
            let app_handle_clone = app_handle.clone();
            let scanner_clone = scanner.clone();

            // Process 50 hosts in parallel for optimal speed without overwhelming the network
            stream::iter(hosts)
                .for_each_concurrent(50, move |mut host| {
                    let stop_flag = stop_flag_clone.clone();
                    let app_handle = app_handle_clone.clone();
                    let scanner = scanner_clone.clone();
                    let resolver_dns = resolver_arc.clone();

                    async move {
                        if stop_flag.load(Ordering::Relaxed) {
                            return;
                        }

                        // Resolve using all methods in parallel
                        if let Some(ref ipv4_str) = host.ipv4 {
                            if let Ok(ipv4_parsed) = ipv4_str.parse::<std::net::Ipv4Addr>() {
                                if let Ok(ip_addr) = ipv4_str.parse::<std::net::IpAddr>() {
                                    // Launch all resolution methods in parallel
                                    let dns_future = async {
                                        if let Ok(Ok(names)) = tokio::time::timeout(
                                            std::time::Duration::from_millis(300),
                                            resolver_dns.reverse_lookup(ip_addr)
                                        ).await {
                                            return names.iter().next().map(|n| n.to_string().trim_end_matches('.').to_string());
                                        }
                                        None
                                    };

                                    let mdns_future = async {
                                        crate::resolver::query_mdns_fast(ipv4_parsed).await.ok()
                                    };

                                    let netbios_future = async {
                                        crate::resolver::query_netbios_fast(ipv4_parsed).await.ok()
                                    };

                                    let wsd_future = async {
                                        crate::resolver::query_wsd_fast(ipv4_parsed).await.ok()
                                    };

                                    let llmnr_future = async {
                                        crate::resolver::query_llmnr(ipv4_parsed).await.ok()
                                    };

                                    // Execute all in parallel
                                    let (dns_result, mdns_result, netbios_result, wsd_result, llmnr_result) = tokio::join!(
                                        dns_future,
                                        mdns_future,
                                        netbios_future,
                                        wsd_future,
                                        llmnr_future
                                    );

                                    // Only log if we found something (reduce spam)
                                    if dns_result.is_some() || mdns_result.is_some() || netbios_result.is_some() || wsd_result.is_some() || llmnr_result.is_some() {
                                        log::debug!("Resolution results for {}: DNS={:?}, mDNS={:?}, NetBIOS={:?}, WSD={:?}, LLMNR={:?}",
                                            ipv4_str, dns_result, mdns_result, netbios_result, wsd_result, llmnr_result);
                                    }

                                    // Update host with results
                                    if let Some(dns_name) = dns_result {
                                        log::debug!("Setting DNS name for {}: {}", ipv4_str, dns_name);
                                        host.dns_name = Some(dns_name.clone());
                                        if host.hostname.is_none() {
                                            host.hostname = Some(dns_name);
                                        }
                                    }

                                    if let Some(mdns_name) = mdns_result {
                                        log::debug!("Setting mDNS name for {}: {}", ipv4_str, mdns_name);
                                        host.mdns_name = Some(mdns_name.clone());
                                        if host.hostname.is_none() {
                                            host.hostname = Some(mdns_name);
                                        }
                                    }

                                    if let Some((smb_name, smb_domain)) = netbios_result {
                                        log::debug!("Setting NetBIOS name for {}: {} (domain: {:?})", ipv4_str, smb_name, smb_domain);
                                        host.smb_name = Some(smb_name.clone());
                                        host.smb_domain = smb_domain;
                                        if host.hostname.is_none() {
                                            host.hostname = Some(smb_name);
                                        }
                                    }

                                    if let Some(wsd_name) = wsd_result {
                                        log::debug!("Setting WSD name for {}: {}", ipv4_str, wsd_name);
                                        if host.hostname.is_none() {
                                            host.hostname = Some(wsd_name);
                                        }
                                    }

                                    if let Some(llmnr_name) = llmnr_result {
                                        log::debug!("Setting LLMNR name for {}: {}", ipv4_str, llmnr_name);
                                        if host.hostname.is_none() {
                                            host.hostname = Some(llmnr_name);
                                        }
                                    }

                                    // Update the host in the scanner's storage
                                    let scanner_write = scanner.write().await;
                                    let mut hosts_map = scanner_write.hosts.write().await;
                                    let key = host.ipv4.clone().unwrap_or_else(|| host.identifier());
                                    hosts_map.insert(key, host.clone());
                                    drop(hosts_map);
                                    drop(scanner_write);

                                    log::debug!("Final hostname for {}: {:?}", ipv4_str, host.hostname);

                                    // Emit updated host to UI
                                    let _ = app_handle.emit("scan-host", &host);
                                }
                            }
                        }
                    }
                })
                .await;

            log::info!("Hostname resolution completed");
        } else {
            log::warn!("DNS resolver not available, hostname resolution skipped");
        }

        // Check one final time before emitting complete
        if stop_flag.load(Ordering::Relaxed) {
            log::info!("Scan stopped by user");
        } else {
            log::info!("Scan completed successfully");
        }

        // Emit scan complete
        let _ = app_handle.emit("scan-complete", ());
    });

    Ok(())
}

#[tauri::command]
async fn get_scan_results(state: State<'_, AppState>) -> Result<Vec<Host>, String> {
    let scanner = state.scanner.read().await;
    Ok(scanner.get_hosts().await)
}

#[tauri::command]
async fn scan_host_ports(
    host_ip: String,
    scan_type: String, // "common" | "all" | "custom"
    custom_range: Option<(u16, u16)>,
    app_handle: tauri::AppHandle,
) -> Result<PortScanResult, String> {
    let scanner = PortScanner::new(PORT_SCANNER_TIMEOUT_MS);

    // Emit start event
    let _ = app_handle.emit("port-scan-start", &host_ip);

    let result = match scan_type.as_str() {
        "common" => scanner.scan_common_ports(&host_ip).await,
        "all" => scanner.scan_all_ports(&host_ip).await,
        "custom" => {
            if let Some((start, end)) = custom_range {
                scanner.scan_port_range(&host_ip, start, end).await
            } else {
                return Err("Custom range requires start and end ports".to_string());
            }
        }
        _ => return Err("Invalid scan type".to_string()),
    };

    match result {
        Ok(res) => {
            // Emit complete event
            let _ = app_handle.emit("port-scan-complete", &res);
            Ok(res)
        }
        Err(e) => Err(format!("Port scan failed: {}", e)),
    }
}

#[tauri::command]
async fn resolve_host_info(
    host_ip: String,
    state: State<'_, AppState>,
) -> Result<Host, String> {
    let scanner = state.scanner.read().await;
    let resolver_state = state.resolver.read().await;

    // Get host from scanner
    let mut host = scanner.get_hosts().await
        .into_iter()
        .find(|h| h.ipv4.as_ref() == Some(&host_ip))
        .ok_or_else(|| "Host not found".to_string())?;

    // Resolve additional info only if resolver is available
    if let Some(resolver) = &*resolver_state {
        resolver.resolve_all(&mut host).await
            .map_err(|e| format!("Resolution failed: {}", e))?;
    } else {
        log::warn!("DNS resolver not available, hostname resolution disabled");
    }

    Ok(host)
}

#[tauri::command]
async fn calculate_subnet(ip: String, netmask: String) -> Result<String, String> {
    use std::net::Ipv4Addr;

    log::debug!("calculate_subnet: ip={}, netmask={}", ip, netmask);

    let ip_addr: Ipv4Addr = ip.parse()
        .map_err(|_| "Invalid IP address".to_string())?;
    let netmask_addr: Ipv4Addr = netmask.parse()
        .map_err(|_| "Invalid netmask".to_string())?;

    // Calculate network address
    let ip_u32 = u32::from(ip_addr);
    let mask_u32 = u32::from(netmask_addr);
    let network_u32 = ip_u32 & mask_u32;
    let network = Ipv4Addr::from(network_u32);

    // Calculate prefix length
    let prefix_len = mask_u32.count_ones();

    let result = format!("{}/{}", network, prefix_len);
    log::debug!("calculate_subnet: result={}", result);

    Ok(result)
}

fn get_interface_mac(interface_name: &str) -> Option<String> {
    use pnet::datalink;

    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .and_then(|iface| iface.mac)
        .map(|mac| format!("{}", mac))
}

fn get_default_gateway() -> Option<String> {
    // Platform-specific gateway detection
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;

        let output_str = String::from_utf8(output.stdout).ok()?;
        for line in output_str.lines() {
            if line.trim().starts_with("gateway:") {
                return line.split_whitespace().nth(1).map(|s| s.to_string());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;

        let output_str = String::from_utf8(output.stdout).ok()?;
        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(idx) = parts.iter().position(|&s| s == "via") {
                if idx + 1 < parts.len() {
                    return Some(parts[idx + 1].to_string());
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        let output = Command::new("ipconfig")
            .output()
            .ok()?;

        let output_str = String::from_utf8(output.stdout).ok()?;
        for line in output_str.lines() {
            if line.contains("Default Gateway") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    return Some(parts[1].trim().to_string());
                }
            }
        }
    }

    None
}

fn main() {
    // Initialize logger - RUST_LOG=debug cargo run for verbose logs
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    log::info!("Starting OpenLanScan");

    tauri::Builder::default()
        .setup(|app| {
            // Initialize app state
            let scanner = Arc::new(RwLock::new(NetworkScanner::new()));
            let resolver = Arc::new(RwLock::new(None));
            let scan_stop_flag = Arc::new(AtomicBool::new(false));

            app.manage(AppState { scanner, resolver, scan_stop_flag });

            log::info!("Application state initialized");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_network_interfaces,
            start_network_scan,
            stop_network_scan,
            get_scan_results,
            scan_host_ports,
            resolve_host_info,
            calculate_subnet,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            log::error!("Fatal error running Tauri application: {}", e);
            std::process::exit(1);
        });
}
