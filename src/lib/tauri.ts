import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

export interface NetworkInterface {
  name: string;
  display_name: string;
  ip: string;
  netmask: string;
  mac?: string;
  gateway?: string;
}

export interface Host {
  ipv4?: string;
  ipv6_local?: string;
  ipv6_global: string[];
  mac?: string;
  vendor?: string;
  hostname?: string;
  mdns_name?: string;
  smb_name?: string;
  smb_domain?: string;
  dns_name?: string;
  arp_responsive: boolean;    // Responds to ARP (Layer 2)
  icmp_responsive: boolean;   // Responds to ICMP ping (Layer 3)
  tcp_ports_open: number[];
  last_seen: number;
}

export interface ScanProgress {
  total: number;
  scanned: number;
  found: number;
  message: string;
}

export interface PortScanResult {
  host_ip: string;
  open_ports: number[];
  scan_type: string;
}

export async function getNetworkInterfaces(): Promise<NetworkInterface[]> {
  return await invoke('get_network_interfaces');
}

export async function startNetworkScan(
  interfaceName: string,
  subnet: string
): Promise<void> {
  return await invoke('start_network_scan', {
    interfaceName,
    subnet,
  });
}

export async function stopNetworkScan(): Promise<void> {
  return await invoke('stop_network_scan');
}

export async function getScanResults(): Promise<Host[]> {
  return await invoke('get_scan_results');
}

export async function scanHostPorts(
  hostIp: string,
  scanType: 'common' | 'all' | 'custom',
  customRange?: [number, number]
): Promise<PortScanResult> {
  return await invoke('scan_host_ports', {
    hostIp,
    scanType,
    customRange,
  });
}

export async function resolveHostInfo(hostIp: string): Promise<Host> {
  return await invoke('resolve_host_info', { hostIp });
}

export async function calculateSubnet(
  ip: string,
  netmask: string
): Promise<string> {
  return await invoke('calculate_subnet', { ip, netmask });
}

// Event listeners
export function onScanProgress(callback: (progress: ScanProgress) => void) {
  return listen<ScanProgress>('scan-progress', (event) => {
    callback(event.payload);
  });
}

export function onScanComplete(callback: () => void) {
  return listen('scan-complete', () => {
    callback();
  });
}

export function onScanHost(callback: (host: Host) => void) {
  return listen<Host>('scan-host', (event) => {
    callback(event.payload);
  });
}

export function onPortScanStart(callback: (hostIp: string) => void) {
  return listen<string>('port-scan-start', (event) => {
    callback(event.payload);
  });
}

export function onPortScanComplete(callback: (result: PortScanResult) => void) {
  return listen<PortScanResult>('port-scan-complete', (event) => {
    callback(event.payload);
  });
}
