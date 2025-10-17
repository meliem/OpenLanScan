<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import type { NetworkInterface, Host, ScanProgress } from './lib/tauri';
  import {
    getNetworkInterfaces,
    startNetworkScan,
    stopNetworkScan,
    getScanResults,
    calculateSubnet,
    onScanProgress,
    onScanComplete,
    onScanHost,
  } from './lib/tauri';

  import ConfigDialog from './lib/ConfigDialog.svelte';
  import HostTable from './lib/HostTable.svelte';
  import HostDetails from './lib/HostDetails.svelte';
  import ProgressBar from './lib/ProgressBar.svelte';

  let interfaces: NetworkInterface[] = [];
  let selectedInterface: NetworkInterface | null = null;
  let subnet: string = '';
  let subnetFrom: string = '';
  let subnetTo: string = '';

  let hosts: Host[] = [];
  let selectedHost: Host | null = null;
  let isScanning = false;
  let scanProgress: ScanProgress | null = null;

  let showConfigDialog = false;

  let unsubscribeProgress: (() => void) | null = null;
  let unsubscribeComplete: (() => void) | null = null;
  let unsubscribeHost: (() => void) | null = null;

  function getHostKey(host: Host): string {
    return (
      host.ipv4 ||
      host.mac ||
      host.hostname ||
      host.mdns_name ||
      host.smb_name ||
      host.dns_name ||
      `host-${host.last_seen}`
    );
  }

  function mergeHost(existing: Host | undefined, incoming: Host): Host {
    if (!existing) {
      return {
        ...incoming,
        ipv6_global: [...incoming.ipv6_global],
        tcp_ports_open: [...incoming.tcp_ports_open],
        arp_responsive: incoming.arp_responsive ?? false,
        icmp_responsive: incoming.icmp_responsive ?? false,
      };
    }

    const mergedPorts = Array.from(
      new Set([...(existing.tcp_ports_open || []), ...(incoming.tcp_ports_open || [])])
    ).sort((a, b) => a - b);

    return {
      ...existing,
      ipv4: incoming.ipv4 ?? existing.ipv4,
      ipv6_local: incoming.ipv6_local ?? existing.ipv6_local,
      ipv6_global:
        incoming.ipv6_global && incoming.ipv6_global.length > 0
          ? [...incoming.ipv6_global]
          : existing.ipv6_global,
      mac: incoming.mac ?? existing.mac,
      vendor: incoming.vendor ?? existing.vendor,
      hostname: incoming.hostname || existing.hostname,        // Prefer incoming if it has any value
      mdns_name: incoming.mdns_name || existing.mdns_name,    // Prefer incoming if it has any value
      smb_name: incoming.smb_name || existing.smb_name,        // Prefer incoming if it has any value
      smb_domain: incoming.smb_domain || existing.smb_domain,  // Prefer incoming if it has any value
      dns_name: incoming.dns_name || existing.dns_name,        // Prefer incoming if it has any value
      arp_responsive: incoming.arp_responsive || existing.arp_responsive, // If either scan confirms ARP, it's responsive
      icmp_responsive: incoming.icmp_responsive || existing.icmp_responsive, // If either scan confirms ICMP, it's responsive
      tcp_ports_open: mergedPorts,
      last_seen: Math.max(incoming.last_seen, existing.last_seen),
    };
  }

  function ipv4ToNumber(ip: string): number {
    const parts = ip.trim().split('.');
    if (parts.length !== 4) {
      throw new Error(`Invalid IPv4 format: ${ip}`);
    }

    return parts.reduce((acc, part) => {
      const octet = Number(part);
      if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
        throw new Error(`Invalid IPv4 octet: ${ip}`);
      }
      return ((acc << 8) | octet) >>> 0;
    }, 0);
  }

  function numberToIpv4(value: number): string {
    return [
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    ].join('.');
  }

  function getRangeFromSubnet(subnetValue: string) {
    const [networkRaw, prefixRaw] = subnetValue.split('/');
    if (!networkRaw || !prefixRaw) {
      throw new Error(`Invalid subnet: ${subnetValue}`);
    }

    const prefix = Number(prefixRaw);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      throw new Error(`Invalid subnet prefix: ${subnetValue}`);
    }

    const networkInt = ipv4ToNumber(networkRaw);
    const mask = prefix === 0 ? 0 : ((0xffffffff << (32 - prefix)) >>> 0);
    const normalizedNetwork = networkInt & mask;
    const broadcastInt = normalizedNetwork | ((~mask) >>> 0);

    let firstHostInt = normalizedNetwork;
    let lastHostInt = broadcastInt;

    if (prefix <= 30) {
      firstHostInt = Math.min(normalizedNetwork + 1, 0xffffffff);
      lastHostInt = Math.max(broadcastInt - 1, normalizedNetwork);
    } else if (prefix === 31) {
      firstHostInt = normalizedNetwork;
      lastHostInt = broadcastInt;
    } else {
      firstHostInt = normalizedNetwork;
      lastHostInt = normalizedNetwork;
    }

    return {
      network: numberToIpv4(normalizedNetwork >>> 0),
      broadcast: numberToIpv4(broadcastInt >>> 0),
      from: numberToIpv4(firstHostInt >>> 0),
      to: numberToIpv4(lastHostInt >>> 0),
    };
  }

  function isPowerOfTwo(value: number): boolean {
    return value > 0 && (value & (value - 1)) === 0;
  }

  function deriveSubnetFromRange(fromValue: string, toValue: string): string | null {
    try {
      const fromInt = ipv4ToNumber(fromValue);
      const toInt = ipv4ToNumber(toValue);

      if (fromInt > toInt) {
        return null;
      }

      if (fromInt === toInt) {
        return `${numberToIpv4(fromInt)}/32`;
      }

      if (toInt - fromInt === 1) {
        // Potential /31 network: ensure alignment on even boundary
        if ((fromInt & 0x1) === 0) {
          return `${numberToIpv4(fromInt)}/31`;
        }
        return null;
      }

      if (fromInt === 0 || toInt === 0xffffffff) {
        return null;
      }

      const hostCount = toInt - fromInt + 1;
      const totalAddresses = hostCount + 2; // include network and broadcast

      if (!isPowerOfTwo(totalAddresses)) {
        return null;
      }

      const networkInt = (fromInt - 1) >>> 0;
      const blockMask = totalAddresses - 1;

      if ((networkInt & blockMask) !== 0) {
        return null;
      }

      const prefix = 32 - Math.log2(totalAddresses);
      if (!Number.isInteger(prefix)) {
        return null;
      }

      return `${numberToIpv4(networkInt)}/${prefix}`;
    } catch (err) {
      console.warn('Failed to derive subnet from range', err);
      return null;
    }
  }

  function applySubnetRange(currentSubnet: string) {
    try {
      const range = getRangeFromSubnet(currentSubnet);
      subnetFrom = range.from;
      subnetTo = range.to;
    } catch (err) {
      console.error('Failed to derive subnet range', err);
      subnetFrom = '';
      subnetTo = '';
    }
  }

  onMount(async () => {
    // Load network interfaces
    await loadInterfaces();

    // Subscribe to scan events
    unsubscribeProgress = await onScanProgress((progress) => {
      scanProgress = progress;
    });

    unsubscribeComplete = await onScanComplete(async () => {
      console.log("Scan complete event received");
      isScanning = false;
      scanProgress = null;
      // Don't reload - hosts are already updated dynamically via onScanHost
      // await loadResults();
    });

    unsubscribeHost = await onScanHost((hostUpdate) => {
      console.log("Received host update:", {
        ip: hostUpdate.ipv4,
        hostname: hostUpdate.hostname,
        dns_name: hostUpdate.dns_name,
        mdns_name: hostUpdate.mdns_name,
        smb_name: hostUpdate.smb_name,
      });

      const key = getHostKey(hostUpdate);
      const index = hosts.findIndex((existing) => getHostKey(existing) === key);

      if (index >= 0) {
        const merged = mergeHost(hosts[index], hostUpdate);
        hosts = [
          ...hosts.slice(0, index),
          merged,
          ...hosts.slice(index + 1),
        ];
      } else {
        hosts = [...hosts, mergeHost(undefined, hostUpdate)];
      }
    });

    // Poll for network interface changes every 5 seconds
    const networkCheckInterval = setInterval(async () => {
      if (isScanning) return; // Don't change interface during scan

      try {
        const currentInterfaces = await getNetworkInterfaces();

        // Check if selected interface still exists
        if (selectedInterface) {
          const stillExists = currentInterfaces.some(
            (iface) => iface.name === selectedInterface.name && iface.ip === selectedInterface.ip
          );

          if (!stillExists) {
            console.log("Network interface changed, updating...");
            // Interface changed or disappeared, select first available
            if (currentInterfaces.length > 0) {
              selectedInterface = currentInterfaces[0];
              interfaces = currentInterfaces;
              await updateSubnet();
            }
          } else {
            // Check if IP changed for the same interface
            const updatedInterface = currentInterfaces.find(
              (iface) => iface.name === selectedInterface.name
            );
            if (updatedInterface && updatedInterface.ip !== selectedInterface.ip) {
              console.log("IP address changed for interface, updating...");
              selectedInterface = updatedInterface;
              interfaces = currentInterfaces;
              await updateSubnet();
            }
          }
        }
      } catch (err) {
        console.error("Failed to check network interfaces:", err);
      }
    }, 5000);

    // Clean up interval on destroy
    return () => {
      clearInterval(networkCheckInterval);
    };
  });

  onDestroy(() => {
    if (unsubscribeProgress) unsubscribeProgress();
    if (unsubscribeComplete) unsubscribeComplete();
    if (unsubscribeHost) unsubscribeHost();
  });

  async function loadInterfaces() {
    try {
      interfaces = await getNetworkInterfaces();
      if (interfaces.length > 0) {
        selectedInterface = interfaces[0];
        await updateSubnet();
      }
    } catch (err) {
      console.error('Failed to load interfaces:', err);
    }
  }

  async function updateSubnet() {
    if (!selectedInterface) return;

    try {
      const computedSubnet = await calculateSubnet(
        selectedInterface.ip,
        selectedInterface.netmask
      );

      subnet = computedSubnet;
      applySubnetRange(computedSubnet);
    } catch (err) {
      console.error('Failed to calculate subnet:', err);
      subnet = '';
      subnetFrom = '';
      subnetTo = '';
    }
  }

  async function startScan() {
    if (!selectedInterface || !subnet) return;

    isScanning = true;
    hosts = [];
    selectedHost = null;
    scanProgress = {
      total: 0,
      scanned: 0,
      found: 0,
      message: 'Initializing scan...',
    };

    try {
      await startNetworkScan(selectedInterface.name, subnet);
    } catch (err) {
      console.error('Scan failed:', err);
      isScanning = false;
      scanProgress = null;
    }
  }

  async function stopScan() {
    try {
      await stopNetworkScan();
      isScanning = false;
      scanProgress = null;
    } catch (err) {
      console.error('Failed to stop scan:', err);
    }
  }

  async function loadResults() {
    try {
      hosts = await getScanResults();
    } catch (err) {
      console.error('Failed to load results:', err);
    }
  }

  function handleHostSelect(host: Host) {
    selectedHost = host;
  }

  function handleConfigSave(event: CustomEvent<{ from: string; to: string }>) {
    const { from, to } = event.detail;
    try {
      const fromValue = ipv4ToNumber(from.trim());
      const toValue = ipv4ToNumber(to.trim());

      if (fromValue > toValue) {
        throw new Error('Invalid IP range: start is after end');
      }

      const normalizedFrom = numberToIpv4(fromValue);
      const normalizedTo = numberToIpv4(toValue);

      subnetFrom = normalizedFrom;
      subnetTo = normalizedTo;

      const derived = deriveSubnetFromRange(normalizedFrom, normalizedTo);
      if (derived) {
        subnet = derived;
        applySubnetRange(derived);
      } else if (subnet) {
        applySubnetRange(subnet);
      }
    } catch (err) {
      console.error('Failed to apply custom range:', err);
      if (subnet) {
        applySubnetRange(subnet);
      }
    }

    showConfigDialog = false;
  }
</script>

<main class="h-screen flex flex-col bg-gray-100 dark:bg-gray-900">
  <!-- Toolbar -->
  <div class="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-4 py-2 flex items-center gap-4">
    <button
      on:click={startScan}
      disabled={isScanning || !selectedInterface}
      class="px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white rounded font-medium transition-colors"
    >
      {isScanning ? 'Scanning...' : 'Start LanScan'}
    </button>

    <button
      on:click={stopScan}
      disabled={!isScanning}
      class="px-4 py-2 bg-red-500 hover:bg-red-600 disabled:bg-gray-400 text-white rounded font-medium transition-colors"
    >
      Stop Scanning
    </button>

    <button
      on:click={() => showConfigDialog = true}
      disabled={isScanning}
      class="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 rounded transition-colors"
    >
      Config
    </button>

    <div class="flex-1" />

    <span class="text-sm text-gray-600 dark:text-gray-400">
      Scan from {subnetFrom} to {subnetTo}
    </span>

    <div class="text-sm text-gray-600 dark:text-gray-400">
      Devices seen: <span class="font-semibold">{hosts.length}</span>
    </div>
  </div>

  <!-- Progress bar -->
  {#if scanProgress}
    <ProgressBar progress={scanProgress} />
  {/if}

  <!-- Main content -->
  <div class="flex-1 flex overflow-hidden">
    <!-- Host table -->
    <div class="flex-1 overflow-auto">
      <HostTable
        {hosts}
        {selectedHost}
        on:select={(e) => handleHostSelect(e.detail)}
      />
    </div>

    <!-- Details panel -->
    {#if selectedHost}
      <div class="w-96 border-l border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 overflow-auto">
        <HostDetails
          host={selectedHost}
          on:close={() => selectedHost = null}
        />
      </div>
    {/if}
  </div>

  <!-- Config dialog -->
  {#if showConfigDialog}
    <ConfigDialog
      {selectedInterface}
      {interfaces}
      from={subnetFrom}
      to={subnetTo}
      on:save={handleConfigSave}
      on:close={() => showConfigDialog = false}
      on:reset={() => {
        if (subnet) {
          applySubnetRange(subnet);
        }
      }}
      on:interfaceChange={async (e) => {
        selectedInterface = e.detail;
        await updateSubnet();
      }}
    />
  {/if}
</main>
