<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import type { Host, PortScanResult } from './tauri';
  import { scanHostPorts } from './tauri';

  export let host: Host;

  const dispatch = createEventDispatcher();

  let isScanning = false;
  let showPortScanDialog = false;
  let scanType: 'common' | 'all' | 'custom' = 'common';
  let portScanResult: PortScanResult | null = null;

  async function startPortScan() {
    if (!host.ipv4) return;

    isScanning = true;
    try {
      portScanResult = await scanHostPorts(host.ipv4, scanType);
      // Update host's port list
      host.tcp_ports_open = portScanResult.open_ports;
    } catch (err) {
      console.error('Port scan failed:', err);
    } finally {
      isScanning = false;
      showPortScanDialog = false;
    }
  }

  function formatMac(mac: string): string {
    return mac.toUpperCase();
  }
</script>

<div class="p-4 space-y-4">
  <div class="flex items-center justify-between border-b border-gray-200 dark:border-gray-700 pb-2">
    <h2 class="text-lg font-semibold">Device Details</h2>
    <div class="flex gap-2">
      <button
        on:click={() => showPortScanDialog = !showPortScanDialog}
        class="text-sm px-3 py-1 bg-blue-500 hover:bg-blue-600 text-white rounded transition-colors"
      >
        Port Scan
      </button>
      <button
        on:click={() => dispatch('close')}
        class="text-sm px-2 py-1 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 rounded transition-colors"
        title="Close details panel"
      >
        ✕
      </button>
    </div>
  </div>

  <!-- Port scan options -->
  {#if showPortScanDialog}
    <div class="bg-gray-50 dark:bg-gray-900 p-4 rounded space-y-3">
      <h3 class="font-medium">Port Scan Configuration</h3>

      <div class="space-y-2">
        <label class="flex items-center gap-2">
          <input type="radio" bind:group={scanType} value="common" />
          <span>Scan 1000 most common TCP ports</span>
        </label>

        <label class="flex items-center gap-2">
          <input type="radio" bind:group={scanType} value="all" />
          <span>Scan all TCP ports (1-65535)</span>
        </label>
      </div>

      <div class="flex gap-2">
        <button
          on:click={startPortScan}
          disabled={isScanning}
          class="px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:bg-gray-400 text-white rounded transition-colors"
        >
          {isScanning ? 'Scanning...' : 'Scan'}
        </button>
        <button
          on:click={() => showPortScanDialog = false}
          class="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 rounded transition-colors"
        >
          Close
        </button>
      </div>
    </div>
  {/if}

  <!-- Host information -->
  <div class="space-y-3 text-sm">
    <div>
      <div class="font-semibold text-gray-600 dark:text-gray-400">IPv4 Address:</div>
      <div class="font-mono">{host.ipv4 || '-'}</div>
    </div>

    {#if host.ipv6_local}
      <div>
        <div class="font-semibold text-gray-600 dark:text-gray-400">IPv6 Addresses:</div>
        <div class="font-mono text-xs">{host.ipv6_local}</div>
        {#each host.ipv6_global as ipv6}
          <div class="font-mono text-xs">{ipv6}</div>
        {/each}
      </div>
    {/if}

    {#if host.mac}
      <div>
        <div class="font-semibold text-gray-600 dark:text-gray-400">MAC Address:</div>
        <div class="font-mono">{formatMac(host.mac)}</div>
      </div>
    {/if}

    {#if host.vendor}
      <div>
        <div class="font-semibold text-gray-600 dark:text-gray-400">Vendor:</div>
        <div>{host.vendor}</div>
      </div>
    {/if}

    {#if host.hostname}
      <div>
        <div class="font-semibold text-gray-600 dark:text-gray-400">Hostname:</div>
        <div>{host.hostname}</div>
      </div>
    {/if}

    {#if host.mdns_name}
      <div>
        <div class="font-semibold text-gray-600 dark:text-gray-400">mDNS Name:</div>
        <div>{host.mdns_name}</div>
      </div>
    {/if}

    {#if host.smb_name}
      <div>
        <div class="font-semibold text-gray-600 dark:text-gray-400">SMB Name:</div>
        <div>{host.smb_name}</div>
        {#if host.smb_domain}
          <div class="text-xs text-gray-500">Domain: {host.smb_domain}</div>
        {/if}
      </div>
    {/if}

    {#if host.dns_name}
      <div>
        <div class="font-semibold text-gray-600 dark:text-gray-400">DNS Name:</div>
        <div>{host.dns_name}</div>
      </div>
    {/if}

    <div>
      <div class="font-semibold text-gray-600 dark:text-gray-400">Port Scan:</div>
      {#if host.tcp_ports_open.length > 0}
        <div class="mt-2 max-h-64 overflow-y-auto">
          <div class="flex flex-wrap gap-1">
            {#each host.tcp_ports_open as port}
              <span class="px-2 py-1 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100 rounded text-xs font-mono">
                {port}
              </span>
            {/each}
          </div>
        </div>
      {:else}
        <div class="text-gray-500 italic">No open ports found</div>
      {/if}
    </div>

    <div>
      <div class="font-semibold text-gray-600 dark:text-gray-400">Comments:</div>
      <textarea
        class="w-full mt-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 resize-none"
        rows="3"
        placeholder="Add notes about this device..."
      ></textarea>
    </div>
  </div>
</div>
