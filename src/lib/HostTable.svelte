<script lang="ts">
  import type { Host } from './tauri';
  import { createEventDispatcher } from 'svelte';

  export let hosts: Host[];
  export let selectedHost: Host | null;

  const dispatch = createEventDispatcher();

  let sortColumn: keyof Host | null = 'ipv4';
  let sortAscending = true;

  $: sortedHosts = [...hosts].sort((a, b) => {
    if (!sortColumn) return 0;

    let aVal = a[sortColumn];
    let bVal = b[sortColumn];

    // Handle arrays and optional values
    if (Array.isArray(aVal)) aVal = aVal.length;
    if (Array.isArray(bVal)) bVal = bVal.length;
    if (aVal === undefined || aVal === null) return 1;
    if (bVal === undefined || bVal === null) return -1;

    // IP address sorting
    if (sortColumn === 'ipv4') {
      const ipToNum = (ip: any) => {
        if (typeof ip !== 'string') return 0;
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
      };
      const comparison = ipToNum(aVal) - ipToNum(bVal);
      return sortAscending ? comparison : -comparison;
    }

    // String/number sorting
    if (aVal < bVal) return sortAscending ? -1 : 1;
    if (aVal > bVal) return sortAscending ? 1 : -1;
    return 0;
  });

  function handleSort(column: keyof Host) {
    if (sortColumn === column) {
      sortAscending = !sortAscending;
    } else {
      sortColumn = column;
      sortAscending = true;
    }
  }

  function selectHost(host: Host) {
    dispatch('select', host);
  }

  function getDisplayName(host: Host): string {
    return host.hostname || host.mdns_name || host.smb_name || host.dns_name || '';
  }

  function getDNSName(host: Host): string {
    return host.dns_name || '';
  }

  function getMDNSName(host: Host): string {
    return host.mdns_name || '';
  }

  function getSMBName(host: Host): string {
    return host.smb_name || '';
  }

  function getSMBDomain(host: Host): string {
    return host.smb_domain || '';
  }
</script>

<table class="w-full text-sm">
  <thead class="bg-gray-50 dark:bg-gray-800 sticky top-0">
    <tr>
      <th class="px-4 py-2 text-left cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('ipv4')}>
        IPv4 Address {sortColumn === 'ipv4' ? (sortAscending ? '▲' : '▼') : ''}
      </th>
      <th class="px-4 py-2 text-left cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('ipv6_local')}>
        IPv6 Local
      </th>
      <th class="px-4 py-2 text-left cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('ipv6_global')}>
        IPv6 Global
      </th>
      <th class="px-4 py-2 text-left cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('mac')}>
        MAC Address
      </th>
      <th class="px-4 py-2 text-left cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('hostname')}>
        Hostname
      </th>
      <th class="px-4 py-2 text-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('arp_responsive')}>
        ARP
      </th>
      <th class="px-4 py-2 text-center cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('icmp_responsive')}>
        ICMP
      </th>
      <th class="px-4 py-2 text-left cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700" on:click={() => handleSort('vendor')}>
        Vendor
      </th>
      <th class="px-4 py-2 text-left">
        DNS Name
      </th>
      <th class="px-4 py-2 text-left">
        mDNS Name
      </th>
      <th class="px-4 py-2 text-left">
        SMB Name
      </th>
      <th class="px-4 py-2 text-left">
        SMB Domain
      </th>
      <th class="px-4 py-2 text-left">
        TCP Ports
      </th>
    </tr>
  </thead>
  <tbody>
    {#each sortedHosts as host}
      <tr
        class="border-b border-gray-200 dark:border-gray-700 hover:bg-blue-50 dark:hover:bg-gray-700 cursor-pointer transition-colors"
        class:bg-blue-100={selectedHost === host}
        class:dark:bg-blue-900={selectedHost === host}
        on:click={() => selectHost(host)}
      >
        <td class="px-4 py-2 font-mono text-sm">{host.ipv4 || ''}</td>
        <td class="px-4 py-2 font-mono text-xs">{host.ipv6_local || ''}</td>
        <td class="px-4 py-2 font-mono text-xs">
          {#if host.ipv6_global.length > 0}
            {host.ipv6_global[0]}
          {/if}
        </td>
        <td class="px-4 py-2 font-mono text-xs">{host.mac || ''}</td>
        <td class="px-4 py-2 text-sm">{getDisplayName(host)}</td>
        <td class="px-4 py-2 text-center">
          <span class="inline-block w-3 h-3 rounded-full {host.arp_responsive ? 'bg-green-500' : 'bg-gray-300 dark:bg-gray-600'}" title="{host.arp_responsive ? 'ARP Responsive' : 'No ARP Response'}"></span>
        </td>
        <td class="px-4 py-2 text-center">
          <span class="inline-block w-3 h-3 rounded-full {host.icmp_responsive ? 'bg-blue-500' : 'bg-gray-300 dark:bg-gray-600'}" title="{host.icmp_responsive ? 'ICMP Responsive' : 'No ICMP Response'}"></span>
        </td>
        <td class="px-4 py-2 text-sm">{host.vendor || ''}</td>
        <td class="px-4 py-2 text-sm">{getDNSName(host)}</td>
        <td class="px-4 py-2 text-sm">{getMDNSName(host)}</td>
        <td class="px-4 py-2 text-sm">{getSMBName(host)}</td>
        <td class="px-4 py-2 text-sm">{getSMBDomain(host)}</td>
        <td class="px-4 py-2 text-sm">
          {#if host.tcp_ports_open.length > 0}
            {host.tcp_ports_open.slice(0, 3).join(', ')}{host.tcp_ports_open.length > 3 ? '...' : ''}
          {:else}
            -
          {/if}
        </td>
      </tr>
    {/each}
  </tbody>
</table>

{#if hosts.length === 0}
  <div class="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
    No devices found. Click "Start LanScan" to begin scanning.
  </div>
{/if}
