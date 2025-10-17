<script lang="ts">
  import type { NetworkInterface } from './tauri';
  import { createEventDispatcher } from 'svelte';

  export let selectedInterface: NetworkInterface | null;
  export let interfaces: NetworkInterface[];
  export let from: string;
  export let to: string;

  const dispatch = createEventDispatcher();

  let localFrom = from;
  let localTo = to;
  let selectedInterfaceIndex = selectedInterface ? interfaces.findIndex(i => i.name === selectedInterface.name) : 0;

  $: localInterface = interfaces[selectedInterfaceIndex];

  function handleSave() {
    dispatch('save', { from: localFrom, to: localTo });
  }

  function handleReset() {
    dispatch('reset');
  }

  function handleInterfaceChange() {
    dispatch('interfaceChange', localInterface);
  }

  // Update local values when props change
  $: localFrom = from;
  $: localTo = to;
  $: if (selectedInterface) {
    const index = interfaces.findIndex(i => i.name === selectedInterface.name);
    if (index >= 0) selectedInterfaceIndex = index;
  }
</script>

<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
  <div class="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-2xl w-full">
    <div class="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
      <h2 class="text-xl font-semibold">Scan Configuration</h2>
      <button
        on:click={() => dispatch('close')}
        class="text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
      >
        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>

    <div class="p-6 space-y-6">
      <!-- Interface selection -->
      <div>
        <label class="block font-semibold mb-2">Selected Interface</label>
        <select
          bind:value={selectedInterfaceIndex}
          on:change={handleInterfaceChange}
          class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700"
        >
          {#each interfaces as iface, index}
            <option value={index}>
              {iface.name} - {iface.ip}
            </option>
          {/each}
        </select>

        {#if localInterface}
          <div class="mt-3 p-4 bg-gray-50 dark:bg-gray-900 rounded text-sm space-y-1">
            <div><span class="font-semibold">Name:</span> {localInterface.name}</div>
            <div><span class="font-semibold">MAC:</span> <span class="font-mono">{localInterface.mac || '-'}</span></div>
            <div><span class="font-semibold">IP / Mask:</span> <span class="font-mono">{localInterface.ip}</span> / {localInterface.netmask}</div>
            <div><span class="font-semibold">Gateway:</span> <span class="font-mono">{localInterface.gateway || '-'}</span></div>
          </div>
        {/if}
      </div>

      <!-- Subnet range -->
      <div>
        <label class="block font-semibold mb-2">Configure Subrange</label>
        <div class="flex items-center gap-4">
          <div class="flex-1">
            <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">From:</label>
            <input
              type="text"
              bind:value={localFrom}
              placeholder="172.20.10.1"
              class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 font-mono"
            />
          </div>

          <div class="flex-1">
            <label class="block text-sm text-gray-600 dark:text-gray-400 mb-1">To:</label>
            <input
              type="text"
              bind:value={localTo}
              placeholder="172.20.10.14"
              class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 font-mono"
            />
          </div>
        </div>

        <div class="mt-2 flex gap-2">
          <button
            on:click={handleReset}
            class="text-sm px-3 py-1 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 rounded transition-colors"
          >
            Reset
          </button>
        </div>
      </div>
    </div>

    <div class="flex items-center justify-end gap-3 p-6 border-t border-gray-200 dark:border-gray-700">
      <button
        on:click={() => dispatch('close')}
        class="px-4 py-2 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 rounded transition-colors"
      >
        Close
      </button>
      <button
        on:click={handleSave}
        class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded transition-colors"
      >
        Save
      </button>
    </div>
  </div>
</div>
