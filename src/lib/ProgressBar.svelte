<script lang="ts">
  import type { ScanProgress } from './tauri';

  export let progress: ScanProgress;

  $: percentage = progress.total > 0 ? (progress.scanned / progress.total) * 100 : 0;
</script>

<div class="bg-blue-50 dark:bg-blue-900 px-4 py-2 border-b border-blue-200 dark:border-blue-800">
  <div class="flex items-center justify-between mb-1 text-sm">
    <span class="text-blue-800 dark:text-blue-200">{progress.message}</span>
    <span class="text-blue-600 dark:text-blue-300 font-mono">
      {progress.scanned}/{progress.total} ({Math.round(percentage)}%)
    </span>
  </div>
  <div class="w-full bg-blue-200 dark:bg-blue-800 rounded-full h-2 overflow-hidden">
    <div
      class="bg-blue-500 dark:bg-blue-400 h-full transition-all duration-300"
      style="width: {percentage}%"
    />
  </div>
</div>
