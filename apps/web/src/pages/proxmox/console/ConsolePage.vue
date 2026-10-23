<script setup lang="ts">
import { ref } from 'vue'
import { RouterLink } from 'vue-router'

import ProxmoxConsole from './ProxmoxConsole.vue'
import { sessionFromHash } from './session'

// The console link `fleetctl proxmox console` prints: /proxmox/console#session=<token>.
// The token rides in the fragment, which no server or proxy log ever sees,
// and is removed from the address bar as soon as it is read. It works once.
const token = ref<string | null>(sessionFromHash(window.location.hash))
if (token.value !== null)
  window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search)
</script>

<template>
  <div class="mx-auto max-w-[1320px] space-y-4">
    <RouterLink
      to="/proxmox"
      class="font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-ink"
    >
      ← Proxmox
    </RouterLink>
    <h1 class="text-[26px] font-extrabold tracking-tight">
      Guest screen
    </h1>
    <ProxmoxConsole
      v-if="token"
      :session-token="token"
      :auto-connect="true"
    />
    <p
      v-else
      class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="console-link-missing"
    >
      This page needs a console link. Open a guest's Screen tab, or run
      <span class="font-mono">fleetctl proxmox console --account &lt;id&gt; --node &lt;node&gt; --vmid &lt;vmid&gt;</span>
      and open the URL it prints. A link works once and expires after two minutes.
    </p>
  </div>
</template>
