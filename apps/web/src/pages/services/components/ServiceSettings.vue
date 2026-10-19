<script setup lang="ts">
import { computed } from 'vue'

import type { RunningServiceDto } from '@frogbyte-io/fleet-api-client'
import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../../machine/api'
import { settingsFor } from '../settings'
import { useServiceSettings } from '../useServiceSettings'
import DomainsSettings from './DomainsSettings.vue'
import EnvSettings from './EnvSettings.vue'
import HealthSettings from './HealthSettings.vue'

// The settings tab (FM-1034): what Fleet can show and change for a Coolify
// resource. Every edit files an approval-class request; nothing here changes
// Coolify directly. The settings are read from Coolify when the tab opens.
const props = defineProps<{ service: RunningServiceDto }>()

const offered = computed(() => settingsFor(props.service.kind, props.service.coolify != null))
const query = useServiceSettings(() => props.service.id, () => offered.value.env || offered.value.domains || offered.value.health)
const data = computed(() => query.data.value ?? null)

const panelClass = 'rounded-sm border border-fc-line bg-fc-panel p-4'
const headingClass = 'fc-kicker border-b border-fc-line pb-1'
</script>

<template>
  <div data-testid="service-settings">
    <p
      v-if="!offered.env && !offered.domains && !offered.health"
      class="mt-4 text-xs text-fc-faint"
      data-testid="settings-none"
    >
      Settings are managed for Coolify applications and services. This one is {{ service.coolify ? 'a database, which has none Fleet changes' : 'observed from Docker only' }}.
    </p>

    <div
      v-else-if="query.isLoading.value"
      class="mt-4 grid gap-3"
    >
      <Skeleton class="h-24 rounded-sm" />
      <Skeleton class="h-24 rounded-sm" />
    </div>

    <div
      v-else-if="query.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="settings-error"
    >
      Could not read the settings from Coolify: {{ errorMessage(query.error.value) }}
    </div>

    <div
      v-else-if="data"
      class="mt-4 grid gap-3"
    >
      <section
        v-for="note in data.notes"
        :key="note"
        class="border-l-2 border-l-fc-info bg-card px-3 py-2 text-xs text-fc-muted"
        data-testid="settings-note"
      >
        {{ note }}
      </section>

      <section
        v-if="offered.env && data.env"
        :class="panelClass"
        aria-labelledby="env-heading"
      >
        <h2
          id="env-heading"
          :class="headingClass"
        >
          Environment variables
        </h2>
        <div class="mt-3">
          <EnvSettings
            :service-id="service.id"
            :kind="service.kind"
            :envs="data.env"
          />
        </div>
      </section>

      <section
        v-if="offered.domains && data.domains"
        :class="panelClass"
        aria-labelledby="domains-heading"
      >
        <h2
          id="domains-heading"
          :class="headingClass"
        >
          Domains
        </h2>
        <div class="mt-3">
          <DomainsSettings
            :service-id="service.id"
            :domains="data.domains"
          />
        </div>
      </section>

      <section
        v-if="offered.health && data.health"
        :class="panelClass"
        aria-labelledby="health-heading"
      >
        <h2
          id="health-heading"
          :class="headingClass"
        >
          Health check
        </h2>
        <div class="mt-3">
          <HealthSettings
            :service-id="service.id"
            :health="data.health"
          />
        </div>
      </section>
    </div>
  </div>
</template>
