<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  promoteImageVersion,
  startImageBuild,
  type LabTemplateDto,
  type OperationDto,
  type RecipeVersionDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { errorMessage, isTerminal, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import { buildCommand, buildResult, promoteCommand } from '../images'
import { BUILD_OPERATIONS_KEY, trackBuild, versionsKey } from '../useImages'

// One published version: build it through the operator-installed Packer
// CLI, follow the build, and promote it on the evidence of a successful
// build. The promotion gate is the controller's; the UI only shows it.
const props = defineProps<{
  version: RecipeVersionDto
  label: string
  build: OperationDto | null
  pinnedBy: LabTemplateDto[]
  /** Running builds whose version is not known yet (started elsewhere). */
  unattributedRunning: number
}>()
const emit = defineEmits<{ close: [] }>()

const queryClient = useQueryClient()

/** The build deadline fleetctl always sends, which is also the executor's cap (4h). */
const MAX_TIMEOUT = 4 * 3600
const DEFAULT_TIMEOUT = MAX_TIMEOUT

const timeoutMinutes = ref(DEFAULT_TIMEOUT / 60)
const secretVars = ref<{ name: string, reference: string }[]>([])
const busy = ref(false)
const error = ref('')
const startedId = ref<string | null>(null)

// Every per-version input and message starts over on another version.
watch(() => props.version.id, () => {
  startedId.value = null
  error.value = ''
  confirming.value = false
  promoteError.value = ''
  secretVars.value = []
  timeoutMinutes.value = DEFAULT_TIMEOUT / 60
  concurrentAcknowledged.value = false
})

const varsValid = computed(() => secretVars.value.every(v => /^[A-Za-z_][\w-]*$/.test(v.name.trim()) && v.reference.trim() !== ''))
const timeoutSeconds = computed(() => Math.min(MAX_TIMEOUT, Math.max(60, Math.round(timeoutMinutes.value * 60))))
// fleetctl sends exactly this request only without secret variables and
// with its fixed 4h deadline.
const cliCommand = computed(() => (secretVars.value.length === 0 && timeoutSeconds.value === MAX_TIMEOUT ? buildCommand(props.version.id) : null))
const buildRunning = computed(() => !!props.build && !isTerminal(props.build.state))
// A build started elsewhere may be this version; the controller does not
// refuse concurrent builds, so the operator has to rule it out.
const concurrentAcknowledged = ref(false)
const buildBlocked = computed(() => buildRunning.value || (props.unattributedRunning > 0 && !concurrentAcknowledged.value))

async function startBuild() {
  if (!varsValid.value)
    return
  busy.value = true
  error.value = ''
  try {
    const operation = unwrap<OperationDto>(await startImageBuild({
      versionId: props.version.id,
      timeoutSeconds: timeoutSeconds.value,
      secretVars: secretVars.value.map(v => ({ name: v.name.trim(), reference: v.reference.trim() })),
    }), [202])
    trackBuild(operation.id, props.version.id)
    startedId.value = operation.id
    await queryClient.invalidateQueries({ queryKey: BUILD_OPERATIONS_KEY })
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

function onBuildSettled() {
  void queryClient.invalidateQueries({ queryKey: BUILD_OPERATIONS_KEY })
}

// The operation followed on screen: this tab's latest start, else the
// newest build attributed to the version.
const followed = computed(() => startedId.value ?? props.build?.id ?? null)
const evidence = computed(() => (props.build ? buildResult(props.build) : null))
const promotable = computed(() => props.build?.state === 'succeeded' && !!evidence.value?.artifactId)

const confirming = ref(false)
const promoteError = ref('')
async function promote() {
  busy.value = true
  promoteError.value = ''
  try {
    unwrap<RecipeVersionDto>(await promoteImageVersion(props.version.id))
    confirming.value = false
    await queryClient.invalidateQueries({ queryKey: versionsKey(props.version.recipeId) })
  }
  catch (caught) {
    promoteError.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

const structured = computed(() => props.version.structured ?? null)
</script>

<template>
  <div
    class="space-y-4 rounded-sm border border-fc-line bg-card p-4 text-xs"
    data-testid="version-panel"
  >
    <div class="flex items-start gap-2">
      <div class="min-w-0">
        <p class="fc-kicker">
          image version · {{ version.contentDigest.slice(0, 12) }}
        </p>
        <h3 class="font-head text-[17px] font-extrabold">
          {{ version.name }} {{ label }}
          <StatusChip
            v-if="version.promotedAt"
            class="ml-1 align-middle"
            label="promoted"
            tone="ok"
          />
        </h3>
        <p class="font-mono text-[10.5px] text-fc-faint">
          {{ version.source }} · {{ version.node }} · {{ version.storagePool }} · published {{ new Date(version.publishedAt).toISOString().slice(0, 16).replace('T', ' ') }}Z
          <template v-if="version.promotedAt">
            · promoted {{ new Date(version.promotedAt).toISOString().slice(0, 16).replace('T', ' ') }}Z by {{ version.promotedBy ?? 'unknown' }}
          </template>
        </p>
      </div>
      <button
        type="button"
        class="ml-auto text-fc-muted hover:text-fc-ink"
        aria-label="Close version"
        @click="emit('close')"
      >
        ✕
      </button>
    </div>

    <dl
      v-if="structured"
      class="grid grid-cols-[120px_1fr] gap-x-3 gap-y-0.5 font-mono text-[11px]"
    >
      <dt class="text-fc-faint">
        node / pool
      </dt><dd>{{ structured.node }} · {{ structured.firstDiskStoragePool ?? (structured.source === 'clone' ? 'source storage' : '—') }}</dd>
      <dt class="text-fc-faint">
        {{ structured.source === 'clone' ? 'clone from' : 'iso' }}
      </dt><dd>{{ structured.source === 'clone' ? structured.cloneVm ?? '—' : structured.bootIsoFile ?? '—' }}</dd>
      <dt class="text-fc-faint">
        cores / memory
      </dt><dd>{{ structured.cores ?? '—' }} · {{ structured.memory ? `${structured.memory} MiB` : '—' }}</dd>
      <dt class="text-fc-faint">
        disk / bridge
      </dt><dd>{{ structured.firstDiskSize ?? '—' }} · {{ structured.networkBridge ?? '—' }}</dd>
    </dl>

    <section class="space-y-2">
      <h4 class="fc-kicker border-b border-fc-line pb-1">
        Build
      </h4>
      <p class="text-fc-muted">
        Runs <span class="font-mono">packer validate</span>, then <span class="font-mono">packer build</span>, with the operator-installed CLI on the controller. Secret variables are passed by secret reference; their values never reach this page, argv, logs, or audit.
      </p>
      <div
        v-for="(item, index) in secretVars"
        :key="index"
        class="flex flex-wrap items-center gap-2"
      >
        <input
          v-model="item.name"
          placeholder="variable name"
          aria-label="Packer variable name"
          class="h-8 w-44 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
        <span class="text-fc-faint">←</span>
        <input
          v-model="item.reference"
          placeholder="secret reference id"
          aria-label="Secret reference id"
          class="h-8 w-56 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
        <button
          type="button"
          class="text-fc-muted hover:text-fc-err"
          :aria-label="`Remove variable ${index + 1}`"
          @click="secretVars.splice(index, 1)"
        >
          ✕
        </button>
      </div>
      <div class="flex flex-wrap items-end gap-3">
        <button
          type="button"
          class="h-8 rounded-sm border border-input px-2.5 text-fc-muted hover:text-fc-ink"
          @click="secretVars.push({ name: '', reference: '' })"
        >
          + Secret variable
        </button>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Deadline (minutes)</span>
          <input
            v-model.number="timeoutMinutes"
            type="number"
            min="1"
            max="240"
            class="h-8 w-24 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 font-semibold text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="busy || !varsValid || buildBlocked"
          :title="buildRunning ? 'A build of this version is still running' : ''"
          data-testid="build"
          @click="startBuild"
        >
          Build →
        </button>
      </div>
      <label
        v-if="unattributedRunning > 0 && !buildRunning"
        class="flex items-start gap-2 rounded-sm border border-fc-warn/40 p-2 text-fc-muted"
        data-testid="concurrent-builds"
      >
        <input
          v-model="concurrentAcknowledged"
          type="checkbox"
          class="mt-0.5"
        >
        <span>{{ unattributedRunning }} build{{ unattributedRunning === 1 ? ' is' : 's are' }} running that {{ unattributedRunning === 1 ? 'was' : 'were' }} started elsewhere; the controller does not say which version. I checked Operations and none of them is this version.</span>
      </label>
      <p
        v-if="error"
        class="text-fc-err"
        role="alert"
      >
        {{ error }}
      </p>
      <OperationStatus
        v-if="followed"
        :key="followed"
        :operation-id="followed"
        :label="`build ${version.name} ${label}`"
        @settled="onBuildSettled"
      />
      <p class="text-[11px] text-fc-faint">
        The controller reports the build's stage while it runs and Packer's machine-readable output when it ends; it does not stream the full Packer log.
      </p>
      <CopyFleetctl
        :command="cliCommand"
        missing="fleetctl images build always sends the 4h deadline and no secret variables; this build has to start here."
      />
    </section>

    <section class="space-y-2">
      <h4 class="fc-kicker border-b border-fc-line pb-1">
        Promotion
      </h4>
      <template v-if="build">
        <dl
          class="grid grid-cols-[120px_1fr] gap-x-3 gap-y-0.5 font-mono text-[11px]"
          data-testid="promotion-evidence"
        >
          <dt class="text-fc-faint">
            build
          </dt><dd>{{ build.id }} · {{ build.state }}</dd>
          <dt class="text-fc-faint">
            artifact
          </dt><dd>{{ evidence?.artifactId ?? 'none recorded' }}</dd>
          <template v-if="evidence?.says.length">
            <dt class="text-fc-faint">
              packer said
            </dt>
            <dd>
              <pre class="max-h-40 overflow-auto whitespace-pre-wrap break-all text-fc-muted">{{ evidence.says.join('\n') }}</pre>
            </dd>
          </template>
        </dl>
      </template>
      <p
        v-else
        class="text-fc-muted"
      >
        No build of this version is on record here yet. The controller promotes only a version whose latest build succeeded with a recorded artifact.
      </p>

      <p
        v-if="version.promotedAt"
        class="text-fc-ok"
      >
        This version is the recipe's promoted image.
      </p>
      <template v-else>
        <button
          v-if="!confirming"
          type="button"
          class="h-8 rounded-sm border border-fc-ok/50 px-3 font-semibold text-fc-ok hover:bg-fc-ok/10 disabled:opacity-50"
          :disabled="busy || !promotable"
          :title="promotable ? '' : 'Needs a successful build with a recorded artifact'"
          data-testid="promote"
          @click="confirming = true"
        >
          Promote…
        </button>
        <div
          v-else
          class="space-y-2 rounded-sm border border-fc-ok/40 p-3"
          role="alertdialog"
          aria-label="Confirm promotion"
        >
          <p>
            Promote <span class="font-mono text-fc-ink">{{ version.name }} {{ label }}</span> as the recipe's built image, on the evidence of build <span class="font-mono">{{ build?.id }}</span> (artifact <span class="font-mono">{{ evidence?.artifactId }}</span>). Any previously promoted version is demoted, and Lab templates pinning it become stale.
          </p>
          <div class="flex gap-2">
            <button
              type="button"
              class="h-8 rounded-sm border border-fc-ok bg-fc-ok/10 px-3 font-semibold text-fc-ok disabled:opacity-50"
              :disabled="busy"
              data-testid="promote-confirm"
              @click="promote"
            >
              Yes, promote
            </button>
            <button
              type="button"
              class="h-8 px-2 text-fc-muted hover:text-fc-ink"
              @click="confirming = false"
            >
              Cancel
            </button>
          </div>
        </div>
        <p
          v-if="promoteError"
          class="text-fc-err"
          role="alert"
        >
          {{ promoteError }}
        </p>
      </template>
      <CopyFleetctl :command="promoteCommand(version.id)" />
    </section>

    <section
      v-if="pinnedBy.length"
      class="space-y-1"
    >
      <h4 class="fc-kicker border-b border-fc-line pb-1">
        Pinned by Lab templates
      </h4>
      <p
        v-for="template in pinnedBy"
        :key="template.id"
        class="font-mono text-[11px] text-fc-muted"
      >
        {{ template.name }}
      </p>
    </section>
  </div>
</template>
