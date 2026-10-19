<script setup lang="ts">
import { computed, ref } from 'vue'

import type { ActionRequestDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Button } from '@/components/ui/button'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { approveCommand, denyCommand, expiresText, parametersText, riskTone, stateTone } from '../requests'
import { useDecision } from '../useRequests'

// One request waiting for a person. Approving starts the action's durable
// operation; denying records an optional note. Authorization and audit are
// the controller's: this card only asks.
const props = defineProps<{ request: ActionRequestDto, highlighted?: boolean }>()

const decision = useDecision()
const choice = ref<'approve' | 'deny' | null>(null)
const note = ref('')
const error = ref('')

const params = computed(() => parametersText(props.request.parameters))
const command = computed(() => choice.value === 'approve'
  ? approveCommand(props.request.id)
  : choice.value === 'deny' ? denyCommand(props.request.id, note.value) : null)

function choose(next: 'approve' | 'deny') {
  choice.value = next
  error.value = ''
}

function cancel() {
  choice.value = null
  note.value = ''
  error.value = ''
}

async function submit() {
  if (!choice.value)
    return
  error.value = ''
  try {
    await (choice.value === 'approve'
      ? decision.mutateAsync({ id: props.request.id, decision: 'approve' })
      : decision.mutateAsync({ id: props.request.id, decision: 'deny', note: note.value }))
    cancel()
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
}
</script>

<template>
  <article
    class="space-y-3 border border-fc-line border-l-2 border-l-fc-warn bg-card p-4 text-xs"
    :class="highlighted ? 'ring-1 ring-ring' : ''"
    :data-testid="`request-${request.id}`"
    :aria-label="`${request.actionId} on ${request.target}`"
  >
    <div class="flex flex-wrap items-start gap-2">
      <div class="min-w-0">
        <p class="fc-kicker">
          {{ request.id }}
        </p>
        <h3 class="break-all font-head text-[15px] font-bold">
          {{ request.actionId }}
        </h3>
        <p class="break-all font-mono text-[11px] text-fc-muted">
          on {{ request.target }}
        </p>
      </div>
      <div class="ml-auto flex items-center gap-1.5">
        <StatusChip
          :label="`risk ${request.riskClass}`"
          :tone="riskTone(request.riskClass)"
        />
        <StatusChip
          :label="request.state"
          :tone="stateTone(request.state)"
        />
      </div>
    </div>

    <dl class="grid grid-cols-[90px_1fr] gap-x-3 gap-y-0.5 font-mono text-[11px]">
      <dt class="text-fc-faint">
        requester
      </dt><dd class="break-all">
        {{ request.requester }} <span class="text-fc-faint">via {{ request.origin }}</span>
      </dd>
      <dt class="text-fc-faint">
        asked
      </dt><dd>{{ relativeTime(request.createdAt) }}</dd>
      <dt class="text-fc-faint">
        deadline
      </dt><dd data-testid="expires">
        {{ expiresText(request.expiresAt) }}
      </dd>
    </dl>

    <div>
      <p class="fc-kicker">
        reason
      </p>
      <p class="mt-0.5 whitespace-pre-wrap break-words text-fc-ink">
        {{ request.reason }}
      </p>
    </div>

    <div>
      <p class="fc-kicker">
        parameters
      </p>
      <pre
        v-if="params"
        class="mt-0.5 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-sm border border-fc-line bg-fc-inset p-2 font-mono text-[11px]"
        data-testid="parameters"
      >{{ params }}</pre>
      <p
        v-else
        class="mt-0.5 text-fc-faint"
      >
        None.
      </p>
    </div>

    <div
      v-if="!choice"
      class="flex flex-wrap gap-2"
    >
      <Button
        size="sm"
        data-testid="approve"
        @click="choose('approve')"
      >
        Approve…
      </Button>
      <Button
        size="sm"
        variant="outline"
        data-testid="deny"
        @click="choose('deny')"
      >
        Deny…
      </Button>
    </div>

    <div
      v-else
      class="space-y-2 rounded-sm border border-fc-line2 p-3"
      role="group"
      :aria-label="choice === 'approve' ? 'Confirm approval' : 'Confirm denial'"
    >
      <p
        v-if="choice === 'approve'"
        class="text-fc-ink"
      >
        Approve and run <span class="font-mono">{{ request.actionId }}</span> on <span class="font-mono">{{ request.target }}</span>?
        This starts a durable operation and is audited under your name.
      </p>
      <label
        v-else
        class="flex flex-col gap-1"
      >
        <span class="fc-kicker">Note (optional, shown to the requester)</span>
        <textarea
          v-model="note"
          rows="2"
          maxlength="1000"
          class="rounded-sm border border-input bg-background p-2 text-foreground"
          data-testid="deny-note"
        />
      </label>
      <CopyFleetctl :command="command" />
      <div class="flex flex-wrap gap-2">
        <Button
          size="sm"
          :variant="choice === 'approve' ? 'default' : 'destructive'"
          :disabled="decision.isPending.value"
          data-testid="confirm"
          @click="submit"
        >
          {{ choice === 'approve' ? 'Approve and run' : 'Deny request' }}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          :disabled="decision.isPending.value"
          data-testid="cancel"
          @click="cancel"
        >
          Back
        </Button>
      </div>
    </div>
    <p
      v-if="error"
      class="text-fc-err"
      role="alert"
      data-testid="decision-error"
    >
      {{ error }}
    </p>
  </article>
</template>
