<script setup lang="ts">
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import {
  createEnrollmentToken,
  createOperation,
  getNode,
  revokeNode,
  type EnrollmentTokenCreatedDto,
  type MachineDto,
  type NodeRevokedDto,
  type NodeViewDto,
  type OperationDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage, unwrap } from '../api'
import CopyFleetctl from '../components/CopyFleetctl.vue'
import OperationStatus from '../components/OperationStatus.vue'
import SshAuthFields from '../components/SshAuthFields.vue'
import { absoluteTime } from '../facts'
import { installNodeCommand, type SshAuth } from '../fleetctl'
import { useMachineOperations } from '../operations'

const props = defineProps<{ machine: MachineDto }>()

const queryClient = useQueryClient()
const { track } = useMachineOperations()

const nodeQuery = useQuery({
  queryKey: computed(() => ['machine', props.machine.id, 'node']),
  queryFn: async () => unwrap<NodeViewDto>(await getNode(props.machine.id)),
})
const node = computed(() => nodeQuery.data.value ?? null)
const identity = computed(() => node.value?.identity ?? null)

function refreshNode() {
  return queryClient.invalidateQueries({ queryKey: ['machine', props.machine.id] })
}

// Enrollment: the token value appears once, in this response, and is kept
// only in component state until the operator leaves the page.
const ttl = ref(3_600_000)
const created = ref<EnrollmentTokenCreatedDto | null>(null)
const enrollError = ref('')
const enrollBusy = ref(false)

async function enroll() {
  enrollBusy.value = true
  enrollError.value = ''
  try {
    created.value = unwrap<EnrollmentTokenCreatedDto>(await createEnrollmentToken(props.machine.id, { ttlMillis: ttl.value }), [201])
    await refreshNode()
  }
  catch (error) {
    enrollError.value = errorMessage(error)
  }
  finally {
    enrollBusy.value = false
  }
}

async function copyToken() {
  if (created.value)
    await navigator.clipboard.writeText(created.value.token).catch(() => {})
}

const confirmingRevoke = ref(false)
const revokeError = ref('')
const revokeBusy = ref(false)

async function revoke() {
  revokeBusy.value = true
  revokeError.value = ''
  try {
    unwrap<NodeRevokedDto>(await revokeNode(props.machine.id))
    confirmingRevoke.value = false
    await refreshNode()
  }
  catch (error) {
    revokeError.value = errorMessage(error)
  }
  finally {
    revokeBusy.value = false
  }
}

// Install fleetd: a durable `machine.install-fleetd` operation, shaped as
// `fleetctl machines install-node` sends it.
const INSTALL_TIMEOUT_SECONDS = 300
const endpointId = ref('')
const auth = ref<SshAuth>({ type: 'agent' })
const installId = ref<string | null>(null)
const installError = ref('')
const installBusy = ref(false)
const controllerUrl = window.location.origin
const authReady = computed(() => endpointId.value !== '' && (auth.value.type === 'agent' || auth.value.path !== ''))
const installCommand = computed(() =>
  authReady.value ? installNodeCommand(props.machine.id, endpointId.value, auth.value, controllerUrl) : null,
)

async function install() {
  installBusy.value = true
  installError.value = ''
  try {
    const payload = {
      machineId: props.machine.id,
      endpointId: endpointId.value,
      auth: auth.value,
      timeoutSeconds: INSTALL_TIMEOUT_SECONDS,
      controllerUrl,
    }
    const operation = unwrap<OperationDto>(await createOperation({
      kind: 'machine.install-fleetd',
      payloadJson: JSON.stringify(payload),
      deadlineAt: Date.now() + (INSTALL_TIMEOUT_SECONDS + 180) * 1000,
    }), [201])
    installId.value = operation.id
    track(operation, 'Install fleetd')
  }
  catch (error) {
    installError.value = errorMessage(error)
  }
  finally {
    installBusy.value = false
  }
}
</script>

<template>
  <div class="space-y-8">
    <section>
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Endpoints
      </h2>
      <table class="mt-2 w-full text-left text-xs">
        <thead class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          <tr>
            <th class="py-1 pr-3 font-normal">
              Kind
            </th>
            <th class="py-1 pr-3 font-normal">
              Reference
            </th>
            <th class="py-1 font-normal">
              Endpoint id
            </th>
          </tr>
        </thead>
        <tbody class="font-mono text-fc-ink">
          <tr
            v-for="endpoint in machine.endpoints"
            :key="endpoint.id"
            class="border-t border-fc-line"
          >
            <td class="py-1.5 pr-3 uppercase">
              {{ endpoint.kind }}
            </td>
            <td class="py-1.5 pr-3">
              {{ endpoint.reference }}
            </td>
            <td class="py-1.5 text-fc-faint">
              {{ endpoint.id }}
            </td>
          </tr>
          <tr v-if="machine.endpoints.length === 0">
            <td
              colspan="3"
              class="py-2 text-fc-faint"
            >
              No endpoints recorded.
            </td>
          </tr>
        </tbody>
      </table>
      <p class="mt-2 text-xs text-fc-faint">
        SSH host key: pinned when the machine was onboarded. The machines API does not expose the pinned key yet.
      </p>
    </section>

    <section>
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Fleet node
      </h2>
      <p
        v-if="nodeQuery.isLoading.value"
        class="mt-2 text-xs text-fc-faint"
      >
        Loading node state…
      </p>
      <p
        v-else-if="nodeQuery.error.value"
        class="mt-2 text-xs text-fc-err"
      >
        Node state unavailable: {{ errorMessage(nodeQuery.error.value) }}
      </p>
      <template v-else-if="node">
        <dl
          v-if="identity"
          class="mt-3 grid grid-cols-[140px_1fr] gap-x-3 gap-y-2 text-xs"
          data-testid="node-identity"
        >
          <dt class="text-fc-faint">
            Identity
          </dt>
          <dd>
            <StatusChip
              :label="identity.status"
              :tone="identity.status === 'active' ? 'ok' : 'err'"
            />
          </dd>
          <dt class="text-fc-faint">
            Gateway
          </dt>
          <dd class="font-mono uppercase text-fc-ink">
            {{ identity.gatewayState }} · seen {{ relativeTime(identity.lastSeenAt ?? null) }}
          </dd>
          <dt class="text-fc-faint">
            Node
          </dt>
          <dd class="font-mono text-fc-ink">
            fleetd {{ identity.nodeVersion }} · {{ identity.os }} · {{ identity.arch }}
          </dd>
          <dt class="text-fc-faint">
            Public key
          </dt>
          <dd class="break-all font-mono text-fc-ink">
            {{ identity.publicKey }} <span class="text-fc-faint">(v{{ identity.keyVersion }})</span>
          </dd>
          <dt class="text-fc-faint">
            Enrolled
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ absoluteTime(identity.enrolledAt) }}<template v-if="identity.rotatedAt">
              · rotated {{ absoluteTime(identity.rotatedAt) }}
            </template>
          </dd>
          <dt class="text-fc-faint">
            Sessions
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ node.activeSessions }} active · {{ node.activeCredentials.length }} credential(s)
          </dd>
        </dl>
        <p
          v-else
          class="mt-2 text-xs text-fc-muted"
          data-testid="node-not-enrolled"
        >
          No Fleet node is enrolled on this machine.
        </p>

        <p
          v-if="node.pendingTokens.length > 0"
          class="mt-3 text-xs text-fc-muted"
        >
          Pending enrollment tokens:
          <span
            v-for="token in node.pendingTokens"
            :key="token.id"
            class="ml-2 font-mono text-fc-ink"
          >{{ token.id }} (expires {{ absoluteTime(token.expiresAt) }})</span>
        </p>

        <div class="mt-4 grid gap-4 lg:grid-cols-2">
          <div class="space-y-2 rounded-sm border border-fc-line p-3">
            <p class="text-sm font-semibold text-fc-ink">
              Create enrollment token
            </p>
            <p class="text-xs text-fc-muted">
              A one-time token a node presents to enroll as this machine. It is shown once and never stored by the console.
            </p>
            <div class="flex items-end gap-2 text-xs">
              <label class="flex flex-col gap-1">
                <span class="fc-kicker">Lifetime</span>
                <select
                  v-model.number="ttl"
                  class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
                >
                  <option :value="900_000">15 minutes</option>
                  <option :value="3_600_000">1 hour</option>
                  <option :value="86_400_000">1 day</option>
                </select>
              </label>
              <button
                type="button"
                class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
                :disabled="enrollBusy"
                data-testid="create-token"
                @click="enroll"
              >
                Create token
              </button>
            </div>
            <div
              v-if="created"
              class="rounded-sm border border-fc-warn/40 bg-fc-inset p-2 text-xs"
              data-testid="created-token"
            >
              <p class="text-fc-warn">
                Copy this token now — it cannot be shown again. Expires {{ absoluteTime(created.expiresAt) }}.
              </p>
              <pre class="mt-1 break-all whitespace-pre-wrap font-mono text-fc-ink">{{ created.token }}</pre>
              <button
                type="button"
                class="mt-1 font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
                @click="copyToken"
              >
                Copy token
              </button>
            </div>
            <p
              v-if="enrollError"
              class="text-xs text-fc-err"
            >
              {{ enrollError }}
            </p>
            <CopyFleetctl
              :command="null"
              missing="fleetctl has no enrollment-token command yet; use this form or POST /api/v1/machines/{id}/node/enrollments."
            />
          </div>

          <div class="space-y-2 rounded-sm border border-fc-line p-3">
            <p class="text-sm font-semibold text-fc-ink">
              Revoke node
            </p>
            <p class="text-xs text-fc-muted">
              Revokes the node identity and its credentials. Re-enrolling needs an enrollment token.
            </p>
            <p
              v-if="node.pendingTokens.length > 0"
              class="text-xs text-fc-warn"
              data-testid="pending-token-warning"
            >
              {{ node.pendingTokens.length }} pending enrollment token(s) stay valid after a revoke until they expire
              (last at {{ absoluteTime(Math.max(...node.pendingTokens.map(t => t.expiresAt))) }}) and could re-enroll this machine.
            </p>
            <template v-if="identity?.status === 'active'">
              <button
                v-if="!confirmingRevoke"
                type="button"
                class="h-8 rounded-sm border border-fc-err/40 px-3 text-xs text-fc-err hover:bg-fc-err/10"
                data-testid="revoke-node"
                @click="confirmingRevoke = true"
              >
                Revoke…
              </button>
              <div
                v-else
                class="flex flex-wrap items-center gap-2 text-xs"
              >
                <span class="text-fc-err">Revoke {{ machine.name }}'s node identity?</span>
                <button
                  type="button"
                  class="h-8 rounded-sm border border-fc-err bg-fc-err/10 px-3 text-fc-err disabled:opacity-50"
                  :disabled="revokeBusy"
                  data-testid="confirm-revoke"
                  @click="revoke"
                >
                  Confirm revoke
                </button>
                <button
                  type="button"
                  class="h-8 px-2 text-fc-muted hover:text-fc-ink"
                  @click="confirmingRevoke = false"
                >
                  Cancel
                </button>
              </div>
            </template>
            <p
              v-else
              class="text-xs text-fc-faint"
            >
              No active node identity to revoke.
            </p>
            <p
              v-if="revokeError"
              class="text-xs text-fc-err"
            >
              {{ revokeError }}
            </p>
            <CopyFleetctl
              :command="null"
              missing="fleetctl has no node-revoke command yet; use this form or POST /api/v1/machines/{id}/node/revoke."
            />
          </div>
        </div>
      </template>
    </section>

    <section>
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Install fleetd
      </h2>
      <p class="mt-2 text-xs text-fc-muted">
        Upgrades this machine to fully managed over SSH. The controller picks the package for the machine's platform and keeps its Fleet id.
      </p>
      <div class="mt-3 space-y-3">
        <SshAuthFields
          v-model:endpoint-id="endpointId"
          v-model:auth="auth"
          :endpoints="machine.endpoints"
        />
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="installBusy || !authReady"
          data-testid="install-fleetd"
          @click="install"
        >
          Install fleetd
        </button>
        <p
          v-if="installError"
          class="text-xs text-fc-err"
        >
          {{ installError }}
        </p>
        <OperationStatus
          v-if="installId"
          :operation-id="installId"
          label="Install fleetd"
        />
        <CopyFleetctl
          :command="installCommand"
          missing="Pick an SSH endpoint and auth to see the command."
        />
      </div>
    </section>
  </div>
</template>
