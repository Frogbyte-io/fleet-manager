// Pure Operations page helpers: state groups for filtering, and what a
// person does about an operation blocked on an approval.

import type { OperationDto } from '@frogbyte-io/fleet-api-client'
import type { RouteLocationRaw } from 'vue-router'

export type StateGroup = 'all' | 'live' | 'blocked' | 'failed' | 'succeeded' | 'cancelled'

const GROUPS: Record<Exclude<StateGroup, 'all'>, string[]> = {
  live: ['pending', 'running', 'cancelling'],
  blocked: ['blocked_manual_approval'],
  failed: ['failed', 'timed_out'],
  succeeded: ['succeeded'],
  cancelled: ['cancelled'],
}

export function inGroup(state: string, group: StateGroup): boolean {
  return group === 'all' || GROUPS[group].includes(state)
}

export interface OperationFilter {
  group: StateGroup
  kind: string
  text: string
}

export function filterOperations(operations: OperationDto[], filter: OperationFilter): OperationDto[] {
  const needle = filter.text.trim().toLowerCase()
  return operations
    .filter(o => inGroup(o.state, filter.group))
    .filter(o => !filter.kind || o.kind === filter.kind)
    .filter(o => !needle || o.id.toLowerCase().includes(needle) || o.kind.toLowerCase().includes(needle))
    .sort((a, b) => b.createdAt - a.createdAt)
}

/** Whether cancel can apply: fleet-core only cancels a pending or running operation. */
export function cancellable(operation: Pick<OperationDto, 'state' | 'cancelRequested'>): boolean {
  return (operation.state === 'pending' || operation.state === 'running') && !operation.cancelRequested
}

export interface BlockedGuidance {
  /** The blocked reason the controller recorded. */
  detail: string
  /** What the operator does next. */
  steps: string[]
  /** Where to act, when a page covers it. */
  link: { to: RouteLocationRaw, label: string } | null
}

/**
 * `blocked_manual_approval` is terminal (fleet-core `OperationState`): the
 * operation will not resume by itself. The workflows that block are
 * idempotent, so the way forward is to satisfy the approval and start the
 * same action again; it skips what is already done.
 */
export function blockedGuidance(operation: Pick<OperationDto, 'kind' | 'errorJson'>): BlockedGuidance {
  let detail = 'A step needs a person to approve it.'
  try {
    const parsed = JSON.parse(operation.errorJson ?? '') as { detail?: unknown }
    if (typeof parsed.detail === 'string')
      detail = parsed.detail
  }
  catch {
    // Keep the generic detail.
  }
  if (operation.kind === 'ready.workflow') {
    return {
      detail,
      steps: [
        'Approve the pending Frogenv request for this checkout (Frogenv shows it to its approvers).',
        'Run Make ready again for the same project and machine: the plan skips the steps already done and continues from the blocked one.',
      ],
      link: { to: '/projects', label: 'Projects' },
    }
  }
  if (operation.kind === 'apply.workflow') {
    return {
      detail,
      steps: [
        'Review the actions the plan named above.',
        'Start apply again with approvals for those actions (fleetctl apply … with the approved plan); nothing ran while it was blocked.',
      ],
      link: null,
    }
  }
  if (operation.kind.startsWith('frogenv.')) {
    return {
      detail,
      steps: [
        'Approve the request in Frogenv.',
        'Run the same Frogenv action again from the machine\'s Tools tab.',
      ],
      link: { to: '/fleet', label: 'Fleet' },
    }
  }
  return { detail, steps: ['Resolve the approval the detail names, then start the action again.'], link: null }
}
