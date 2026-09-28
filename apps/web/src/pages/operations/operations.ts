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
  /** The step that blocked, when the workflow recorded it. */
  blockedAt: string | null
  /** Steps that already ran, and the ones still to run. */
  completed: string[]
  remaining: string[]
  /** What the operator does next. */
  steps: string[]
  /** Where to act, when a page covers it. */
  link: { to: RouteLocationRaw, label: string } | null
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

/**
 * `blocked_manual_approval` is terminal (fleet-core `OperationState`): the
 * operation will not resume by itself. What unblocks it depends on what the
 * controller recorded: a Frogenv ceremony either needs an approval, or ran
 * out of time on interactive steps only a person on the machine can do
 * (fleet-controller `frogenv.rs`); an apply names the actions it needs
 * approved. The workflows are idempotent, so the last step is always to
 * start the same action again.
 */
export function blockedGuidance(operation: Pick<OperationDto, 'kind' | 'errorJson'>): BlockedGuidance {
  let recorded: Record<string, unknown> = {}
  try {
    const parsed = JSON.parse(operation.errorJson ?? '') as unknown
    if (parsed && typeof parsed === 'object')
      recorded = parsed as Record<string, unknown>
  }
  catch {
    // Keep the generic detail.
  }
  const detail = typeof recorded.detail === 'string' && recorded.detail ? recorded.detail : 'A step needs a person to act.'
  const base = {
    detail,
    blockedAt: typeof recorded.blockedAt === 'string' ? recorded.blockedAt : null,
    completed: strings(recorded.completed),
    remaining: strings(recorded.remaining),
  }
  const interactive = /interactive steps|run it on the machine yourself/i.test(detail)
  const approval = /manual approval|approval/i.test(detail)
  const rerun = operation.kind === 'ready.workflow'
    ? 'Run Make ready again for the same project and machine: it skips the steps already done and continues from the blocked one.'
    : operation.kind.startsWith('frogenv.')
      ? 'Run the same Frogenv action again from the machine\'s Tools tab.'
      : operation.kind === 'apply.workflow'
        ? 'Start apply again with approvals for the actions named above (fleetctl apply with the approved plan); nothing ran while it was blocked.'
        : 'Start the same action again.'
  const first = interactive
    ? 'Run the ceremony interactively on the machine yourself; Fleet cannot perform its interactive steps.'
    : operation.kind === 'apply.workflow'
      ? 'Review the actions the plan named above.'
      : approval
        ? 'Get the request approved (the detail above says which one).'
        : 'Resolve what the detail above describes.'
  const link = operation.kind === 'ready.workflow'
    ? { to: '/projects', label: 'Projects' }
    : operation.kind.startsWith('frogenv.') ? { to: '/fleet', label: 'Fleet' } : null
  return { ...base, steps: [first, rerun], link }
}
