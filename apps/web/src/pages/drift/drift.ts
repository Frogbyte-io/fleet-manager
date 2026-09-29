// Drift against the active desired revision (FM-408). The controller
// computes it (the same composition the planner uses); this module only
// reads and words it. No Vue imports, so every rule is unit-tested directly.

import type { MachineDriftDto } from '@frogbyte-io/fleet-api-client'

export type DriftState = 'missing' | 'changed' | 'extra' | 'unknown' | 'unsupported'

export type DriftTone = 'ok' | 'info' | 'warn' | 'err' | 'muted' | 'faint'

/** The states Fleet would act on, as opposed to states it can only report. */
const ACTIONABLE = new Set<string>(['missing', 'changed', 'extra'])

export const STATE_LABEL: Record<DriftState, string> = {
  missing: 'missing',
  changed: 'changed',
  extra: 'extra',
  unknown: 'unknown',
  unsupported: 'unsupported',
}

export const STATE_EXPLANATION: Record<DriftState, string> = {
  missing: 'Desired, but not on the machine.',
  changed: 'On the machine with a different value than desired.',
  extra: 'On the machine, but Fleet Git no longer wants it there.',
  unknown: 'The machine did not answer, so its state is not known. This is not "in sync".',
  unsupported: 'Fleet cannot manage this on the machine, or does not manage it.',
}

export type DriftView =
  | { kind: 'in-sync' }
  | { kind: 'drifted', actionable: number, unknown: number, unsupported: number }
  | { kind: 'unknown', unknown: number, unsupported: number }
  | { kind: 'no-revision' }
  | { kind: 'unavailable', detail: string }

/** One machine's drift as the console words it. */
export function driftView(entry: Pick<MachineDriftDto, 'status' | 'counts' | 'detail'>): DriftView {
  if (entry.status === 'no_revision')
    return { kind: 'no-revision' }
  if (entry.status !== 'computed')
    return { kind: 'unavailable', detail: entry.detail ?? 'Drift could not be computed for this machine.' }
  const actionable = entry.counts.missing + entry.counts.changed + entry.counts.extra
  if (actionable > 0)
    return { kind: 'drifted', actionable, unknown: entry.counts.unknown, unsupported: entry.counts.unsupported }
  // Nothing to act on, but not everything was observed: never "in sync".
  if (entry.counts.unknown > 0 || entry.counts.unsupported > 0)
    return { kind: 'unknown', unknown: entry.counts.unknown, unsupported: entry.counts.unsupported }
  return { kind: 'in-sync' }
}

export function driftLabel(view: DriftView): string {
  switch (view.kind) {
    case 'in-sync': return 'in sync'
    case 'drifted': return `${view.actionable} drifted`
    case 'unknown': return 'unknown'
    case 'no-revision': return 'no revision'
    case 'unavailable': return 'unavailable'
  }
}

export function driftTone(view: DriftView): DriftTone {
  switch (view.kind) {
    case 'in-sync': return 'ok'
    case 'drifted': return 'warn'
    case 'unknown': return 'muted'
    case 'no-revision': return 'faint'
    case 'unavailable': return 'err'
  }
}

/** `skill:db/codex` → its parts; identities outside the vocabulary keep the raw text. */
export function describeIdentity(identity: string): { kind: string, name: string, agent: string | null } {
  const separator = identity.indexOf(':')
  if (separator < 0)
    return { kind: 'field', name: identity, agent: null }
  const kind = identity.slice(0, separator)
  const rest = identity.slice(separator + 1)
  const slash = rest.lastIndexOf('/')
  if ((kind === 'skill' || kind === 'catalog-skill') && slash > 0)
    return { kind: kind === 'skill' ? 'skill' : 'catalog skill', name: rest.slice(0, slash), agent: rest.slice(slash + 1) }
  return { kind: kind === 'catalog-skill' ? 'catalog skill' : kind, name: rest, agent: null }
}

export function isActionable(state: string): boolean {
  return ACTIONABLE.has(state)
}

/** Differences grouped by state, actionable states first, empty groups dropped. */
export function groupDifferences(differences: MachineDriftDto['differences']) {
  const order: DriftState[] = ['missing', 'changed', 'extra', 'unknown', 'unsupported']
  return order
    .map(state => ({ state, items: differences.filter(d => d.state === state) }))
    .filter(group => group.items.length > 0)
}

/** The differences on one skill, for a matrix cell. */
export function skillDifferences(entry: Pick<MachineDriftDto, 'differences'> | undefined, skillId: string) {
  return (entry?.differences ?? []).filter((d) => {
    const parts = describeIdentity(d.identity)
    return parts.kind === 'skill' && parts.name === skillId
  })
}
