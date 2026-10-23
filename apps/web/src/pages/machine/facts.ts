import type { CapabilityFactDto } from '@frogbyte-io/fleet-api-client'

import type { Tone } from '../fleet/inventory'

export function factStatusTone(status: string): Tone {
  switch (status) {
    case 'known': return 'ok'
    case 'stale': return 'warn'
    case 'unavailable': return 'muted'
    default: return 'faint'
  }
}

/** Facts grouped by namespace, namespaces and names sorted. */
export function groupFacts(facts: CapabilityFactDto[]): { namespace: string, facts: CapabilityFactDto[] }[] {
  const groups = new Map<string, CapabilityFactDto[]>()
  for (const fact of facts) {
    const list = groups.get(fact.namespace) ?? []
    list.push(fact)
    groups.set(fact.namespace, list)
  }
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([namespace, list]) => ({ namespace, facts: [...list].sort((a, b) => a.name.localeCompare(b.name)) }))
}

export function statusCounts(facts: CapabilityFactDto[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const fact of facts)
    counts[fact.status] = (counts[fact.status] ?? 0) + 1
  return counts
}

export function absoluteTime(ms: number | null | undefined): string {
  return ms === null || ms === undefined ? '—' : new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + 'Z'
}
