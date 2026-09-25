/** The Audit page's filter model: pure functions, unit-tested without the DOM. */

/** The outcomes the API accepts, verbatim. */
export const OUTCOMES = [
  'allowed',
  'denied',
  'pending',
  'succeeded',
  'failed',
  'cancelled',
  'blocked_manual_approval',
] as const

export type Outcome = (typeof OUTCOMES)[number]

export interface AuditFilters {
  actor: string
  action: string
  resource: string
  outcome: Outcome | ''
  from: string
  to: string
}

export const EMPTY_FILTERS: AuditFilters = {
  actor: '',
  action: '',
  resource: '',
  outcome: '',
  from: '',
  to: '',
}

/** How many events one page carries; the API clamps at 200. */
export const PAGE = 200

/** How many pages the page will walk before declaring truncation. */
export const MAX_PAGES = 10

function isOutcome(value: string): value is Outcome {
  return (OUTCOMES as readonly string[]).includes(value)
}

/**
 * Turns the form state into API params: blank fields are dropped, the
 * date inputs are parsed as local-time epoch milliseconds, and an invalid
 * pair (from after to) is rejected rather than silently inverted.
 */
export function buildParams(
  filters: AuditFilters,
  cursor?: string,
): { params: Record<string, string | number>; error: string | null } {
  const params: Record<string, string | number> = {}
  if (filters.actor.trim()) params.actor = filters.actor.trim()
  if (filters.action.trim()) params.action = filters.action.trim()
  if (filters.resource.trim()) params.resource = filters.resource.trim()
  if (filters.outcome && isOutcome(filters.outcome)) params.outcome = filters.outcome

  if (filters.from.trim()) {
    const from = Date.parse(filters.from.trim())
    if (Number.isNaN(from)) return { params: {}, error: 'the "from" date is not a valid date' }
    params.from = from
  }
  if (filters.to.trim()) {
    const to = Date.parse(filters.to.trim())
    if (Number.isNaN(to)) return { params: {}, error: 'the "to" date is not a valid date' }
    params.to = to
  }
  if (params.from !== undefined && params.to !== undefined && (params.from as number) > (params.to as number)) {
    return { params: {}, error: 'the "from" date is after the "to" date' }
  }
  if (cursor) params.cursor = cursor
  return { params, error: null }
}

/** True when any filter field is set, so "clear" can be offered honestly. */
export function hasFilters(filters: AuditFilters): boolean {
  return (
    filters.actor.trim() !== '' ||
    filters.action.trim() !== '' ||
    filters.resource.trim() !== '' ||
    filters.outcome !== '' ||
    filters.from.trim() !== '' ||
    filters.to.trim() !== ''
  )
}
