// The plan flow's rules (FM-409): what needs approval, what the operator is
// told before applying, and how a fetched candidate's result reads. No Vue
// imports, so each rule is unit-tested directly.

import type { PlanDto } from '@frogbyte-io/fleet-api-client'

import { ApiRequestError } from '../machine/api'

export type PlanAction = PlanDto['actions'][number]

/** Actions that must be approved before the plan can be applied. */
export function approvalsRequired(plan: Pick<PlanDto, 'actions'>): PlanAction[] {
  return plan.actions.filter(action => action.requiresApproval)
}

/** Whether every risky action has been approved (a plan with none is ready). */
export function allApproved(plan: Pick<PlanDto, 'actions'>, approved: ReadonlySet<number>): boolean {
  return approvalsRequired(plan).every(action => approved.has(action.order))
}

/** The approvals the apply request carries: exactly the approved risky actions. */
export function approvalsFor(plan: Pick<PlanDto, 'actions'>, approved: ReadonlySet<number>) {
  return approvalsRequired(plan)
    .filter(action => approved.has(action.order))
    .map(action => ({ actionOrder: action.order, kind: action.kind }))
}

const KIND_NOUN: Record<string, [string, string]> = {
  'skills.deploy': ['skill deployment', 'skill deployments'],
  'skills.undeploy': ['skill removal', 'skill removals'],
  'skills.catalog-rollout': ['catalog skill rollout', 'catalog skill rollouts'],
  'mise.install': ['tool install', 'tool installs'],
  'projects.clone': ['checkout', 'checkouts'],
}

/** "3 changes on box: 2 skill deployments, 1 skill removal", the blast radius in words. */
export function blastRadius(plan: Pick<PlanDto, 'actions'>, machineName: string): string {
  if (plan.actions.length === 0)
    return `Nothing to change on ${machineName}.`
  const counts = new Map<string, number>()
  for (const action of plan.actions)
    counts.set(action.kind, (counts.get(action.kind) ?? 0) + 1)
  const parts = [...counts].map(([kind, count]) => {
    const [one, many] = KIND_NOUN[kind] ?? [kind, `${kind} steps`]
    return `${count} ${count === 1 ? one : many}`
  })
  const total = plan.actions.length
  return `${total} change${total === 1 ? '' : 's'} on ${machineName}: ${parts.join(', ')}.`
}

/** A 409 `stale_plan`: the plan changed after it was reviewed. */
export function isStalePlan(error: unknown): boolean {
  return error instanceof ApiRequestError && error.code === 'stale_plan'
}

export interface FetchResult {
  commitSha: string
  contentDigest: string
  valid: boolean
  diagnostics: string[]
  resourceCount: number
}

/** Reads a settled `source.fetch` operation's result; null when it has none. */
export function parseFetchResult(resultJson: string | null | undefined): FetchResult | null {
  if (!resultJson)
    return null
  try {
    const parsed = JSON.parse(resultJson) as Record<string, unknown>
    if (typeof parsed.commitSha !== 'string' || typeof parsed.contentDigest !== 'string')
      return null
    return {
      commitSha: parsed.commitSha,
      contentDigest: parsed.contentDigest,
      valid: parsed.valid === true,
      diagnostics: Array.isArray(parsed.diagnostics) ? parsed.diagnostics.filter((d): d is string => typeof d === 'string') : [],
      resourceCount: typeof parsed.resourceCount === 'number' ? parsed.resourceCount : 0,
    }
  }
  catch {
    return null
  }
}

/** A full 40-character lowercase hexadecimal commit id, the only form the controller accepts. */
export function isCommitSha(value: string): boolean {
  return /^[0-9a-f]{40}$/.test(value)
}

/** Where a history entry sits relative to the active one (the list is newest first). */
export function historyAction(index: number, activeIndex: number): 'active' | 'activate' | 'rollback' {
  if (index === activeIndex)
    return 'active'
  return activeIndex < 0 || index < activeIndex ? 'activate' : 'rollback'
}
