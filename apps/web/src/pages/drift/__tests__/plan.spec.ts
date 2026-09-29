import { describe, expect, it } from 'vitest'

import { ApiRequestError } from '../../machine/api'
import {
  allApproved,
  approvalsFor,
  approvalsRequired,
  blastRadius,
  historyAction,
  isCommitSha,
  isStalePlan,
  parseFetchResult,
} from '../plan'

function action(order: number, kind: string, requiresApproval = false) {
  return {
    order,
    kind,
    requiresApproval,
    reason: 'r',
    difference: { identity: `id-${order}`, state: 'missing', desired: null, observed: null, reason: null },
  } as never
}

const plan = {
  actions: [action(1, 'skills.deploy'), action(2, 'skills.undeploy', true), action(3, 'skills.deploy', true)],
}

describe('approvals', () => {
  it('lists only the actions that need approval', () => {
    expect(approvalsRequired(plan).map(a => a.order)).toEqual([2, 3])
    expect(approvalsRequired({ actions: [] })).toEqual([])
  })

  it('is ready only when every risky action is approved', () => {
    expect(allApproved(plan, new Set())).toBe(false)
    expect(allApproved(plan, new Set([2]))).toBe(false)
    expect(allApproved(plan, new Set([2, 3]))).toBe(true)
    expect(allApproved({ actions: [action(1, 'skills.deploy')] }, new Set())).toBe(true)
  })

  it('carries exactly the approved risky actions, ignoring unrelated orders', () => {
    expect(approvalsFor(plan, new Set([3, 1, 9]))).toEqual([{ actionOrder: 3, kind: 'skills.deploy' }])
    expect(approvalsFor(plan, new Set())).toEqual([])
  })
})

describe('blastRadius', () => {
  it('says nothing changes for an empty plan', () => {
    expect(blastRadius({ actions: [] }, 'box')).toBe('Nothing to change on box.')
  })

  it('uses singular wording for one change', () => {
    expect(blastRadius({ actions: [action(1, 'skills.undeploy')] }, 'box')).toBe('1 change on box: 1 skill removal.')
  })

  it('counts and pluralises per kind', () => {
    expect(blastRadius(plan, 'box')).toBe('3 changes on box: 2 skill deployments, 1 skill removal.')
  })

  it('falls back to the kind name for an unknown kind', () => {
    expect(blastRadius({ actions: [action(1, 'x.y'), action(2, 'x.y')] }, 'box')).toBe('2 changes on box: 2 x.y steps.')
    expect(blastRadius({ actions: [action(1, 'x.y')] }, 'box')).toBe('1 change on box: 1 x.y.')
  })
})

describe('isStalePlan', () => {
  it('recognises the stale_plan conflict only', () => {
    expect(isStalePlan(new ApiRequestError(409, 'stale_plan', 'stale_plan: changed'))).toBe(true)
    expect(isStalePlan(new ApiRequestError(409, 'conflict', 'conflict'))).toBe(false)
    expect(isStalePlan(new ApiRequestError(500, null, 'boom'))).toBe(false)
    expect(isStalePlan(new Error('stale_plan'))).toBe(false)
    expect(isStalePlan(null)).toBe(false)
  })
})

describe('parseFetchResult', () => {
  it('reads a valid result', () => {
    expect(parseFetchResult(JSON.stringify({ commitSha: 'a', contentDigest: 'd', valid: true, diagnostics: [], resourceCount: 4 })))
      .toEqual({ commitSha: 'a', contentDigest: 'd', valid: true, diagnostics: [], resourceCount: 4 })
  })

  it('reads an invalid result with its diagnostics', () => {
    const result = parseFetchResult(JSON.stringify({ commitSha: 'a', contentDigest: 'd', valid: false, diagnostics: ['bad', 3, 'worse'] }))
    expect(result).toEqual({ commitSha: 'a', contentDigest: 'd', valid: false, diagnostics: ['bad', 'worse'], resourceCount: 0 })
  })

  it('never treats a missing or non-true valid as valid', () => {
    expect(parseFetchResult('{"commitSha":"a","contentDigest":"d","valid":"true"}')?.valid).toBe(false)
    expect(parseFetchResult('{"commitSha":"a","contentDigest":"d"}')?.valid).toBe(false)
  })

  it('returns null for missing, partial or garbage JSON', () => {
    expect(parseFetchResult(null)).toBeNull()
    expect(parseFetchResult(undefined)).toBeNull()
    expect(parseFetchResult('')).toBeNull()
    expect(parseFetchResult('not json')).toBeNull()
    expect(parseFetchResult('{"commitSha":"a"}')).toBeNull()
    expect(parseFetchResult('{"commitSha":1,"contentDigest":"d"}')).toBeNull()
  })
})

describe('isCommitSha', () => {
  it('accepts only 40 lowercase hex characters', () => {
    expect(isCommitSha('a'.repeat(40))).toBe(true)
    expect(isCommitSha('0123456789abcdef0123456789abcdef01234567')).toBe(true)
    expect(isCommitSha('a'.repeat(39))).toBe(false)
    expect(isCommitSha('a'.repeat(41))).toBe(false)
    expect(isCommitSha('A'.repeat(40))).toBe(false)
    expect(isCommitSha('main')).toBe(false)
    expect(isCommitSha(`${'a'.repeat(39)}g`)).toBe(false)
  })
})

describe('historyAction (newest first)', () => {
  it('marks the active entry', () => {
    expect(historyAction(2, 2)).toBe('active')
  })

  it('offers activation for entries newer than the active one', () => {
    expect(historyAction(0, 2)).toBe('activate')
    expect(historyAction(1, 2)).toBe('activate')
  })

  it('offers rollback for entries older than the active one', () => {
    expect(historyAction(3, 2)).toBe('rollback')
  })

  it('offers activation when nothing is active', () => {
    expect(historyAction(0, -1)).toBe('activate')
    expect(historyAction(5, -1)).toBe('activate')
  })
})
