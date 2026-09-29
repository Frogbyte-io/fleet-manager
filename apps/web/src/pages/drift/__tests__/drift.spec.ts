import { describe, expect, it } from 'vitest'

import type { MachineDriftDto } from '@frogbyte-io/fleet-api-client'

import { describeIdentity, driftLabel, driftTone, driftView, groupDifferences, isActionable, skillDifferences } from '../drift'

const counts = (overrides: Partial<MachineDriftDto['counts']> = {}) => ({ missing: 0, changed: 0, extra: 0, unknown: 0, unsupported: 0, ...overrides })
const entry = (status: string, overrides: Partial<MachineDriftDto['counts']> = {}, detail: string | null = null) => ({ status, counts: counts(overrides), detail })

describe('driftView', () => {
  it('is in sync only when everything was observed and matches', () => {
    expect(driftView(entry('computed'))).toEqual({ kind: 'in-sync' })
  })

  it('counts missing, changed and extra as drift and keeps the unobserved counts', () => {
    expect(driftView(entry('computed', { missing: 2, extra: 1, unknown: 1 }))).toEqual({ kind: 'drifted', actionable: 3, unknown: 1, unsupported: 0 })
  })

  it('never calls unknown or unsupported fields "in sync"', () => {
    expect(driftView(entry('computed', { unknown: 2 })).kind).toBe('unknown')
    expect(driftView(entry('computed', { unsupported: 1 })).kind).toBe('unknown')
  })

  it('separates "no revision" and "unavailable" from a clean machine', () => {
    expect(driftView(entry('no_revision'))).toEqual({ kind: 'no-revision' })
    expect(driftView(entry('unavailable', {}, 'reading the machine failed'))).toEqual({ kind: 'unavailable', detail: 'reading the machine failed' })
    expect(driftView(entry('unavailable'))).toMatchObject({ kind: 'unavailable' })
  })

  it('words and tones each view', () => {
    expect(driftLabel(driftView(entry('computed', { changed: 1 })))).toBe('1 drifted')
    expect(driftTone(driftView(entry('computed')))).toBe('ok')
    expect(driftTone(driftView(entry('computed', { missing: 1 })))).toBe('warn')
    expect(driftTone(driftView(entry('computed', { unknown: 1 })))).toBe('muted')
    expect(driftTone(driftView(entry('unavailable')))).toBe('err')
    expect(driftLabel(driftView(entry('no_revision')))).toBe('no revision')
  })
})

describe('identities and grouping', () => {
  it('splits skill identities into name and agent', () => {
    expect(describeIdentity('skill:db/codex')).toEqual({ kind: 'skill', name: 'db', agent: 'codex' })
    expect(describeIdentity('catalog-skill:builtin-fleet/claude_code')).toEqual({ kind: 'catalog skill', name: 'builtin-fleet', agent: 'claude_code' })
    expect(describeIdentity('tool:node')).toEqual({ kind: 'tool', name: 'node', agent: null })
    expect(describeIdentity('odd')).toEqual({ kind: 'field', name: 'odd', agent: null })
  })

  it('groups by state with actionable states first and drops empty groups', () => {
    const differences = [
      { identity: 'skill:a/codex', state: 'unknown', desired: null, observed: null, reason: null },
      { identity: 'skill:b/codex', state: 'missing', desired: null, observed: null, reason: null },
      { identity: 'skill:c/codex', state: 'extra', desired: null, observed: null, reason: null },
    ] as MachineDriftDto['differences']
    expect(groupDifferences(differences).map(g => [g.state, g.items.length])).toEqual([['missing', 1], ['extra', 1], ['unknown', 1]])
  })

  it('finds the differences on one skill and ignores catalog pins', () => {
    const differences = [
      { identity: 'skill:db/codex', state: 'missing' },
      { identity: 'skill:db/claude_code', state: 'extra' },
      { identity: 'skill:other/codex', state: 'missing' },
      { identity: 'catalog-skill:db/codex', state: 'unknown' },
    ] as MachineDriftDto['differences']
    expect(skillDifferences({ differences }, 'db').map(d => d.identity)).toEqual(['skill:db/codex', 'skill:db/claude_code'])
    expect(skillDifferences(undefined, 'db')).toEqual([])
    expect(isActionable('missing')).toBe(true)
    expect(isActionable('unknown')).toBe(false)
  })
})
