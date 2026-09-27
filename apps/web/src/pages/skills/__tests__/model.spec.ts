import { describe, expect, it } from 'vitest'

import { agentShort, buildMatrix, columnLabel, fleetAgents, filterRows, parseSkillsData, type SnapshotLike } from '../model'

function snapshot(machineId: string, overrides: Partial<SnapshotLike> = {}): SnapshotLike {
  return {
    machineId,
    availability: 'available',
    cliVersion: '1.40.0',
    updateCheck: 'complete',
    observedAt: 1_000,
    stale: false,
    data: {
      skills: [
        { id: 'fleet', name: 'Fleet', enabled: true, presetIds: [], deployedTo: ['codex', 'claude_code'], updateStatus: 'up_to_date' },
        { id: 'notes', name: 'notes', enabled: true, presetIds: ['p1'], deployedTo: [], updateStatus: 'update_available' },
      ],
      presets: [{ id: 'p1', name: 'Default', skillCount: 1, active: true }],
      agents: [{ id: 'claude_code', name: 'Claude Code', installed: true, enabled: true }, { id: 'codex', name: 'Codex', installed: false, enabled: false }],
    },
    ...overrides,
  }
}

const machines = [
  { id: 'm1', name: 'workstation', machineStatus: 'connected' },
  { id: 'm2', name: 'rpi', machineStatus: 'agentless' },
  { id: 'm3', name: 'laptop', machineStatus: 'offline' },
]

describe('parseSkillsData', () => {
  it('reads the normalized shape and drops entries without an id', () => {
    const data = parseSkillsData({
      skills: [{ id: 'a', name: 'A', enabled: true, presetIds: ['x', 3], deployedTo: ['codex'], updateStatus: 'weird' }, { name: 'no id' }],
      presets: [{ id: 'p', name: 'P', skillCount: 2, active: false }, null],
      agents: 'not a list',
    })
    expect(data.skills).toEqual([{ id: 'a', name: 'A', enabled: true, presetIds: ['x'], deployedTo: ['codex'], updateStatus: 'unknown' }])
    expect(data.presets).toEqual([{ id: 'p', name: 'P', skillCount: 2, active: false }])
    expect(data.agents).toEqual([])
  })

  it('treats missing data as empty', () => {
    expect(parseSkillsData(undefined)).toEqual({ skills: [], presets: [], agents: [] })
  })
})

describe('buildMatrix', () => {
  const matrix = buildMatrix(
    [snapshot('m1'), snapshot('m2', { availability: 'absent', cliVersion: null, data: { skills: [], presets: [], agents: [] } })],
    machines,
    new Map([['fleet', 'cat-1'], ['rust-review', 'cat-2']]),
  )

  it('gives every machine a column and says why a column is empty', () => {
    expect(matrix.columns.map(c => [c.name, c.state])).toEqual([
      ['laptop', 'unobserved'],
      ['rpi', 'absent'],
      ['workstation', 'available'],
    ])
    expect(matrix.columns.map(columnLabel)).toEqual(['not probed', 'no CLI', 'cli 1.40.0'])
  })

  it('groups catalog skills before machine-local ones, including catalog skills no machine has', () => {
    expect(matrix.rows.map(r => [r.skillId, r.group, r.catalogId])).toEqual([
      ['fleet', 'catalog', 'cat-1'],
      ['rust-review', 'catalog', 'cat-2'],
      ['notes', 'local', null],
    ])
  })

  it('marks cells deployed, library-only, missing, or no-cli', () => {
    const fleet = matrix.rows[0]!
    expect(fleet.cells.m1).toEqual({ state: 'deployed', agents: ['claude_code', 'codex'], update: false, enabled: true })
    expect(fleet.cells.m2!.state).toBe('no-cli')
    expect(fleet.cells.m3!.state).toBe('no-cli')
    expect(fleet.deployedOn).toBe(1)
    const notes = matrix.rows[2]!
    expect(notes.cells.m1).toMatchObject({ state: 'library', update: true })
    expect(notes.updatesOn).toBe(1)
    expect(matrix.rows[1]!.cells.m1!.state).toBe('missing')
  })

  it('matches a library entry to the catalog by name when its id differs', () => {
    const renamed = buildMatrix(
      [snapshot('m1', { data: { skills: [{ id: 'sm-42', name: 'fleet', enabled: true, presetIds: [], deployedTo: ['codex'], updateStatus: 'up_to_date' }] } })],
      machines,
      new Map([['fleet', 'cat-1']]),
    )
    expect(renamed.rows.map(r => [r.skillId, r.group])).toEqual([['fleet', 'catalog']])
    expect(renamed.rows[0]!.cells.m1!.state).toBe('deployed')
  })

  it('filters by name, agent, and state', () => {
    expect(filterRows(matrix.rows, { text: 'rust', agent: '', state: 'any' }).map(r => r.skillId)).toEqual(['rust-review'])
    expect(filterRows(matrix.rows, { text: '', agent: 'codex', state: 'any' }).map(r => r.skillId)).toEqual(['fleet'])
    expect(filterRows(matrix.rows, { text: '', agent: '', state: 'update' }).map(r => r.skillId)).toEqual(['notes'])
    expect(filterRows(matrix.rows, { text: '', agent: '', state: 'library-only' }).map(r => r.skillId)).toEqual(['notes'])
  })
})

describe('agents', () => {
  it('abbreviates known and unknown agents', () => {
    expect(agentShort('claude_code')).toBe('CC')
    expect(agentShort('opencode')).toBe('OC')
    expect(agentShort('roo_code')).toBe('RC')
    expect(agentShort('windsurf')).toBe('WI')
    expect(agentShort('constructor')).toBe('CO')
  })

  it('unions agents across machines, installed anywhere wins', () => {
    const agents = fleetAgents([
      snapshot('m1'),
      snapshot('m2', { data: { agents: [{ id: 'codex', name: 'Codex', installed: true, enabled: true }] } }),
    ])
    expect(agents.map(a => [a.id, a.installed])).toEqual([['claude_code', true], ['codex', true]])
  })
})
