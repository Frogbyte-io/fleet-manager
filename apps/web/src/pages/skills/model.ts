// Pure Skills console model: the normalized Skills Manager snapshot shape
// (fleet-controller `normalize_probe`), the fleet matrix, and agent labels.
// No Vue imports, so the rules here are unit-tested directly.

import type { Tone } from '../fleet/inventory'

export type UpdateStatus = 'update_available' | 'up_to_date' | 'local_only' | 'unknown'

export interface SkillEntry {
  id: string
  name: string
  enabled: boolean
  presetIds: string[]
  deployedTo: string[]
  updateStatus: UpdateStatus
}

export interface PresetEntry {
  id: string
  name: string
  skillCount: number
  active: boolean
}

export interface AgentEntry {
  id: string
  name: string
  installed: boolean
  enabled: boolean
}

export interface SkillsData {
  skills: SkillEntry[]
  presets: PresetEntry[]
  agents: AgentEntry[]
}

/** The snapshot fields the console reads (`SkillsSnapshotDto`). */
export interface SnapshotLike {
  machineId: string
  availability: string
  cliVersion?: string | null
  data?: unknown
  updateCheck: string
  observedAt: number
  stale: boolean
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value !== '' ? value : null
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : []
}

const UPDATE_STATUSES = new Set<UpdateStatus>(['update_available', 'up_to_date', 'local_only', 'unknown'])

/**
 * Reads the snapshot's `data`, which the OpenAPI document leaves untyped.
 * Entries without an id are dropped rather than guessed at.
 */
export function parseSkillsData(data: unknown): SkillsData {
  const root = record(data) ?? {}
  const list = (key: string) => (Array.isArray(root[key]) ? root[key] as unknown[] : [])
  const skills: SkillEntry[] = []
  for (const item of list('skills')) {
    const entry = record(item)
    const id = text(entry?.id)
    if (!entry || !id)
      continue
    const status = entry.updateStatus as UpdateStatus
    skills.push({
      id,
      name: text(entry.name) ?? id,
      enabled: entry.enabled === true,
      presetIds: strings(entry.presetIds),
      deployedTo: strings(entry.deployedTo),
      updateStatus: UPDATE_STATUSES.has(status) ? status : 'unknown',
    })
  }
  const presets: PresetEntry[] = []
  for (const item of list('presets')) {
    const entry = record(item)
    const id = text(entry?.id)
    if (!entry || !id)
      continue
    presets.push({
      id,
      name: text(entry.name) ?? id,
      skillCount: typeof entry.skillCount === 'number' ? entry.skillCount : 0,
      active: entry.active === true,
    })
  }
  const agents: AgentEntry[] = []
  for (const item of list('agents')) {
    const entry = record(item)
    const id = text(entry?.id)
    if (!entry || !id)
      continue
    agents.push({ id, name: text(entry.name) ?? id, installed: entry.installed === true, enabled: entry.enabled === true })
  }
  return { skills, presets, agents }
}

const KNOWN_AGENT_SHORT: Record<string, string> = {
  claude_code: 'CC',
  codex: 'CX',
  opencode: 'OC',
  cursor: 'CU',
  gemini_cli: 'GE',
}

/** A two-letter badge for an agent id, e.g. `claude_code` → `CC`. */
export function agentShort(id: string): string {
  const known = Object.hasOwn(KNOWN_AGENT_SHORT, id) ? KNOWN_AGENT_SHORT[id] : undefined
  if (known)
    return known
  const words = id.split(/[_\-\s.]+/).filter(Boolean)
  const letters = words.length > 1 ? words.slice(0, 2).map(w => w[0]) : [...(words[0] ?? id).slice(0, 2)]
  return letters.join('').toUpperCase()
}

/** Every agent any machine reports, by id, with its first reported name. */
export function fleetAgents(snapshots: SnapshotLike[]): AgentEntry[] {
  const byId = new Map<string, AgentEntry>()
  for (const snapshot of snapshots) {
    for (const agent of parseSkillsData(snapshot.data).agents) {
      const known = byId.get(agent.id)
      if (!known)
        byId.set(agent.id, { ...agent })
      else if (agent.installed)
        known.installed = true
    }
  }
  return [...byId.values()].sort((a, b) => a.name.localeCompare(b.name))
}

// ---------------------------------------------------------------------------
// Fleet matrix

export interface MachineLike {
  id: string
  name: string
  machineStatus: string
  groups?: string[]
  tags?: string[]
}

/**
 * Why a machine column can or cannot say anything about skills:
 * `available` has a supported CLI; the rest explain the empty column.
 */
export type ColumnState = 'available' | 'absent' | 'unsupported' | 'unobserved'

export interface MatrixColumn {
  machineId: string
  name: string
  machineStatus: string
  state: ColumnState
  stale: boolean
  cliVersion: string | null
  updateCheck: string | null
  observedAt: number | null
}

export type CellState = 'deployed' | 'library' | 'missing' | 'no-cli'

export interface MatrixCell {
  state: CellState
  /** Agents the skill is deployed to on this machine. */
  agents: string[]
  update: boolean
  enabled: boolean
}

export type RowGroup = 'catalog' | 'local'

export interface MatrixRow {
  skillId: string
  name: string
  group: RowGroup
  catalogId: string | null
  cells: Record<string, MatrixCell>
  /** Machines where the skill is deployed to at least one agent. */
  deployedOn: number
  /** Machines where the skill has an update available. */
  updatesOn: number
}

export interface Matrix {
  columns: MatrixColumn[]
  rows: MatrixRow[]
}

function columnState(snapshot: SnapshotLike | undefined): ColumnState {
  if (!snapshot)
    return 'unobserved'
  if (snapshot.availability === 'available')
    return 'available'
  if (snapshot.availability === 'absent')
    return 'absent'
  return 'unsupported'
}

/**
 * Joins the fleet-wide snapshots with the machine list. Every machine gets a
 * column (a machine never probed says so); every skill any machine reports
 * gets a row, grouped by whether Fleet's catalog carries a skill of that name.
 */
export function buildMatrix(
  snapshots: SnapshotLike[],
  machines: MachineLike[],
  catalogByName: Map<string, string>,
): Matrix {
  const snapshotsById = new Map(snapshots.map(s => [s.machineId, s]))
  const machineById = new Map(machines.map(m => [m.id, m]))
  const ids = [...new Set([...machines.map(m => m.id), ...snapshots.map(s => s.machineId)])]
  const columns: MatrixColumn[] = ids.map((id) => {
    const snapshot = snapshotsById.get(id)
    const machine = machineById.get(id)
    return {
      machineId: id,
      name: machine?.name ?? id,
      machineStatus: machine?.machineStatus ?? 'unknown',
      state: columnState(snapshot),
      stale: snapshot?.stale ?? false,
      cliVersion: snapshot?.cliVersion ?? null,
      updateCheck: snapshot?.updateCheck ?? null,
      observedAt: snapshot?.observedAt ?? null,
    }
  }).sort((a, b) => a.name.localeCompare(b.name))

  const rows = new Map<string, MatrixRow>()
  const libraries = new Map<string, Map<string, SkillEntry>>()
  for (const column of columns) {
    const snapshot = snapshotsById.get(column.machineId)
    if (column.state !== 'available' || !snapshot)
      continue
    const skills = new Map<string, SkillEntry>()
    for (const skill of parseSkillsData(snapshot.data).skills) {
      // Catalog entries are keyed by their Agent Skills name; a library entry
      // matches one by id or by name, and then shares the catalog's row.
      const key = catalogByName.has(skill.id) ? skill.id : catalogByName.has(skill.name) ? skill.name : skill.id
      skills.set(key, skill)
      if (!rows.has(key)) {
        const catalogId = catalogByName.get(key) ?? null
        rows.set(key, {
          skillId: key,
          name: skill.name,
          group: catalogId ? 'catalog' : 'local',
          catalogId,
          cells: {},
          deployedOn: 0,
          updatesOn: 0,
        })
      }
    }
    libraries.set(column.machineId, skills)
  }
  // Catalog entries no machine has yet still get a row, so the matrix shows
  // what Fleet could roll out and where it is missing.
  for (const [name, catalogId] of catalogByName) {
    if (!rows.has(name))
      rows.set(name, { skillId: name, name, group: 'catalog', catalogId, cells: {}, deployedOn: 0, updatesOn: 0 })
  }

  for (const row of rows.values()) {
    for (const column of columns) {
      if (column.state !== 'available') {
        row.cells[column.machineId] = { state: 'no-cli', agents: [], update: false, enabled: false }
        continue
      }
      const skill = libraries.get(column.machineId)?.get(row.skillId)
      if (!skill) {
        row.cells[column.machineId] = { state: 'missing', agents: [], update: false, enabled: false }
        continue
      }
      const deployed = skill.deployedTo.length > 0
      const update = skill.updateStatus === 'update_available'
      row.cells[column.machineId] = {
        state: deployed ? 'deployed' : 'library',
        agents: [...skill.deployedTo].sort(),
        update,
        enabled: skill.enabled,
      }
      if (deployed)
        row.deployedOn++
      if (update)
        row.updatesOn++
    }
  }
  const sorted = [...rows.values()].sort((a, b) =>
    (a.group === b.group ? 0 : a.group === 'catalog' ? -1 : 1) || a.skillId.localeCompare(b.skillId))
  return { columns, rows: sorted }
}

export type StateFilter = 'any' | 'deployed' | 'update' | 'library-only'

export interface MatrixFilter {
  text: string
  agent: string
  state: StateFilter
}

/** Whether one cell satisfies the agent and state filters. */
function cellMatches(cell: MatrixCell, filter: MatrixFilter): boolean {
  if (filter.agent && !cell.agents.includes(filter.agent))
    return false
  switch (filter.state) {
    case 'deployed': return cell.state === 'deployed'
    case 'update': return cell.update
    case 'library-only': return cell.state === 'library'
    default: return filter.agent ? true : cell.state !== 'no-cli'
  }
}

/** Rows with at least one cell matching the filters, and a name matching the text. */
export function filterRows(rows: MatrixRow[], filter: MatrixFilter): MatrixRow[] {
  const needle = filter.text.trim().toLowerCase()
  return rows.filter((row) => {
    if (needle && !row.skillId.toLowerCase().includes(needle) && !row.name.toLowerCase().includes(needle))
      return false
    if (!filter.agent && filter.state === 'any')
      return true
    return Object.values(row.cells).some(cell => cellMatches(cell, filter))
  })
}

export function columnTone(column: MatrixColumn): Tone {
  if (column.state === 'available')
    return column.stale ? 'warn' : 'ok'
  if (column.state === 'unobserved')
    return 'faint'
  return 'muted'
}

export function columnLabel(column: MatrixColumn): string {
  switch (column.state) {
    case 'available': return column.stale ? 'stale' : (column.cliVersion ? `cli ${column.cliVersion}` : 'available')
    case 'absent': return 'no CLI'
    case 'unsupported': return column.cliVersion ? `unsupported ${column.cliVersion}` : 'unsupported'
    default: return 'not probed'
  }
}
