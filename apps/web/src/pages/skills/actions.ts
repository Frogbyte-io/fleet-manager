// Skills Manager library and preset actions as the machine Skills tab sends
// them: the `startSkillsOperation` body, the `fleetctl skills …` equivalent,
// and how a settled operation's conflict data reads. Mirrors fleetctl's
// `parse_skills_command` and fleet-api `start_skills_operation`.

import type { CatalogContentDto, CatalogRolloutRequest, StartSkillsOperationRequest } from '@frogbyte-io/fleet-api-client'

import { shellQuote, type SshAuth } from '../machine/fleetctl'

export const OPERATION_TIMEOUT_SECONDS = 300

export type SkillAction =
  | 'install'
  | 'update'
  | 'check'
  | 'remove'
  | 'adopt'
  | 'set-source'
  | 'deploy'
  | 'undeploy'
  | 'presets.create'
  | 'presets.update'
  | 'presets.delete'
  | 'presets.add-skill'
  | 'presets.remove-skill'
  | 'presets.deploy'
  | 'presets.undeploy'

/** Actions whose real run must follow a successful dry run of the same request. */
export const PREVIEW_FIRST = new Set<SkillAction>(['remove', 'adopt', 'presets.delete'])

/** Actions the pinned CLI can dry-run (fleet-controller `library_operation`). */
export const DRY_RUNNABLE = new Set<SkillAction>([
  'remove', 'adopt', 'set-source', 'deploy', 'undeploy', 'presets.deploy', 'presets.undeploy', 'presets.delete',
])

/** Actions that take `--yes` / `confirm: true`. */
export const CONFIRMED = new Set<SkillAction>(['remove', 'presets.delete'])

export interface ActionInput {
  action: SkillAction
  /** Skill or preset reference; for update/check an empty value means all. */
  reference: string
  /** Extra skills to remove in the same call. */
  references: string[]
  /** skills.adopt paths; set-source subpath; preset add/remove skill id. */
  path: string
  paths: string[]
  sourceUrl: string
  gitSubpath: string
  branch: string
  name: string
  description: string
  icon: string
  local: boolean
  git: boolean
  sync: boolean
  syncPreset: string
  force: boolean
  agents: string[]
}

export function emptyInput(action: SkillAction): ActionInput {
  return {
    action, reference: '', references: [], path: '', paths: [], sourceUrl: '', gitSubpath: '', branch: '',
    name: '', description: '', icon: '', local: false, git: false, sync: false, syncPreset: '', force: false, agents: [],
  }
}

/** What the form is missing before it can be sent, or null when complete. */
export function missingField(input: ActionInput): string | null {
  const has = (value: string) => value.trim() !== ''
  switch (input.action) {
    case 'install': return has(input.reference) ? null : 'a source reference'
    case 'remove': return has(input.reference) || input.references.length > 0 ? null : 'a skill to remove'
    case 'adopt': return has(input.path) || input.paths.length > 0 ? null : 'a directory to adopt'
    case 'set-source': return has(input.reference) && has(input.sourceUrl) ? null : 'a skill and its source URL'
    case 'deploy':
    case 'undeploy': return !has(input.reference) ? 'a skill' : input.agents.length === 0 ? 'at least one agent' : null
    case 'presets.update':
      if (!has(input.reference))
        return 'a preset'
      return has(input.name) || has(input.description) || has(input.icon) ? null : 'a changed name, description, or icon'
    case 'presets.add-skill':
    case 'presets.remove-skill': return has(input.reference) && has(input.path) ? null : 'a preset and a skill'
    case 'presets.create':
    case 'presets.delete':
    case 'presets.deploy':
    case 'presets.undeploy': return has(input.reference) ? null : 'a preset'
    default: return null
  }
}

function optional(value: string): string | undefined {
  return value.trim() === '' ? undefined : value.trim()
}

export interface Target {
  machineId: string
  endpointId: string
  auth: SshAuth
}

/** The request body; `dryRun` previews, and `confirm` is sent only for a real removal. */
export function operationRequest(target: Target, input: ActionInput, dryRun: boolean): StartSkillsOperationRequest {
  const base = {
    machineId: target.machineId,
    endpointId: target.endpointId,
    auth: target.auth,
    timeoutSeconds: OPERATION_TIMEOUT_SECONDS,
    dryRun,
  }
  if (input.action === 'deploy' || input.action === 'undeploy')
    return { ...base, skillId: input.reference.trim(), agents: input.agents, direction: input.action }
  const body: StartSkillsOperationRequest = {
    ...base,
    operation: input.action,
    confirm: CONFIRMED.has(input.action),
    agents: input.action === 'presets.deploy' || input.action === 'presets.undeploy' ? input.agents : [],
  }
  const reference = optional(input.reference)
  if (reference)
    body.reference = reference
  if (input.action === 'remove' && input.references.length > 0)
    body.references = input.references
  if (input.action === 'adopt') {
    if (optional(input.path))
      body.path = input.path.trim()
    if (input.paths.length > 0)
      body.paths = input.paths
    if (optional(input.sourceUrl))
      body.sourceUrl = input.sourceUrl.trim()
    if (optional(input.gitSubpath))
      body.gitSubpath = input.gitSubpath.trim()
  }
  if (input.action === 'set-source') {
    body.sourceUrl = input.sourceUrl.trim()
    if (optional(input.path))
      body.path = input.path.trim()
    if (optional(input.branch))
      body.branch = input.branch.trim()
    body.force = input.force
  }
  if (input.action === 'presets.add-skill' || input.action === 'presets.remove-skill')
    body.path = input.path.trim()
  if (input.action === 'install') {
    body.local = input.local
    body.git = input.git
    body.sync = input.sync
    if (optional(input.name))
      body.name = input.name.trim()
    if (optional(input.syncPreset))
      body.syncPreset = input.syncPreset.trim()
  }
  if (input.action === 'presets.create' || input.action === 'presets.update') {
    if (input.action === 'presets.update' && optional(input.name))
      body.name = input.name.trim()
    if (optional(input.description))
      body.description = input.description.trim()
    if (optional(input.icon))
      body.icon = input.icon.trim()
  }
  return body
}

const VERBS: Record<SkillAction, string> = {
  'install': 'install',
  'update': 'update',
  'check': 'check',
  'remove': 'remove',
  'adopt': 'adopt',
  'set-source': 'set-source',
  'deploy': 'deploy',
  'undeploy': 'undeploy',
  'presets.create': 'preset-create',
  'presets.update': 'preset-update',
  'presets.delete': 'preset-delete',
  'presets.add-skill': 'preset-add-skill',
  'presets.remove-skill': 'preset-remove-skill',
  'presets.deploy': 'preset-deploy',
  'presets.undeploy': 'preset-undeploy',
}

function join(words: string[]): string {
  return words.map(shellQuote).join(' ')
}

function authFlags(target: Target): string[] {
  return ['--endpoint', target.endpointId, ...(target.auth.type === 'agent'
    ? ['--auth', 'agent']
    : ['--auth', 'identity-file', '--identity', target.auth.path])]
}

/** The `fleetctl skills …` command that sends the same request. */
export function actionCommand(target: Target, input: ActionInput, dryRun: boolean): string {
  const words = ['fleetctl', 'skills', VERBS[input.action], target.machineId]
  const flag = (name: string, value: string) => {
    if (value.trim() !== '')
      words.push(`--${name}`, value.trim())
  }
  if (input.action === 'deploy' || input.action === 'undeploy')
    flag('skill', input.reference)
  else
    flag('reference', input.reference)
  if (input.action === 'remove')
    input.references.forEach(r => words.push('--reference-batch', r))
  if (input.action === 'adopt') {
    flag('path', input.path)
    input.paths.forEach(p => words.push('--path-batch', p))
    flag('source-url', input.sourceUrl)
    flag('git-subpath', input.gitSubpath)
  }
  if (input.action === 'set-source') {
    flag('source-url', input.sourceUrl)
    flag('path', input.path)
    flag('branch', input.branch)
    if (input.force)
      words.push('--force')
  }
  if (input.action === 'presets.add-skill' || input.action === 'presets.remove-skill')
    flag('path', input.path)
  if (input.action === 'install') {
    if (input.local)
      words.push('--local')
    if (input.git)
      words.push('--git')
    flag('name', input.name)
    if (input.sync)
      words.push('--sync')
    flag('sync-preset', input.syncPreset)
  }
  if (input.action === 'presets.update')
    flag('name', input.name)
  if (input.action === 'presets.create' || input.action === 'presets.update') {
    flag('description', input.description)
    flag('icon', input.icon)
  }
  if (['deploy', 'undeploy', 'presets.deploy', 'presets.undeploy'].includes(input.action))
    input.agents.forEach(agent => words.push('--agent', agent))
  if (CONFIRMED.has(input.action))
    words.push('--yes')
  if (dryRun)
    words.push('--dry-run')
  words.push(...authFlags(target))
  // Only the commands whose usage lists --wait take it.
  if (['install', 'update', 'check', 'remove', 'deploy', 'undeploy'].includes(input.action))
    words.push('--wait')
  return join(words)
}

// ---------------------------------------------------------------------------
// Catalog commands

export function catalogSaveCommand(id: string | null, content: CatalogContentDto): string {
  const json = JSON.stringify(content)
  return id
    ? join(['fleetctl', 'skills', 'catalog', 'update', id, '--content-json', json])
    : join(['fleetctl', 'skills', 'catalog', 'create', '--content-json', json])
}

export function catalogPublishCommand(id: string): string {
  return join(['fleetctl', 'skills', 'catalog', 'publish', id])
}

export function catalogRolloutCommand(verb: 'plan' | 'rollout', request: CatalogRolloutRequest): string {
  return join(['fleetctl', 'skills', 'catalog', verb, '--request-json', JSON.stringify(request)])
}

// ---------------------------------------------------------------------------
// Settled operation outcomes

export interface Outcome {
  /** The CLI's or controller's reason code, e.g. `TARGET_CONFLICT`. */
  code: string | null
  detail: string | null
  /** Paths a deployment refused to overwrite. */
  conflicts: string[]
  /** Paths an update kept because the new source no longer ships them. */
  heldBack: string[]
  /** Other paths the CLI reported (e.g. what a dry run would touch). */
  paths: string[]
  /** The CLI's `skills` list, when it reported one (e.g. a remove preview). */
  skills: string[]
}

function parse(json: string | null | undefined): Record<string, unknown> | null {
  if (!json)
    return null
  try {
    const value = JSON.parse(json)
    return value && typeof value === 'object' && !Array.isArray(value) ? value : null
  }
  catch {
    return null
  }
}

/** Collects path strings from a string, a list, or `{ path }` objects (`details.conflicts`). */
function pathList(value: unknown): string[] {
  if (typeof value === 'string')
    return [value]
  if (Array.isArray(value))
    return value.flatMap(pathList)
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>
    if (typeof record.path === 'string')
      return [record.path]
    if (Array.isArray(record.conflicts))
      return pathList(record.conflicts)
    if (Array.isArray(record.paths))
      return pathList(record.paths)
  }
  return []
}

function skillList(value: unknown): string[] {
  if (!Array.isArray(value))
    return []
  return value.flatMap((item) => {
    if (typeof item === 'string')
      return [item]
    const record = item && typeof item === 'object' ? item as Record<string, unknown> : null
    const id = record?.id ?? record?.name ?? record?.skill_id
    return typeof id === 'string' ? [id] : []
  })
}

/**
 * Reads a settled skills operation. Failures carry `{ reason, detail, data }`
 * in `errorJson`; successes carry `{ outcome }` in `resultJson`
 * (fleet-controller `finish_cli` and `safe_cli_outcome`).
 */
export function readOutcome(operation: { errorJson?: string | null, resultJson?: string | null }): Outcome {
  const error = parse(operation.errorJson)
  const result = parse(operation.resultJson)
  const data = (error?.data ?? result?.outcome ?? null) as Record<string, unknown> | null
  const code = (typeof data?.code === 'string' ? data.code : null)
    ?? (typeof error?.reason === 'string' ? error.reason : null)
  const detail = typeof error?.detail === 'string'
    ? error.detail
    : typeof data?.message === 'string' ? data.message : null
  // Skills Manager reports conflicts under `details.conflicts`; the
  // controller currently keeps only `target_conflict`/`targetConflict`.
  const details = code === 'TARGET_CONFLICT' ? pathList(data?.details) : []
  const conflicts = [...new Set([...pathList(data?.targetConflict), ...pathList(data?.target_conflict), ...details])]
  const heldBack = [...new Set([...pathList(data?.heldBackRemovals), ...pathList(data?.held_back_removals)])]
  return { code, detail, conflicts, heldBack, paths: pathList(data?.paths), skills: skillList(data?.skills) }
}

export function isTargetConflict(outcome: Outcome): boolean {
  return outcome.code === 'TARGET_CONFLICT' || outcome.conflicts.length > 0
}
