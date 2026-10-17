// The settings model for one Coolify resource (FM-1034): pure functions over
// the generated DTOs, no Vue, so every rule is unit-tested directly. The
// controller decides everything that matters (authorization, the preview, the
// approval, the audit); this file only shapes forms and reads requests.
//
// Environment variable values are write-only. Nothing here reads, stores, or
// formats one: a value lives in a form field until it is sent, and the
// request the controller answers carries names and flags only.

import type {
  ActionRequestDto,
  ServiceEnvBody,
  ServiceEnvChangeBody,
  ServiceEnvVarDto,
  ServiceHealthBody,
  ServiceHealthDto,
} from '@frogbyte-io/fleet-api-client'

import type { Tone } from '../fleet/inventory'
import { stateTone } from '../requests/requests'

/** A lifecycle verb the console can file. */
export type Verb = 'start' | 'stop' | 'restart' | 'redeploy'

export interface VerbView {
  verb: Verb
  label: string
  /** Stop waits for a person and asks first. */
  confirm: boolean
}

const VERBS: VerbView[] = [
  { verb: 'start', label: 'Start', confirm: false },
  { verb: 'stop', label: 'Stop', confirm: true },
  { verb: 'restart', label: 'Restart', confirm: false },
  { verb: 'redeploy', label: 'Redeploy', confirm: false },
]

/**
 * The lifecycle actions a resource offers. Only a Coolify resource has any
 * (a Docker container is observed, not managed here), and only an
 * application can be redeployed (FM-1033).
 */
export function lifecycleVerbs(kind: string, isCoolify: boolean): VerbView[] {
  if (!isCoolify || !['application', 'service', 'database'].includes(kind))
    return []
  return VERBS.filter(v => v.verb !== 'redeploy' || kind === 'application')
}

/** What a request's state means to the person who filed it. */
export function requestOutcome(request: Pick<ActionRequestDto, 'state' | 'riskClass' | 'failure'>, kind: 'lifecycle' | 'settings' = 'settings'): { label: string, tone: Tone, text: string } {
  const tone = stateTone(request.state)
  switch (request.state) {
    case 'pending': return { label: 'pending', tone, text: 'Waiting for a person to approve it in Approvals. Nothing has changed yet.' }
    case 'approved':
    case 'executing': return { label: request.state, tone, text: 'Approved. Fleet is carrying it out.' }
    case 'succeeded': return { label: 'succeeded', tone, text: kind === 'lifecycle' ? 'Done. Fleet carried it out and read the status back from Coolify.' : 'Done. Coolify accepted the change and Fleet read it back.' }
    case 'failed': return { label: 'failed', tone, text: request.failure ?? 'The change did not complete.' }
    case 'denied': return { label: 'denied', tone, text: 'A person denied the request. Nothing changed.' }
    case 'expired': return { label: 'expired', tone, text: 'Nobody decided in time. Nothing changed.' }
    default: return { label: request.state, tone, text: '' }
  }
}

/** Whether a request will never change again. */
export function requestTerminal(state: string): boolean {
  return ['denied', 'expired', 'succeeded', 'failed'].includes(state)
}

/** Which settings a resource offers: variables for an application or service, domains and health for an application. */
export function settingsFor(kind: string, isCoolify: boolean): { env: boolean, domains: boolean, health: boolean } {
  if (!isCoolify)
    return { env: false, domains: false, health: false }
  return {
    env: kind === 'application' || kind === 'service',
    domains: kind === 'application',
    health: kind === 'application',
  }
}

const FLAG_LABELS: [keyof ServiceEnvVarDto, string][] = [
  ['isBuildtime', 'build'],
  ['isRuntime', 'runtime'],
  ['isLiteral', 'literal'],
  ['isMultiline', 'multiline'],
  ['isShownOnce', 'hidden after save'],
  ['isPreview', 'preview'],
  ['isShared', 'shared'],
]

/** The flags that are on, as short words. */
export function envFlagLabels(env: ServiceEnvVarDto, kind: string): string[] {
  return FLAG_LABELS
    // A service's variables have no build or runtime scope.
    .filter(([name]) => kind === 'application' || (name !== 'isBuildtime' && name !== 'isRuntime'))
    .filter(([name]) => env[name] === true)
    .map(([, label]) => label)
}

/** A Coolify variable name: letters, digits, `_` and `.`, not starting with a digit. */
export const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_.]*$/
export const MAX_ENV_KEY = 128
export const MAX_ENV_VALUE = 16 * 1024

export interface EnvForm {
  key: string
  /** Typed by the person; never prefilled, never kept after sending. */
  value: string
  preview: boolean
  buildtime: boolean
  runtime: boolean
  literal: boolean
  multiline: boolean
  shownOnce: boolean
  redeploy: boolean
  reason: string
}

/** A blank form: Coolify's own defaults for a new variable. */
export function blankEnvForm(): EnvForm {
  return { key: '', value: '', preview: false, buildtime: true, runtime: true, literal: false, multiline: false, shownOnce: false, redeploy: false, reason: '' }
}

/** The variable a (key, preview) pair names, if it exists. */
export function findEnv(envs: ServiceEnvVarDto[], key: string, preview: boolean): ServiceEnvVarDto | undefined {
  return envs.find(env => env.key === key && env.isPreview === preview)
}

/**
 * The form with the flags of the variable it names, so a changed value keeps
 * the flags it had. Only flags are copied: there is no current value to copy,
 * and what the person already typed stays as it is.
 */
export function withCurrentFlags(form: EnvForm, envs: ServiceEnvVarDto[]): EnvForm {
  const current = findEnv(envs, form.key, form.preview)
  if (!current)
    return form
  return { ...form, buildtime: current.isBuildtime, runtime: current.isRuntime, literal: current.isLiteral, multiline: current.isMultiline, shownOnce: current.isShownOnce }
}

/** Why a form cannot be sent yet, or null. */
export function envFormProblem(form: EnvForm): string | null {
  if (!form.key)
    return 'Name the variable.'
  if (form.key.length > MAX_ENV_KEY || !ENV_KEY.test(form.key))
    return 'A name is letters, digits, "_" and ".", and does not start with a digit.'
  if (new TextEncoder().encode(form.value).length > MAX_ENV_VALUE)
    return 'A value is at most 16 KiB.'
  if (form.value.includes('\u0000'))
    return 'A value cannot contain a NUL character.'
  return null
}

/** The request body of a `set`. The value is in the body and nowhere else. */
export function envSetBody(form: EnvForm, kind: string): ServiceEnvBody {
  const change: ServiceEnvChangeBody = {
    op: 'set',
    key: form.key,
    value: form.value,
    isLiteral: form.literal,
    isMultiline: form.multiline,
    isShownOnce: form.shownOnce,
  }
  if (kind === 'application') {
    change.isPreview = form.preview
    change.isBuildtime = form.buildtime
    change.isRuntime = form.runtime
  }
  return { changes: [change], redeploy: form.redeploy, reason: form.reason.trim() }
}

/** The request body of an `unset`. */
export function envUnsetBody(env: ServiceEnvVarDto, redeploy: boolean, reason: string): ServiceEnvBody {
  return { changes: [{ op: 'unset', key: env.key, isPreview: env.isPreview }], redeploy, reason: reason.trim() }
}

/** Domains as one per line. */
export function domainsText(domains: string[]): string {
  return domains.join('\n')
}

/** The domain list a textarea holds: one URL per line, blanks dropped, commas also separate. */
export function parseDomains(text: string): string[] {
  return text.split(/[\n,]/).map(line => line.trim()).filter(line => line !== '')
}

/** Why a domain list cannot be sent, or null. The controller normalizes and has the last word. */
export function domainsProblem(list: string[], current: string[]): string | null {
  if (list.length > 12)
    return 'At most 12 domains.'
  for (const domain of list) {
    if (!/^https?:\/\//i.test(domain))
      return `"${domain}" must start with http:// or https://.`
    if (/@/.test(domain.slice(0, domain.indexOf('/', 8) < 0 ? undefined : domain.indexOf('/', 8))))
      return 'A domain must not carry credentials.'
  }
  if (new Set(list.map(d => d.toLowerCase())).size !== list.length)
    return 'A domain is listed twice.'
  if (sameList(list.map(d => d.toLowerCase()), current.map(d => d.toLowerCase())))
    return 'The domains already match.'
  return null
}

function sameList(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i])
}

export const HEALTH_METHODS = ['GET', 'HEAD', 'POST', 'OPTIONS'] as const
export const HEALTH_SCHEMES = ['http', 'https'] as const

/** Whether Fleet edits this health check: only the HTTP kind. */
export function healthEditable(health: ServiceHealthDto): boolean {
  return health.checkType === 'http'
}

export interface HealthForm {
  enabled: boolean
  path: string
  port: string
  host: string
  method: string
  scheme: string
  returnCode: string
  responseText: string
  interval: string
  timeout: string
  retries: string
  startPeriod: string
  redeploy: boolean
  reason: string
}

/** The form as the application has it now. */
export function healthForm(health: ServiceHealthDto): HealthForm {
  return {
    enabled: health.enabled,
    path: health.path,
    port: health.port == null ? '' : String(health.port),
    host: health.host ?? '',
    method: health.method,
    scheme: health.scheme,
    returnCode: String(health.returnCode),
    responseText: health.responseText ?? '',
    interval: String(health.interval),
    timeout: String(health.timeout),
    retries: String(health.retries),
    startPeriod: String(health.startPeriod),
    redeploy: false,
    reason: '',
  }
}

type HealthPatch = Pick<ServiceHealthBody, 'enabled' | 'path' | 'port' | 'host' | 'method' | 'scheme' | 'returnCode' | 'responseText' | 'interval' | 'timeout' | 'retries' | 'startPeriod' | 'clear'>

function whole(text: string): number | null {
  return /^\d+$/.test(text.trim()) ? Number(text.trim()) : null
}

/**
 * The fields that differ from `current`, or an error naming the first bad
 * field. Only changed fields are sent, so the request names exactly what the
 * person edited.
 */
export function healthPatch(form: HealthForm, current: ServiceHealthDto): { patch: HealthPatch } | { error: string } {
  const patch: HealthPatch = {}
  if (form.enabled !== current.enabled)
    patch.enabled = form.enabled
  if (form.path !== current.path) {
    if (!/^\/[A-Za-z0-9/\-_.~%,;]*$/.test(form.path) || form.path.length > 256)
      return { error: 'The path starts with "/" and uses letters, digits and /-_.~%,;' }
    patch.path = form.path
  }
  const clear: string[] = []
  const port = form.port.trim()
  if (port !== (current.port == null ? '' : String(current.port))) {
    if (port === '') {
      clear.push('port')
    }
    else {
      const n = whole(port)
      if (n === null || n < 1 || n > 65535)
        return { error: 'The port is 1 to 65535, or blank to use the application\'s own.' }
      patch.port = n
    }
  }
  if (form.host.trim() !== (current.host ?? '')) {
    if (form.host.trim() === '') {
      clear.push('host')
    }
    else if (!/^[A-Za-z0-9._-]+$/.test(form.host.trim())) {
      return { error: 'The host is a plain host name (letters, digits, "-", "_" and ".").' }
    }
    else {
      patch.host = form.host.trim()
    }
  }
  if (form.method !== current.method)
    patch.method = form.method
  if (form.scheme !== current.scheme)
    patch.scheme = form.scheme
  const code = whole(form.returnCode)
  if (code === null || code < 100 || code > 599)
    return { error: 'The healthy status code is 100 to 599.' }
  if (code !== current.returnCode)
    patch.returnCode = code
  if (form.responseText !== (current.responseText ?? '')) {
    if (form.responseText === '') {
      clear.push('responseText')
    }
    else if (form.responseText.length > 256) {
      return { error: 'The response text is at most 256 characters.' }
    }
    else {
      patch.responseText = form.responseText
    }
  }
  for (const [name, text, min, max, now] of [
    ['interval', form.interval, 1, 3600, current.interval],
    ['timeout', form.timeout, 1, 3600, current.timeout],
    ['retries', form.retries, 1, 100, current.retries],
    ['startPeriod', form.startPeriod, 0, 3600, current.startPeriod],
  ] as const) {
    const n = whole(text)
    if (n === null || n < min || n > max)
      return { error: `${name === 'startPeriod' ? 'The start period' : `The ${name}`} is ${min} to ${max}.` }
    if (n !== now)
      patch[name] = n
  }
  if (clear.length > 0)
    patch.clear = clear
  if (Object.keys(patch).length === 0)
    return { error: 'Nothing differs from the current health check.' }
  return { patch }
}

interface PreviewField { field?: string, from?: unknown, to?: unknown }

function show(value: unknown): string {
  if (value === null || value === undefined)
    return '—'
  if (Array.isArray(value))
    return value.length === 0 ? '(none)' : value.map(show).join(', ')
  return typeof value === 'string' ? value : JSON.stringify(value)
}

/**
 * The preview an approver and the requester read, as plain lines. Variables
 * show their name and flag changes (a written value is "write-only"); the
 * domains and the health check show before and after.
 */
export function previewLines(parameters: unknown): string[] {
  const params = (parameters ?? {}) as { preview?: unknown, redeploy?: boolean }
  const lines: string[] = []
  const preview = params.preview
  if (Array.isArray(preview)) {
    for (const entry of preview as { operation?: string, key?: string, isPreview?: boolean, changes?: PreviewField[] }[]) {
      const flags = (entry.changes ?? [])
        .filter(change => change.field !== 'value' && entry.operation !== 'create')
        .map(change => `${change.field}: ${show(change.from)} → ${show(change.to)}`)
      const writes = (entry.changes ?? []).some(change => change.field === 'value')
      const suffix = [writes ? 'value write-only' : '', ...flags].filter(Boolean).join('; ')
      lines.push(`${entry.operation ?? 'change'} ${entry.key ?? '?'}${entry.isPreview ? ' (preview)' : ''}${suffix ? ` [${suffix}]` : ''}`)
    }
  }
  else if (preview && typeof preview === 'object') {
    for (const change of ((preview as { changes?: PreviewField[] }).changes ?? []))
      lines.push(`${change.field ?? '?'}: ${show(change.from)} → ${show(change.to)}`)
  }
  if (params.redeploy)
    lines.push('then redeploy (restart for a service)')
  return lines
}
