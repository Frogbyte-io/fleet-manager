// Pure Images pipeline helpers: the structured Proxmox view of a raw
// `.pkr.json` (mirroring fleet-core `StructuredRecipe::from_raw`, so a
// draft and its published version agree), in-place edits that keep every
// unknown field, recipe → version → template → lease lineage, stale pins,
// build attribution, and the `fleetctl images …` equivalents.

import type { LabTemplateDto, LeaseDto, OperationDto, RecipeVersionDto } from '@frogbyte-io/fleet-api-client'

import { shellQuote } from '../machine/fleetctl'

// ---------------------------------------------------------------------------
// Structured ⇄ raw

export type BuilderType = 'proxmox-iso' | 'proxmox-clone'

/** The fields the server's structured view reads, as the form edits them. */
export interface StructuredFields {
  builderType: BuilderType
  node: string
  storagePool: string
  isoFile: string
  isoStoragePool: string
  cloneVm: string
  cores: number | null
  memory: number | null
  diskSize: string
  bridge: string
  cloudInitUser: string
  sshKeys: string
}

export type Analysis =
  | { editable: true, fields: StructuredFields }
  | { editable: false, reason: string }

type Json = null | boolean | number | string | Json[] | { [key: string]: Json }
type JsonObject = { [key: string]: Json }

function isObject(value: Json | undefined): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

/** Whether parsing lost integer precision somewhere (JSON numbers past 2^53). */
function hasUnsafeInteger(value: Json): boolean {
  if (typeof value === 'number')
    return Number.isInteger(value) && !Number.isSafeInteger(value)
  if (Array.isArray(value))
    return value.some(hasUnsafeInteger)
  if (isObject(value))
    return Object.values(value).some(hasUnsafeInteger)
  return false
}

const SUPPORTED: BuilderType[] = ['proxmox-iso', 'proxmox-clone']

function parse(raw: string): { doc: JsonObject, builder: JsonObject } | { reason: string } {
  let doc: Json
  try {
    doc = JSON.parse(raw) as Json
  }
  catch {
    return { reason: 'The content is not JSON (for example a .pkr.hcl template), so only the raw editor applies.' }
  }
  if (!isObject(doc))
    return { reason: 'The template is not a JSON object.' }
  if (hasUnsafeInteger(doc))
    return { reason: 'The template holds integers larger than the browser can represent exactly; editing it structurally would change them, so only the raw editor applies.' }
  const builders = Array.isArray(doc.builders) ? doc.builders : []
  // The first supported builder, as fleet-core `parse_template` chooses it.
  const builder = builders.find((b): b is JsonObject => isObject(b) && SUPPORTED.includes(b.type as BuilderType))
  if (!builder)
    return { reason: 'No proxmox-iso or proxmox-clone builder, so there is no structured view.' }
  // fleet-core offers no structured view without a string `node`.
  if (typeof builder.node !== 'string')
    return { reason: 'The Proxmox builder has no "node" string, so fleet-core offers no structured view; add "node" in the raw template to use the form.' }
  return { doc, builder }
}

function str(value: Json | undefined): string {
  return typeof value === 'string' ? value : ''
}

/** fleet-core reads cores and memory as `u32`; anything outside that is absent. */
const U32_MAX = 0xFFFFFFFF

function count(value: Json | undefined): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= U32_MAX ? value : null
}

/** The structured view of raw content, or why there is none. */
export function analyze(raw: string): Analysis {
  const parsed = parse(raw)
  if ('reason' in parsed)
    return { editable: false, reason: parsed.reason }
  const b = parsed.builder
  const cloneVm = b.clone_vm !== undefined
    ? (typeof b.clone_vm === 'string' ? b.clone_vm : JSON.stringify(b.clone_vm))
    : (count(b.clone_vm_id)?.toString() ?? '')
  return {
    editable: true,
    fields: {
      builderType: b.type as BuilderType,
      node: str(b.node),
      storagePool: str(b.vm_storage_pool) || str(b.storage_pool),
      isoFile: str(b.iso_file),
      isoStoragePool: str(b.iso_storage_pool),
      cloneVm,
      cores: count(b.cores),
      memory: count(b.memory),
      diskSize: str(b.disk_size),
      bridge: str(b.bridge),
      cloudInitUser: str(b.ciuser),
      sshKeys: str(b.sshkeys),
    },
  }
}

/** The indentation the raw text uses, so a rewrite stays close to it. */
function indentOf(raw: string): string | number {
  const match = /\n([ \t]+)\S/.exec(raw)
  if (!match)
    return 2
  return match[1]!.startsWith('\t') ? '\t' : match[1]!.length
}

function setOrDelete(target: JsonObject, key: string, value: Json | undefined) {
  if (value === undefined || value === '' || value === null)
    delete target[key]
  else
    target[key] = value
}

/**
 * Applies structured fields to the raw content in place: only the keys the
 * structured view owns change; every other key, builder, provisioner, and
 * variable is kept. A cleared field removes its key. Returns the raw text
 * unchanged when the content has no structured view.
 */
export function applyFields(raw: string, fields: StructuredFields): string {
  const parsed = parse(raw)
  if ('reason' in parsed)
    return raw
  const b = parsed.builder
  b.type = fields.builderType
  setOrDelete(b, 'node', fields.node.trim())
  // The storage pool keeps whichever key the template already uses.
  const poolKey = b.vm_storage_pool !== undefined || b.storage_pool === undefined ? 'vm_storage_pool' : 'storage_pool'
  setOrDelete(b, poolKey, fields.storagePool.trim())
  setOrDelete(b, 'iso_file', fields.isoFile.trim())
  setOrDelete(b, 'iso_storage_pool', fields.isoStoragePool.trim())
  // Packer's `clone_vm` is a VM name; `clone_vm_id` is the numeric VMID.
  // Keep the form the template uses.
  const clone = fields.cloneVm.trim()
  if (b.clone_vm_id !== undefined && b.clone_vm === undefined && /^\d+$/.test(clone))
    b.clone_vm_id = Number(clone)
  else {
    delete b.clone_vm_id
    setOrDelete(b, 'clone_vm', clone)
  }
  setOrDelete(b, 'cores', fields.cores)
  setOrDelete(b, 'memory', fields.memory)
  setOrDelete(b, 'disk_size', fields.diskSize.trim())
  setOrDelete(b, 'bridge', fields.bridge.trim())
  setOrDelete(b, 'ciuser', fields.cloudInitUser.trim())
  setOrDelete(b, 'sshkeys', fields.sshKeys.trim())
  const out = JSON.stringify(parsed.doc, null, indentOf(raw))
  return raw.endsWith('\n') ? `${out}\n` : out
}

/** The draft metadata a structured builder implies. */
export function metadataFrom(fields: StructuredFields): { node: string, storagePool: string, source: 'iso' | 'clone' } {
  return { node: fields.node.trim(), storagePool: fields.storagePool.trim(), source: fields.builderType === 'proxmox-clone' ? 'clone' : 'iso' }
}

/**
 * fleet-core `RecipeContent::validate`, applied to the request as the editor
 * sends it (name, node, and pool trimmed), so the form refuses early what
 * the controller would refuse. The controller's check stays authoritative.
 */
export function recipeErrors(input: { name: string, description: string, node: string, storagePool: string, content: string }): string[] {
  const errors: string[] = []
  const length = (value: string) => [...value].length
  if (length(input.name.trim()) === 0 || length(input.name) > 128)
    errors.push('the name must be 1..=128 characters')
  if (length(input.description) > 512)
    errors.push('the description must be at most 512 characters')
  if (length(input.node.trim()) === 0 || length(input.node) > 128)
    errors.push('the node must be 1..=128 characters')
  if (length(input.storagePool.trim()) === 0 || length(input.storagePool) > 128)
    errors.push('the storage pool must be 1..=128 characters')
  if (input.content.trim() === '')
    errors.push('the recipe content must not be empty')
  if (new TextEncoder().encode(input.content).length > MAX_RECIPE_BYTES)
    errors.push(`the recipe content is over the ${MAX_RECIPE_BYTES}-byte bound`)
  return errors
}

/** fleet-core `MAX_RECIPE_CONTENT_BYTES`. */
export const MAX_RECIPE_BYTES = 256 * 1024

export const NEW_RECIPE = `{
  "builders": [
    {
      "type": "proxmox-clone",
      "node": "",
      "clone_vm": "",
      "vm_storage_pool": "",
      "cores": 2,
      "memory": 4096
    }
  ],
  "provisioners": []
}
`

// ---------------------------------------------------------------------------
// Lineage

export type NodeKind = 'recipe' | 'version' | 'template' | 'lease'
export interface Selection {
  kind: NodeKind
  id: string
}

export interface PipelineInput {
  recipes: { id: string }[]
  versions: Pick<RecipeVersionDto, 'id' | 'recipeId'>[]
  templates: Pick<LabTemplateDto, 'id' | 'imageVersionId' | 'publishedFrom'>[]
  leases: Pick<LeaseDto, 'id' | 'templateVersionId'>[]
}

export interface Lineage {
  recipes: Set<string>
  versions: Set<string>
  templates: Set<string>
  leases: Set<string>
}

/**
 * The template a lease's template version belongs to. Template version ids
 * are `<template id>@<digest prefix>` (fleet-application `lab.rs`); a
 * template whose `publishedFrom` is exactly this version also matches.
 */
export function templateOfVersion(templates: PipelineInput['templates'], versionId: string): string | null {
  const direct = templates.find(t => t.publishedFrom === versionId)
  if (direct)
    return direct.id
  const prefix = versionId.includes('@') ? versionId.slice(0, versionId.lastIndexOf('@')) : null
  return prefix && templates.some(t => t.id === prefix) ? prefix : null
}

/** Everything upstream and downstream of one selected item. */
export function lineage(input: PipelineInput, selection: Selection | null): Lineage {
  const out: Lineage = { recipes: new Set(), versions: new Set(), templates: new Set(), leases: new Set() }
  if (!selection)
    return out
  const versionRecipe = new Map(input.versions.map(v => [v.id, v.recipeId]))
  const leaseTemplate = new Map(input.leases.map(l => [l.id, templateOfVersion(input.templates, l.templateVersionId)]))

  const down = {
    fromVersions(ids: Set<string>) {
      for (const t of input.templates) {
        if (t.imageVersionId && ids.has(t.imageVersionId))
          out.templates.add(t.id)
      }
      this.fromTemplates(out.templates)
    },
    fromTemplates(ids: Set<string>) {
      for (const [lease, template] of leaseTemplate) {
        if (template && ids.has(template))
          out.leases.add(lease)
      }
    },
  }
  const upFromVersion = (id: string) => {
    out.versions.add(id)
    const recipe = versionRecipe.get(id)
    if (recipe)
      out.recipes.add(recipe)
  }
  const upFromTemplate = (id: string) => {
    out.templates.add(id)
    const pinned = input.templates.find(t => t.id === id)?.imageVersionId
    if (pinned)
      upFromVersion(pinned)
  }

  switch (selection.kind) {
    case 'recipe':
      out.recipes.add(selection.id)
      for (const v of input.versions) {
        if (v.recipeId === selection.id)
          out.versions.add(v.id)
      }
      down.fromVersions(out.versions)
      break
    case 'version':
      upFromVersion(selection.id)
      down.fromVersions(new Set([selection.id]))
      break
    case 'template':
      upFromTemplate(selection.id)
      down.fromTemplates(new Set([selection.id]))
      break
    case 'lease': {
      out.leases.add(selection.id)
      const template = leaseTemplate.get(selection.id)
      if (template)
        upFromTemplate(template)
      break
    }
  }
  return out
}

// ---------------------------------------------------------------------------
// Versions, pins, and builds

/** `v1`, `v2`, … per recipe, oldest first. */
export function versionNumbers(versions: Pick<RecipeVersionDto, 'id' | 'recipeId' | 'publishedAt'>[]): Map<string, number> {
  const out = new Map<string, number>()
  const byRecipe = new Map<string, typeof versions>()
  for (const v of versions)
    byRecipe.set(v.recipeId, [...(byRecipe.get(v.recipeId) ?? []), v])
  for (const list of byRecipe.values()) {
    [...list].sort((a, b) => a.publishedAt - b.publishedAt || a.id.localeCompare(b.id)).forEach((v, i) => out.set(v.id, i + 1))
  }
  return out
}

export type PinState =
  | { stale: false }
  | { stale: true, reason: 'unknown' | 'superseded' | 'unpromoted', promotedId: string | null }

/**
 * Whether a template's pinned image version is the one its recipe currently
 * promotes. At most one version per recipe is promoted (fleet-core
 * `RecipeVersion::promoted_at`), so anything else is stale.
 */
export function pinState(
  template: Pick<LabTemplateDto, 'imageVersionId'>,
  versions: Pick<RecipeVersionDto, 'id' | 'recipeId' | 'promotedAt'>[],
): PinState {
  const pinned = versions.find(v => v.id === template.imageVersionId)
  if (!pinned)
    return { stale: true, reason: 'unknown', promotedId: null }
  if (pinned.promotedAt)
    return { stale: false }
  const promoted = versions.find(v => v.recipeId === pinned.recipeId && v.promotedAt)
  return { stale: true, reason: promoted ? 'superseded' : 'unpromoted', promotedId: promoted?.id ?? null }
}

export interface BuildResult {
  artifactId: string | null
  recipeVersion: string | null
  says: string[]
}

export function buildResult(operation: Pick<OperationDto, 'resultJson'>): BuildResult {
  try {
    const value = JSON.parse(operation.resultJson ?? '') as Record<string, unknown>
    return {
      artifactId: typeof value.artifactId === 'string' ? value.artifactId : null,
      recipeVersion: typeof value.recipeVersion === 'string' ? value.recipeVersion : null,
      says: Array.isArray(value.says) ? value.says.filter((s): s is string => typeof s === 'string') : [],
    }
  }
  catch {
    return { artifactId: null, recipeVersion: null, says: [] }
  }
}

/**
 * The newest `image.build` operation per version. Operations carry no
 * payload, so a build is attributed by the version its result names, or by
 * the builds this browser started (`started`: operation id → version id).
 */
export function latestBuilds(operations: OperationDto[], started: Record<string, string>): Map<string, OperationDto> {
  const out = new Map<string, OperationDto>()
  const newestFirst = [...operations].filter(o => o.kind === 'image.build').sort((a, b) => b.createdAt - a.createdAt)
  for (const operation of newestFirst) {
    const version = started[operation.id] ?? buildResult(operation).recipeVersion
    if (version && !out.has(version))
      out.set(version, operation)
  }
  return out
}

// ---------------------------------------------------------------------------
// fleetctl

function join(words: string[]): string {
  return words.map(shellQuote).join(' ')
}

export function createRecipeCommand(input: { name: string, description: string, node: string, storagePool: string, source: string }): string {
  return `${join(['fleetctl', 'images', 'create', '--name', input.name, '--description', input.description, '--node', input.node, '--storage-pool', input.storagePool, '--source', input.source])} < recipe.pkr.json`
}

export function publishRecipeCommand(recipeId: string): string {
  return join(['fleetctl', 'images', 'publish', recipeId])
}

export function buildCommand(versionId: string): string {
  return join(['fleetctl', 'images', 'build', versionId, '--wait'])
}

export function promoteCommand(versionId: string): string {
  return join(['fleetctl', 'images', 'promote', versionId])
}
