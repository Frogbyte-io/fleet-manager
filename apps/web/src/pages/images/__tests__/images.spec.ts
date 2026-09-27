import { describe, expect, it } from 'vitest'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

import {
  analyze,
  applyFields,
  latestBuilds,
  lineage,
  metadataFrom,
  pinState,
  recipeErrors,
  templateOfVersion,
  versionNumbers,
  type StructuredFields,
} from '../images'

const TEMPLATE = `{
  "variables": { "pve_url": "https://pve:8006" },
  "builders": [
    { "type": "docker", "image": "ubuntu" },
    {
      "type": "proxmox-clone",
      "proxmox_url": "{{user \`pve_url\`}}/api2/json",
      "node": "pve-01",
      "clone_vm": "ubuntu-24-cloud",
      "vm_storage_pool": "local-lvm",
      "cores": 2,
      "memory": 4096,
      "template_name": "ubuntu-24-dev",
      "network_adapters": [{ "model": "virtio", "bridge": "vmbr0" }],
      "x_unknown": { "nested": [1, 2, { "deep": true }] }
    }
  ],
  "provisioners": [{ "type": "shell", "inline": ["apt-get update"] }]
}
`

function fields(raw: string): StructuredFields {
  const result = analyze(raw)
  if (!result.editable)
    throw new Error(result.reason)
  return result.fields
}

describe('structured view', () => {
  it('reads the keys fleet-core reads, from the first Proxmox builder', () => {
    expect(fields(TEMPLATE)).toEqual({
      builderType: 'proxmox-clone',
      node: 'pve-01',
      storagePool: 'local-lvm',
      isoFile: '',
      isoStoragePool: '',
      cloneVm: 'ubuntu-24-cloud',
      cores: 2,
      memory: 4096,
      diskSize: '',
      bridge: '',
      cloudInitUser: '',
      sshKeys: '',
    })
  })

  it('offers raw-only editing with a reason when there is no structured view', () => {
    expect(analyze('source "proxmox-iso" "x" {}')).toMatchObject({ editable: false, reason: expect.stringContaining('not JSON') })
    expect(analyze('{"builders":[{"type":"docker"}]}')).toMatchObject({ editable: false, reason: expect.stringContaining('No proxmox') })
    expect(analyze('{"builders":[{"type":"proxmox-iso","node":"p","vmid":12345678901234567890}]}'))
      .toMatchObject({ editable: false, reason: expect.stringContaining('larger than the browser') })
    // fleet-core gives no structured view without a string node.
    expect(analyze('{"builders":[{"type":"proxmox-iso"}]}')).toMatchObject({ editable: false, reason: expect.stringContaining('"node"') })
  })

  it('reads cores and memory only within u32, as fleet-core does', () => {
    expect(fields('{"builders":[{"type":"proxmox-iso","node":"p","cores":4294967296,"memory":4294967295}]}'))
      .toMatchObject({ cores: null, memory: 4294967295 })
  })
})

describe('round-trip', () => {
  it('changes only the edited keys and keeps every unknown field, builder, and provisioner', () => {
    const edited = applyFields(TEMPLATE, { ...fields(TEMPLATE), cores: 4, node: 'pve-02', diskSize: '40G' })
    const before = JSON.parse(TEMPLATE)
    const after = JSON.parse(edited)
    expect(after.variables).toEqual(before.variables)
    expect(after.provisioners).toEqual(before.provisioners)
    expect(after.builders[0]).toEqual(before.builders[0])
    expect(after.builders[1]).toEqual({ ...before.builders[1], cores: 4, node: 'pve-02', disk_size: '40G' })
    // And back: the structured view of the result is what was applied.
    expect(fields(edited)).toMatchObject({ cores: 4, node: 'pve-02', diskSize: '40G', cloneVm: 'ubuntu-24-cloud' })
    expect(edited.endsWith('\n')).toBe(true)
  })

  it('returns the raw text byte for byte when nothing changed', () => {
    expect(applyFields(TEMPLATE, fields(TEMPLATE))).toBe(TEMPLATE)
  })

  it('removes a cleared key', () => {
    const edited = applyFields(TEMPLATE, { ...fields(TEMPLATE), memory: null, storagePool: '' })
    const builder = JSON.parse(edited).builders[1]
    expect(builder).not.toHaveProperty('memory')
    expect(builder).not.toHaveProperty('vm_storage_pool')
  })

  it('keeps the storage-pool and clone keys the template already uses', () => {
    const legacy = '{"builders":[{"type":"proxmox-clone","node":"p","storage_pool":"a","clone_vm_id":8000}]}'
    const edited = JSON.parse(applyFields(legacy, { ...fields(legacy), storagePool: 'b', cloneVm: '8001' })).builders[0]
    expect(edited).toEqual({ type: 'proxmox-clone', node: 'p', storage_pool: 'b', clone_vm_id: 8001 })
    // A name replaces the numeric form with Packer's documented `clone_vm`.
    const named = JSON.parse(applyFields(legacy, { ...fields(legacy), cloneVm: 'golden' })).builders[0]
    expect(named).toEqual({ type: 'proxmox-clone', node: 'p', storage_pool: 'a', clone_vm: 'golden' })
  })

  it('switches the builder type and derives the draft metadata from it', () => {
    const edited = applyFields(TEMPLATE, { ...fields(TEMPLATE), builderType: 'proxmox-iso', isoFile: 'local:iso/u.iso' })
    const view = fields(edited)
    expect(view.builderType).toBe('proxmox-iso')
    expect(metadataFrom(view)).toEqual({ node: 'pve-01', storagePool: 'local-lvm', source: 'iso' })
  })

  it('keeps values the form cannot represent unless that field is edited', () => {
    const odd = '{"builders":[{"type":"proxmox-iso","node":"p","cores":5000000000,"memory":"4096"}]}'
    const view = fields(odd)
    expect(view).toMatchObject({ cores: null, memory: null })
    const edited = JSON.parse(applyFields(odd, { ...view, node: 'q' })).builders[0]
    expect(edited).toEqual({ type: 'proxmox-iso', node: 'q', cores: 5000000000, memory: '4096' })
    // Editing the field itself replaces the value.
    expect(JSON.parse(applyFields(odd, { ...view, cores: 8 })).builders[0].cores).toBe(8)
    // Nothing changed: the raw text is returned byte for byte.
    expect(applyFields(odd, view)).toBe(odd)
  })

  it('leaves raw-only content untouched', () => {
    const hcl = 'source "proxmox-iso" "x" {}'
    expect(applyFields(hcl, fields(TEMPLATE))).toBe(hcl)
  })

  it('mirrors fleet-core metadata validation', () => {
    expect(recipeErrors({ name: '', description: '', node: '', storagePool: 'x', content: '' })).toEqual([
      'the name must be 1..=128 characters',
      'the node must be 1..=128 characters',
      'the recipe content must not be empty',
    ])
  })
})

const input = {
  recipes: [{ id: 'r1' }, { id: 'r2' }],
  versions: [
    { id: 'r1@aaaa', recipeId: 'r1', publishedAt: 1, promotedAt: null },
    { id: 'r1@bbbb', recipeId: 'r1', publishedAt: 2, promotedAt: 5 },
    { id: 'r2@cccc', recipeId: 'r2', publishedAt: 1, promotedAt: null },
  ],
  templates: [
    { id: 't1', imageVersionId: 'r1@bbbb', publishedFrom: 't1@1111' },
    { id: 't2', imageVersionId: 'r1@aaaa', publishedFrom: null },
  ],
  leases: [
    { id: 'l1', templateVersionId: 't1@1111' },
    { id: 'l2', templateVersionId: 't2@2222' },
  ],
}

describe('lineage', () => {
  it('follows a recipe down to its environments', () => {
    const l = lineage(input, { kind: 'recipe', id: 'r1' })
    expect([...l.versions].sort()).toEqual(['r1@aaaa', 'r1@bbbb'])
    expect([...l.templates].sort()).toEqual(['t1', 't2'])
    expect([...l.leases].sort()).toEqual(['l1', 'l2'])
  })

  it('follows a lease up to its recipe', () => {
    const l = lineage(input, { kind: 'lease', id: 'l1' })
    expect([...l.recipes]).toEqual(['r1'])
    expect([...l.versions]).toEqual(['r1@bbbb'])
    expect([...l.templates]).toEqual(['t1'])
    expect([...l.leases]).toEqual(['l1'])
  })

  it('follows a version both ways', () => {
    const l = lineage(input, { kind: 'version', id: 'r1@aaaa' })
    expect([...l.recipes]).toEqual(['r1'])
    expect([...l.templates]).toEqual(['t2'])
    expect([...l.leases]).toEqual(['l2'])
  })

  it('resolves a lease template by publishedFrom or by id prefix', () => {
    expect(templateOfVersion(input.templates, 't1@1111')).toBe('t1')
    expect(templateOfVersion(input.templates, 't2@9999')).toBe('t2')
    expect(templateOfVersion(input.templates, 'gone@1')).toBeNull()
  })
})

describe('pins and builds', () => {
  it('flags stale pins with the reason', () => {
    expect(pinState({ imageVersionId: 'r1@bbbb' }, input.versions)).toEqual({ stale: false })
    expect(pinState({ imageVersionId: 'r1@aaaa' }, input.versions)).toEqual({ stale: true, reason: 'superseded', promotedId: 'r1@bbbb' })
    expect(pinState({ imageVersionId: 'r2@cccc' }, input.versions)).toEqual({ stale: true, reason: 'unpromoted', promotedId: null })
    expect(pinState({ imageVersionId: 'nope' }, input.versions)).toMatchObject({ stale: true, reason: 'unknown' })
  })

  it('numbers versions per recipe, oldest first', () => {
    expect(Object.fromEntries(versionNumbers(input.versions as never))).toEqual({ 'r1@aaaa': 1, 'r1@bbbb': 2, 'r2@cccc': 1 })
  })

  it('attributes builds by result or by this tab, newest first', () => {
    const op = (id: string, createdAt: number, state: string, resultJson: string | null = null) =>
      ({ id, kind: 'image.build', createdAt, state, resultJson }) as OperationDto
    const builds = latestBuilds([
      op('by-result', 1, 'succeeded', '{"artifactId":"9000","recipeVersion":"r1@aaaa"}'),
      op('older-for-b', 1, 'succeeded', '{"artifactId":"8999","recipeVersion":"r1@bbbb"}'),
      op('by-tab', 2, 'running'),
      op('unknown', 4, 'running'),
      { ...op('other', 3, 'succeeded'), kind: 'lab.provision' },
    ], { 'by-tab': 'r1@bbbb' })
    // Attributed through the result's recipeVersion.
    expect(builds.get('r1@aaaa')?.id).toBe('by-result')
    // Attributed through this tab, and newer than the result-attributed build.
    expect(builds.get('r1@bbbb')?.id).toBe('by-tab')
    expect(builds.size).toBe(2)
  })
})
