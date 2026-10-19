import { describe, expect, it } from 'vitest'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

import {
  analyze,
  applyFields,
  buildRunning,
  buildSeconds,
  buildTone,
  latestBuilds,
  latestSucceeded,
  lineage,
  metadataFrom,
  pinState,
  promotionBuild,
  recipeErrors,
  shortDigest,
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
      "disks": [{ "type": "scsi", "storage_pool": "local-lvm", "disk_size": "20G" }],
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
      diskSize: '20G',
      bridge: 'vmbr0',
    })
    expect(analyze(TEMPLATE)).toMatchObject({ diskless: false })
  })

  it('ignores the top-level keys the Packer Proxmox plugin does not have', () => {
    // `packer validate` refuses these, so the view never presents them.
    const invalid = '{"builders":[{"type":"proxmox-iso","node":"p","vm_storage_pool":"a","storage_pool":"a","disk_size":"9G","bridge":"vmbr9"}]}'
    expect(fields(invalid)).toMatchObject({ storagePool: '', diskSize: '', bridge: '' })
  })

  it('reads the ISO from boot_iso, falling back to the deprecated top-level keys', () => {
    expect(fields('{"builders":[{"type":"proxmox-iso","node":"p","boot_iso":{"iso_file":"local:iso/new.iso","iso_storage_pool":"local"},"iso_file":"local:iso/old.iso"}]}'))
      .toMatchObject({ isoFile: 'local:iso/new.iso', isoStoragePool: 'local' })
    expect(fields('{"builders":[{"type":"proxmox-iso","node":"p","iso_file":"local:iso/old.iso"}]}'))
      .toMatchObject({ isoFile: 'local:iso/old.iso' })
  })

  it('marks a clone without disks as inheriting its source storage', () => {
    expect(analyze('{"builders":[{"type":"proxmox-clone","node":"p","clone_vm_id":7000}]}')).toMatchObject({ editable: true, diskless: true })
    expect(analyze('{"builders":[{"type":"proxmox-iso","node":"p"}]}')).toMatchObject({ editable: true, diskless: false })
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
    const edited = applyFields(TEMPLATE, { ...fields(TEMPLATE), cores: 4, node: 'pve-02', diskSize: '40G', bridge: 'vmbr1' })
    const before = JSON.parse(TEMPLATE)
    const after = JSON.parse(edited)
    expect(after.variables).toEqual(before.variables)
    expect(after.provisioners).toEqual(before.provisioners)
    expect(after.builders[0]).toEqual(before.builders[0])
    expect(after.builders[1]).toEqual({
      ...before.builders[1],
      cores: 4,
      node: 'pve-02',
      disks: [{ type: 'scsi', storage_pool: 'local-lvm', disk_size: '40G' }],
      network_adapters: [{ model: 'virtio', bridge: 'vmbr1' }],
    })
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
    expect(builder.disks).toEqual([{ type: 'scsi', disk_size: '20G' }])
  })

  it('keeps the clone key form the template already uses', () => {
    const legacy = '{"builders":[{"type":"proxmox-clone","node":"p","clone_vm_id":8000}]}'
    const edited = JSON.parse(applyFields(legacy, { ...fields(legacy), cloneVm: '8001' })).builders[0]
    expect(edited).toEqual({ type: 'proxmox-clone', node: 'p', clone_vm_id: 8001 })
    // A name replaces the numeric form with Packer's documented `clone_vm`.
    const named = JSON.parse(applyFields(legacy, { ...fields(legacy), cloneVm: 'golden' })).builders[0]
    expect(named).toEqual({ type: 'proxmox-clone', node: 'p', clone_vm: 'golden' })
  })

  it('never adds a disk to a clone implicitly, but gives an ISO build its first disk', () => {
    const clone = '{"builders":[{"type":"proxmox-clone","node":"p","clone_vm_id":8000}]}'
    expect(applyFields(clone, { ...fields(clone), storagePool: 'local-lvm', diskSize: '40G' })).toBe(clone)
    const iso = '{"builders":[{"type":"proxmox-iso","node":"p"}]}'
    const built = JSON.parse(applyFields(iso, { ...fields(iso), storagePool: 'local-lvm', diskSize: '40G' })).builders[0]
    expect(built.disks).toEqual([{ type: 'scsi', storage_pool: 'local-lvm', disk_size: '40G' }])
    expect(built).not.toHaveProperty('vm_storage_pool')
  })

  it('lets an explicit empty boot_iso value win over the deprecated key, as fleet-core does', () => {
    expect(fields('{"builders":[{"type":"proxmox-iso","node":"p","boot_iso":{"iso_file":""},"iso_file":"local:iso/old.iso"}]}'))
      .toMatchObject({ isoFile: '' })
  })

  it('clears a leftover top-level ISO key when the nested shape is in use', () => {
    const both = '{"builders":[{"type":"proxmox-iso","node":"p","boot_iso":{"iso_file":"local:iso/new.iso"},"iso_file":"local:iso/old.iso"}]}'
    const edited = applyFields(both, { ...fields(both), isoFile: '' })
    expect(JSON.parse(edited).builders[0]).toEqual({ type: 'proxmox-iso', node: 'p' })
    expect(fields(edited).isoFile).toBe('')
  })

  it('seeds an empty disk or adapter list', () => {
    const empty = '{"builders":[{"type":"proxmox-iso","node":"p","disks":[],"network_adapters":[]}]}'
    const built = JSON.parse(applyFields(empty, { ...fields(empty), storagePool: 'local-lvm', bridge: 'vmbr0' })).builders[0]
    expect(built.disks).toEqual([{ type: 'scsi', storage_pool: 'local-lvm' }])
    expect(built.network_adapters).toEqual([{ model: 'virtio', bridge: 'vmbr0' }])
  })

  it('writes the ISO into boot_iso unless the template uses the deprecated keys', () => {
    const iso = '{"builders":[{"type":"proxmox-iso","node":"p"}]}'
    expect(JSON.parse(applyFields(iso, { ...fields(iso), isoFile: 'local:iso/u.iso' })).builders[0].boot_iso)
      .toEqual({ iso_file: 'local:iso/u.iso' })
    const deprecated = '{"builders":[{"type":"proxmox-iso","node":"p","iso_file":"local:iso/a.iso"}]}'
    const edited = JSON.parse(applyFields(deprecated, { ...fields(deprecated), isoFile: 'local:iso/b.iso' })).builders[0]
    expect(edited).toEqual({ type: 'proxmox-iso', node: 'p', iso_file: 'local:iso/b.iso' })
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

describe('build records', () => {
  const rec = (id: string, startedAt: number, outcome: string, endedAt: number | null = startedAt + 60_000, template = outcome === 'succeeded') =>
    ({ id, startedAt, endedAt, outcome, template: template ? { name: 'tpl', node: 'pve1', vmid: 9000 } : null })

  it('maps outcomes onto the status vocabulary and leaves unknown words neutral', () => {
    expect(buildTone('running')).toBe('info')
    expect(buildTone('succeeded')).toBe('ok')
    expect(buildTone('failed')).toBe('err')
    expect(buildTone('cancelled')).toBe('muted')
    expect(buildTone('something_new')).toBe('faint')
  })

  it('reports a duration only once the build has ended', () => {
    expect(buildSeconds({ startedAt: 1_000, endedAt: 91_400 })).toBe(90)
    expect(buildSeconds({ startedAt: 1_000, endedAt: null })).toBeNull()
    expect(buildRunning({ outcome: 'running', endedAt: null })).toBe(true)
    expect(buildRunning({ outcome: 'failed', endedAt: 5 })).toBe(false)
  })

  it('truncates digests but keeps the algorithm prefix', () => {
    expect(shortDigest(`sha256:${'ab'.repeat(32)}`)).toBe('sha256:abababababab…')
    expect(shortDigest('cd'.repeat(32), 8)).toBe('cdcdcdcd…')
    expect(shortDigest('sha256:short')).toBe('sha256:short')
  })

  it('finds the build record a promotion stood on', () => {
    const builds = [rec('b3', 300_000, 'running', null), rec('b2', 200_000, 'succeeded'), rec('b1', 100_000, 'failed')]
    expect(promotionBuild({ promotedAt: 290_000 }, builds)).toBe('b2')
    // Only records started before the promotion count; here that is a failure.
    expect(promotionBuild({ promotedAt: 150_000 }, builds)).toBeNull()
    expect(promotionBuild({ promotedAt: null }, builds)).toBeNull()
    // The newest record before the promotion is not a finished success: unknown.
    expect(promotionBuild({ promotedAt: 250_000 }, [rec('b2', 200_000, 'succeeded', 260_000)])).toBeNull()
    expect(promotionBuild({ promotedAt: 250_000 }, [])).toBeNull()
  })

  it('names the newest succeeded build', () => {
    expect(latestSucceeded([rec('b1', 1, 'succeeded'), rec('b3', 3, 'failed'), rec('b2', 2, 'succeeded')])).toBe('b2')
    expect(latestSucceeded([rec('b1', 1, 'failed')])).toBeNull()
  })
})
