import { beforeEach, describe, expect, it } from 'vitest'

import type { OnboardingDraftDetailDto } from '@frogbyte-io/fleet-api-client'

import { clearResume, draftStep, loadResume, RESUME_KEY, saveResume } from '../resume'
import { connectHost } from '../tailnet'

function draft(patch: Partial<OnboardingDraftDetailDto>): OnboardingDraftDetailDto {
  return {
    id: 'd1',
    endpoint: { user: 'u', host: 'h', port: 22 },
    auth: { type: 'agent' },
    name: 'h',
    description: '',
    tags: [],
    groups: [],
    stage: 'untested',
    hostKeyStage: 'unseen',
    facts: [],
    duplicates: [],
    createdAt: 0,
    updatedAt: 0,
    ...patch,
  }
}

const hostKey = { keyType: 'ED25519', fingerprint: 'SHA256:x', rawLine: 'h ssh-ed25519 AAAA' }

describe('draftStep', () => {
  it('follows the controller-recorded host-key stage and discovery', () => {
    expect(draftStep(draft({}))).toBe('test')
    expect(draftStep(draft({ hostKeyStage: 'observed', hostKey }))).toBe('verify')
    expect(draftStep(draft({ hostKeyStage: 'changed', hostKey }))).toBe('verify')
    expect(draftStep(draft({ hostKeyStage: 'observed', hostKey: null }))).toBe('test')
    expect(draftStep(draft({ hostKeyStage: 'confirmed' }))).toBe('discover')
    expect(draftStep(draft({ hostKeyStage: 'confirmed', discoveredAt: 1 }))).toBe('finish')
  })
})

describe('resume storage', () => {
  beforeEach(() => localStorage.clear())

  it('round-trips and clears', () => {
    saveResume({ kind: 'proxmox', id: 'acc1' })
    expect(loadResume()).toEqual({ kind: 'proxmox', id: 'acc1' })
    clearResume()
    expect(loadResume()).toBeNull()
  })

  it('treats a corrupt entry as absent', () => {
    localStorage.setItem(RESUME_KEY, '{nope')
    expect(loadResume()).toBeNull()
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'other', id: 'x' }))
    expect(loadResume()).toBeNull()
  })
})

describe('connectHost', () => {
  const device = { name: 'nas-01.example.ts.net.', addresses: ['fd7a:115c::1', '100.101.4.12'] }

  it('picks the MagicDNS name, the Tailscale IPv4, or the entered LAN address', () => {
    expect(connectHost(device, 'magicdns', '')).toBe('nas-01.example.ts.net')
    expect(connectHost(device, 'tailnet-ip', '')).toBe('100.101.4.12')
    expect(connectHost(device, 'lan', ' 192.168.1.40 ')).toBe('192.168.1.40')
    expect(connectHost(device, 'lan', '')).toBeNull()
  })

  it('is null when the device lacks the chosen kind', () => {
    expect(connectHost({ name: 'nas-01', addresses: ['fd7a::1'] }, 'magicdns', '')).toBeNull()
    expect(connectHost({ name: 'nas-01', addresses: ['fd7a::1'] }, 'tailnet-ip', '')).toBeNull()
  })
})
