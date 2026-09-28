import { describe, expect, it } from 'vitest'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

import { isTerminal } from '../../machine/api'
import { blockedGuidance, cancellable, filterOperations } from '../operations'

const op = (id: string, kind: string, state: string, createdAt: number) => ({ id, kind, state, createdAt, cancelRequested: false }) as OperationDto

describe('operations helpers', () => {
  const list = [op('a', 'image.build', 'running', 1), op('b', 'mise.install', 'failed', 3), op('c', 'ready.workflow', 'blocked_manual_approval', 2), op('d', 'mise.install', 'timed_out', 4)]

  it('filters by state group, kind, and text, newest first', () => {
    expect(filterOperations(list, { group: 'failed', kind: '', text: '' }).map(o => o.id)).toEqual(['d', 'b'])
    expect(filterOperations(list, { group: 'all', kind: 'mise.install', text: '' }).map(o => o.id)).toEqual(['d', 'b'])
    expect(filterOperations(list, { group: 'blocked', kind: '', text: '' }).map(o => o.id)).toEqual(['c'])
    expect(filterOperations(list, { group: 'all', kind: '', text: 'image' }).map(o => o.id)).toEqual(['a'])
  })

  it('offers cancel only where fleet-core can cancel', () => {
    expect(cancellable({ state: 'running', cancelRequested: false })).toBe(true)
    expect(cancellable({ state: 'pending', cancelRequested: false })).toBe(true)
    expect(cancellable({ state: 'running', cancelRequested: true })).toBe(false)
    expect(cancellable({ state: 'blocked_manual_approval', cancelRequested: false })).toBe(false)
  })

  it('treats blocked_manual_approval as terminal, like fleet-core', () => {
    expect(isTerminal('blocked_manual_approval')).toBe(true)
    expect(isTerminal('cancelling')).toBe(false)
  })

  it('explains what to do about a blocked workflow', () => {
    const ready = blockedGuidance({ kind: 'ready.workflow', errorJson: '{"reason":"blocked_manual_approval","detail":"frogenv request needs approval"}' })
    expect(ready.detail).toBe('frogenv request needs approval')
    expect(ready.steps.join(' ')).toContain('Run Make ready again')
    expect(ready.link).toEqual({ to: '/projects', label: 'Projects' })
    expect(blockedGuidance({ kind: 'apply.workflow', errorJson: null }).steps.join(' ')).toContain('approvals')
    expect(blockedGuidance({ kind: 'frogenv.request', errorJson: 'garbage' }).detail).toBe('A step needs a person to act.')
  })

  it('bases the guidance on what the controller recorded', () => {
    const interactive = blockedGuidance({ kind: 'frogenv.setup', errorJson: JSON.stringify({ detail: 'the setup ceremony did not complete within its deadline; it requires interactive steps Fleet cannot perform — run it on the machine yourself' }) })
    expect(interactive.steps[0]).toContain('interactively on the machine')
    expect(interactive.steps.join(' ')).not.toContain('approved')

    const ready = blockedGuidance({ kind: 'ready.workflow', errorJson: JSON.stringify({ detail: 'the setup ceremony requires manual approval: request 42', blockedAt: 'frogenv_setup', completed: ['clone'], remaining: ['configure Frogenv', 'install node 22'] }) })
    expect(ready.steps[0]).toContain('approved')
    expect(ready).toMatchObject({ blockedAt: 'frogenv_setup', completed: ['clone'], remaining: ['configure Frogenv', 'install node 22'] })
  })
})
