import { describe, expect, it } from 'vitest'

import type { CheckoutFactDto, MachineDto, ReadyPlanDto } from '@frogbyte-io/fleet-api-client'

import {
  blockedDetail,
  buildMatrix,
  dirtyLabel,
  planLines,
} from '../matrix'

const machine = (id: string, name: string): MachineDto =>
  ({
    id,
    name,
    machineStatus: 'connected',
    capabilities: [],
    createdAt: 0,
    updatedAt: 0,
    description: '',
    endpoints: [],
    groups: [],
    tags: [],
  }) as never

const checkout = (machineId: string, branch: string, dirty: boolean): CheckoutFactDto =>
  ({ machineId, branch, dirty, observedAt: 1_000, root: '/srv/x', source: 'agentless/1' })

describe('the checkout matrix', () => {
  it('places every machine in every project row, with honest empty cells', () => {
    const rows = buildMatrix(
      [
        // The checkout list is deliberately ordered opposite to the
        // machines so a position-based match could not pass.
        { id: 'p1', name: 'alpha', checkouts: [checkout('m2', 'feat', true), checkout('m1', 'main', false)] },
        { id: 'p2', name: 'beta', checkouts: [] },
      ],
      [machine('m1', 'homelab'), machine('m2', 'bare-lab')],
    )
    expect(rows).toHaveLength(2)
    expect(rows[0].cells.map((cell) => cell.machineId)).toEqual(['m1', 'm2'])
    expect(rows[0].cells[0]).toMatchObject({ machineId: 'm1', branch: 'main', dirty: false })
    expect(rows[0].cells[1]).toMatchObject({ machineId: 'm2', branch: 'feat', dirty: true })
    expect(rows[1].cells.every((cell) => cell.observedAt === null)).toBe(true)
  })

  it('reads dirty as three states, unknown included', () => {
    expect(dirtyLabel(true)).toBe('dirty')
    expect(dirtyLabel(false)).toBe('clean')
    expect(dirtyLabel(null)).toBe('unknown')
  })

  it('renders the plan in execution order with the note last', () => {
    const plan = {
      machineId: 'm1',
      projectId: 'p1',
      root: '/srv/x',
      note: 'how the executed plan relates to this description',
      steps: [
        { kind: 'clone', when: 'always' },
        { kind: 'verify', when: 'after clone' },
      ],
    } as ReadyPlanDto
    const lines = planLines(plan)
    expect(lines[0]).toContain('m1')
    expect(lines[1]).toBe('clone (always)')
    expect(lines[2]).toBe('verify (after clone)')
    expect(lines.at(-1)).toContain('relates')
  })

  it("extracts a blocked approval's detail from the operation error JSON", () => {
    expect(blockedDetail('{"reason":"blocked_manual_approval","detail":"the frogenv_setup ceremony requires manual approval"}')).toBe(
      'the frogenv_setup ceremony requires manual approval',
    )
    expect(blockedDetail('{"detail":"just a detail"}')).toBe('just a detail')
    // An empty or non-string field cannot suppress the banner silently.
    expect(blockedDetail('{"detail":"","reason":"the reason"}')).toBe('the reason')
    expect(blockedDetail('{"detail":42}')).toBeNull()
    expect(blockedDetail('not json')).toBeNull()
    expect(blockedDetail(null)).toBeNull()
  })
})
