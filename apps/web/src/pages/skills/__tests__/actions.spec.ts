import { describe, expect, it } from 'vitest'

import { actionCommand, emptyInput, missingField, operationRequest, readOutcome } from '../actions'

const target = { machineId: 'm1', endpointId: 'e1', auth: { type: 'agent' as const } }

describe('operationRequest', () => {
  it('sends remove with explicit confirmation, previewed as a dry run', () => {
    const input = { ...emptyInput('remove'), reference: 'notes', references: ['old'] }
    expect(operationRequest(target, input, true)).toMatchObject({
      machineId: 'm1', endpointId: 'e1', operation: 'remove', reference: 'notes', references: ['old'], confirm: true, dryRun: true,
    })
  })

  it('sends deploy through skillId and direction, not a library operation', () => {
    const body = operationRequest(target, { ...emptyInput('undeploy'), reference: 'fleet', agents: ['codex'] }, false)
    expect(body).toMatchObject({ skillId: 'fleet', agents: ['codex'], direction: 'undeploy', dryRun: false })
    expect(body).not.toHaveProperty('operation')
  })

  it('never confirms or forces anything the operator did not ask for', () => {
    const adopt = operationRequest(target, { ...emptyInput('adopt'), path: '~/.claude/skills/db' }, true)
    expect(adopt).toMatchObject({ operation: 'adopt', path: '~/.claude/skills/db', confirm: false })
    const source = operationRequest(target, { ...emptyInput('set-source'), reference: 's', sourceUrl: 'https://x/y' }, false)
    expect(source).toMatchObject({ operation: 'set-source', force: false })
  })

  it('knows what is missing', () => {
    expect(missingField(emptyInput('remove'))).toBe('a skill to remove')
    expect(missingField({ ...emptyInput('deploy'), reference: 'x' })).toBe('at least one agent')
    expect(missingField(emptyInput('update'))).toBeNull()
    expect(missingField({ ...emptyInput('presets.update'), reference: 'p' })).toBe('a changed name, description, or icon')
  })
})

describe('actionCommand', () => {
  it('matches fleetctl usage', () => {
    expect(actionCommand(target, { ...emptyInput('remove'), reference: 'notes' }, true))
      .toBe('fleetctl skills remove m1 --reference notes --yes --dry-run --endpoint e1 --auth agent --wait')
    expect(actionCommand({ ...target, auth: { type: 'identityFile', path: '~/.ssh/id' } }, { ...emptyInput('deploy'), reference: 'fleet', agents: ['codex'] }, false))
      .toBe('fleetctl skills deploy m1 --skill fleet --agent codex --endpoint e1 --auth identity-file --identity \'~/.ssh/id\' --wait')
    expect(actionCommand(target, { ...emptyInput('presets.delete'), reference: 'p1' }, false))
      .toBe('fleetctl skills preset-delete m1 --reference p1 --yes --endpoint e1 --auth agent')
  })
})

describe('readOutcome', () => {
  it('reads a target conflict from a failed operation', () => {
    const outcome = readOutcome({
      errorJson: JSON.stringify({ reason: 'TARGET_CONFLICT', detail: 'refusing', data: { code: 'TARGET_CONFLICT', target_conflict: { conflicts: [{ path: '/home/me/.claude/skills/db', reason: 'unmanaged' }] } } }),
    })
    expect(outcome.code).toBe('TARGET_CONFLICT')
    expect(outcome.conflicts).toEqual(['/home/me/.claude/skills/db'])
  })

  it('reads held-back removals from a successful update', () => {
    const outcome = readOutcome({ resultJson: JSON.stringify({ outcome: { held_back_removals: ['library: templates/mine.pptx'] } }) })
    expect(outcome.heldBack).toEqual(['library: templates/mine.pptx'])
    expect(outcome.code).toBeNull()
  })

  it('tolerates missing or malformed JSON', () => {
    expect(readOutcome({ errorJson: 'not json' })).toMatchObject({ code: null, conflicts: [], heldBack: [] })
  })
})
