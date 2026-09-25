import { describe, expect, it } from 'vitest'

import {
  destructiveCommand,
  frogenvCommand,
  installNodeCommand,
  lifecycleCommand,
  miseCommand,
  observeGuestCommand,
  shellQuote,
  skillsProbeCommand,
} from '../fleetctl'

const guest = { accountId: 'acc1', node: 'pve', vmid: 100 }

describe('shellQuote', () => {
  it('leaves safe words alone and single-quotes the rest', () => {
    expect(shellQuote('m-1_a.b/c:d@e')).toBe('m-1_a.b/c:d@e')
    expect(shellQuote('')).toBe(`''`)
    expect(shellQuote('a b')).toBe(`'a b'`)
    expect(shellQuote(`it's`)).toBe(`'it'\\''s'`)
    expect(shellQuote('$(rm -rf /)')).toBe(`'$(rm -rf /)'`)
  })
})

describe('fleetctl builders', () => {
  it('mirrors the documented install-node usage', () => {
    expect(installNodeCommand('m1', 'e2', { type: 'identityFile', path: '/home/op/.ssh/id' }, 'http://ctl:8080'))
      .toBe('fleetctl machines install-node m1 --endpoint e2 --auth identity-file --identity /home/op/.ssh/id --controller-url http://ctl:8080 --wait --timeout 480')
  })

  it('adds tool and version only for mise install', () => {
    expect(miseCommand('m1', 'status', 'e2', { type: 'agent' })).toBe('fleetctl mise status m1 --endpoint e2 --auth agent --wait')
    expect(miseCommand('m1', 'install', 'e2', { type: 'agent' }, { tool: 'node', version: '22.11.0' }))
      .toBe('fleetctl mise install m1 --tool node --version 22.11.0 --endpoint e2 --auth agent --wait')
  })

  it('builds frogenv and skills probe commands', () => {
    expect(frogenvCommand('m1', 'sync', 'e2', { type: 'agent' })).toBe('fleetctl frogenv sync m1 --endpoint e2 --auth agent --wait')
    expect(skillsProbeCommand('m1', 'e2', { type: 'agent' })).toBe('fleetctl skills probe m1 --endpoint e2 --auth agent --wait')
  })

  it('builds Proxmox guest commands', () => {
    expect(lifecycleCommand('shutdown', guest)).toBe('fleetctl proxmox shutdown --account acc1 --node pve --vmid 100 --wait')
    expect(observeGuestCommand(guest, 'm1')).toBe('fleetctl proxmox observe-guest acc1 100 --machine m1')
  })

  it('pipes destructive parameters on stdin, never in argv', () => {
    expect(destructiveCommand('snapshot', guest, { snapshot: 'pre upgrade', description: `it's` }))
      .toBe(`printf '%s' '{"snapshot":"pre upgrade","description":"it'\\''s"}' | fleetctl proxmox snapshot --account acc1 --node pve --vmid 100 --wait`)
  })
})
