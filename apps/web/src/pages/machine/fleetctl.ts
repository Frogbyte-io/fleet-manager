// Builders for the `fleetctl` command equivalent to each machine-page action.
// Each mirrors the CLI's documented usage (crates/fleetctl `usage()`), so a
// copied command performs the same request the form sends.

export type SshAuth = { type: 'agent' } | { type: 'identityFile', path: string }

/** POSIX single-quote a word when it holds anything beyond a safe set. */
export function shellQuote(word: string): string {
  if (word !== '' && /^[\w@%+=:,./-]+$/.test(word))
    return word
  return `'${word.replace(/'/g, `'\\''`)}'`
}

function join(words: string[]): string {
  return words.map(shellQuote).join(' ')
}

function authFlags(auth: SshAuth): string[] {
  return auth.type === 'agent'
    ? ['--auth', 'agent']
    : ['--auth', 'identity-file', '--identity', auth.path]
}

function endpointFlags(endpointId: string, auth: SshAuth): string[] {
  return ['--endpoint', endpointId, ...authFlags(auth)]
}

export function installNodeCommand(machineId: string, endpointId: string, auth: SshAuth, controllerUrl: string): string {
  // --timeout covers the install deadline plus fleetd's connect wait, so the
  // copied command waits as long as the durable operation can run.
  return join(['fleetctl', 'machines', 'install-node', machineId, ...endpointFlags(endpointId, auth), '--controller-url', controllerUrl, '--wait', '--timeout', '480'])
}

export type MiseAction = 'inventory' | 'status' | 'install'

export function miseCommand(machineId: string, action: MiseAction, endpointId: string, auth: SshAuth, install?: { tool: string, version: string }): string {
  const extra = action === 'install' && install ? ['--tool', install.tool, '--version', install.version] : []
  return join(['fleetctl', 'mise', action, machineId, ...extra, ...endpointFlags(endpointId, auth), '--wait'])
}

export type FrogenvAction = 'status' | 'setup' | 'login' | 'request' | 'sync'

export function frogenvCommand(machineId: string, action: FrogenvAction, endpointId: string, auth: SshAuth): string {
  return join(['fleetctl', 'frogenv', action, machineId, ...endpointFlags(endpointId, auth), '--wait'])
}

export function skillsProbeCommand(machineId: string, endpointId: string, auth: SshAuth): string {
  return join(['fleetctl', 'skills', 'probe', machineId, ...endpointFlags(endpointId, auth), '--wait'])
}

export function projectDiscoverCommand(projectId: string, machineId: string, endpointId: string, auth: SshAuth): string {
  return join(['fleetctl', 'projects', 'discover', projectId, machineId, ...endpointFlags(endpointId, auth), '--wait'])
}

export type LifecycleAction = 'start' | 'stop' | 'shutdown' | 'reboot'
export type DestructiveAction = 'snapshot' | 'snapshot-revert' | 'snapshot-delete' | 'clone' | 'template'

export interface GuestRef {
  accountId: string
  node: string
  vmid: number
}

function guestFlags(guest: GuestRef): string[] {
  return ['--account', guest.accountId, '--node', guest.node, '--vmid', String(guest.vmid)]
}

export function lifecycleCommand(action: LifecycleAction, guest: GuestRef): string {
  return join(['fleetctl', 'proxmox', action, ...guestFlags(guest), '--wait'])
}

/** The CLI reviews and runs in one call; the parameters travel on stdin. */
export function destructiveCommand(action: DestructiveAction, guest: GuestRef, params: Record<string, unknown>): string {
  return `printf '%s' ${shellQuote(JSON.stringify(params))} | ${join(['fleetctl', 'proxmox', action, ...guestFlags(guest), '--wait'])}`
}

export function observeGuestCommand(guest: GuestRef, machineId: string): string {
  return join(['fleetctl', 'proxmox', 'observe-guest', guest.accountId, String(guest.vmid), '--machine', machineId])
}

// Onboarding (`fleetctl machines onboard …`), tailnet import, and Proxmox
// accounts, as the guided Add dialog drives them.

export interface DraftInput {
  user: string
  host: string
  port: number
  name: string
  description?: string
  tags: string[]
  auth: SshAuth
}

export function onboardCreateCommand(input: DraftInput): string {
  return join([
    'fleetctl', 'machines', 'onboard', 'create',
    '--user', input.user,
    '--host', input.host,
    ...(input.port !== 22 ? ['--port', String(input.port)] : []),
    ...(input.name ? ['--name', input.name] : []),
    ...(input.description ? ['--description', input.description] : []),
    ...input.tags.flatMap(tag => ['--tag', tag]),
    ...authFlags(input.auth),
  ])
}

export type DraftStage = 'test' | 'discover' | 'add' | 'cancel'

export function onboardStageCommand(stage: DraftStage, draftId: string): string {
  const wait = stage === 'test' || stage === 'discover' ? ['--wait'] : []
  return join(['fleetctl', 'machines', 'onboard', stage, draftId, ...wait])
}

export function onboardConfirmCommand(draftId: string, fingerprint: string): string {
  return join(['fleetctl', 'machines', 'onboard', 'confirm', draftId, '--fingerprint', fingerprint])
}

export function tailnetImportCommand(nodeId: string, user: string, port: number): string {
  return join(['fleetctl', 'tailnet', 'import', nodeId, '--user', user, ...(port !== 22 ? ['--port', String(port)] : [])])
}

/** The token secret is read from stdin; it never appears in the command. */
export function proxmoxCreateCommand(name: string, host: string, port: number, tokenId: string): string {
  return `${join(['fleetctl', 'proxmox', 'create', '--name', name, '--host', host, ...(port !== 8006 ? ['--port', String(port)] : []), '--token-id', tokenId])}  # token secret on stdin`
}

export function proxmoxAccountCommand(verb: 'observe' | 'discover', accountId: string): string {
  return join(['fleetctl', 'proxmox', verb, accountId])
}

export function proxmoxConfirmCommand(accountId: string, fingerprint: string): string {
  return join(['fleetctl', 'proxmox', 'confirm', accountId, '--fingerprint', fingerprint])
}
