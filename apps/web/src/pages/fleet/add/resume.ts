import type { OnboardingDraftDetailDto } from '@frogbyte-io/fleet-api-client'

// The Add dialog's durable state lives in the controller (onboarding drafts,
// unconfirmed Proxmox accounts). The browser only remembers which one the
// dialog was showing, so closing and reopening lands on the same step.

export type Source = 'tailscale' | 'ssh' | 'proxmox' | 'guest'

export type ResumeTarget =
  | { kind: 'draft', id: string }
  | { kind: 'proxmox', id: string }

export const RESUME_KEY = 'fleet-console-add-resume'

export function loadResume(): ResumeTarget | null {
  try {
    const parsed = JSON.parse(localStorage.getItem(RESUME_KEY) ?? 'null') as ResumeTarget | null
    if (parsed && (parsed.kind === 'draft' || parsed.kind === 'proxmox') && typeof parsed.id === 'string')
      return parsed
  }
  catch {
    // A corrupt entry is treated as absent.
  }
  return null
}

export function saveResume(target: ResumeTarget): void {
  localStorage.setItem(RESUME_KEY, JSON.stringify(target))
}

export function clearResume(): void {
  localStorage.removeItem(RESUME_KEY)
}

export type DraftStep = 'test' | 'verify' | 'discover' | 'finish'

/** Where a draft's flow stands, derived from what the controller recorded. */
export function draftStep(draft: OnboardingDraftDetailDto): DraftStep {
  if (draft.hostKeyStage === 'confirmed')
    return draft.discoveredAt ? 'finish' : 'discover'
  if ((draft.hostKeyStage === 'observed' || draft.hostKeyStage === 'changed') && draft.hostKey)
    return 'verify'
  return 'test'
}
