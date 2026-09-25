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
  try {
    localStorage.setItem(RESUME_KEY, JSON.stringify(target))
  }
  catch {
    // Best-effort: the draft is still durable and listed under Resume.
  }
}

export function clearResume(): void {
  try {
    localStorage.removeItem(RESUME_KEY)
  }
  catch {
    // Storage unavailable: nothing was stored either.
  }
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

// The test or discover operation a draft is running, so a reopened dialog
// follows it instead of starting a duplicate probe.
const STAGE_KEY = 'fleet-console-add-stage-operation'

export interface StageOperation {
  stage: 'test' | 'discover'
  id: string
}

export function loadStageOperation(draftId: string): StageOperation | null {
  try {
    const parsed = JSON.parse(localStorage.getItem(STAGE_KEY) ?? 'null') as ({ draftId: string } & StageOperation) | null
    if (parsed && parsed.draftId === draftId && (parsed.stage === 'test' || parsed.stage === 'discover') && typeof parsed.id === 'string')
      return { stage: parsed.stage, id: parsed.id }
  }
  catch {
    // A corrupt entry is treated as absent.
  }
  return null
}

export function saveStageOperation(draftId: string, operation: StageOperation): void {
  try {
    localStorage.setItem(STAGE_KEY, JSON.stringify({ draftId, ...operation }))
  }
  catch {
    // Best-effort: without storage, a reopened dialog just re-reads the draft.
  }
}

export function clearStageOperation(): void {
  try {
    localStorage.removeItem(STAGE_KEY)
  }
  catch {
    // Storage unavailable: nothing was stored either.
  }
}
