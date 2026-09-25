/** The Projects page's pure model: the checkout matrix and ready-plan view. */

import type {
  CheckoutFactDto,
  MachineDto,
  ReadyPlanDto,
} from '@frogbyte-io/fleet-api-client'

/** One matrix cell: what is checked out where, and whether it is ready. */
export interface MatrixCell {
  machineId: string
  machineName: string
  branch: string | null
  dirty: boolean | null
  observedAt: number | null
}

export interface MatrixRow {
  projectId: string
  projectName: string
  cells: MatrixCell[]
}

/**
 * The project × machine checkout matrix. Every machine appears in every
 * row; a machine with no observed checkout renders an honest empty cell
 * rather than vanishing from the grid.
 */
export function buildMatrix(
  projects: readonly { id: string; name: string; checkouts: readonly CheckoutFactDto[] }[],
  machines: readonly MachineDto[],
): MatrixRow[] {
  return projects.map((project) => ({
    projectId: project.id,
    projectName: project.name,
    cells: machines.map((machine) => {
      const checkout = project.checkouts.find(
        (candidate) => candidate.machineId === machine.id,
      )
      return {
        machineId: machine.id,
        machineName: machine.name,
        branch: checkout?.branch ?? null,
        dirty: checkout?.dirty ?? null,
        observedAt: checkout?.observedAt ?? null,
      }
    }),
  }))
}

/** The three-state dirty reading: unknown when nothing observed it. */
export function dirtyLabel(dirty: boolean | null): 'dirty' | 'clean' | 'unknown' {
  if (dirty === null) return 'unknown'
  return dirty ? 'dirty' : 'clean'
}

/** A plan step's display text; the kind is an id, the when a condition. */
export function planStepLabel(step: { kind: string; when: string }): string {
  return `${step.kind} (${step.when})`
}

/** The ready plan as human-readable lines, in execution order. */
export function planLines(plan: ReadyPlanDto): string[] {
  return [
    `machine ${plan.machineId} · root ${plan.root}`,
    ...plan.steps.map(planStepLabel),
    plan.note,
  ]
}

/**
 * The blocked state a make-ready run can land in: an explicit state, not
 * an error. The detail comes from the operation's error JSON.
 */
export function blockedDetail(errorJson: string | null | undefined): string | null {
  if (!errorJson) return null
  try {
    const parsed = JSON.parse(errorJson) as { detail?: string; reason?: string }
    return parsed.detail ?? parsed.reason ?? null
  } catch {
    return null
  }
}
