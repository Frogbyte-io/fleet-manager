import { inject, provide, ref, type InjectionKey, type Ref } from 'vue'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

// Operations started from one machine's page. The operations API has no
// machine filter, so the page remembers what it started (per browser tab)
// and the Operations tab follows those ids.

export interface TrackedOperation {
  id: string
  kind: string
  label: string
  startedAt: number
}

export interface MachineOperations {
  operations: Ref<TrackedOperation[]>
  track: (operation: OperationDto, label: string) => void
  forget: (ids: string[]) => void
}

const KEY: InjectionKey<MachineOperations> = Symbol('machine-operations')

export function storageKey(machineId: string): string {
  return `fleet-console-machine-operations:${machineId}`
}

function load(machineId: string): TrackedOperation[] {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(storageKey(machineId)) ?? '[]')
    return Array.isArray(parsed) ? (parsed as TrackedOperation[]) : []
  }
  catch {
    return []
  }
}

export function provideMachineOperations(machineId: string): MachineOperations {
  const operations = ref<TrackedOperation[]>(load(machineId))
  // Storage is best-effort: when it is unavailable or full, tracking stays
  // in memory rather than failing the mutation that already succeeded.
  function persist() {
    try {
      sessionStorage.setItem(storageKey(machineId), JSON.stringify(operations.value))
    }
    catch {
      // Memory-only for this tab.
    }
  }
  function track(operation: OperationDto, label: string) {
    const entry = { id: operation.id, kind: operation.kind, label, startedAt: operation.createdAt }
    operations.value = [entry, ...operations.value.filter(o => o.id !== operation.id)].slice(0, 50)
    persist()
  }
  function forget(ids: string[]) {
    operations.value = operations.value.filter(o => !ids.includes(o.id))
    persist()
  }
  const value = { operations, track, forget }
  provide(KEY, value)
  return value
}

export function useMachineOperations(): MachineOperations {
  const value = inject(KEY)
  if (!value)
    throw new Error('useMachineOperations requires provideMachineOperations')
  return value
}
