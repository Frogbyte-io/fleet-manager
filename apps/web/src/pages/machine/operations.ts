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
  function track(operation: OperationDto, label: string) {
    const entry = { id: operation.id, kind: operation.kind, label, startedAt: operation.createdAt }
    operations.value = [entry, ...operations.value.filter(o => o.id !== operation.id)].slice(0, 50)
    sessionStorage.setItem(storageKey(machineId), JSON.stringify(operations.value))
  }
  const value = { operations, track }
  provide(KEY, value)
  return value
}

export function useMachineOperations(): MachineOperations {
  const value = inject(KEY)
  if (!value)
    throw new Error('useMachineOperations requires provideMachineOperations')
  return value
}
