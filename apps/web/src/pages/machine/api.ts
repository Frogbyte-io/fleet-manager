// Response helpers shared by the machine page. The generated client resolves
// every HTTP status; these turn a non-success status into a thrown error that
// carries the API's public message.

interface ApiErrorBody {
  code?: string
  message?: string
}

export class ApiRequestError extends Error {
  constructor(readonly status: number, readonly code: string | null, message: string) {
    super(message)
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/** Returns `data.data` when the status is one of `ok`, or throws the API error. */
export function unwrap<T>(response: { status: number, data: unknown }, ok: number[] = [200]): T {
  if (ok.includes(response.status))
    return (response.data as { data: T }).data
  const body = (response.data ?? {}) as ApiErrorBody
  const detail = body.message ?? `request failed (${response.status})`
  throw new ApiRequestError(response.status, body.code ?? null, body.code ? `${body.code}: ${detail}` : detail)
}

/** The operation states that never change again (fleet-core `OperationState`). */
const TERMINAL = new Set(['succeeded', 'failed', 'cancelled', 'timed_out'])

/**
 * Whether an operation has settled. `cancelling` and
 * `blocked_manual_approval` are still live, and so is any state this client
 * does not know yet.
 */
export function isTerminal(state: string): boolean {
  return TERMINAL.has(state)
}

/** Retries only failures a retry can fix: network errors and 5xx answers. */
export function retryTransient(count: number, error: unknown): boolean {
  if (error instanceof ApiRequestError && error.status < 500)
    return false
  return count < 2
}
