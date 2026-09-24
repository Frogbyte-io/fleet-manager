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

/** `pending` and `running` are the only non-terminal operation states. */
export function isTerminal(state: string): boolean {
  return state !== 'pending' && state !== 'running'
}
