const DAY_MS = 86_400_000

/**
 * Whole days from today to a `YYYY-MM-DD` date, or null when it does not parse.
 * Both sides are compared as UTC calendar days (the date has no zone, and the
 * controller works in UTC), so the answer does not shift with the browser's
 * time zone.
 */
export function daysUntil(date: string | null | undefined, now = Date.now()): number | null {
  const match = date ? /^(\d{4})-(\d{2})-(\d{2})$/.exec(date) : null
  if (!match)
    return null
  const at = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]))
  return Math.round((at - Math.floor(now / DAY_MS) * DAY_MS) / DAY_MS)
}
