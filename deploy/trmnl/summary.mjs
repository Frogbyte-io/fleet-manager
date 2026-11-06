// Turns Fleet's public API answers into the small merge-variables object a
// TRMNL webhook plugin renders. Pure: no network, no clock, no environment.

/** TRMNL rejects webhook payloads over 5 KB (10 KB with TRMNL+). */
export const MAX_PAYLOAD_BYTES = 5_000;

const HOUR_MS = 3_600_000;
const DAY_MS = 24 * HOUR_MS;
const ACTIVE_LEASE_STATES = new Set([
  'requested', 'queued', 'reserving', 'provisioning', 'booting', 'bootstrapping', 'ready', 'releasing',
]);
const MAX_ATTENTION = 8;
const MAX_TEXT = 44;

/**
 * @param {object} input       Raw API answers; a section is `undefined` when its request failed.
 * @param {object} input.system            GET /system
 * @param {object[]} [input.machines]      GET /machines items
 * @param {object[]} [input.operations]    GET /operations items (newest 200)
 * @param {object[]} [input.leases]        GET /lab/leases items
 * @param {object[]} [input.services]      GET /services items
 * @param {object[]} [input.domains]       GET /registry/observations items
 * @param {object[]} [input.drift]         GET /desired/drift items
 * @param {object[]} [input.requests]      GET /requests items
 * @param {object}   [input.revision]      GET /desired/revision data
 * @param {Record<string,string>} [input.errors] Section name to failure message.
 * @param {object} options
 * @param {number} options.now             Epoch milliseconds.
 * @param {string} [options.timeZone]      IANA zone for the "updated" label.
 * @param {boolean} [options.names=true]   Put machine, service and domain names on the screen.
 * @param {number} [options.windowHours=24]
 * @param {number} [options.expiryDays=30]
 */
export function summarize(input, options) {
  const { now, timeZone, names = true, windowHours = 24, expiryDays = 30 } = options;
  const errors = { ...(input.errors ?? {}) };
  const attention = [];
  const flag = (text) => attention.push(clip(text));

  const out = {
    updated_at: new Date(now).toISOString(),
    updated: formatTime(now, timeZone),
    controller: { reachable: Boolean(input.system) },
  };

  if (input.system) {
    out.controller.version = input.system.version ?? null;
    out.controller.storage_ok = input.system.storageOk !== false;
    out.controller.queue_pending = input.system.queuePending ?? 0;
    out.controller.queue_running = input.system.queueRunning ?? 0;
    if (!out.controller.storage_ok) flag('Controller storage check failing');
  }

  if (input.machines) {
    const by = countBy(input.machines, (m) => m.machineStatus);
    out.machines = {
      total: input.machines.length,
      connected: by.connected ?? 0,
      stale: by.stale ?? 0,
      offline: by.offline ?? 0,
      agentless: by.agentless ?? 0,
    };
    const down = input.machines.filter((m) => m.machineStatus === 'offline' || m.machineStatus === 'stale');
    if (names) down.forEach((m) => flag(`${m.name} ${m.machineStatus}`));
    else if (down.length) flag(`${plural(down.length, 'machine')} offline or stale`);
  }

  if (input.operations) {
    const since = now - windowHours * HOUR_MS;
    const recent = input.operations.filter((o) => o.createdAt >= since);
    const by = countBy(recent, (o) => o.state);
    const live = countBy(input.operations, (o) => o.state);
    out.operations = {
      hours: windowHours,
      running: live.running ?? 0,
      pending: live.pending ?? 0,
      succeeded: by.succeeded ?? 0,
      failed: by.failed ?? 0,
      cancelled: by.cancelled ?? 0,
    };
    out.operations.hourly = hourly(recent, since, windowHours);
    const failed = recent.filter((o) => o.state === 'failed').sort((a, b) => b.updatedAt - a.updatedAt);
    failed.slice(0, 3).forEach((o) => flag(`${o.kind} failed ${ago(now - (o.updatedAt ?? o.createdAt))}`));
    if (failed.length > 3) flag(`${failed.length - 3} more failed operations`);
  }

  if (input.leases) {
    const by = countBy(input.leases, (l) => l.state);
    out.lab = {
      active: input.leases.filter((l) => ACTIVE_LEASE_STATES.has(l.state)).length,
      ready: by.ready ?? 0,
      cleanup_failed: by.cleanup_failed ?? 0,
    };
    if (out.lab.cleanup_failed) flag(`${plural(out.lab.cleanup_failed, 'lab lease')} failed cleanup`);
  }

  if (input.services) {
    const by = countBy(input.services, (s) => s.state);
    out.services = {
      total: input.services.length,
      running: by.running ?? 0,
      stopped: (by.stopped ?? 0) + (by.exited ?? 0),
      other: input.services.length - (by.running ?? 0) - (by.stopped ?? 0) - (by.exited ?? 0),
    };
    const stopped = input.services.filter((s) => s.state === 'stopped' || s.state === 'exited');
    if (names) stopped.forEach((s) => flag(`${s.name} stopped`));
    else if (stopped.length) flag(`${plural(stopped.length, 'service')} stopped`);
  }

  if (input.drift) {
    const drifting = input.drift.filter((d) => drifted(d.counts) > 0);
    out.drift = { machines: drifting.length, differences: drifting.reduce((n, d) => n + drifted(d.counts), 0) };
    if (names) drifting.forEach((d) => flag(`${d.machineName} drifted (${drifted(d.counts)})`));
    else if (drifting.length) flag(`${plural(drifting.length, 'machine')} drifted`);
  }

  if (input.domains) {
    const expiring = input.domains
      .map((d) => ({ name: d.key, days: daysUntil(d.observation?.rdap?.expires, now) }))
      .filter((d) => d.days !== null && d.days <= expiryDays)
      .sort((a, b) => a.days - b.days);
    const known = input.domains
      .map((d) => ({ name: d.key, days: daysUntil(d.observation?.rdap?.expires, now) }))
      .filter((d) => d.days !== null)
      .sort((a, b) => a.days - b.days)
      .slice(0, 3);
    out.domains = {
      total: input.domains.length,
      expiring: expiring.length,
      // The runway chart: the soonest expiries, as a share of a year.
      next: known.map((d) => ({
        ...(names ? { name: clip(d.name) } : {}),
        days: d.days,
        pct: Math.round((Math.min(Math.max(d.days, 0), 365) / 365) * 100),
      })),
    };
    if (names) expiring.forEach((d) => flag(d.days < 0 ? `${d.name} expired` : `${d.name} expires in ${d.days} d`));
    else if (expiring.length) flag(`${plural(expiring.length, 'domain')} expiring`);
  }

  if (input.requests) {
    const pending = input.requests.filter((r) => r.state === 'pending').length;
    out.requests = { pending };
    if (pending) flag(`${plural(pending, 'action request')} awaiting approval`);
  }

  if (input.revision?.active?.commitSha) out.revision = input.revision.active.commitSha.slice(0, 7);

  if (!out.controller.reachable) {
    attention.unshift(clip('Controller unreachable'));
    // Every other section failed for the same reason; one line says it.
    for (const key of Object.keys(errors)) if (key !== 'system') delete errors[key];
  }

  out.attention_count = attention.length;
  out.attention = attention.slice(0, MAX_ATTENTION);
  if (attention.length > MAX_ATTENTION) out.attention.push(`+${attention.length - MAX_ATTENTION} more`);
  out.errors = Object.entries(errors).map(([section, message]) => clip(`${section}: ${message}`));
  out.ok = out.controller.reachable && attention.length === 0 && out.errors.length === 0;
  return out;
}

/** The webhook body, refusing one TRMNL would reject. */
export function webhookBody(mergeVariables, maxBytes = MAX_PAYLOAD_BYTES) {
  const body = JSON.stringify({ merge_variables: mergeVariables });
  const size = Buffer.byteLength(JSON.stringify(mergeVariables));
  if (size > maxBytes) throw new Error(`merge variables are ${size} bytes; TRMNL accepts at most ${maxBytes}`);
  return body;
}

/** Operations started per bucket across the window, oldest first: 24 buckets. */
function hourly(operations, since, windowHours, buckets = 24) {
  const width = (windowHours * HOUR_MS) / buckets;
  const ok = new Array(buckets).fill(0);
  const failed = new Array(buckets).fill(0);
  for (const o of operations) {
    const i = Math.min(buckets - 1, Math.floor((o.createdAt - since) / width));
    if (i < 0) continue;
    if (o.state === 'failed') failed[i] += 1;
    else ok[i] += 1;
  }
  const peak = Math.max(1, ...ok.map((n, i) => n + failed[i]));
  // Bar heights in percent of the peak, so the template needs no arithmetic on floats.
  const bars = ok.map((n, i) => ({
    h: Math.round(((n + failed[i]) / peak) * 100),
    f: n + failed[i] ? Math.round((failed[i] / (n + failed[i])) * 100) : 0,
  }));
  return { peak, failed, bars };
}

function drifted(counts = {}) {
  return (counts.missing ?? 0) + (counts.changed ?? 0) + (counts.extra ?? 0);
}

function countBy(items, key) {
  const counts = {};
  for (const item of items) {
    const k = key(item);
    counts[k] = (counts[k] ?? 0) + 1;
  }
  return counts;
}

function daysUntil(isoDate, now) {
  if (typeof isoDate !== 'string') return null;
  const at = Date.parse(isoDate);
  return Number.isNaN(at) ? null : Math.floor((at - now) / DAY_MS);
}

function ago(ms) {
  if (ms < HOUR_MS) return `${Math.max(1, Math.round(ms / 60_000))} min ago`;
  if (ms < DAY_MS) return `${Math.round(ms / HOUR_MS)} h ago`;
  return `${Math.round(ms / DAY_MS)} d ago`;
}

function plural(n, noun) {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

function clip(text) {
  return text.length > MAX_TEXT ? `${text.slice(0, MAX_TEXT - 1)}…` : text;
}

function formatTime(now, timeZone) {
  return new Intl.DateTimeFormat('en-GB', {
    timeZone, day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).format(new Date(now));
}
