// Keeps a day of samples between publisher runs so the screen can draw
// trends. Fleet keeps no history of these numbers itself; this file is the
// publisher's own small state, and losing it only blanks the sparklines.
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const HOUR_MS = 3_600_000;
const KEEP_MS = 25 * HOUR_MS;
const MAX_SAMPLES = 400;
const BUCKETS = 24;

/** The numbers worth trending, taken from one summary. */
export function sampleFrom(summary) {
  const m = summary.machines;
  const s = summary.services;
  return {
    t: Date.parse(summary.updated_at),
    up: summary.controller.reachable ? 1 : 0,
    att: summary.attention_count,
    mok: m ? m.total - m.offline - m.stale : null,
    srun: s ? s.running : null,
    lab: summary.lab ? summary.lab.active : null,
  };
}

/** Appends a sample and drops what is older than a day (plus a margin). */
export function record(history, sample) {
  const kept = history.filter((h) => Number.isFinite(h.t) && h.t > sample.t - KEEP_MS && h.t < sample.t);
  return [...kept, sample].slice(-MAX_SAMPLES);
}

/**
 * One value per hour for the last 24 hours, oldest first: the last sample
 * in each hour, or null for an hour with no sample (the line skips it).
 */
export function series(history, key, now) {
  const start = now - BUCKETS * HOUR_MS;
  const out = new Array(BUCKETS).fill(null);
  for (const h of history) {
    const i = Math.floor((h.t - start) / HOUR_MS);
    if (i >= 0 && i < BUCKETS && h[key] !== null && h[key] !== undefined) out[i] = h[key];
  }
  return out;
}

/**
 * How long the current state (clear, or not) has held. `since_start` means
 * the history does not reach back to a change, so the hours are a minimum.
 */
export function streak(history) {
  if (history.length === 0) return null;
  const clear = (h) => h.up === 1 && h.att === 0;
  const last = history.at(-1);
  const state = clear(last);
  let first = last;
  for (let i = history.length - 1; i >= 0 && clear(history[i]) === state; i -= 1) first = history[i];
  const sinceStart = first === history[0];
  return { clear: state, hours: Math.floor((last.t - first.t) / HOUR_MS), since_start: sinceStart };
}

/** Adds the trend series, streak and controller availability to a summary. */
export function withTrends(summary, history, now) {
  const window = history.filter((h) => h.t > now - BUCKETS * HOUR_MS);
  const reachable = window.filter((h) => h.up === 1).length;
  return {
    ...summary,
    trends: {
      samples: window.length,
      machines_ok: series(history, 'mok', now),
      services_running: series(history, 'srun', now),
      lab_active: series(history, 'lab', now),
      attention: series(history, 'att', now),
    },
    streak: streak(history),
    availability_pct: window.length ? Math.floor((reachable / window.length) * 100) : null,
  };
}

export function loadHistory(file) {
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    return Array.isArray(parsed) ? parsed.filter((h) => h && Number.isFinite(h.t)) : [];
  } catch {
    return [];
  }
}

export function saveHistory(file, history) {
  mkdirSync(dirname(file), { recursive: true });
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, JSON.stringify(history), { mode: 0o600 });
  renameSync(temporary, file);
}
