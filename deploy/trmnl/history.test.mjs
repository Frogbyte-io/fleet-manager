// node --test "deploy/trmnl/*.test.mjs"
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { loadHistory, record, sampleFrom, saveHistory, series, streak, withTrends } from './history.mjs';

const HOUR = 3_600_000;
const NOW = Date.parse('2026-11-06T12:00:00Z');
const at = (hoursAgo, fields = {}) => ({ t: NOW - hoursAgo * HOUR, up: 1, att: 0, mok: 3, srun: 5, lab: 1, ...fields });

test('a sample keeps only the trended numbers', () => {
  const summary = {
    updated_at: new Date(NOW).toISOString(),
    controller: { reachable: true },
    attention_count: 2,
    machines: { total: 5, connected: 3, stale: 1, offline: 0, agentless: 1 },
    services: { total: 4, running: 3, stopped: 1, other: 0 },
    lab: { active: 2 },
  };
  assert.deepEqual(sampleFrom(summary), { t: NOW, up: 1, att: 2, mok: 4, srun: 3, lab: 2 });
  assert.deepEqual(sampleFrom({ ...summary, controller: { reachable: false }, machines: undefined, services: undefined, lab: undefined }),
    { t: NOW, up: 0, att: 2, mok: null, srun: null, lab: null });
});

test('recording drops samples older than a day and samples from the future', () => {
  const history = record([at(30), at(20), at(-1), { t: Number.NaN }], at(0));
  assert.deepEqual(history.map((h) => h.t), [at(20).t, NOW]);
});

test('a series has one value per hour, last sample wins, gaps are null', () => {
  const values = series([at(23.5, { mok: 1 }), at(23.2, { mok: 2 }), at(0.5, { mok: 7 }), at(0.1, { mok: null })], 'mok', NOW);
  assert.equal(values.length, 24);
  assert.equal(values[0], 2);
  assert.equal(values[23], 7); // a null sample does not erase the hour's earlier value
  assert.equal(values.filter((v) => v === null).length, 22);
});

test('the streak measures the current state back to the last change', () => {
  assert.equal(streak([]), null);
  assert.deepEqual(streak([at(10, { att: 3 }), at(6), at(3), at(0)]), { clear: true, hours: 6, since_start: false });
  assert.deepEqual(streak([at(5), at(2, { att: 1 }), at(0, { att: 2 })]), { clear: false, hours: 2, since_start: false });
  // An unreachable controller is not clear, whatever the attention count says.
  assert.deepEqual(streak([at(4), at(1, { up: 0 }), at(0, { up: 0 })]), { clear: false, hours: 1, since_start: false });
  // No change in the history: the hours are a minimum.
  assert.deepEqual(streak([at(20), at(0)]), { clear: true, hours: 20, since_start: true });
});

test('trends, streak and availability are added to the summary', () => {
  const history = [at(20), at(10, { up: 0 }), at(5), at(0)];
  const out = withTrends({ ok: true }, history, NOW);
  assert.equal(out.ok, true);
  assert.equal(out.trends.samples, 4);
  assert.equal(out.availability_pct, 75);
  assert.deepEqual(Object.keys(out.trends), ['samples', 'machines_ok', 'services_running', 'lab_active', 'attention']);
  assert.deepEqual(out.streak, { clear: true, hours: 5, since_start: false });
  assert.equal(withTrends({}, [], NOW).availability_pct, null);
});

test('history survives a round trip and a corrupt file reads as empty', () => {
  const dir = mkdtempSync(join(tmpdir(), 'fleet-trmnl-'));
  try {
    const file = join(dir, 'state', 'history.json');
    assert.deepEqual(loadHistory(file), []);
    saveHistory(file, [at(1), at(0)]);
    assert.deepEqual(loadHistory(file), [at(1), at(0)]);
    assert.equal(statSync(file).mode & 0o777, 0o600);
    writeFileSync(file, '{not json');
    assert.deepEqual(loadHistory(file), []);
    writeFileSync(file, JSON.stringify([at(0), 'junk', { t: 'x' }]));
    assert.deepEqual(loadHistory(file), [at(0)]);
    assert.ok(readFileSync(file, 'utf8'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
