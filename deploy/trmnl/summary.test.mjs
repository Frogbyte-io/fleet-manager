// node --test "deploy/trmnl/*.test.mjs"
import assert from 'node:assert/strict';
import test from 'node:test';
import { summarize, webhookBody } from './summary.mjs';

const NOW = Date.parse('2026-11-06T12:00:00Z');
const HOUR = 3_600_000;
const options = { now: NOW, timeZone: 'UTC' };

const healthy = {
  system: { version: '0.1.0', storageOk: true, queuePending: 0, queueRunning: 1 },
  machines: [
    { name: 'build-01', machineStatus: 'connected' },
    { name: 'runner', machineStatus: 'agentless' },
  ],
  operations: [
    { kind: 'source.fetch', state: 'succeeded', createdAt: NOW - HOUR, updatedAt: NOW - HOUR },
    { kind: 'lab.provision', state: 'running', createdAt: NOW - 30 * HOUR, updatedAt: NOW },
    { kind: 'old.thing', state: 'failed', createdAt: NOW - 48 * HOUR, updatedAt: NOW - 48 * HOUR },
  ],
  leases: [{ state: 'ready' }, { state: 'released' }, { state: 'booting' }],
  services: [{ name: 'web', state: 'running' }, { name: 'tunnel', state: 'unknown' }],
  domains: [{ key: 'example.org', observation: { rdap: { expires: '2027-06-01' } } }],
  drift: [{ machineName: 'runner', counts: { missing: 0, changed: 0, extra: 0, unknown: 2, unsupported: 0 } }],
  requests: [{ state: 'denied' }],
  revision: { active: { commitSha: '2f38ac9e18e48618ce6c82b8d8f7fe2e6a47a7c0' } },
  errors: {},
};

test('a healthy fleet is ok with nothing to check', () => {
  const out = summarize(healthy, options);
  assert.equal(out.ok, true);
  assert.deepEqual(out.attention, []);
  assert.deepEqual(out.machines, { total: 2, connected: 1, stale: 0, offline: 0, agentless: 1 });
  // Running counts are live; finished counts only cover the window.
  const { hourly, ...operations } = out.operations;
  assert.deepEqual(operations, { hours: 24, running: 1, pending: 0, succeeded: 1, failed: 0, cancelled: 0 });
  assert.equal(hourly.bars.length, 24);
  assert.deepEqual(out.lab, { active: 2, ready: 1, cleanup_failed: 0 });
  assert.deepEqual(out.services, { total: 2, running: 1, stopped: 0, other: 1 });
  // Unknown drift is not drift.
  assert.deepEqual(out.drift, { machines: 0, differences: 0 });
  assert.equal(out.revision, '2f38ac9');
  assert.equal(out.updated, '06 Nov, 12:00');
  assert.deepEqual(out.domains.next, [{ name: 'example.org', days: 206, pct: 56 }]);
});

test('operations per hour stack failures on top, oldest hour first', () => {
  const op = (hoursAgo, state) => ({ kind: 'k', state, createdAt: NOW - hoursAgo * HOUR + 1, updatedAt: NOW });
  const out = summarize({
    ...healthy,
    operations: [op(1, 'succeeded'), op(1, 'succeeded'), op(1, 'failed'), op(1, 'failed'), op(23.5, 'succeeded'), op(30, 'failed')],
  }, options);
  const { peak, failed, bars } = out.operations.hourly;
  assert.equal(peak, 4);
  assert.deepEqual(bars[0], { h: 25, f: 0 });   // 23.5 h ago (the oldest hour): 1 of the 4-operation peak
  assert.deepEqual(bars[22], { h: 0, f: 0 });
  assert.deepEqual(bars[23], { h: 100, f: 50 }); // the last hour: half of them failed
  assert.equal(failed.reduce((a, b) => a + b), 2); // the 30 h old failure is outside the window
});

test('the domain runway lists the soonest expiries without names when asked', () => {
  const domains = ['2027-11-06', '2026-11-20', '2026-10-30', '2028-01-01'].map((expires, i) => ({ key: `d${i}.example`, observation: { rdap: { expires } } }));
  assert.deepEqual(summarize({ ...healthy, domains }, options).domains.next, [
    { name: 'd2.example', days: -8, pct: 0 },
    { name: 'd1.example', days: 13, pct: 4 },
    { name: 'd0.example', days: 364, pct: 100 },
  ]);
  assert.deepEqual(summarize({ ...healthy, domains }, { ...options, names: false }).domains.next.map((d) => Object.keys(d)), [['days', 'pct'], ['days', 'pct'], ['days', 'pct']]);
});

test('problems become attention lines in section order', () => {
  const out = summarize({
    ...healthy,
    machines: [...healthy.machines, { name: 'laptop', machineStatus: 'offline' }],
    operations: [{ kind: 'lab.provision', state: 'failed', createdAt: NOW - 3 * HOUR, updatedAt: NOW - 3 * HOUR }],
    services: [{ name: 'storage', state: 'stopped' }],
    domains: [{ key: 'example.org', observation: { rdap: { expires: '2026-11-18' } } }],
    drift: [{ machineName: 'runner', counts: { missing: 1, changed: 2, extra: 0 } }],
    requests: [{ state: 'pending' }, { state: 'pending' }],
    leases: [{ state: 'cleanup_failed' }],
  }, options);
  assert.equal(out.ok, false);
  assert.deepEqual(out.attention, [
    'laptop offline',
    'lab.provision failed 3 h ago',
    '1 lab lease failed cleanup',
    'storage stopped',
    'runner drifted (3)',
    'example.org expires in 11 d',
    '2 action requests awaiting approval',
  ]);
  assert.equal(out.attention_count, 7);
});

test('names can be kept off the screen', () => {
  const out = summarize({
    ...healthy,
    machines: [{ name: 'laptop', machineStatus: 'offline' }],
    services: [{ name: 'storage', state: 'stopped' }],
    domains: [{ key: 'secret.example', observation: { rdap: { expires: '2026-11-01' } } }],
  }, { ...options, names: false });
  assert.deepEqual(out.attention, ['1 machine offline or stale', '1 service stopped', '1 domain expiring']);
  assert.ok(!JSON.stringify(out).includes('laptop'));
  assert.ok(!JSON.stringify(out).includes('secret.example'));
});

test('an unreachable controller says so once', () => {
  const out = summarize({ errors: { system: 'unreachable' } }, options);
  assert.equal(out.ok, false);
  assert.equal(out.controller.reachable, false);
  assert.deepEqual(out.attention, ['Controller unreachable']);
  assert.deepEqual(out.errors, ['system: unreachable']);
  assert.equal(out.machines, undefined);
});

test('a failed section is reported and the rest still render', () => {
  const out = summarize({ ...healthy, services: undefined, errors: { services: 'HTTP 502' } }, options);
  assert.equal(out.services, undefined);
  assert.deepEqual(out.errors, ['services: HTTP 502']);
  assert.equal(out.ok, false);
  assert.ok(out.machines);
});

test('the attention list is capped and long lines are clipped', () => {
  const machines = Array.from({ length: 12 }, (_, i) => ({ name: `machine-${i}-${'x'.repeat(60)}`, machineStatus: 'offline' }));
  const out = summarize({ ...healthy, machines }, options);
  assert.equal(out.attention_count, 12);
  assert.equal(out.attention.length, 9);
  assert.equal(out.attention.at(-1), '+4 more');
  assert.ok(out.attention.every((line) => line.length <= 44));
});

test('the webhook body fits TRMNL and refuses an oversized one', () => {
  const out = summarize(healthy, options);
  assert.deepEqual(JSON.parse(webhookBody(out)), { merge_variables: out });
  assert.throws(() => webhookBody(out, 100), /TRMNL accepts at most 100/);
});
