#!/usr/bin/env node
// Prints the `variables:` block of plugin/.trmnlp.yml: a made-up fleet with a
// day of history, run through the real summary and trend code, so the local
// preview shows every chart. No real machine names, hosts or domains.
//
//   node sample.mjs > /tmp/vars.yml   (then replace the block in plugin/.trmnlp.yml)
import { summarize } from './summary.mjs';
import { record, sampleFrom, withTrends } from './history.mjs';

const HOUR = 3_600_000;
const NOW = Date.parse('2026-11-06T10:21:00Z');

// Deterministic noise, so the preview is stable between runs.
let seed = 7;
const rand = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);

function fleetAt(hoursAgo) {
  const offline = hoursAgo < 2 ? ['build-01'] : [];
  const stale = hoursAgo < 5 && hoursAgo > 1 ? ['dev-laptop'] : [];
  const names = ['build-01', 'build-02', 'dev-laptop', 'gpu-box', 'nas', 'pi-kitchen', 'runner-01', 'runner-02', 'win-runner', 'mac-mini', 'ci-arm', 'edge-01', 'edge-02', 'media'];
  const machines = names.map((name, i) => ({
    name,
    machineStatus: offline.includes(name) ? 'offline' : stale.includes(name) ? 'stale' : i > 10 ? 'agentless' : 'connected',
  }));
  // object-storage stopped six hours ago; one service flaps; two never report.
  const services = Array.from({ length: 12 }, (_, i) => ({ name: i === 0 ? 'object-storage' : `service-${i}`, state: 'running' }));
  if (hoursAgo < 6) services[0].state = 'stopped';
  if (hoursAgo % 7 === 3) services[1].state = 'unknown';
  services[10].state = 'unknown';
  services[11].state = 'unknown';
  const leases = Array.from({ length: Math.round(2 + 2 * Math.sin(hoursAgo / 4) + rand()) }, () => ({ state: 'ready' }));
  return { machines, services, leases };
}

const operations = [];
for (let h = 0; h < 24; h += 1) {
  const busy = Math.round(3 + 5 * Math.max(0, Math.sin((h - 6) / 3)) + rand() * 3);
  for (let k = 0; k < busy; k += 1) {
    const at = NOW - h * HOUR - rand() * HOUR;
    const failed = (h === 3 && k < 2) || (h === 15 && k === 0);
    operations.push({ kind: h === 3 ? 'lab.provision' : 'source.fetch', state: failed ? 'failed' : 'succeeded', createdAt: at, updatedAt: at + 60_000 });
  }
}
operations.push({ kind: 'image.build', state: 'running', createdAt: NOW - 600_000, updatedAt: NOW });

const base = {
  system: { version: '0.1.0', storageOk: true, queuePending: 0, queueRunning: 1 },
  operations,
  domains: [
    { key: 'example.org', observation: { rdap: { expires: '2026-11-18' } } },
    { key: 'example.net', observation: { rdap: { expires: '2027-06-15' } } },
    { key: 'example.com', observation: { rdap: { expires: '2027-02-16' } } },
  ],
  drift: [{ machineName: 'gpu-box', counts: { missing: 0, changed: 2, extra: 0 } }],
  requests: [{ state: 'pending' }],
  revision: { active: { commitSha: '2f38ac9e18e48618ce6c82b8d8f7fe2e6a47a7c0' } },
  errors: {},
};

let history = [];
let summary;
for (let h = 24; h >= 0; h -= 1) {
  const t = NOW - h * HOUR;
  summary = summarize({ ...base, ...fleetAt(h), operations: operations.filter((o) => o.createdAt <= t) }, { now: t, timeZone: 'Europe/Oslo' });
  history = record(history, sampleFrom(summary));
}
const variables = withTrends(summary, history, NOW);

// JSON is valid YAML; one flow mapping per top-level key keeps diffs readable.
console.log('variables:');
for (const [key, value] of Object.entries(variables)) console.log(`  ${key}: ${JSON.stringify(value)}`);
