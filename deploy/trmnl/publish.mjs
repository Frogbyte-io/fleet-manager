#!/usr/bin/env node
// Reads Fleet's public API and posts a summary to a TRMNL webhook plugin.
// Read-only against Fleet; one POST to TRMNL per run. Requires Node 24+.
//
//   FLEET_URL=http://127.0.0.1:8080 TRMNL_WEBHOOK_URL_FILE=~/.config/fleet-trmnl/webhook node publish.mjs
//   FLEET_URL=... node publish.mjs --dry-run      # print the merge variables, post nothing
//
// See README.md for every setting.
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { summarize, webhookBody, MAX_PAYLOAD_BYTES } from './summary.mjs';
import { loadHistory, record, sampleFrom, saveHistory, withTrends } from './history.mjs';

const REQUEST_TIMEOUT_MS = 10_000;
const MAX_PAGES = 10;

const { values: flags } = parseArgs({
  options: {
    'dry-run': { type: 'boolean', default: false },
    'fleet-url': { type: 'string' },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

if (flags.help) {
  console.log('usage: publish.mjs [--dry-run] [--fleet-url <url>]  (settings: README.md)');
  process.exit(0);
}

const env = process.env;
const fleetUrl = (flags['fleet-url'] ?? env.FLEET_URL ?? '').replace(/\/+$/, '');
if (!fleetUrl) fail('set FLEET_URL to the controller, for example http://127.0.0.1:8080');
const api = `${fleetUrl}/api/v1`;

const now = Date.now();
const input = await collect();
const summary = summarize(input, {
  now,
  timeZone: env.FLEET_TRMNL_TIME_ZONE || undefined,
  names: env.FLEET_TRMNL_NAMES !== '0',
  windowHours: positiveInt(env.FLEET_TRMNL_WINDOW_HOURS, 24),
  expiryDays: positiveInt(env.FLEET_TRMNL_EXPIRY_DAYS, 30),
});
// Trend history: systemd's StateDirectory, or an explicit file; none means no sparklines.
const historyFile = env.FLEET_TRMNL_STATE_FILE
  || (env.STATE_DIRECTORY ? `${env.STATE_DIRECTORY.split(':')[0]}/history.json` : null);
const history = record(historyFile ? loadHistory(historyFile) : [], sampleFrom(summary));
const mergeVariables = withTrends(summary, history, now);
const body = webhookBody(mergeVariables, positiveInt(env.FLEET_TRMNL_MAX_BYTES, MAX_PAYLOAD_BYTES));

if (flags['dry-run']) {
  console.log(JSON.stringify(mergeVariables, null, 2));
  console.error(`${Buffer.byteLength(JSON.stringify(mergeVariables))} bytes; not posted (--dry-run)`);
  process.exit(0);
}

if (historyFile) {
  try {
    saveHistory(historyFile, history);
  } catch (error) {
    console.error(`fleet-trmnl: cannot save trend history: ${error.code ?? error.message}`);
  }
}

const webhook = webhookUrl();
const response = await fetch(webhook, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body,
  signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
}).catch((error) => fail(`TRMNL webhook request failed: ${error.message}`));
if (!response.ok) {
  // Never echo the URL: it is the only credential for writing to the screen.
  const hint = { 403: ' (the account needs a device with Developer edition)', 422: ' (payload too large)', 429: ' (rate limited: 12 posts/hour, 30 with TRMNL+)' }[response.status] ?? '';
  fail(`TRMNL webhook answered HTTP ${response.status}${hint}`);
}
const failed = Object.keys(input.errors);
console.log(`posted ${mergeVariables.attention_count} attention item(s)${failed.length ? `; unavailable: ${failed.join(', ')}` : ''}`);

async function collect() {
  const errors = {};
  const section = async (name, load) => {
    try {
      return await load();
    } catch (error) {
      errors[name] = error.message;
      return undefined;
    }
  };
  const system = await section('system', () => get('/system'));
  if (!system) return { errors };
  const [machines, operations, leases, services, domains, drift, requests, revision] = await Promise.all([
    section('machines', () => list('/machines')),
    section('operations', async () => (await get('/operations?limit=200')).items),
    section('lab', async () => (await get('/lab/leases')).items),
    section('services', () => list('/services')),
    section('domains', () => list('/registry/observations')),
    section('drift', () => list('/desired/drift')),
    section('requests', async () => (await get('/requests?limit=200')).items),
    section('revision', async () => (await get('/desired/revision')).data),
  ]);
  return { system, machines, operations, leases, services, domains, drift, requests, revision, errors };
}

async function list(path) {
  const items = [];
  let cursor = null;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const query = new URLSearchParams({ limit: '200', ...(cursor ? { cursor } : {}) });
    const answer = await get(`${path}?${query}`);
    items.push(...(answer.items ?? []));
    cursor = answer.page?.nextCursor;
    if (!cursor) break;
  }
  return items;
}

async function get(path) {
  let response;
  try {
    response = await fetch(`${api}${path}`, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    throw new Error(error.name === 'TimeoutError' ? 'timed out' : 'unreachable');
  }
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

function webhookUrl() {
  let value = env.TRMNL_WEBHOOK_URL;
  const file = env.TRMNL_WEBHOOK_URL_FILE
    ?? (env.CREDENTIALS_DIRECTORY ? `${env.CREDENTIALS_DIRECTORY}/trmnl-webhook` : undefined);
  if (!value && file) {
    try {
      value = readFileSync(file, 'utf8');
    } catch (error) {
      fail(`cannot read the TRMNL webhook URL file: ${error.code ?? error.message}`);
    }
  }
  value = value?.trim();
  if (!value) fail('set TRMNL_WEBHOOK_URL_FILE (or TRMNL_WEBHOOK_URL), or pass --dry-run');
  let url;
  try {
    url = new URL(value);
  } catch {
    fail('the TRMNL webhook URL is not a valid URL');
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    fail('the TRMNL webhook URL must use https (plain http only for a local trmnlp preview)');
  }
  return url;
}

function positiveInt(value, fallback) {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

function fail(message) {
  console.error(`fleet-trmnl: ${message}`);
  process.exit(1);
}
