// Exercises the Coolify stack with a temporary key and its own external volume.
// Requires Node 24+, Docker Compose, and a running Linux Docker engine.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';

const root = fileURLToPath(new URL('../', import.meta.url));
const project = `fleet-coolify-smoke-${randomUUID().slice(0, 8)}`;
const volume = `${project}-data`;
const temporary = mkdtempSync(join(tmpdir(), 'fleet-coolify-smoke-'));
const keyPath = join(temporary, 'master_key');
const overridePath = join(temporary, 'override.json');
const image = process.env.FLEET_SMOKE_IMAGE;
const env = {
  ...process.env,
  FLEET_MASTER_KEY_SOURCE: keyPath,
  FLEET_DATA_VOLUME: volume,
  FLEET_COOLIFY_PORT: '0',
};
const composeArgs = ['compose', '-p', project, '-f', join(root, 'deploy/compose.coolify.yaml')];
let volumeCreated = false;

function docker(args, options = {}) {
  const result = spawnSync('docker', args, {
    cwd: root, env, encoding: 'utf8', timeout: 180_000, ...options,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message || 'Docker command failed');
  if (args[0] === 'logs') return ((result.stdout ?? '') + (result.stderr ?? '')).trim();
  return result.stdout?.trim() ?? '';
}

function compose(...args) {
  return docker([...composeArgs, ...args]);
}

async function healthy() {
  for (let attempt = 0; attempt < 90; attempt++) {
    const id = compose('ps', '-a', '-q', 'controller');
    if (id) {
      const info = JSON.parse(docker(['inspect', id]))[0];
      if (info.State.Health?.Status === 'healthy') return info;
      assert.notEqual(info.State.Status, 'exited', 'Controller exited before readiness');
    }
    await sleep(2000);
  }
  throw new Error('Controller did not become healthy within 180 seconds');
}

function baseUrl(info) {
  const binding = info.NetworkSettings.Ports['8080/tcp'][0];
  assert.equal(binding.HostIp, '127.0.0.1');
  return `http://127.0.0.1:${binding.HostPort}`;
}

async function request(base, path, options = {}) {
  const response = await fetch(base + path, { signal: AbortSignal.timeout(10_000), ...options });
  assert.equal(response.ok, true, `HTTP ${response.status} for ${path}`);
  return response;
}

function stopAndCheck(id) {
  compose('stop', 'controller');
  const info = JSON.parse(docker(['inspect', id]))[0];
  assert.equal(info.State.ExitCode, 0);
  assert.match(docker(['logs', id]), /stopped gracefully/);
}

try {
  writeFileSync(keyPath, `1 ${randomBytes(32).toString('hex')}\n`, { mode: 0o600 });
  if (image) {
    writeFileSync(overridePath, JSON.stringify({ services: { controller: { image } } }));
    composeArgs.push('-f', overridePath);
  } else {
    console.log('Building the controller image');
    docker([...composeArgs, 'build'], { stdio: 'inherit', timeout: 1_800_000 });
  }
  docker(['volume', 'create', volume]);
  volumeCreated = true;
  console.log('Starting the isolated Coolify stack');
  compose('up', '-d', '--no-build');
  const info = await healthy();
  const base = baseUrl(info);
  assert.equal(info.HostConfig.ReadonlyRootfs, true);
  assert.equal(info.HostConfig.Privileged, false);
  assert.notEqual(info.HostConfig.NetworkMode, 'host');
  assert.equal(info.Mounts.some((mount) => mount.Destination.includes('docker.sock')), false);
  assert.match(docker(['exec', info.Id, 'cat', '/proc/1/status']), /Uid:\s+999\s+999\s+999\s+999/);
  assert.equal((await (await request(base, '/readyz')).text()).trim(), 'ok');
  assert.match(await (await request(base, '/')).text(), /Fleet Manager/);
  assert.equal((await (await request(base, '/api/v1/meta')).json()).data.service, 'fleet-controller');
  const sseAbort = new AbortController();
  try {
    const events = await request(base, '/api/v1/events', { signal: sseAbort.signal });
    assert.match(events.headers.get('content-type'), /text\/event-stream/);
    await events.body.cancel();
  } finally {
    sseAbort.abort();
  }
  const archive = docker(['exec', info.Id, 'find', '/var/lib/fleet/artifacts/fleetd',
    '-maxdepth', '1', '-name', 'fleetd-*.tar.gz']).split('\n')[0];
  assert.match(archive, /^\/var\/lib\/fleet\/artifacts\/fleetd\/fleetd-[\w.-]+\.tar\.gz$/);
  for (const script of ['install.sh', 'uninstall.sh']) {
    const content = docker(['exec', info.Id, 'tar', '-xOzf', archive, script]);
    assert.equal(content.includes('\r'), false, `${script} must use Linux line endings`);
  }
  const download = await request(base, `/downloads/fleetd/${archive.split('/').at(-1)}`);
  assert.ok((await download.arrayBuffer()).byteLength > 0);
  const draft = (await (await request(base, '/api/v1/machines/onboarding/drafts', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user: 'smoke', host: 'smoke.invalid', auth: { type: 'agent' }, name: project }),
  })).json()).data;
  assert.ok(draft.id);
  console.log('Web, API, SSE, installer downloads, isolation, and non-root process verified');
  stopAndCheck(info.Id);
  compose('up', '-d', '--no-build', '--force-recreate');
  const recreated = await healthy();
  const persisted = (await (await request(baseUrl(recreated),
    `/api/v1/machines/onboarding/drafts/${draft.id}`)).json()).data;
  assert.equal(persisted.name, project);
  stopAndCheck(recreated.Id);
  console.log('Coolify smoke passed: persistent records and graceful shutdown across recreation');
} finally {
  // These names are generated by this run; production storage is never selected.
  spawnSync('docker', [...composeArgs, 'down', '--remove-orphans'], { cwd: root, env, timeout: 180_000 });
  if (volumeCreated) spawnSync('docker', ['volume', 'rm', volume], { timeout: 30_000 });
  rmSync(keyPath, { force: true });
  rmSync(overridePath, { force: true });
  rmdirSync(temporary);
}
