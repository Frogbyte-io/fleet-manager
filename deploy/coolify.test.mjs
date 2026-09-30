import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));

function config(overrides = {}) {
  const env = { ...process.env };
  // Do not depend on a developer's deployment settings or read a real key.
  delete env.FLEET_MASTER_KEY_SOURCE;
  delete env.FLEET_COOLIFY_PORT;
  delete env.FLEET_DATA_VOLUME;
  Object.assign(env, overrides);
  return spawnSync('docker', [
    'compose', '-f', 'deploy/compose.coolify.yaml', 'config', '--format', 'json',
  ], { cwd: root, env, encoding: 'utf8' });
}

function rendered(overrides = {}) {
  const result = config({ FLEET_MASTER_KEY_SOURCE: '/tmp/fleet-test-key', ...overrides });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('a missing master-key source fails before deployment', () => {
  const result = config();
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /FLEET_MASTER_KEY_SOURCE/);
});

test('ingress stays on host loopback, including a custom port', () => {
  for (const overrides of [{}, { FLEET_COOLIFY_PORT: '18080' }]) {
    const service = rendered(overrides).services.controller;
    assert.equal(service.ports.length, 1);
    assert.equal(service.ports[0].host_ip, '127.0.0.1');
    assert.equal(service.ports[0].target, 8080);
    assert.equal(service.ports[0].published, overrides.FLEET_COOLIFY_PORT ?? '8080');
    assert.equal(service.environment.FLEET_TAILSCALE_SERVE_LISTEN, undefined);
    assert.equal(service.labels['coolify.managed'], undefined);
    assert.equal(service.labels['traefik.enable'], 'false');
  }
});

test('SQLite volume has a stable external identity across Compose project names', () => {
  for (const name of ['fleet-manager-data', 'fleet-test-data']) {
    const stack = rendered({ FLEET_DATA_VOLUME: name });
    assert.equal(stack.volumes['fleet-data'].name, name);
    assert.equal(stack.volumes['fleet-data'].external, true);
    assert.equal(stack.services.controller.volumes[0].target, '/var/lib/fleet');
    assert.equal(Object.keys(stack.services).length, 1);
  }
});

test('controller preserves container isolation and worker drain time', () => {
  const service = rendered().services.controller;
  assert.equal(service.read_only, true);
  assert.notEqual(service.privileged, true);
  assert.notEqual(service.network_mode, 'host');
  assert.deepEqual(service.tmpfs, ['/tmp']);
  assert.equal(service.stop_grace_period, '2m30s');
  assert.deepEqual(service.healthcheck.test, ['CMD', 'fleet-controller', 'healthcheck']);
  assert.equal(service.volumes.some((mount) => mount.target.includes('docker.sock')), false);
});

test('master key is a file secret and never a build argument or environment value', () => {
  const stack = rendered();
  const service = stack.services.controller;
  assert.equal(stack.secrets.master_key.file, '/tmp/fleet-test-key');
  assert.equal(service.secrets.length, 1);
  assert.equal(service.secrets[0].source, 'master_key');
  assert.equal(service.secrets[0].target, '/run/secrets/master_key');
  assert.equal(service.environment.FLEET_MASTER_KEY_FILE, '/tmp/fleet-secrets/master_key');
  assert.equal(service.build.args, undefined);
});
