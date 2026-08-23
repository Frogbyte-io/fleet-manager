// test/config.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configFilePath, readConfig, writeConfig, resolveRegistryRoot } from '../src/config.js';

function fakeHome() {
  return mkdtempSync(join(tmpdir(), 'fleet-manager-config-test-'));
}

test('configFilePath uses ~/.config/fleet-manager/config.yaml on linux/darwin', () => {
  const home = fakeHome();
  try {
    const path = configFilePath({ platform: 'linux', env: { HOME: home } });
    assert.equal(path, join(home, '.config', 'fleet-manager', 'config.yaml'));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('configFilePath uses %APPDATA%/fleet-manager/config.yaml on win32', () => {
  const appData = fakeHome();
  try {
    const path = configFilePath({ platform: 'win32', env: { APPDATA: appData } });
    assert.equal(path, join(appData, 'fleet-manager', 'config.yaml'));
  } finally {
    rmSync(appData, { recursive: true, force: true });
  }
});

test('writeConfig then readConfig round-trips registry_path', () => {
  const home = fakeHome();
  try {
    const env = { HOME: home };
    writeConfig({ registry_path: '/some/fleet/clone' }, { platform: 'linux', env });
    const config = readConfig({ platform: 'linux', env });
    assert.equal(config.registry_path, '/some/fleet/clone');
    const raw = readFileSync(configFilePath({ platform: 'linux', env }), 'utf8');
    assert.match(raw, /registry_path: \/some\/fleet\/clone/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('readConfig returns {} when no config file exists yet', () => {
  const home = fakeHome();
  try {
    const config = readConfig({ platform: 'linux', env: { HOME: home } });
    assert.deepEqual(config, {});
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('resolveRegistryRoot prefers --root flag over env var over config file', () => {
  const home = fakeHome();
  try {
    const env = { HOME: home, FLEET_REGISTRY_PATH: '/from/env' };
    writeConfig({ registry_path: '/from/config' }, { platform: 'linux', env });

    const fromFlag = resolveRegistryRoot({ flags: { root: '/from/flag' }, env, platform: 'linux' });
    assert.deepEqual(fromFlag, { root: '/from/flag', source: '--root' });

    const fromEnv = resolveRegistryRoot({ flags: {}, env, platform: 'linux' });
    assert.deepEqual(fromEnv, { root: '/from/env', source: 'FLEET_REGISTRY_PATH' });

    const { FLEET_REGISTRY_PATH, ...envWithoutVar } = env;
    const fromConfig = resolveRegistryRoot({ flags: {}, env: envWithoutVar, platform: 'linux' });
    assert.deepEqual(fromConfig, { root: '/from/config', source: 'config file' });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('resolveRegistryRoot throws a clear error when nothing is configured', () => {
  const home = fakeHome();
  try {
    assert.throws(
      () => resolveRegistryRoot({ flags: {}, env: { HOME: home }, platform: 'linux' }),
      /No registry configured/,
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
