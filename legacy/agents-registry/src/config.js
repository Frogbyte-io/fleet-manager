// src/config.js
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

export function configFilePath({ platform = process.platform, env = process.env } = {}) {
  if (platform === 'win32') {
    return join(env.APPDATA, 'fleet-manager', 'config.yaml');
  }
  return join(env.HOME, '.config', 'fleet-manager', 'config.yaml');
}

export function readConfig({ platform = process.platform, env = process.env } = {}) {
  const path = configFilePath({ platform, env });
  if (!existsSync(path)) return {};
  return parseYaml(readFileSync(path, 'utf8')) ?? {};
}

export function writeConfig(config, { platform = process.platform, env = process.env } = {}) {
  const path = configFilePath({ platform, env });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, stringifyYaml(config));
}

export function resolveRegistryRoot({ flags = {}, env = process.env, platform = process.platform } = {}) {
  if (flags.root) return { root: flags.root, source: '--root' };
  if (env.FLEET_REGISTRY_PATH) return { root: env.FLEET_REGISTRY_PATH, source: 'FLEET_REGISTRY_PATH' };
  const config = readConfig({ platform, env });
  if (config.registry_path) return { root: config.registry_path, source: 'config file' };
  throw new Error('No registry configured. Run "agents-registry init --repo-url <url>" first, or pass --root <dir>.');
}
