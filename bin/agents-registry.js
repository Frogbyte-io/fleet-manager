#!/usr/bin/env node
import { homedir } from 'node:os';
import { join } from 'node:path';
import { runStatus } from '../src/commands/status.js';
import { runResolve } from '../src/commands/resolve.js';
import { runCapabilities } from '../src/commands/capabilities.js';
import { runValidate } from '../src/commands/validate.js';
import { runSync } from '../src/commands/sync.js';
import { runInit } from '../src/commands/init.js';
import { resolveRegistryRoot } from '../src/config.js';

function parseFlags(args) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i += 1;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { flags, positional };
}

function usage() {
  console.log(`agents-registry - declarative fleet/machine/skill registry CLI

Usage:
  agents-registry status
  agents-registry resolve <machine-id> [--json]
  agents-registry capabilities <capability>
  agents-registry validate
  agents-registry sync [--machine <id>] [--dry-run] [--install-cmd "..."] [--pack-add-cmd "..."]
  agents-registry init --repo-url <url> [--path <dir>]

Run from anywhere inside this repo, or point at another registry with --root <dir>.`);
}

async function main() {
  const [, , command, ...rest] = process.argv;
  const { flags, positional } = parseFlags(rest);

  if (command === 'init') {
    const path = typeof flags.path === 'string' ? flags.path : join(homedir(), '.fleet-manager', 'registry');
    process.exitCode = runInit(null, { repoUrl: typeof flags['repo-url'] === 'string' ? flags['repo-url'] : undefined, path });
    return;
  }

  let rootDir;
  try {
    ({ root: rootDir } = resolveRegistryRoot({ flags }));
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
    return;
  }

  switch (command) {
    case 'status':
      process.exitCode = runStatus(rootDir);
      break;
    case 'resolve': {
      const machineId = positional[0];
      if (!machineId) {
        console.error('Usage: agents-registry resolve <machine-id> [--json]');
        process.exitCode = 1;
        break;
      }
      process.exitCode = runResolve(rootDir, machineId, { json: Boolean(flags.json) });
      break;
    }
    case 'capabilities': {
      const capability = positional[0];
      if (!capability) {
        console.error('Usage: agents-registry capabilities <capability>');
        process.exitCode = 1;
        break;
      }
      process.exitCode = runCapabilities(rootDir, capability);
      break;
    }
    case 'validate':
      process.exitCode = runValidate(rootDir);
      break;
    case 'sync':
      process.exitCode = runSync(rootDir, {
        explicitId: typeof flags.machine === 'string' ? flags.machine : undefined,
        installCmd: typeof flags['install-cmd'] === 'string' ? flags['install-cmd'] : undefined,
        packAddCmd: typeof flags['pack-add-cmd'] === 'string' ? flags['pack-add-cmd'] : undefined,
        dryRun: Boolean(flags['dry-run']),
      });
      break;
    case undefined:
    case '--help':
    case '-h':
    case 'help':
      usage();
      break;
    default:
      console.error(`Unknown command "${command}"\n`);
      usage();
      process.exitCode = 1;
  }
}

main();
