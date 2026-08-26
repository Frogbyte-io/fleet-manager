#!/usr/bin/env node
// Runs every generated artifact in .github/scripts/lib/generators.mjs.
//
//   node .github/scripts/generate.mjs            regenerate in place
//   node .github/scripts/generate.mjs --check     fail if anything is stale
//
// --check leaves the working tree exactly as it found it, so it is safe to run
// locally and does not depend on git state.
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generators } from './lib/generators.mjs';

const repoRoot = resolve(join(dirname(fileURLToPath(import.meta.url)), '..', '..'));

function snapshot(root, outputs) {
  return outputs.map((path) => {
    const full = join(root, path);
    return { path, full, before: existsSync(full) ? readFileSync(full, 'utf8') : null };
  });
}

function restore(files) {
  for (const file of files) {
    if (file.before === null) rmSync(file.full, { force: true });
    else writeFileSync(file.full, file.before);
  }
}

/**
 * @param {string} root repository root to operate on
 * @param {{check?: boolean}} options
 * @returns {{stale: string[], changed: string[], skipped: string[], failed: string[], log: string[]}}
 */
export function runGenerators(root, { check = false } = {}) {
  const result = { stale: [], changed: [], skipped: [], failed: [], log: [] };

  for (const generator of generators) {
    const missing = generator.requires.filter((path) => !existsSync(join(root, path)));
    if (missing.length > 0) {
      result.skipped.push(generator.id);
      result.log.push(`- ${generator.id}: skipped, not present yet (${missing.join(', ')})`);
      continue;
    }

    const files = snapshot(root, generator.outputs);
    try {
      generator.run(root);
    } catch (error) {
      restore(files);
      result.failed.push(generator.id);
      result.log.push(`- ${generator.id}: FAILED: ${error.message}`);
      continue;
    }

    const differing = files
      .filter((file) => readFileSync(file.full, 'utf8') !== file.before)
      .map((file) => file.path);

    if (check) restore(files);

    if (differing.length === 0) {
      result.log.push(`- ${generator.id}: up to date`);
    } else if (check) {
      result.stale.push(generator.id);
      result.log.push(`- ${generator.id}: STALE: ${differing.join(', ')}`);
    } else {
      result.changed.push(...differing);
      result.log.push(`- ${generator.id}: wrote ${differing.join(', ')}`);
    }
  }

  return result;
}

function main(argv) {
  const check = argv.includes('--check');
  const root = resolve(argv.find((arg) => !arg.startsWith('--')) ?? repoRoot);

  const result = runGenerators(root, { check });
  console.log(`Generated artifacts (${check ? 'check' : 'write'}) in ${root}:`);
  for (const line of result.log) console.log(line);

  for (const id of result.failed) {
    console.error(`::error::generator ${id} failed`);
  }
  for (const id of result.stale) {
    console.error(
      `::error::${id} is stale. Its source changed without regenerating it. ` +
        'Run `node .github/scripts/generate.mjs` and commit the result.',
    );
  }

  if (result.failed.length > 0 || result.stale.length > 0) return 1;
  if (!check && result.changed.length > 0) console.log(`Regenerated ${result.changed.length} file(s).`);
  console.log(check ? 'All generated artifacts are up to date.' : 'Generation complete.');
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv.slice(2)));
}
