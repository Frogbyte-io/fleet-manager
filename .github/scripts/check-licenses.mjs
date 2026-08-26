#!/usr/bin/env node
// Enforces the inbound license policy against npm lockfiles.
//
//   node .github/scripts/check-licenses.mjs [root]
//
// cargo-deny covers the Cargo graph, but only once a Cargo workspace exists and
// only for Cargo. This covers the Node dependency graph, which is the graph the
// repository actually has today, using the same allowed-license table.
//
// #30 adds pnpm-lock.yaml; add it to LOCKFILES when it lands.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readPolicy, POLICY_PATH } from './lib/policy.mjs';
import { satisfies } from './lib/spdx.mjs';

const repoRoot = resolve(join(dirname(fileURLToPath(import.meta.url)), '..', '..'));
// Both locations are listed rather than one, so that #23 relocating the Node
// package under legacy/ moves the check with it instead of quietly leaving it
// with nothing to inspect.
const LOCKFILES = ['package-lock.json', join('legacy', 'package-lock.json')];

/** npm has recorded `license` for years and `licenses` before that. */
function declaredLicense(entry) {
  if (typeof entry.license === 'string') return entry.license;
  if (Array.isArray(entry.license)) return entry.license.join(' OR ');
  if (Array.isArray(entry.licenses)) {
    return entry.licenses.map((item) => (typeof item === 'string' ? item : item?.type)).filter(Boolean).join(' OR ');
  }
  return null;
}

/**
 * @param {string} root
 * @param {string} lockfile path relative to root
 * @param {ReadonlyArray<string>} allowed
 */
function checkNpmLockfile(root, lockfile, allowed) {
  const lock = JSON.parse(readFileSync(join(root, lockfile), 'utf8'));
  const problems = [];
  let checked = 0;

  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    // "" is this repository, and `link: true` entries point at a workspace
    // package whose real entry is elsewhere in the lockfile.
    if (path === '' || entry.link) continue;
    checked += 1;

    const name = entry.name ?? path.replace(/^.*node_modules\//, '');
    const version = entry.version ?? 'unknown version';
    const expression = declaredLicense(entry);

    if (!expression) {
      problems.push(`${name}@${version}: no license recorded in ${lockfile}`);
      continue;
    }
    let ok;
    try {
      ok = satisfies(expression, allowed);
    } catch (error) {
      problems.push(`${name}@${version}: ${error.message}`);
      continue;
    }
    if (!ok) problems.push(`${name}@${version}: ${expression} is not in the allowed inbound set`);
  }

  return { checked, problems };
}

/** @returns {{ok: boolean, lines: string[], problems: string[]}} */
export function checkLicenses(root) {
  const lines = [];
  const problems = [];
  const { allowed } = readPolicy(root);
  lines.push(`Allowed inbound licenses (${allowed.length}) from ${POLICY_PATH}.`);

  let sawLockfile = false;
  for (const lockfile of LOCKFILES) {
    if (!existsSync(join(root, lockfile))) {
      lines.push(`- ${lockfile}: not present yet, skipped`);
      continue;
    }
    sawLockfile = true;
    const { checked, problems: found } = checkNpmLockfile(root, lockfile, allowed);
    lines.push(`- ${lockfile}: ${checked} package(s) checked, ${found.length} rejected`);
    problems.push(...found);
  }

  if (!sawLockfile) lines.push('No lockfile to check.');
  return { ok: problems.length === 0, lines, problems };
}

function main(argv) {
  const root = resolve(argv[0] ?? repoRoot);
  const { ok, lines, problems } = checkLicenses(root);
  for (const line of lines) console.log(line);
  if (ok) {
    console.log('Every dependency license is in the allowed inbound set.');
    return 0;
  }
  console.error(`Rejected dependencies (${problems.length}):`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error(
    `::error::A dependency license is outside the Apache-2.0-compatible inbound set. ` +
      `See ${POLICY_PATH}; widening the set or adding an exception is a reviewed decision.`,
  );
  return 1;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv.slice(2)));
}
