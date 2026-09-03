#!/usr/bin/env node
// Enforces the inbound license policy against the Node dependency graphs.
//
//   node .github/scripts/check-licenses.mjs [root]
//
// cargo-deny covers the Cargo graph. This covers the npm lockfiles and the
// pnpm workspace graph using the same allowed-license table, so no dependency
// graph in the repository is outside enforcement.
//
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readPolicy, POLICY_PATH } from './lib/policy.mjs';
import { satisfies } from './lib/spdx.mjs';

const repoRoot = resolve(join(dirname(fileURLToPath(import.meta.url)), '..', '..'));
// The root lockfile covers repository tooling. The second lockfile preserves
// policy enforcement for the independently installable legacy package.
const LOCKFILES = ['package-lock.json', join('legacy', 'agents-registry', 'package-lock.json')];
const PNPM_WORKSPACE = 'pnpm-workspace.yaml';
const PNPM_LOCKFILE = 'pnpm-lock.yaml';

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

/**
 * Evaluates one `pnpm licenses list --json` report against the allowed set.
 *
 * The report maps each license to the packages declaring it:
 * `{ "<license>": [{ name, versions: [..], license, ... }] }`. One entry can
 * carry several installed versions, and each of them is a separate fact to
 * enforce. Split out from the process half so tests can feed synthetic reports.
 * @param {unknown} report parsed JSON report
 * @param {ReadonlyArray<string>} allowed
 * @returns {{checked: number, problems: string[]}}
 */
export function checkPnpmLicenses(report, allowed) {
  const problems = [];
  let checked = 0;

  if (report === null || typeof report !== 'object') {
    return { checked, problems: ['pnpm licenses report is not an object'] };
  }
  for (const [licenseGroup, packages] of Object.entries(report)) {
    if (!Array.isArray(packages)) {
      problems.push(`pnpm licenses report: ${licenseGroup} is not a package list`);
      continue;
    }
    for (const entry of packages) {
      const name = entry?.name ?? '<unknown package>';
      const versions = Array.isArray(entry?.versions) && entry.versions.length > 0 ? entry.versions : ['unknown version'];
      for (const version of versions) {
        checked += 1;
        const expression = typeof entry?.license === 'string' ? entry.license : null;
        if (!expression) {
          problems.push(`${name}@${version}: no license recorded in the pnpm graph`);
          continue;
        }
        let ok;
        try {
          ok = satisfies(expression, allowed);
        } catch (error) {
          problems.push(`${name}@${version}: ${error.message}`);
          continue;
        }
        if (!ok) problems.push(`${name}@${version}: ${expression} is not in the allowed inbound set (pnpm graph)`);
      }
    }
  }

  return { checked, problems };
}

/**
 * Runs the pnpm half of the check against an installed store. The workspace
 * graph is committed as pnpm-lock.yaml, but the lockfile records no license
 * fields, so the report has to come from `pnpm licenses list --json`.
 * @param {string} root
 * @param {ReadonlyArray<string>} allowed
 */
function checkPnpmGraph(root, allowed) {
  const lines = [];
  const problems = [];
  const present = [join(root, PNPM_WORKSPACE), join(root, PNPM_LOCKFILE)].every((path) => existsSync(path));
  if (!present) {
    lines.push(`- pnpm workspace: not present yet, skipped`);
    return { lines, problems, checked: 0 };
  }

  // A committed lockfile without an installed store would otherwise make the
  // command below return an empty report and silently pass nothing.
  if (!existsSync(join(root, 'node_modules', '.pnpm'))) {
    lines.push('- pnpm workspace: graph found, but node_modules is not installed');
    problems.push('pnpm workspace is committed but not installed; run pnpm install --frozen-lockfile so its licenses can be read');
    return { lines, problems, checked: 0 };
  }

  const result = spawnSync('pnpm', ['licenses', 'list', '--json'], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
    shell: process.platform === 'win32',
  });
  if (result.error || result.status !== 0) {
    const detail = (result.stderr ?? result.error?.message ?? '').split('\n').slice(0, 3).join(' ');
    problems.push(`pnpm licenses list failed: ${detail}`.trimEnd());
    return { lines, problems, checked: 0 };
  }

  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    problems.push('pnpm licenses list produced output that is not JSON');
    return { lines, problems, checked: 0 };
  }

  const { checked, problems: found } = checkPnpmLicenses(report, allowed);
  lines.push(`- pnpm workspace (${PNPM_LOCKFILE}): ${checked} package version(s) checked, ${found.length} rejected`);
  problems.push(...found);
  return { lines, problems, checked };
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

  const pnpm = checkPnpmGraph(root, allowed);
  lines.push(...pnpm.lines);
  problems.push(...pnpm.problems);
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
