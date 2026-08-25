#!/usr/bin/env node
// Validates relative Markdown links across the repository: the target file must
// exist, and a #fragment must match a heading in that file. FM-000 requires
// documentation link checks; this runs without installing anything.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Defaults to the repository root; an explicit path keeps the checker testable.
const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), '..'));
const skipDirs = new Set(['node_modules', '.git', 'dist', 'target']);

function markdownFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.github') continue;
    if (skipDirs.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...markdownFiles(full));
    else if (entry.name.endsWith('.md')) out.push(full);
  }
  return out;
}

// Fenced code blocks contain directory trees and issue templates, not real links.
function stripFences(text) {
  let inFence = false;
  return text
    .split('\n')
    .map((line) => {
      if (/^\s*(```|~~~)/.test(line)) {
        inFence = !inFence;
        return '';
      }
      return inFence ? '' : line;
    })
    .join('\n');
}

// GitHub's heading slug: lowercase, drop punctuation, spaces to hyphens.
function slug(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/`/g, '')
    .replace(/[^\w\s-]/g, '')
    // One hyphen per space, not per run: "A — B" becomes "a--b", matching GitHub.
    .replace(/\s/g, '-');
}

const anchorCache = new Map();
function anchorsOf(file) {
  if (!anchorCache.has(file)) {
    const found = new Set();
    const counts = new Map();
    for (const line of stripFences(readFileSync(file, 'utf8')).split('\n')) {
      const match = /^(#{1,6})\s+(.*)$/.exec(line);
      if (!match) continue;
      const base = slug(match[2]);
      const n = counts.get(base) ?? 0;
      counts.set(base, n + 1);
      found.add(n === 0 ? base : `${base}-${n}`);
    }
    anchorCache.set(file, found);
  }
  return anchorCache.get(file);
}

const problems = [];
for (const file of markdownFiles(root)) {
  const body = stripFences(readFileSync(file, 'utf8'));
  const lines = body.split('\n');
  lines.forEach((line, index) => {
    for (const [, text, target] of line.matchAll(/\[([^\]]*)\]\(([^)\s]+)\)/g)) {
      if (/^(https?:|mailto:|#)/.test(target)) {
        if (target.startsWith('#') && !anchorsOf(file).has(target.slice(1))) {
          problems.push(`${relative(root, file)}:${index + 1}: [${text}] -> no heading matches ${target}`);
        }
        continue;
      }
      const [path, fragment] = target.split('#');
      const resolved = resolve(dirname(file), path);
      let stats;
      try {
        stats = statSync(resolved);
      } catch {
        problems.push(`${relative(root, file)}:${index + 1}: [${text}] -> missing ${target}`);
        continue;
      }
      if (fragment && stats.isFile() && resolved.endsWith('.md') && !anchorsOf(resolved).has(fragment)) {
        problems.push(`${relative(root, file)}:${index + 1}: [${text}] -> no heading matches #${fragment} in ${path}`);
      }
    }
  });
}

if (problems.length > 0) {
  console.error(`Broken Markdown links (${problems.length}):`);
  for (const problem of problems) console.error(`  ${problem}`);
  process.exit(1);
}
console.log('All relative Markdown links and anchors resolve.');
