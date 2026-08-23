// src/commands/init.js
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { writeConfig } from '../config.js';

const defaultGit = {
  clone(url, dest) {
    execFileSync('git', ['clone', url, dest], { stdio: 'inherit' });
  },
  pull(dest) {
    execFileSync('git', ['-C', dest, 'pull', '--ff-only'], { stdio: 'inherit' });
  },
};

export function runInit(rootDirUnused, { repoUrl, path, env = process.env, platform = process.platform, git = defaultGit } = {}) {
  if (!repoUrl) {
    console.error('Usage: agents-registry init --repo-url <url> [--path <dir>]');
    return 1;
  }
  if (existsSync(join(path, '.git'))) {
    git.pull(path);
  } else {
    git.clone(repoUrl, path);
  }
  writeConfig({ registry_path: path }, { env, platform });
  console.log(`Registry ready at ${path} (config written).`);
  return 0;
}
