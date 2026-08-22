import { spawnSync } from 'node:child_process';

const DEFAULT_INSTALL_CMD = 'skills install {skill}';
const DEFAULT_PACK_ADD_CMD = 'skills pack add {url}';

/**
 * `agents-registry` deliberately does not reimplement skill installation
 * (issue #2 section 4: "do not duplicate skill download/install/update
 * logic if a suitable backend already exists"). The exact CLI contract of
 * that backend isn't specified by the issue, so the command templates here
 * are a best-effort default, overridable via env vars / CLI flags, rather
 * than a hard dependency on one specific tool.
 */
export function findSkillsBackend(env = process.env) {
  if (env.AGENTS_REGISTRY_SKILLS_CMD) {
    return { available: true, source: 'AGENTS_REGISTRY_SKILLS_CMD' };
  }
  const probe = spawnSync(process.platform === 'win32' ? 'where' : 'which', ['skills'], {
    encoding: 'utf8',
  });
  if (probe.status === 0) {
    return { available: true, source: 'PATH' };
  }
  return { available: false, source: null };
}

function runTemplate(template, vars) {
  const filled = Object.entries(vars).reduce(
    (cmd, [key, value]) => cmd.replaceAll(`{${key}}`, value),
    template,
  );
  const [command, ...args] = filled.split(' ');
  const result = spawnSync(command, args, { encoding: 'utf8' });
  return {
    ok: result.status === 0,
    command: filled,
    stdout: result.stdout?.trim() ?? '',
    stderr: result.stderr?.trim() ?? '',
  };
}

export function installSkill(skill, { installCmd = DEFAULT_INSTALL_CMD } = {}) {
  return runTemplate(installCmd, { skill });
}

export function addExternalPack(url, { packAddCmd = DEFAULT_PACK_ADD_CMD } = {}) {
  return runTemplate(packAddCmd, { url });
}
