import { loadRegistry } from '../registry.js';
import { resolveMachine } from '../resolve.js';
import { detectMachineId, matchByHostname } from '../currentMachine.js';
import { findSkillsBackend, installSkill, addExternalPack } from '../skillsBackend.js';

/**
 * `sync` resolves this machine's desired state and reconciles it via the
 * skills CLI backend (issue #2 section 4/13). It does not touch Proxmox,
 * agent-specific wiring (Codex/Claude config), or global context files -
 * those are deliberately left to `setup.sh`/`setup.ps1` and a future
 * Proxmox adapter so this command can't destabilize the existing,
 * timer-driven sync flow those scripts already run on real machines.
 */
export function runSync(rootDir, { explicitId, installCmd, packAddCmd, dryRun = false } = {}) {
  const registry = loadRegistry(rootDir);
  if (registry.errors.length > 0) {
    console.error(`Warning: ${registry.errors.length} registry load error(s); run \`agents-registry validate\` for details.`);
  }

  const detected = detectMachineId(rootDir, { explicitId });
  let machineId = detected.id;
  if (!machineId) {
    machineId = matchByHostname(registry, detected.hostname);
  }
  if (!machineId) {
    console.error(
      `Could not determine which machine to sync (hostname "${detected.hostname}" matched no machine).\n` +
        'Pass --machine <id>, set AGENTS_REGISTRY_MACHINE, or write the id to .agents-registry-machine.',
    );
    return 1;
  }

  let desired;
  try {
    desired = resolveMachine(machineId, registry);
  } catch (err) {
    console.error(`Error resolving machine "${machineId}": ${err.message}`);
    return 1;
  }

  console.log(`Syncing machine "${machineId}" (${desired.skills.length} skill(s), ${desired.externalPacks.length} external pack(s))`);

  const backend = findSkillsBackend();
  if (!backend.available) {
    console.log(
      'No skills CLI found (set AGENTS_REGISTRY_SKILLS_CMD or install a `skills` binary on PATH). Dry run only:',
    );
    for (const skill of desired.skills) console.log(`  would install: ${skill}`);
    for (const pack of desired.externalPacks) console.log(`  would add external pack: ${pack}`);
    return 0;
  }

  console.log(`Using skills backend via ${backend.source}.`);

  let failures = 0;
  for (const skill of desired.skills) {
    if (dryRun) {
      console.log(`  would install: ${skill}`);
      continue;
    }
    const result = installSkill(skill, { installCmd });
    console.log(`  ${result.ok ? 'installed' : 'FAILED'}: ${skill}`);
    if (!result.ok) {
      failures += 1;
      console.error(`    ${result.command}: ${result.stderr || result.stdout}`);
    }
  }

  for (const pack of desired.externalPacks) {
    if (dryRun) {
      console.log(`  would add external pack: ${pack}`);
      continue;
    }
    const result = addExternalPack(pack, { packAddCmd });
    console.log(`  ${result.ok ? 'added' : 'FAILED'}: ${pack}`);
    if (!result.ok) {
      failures += 1;
      console.error(`    ${result.command}: ${result.stderr || result.stdout}`);
    }
  }

  if (failures > 0) {
    console.error(`\n${failures} operation(s) failed.`);
    return 1;
  }
  console.log('\nSync complete.');
  return 0;
}
