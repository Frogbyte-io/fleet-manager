function dedupe(list) {
  return [...new Set(list)];
}

/**
 * Resolves a role's contributed packs/include/exclude/external_packs/
 * capabilities, following `extends` chains (a role composing other roles).
 * Not shown explicitly in issue #2's examples, but a natural extension of
 * "Roles and inheritance" for avoiding duplicated role bodies. Throws on
 * unknown roles or `extends` cycles.
 */
function resolveRole(roleId, registry, chain = []) {
  if (chain.includes(roleId)) {
    throw new Error(`role inheritance cycle: ${[...chain, roleId].join(' -> ')}`);
  }
  const role = registry.roles.get(roleId);
  if (!role) {
    throw new Error(`unknown role "${roleId}"`);
  }
  const nextChain = [...chain, roleId];

  const packs = [];
  const include = [];
  const exclude = [];
  const externalPacks = [];
  const capabilities = [];

  for (const parentId of role.extends ?? []) {
    const parent = resolveRole(parentId, registry, nextChain);
    packs.push(...parent.packs);
    include.push(...parent.include);
    exclude.push(...parent.exclude);
    externalPacks.push(...parent.externalPacks);
    capabilities.push(...parent.capabilities);
  }

  packs.push(...(role.skills?.packs ?? []));
  include.push(...(role.skills?.include ?? []));
  exclude.push(...(role.skills?.exclude ?? []));
  externalPacks.push(...(role.skills?.external_packs ?? []));
  capabilities.push(...(role.capabilities ?? []));

  return {
    packs: dedupe(packs),
    include: dedupe(include),
    exclude: dedupe(exclude),
    externalPacks: dedupe(externalPacks),
    capabilities: dedupe(capabilities),
  };
}

function resolvePack(packId, registry) {
  const pack = registry.packs.get(packId);
  if (!pack) {
    throw new Error(`unknown pack "${packId}"`);
  }
  return pack.skills ?? [];
}

/**
 * Composes a machine's full desired state: Machine -> Roles -> Packs ->
 * Skills, per issue #2 section 3. Machine-level `skills.include` /
 * `skills.exclude` are applied last, after pack expansion, so a machine can
 * always override what its roles/packs bring in.
 */
export function resolveMachine(machineId, registry) {
  const machine = registry.machines.get(machineId);
  if (!machine) {
    throw new Error(`unknown machine "${machineId}"`);
  }

  const packs = [];
  const include = [];
  const exclude = [];
  const externalPacks = [];
  const capabilities = [...(machine.capabilities ?? [])];

  for (const roleId of machine.roles ?? []) {
    const role = resolveRole(roleId, registry);
    packs.push(...role.packs);
    include.push(...role.include);
    exclude.push(...role.exclude);
    externalPacks.push(...role.externalPacks);
    capabilities.push(...role.capabilities);
  }

  packs.push(...(machine.skills?.packs ?? []));
  include.push(...(machine.skills?.include ?? []));
  exclude.push(...(machine.skills?.exclude ?? []));
  externalPacks.push(...(machine.skills?.external_packs ?? []));

  const resolvedPacks = dedupe(packs);

  const expandedSkills = [];
  for (const packId of resolvedPacks) {
    expandedSkills.push(...resolvePack(packId, registry));
  }
  expandedSkills.push(...include);

  const excludeSet = new Set(exclude);
  const skills = dedupe(expandedSkills).filter((skill) => !excludeSet.has(skill));

  const devices = (machine.requires?.devices ?? []).map((deviceId) => {
    const device = registry.devices.get(deviceId);
    if (!device) {
      throw new Error(`machine "${machineId}" requires unknown device "${deviceId}"`);
    }
    return device;
  });

  return {
    id: machineId,
    host: machine.host,
    os: machine.os,
    roles: machine.roles ?? [],
    packs: resolvedPacks,
    skills,
    excluded: dedupe(exclude),
    externalPacks: dedupe(externalPacks),
    capabilities: dedupe(capabilities),
    resources: machine.resources,
    lifecycle: machine.lifecycle,
    devices,
  };
}

/** Resolves every machine in the registry, collecting per-machine errors instead of throwing. */
export function resolveAllMachines(registry) {
  const resolved = new Map();
  const errors = [];
  for (const machineId of registry.machines.keys()) {
    try {
      resolved.set(machineId, resolveMachine(machineId, registry));
    } catch (err) {
      errors.push(`machine "${machineId}": ${err.message}`);
    }
  }
  return { resolved, errors };
}

/** Resolves a project's desired skill state the same way a machine's `skills:` block would. */
export function resolveProject(projectId, registry) {
  const project = registry.projects.get(projectId);
  if (!project) {
    throw new Error(`unknown project "${projectId}"`);
  }

  const packs = dedupe(project.skills?.packs ?? []);
  const include = project.skills?.include ?? [];
  const exclude = new Set(project.skills?.exclude ?? []);

  const expandedSkills = [];
  for (const packId of packs) {
    expandedSkills.push(...resolvePack(packId, registry));
  }
  expandedSkills.push(...include);
  const skills = dedupe(expandedSkills).filter((skill) => !exclude.has(skill));

  const testMachineIds = new Set();
  for (const profileId of project.tests ?? []) {
    const profile = registry.testProfiles.get(profileId);
    if (!profile) {
      throw new Error(`project "${projectId}" references unknown test profile "${profileId}"`);
    }
    for (const machineId of profile.machines ?? []) {
      testMachineIds.add(machineId);
    }
  }

  return {
    id: projectId,
    repo: project.repo ?? null,
    packs,
    skills,
    externalPacks: dedupe(project.skills?.external_packs ?? []),
    testProfiles: project.tests ?? [],
    testMachines: [...testMachineIds],
  };
}

export function machinesWithCapability(registry, capability) {
  const { resolved, errors } = resolveAllMachines(registry);
  const machines = [...resolved.values()].filter((m) => m.capabilities.includes(capability));
  return { machines, errors };
}
