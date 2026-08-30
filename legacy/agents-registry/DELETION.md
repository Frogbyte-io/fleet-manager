# Legacy package deletion parity checklist

The Node.js `agents-registry` package is migration input, not a component of the
target architecture. Delete it only after each item below is either implemented
on the supported Fleet surfaces or explicitly accepted as behavior that will not
be carried forward.

- [ ] `init`, `validate`, `resolve`, `status`, `capabilities`, and `sync` each
      have a recorded parity or retirement decision.
- [ ] Role inheritance, pack composition, include/exclude behavior, project test
      profile resolution, and error collection fixtures run against their target
      domain replacements.
- [ ] Proxmox TLS fingerprint validation, task polling, and lifecycle
      characterization tests are represented at the provider boundary.
- [ ] Existing installations have a documented migration path, including the
      decision on a temporary `agents-registry` executable compatibility wrapper.
- [ ] No setup automation, bootstrap skill, live documentation, or CI job imports
      files from `legacy/agents-registry/` except checks intentionally preserving
      migration evidence.
- [ ] The legacy npm package, lockfile, license scan, and test job can be removed
      together without reducing the M0 verification gate.
- [ ] The maintainer has approved deletion as a narrow, independently revertible
      change after the replacement tests are green.
