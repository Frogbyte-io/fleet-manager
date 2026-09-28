---
name: fleet
description: Operate this Fleet Manager controller with fleetctl --output json - check controller health, find machines, prepare projects on a machine, run disposable Lab environments, follow operations, and read skill deployments. Use whenever a task involves the fleet's machines, Lab leases, or controller state.
---

# Fleet

Fleet Manager is the control plane for this developer fleet: machines, projects,
Lab environments, and the operations that change them. Drive it through
`fleetctl`, always with `--output json`, and read the JSON rather than parsing
text.

## Rules

1. **Always pass `--output json`, before the command word.**
   `fleetctl --output json machines list` works; `fleetctl machines list --output json` does not.
2. **The controller is the source of truth.** Do not edit machine state, agent
   skill directories, or Skills Manager files by hand; ask the controller.
3. **Mutations are durable operations.** Commands that change something return
   an operation. Pass `--wait` where the command accepts it, or follow the
   operation with `operations get` until its `state` is `succeeded`, `failed`,
   `cancelled`, `timed_out`, or `blocked_manual_approval`. The last one means a
   person has to act (for example approve a Frogenv request): stop polling and
   tell the user.
4. **Preview first.** Where a command offers `--dry-run`, run it before the real
   thing and read the plan.
5. **Never put secrets in arguments.** Commands that need a secret read it from
   stdin; everything you pass on the command line may end up in shell history.
6. **Lab environments are disposable and time-limited.** Release them when you
   are done; extend them only as long as you need.

## Controller and health

```bash
fleetctl --output json status
fleetctl --output json system
```

`status` asks this machine's fleetd over its local socket, which needs no
controller credentials; with `--url <controller>` it asks the controller directly.
`system` reports the controller's version, storage health, operation queue,
trust mode, and the principal you are acting as.

## Machines

```bash
fleetctl --output json machines list
fleetctl --output json machines list --status connected
fleetctl --output json machines list --tag <tag>
fleetctl --output json machines get <machine-id>
```

`machineStatus` is `connected`, `stale`, `offline`, or `agentless`. Use the
machine `id` (not its name) in every other command. A machine's `endpoints`
list the SSH endpoint ids that SSH-driven commands take as `--endpoint`.

## Projects

```bash
fleetctl --output json projects list
fleetctl --output json projects get <project-id>
fleetctl --output json projects ready <project-id> <machine-id> --root <path> --dry-run --endpoint <endpoint-id> --auth agent --wait
fleetctl --output json projects ready <project-id> <machine-id> --root <path> --endpoint <endpoint-id> --auth agent --wait
```

`projects ready` makes a checkout ready to work in: clone if missing, then the
project's setup. Run it with `--dry-run` first and read the plan. A step blocked
on a human (for example a Frogenv approval) is reported as blocked, not failed;
tell the user instead of retrying.

## Lab environments

```bash
fleetctl --output json lab templates
fleetctl --output json lab lease <template-version-id> --purpose "reproduce flaky test"
fleetctl --output json lab provision-lease <lease-id> --account <account-id>
fleetctl --output json lab leases
fleetctl --output json lab provisions
fleetctl --output json lab extend <lease-id> --seconds 3600
fleetctl --output json lab release <lease-id>
```

1. Pick a published template version from `lab templates` (`publishedFrom`).
2. `lab lease` creates the lease; `lab provision-lease` builds it on a Proxmox
   account.
3. Poll `lab leases` until the lease `state` is `ready`. `lab provisions` shows
   where it landed (node, VMID, address).
4. `lab extend` adds time up to the lease's maximum lifetime; the controller
   refuses more.
5. `lab release` destroys the environment. Always release what you leased.

A lease in `cleanup_failed` still owns resources: report it to the user.

## Operations

```bash
fleetctl --output json operations list --limit 20
fleetctl --output json operations get <operation-id>
fleetctl --output json operations cancel <operation-id>
fleetctl --output json events
```

`events` streams operation, machine, and lease changes as they happen.

## Skills

```bash
fleetctl --output json skills matrix
fleetctl --output json skills list <machine-id>
```

The matrix shows, per machine, which skills are installed and which agents they
are deployed to. This skill itself is the controller's built-in `fleet` catalog
entry: it changes only with a controller release, so do not edit it by hand.
