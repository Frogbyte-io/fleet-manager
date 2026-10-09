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
6. **Lab environments are disposable and time-limited.** Destroy them when you
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
fleetctl --output json proxmox accounts
fleetctl --output json lab create <template-version-id> --project <project-id> --purpose "reproduce flaky test" --wait
fleetctl --output json lab exec <lease-id> --wait -- cargo test
fleetctl --output json lab status <lease-id>
fleetctl --output json lab collect <lease-id> /home/lab/out/report.xml --wait
fleetctl --output json lab artifacts --lease <lease-id>
fleetctl --output json lab extend <lease-id> --seconds 3600
fleetctl --output json lab destroy <lease-id> --wait
```

1. Pick a published template version from `lab templates` (`publishedFrom`).
2. `lab create` leases and provisions the environment (`--wait` waits for it). `--project`
   attaches the lease to a project. Without `--account` it uses the only
   trusted Proxmox account; with none or several, pass `--account <account-id>`.
   `proxmox accounts` lists the accounts (`id`, `name`, `host`,
   `fingerprintState`); use the `id` of an account whose `fingerprintState` is
   `confirmed`. Nothing maps a template to its account: a wrong pick typically
   fails with `template_missing` (or another refusal if that account has no
   build artifact for the template), so ask the user or try the next account
   with a new `lab create`.
   Without `--wait` it returns the lease as it is right after provisioning was
   queued, and you follow it with `lab status` until its `state` is `ready`. With
   `--wait` the exit code is non-zero unless the lease is `ready`. Keep the
   lease `id` it returns, even on failure, so you can destroy it.
3. `lab exec` runs a command in the guest. Put `--wait` and `--timeout` before
   the `--`; everything after it is the guest command. With `--wait` the exit
   code is the guest command's (1 if it did not run, or if the wait timed out
   before the operation finished: the error names the operation). The default
   `--timeout` is 60 seconds. Its output is stored as an exec-log artifact.
   The guest command starts in the SSH user's home directory (`/root` for the
   default `root` user; the template's `ssh_user`). When the template's
   readiness probe is `project_ready`, the lease's project (the `--project` you
   passed, else the template's bootstrap project) is checked out at
   `/tmp/fleet-projects/<project-id>`:
   run `lab exec <lease-id> --wait -- sh -c 'cd /tmp/fleet-projects/<project-id> && cargo test'`
   rather than searching the filesystem.
4. Optionally `lab put <lease-id> <local-path> <guest-path> [--overwrite] --wait`
   copies one local file into the guest (its directory must exist; the
   guest checks the SHA-256 before the file appears, and an existing file is
   refused unless `--overwrite`). `lab collect` copies absolute guest paths into artifacts, which
   outlive the lease (with `--wait` it exits non-zero unless it succeeded), and
   `lab artifacts` lists them (filter with `--lease` or `--project`).
5. `lab extend` adds time up to the lease's maximum lifetime; the controller
   refuses more.
6. `lab destroy` removes the environment.

Polling `lab status` (or `lab leases`) stops at `ready` (go on), `released`
(final), or `cleanup_failed` (needs an operator: report it). `failed` is not
the end of the story if a guest was already cloned: the controller then moves
the lease to `releasing` and removes the guest, so keep polling until
`released` or `cleanup_failed`. A lease that stays `failed` never got a guest.
`requested`, `queued`, `reserving`, `provisioning`, `booting`,
`bootstrapping`, and `releasing` are worth waiting for.

Rules:

- Always run `lab destroy` as the last step, even when the task failed or you
  are giving up (a finally-style step). Never leave a lease behind.
- Never use `--keep`: it hands the guest out of Lab ownership, and nothing will
  clean it up.
- The exception is `lab destroy` on a `failed`, `released`, or
  `cleanup_failed` lease: it returns 400 (`the lease <id> is already <state>`,
  exit 1), so do not retry it. A `failed` lease cannot be re-provisioned
  either (`lab provision-lease` returns 409). Read the explanation, fix the
  cause (for `placement_ambiguous`, pass `--account`), and start over with a
  new `lab create`; the controller cleans up any guest the failed lease held.
- A lease in `cleanup_failed` still owns resources. Report it to the user; do
  not retry `lab destroy` in a loop. `lab cleanup-retry` is for an operator
  after the cause is fixed.
- Do not put secrets in `--purpose` or in `lab exec` arguments.

If `lab create` fails, the operation carries an explanation (for example
`template_missing`, no capacity on the node, or `pool_exhausted`). Report it to
the user. `lab destroy` a lease it left `ready` or in progress; a `failed` one
is refused, and the controller removes any guest it had (see polling above). With no trusted account, or
several and no `--account`, `lab create` stops before it creates a lease.

Lab pools (`lab pool ...`) are set up by an operator. A template version with a
pool is used by `lab create` with no extra step, provided `--account` is
omitted or names the pool's account.

### Advanced: the low-level flow

`lab create` is `lab lease` followed by `lab provision-lease`; use the pieces
only when you need to control them separately.

```bash
fleetctl --output json lab lease <template-version-id> --purpose "reproduce flaky test"
fleetctl --output json lab provision-lease <lease-id>
fleetctl --output json lab leases
fleetctl --output json lab leases --purpose-prefix "release-qa:v1.2:" --state ready,provisioning --owner <principal-id>
fleetctl --output json lab provisions
fleetctl --output json lab release <lease-id>
```

- Make creation safe to retry: add `--idempotency-key <key>` to `lab lease` or
  `lab create`. A retry with the same key and the same template version, purpose
  and project returns the lease already created (no second lease, no second pool
  member); the same key with different values is refused (`conflict`). A replay returns the lease in whatever state it has reached, even `failed` or `released`, so use a new key for each new attempt. Put the run
  identity in `--purpose` and find an unrecorded lease again with
  `lab leases --purpose <text>` or `--purpose-prefix <text>`, optionally with
  `--state` (repeatable or comma-separated) and `--owner`.
- Poll `lab leases` until the lease `state` is `ready`; `lab provisions` shows
  where it landed (node, VMID, address).
- Provisioning places the lease on the one Proxmox account whose cluster holds
  the template's image, after reserving CPU, memory, and disk against the
  node's latest observed capacity (not a live host guarantee). It fails with
  `placement_no_candidate`, `placement_ambiguous`, `placement_unresolved`, a
  capacity error, or a stale-capacity error; report the explanation.
  `lab provision-lease <lease-id> --account <account-id>` skips the scan, which
  resolves `placement_ambiguous` and `placement_unresolved` but not
  `placement_no_candidate` (that fails with `template_missing`).
- `lab release` is the low-level `lab destroy`; the same rules apply.

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
