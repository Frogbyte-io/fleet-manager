---
name: fleet
description: Operate this Fleet Manager controller with fleetctl --output json - check controller health, find machines, prepare projects on a machine, run disposable Lab environments, follow operations, and read skill deployments, request brokered Coolify and DNS changes, and look up or record the Registry (domains, services, vendors, accounts, hosting). Use whenever a task involves the fleet's machines, Lab leases, controller state, or where something is hosted or who provides it.
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
   are done; extend them only as long as you need. A Lab lease is the default
   way to get a machine; request a permanent one only when you must (see
   Creating a permanent VM).

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

### Working on a machine

```bash
fleetctl --output json machines exec <machine-id> -- uname -a
fleetctl --output json machines exec <machine-id> --timeout 300 -- cargo test --workspace
fleetctl --output json machines exec <machine-id> --script -- "cd /srv/app && ./deploy.sh | tail -n 20"
fleetctl --output json machines exec <machine-id> --os windows --script -- "Get-Service sshd"
fleetctl --output json machines put <machine-id> ./build/app.tar.gz /opt/app/app.tar.gz --overwrite
fleetctl --output json machines collect <machine-id> /var/log/app/error.log /etc/app/config.yaml
fleetctl --output json machines files <machine-id>
fleetctl --output json machines file-get <file-id> --out ./error.log
```

The controller holds the machine's SSH key and runs every command; you never
see the key and you never need an SSH client. An endpoint's default credential
is recorded by whoever set up the machine, so you pass no `--auth`. If a
command answers "the endpoint has no default auth", ask the user to set one
(`machines endpoint-auth set`) rather than guessing a credential. `--endpoint`
is only needed when the machine has more than one SSH endpoint.

- `exec` waits and answers `{state, exitCode, stdout, stderr, truncatedStdout,
  truncatedStderr}`. **The CLI exits with the command's own exit code**, so
  branch on it. `255` can also be `ssh` itself failing (a refused login, an
  unreachable host); read `stderr` and `reason`. A `reason` of `deadline_killed`
  means the deadline (default 60 s, at most 900 s) passed: the command may
  still have run, so check before repeating it. Output is cut at 1 MiB per
  stream, with the matching `truncated*` flag set; send long output to a file
  and `collect` it. Anything credential-shaped in the output is redacted.
- Words after `--` are passed to the program as data, with no shell: pipes,
  `&&` and `$VAR` do nothing. For shell syntax use `--script` with exactly one
  word, the script text (bash; PowerShell on Windows, with `--os windows`).
  Empty arguments cannot be passed, and on Windows an argument containing a
  double quote may be re-split; use `--script` for those.
- `--os` is `linux` (default) or `windows`. A Windows machine takes
  drive-absolute paths (`C:\Users\...`) for `put` and `collect`.
- `put` sends one local file to an absolute path; it fails rather than replace
  an existing file unless you pass `--overwrite`, and it verifies the SHA-256
  inside the machine so a failed put leaves nothing behind. `collect` copies up
  to 16 files (each within the controller's artifact cap) into the controller;
  `file-get` downloads one and verifies it. Collected files are kept for seven
  days. A failed `collect` still keeps the files it did copy and lists the
  `failures` by path.
- Never type a secret into a command, because the operation records it. Put it
  in a file with `put`, or ask the user to set it up another way. `exec` is
  audited by the command's digest, not its text.
- Do not use `exec` to read the controller's own secrets or to remove your
  access. There is no interactive terminal and no privilege elevation here;
  if `sudo` needs a password, tell the user.

### Creating a permanent VM

**Default to a Lab lease.** When you need a machine to run, build or test
something, take a disposable Lab environment (see Lab environments): it has a
time limit and the controller removes it. Ask for a permanent VM only when the
work genuinely needs one that outlives you (a build host, a long-running
service, a machine the user will keep using), and only when the user asked for
it or agreed. A permanent VM takes capacity indefinitely and is never cleaned
up.

If you are an agent with a restricted credential you cannot create one
directly (`machines create` is refused with `denied`). Request it instead and
say why; a person approves it, and the controller creates it:

```bash
fleetctl --output json machines create --request --purpose "nightly build host for project X" --account <account-id> --image-version <version-id> --name build-box --cores 4 --memory 8192 --disk 40 --wait-approval=15m
fleetctl --output json requests get <request-id> --wait=15m
```

- `--purpose` is required: say what the machine is for in a sentence. It is
  recorded on the machine with you as its owner, and the approver reads it.
  State the cores, memory and disk you need; a request that leaves them to the
  image default may need a person even where small ones are approved
  automatically.
- Without a wait the command files the request and returns it (`state`
  `pending`, an `id`). With `--wait-approval[=<duration>]` (1s to 1h, default
  5m) it stays for the answer, which is `{outcome, request, result}`: exit 0
  is `executed` (`result` names `machineId`, `endpointId`, `vmid`, `address`),
  2 is `still_pending`, 1 is anything else. The creation itself takes minutes
  after the approval; the wait covers it. Waiting is bounded: do not loop.
- A request that policy approves starts at once (`state` `executing`); you
  cannot tell in advance, so always pass the wait or read `requests get`.
- Handle the outcomes as in Brokered actions below. In particular on `denied`
  never re-file or file a variant: report it and use a Lab lease or ask the
  user. Do not approve your own request. A Windows
  activation key goes in by reference id only; never put a secret in the request (`--activate-key <ref>`,
  stored beforehand by the user with `machines product-key store`).
- You never destroy a permanent VM; that stays the user's decision.

With an operator credential (`machines.provision`) the direct form creates it
without a request:

```bash
fleetctl --output json machines create --account <account-id> --image-version <version-id> --name build-box --cores 4 --memory 8192
fleetctl --output json machines create --account <account-id> --image-version <version-id> --name build-box --review-only
```

`machines create` makes a long-lived VM Fleet manages and never cleans up: it
clones a promoted image, applies the settings, starts it, registers and links
the machine, gives it its own SSH key (held by the controller, never shown) and
removes the image's shared key. It waits and answers `{state, machineId,
endpointId, vmid, address, hostKeyFingerprint, bootstrapKeyRemoved}`. It is a
privileged action: do it only when the user asked for a permanent machine, and
use `--review-only` first when unsure. A failed creation keeps the VM and names
the `step` that failed; re-running the same command resumes it. Destroying a
persistent VM is a separate, confirmed act by the user.

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
fleetctl --output json lab exec <lease-id> --detach --idempotency-key <key> -- ./run-suite.sh
fleetctl --output json lab exec-status <handle>
fleetctl --output json lab exec-status <handle> --wait --timeout 3600
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
   A command that may run longer than 15 minutes (the `--timeout` maximum is
   900 seconds) is run detached instead: `lab exec <lease-id> --detach [--timeout <s>]
   [--idempotency-key <key>] -- <command>` returns at once with a `handle`.
   Poll `lab exec-status <handle>` (or `--wait [--timeout <s>]`, which polls
   for you and exits with the command's exit code; 1 for any state but
   `exited`). Each answer carries `state`, `terminal`, `exitCode`, and the last
   3,000 bytes of `stdout` and `stderr`. States: `starting` and `running`
   (poll again), `unreachable` (the guest could not be read: poll again),
   and the terminal `exited` (read `exitCode`; 124 means the time bound ended
   it), `lost` (the guest rebooted or the wrapper died without an exit
   code), `failed_to_start` (the start operation failed and the guest has no trace of it; check status once more, then start again),
   and `lease_ended` (the lease was released or expired and took the
   command with it). A detached command never outlives its lease or
   extends it: its time bound is capped at the lease's remaining TTL, so
   read the result before `lab destroy`, and `lab extend` first if the
   lease is too short. Reuse the same `--idempotency-key` when retrying a
   start so the command is not run twice. The full output stays in the guest
   under `/var/lib/fleet-lab/exec/<handle>/` (`$HOME/.local/state/fleet-lab/exec/<handle>/`
   for a non-root SSH user): `lab collect <lease-id> <dir>/stdout <dir>/stderr` before the lease ends.
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

## Registry

The Registry is the fleet's descriptive record of things that are not
machines: domains and services (vendor, plan, cost, renewal, where it is
hosted, where its login lives). It lives in Fleet Git; the controller serves
the active revision read-only.

**Look up before you ask the user, and record what you learn.** Consult it
when a task mentions a domain, a vendor, a subscription, an account, or "where
is X hosted / who runs X / who pays for X".

```bash
fleetctl --output json registry types
fleetctl --output json registry find aptabase
fleetctl --output json registry list --type domain --tag client-x
fleetctl --output json registry get domain/example.com
fleetctl --output json registry list --target domain/example.com --relation used-by
```

Built-in types: `domain` (key `fqdn`) and `service` (key `slug`).
`registry types` shows each type's fields and allowed relations. An address
is `<type>/<key>`, for example `service/aptabase`.

### Recording facts

Reads use the controller. Edits change YAML in a local checkout of the Fleet
Git repository (run from inside it or pass `--repo <path>`); nothing reaches
the controller until you publish.

```bash
fleetctl --output json registry set domain/example.com --field registrar=Webhuset --field autoRenew=true --field loginAt="1Password (Webhuset vault)"
fleetctl --output json registry set service/aptabase --field name=Aptabase --field vendor=Aptabase
fleetctl --output json registry relate domain/example.com used-by service/aptabase
fleetctl --output json registry tags add domain/example.com client-x
fleetctl --output json registry unset domain/example.com --field dnsHost
fleetctl --output json registry validate
fleetctl --output json registry publish -m "Record example.com registrar"
```

1. `set` creates or patches an entry; fields you omit stay as they are. Use
   `relate <from> <relation> <target>` for links (`--remove` undoes one).
   Relation targets are `<type>/<key>`, `machine:<name>`, or `project:<name>`.
2. Nothing invalid is written: an unknown field, wrong value type, or
   credential-looking value is refused with an `FM_SCHEMA_*` diagnostic.
3. Run `registry validate` before publishing.
4. `publish -m <message>` commits only Registry files, then follows the
   controller's `registry.changeMode`. `direct` pushes to the default branch:
   the change is live once the controller activates it. `pull-request` (the
   default) pushes a branch and opens a pull request, or prints a compare URL:
   the change is not live until a person merges it. In that case tell the
   user and give them the link; do not claim the Registry changed.
5. `rm` deletes an entry; do it only when the user asked for it.

**Never write secrets into the Registry.** No passwords, tokens, recovery
codes, or keys in any field, note, or tag. Use `loginAt` to say where a login
lives, for example `1Password (Webhuset vault)`, never the credential itself.
Record only what you verified or were told; leave unknown fields out.

## Brokered actions

Changes at Coolify (running services) and Cloudflare (DNS) are not made with
provider keys. You file a request; the controller holds the keys, authorizes
it, audits it, and runs it once its risk class allows. Low-risk requests run
at once; `approve`-class requests (stop, env, domains, DNS, deploys) wait for a
person.

**Never ask for, read, or handle a provider key** (Coolify or Cloudflare
token). Never put one in an argument, file, or Registry field. Environment
variable values are the only secrets you touch, and only values the user
supplied, through `--stdin` or `--file`, never as arguments.

```bash
fleetctl --output json services list --source coolify
fleetctl --output json services settings <service-id>
fleetctl --output json services logs <service-id> --lines 100
fleetctl --output json services restart <service-id> --reason "pick up new config" --wait-approval=5m
fleetctl --output json services stop <service-id> --reason "client asked to pause" --wait-approval
fleetctl --output json services start <service-id> --wait-approval
fleetctl --output json services redeploy <service-id> --wait-approval=10m
fleetctl --output json services env list <service-id>
fleetctl --output json services env set <service-id> --stdin --redeploy --wait-approval=5m
fleetctl --output json services env unset <service-id> OLD_FLAG --wait-approval
fleetctl --output json services domains set <service-id> https://www.example.com --wait-approval=5m
fleetctl --output json services health set <service-id> --enabled --path /healthz --wait-approval
fleetctl --output json services templates
fleetctl --output json services deploy --template <template-id> --account <account-id> --server <server> --project <project> --environment production --domain www.example.com --dns --dns-target 203.0.113.10 --wait-approval=10m
fleetctl --output json dns zones
fleetctl --output json dns records www.example.com
fleetctl --output json dns observations www.example.com
fleetctl --output json dns set www.example.com --type A --content 203.0.113.10 --replaces 203.0.113.9 --reason "move to new host" --wait-approval=5m
fleetctl --output json dns delete old.example.com --type CNAME --content target.example.net --wait-approval
fleetctl --output json requests list --state pending
fleetctl --output json requests get <request-id> --wait=2m
```

- Use `services` for lifecycle, `services env|domains|health` for Coolify
  settings, `services deploy` to create a site from a built-in template
  (`--dns` also files the Cloudflare request), and `dns` for records. Read
  first (`settings`, `env list`, `dns records`): the request shows a preview of
  the change, and env commands show names and flags, never values.
- Always give `--reason`. Without a wait, the command files the request and
  returns its id; add `--wait-approval[=<duration>]` (1s to 1h, default 5m) to
  stay for the answer. Waiting is bounded: do not wrap it in a loop.
- With a wait the answer is `{outcome, request, result}`. Exit 0 is `executed`,
  2 is `still_pending`, 1 is anything else.
- `env set --stdin` reads `KEY=VALUE` lines (or one value with `--key <name>`)
  that the user gave you. If you do not have the value, ask the user; do not
  invent or look one up.

Outcomes:

| `outcome` | What to do |
| --- | --- |
| `executed` | Report what changed. Verify with a read (`services get`, `dns records`), then record new facts (below). |
| `denied` | A person said no. Report it with the request id and any note. **Never retry or re-file the request**, or file a variant to get around it; ask the user. |
| `expired` | No one answered in time and it did not run. Tell the user; file again only if they ask. |
| `still_pending` | Not decided yet. Report the request id and stop. Do not poll in a loop; the user can approve it and you can check once with `requests get <request-id>` when asked. |
| `failed` | The provider rejected or failed it. Report the error as printed; do not retry blindly. |

Do not `requests approve` your own request. Approving is a person's decision;
do it only when the user explicitly tells you to.

After a successful change, record what is now true in the Registry (see
Registry above): `services deploy` prints the `registry set` patch to apply,
`registry suggest domain/<fqdn>` prints one from the latest DNS observation,
and `registry set` / `registry relate` record the service, its domain, and the
link between them.

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
