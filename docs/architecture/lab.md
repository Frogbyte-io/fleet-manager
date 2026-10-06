# Fleet Lab architecture

Status: proposed

## Responsibility boundary

Fleet Lab owns image-recipe/version lifecycle, infrastructure selection, provisioning, readiness, project/tool setup, resource leasing, command dispatch, expiry, and cleanup. Proxmox runs VMs, while Packer is the first external image builder. External browser/desktop/hardware test frameworks perform tests.

## Main resources

| Resource | Purpose |
|---|---|
| Image recipe | Editable draft/version containing modern Packer `.pkr.json`, provisioning assets, compatibility, and provenance metadata |
| Image version | Immutable build snapshot and association to a concrete Proxmox VM template; only manually promoted versions become defaults |
| Lab template | Versioned definition that pins an image version plus runtime constraints, minimal bootstrap profile, readiness policy, default TTL, and cleanup strategy |
| Lease | Owner/purpose/project-scoped request and lifecycle; public handle used by CLI/API |
| Instance | Association to a concrete Proxmox QEMU/LXC resource and temporary Fleet machine/node |
| Resource | Schedulable host capacity or exclusive item such as GPU/USB controller |
| Reservation | Transactional claim of capacity/exclusive resource for one lease |
| Artifact | Metadata/digest/location/retention for logs, screenshots, results, or bundles |

Lab templates reference image versions/provider resources by stable IDs and an observed fingerprint/version. “Latest template named win11” is not reproducible enough for an active lease.

## Image recipe and promotion lifecycle

The first image-build provider invokes a compatible, externally installed Packer CLI. Fleet edits and stores modern `*.pkr.json`: a structured editor covers the supported Proxmox subset and an advanced raw editor exposes the complete JSON while preserving unknown fields. Recipes and provisioning scripts are privileged build inputs.

Editing any recipe, including an existing version, creates an editable draft/new version. Starting a build snapshots immutable inputs, asset digests, Packer/plugin versions, and provider target. A completed build records the resulting Proxmox template identity but never replaces or promotes another version automatically. Promotion is a separate manual mutation. The mandatory validation evidence for promotion is still under review.

A future catalog/marketplace distributes recipes, manifests, provisioning assets, compatibility constraints, and signatures/provenance. It never distributes VM disk images or licensed OS media; operators provide the required installation media and build locally.

## Lease state machine

```text
requested -> queued -> reserving -> provisioning -> booting -> bootstrapping -> ready
     |          |           |             |            |             |
     +----------+-----------+-------------+------------+-----------> failed
                                                                    |
ready -> releasing -> released                                      |
  |          |                                                       |
  +-------> cleanup_failed <-----------------------------------------+
```

Cancellation and expiry transition any non-terminal state into release/compensation. Provider VM state is tracked separately; a running VM does not imply a ready lease.

Deadlines:

- Queue deadline/optional caller wait limit
- Provisioning/readiness deadline from request
- Ready TTL beginning only when the lease reaches `ready`
- Absolute maximum lifetime of 30 days beginning at request to cap stuck workflows
- Ready TTL extensions can move the expiry only up to that creation-relative maximum
- Cleanup retry/backoff horizon with persistent operator alert after exhaustion

The current controller path attaches a provision record to a requested lease before queuing `lab.provision`. When the provision executor reaches guest readiness, it marks that same linked lease `ready`, starts its template TTL, and caps the expiry at the creation-relative maximum. Standalone template provisioning remains separate from lease lifecycle and does not make a lease ready.

If the linked operation fails, the lease becomes `failed` and the provision record becomes `never_ready`, retaining its named failure step and any guest identifiers. A readiness timeout is terminal for that lease: another provision request returns a conflict directing the caller to release it and request a replacement. Provision failure cleanup remains part of the broader Lab saga work.

Cleanup strategies:

- `destroy` is the default and deletes the allocated clone.
- `revert` is allowed only for explicitly managed preallocated/pool instances whose reservation prevents concurrent use.
- `keep` requires elevated permission; it detaches the instance from automatic Lab cleanup and records the new owner. It is not “skip cleanup and forget.”

## Placement and later scheduling

The first Lab release selects among compatible Proxmox targets and transactionally reserves the CPU/memory/storage capacity needed to prevent over-allocation. It does not claim rich fairness, quotas, preemption, or exclusive hardware scheduling. The later scheduler filters then ranks:

1. Authorized provider accounts/hosts for the caller/project/template
2. Compatible provider/template/version, architecture/OS, capabilities, storage/network, readiness route
3. Sufficient safe CPU/memory/storage capacity with configured overcommit policy
4. Availability of every exclusive resource (GPU partition, USB device/controller, other hardware)
5. Placement preferences, queue priority, fairness, and data locality

Reservation is a short SQLite transaction with uniqueness/usage constraints. Provisioning starts only after commit. External calls cannot share that transaction, so every transition has a reconciler and compensation. Scheduler correctness uses database constraints in addition to in-memory locks.

Later fairness begins as bounded FIFO per priority with per-identity/project concurrency limits. Preemption remains out of scope. Queued requests explain the blocking resource without exposing unrelated tenant details.

## Provisioning saga

1. Create lease and operation after centralized authorization/audit intent. In the initial trusted-LAN mode the caller is `anonymous-lan-admin`, including skill-driven agent calls.
2. Select placement and reserve capacity/resources/VMID.
3. Clone the immutable, manually promoted image version to a Fleet-namespaced guest.
4. Apply bounded resource/network/cloud-init configuration.
5. Start and poll Proxmox task/guest state.
6. Obtain guest IP through QEMU Guest Agent when available; never assume a fixed delay.
7. Register a temporary SSH Fleet machine in the same storage transaction that records its machine and endpoint IDs on the provision. The machine carries the `lab` tag and `lab-provision:<id>` / `lab-lease:<id>` groups in the machine read model. A resumed provision reuses this association; an incomplete or changed endpoint blocks continuation. Fleetd installation and Windows guest bootstrap are outside this route.
8. Persist `bootstrapping`, then establish SSH host-key trust through FM-201 before any command runs. Templates declare `sshUser` (default `root`), `sshPort` (default `22`), `sshTrustMode` (`tofu` or `pinned`), and, for pinned trust, `sshFingerprint`. Authentication uses the controller's SSH agent; keys must already be installed in the pinned image. For a Fleet-created Lab guest on the trusted provisioning network, first-contact TOFU is the default; that confirmation is audited and persisted. Every subsequent connection must match the recorded key. A template fingerprint mismatch or changed host key fails the provision and never replaces the pin automatically. This is specific to Fleet-created Lab guests, not general machine onboarding. OpenSSH remains an external system integration ([keyscan contract](https://man.openbsd.org/ssh-keyscan), [strict verification](https://man.openbsd.org/ssh_config#StrictHostKeyChecking)); no SSH library or binary is bundled.
9. Execute the configured readiness policy: `guest_agent` requires a reachable QEMU agent with a usable non-loopback/non-link-local IPv4 address plus the trusted SSH endpoint; `ssh_exec` additionally retries the declared command through FM-202 until exit zero; `project_ready` requires `bootstrap_project_id` and succeeds only after M3's verify step passes. After the guest-agent and optional SSH command probe pass, any declared bootstrap project is prepared and verified before the lease is marked ready, including with the other probe kinds. The existing M3 `ready.workflow` is a durable child operation with a provision-scoped idempotency key, recorded before execution. Its checkout root is `/tmp/fleet-projects/<project-id>` on the disposable Linux guest. Full M4 GitOps is not a prerequisite. A completed successful child whose result includes `verify` is reused on resume; a blocked or failed child never implies ready.
10. Atomically mark the provision and linked lease ready, start ready TTL, and return connection metadata allowed to the caller. The absolute readiness deadline is persisted before boot, shared by IP discovery, SSH trust/probes and project setup, and never restarted on resume. Failure records `never_ready` on the provision and `failed` on the lease with a named step, retaining the VMID, node, clone task, observed IP, machine/endpoint, and child operation IDs for FM-713 cleanup. Provider command output is not copied into the parent failure. Lab children check parent cancellation between M3 steps, clamp each step timeout to the remaining absolute budget, and request child cancellation even if the readiness caller times out. An active SSH command can finish within its bounded timeout; cancellation prevents subsequent steps. Child operations retain their existing bounded/redacted output contracts; cancellation/deadline does not claim remote commands were rolled back.

Migration 0035 extends the provision state constraint using SQLite's transactional table rebuild. It runs at controller startup before the HTTP listener and workers start; it must not run alongside another controller writer. For a database with substantial provision history, stop the controller, back up the database using SQLite's backup mechanism, and rehearse the migration on the backup in an isolated data directory. Set an explicit maintenance time budget from that measured run before restarting production. Stop startup if that budget is exceeded; the transactional migration rolls back rather than leaving a partially rebuilt table. Keep the backup until readiness and legacy record checks pass. This is offline maintenance proportional to provision history, not an online or phased schema migration.

Every step records external IDs before continuing. Repeated execution discovers existing state and resumes or compensates instead of creating a second VM.

The current clone step works as follows:

- **Source.** The clone source is the template VMID recorded by the pinned image version's latest successful build. If no artifact is recorded, the provision fails; there is no default source. The clone runs on the node that `/cluster/resources` reports for that template. The Proxmox account's host is only the API endpoint.
- **Target VMID.** The executor takes the next free VMID from `GET /cluster/nextid`. The operator limits it to the VMIDs granted to Fleet with the PVE `datacenter.cfg` `next-id` range (see the [token guide](../operations/proxmox-token.md#why-clone-and-lab-need-more-than-the-pool)). Before the clone request, the executor records the VMID and the node on the provision record in one transaction. That transaction refuses a VMID that another in-flight record already holds.
- **Re-runs.** A re-run reuses the recorded VMID. Before the clone, if a guest already exists at that VMID, the executor adopts it only when it carries the record's Fleet name (`fm-lab-<record>`); any other guest there is a conflict. After the clone, a resumed record's guest must still exist with that name before it is started; otherwise the provision fails without starting anything.
- **Task check.** The recorded VMID is always the reserved target. PVE starts a `qmclone` task under the *source* VMID, so the executor checks the returned task against the source and node it requested, and fails on a mismatch.
- **Cleanup guard.** Cleanup refuses to destroy a VMID that the cluster reports as a template, or that matches the recorded build artifact of a promoted image version. The executor also refuses to resume a provision record that names such a VMID, and it never reserves a promoted artifact's VMID as a clone target, even after that template is gone.

## Execution and artifacts

`fleetctl lab exec` creates a normal authorized operation targeting the leased node. It validates that the caller owns/can use the lease and that the lease is ready. Command output limits and secret rules are identical to machine exec.

The first Lab release guarantees command execution and bounded/redacted logs needed to operate the lease. Rich collection of declared paths, test reports, screenshots, and result bundles is a follow-on. Artifact bytes eventually live in a configured controller volume/object store while SQLite retains metadata and digest; collection failure never silently suppresses cleanup.

## Later USB and physical resources

- Inventory uses stable host topology identifiers (vendor/product/serial and physical port/path where available), not transient bus numbers alone.
- A resource declares which Proxmox node owns it, passthrough/IOMMU constraints, reset needs, and concurrency (`exclusive` initially).
- Reservation precedes VM configuration. Attach verifies the expected device immediately before mutation.
- Detach/release is a mandatory compensation even when tests fail. A reconciler compares reservation, Proxmox config, host inventory, and lease state.
- Conflicts queue rather than stealing a device. Manual override is elevated and audited.

The first Lab release should omit USB if the real hardware validation environment is unavailable; it must not ship an untested “exclusive” claim.

## Failure-injection acceptance

Tests interrupt the controller after reservation, clone request, clone completion, boot, enrollment, project setup, ready, TTL expiry, device attach, and delete. On restart, reconciliation must reach one of:

- a valid owned ready lease,
- a queued/failed lease with no external allocation, or
- a cleanup-failed lease that visibly owns the remaining resource and retries/alerts.

There must never be an untracked VM, a resource reserved by two live leases, or a released lease whose USB device remains silently assigned.
