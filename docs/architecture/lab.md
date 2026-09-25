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
7. Wait for `fleetd` enrollment/session or an explicitly supported SSH/WinRM readiness route.
8. Apply bootstrap profile and verify required tools/providers.
9. Clone and prepare the project through the M3 ready-project operation and the minimal Lab bootstrap-profile contract; full M4 GitOps is not a prerequisite.
10. Mark ready, start ready TTL, and return connection metadata allowed to the caller.

Every step records external IDs before continuing. Repeated execution discovers existing state and resumes or compensates instead of creating a second VM.

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
