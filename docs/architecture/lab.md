# Fleet Lab architecture

Status: proposed

To enable and run Fleet Lab, see the [operator runbook](../operations/lab.md).

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

A lease names the Fleet project it serves, when one is recorded: creation accepts an explicit project id that must exist (a nonexistent id fails the creation), and with no explicit id the lease inherits the template version's `bootstrap_project_id` — also validated at creation — leaving the lease without a project when the template carries none.

## Image recipe and promotion lifecycle

The first image-build provider invokes a compatible, externally installed Packer CLI. Fleet edits and stores modern `*.pkr.json`: a structured editor covers the supported Proxmox subset and an advanced raw editor exposes the complete JSON while preserving unknown fields. Recipes and provisioning scripts are privileged build inputs.

The structured subset uses only keys the Packer Proxmox plugin has: the storage pool and disk size of `disks[0]`, the bridge of `network_adapters[0]`, and `boot_iso` for ISO builds. A build target is frozen when every declared disk names the version's storage pool. A `proxmox-clone` without `disks` keeps its source template's storage, which no recipe key can express: the version's storage pool is then the operator's declaration, and the build cannot verify it.

Editing any recipe, including an existing version, creates an editable draft/new version. Starting a build snapshots immutable inputs, asset digests, Packer/plugin versions, and provider target. A completed build records the resulting Proxmox template identity but never replaces or promotes another version automatically. Promotion is a separate manual mutation. The mandatory validation evidence for promotion is still under review.

Promotion pins the build record that justified it (issue #281). The gate reads the version's latest build record, and the promotion commits only while that record is still the latest, succeeded, and matches the version's inputs. The pinned record id is stored on the version (`promotedBuildId`) and named in both promotion audit events. Lab clones the pinned build's template. Rebuilding a promoted version only adds evidence: even when the rebuild succeeds into a new template, Lab keeps cloning the pinned build. To clone the new template, promote the version again; that re-promotion is the audited step that changes the clone source. A demotion keeps the pin, so a lease pinned to the version before the demotion keeps its clone source. A version promoted before migration 0039 has no pin until it is promoted again; until then Lab uses the earlier rule, the version's newest successful build.

### Build credentials and TLS trust

A build gets its target account's API token in Packer's child environment only (#272). Unless the version opted out of verification (below), the token goes only to the certificate the operator confirmed for that account (FM-600, issue #284). The Proxmox plugin does its own TLS: it builds a `tls.Config` without `RootCAs` ([`client.go`, v1.2.4](https://github.com/hashicorp/packer-plugin-proxmox/blob/v1.2.4/builder/proxmox/common/client.go)), so Go verifies against the system root pool. On Linux that pool is the file named by `SSL_CERT_FILE` plus every directory in `SSL_CERT_DIR`. When `SSL_CERT_DIR` is unset, the system directories are still loaded ([`root_unix.go`](https://github.com/golang/go/blob/go1.26.0/src/crypto/x509/root_unix.go)). A certificate that is itself in the pool verifies as a chain of one, and Go still checks the host name, validity, and key usage ([`verify.go`](https://github.com/golang/go/blob/go1.26.0/src/crypto/x509/verify.go)).

For each build, after the uncredentialed Packer version probes and before any secret is resolved (neither the account token nor recipe secret variables, which travel separately in the private `-var-file`), the executor:

1. Requires the account's confirmed fingerprint (`target_account_untrusted`).
2. Captures the host's leaf certificate without credentials. It uses the same observe-only transport as the trust probe, and the request carries no `Authorization` header. If the host can't be reached, the build fails with `target_certificate_unobservable`.
3. Refuses the leaf unless its SHA-256 equals the confirmed pin (`target_certificate_changed`). No credentialed `validate` or `build` child starts, so no process ever holds the token.

For a version without the opt-in, the executor also:

4. Refuses the leaf unless it names the account host in its SANs, by the same rules Go applies (`target_certificate_name_mismatch`). Fleet never falls back to skipping verification.
5. Writes the leaf as `tls/pinned.pem`, next to an empty `tls/roots.d/`, inside the operation's private work directory. Both are removed with that directory.
6. Sets `SSL_CERT_FILE` and `SSL_CERT_DIR` to those paths, alongside the token, on the `packer validate` and `packer build` children only. The controller's own environment and the version probes never see them.

If the certificate changes between step 3 and the plugin's connection, Go's handshake fails, so no request and no token is sent. On macOS and Windows, Go uses the platform verifier instead of `SSL_CERT_FILE`, so a pinned build is refused there (`certificate_pin_unsupported`). For Go TLS clients that honor these variables (Packer and its plugins), the pin replaces the system roots. A subprocess that uses another TLS implementation or trust store is not covered. A recipe that has Packer itself download over HTTPS (for example an `iso_url` fetched on the controller) cannot verify that server. Stage the ISO on PVE storage (`iso_file`), or let PVE download it (`iso_download_pve`).

**Why the leaf, and not the chain or the CA.** The leaf is exactly what FM-600 pins and what the operator confirmed. `pveproxy` presents only `pve-ssl.pem`, so the cluster's `pve-root-ca` never appears in the handshake. Fetching it would need a credentialed API call, which is the trust this step establishes. Trusting the CA or any presented intermediate would also widen trust to every certificate that CA signs, beyond what the operator confirmed. The certificate is not persisted in account state; the only copy is the transient one in the operation's private work directory. It is public, its identity is the stored fingerprint, and capturing it per build means existing confirmed accounts need no re-confirmation or migration. When PVE renews the leaf, builds fail with `target_certificate_changed` until the operator observes and confirms the new fingerprint, the same rule every other Proxmox call follows.

**Skipping verification is an audited exception.** A recipe whose builders set `insecure_skip_tls_verify` to anything other than a literal `false` (a template variable counts) builds only if its version was published with `allowInsecureTls`. That is the optional `POST /api/v1/images/recipes/{id}/publish` body, or `fleetctl images publish <id> --allow-insecure-tls`. Otherwise the build fails with `insecure_tls_not_allowed` before any Packer command runs.

- The opt-in is refused for a recipe that does not skip verification.
- It is recorded on the `image_recipe_publishing` audit intent.
- It is shown on the version as `allowInsecureTls`.
- It is part of the version digest, so it can never be added to an existing version. Without the opt-in the digest is unchanged, so existing versions keep their identities.

Opted-in builds still pass steps 1–3, so they never hand the token out while the host presents another certificate. That is the only check: Packer itself then skips verification, so an endpoint that changes after the check receives the token. This is why the opt-in is an explicit, audited exception. A version published before migration 0042 has no opt-in. If its recipe skips verification, drop the field and publish again (the build then pins), or publish again with the opt-in. Either way you get a new version.

A future catalog/marketplace distributes recipes, manifests, provisioning assets, compatibility constraints, and signatures/provenance. It never distributes VM disk images or licensed OS media; operators provide the required installation media and build locally.

## Lease state machine

```text
requested -> queued -> reserving -> provisioning -> booting -> bootstrapping -> ready
     |          |           |             |            |             |            |
     +----------+-----------+-------------+------------+-------------+--> failed  |
                                                                          |        |
                                    (a guest was allocated: cleanup owed) |        |
                                                                          v        v
                            released <-- releasing <----------------------+--------+
                                           |   ^
                          (attempt failed) |   | (retry after backoff)
                                           +---+
                                           |
                                           +--> cleanup_failed  (attempts exhausted)
                                                     |
                     (operator re-arm: back to releasing, fresh round of attempts)
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

If the linked operation fails, the lease becomes `failed` and the provision record becomes `never_ready`, retaining its named failure step and any guest identifiers. A readiness timeout is terminal for that lease: another provision request returns a conflict directing the caller to release it and request a replacement. When the failed or cancelled provision owns a guest, the lease moves on to `releasing` and its cleanup runs (FM-713); a lease that never allocated one stays `failed`.

Release queues one `lab.cleanup` operation per attempt (FM-713). It destroys the guest through the reviewed `proxmox.guest.destroy` path, with a review token the controller computes itself; that path stops the guest first, refuses templates and promoted image artifacts, and treats an absent guest as done. After a successful destroy, cleanup removes the Lab-owned machine record and marks the lease `released`; a failure at either step is a failed attempt. A failed attempt backs off (one minute, doubling, capped at an hour, with the next attempt's time stored on the lease); repeating a release does not queue the retry early. After five attempts the lease becomes `cleanup_failed`, and an audit event records the guest identifiers it last knew (the guest may already be gone if only the machine-record removal failed). Each provision record stores the Proxmox account its guest was cloned through, so cleanup uses the same account; a record from before that column refuses to guess.

The controller's Lab sweeper (FM-716, every `FLEET_LAB_SWEEP_INTERVAL_SECONDS`, default 60) keeps this converging without an operator:
- it expires `ready` leases past their TTL;
- it compensates leases stuck past their readiness deadline (plus a ten-minute grace) or their maximum lifetime, and `failed` leases whose record still holds a guest (a crash between the failure and its compensation). The transition is a compare-and-set on the observed state and provision link, so a provision that completes concurrently wins;
- it queues the cleanup of every `releasing` lease whose next attempt is due, which also repairs a release or compensation whose enqueue was lost;
- it compares the `fm-lab-*` guests on every trusted account with the Lab records, and reports, once per controller run, any guest that no live lease, standalone provision, or `keep` release owns. A guest is owned only through the account and VMID its record names, the ones cleanup destroys through, and a leased record only when record and lease link to each other. It never deletes a guest it cannot attribute, and a store failure fails the pass rather than reading as a missing record.

The rules live in `fleet_application::lab` (`stuck_compensation`, `cleanup_due`, `guest_owned`); the sweeper is an adapter. Each committed change publishes `lease.changed` immediately. A failure confined to one lease is logged and retried next tick without stalling the others. Shutdown cancels an in-flight tick; every step commits on its own. Every deadline and attempt lives in the rows, so a restarted controller continues where the last one stopped.

`cleanup_failed` stops automatic cleanup, and `lab release` refuses it. Once an operator has fixed the cause, `POST /api/v1/lab/leases/{leaseId}/cleanup/retry` (`fleetctl lab cleanup-retry`) re-arms it (#292). The route requires `lab.lease` and `operation.create`, the same permissions a release needs to queue the same cleanup. The re-arm resumes the release that the lease already recorded, with the same strategy and destroy guards, so it grants nothing a release does not. It is audited: `lab_lease_cleanup_rearm_requested` is required and recorded before the change, and `lab_lease_cleanup_rearmed` is recorded best effort once it is made, so a failure to write it never strands the cleanup the lease now owes. The re-arm moves the lease back to `releasing` with nothing scheduled, conditional on the lease still being `cleanup_failed`. The next `lab.cleanup` attempt is queued at once. Because an absent guest counts as destroyed, a guest the operator removed by hand resolves to `released`, and the Lab-owned machine record goes with it. The re-arm grants a fresh round of five attempts with the backoff restarted. `cleanupAttempts` keeps counting across rounds instead of returning to zero, because each attempt's idempotency key (`lab-cleanup:<lease>:<attempts>`) names that count: a reset would name the first round's failed operation, and nothing new would be queued.

Cleanup strategies:

- `destroy` is the default and deletes the allocated clone.
- `revert` is meant for explicitly managed preallocated/pool instances whose reservation prevents concurrent use. Pooled guests do not exist yet (FM-717), so cleanup currently refuses `revert` (`unsupported_until_pooled`) without destroying anything or spending an attempt; the lease stays `releasing`, so an operator can release it with `keep` instead.
- `keep` requires elevated permission; it releases the lease and leaves the guest and its Lab-owned machine record in place, out of automatic Lab cleanup. It is not “skip cleanup and forget.”

## Placement and later scheduling

The first Lab release selects among compatible Proxmox targets and transactionally reserves the CPU/memory/storage capacity needed to prevent over-allocation. It does not claim rich fairness, quotas, preemption, or exclusive hardware scheduling. The later scheduler filters then ranks:

1. Authorized provider accounts/hosts for the caller/project/template
2. Compatible provider/template/version, architecture/OS, capabilities, storage/network, readiness route
3. Sufficient safe CPU/memory/storage capacity with configured overcommit policy
4. Availability of every exclusive resource (GPU partition, USB device/controller, other hardware)
5. Placement preferences, queue priority, fairness, and data locality

Reservation is a short SQLite transaction with uniqueness/usage constraints. Provisioning starts only after commit. External calls cannot share that transaction, so every transition has a reconciler and compensation. Scheduler correctness uses database constraints in addition to in-memory locks.

Later fairness begins as bounded FIFO per priority with per-identity/project concurrency limits. Preemption remains out of scope. Queued requests explain the blocking resource without exposing unrelated tenant details.

### Current placement and reservation (FM-715)

- **Selection.** `lab provision-lease` takes an optional `--account`. Without one, the provision executor considers every trusted account (confirmed fingerprint and stored token) whose cluster reports the pinned image's recorded template VMID as a template; the clone constraint fixes the node to the template's node. Exactly one candidate is placed. None, or more than one, fails the provision operation with an explanation (`placement_no_candidate`, `placement_ambiguous`); so does any trusted account whose cluster or credential could not be read (`placement_unresolved`), since it could hold another template under the same VMID: two clusters can each hold an unrelated template under the same VMID, so Fleet does not rank between them. There is no per-account authorization today; every trusted account is a candidate.
- **Observation.** Immediately before reserving, the executor refreshes the node's capacity (FM-915's node status and storage reads) and stores it per account and node in `lab_capacity_observations`. A failed refresh, or one missing the CPU count, a memory figure, or every storage pool, replaces nothing, so the stored observation decides; a refresh with a nonempty but partial storage list does replace it, and a pool missing from it then refuses (`storage_unknown`). An observation older than `FLEET_LAB_CAPACITY_MAX_AGE_SECONDS` (default 300), or dated in the future after a clock rollback, refuses placement (`capacity_stale`). No observation, or one missing the CPU count or a memory figure, refuses it as `capacity_unknown`. A figure too large for SQLite is rejected when written, not clamped.
- **Reservation.** One `BEGIN IMMEDIATE` transaction reads the observation and the node's held reservations, applies the rule in `fleet-application`'s `lab_placement`, and inserts a row in the STRICT `lab_capacity_reservations` table (one per lease) before a VMID is taken or the clone requested. Memory is `total × FLEET_LAB_MEMORY_OVERCOMMIT − used − reserved`; CPU is `cpus × FLEET_LAB_CPU_OVERCOMMIT − reserved cores`; disk is `free − reserved` on the storage pool of the build Lab clones (the promotion's pinned build, else the newest successful one, else the image version's declared pool when no first-class build record exists), without overcommit. Observed memory use and the pool's observed used space already include running Lab guests, so their memory and disk count twice: against a given observation, placement can refuse a lease that would have fit, never admit one that does not. The check is against capacity as observed: SQLite serializes Fleet's own reservations, but usage on the node can change between the observation and the clone, and allocations made outside Fleet are seen only by a later observation, so placement does not guarantee live host capacity. Held reservations are summed per node name across accounts, which is conservative when two clusters share a node name. A refusal names the constraint, for example `insufficient memory on pve1: need 4096 MiB, 2048 free`.
- **Release.** The lease's state is authoritative: the reservation transaction stops counting a held row as soon as its lease is `released`, or `failed` without a VMID on its provision record, so a lost release write never strands capacity. The row itself is marked released (bookkeeping and audit) when the provision operation ends for a lease that failed without a VMID, and otherwise by cleanup right after it marks the lease `released`: after a successful destroy, for a lease that never allocated a guest, or for `keep`, whose guest leaves Lab ownership (and whose usage then appears in later observations). A failed destroy keeps it held, including in `cleanup_failed`, until a re-armed cleanup (`lab cleanup-retry`) destroys the guest and releases it the same way. A resumed clone re-checks its lease's reservation and refuses (`reservation_mismatch`, naming the held and the requested target and demand) unless the reservation has the same account, node, cores, memory, disk, and storage pool. A held reservation is never reused when the template has moved or a re-promotion changed the pinned build's pool. The reservation transaction applies the same check when it finds a held row for the lease. Inside the reservation transaction, a request for a lease that no longer counts (unknown, `released`, or `failed` without a VMID) errors and inserts nothing. If such a lease still has a held row, that row is released in the same transaction first. The provision operation fails with the error. This storage-side release is bookkeeping and is not audited separately. A lease that still counts and already holds a row gets that row back. Reservation, release, and every placement refusal (including `reservation_mismatch` and `storage_unknown`) each attempt a best-effort audit (`lab_capacity_reserved`, `lab_capacity_released`, `lab_placement_refused`): an audit-sink failure is not propagated, so a committed transition or refusal can lack its record.

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

Migration 0037 extends the provision state constraint using SQLite's transactional table rebuild. It runs at controller startup before the HTTP listener and workers start; it must not run alongside another controller writer. For a database with substantial provision history, stop the controller, back up the database using SQLite's backup mechanism, and rehearse the migration on the backup in an isolated data directory. Set an explicit maintenance time budget from that measured run before restarting production. Stop startup if that budget is exceeded; the transactional migration rolls back rather than leaving a partially rebuilt table. Keep the backup until readiness and legacy record checks pass. This is offline maintenance proportional to provision history, not an online or phased schema migration.

Every step records external IDs before continuing. Repeated execution discovers existing state and resumes or compensates instead of creating a second VM.

The current clone step works as follows:

- **Source.** The clone source is the template VMID of the build that the pinned image version's promotion pinned (see [promotion](#image-recipe-and-promotion-lifecycle)). For a version promoted before pins were recorded, it is the version's latest successful build. If no artifact is recorded, the provision fails; there is no default source. The clone runs on the node that `/cluster/resources` reports for that template. The Proxmox account's host is only the API endpoint.
- **Target VMID.** The executor takes the next free VMID from `GET /cluster/nextid`. The operator limits it to the VMIDs granted to Fleet with the PVE `datacenter.cfg` `next-id` range (see the [token guide](../operations/proxmox-token.md#why-clone-and-lab-need-more-than-the-pool)). Before the clone request, the executor records the VMID and the node on the provision record in one transaction. That transaction refuses a VMID that another in-flight record already holds.
- **Re-runs.** A re-run reuses the recorded VMID. Before the clone, if a guest already exists at that VMID, the executor adopts it only when it carries the record's Fleet name (`fm-lab-<record>`); any other guest there is a conflict. After the clone, a resumed record's guest must still exist with that name before it is started; otherwise the provision fails without starting anything.
- **Task check.** The recorded VMID is always the reserved target. PVE starts a `qmclone` task under the *source* VMID, so the executor checks the returned task against the source and node it requested, and fails on a mismatch.
- **Protection flag** (issue #290). A PVE clone copies the template's `protection` flag, and PVE refuses to delete a protected guest, so without this step every lease cloned from a protected template would end `cleanup_failed`. After the clone, and before the start, the executor reads the new guest's config until it exists and its clone lock is gone (PVE writes it inside the forked clone task; bounded at one hour; cancellation is honored, and is checked again before the start; a refused read fails at once). If the config carries `protection: 1`, the executor clears it with `PUT /nodes/{node}/qemu/{vmid}/config` and `protection=0`, conditional on the config digest it just checked. If PVE refuses that update with a server error (a stale digest or a brief lock), the executor re-reads and re-checks the config and tries once more. It changes only the reserved VMID, and only when that config is a non-template guest named `fm-lab-<record>`. It never touches the source template, which stays protected. A clone without the flag is not changed, so a resumed record repeats neither the clone nor the update. If the update is refused (the token lacks `VM.Config.Options` on `/vms/{newid}`, the `lab.provision.unprotect` row of the privilege table), the provision fails at step `unprotect` before the guest starts. The guest stays recorded, so cleanup still owns it. The protection is cleared at provisioning, not at destroy, so that the destroy path (FM-712) needs no Lab-specific exception and never unprotects anything.
- **Cleanup guard.** Cleanup refuses to destroy a VMID that the cluster reports as a template, or that matches a protected image build artifact: every successful build of a promoted image version, and every build a promotion pinned, including a demoted version's pinned build. The executor also refuses to resume a provision record that names such a VMID, and it never reserves a promoted artifact's VMID as a clone target, even after that template is gone.

## Execution and artifacts

`fleetctl lab exec` creates a normal authorized operation targeting the leased node. It validates that the caller owns/can use the lease and that the lease is ready. Command output limits and secret rules are identical to machine exec.

Lab artifacts (FM-721) are exec logs and explicitly collected guest files that outlive their lease. SQLite (`lab_artifacts`, migration 0041) keeps each one's lease, project, owner (the lease's owner), kind (`exec-log` or `file`), name, size, sha256, store-relative location, producing operation, and retention deadline; the bytes never enter SQLite. They live in the configured controller directory (`lab_artifacts_dir`), content-addressed at `sha256/<2 hex>/<64 hex>`, so identical content is stored once. Writes stage under `tmp/` and are renamed into place; every location must have exactly that shape and canonicalize inside the store root; one artifact is capped at `lab_artifact_max_bytes`. A download re-hashes the bytes and refuses a size or digest mismatch, then streams them with `Repr-Digest` and `ETag`.

- After every `lab.exec` that ran (one refused before running has no output), the controller keeps the command's bounded output (the same 3,000-byte-per-stream result machine exec returns), scrubbed of URL and `user:password@` credentials, as an `exec-log` artifact. A failure to store it is logged and never changes the exec's outcome.
- `POST /lab/leases/{id}/artifacts/collect` (permission `lab.artifacts`, audited) queues a `lab.collect` operation for 1–16 absolute guest paths. Paths may not contain `.`, `..`, or empty components or control characters. The executor re-checks that the lease is ready, then copies each regular file over the lease machine's verified SSH endpoint through `fleet-provider-ssh` (the path rides the shell-inert metadata blob; the raw bytes stream on stdout and are cut off past the cap).
- Collection never changes the lease. A path that cannot be copied fails the operation (`collection_partial` or `collection_failed`, with a per-path reason), keeps whatever was copied, and records the failure beside the lease (`lab_artifact_collection_failures`, shown as `collectionFailure` in the lease detail). A collection that runs after the lease left `ready` fails the same way. Release and cleanup never wait for collection, so a failed collection cannot block or skip cleanup.
- The Lab sweeper deletes artifacts past their retention deadline (`lab_artifact_retention_seconds`, default 7 days), audited as `lab_artifact_expired`; it removes the bytes only when no other artifact still references them.

Object storage, test-report parsing, screenshots, and result bundles remain follow-ons.

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
