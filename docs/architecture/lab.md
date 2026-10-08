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

If the certificate changes between step 3 and the plugin's connection, Go's handshake fails, so no request and no token is sent. On macOS and Windows, Go uses the platform verifier instead of `SSL_CERT_FILE`, so a pinned build is refused there (`certificate_pin_unsupported`). The pin covers every TLS connection the Packer child makes. A recipe that has Packer itself download over HTTPS (for example an `iso_url` fetched on the controller) cannot verify that server. Stage the ISO on PVE storage (`iso_file`), or let PVE download it (`iso_download_pve`).

**Why the leaf, and not the chain or the CA.** The leaf is exactly what FM-600 pins and what the operator confirmed. `pveproxy` presents only `pve-ssl.pem`, so the cluster's `pve-root-ca` never appears in the handshake. Fetching it would need a credentialed API call, which is the trust this step establishes. Trusting the CA or any presented intermediate would also widen trust to every certificate that CA signs, beyond what the operator confirmed. The certificate is not stored. It is public, its identity is the stored fingerprint, and capturing it per build means existing confirmed accounts need no re-confirmation or migration. When PVE renews the leaf, builds fail with `target_certificate_changed` until the operator observes and confirms the new fingerprint, the same rule every other Proxmox call follows.

**Skipping verification is an audited exception.** A recipe whose builders set `insecure_skip_tls_verify` to anything other than a literal `false` (a template variable counts) builds only if its version was published with `allowInsecureTls`. That is the optional `POST /images/recipes/{id}/publish` body, or `fleetctl images publish <id> --allow-insecure-tls`. Otherwise the build fails with `insecure_tls_not_allowed` before any Packer command runs.

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
- **Cleanup guard.** Cleanup refuses to destroy a VMID that the cluster reports as a template, or that matches a protected image build artifact: every successful build of a promoted image version, and every build a promotion pinned, including a demoted version's pinned build. The executor also refuses to resume a provision record that names such a VMID, and it never reserves a promoted artifact's VMID as a clone target, even after that template is gone.

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
