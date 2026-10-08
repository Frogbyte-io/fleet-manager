# Deploying the Fleet controller

One controller container serves the API, Vue web app, node gateway, and health
probes. SQLite runtime state and encrypted secrets persist in the data volume;
the master key is mounted separately. The dashboard has no login and must stay
inside a trusted network. The service process runs without root privileges.

For Coolify and private Tailscale ingress, use the standalone
[Coolify deployment guide](COOLIFY.md) and `compose.coolify.yaml`.

## Run it

```sh
export FLEET_MASTER_KEY_SOURCE=/absolute/path/to/master_key
docker compose -f deploy/compose.yaml up --build -d
```

Provision a real key first using the format in
[fleet-secrets](../crates/fleet-secrets/README.md). The smoke script below
creates its own temporary key and disposable volume instead.

Or run the full end-to-end smoke, which builds, waits for healthy, probes the
served surfaces, asserts the isolation posture, and checks the SIGTERM path:

```sh
deploy/smoke.sh
```

## What the controller serves

| Path | Purpose |
|---|---|
| `/` and static assets | The built Vue web shell |
| `/api/v1/*` | The public API described by `packages/api-client/openapi.json` |
| `/api/node/v1/*` | Node enrollment, session proof, and outbound WebSocket gateway |
| `/downloads/fleetd/*` | Linux node installer packages |
| `/healthz` | Process liveness |
| `/readyz` | Readiness; reports unavailable while the web shell is missing |

## Configuration

Precedence, documented in `crates/fleet-config`: built-in defaults < the
configuration file selected with `--config <path>` (TOML) < environment
variables. The controller validates everything below **before readiness** and
refuses to start on a missing or unsafe setting.

| Variable | Default | Meaning |
|---|---|---|
| `FLEET_LISTEN` | `127.0.0.1:8080` | Address the HTTP listener binds. Loopback is the default on purpose: the controller is a trusted-LAN service and must not face an untrusted network by accident. The container overrides this to `0.0.0.0:8080` because reachability is limited by the loopback publish instead. |
| `FLEET_TAILSCALE_SERVE_LISTEN` | *(unset)* | Enables a dedicated loopback-only HTTP listener for Tailscale Serve identity. When set, `FLEET_LISTEN` must also be loopback and the two addresses must differ. Configure Serve to proxy to `http://127.0.0.1:<port>`. This mode is not supported by the default bridged Compose deployment; use host networking or run the controller directly on the host. |
| `FLEET_WEB_DIST` | `./web` | Directory of the built web shell. The image sets `/opt/fleet/web`. |
| `FLEET_DATA_DIR` | `./data` | Runtime state directory; created during startup validation. The container sets `/var/lib/fleet`. |
| `FLEET_MASTER_KEY_FILE` | *(unset)* | Master key file for the secret store. Must exist, be a regular file, and have owner-only permissions; startup refuses a more exposed key. Compose sets `/tmp/fleet-secrets/master_key`, the protected copy made by the entrypoint from `/run/secrets/master_key`, so service and healthcheck use the same file. |
| `FLEET_LAB_SWEEP_INTERVAL_SECONDS` | `60` | How often the Lab sweeper runs (FM-716). Each tick expires leases past their TTL, queues due cleanups (including backoff retries), compensates leases stuck past their readiness deadline (and `failed` leases still holding a guest), and reports `fm-lab-*` guests that no live lease owns (audit event `lab_orphan_guest`, plus a log line; never deleted). `0` disables the loop; `POST /api/v1/lab/leases/sweep` still works. TOML key: `lab_sweep_interval_seconds`. |
| `FLEET_LAB_MEMORY_OVERCOMMIT` | `1.0` | Lab placement: the ratio applied to a node's total memory before observed usage and held reservations are subtracted. `1.0` is no overcommit; accepted range is above 0 up to 16. File key `lab_memory_overcommit`. |
| `FLEET_LAB_CPU_OVERCOMMIT` | `1.0` | Lab placement: the ratio applied to a node's logical CPU count before held reservations are subtracted. Accepted range is above 0 up to 16. File key `lab_cpu_overcommit`. |
| `FLEET_LAB_CAPACITY_MAX_AGE_SECONDS` | `300` | Lab placement refuses a node capacity observation older than this (1 to 86400 seconds) instead of guessing. File key `lab_capacity_max_age_seconds`. Both Compose files forward the three placement variables and the two artifact bounds below (`FLEET_LAB_ARTIFACT_RETENTION_SECONDS`, `FLEET_LAB_ARTIFACT_MAX_BYTES`) from the host environment (or a Compose `.env`). |
| `FLEET_LAB_ARTIFACTS_DIR` | `<FLEET_DATA_DIR>/lab-artifacts` | Where Lab artifact bytes (exec logs and collected guest files, FM-721) live, content-addressed by sha256; SQLite keeps only their metadata. The controller creates it at startup; if it cannot, the controller logs a warning and serves without Lab artifacts. Keep it on the same persistent volume as the database. TOML key: `lab_artifacts_dir`. |
| `FLEET_LAB_ARTIFACT_RETENTION_SECONDS` | `604800` (7 days) | How long a Lab artifact is kept; the Lab sweeper deletes it afterwards, so expiry needs the background sweeper (`FLEET_LAB_SWEEP_INTERVAL_SECONDS` above 0). With the sweeper disabled, artifacts are kept until it runs again. Must be positive. TOML key: `lab_artifact_retention_seconds`. |
| `FLEET_LAB_ARTIFACT_MAX_BYTES` | `67108864` (64 MiB) | The largest single Lab artifact. A collected file above it is refused. Must be positive. TOML key: `lab_artifact_max_bytes`. |
| `FLEET_IMAGE_BUILD_PROXY` | *(unset, off)* | An explicit proxy for Packer image builds (#339): a bare `http://host[:port]` or `https://host[:port]`. Only the `packer build` child gets it, as `HTTPS_PROXY`; each use is audited. A URL with credentials, a path, a query, or a fragment is refused at startup (the error never shows the value). Builds of versions with the insecure-TLS opt-in are refused while it is set. Empty means off. TOML key: `image_build_proxy`. Both Compose files forward it and `FLEET_IMAGE_BUILD_NO_PROXY`, but the published image has no Packer, so it matters for a derived image. See [the Lab runbook](../docs/operations/lab.md#packer-installed-by-you). |
| `FLEET_IMAGE_BUILD_NO_PROXY` | *(unset)* | Hosts the build reaches directly even with a proxy (`NO_PROXY` syntax: a comma-separated list of hosts, domains such as `.lan`, or CIDRs; at most 1024 bytes). Handed as `NO_PROXY` to the `packer build` child with the proxy; ignored when no proxy is set. TOML key: `image_build_no_proxy`. |

An unset master key source is reported in the startup summary as "secret store
unavailable" rather than pointed at a file that does not exist.

For Tailscale Serve identity on a Linux Docker host, use the opt-in host
network override so Serve and the controller share the host namespace:
`docker compose -f deploy/compose.yaml -f deploy/compose.tailscale.yaml up -d --build`.
Then configure Serve to proxy to `http://127.0.0.1:8081`. Both controller
listeners bind to host loopback in this override; the existing bridged
`compose.yaml` intentionally cannot use this mode because the proxy would
arrive from a container bridge address instead of loopback. Host networking is
an explicit change to the default deployment posture and is supported only
where Docker shares the Linux host network namespace. This override uses the
Compose `!reset` merge tag and requires Docker Compose v2.24.0 or newer.

Identity mode keeps the regular controller listener loopback-only, so the
existing node enrollment and gateway routes are host-local too. Remote
`fleetd` clients cannot connect in this mode; leave it disabled if the
controller needs remote node sessions until a separate node listener is
available. On the Serve listener, a human Tailscale identity is required for
the UI, downloads, health routes, and node routes; node operations still
require their Fleet node credentials.

## Mount locations

| Mount | What it holds |
|---|---|
| `fleet-data` volume at `/var/lib/fleet` | Runtime state: the SQLite database, backups, and operation records. A named volume, so `docker compose down -v` is the explicit destructive act. |
| Docker secret `master_key` at `/run/secrets/master_key` | The secret-store master key, mounted as a file — never an environment variable or a build argument. The compose definition reads the file path from `FLEET_MASTER_KEY_SOURCE` (default `./secrets/master_key`). |

The master key file must be mode 0600. `deploy/smoke.sh` generates an
ephemeral key for the smoke run and removes it on exit; in production the
operator provisions a real one.

## Security posture

- The container has **no Docker socket, no host network, no privileged mode,
  and no host path mounts**. `deploy/smoke.sh` asserts all four.
- The root filesystem is **read-only**; only `/tmp` (tmpfs) and the state
  volume are writable.
- The published port binds **host loopback only**. Use private ingress to
  provide trusted-network access; do not publish an account-less control plane
  to the Internet.
- The entrypoint starts as root to prepare state and copy the mounted key to
  owner-only tmpfs storage, then uses `setpriv` to run the controller as uid/gid
  999. The service account has no login shell.

## Image build

`deploy/controller.Dockerfile` is a three-stage build — web shell (Node
`24.19.0`, pnpm `9.15.9`), controller binary (Rust `1.98.0`, `--locked`), and
a `debian:bookworm-slim` runtime with the binary, static assets, Git/SSH client
tools, CA roots, and a native-architecture Linux node installer package. The
package is copied into the persistent artifacts directory on startup. The
pinned versions are the same ones CI pins in
`.github/toolchain.env` and `rust-toolchain.toml`.
