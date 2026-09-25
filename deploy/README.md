# Deploying the Fleet controller (smoke)

The minimal controller deployment from FM-008: one unprivileged container that
serves the public API, the web shell, and container health probes. It carries
no database, no accounts, and no secrets yet — those are M1 work — but the
mount locations it will use already exist so the deployment does not have to
be rearranged later.

## Run it

```sh
docker compose -f deploy/compose.yaml up --build -d
```

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
| `/healthz` | Process liveness |
| `/readyz` | Readiness; reports unavailable while the web shell is missing |

## Configuration placeholders

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
| `FLEET_MASTER_KEY_FILE` | *(unset)* | Master key file for the secret store. Must exist, be a regular file, and be mode 0600; startup refuses a more exposed key. The container sets `/run/secrets/master_key`. |

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
where Docker shares the Linux host network namespace.

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
- The published port binds **host loopback only**. Publishing to `0.0.0.0`
  would put an account-less control plane on your LAN; the plan's trusted-LAN
  mode with its explicit warning arrives with M1, not before.
- The image runs as a non-root system user with no shell.

## Image build

`deploy/controller.Dockerfile` is a three-stage build — web shell (Node
`24.19.0`, pnpm `9.15.9`), controller binary (Rust `1.98.0`, `--locked`), and
a `debian:bookworm-slim` runtime holding only the binary and the static
assets. The pinned versions are the same ones CI pins in
`.github/toolchain.env` and `rust-toolchain.toml`.
