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
| `/downloads/fleetctl/<platform>` | The `fleetctl` built with this controller, and `<platform>.sha256` beside it ([install fleetctl](#install-fleetctl)) |
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
| `FLEET_HARDWARE_REFRESH_INTERVAL_SECONDS` | `600` | How often the hardware reconciler (FM-1124) refreshes the USB inventory of each Proxmox account that has inventoried devices; `0` turns the scheduled refresh off (repairs still run), a non-zero value must be at least `60`. Each refresh reads the account's mappings, nodes and up to 512 guest configs; above `900` devices read as stale between refreshes. The refresh is quiet (failures and status changes only). |
| `FLEET_LAB_SWEEP_INTERVAL_SECONDS` | `60` | How often the Lab sweeper runs (FM-716). Each tick expires leases past their TTL, queues due cleanups (including backoff retries), compensates leases stuck past their readiness deadline (and `failed` leases still holding a guest), and reports `fm-lab-*` guests that no live lease owns (audit event `lab_orphan_guest`, plus a log line; never deleted). `0` disables the loop; `POST /api/v1/lab/leases/sweep` still works. TOML key: `lab_sweep_interval_seconds`. |
| `FLEET_CONSOLE_IDLE_SECONDS` | `600` | How long a Proxmox VM screen (`proxmox.console`) may go without keyboard, pointer, or paste input before the controller closes it (FM-495). Watching without input counts as idle. Accepted range `30` to `3600`; an invalid value is ignored with a startup warning. The maximum console duration is one hour regardless. |
| `FLEET_DESIRED_FETCH_INTERVAL_SECONDS` | `0` (off) | Optional periodic fetch of the configured desired source's `HEAD` (FM-1014). Each tick queues the ordinary `source.fetch` operation for a new head and never overlaps a pending or running fetch; a Registry-only revision then activates by itself when `registry.autoActivate` is on. A non-zero value must be at least `30`. TOML key: `desired_fetch_interval_seconds`. See `docs/guides/registry-workflow.md`. |
| `FLEET_SKILLS_MANAGER_AUTO_INSTALL` | `true` | After a fleetd install that enrolls the node (first or forced enrollment; an upgrade of a live node only when the machine was never observed by Skills Manager) and after an SSH onboarding add, queue a pinned `skills.probe` that installs the tested `skills-manager-cli` (1.40.0) for the machine's SSH login when it is absent (#600). The release asset and its sha256 come from Fleet's built-in pin table, chosen by the machine's `os/family` and architecture facts (Linux x86_64 and aarch64; any other platform, Windows included, is skipped with a stated reason). The Linux assets need glibc 2.34 or newer plus `liblzma.so.5` and `libz.so.1` (e.g. Debian 12, Ubuntu 22.04 or newer): the probe stages the download in `~/.local/bin` (so a `noexec` `/tmp` does not matter) and runs the verified binary's `--version` before placing it, and a binary that cannot run is deleted and the probe fails with `install_failed` ("does not run on this machine"), so nothing is left behind. An existing CLI is never replaced. The probe is an ordinary audited operation: the install queues it as the trusted worker principal, correlated with the install; an onboarding add queues it as the caller, who therefore needs both `operation.create` on `skills.probe` and `skills.deploy` on the machine. A failed or denied follow-up never fails the install or the add; the install result and the onboarding add response report it as `skillsManager` (`queued` with the operation id, `skipped` or `failed` with a reason, or `disabled`). The machine needs outbound HTTPS to `github.com` and to the release-asset redirect host on `*.githubusercontent.com`. `false` (or `0`) turns it off; `true`/`false`/`1`/`0` are accepted in any case. TOML key: `skills_manager_auto_install`. |
| `FLEET_SSH_KEY_GENERATE` | `true` | At startup, when the controller user has no default SSH key (`~/.ssh/id_rsa`, `id_ecdsa`, `id_ed25519` and the other names `ssh` tries), generate `~/.ssh/id_ed25519` (ed25519, no passphrase, comment `fleet-controller@<hostname>`): the `.ssh` directory 0700, the key 0600, owned by the controller's own user. This is the key `--auth agent` endpoints connect with. `~` is the controller user's **passwd** home, as `ssh` resolves it; in the image that is the data volume, `/var/lib/fleet`, so the key survives redeploys. An existing key is never replaced; one `ssh` could not use (unreadable by the controller user, readable by others, passphrase-protected) is reported in the startup log with the fix. For a usable key the log names its `SHA256:` fingerprint; for an unusable one it names the problem and the fix instead, without the fingerprint. The log never contains the key. `GET /api/v1/system/ssh-public-key` (`fleetctl system ssh-public-key`) publishes the public line, and `fleetctl machines join` installs it on a machine ([add a machine](../docs/operations/add-a-machine.md)). `false` (or `0`) turns generation off; the read endpoint then reports `none` until a key exists. TOML key: `ssh_key_generate`. |
| `FLEET_LAB_MEMORY_OVERCOMMIT` | `1.0` | Lab placement: the ratio applied to a node's total memory before observed usage and held reservations are subtracted. `1.0` is no overcommit; accepted range is above 0 up to 16. File key `lab_memory_overcommit`. |
| `FLEET_LAB_CPU_OVERCOMMIT` | `1.0` | Lab placement: the ratio applied to a node's logical CPU count before held reservations are subtracted. Accepted range is above 0 up to 16. File key `lab_cpu_overcommit`. |
| `FLEET_LAB_CAPACITY_MAX_AGE_SECONDS` | `300` | Lab placement refuses a node capacity observation older than this (1 to 86400 seconds) instead of guessing. File key `lab_capacity_max_age_seconds`. Both Compose files forward the three placement variables and the two artifact bounds below (`FLEET_LAB_ARTIFACT_RETENTION_SECONDS`, `FLEET_LAB_ARTIFACT_MAX_BYTES`) from the host environment (or a Compose `.env`). |
| `FLEET_LAB_ARTIFACTS_DIR` | `<FLEET_DATA_DIR>/lab-artifacts` | Where Lab artifact bytes (exec logs and collected guest files, FM-721) live, content-addressed by sha256; SQLite keeps only their metadata. The controller creates it at startup; if it cannot, the controller logs a warning and serves without Lab artifacts. Keep it on the same persistent volume as the database. TOML key: `lab_artifacts_dir`. |
| `FLEET_LAB_ARTIFACT_RETENTION_SECONDS` | `604800` (7 days) | How long a Lab artifact is kept; the Lab sweeper deletes it afterwards, so expiry needs the background sweeper (`FLEET_LAB_SWEEP_INTERVAL_SECONDS` above 0). With the sweeper disabled, artifacts are kept until it runs again. Must be positive. TOML key: `lab_artifact_retention_seconds`. |
| `FLEET_LAB_ARTIFACT_MAX_BYTES` | `67108864` (64 MiB) | The largest single Lab artifact. A collected file above it is refused. Must be positive. TOML key: `lab_artifact_max_bytes`. |
| `FLEET_IMAGE_BUILD_PROXY` | *(unset, off)* | An explicit proxy for Packer image builds (#339): a bare `http://host[:port]` (an `https://` proxy is refused: a verified build trusts only the PVE certificate). Only the `packer build` child gets it, as `HTTPS_PROXY`; each use is audited. A URL with credentials, a path, a query, a fragment, or percent-encoding is refused at startup (the error never shows the value). An empty value counts as unset. Builds of versions with the insecure-TLS opt-in are refused while it is set. Empty means off. TOML key: `image_build_proxy`. Both Compose files forward it and `FLEET_IMAGE_BUILD_NO_PROXY`, but the published image has no Packer, so it matters for a derived image. See [the Lab runbook](../docs/operations/lab.md#packer-installed-by-you). |
| `FLEET_IMAGE_BUILD_NO_PROXY` | *(unset)* | Hosts the build reaches directly even with a proxy (`NO_PROXY` syntax: a comma-separated list of hosts, domains such as `.lan`, or CIDRs; at most 1024 bytes). Handed as `NO_PROXY` to the `packer build` child with the proxy; ignored when no proxy is set. TOML key: `image_build_no_proxy`. |
| `FLEET_IMAGE_BUILD_ADDRESS_POOL` | *(unset, off)* | Opt-in pool of Fleet-assigned build addresses (#337): an IPv4 CIDR with the network address exactly (prefix 8 to 30). With it, each `proxmox-clone` image build gets a static address that Fleet puts into the guest (cloud-init) and into the communicator host of the recipe copy Packer reads, so the build guest no longer chooses where the controller connects. `proxmox-iso` builds cannot take one. Requires `FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE` and `FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY`; those and the two below without the CIDR fail startup. A bad value fails startup naming the rule, never the value. Empty means off. TOML key: `image_build_address_pool`. See [the Lab runbook](../docs/operations/lab.md#storage-and-network). |
| `FLEET_IMAGE_BUILD_ADDRESS_POOL_RANGE` | *(unset)* | The inclusive `first-last` range inside the CIDR Fleet hands out (not the network or broadcast address; at most 1024 addresses). Keep it out of DHCP. TOML key: `image_build_address_pool_range`. |
| `FLEET_IMAGE_BUILD_ADDRESS_POOL_GATEWAY` | *(unset)* | The gateway handed to build guests: inside the CIDR, outside the range. TOML key: `image_build_address_pool_gateway`. |
| `FLEET_IMAGE_BUILD_ADDRESS_POOL_DNS` | *(unset)* | Optional DNS servers handed to build guests (up to three IPv4 addresses, space or comma separated). TOML key: `image_build_address_pool_dns`. |
| `FLEET_IMAGE_BUILD_ADDRESS_POOL_REFUSE_ISO` | *(unset, false)* | `true` refuses `proxmox-iso` builds while the pool is set (`build_address_iso_refused`), since they cannot take an assigned address. TOML key: `image_build_address_pool_refuse_iso`. |

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
tools, CA roots, a native-architecture Linux node installer package, and a
native-architecture `fleetctl`. The entrypoint copies the package and
`fleetctl` into the persistent artifacts directory on startup. The
pinned versions are the same ones CI pins in
`.github/toolchain.env` and `rust-toolchain.toml`.

## Install fleetctl

`fleetctl` is a single binary. There are two places to get one:

- **From a GitHub release (preferred).** Every merge to `main` publishes a
  release tagged `v<version>-<commit>` with `fleetctl-linux-x86_64`,
  `fleetctl-linux-aarch64`, `fleetctl-windows-x86_64.exe`, and `SHA256SUMS`.
  Pick the release whose commit matches your controller. The binaries and
  `SHA256SUMS` come over HTTPS from GitHub, so the checksum also shows the
  file is the one the release workflow built. The Linux binaries are static
  (musl) and run on any distribution; the Windows binary needs no Visual C++
  runtime. Releases exist only for commits merged to `main`.
- **From your controller.** `GET /downloads/fleetctl/<platform>` serves the
  `fleetctl` built from the same commit as the controller, and
  `/downloads/fleetctl/<platform>.sha256` serves its SHA-256 in `sha256sum`
  format (the binary response also carries it in `x-checksum-sha256`). The
  image carries only its own architecture: `linux-x86_64` on an x86_64 host,
  `linux-aarch64` on an arm64 host. Other platforms answer 404 unless you put
  the release binary in `<FLEET_DATA_DIR>/artifacts/fleetctl/` under its
  release name (`fleetctl-windows-x86_64.exe`, for example). The routes sit
  behind the same caller check as the rest of the listener. This copy is
  built in the Debian 12 image and needs glibc 2.36 or newer (Debian 12,
  Ubuntu 23.04, or later); on Ubuntu 22.04, use the release binary.

  **The controller's checksum detects corruption, not tampering.** Over
  `http://...:8080` the binary and its `.sha256` come from the same
  unauthenticated origin, so anyone on the path can replace both. For
  integrity, compare against the release's `SHA256SUMS` from GitHub, or
  download through the controller's Tailscale Serve HTTPS URL
  (`https://controller.example.ts.net`).

Each snippet below stops at the first failure. It checks the download and
runs `--version` from a temporary directory, and only then replaces the
installed copy, so a corrupt binary or one that cannot run on this machine
never replaces a working one.

The `SHA256SUMS` check is the baseline and needs nothing but a shell. A
release binary also carries a signed build provenance attestation. The
checksum trusts the release page it came from, since `SHA256SUMS` sits next
to the binary; the attestation is signed separately, with a short-lived
certificate that names the workflow, the commit, and the run that built the
file. When the [GitHub CLI](https://cli.github.com/) (`gh`) is installed, the
release snippets also run `gh attestation verify` on the temporary download,
and a failed verification stops the install. Without `gh`, they print that
the check was skipped and install on the checksum alone. An installed `gh`
must be a 2.102.0 or newer release (a prerelease or development build is
refused) and signed in (`gh auth login`); the snippets check the version
first, and an older or signed-out `gh` fails the check, and
nothing is installed.

`--signer-workflow` and `--source-ref` narrow the check to the release
workflow running on `main`; `--repo` alone would accept an attestation from
any workflow in the repository. Older `gh` versions accept both flags but
match them loosely (a regular expression before 2.97.0; a prefix, and a
ref compared without case, before 2.102.0), which is why 2.102.0 is the
minimum; the advisories are listed under
[Verifying a release](../SECURITY.md#verifying-a-release). Only releases published after provenance was
added carry an attestation: for an older one, such as `v0.1.0-482fd9c`, set
`provenance=no` (`$provenance = $false` on Windows) and rely on the checksum.

On Linux, from a release (`<tag>` is the release tag, for example
`v0.1.0-1a2b3c4`; `uname -m` picks the platform):

```sh
(
  set -eu
  base=https://github.com/Frogbyte-io/fleet-manager/releases/download/<tag>
  provenance=yes
  asset="fleetctl-linux-$(uname -m)"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cd "$tmp"
  curl -fsSLO "$base/$asset"
  curl -fsSLO "$base/SHA256SUMS"
  grep "  $asset\$" SHA256SUMS | sha256sum --check --strict -
  if [ "$provenance" = yes ] && command -v gh >/dev/null 2>&1; then
    gh_version="$(gh --version | sed -n '1s/^gh version \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\) (.*/\1/p')"
    if [ "$(printf '%s\n' 2.102.0 "$gh_version" | sort -V | head -n 1)" != 2.102.0 ]; then
      echo "gh ${gh_version:-of unknown version} is older than 2.102.0; nothing was installed" >&2
      exit 1
    fi
    gh attestation verify "$asset" --repo Frogbyte-io/fleet-manager \
      --signer-workflow Frogbyte-io/fleet-manager/.github/workflows/release.yml \
      --source-ref refs/heads/main
  else
    echo "Provenance check skipped; installing on the checksum alone." >&2
  fi
  chmod 0755 "$asset"
  "./$asset" --version
  install -D -m 0755 "$asset" ~/.local/bin/fleetctl
)
```

Or from the controller (it answers 404 if it does not carry this platform):

```sh
(
  set -eu
  url=http://controller.example.ts.net:8080
  platform="linux-$(uname -m)"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cd "$tmp"
  curl -fsSLo fleetctl "$url/downloads/fleetctl/$platform"
  curl -fsSLo fleetctl.sha256 "$url/downloads/fleetctl/$platform.sha256"
  sha256sum --check --strict fleetctl.sha256
  chmod 0755 fleetctl
  ./fleetctl --version
  install -D -m 0755 fleetctl ~/.local/bin/fleetctl
)
```

`sha256sum` must print `OK`. Make sure `~/.local/bin` is on your `PATH`.

On Windows, in PowerShell. The block downloads from a release; the
commented lines switch it to a controller that carries a Windows build (the
controller image does not ship one):

```powershell
& {
  $ErrorActionPreference = 'Stop'
  $base = 'https://github.com/Frogbyte-io/fleet-manager/releases/download/<tag>'
  $binaryUrl = "$base/fleetctl-windows-x86_64.exe"
  $sumsUrl = "$base/SHA256SUMS"
  $provenance = $true
  # From a controller instead (its copy has no attestation):
  # $url = 'http://controller.example.ts.net:8080'
  # $binaryUrl = "$url/downloads/fleetctl/windows-x86_64"
  # $sumsUrl = "$binaryUrl.sha256"
  # $provenance = $false
  $dir = "$env:LOCALAPPDATA\Programs\fleet"
  $tmp = Join-Path ([IO.Path]::GetTempPath()) 'fleetctl-download.exe'
  $sums = Join-Path ([IO.Path]::GetTempPath()) 'fleetctl-download.sha256'
  Invoke-WebRequest -UseBasicParsing $binaryUrl -OutFile $tmp
  Invoke-WebRequest -UseBasicParsing $sumsUrl -OutFile $sums
  $line = Get-Content $sums |
    Where-Object { $_ -match '  fleetctl(-windows-x86_64)?\.exe$' } |
    Select-Object -First 1
  Remove-Item $sums
  $expected = "$line".Split(' ')[0]
  if ($expected -notmatch '^[0-9a-f]{64}$' -or (Get-FileHash $tmp -Algorithm SHA256).Hash -ne $expected) {
    Remove-Item $tmp
    throw 'fleetctl checksum mismatch; nothing was installed'
  }
  if ($provenance -and (Get-Command gh -ErrorAction SilentlyContinue)) {
    $ghVersion = "$(gh --version | Select-Object -First 1)" -replace '^gh version (\d+\.\d+\.\d+) \(.*$', '$1'
    if (-not ($ghVersion -as [version]) -or [version]$ghVersion -lt [version]'2.102.0') {
      Remove-Item $tmp
      throw "gh $ghVersion is older than 2.102.0; nothing was installed"
    }
    gh attestation verify $tmp --repo Frogbyte-io/fleet-manager `
      --signer-workflow Frogbyte-io/fleet-manager/.github/workflows/release.yml `
      --source-ref refs/heads/main
    if ($LASTEXITCODE -ne 0) { Remove-Item $tmp; throw 'fleetctl provenance check failed; nothing was installed' }
  } else {
    Write-Warning 'Provenance check skipped; installing on the checksum alone.'
  }
  & $tmp --version
  if ($LASTEXITCODE -ne 0) { Remove-Item $tmp; throw 'fleetctl did not run; nothing was installed' }
  New-Item -ItemType Directory -Force $dir | Out-Null
  Move-Item -Force $tmp "$dir\fleetctl.exe"
}
```

Then add that directory to your user `PATH`. On Windows, `fleetctl status`
without `--url` reports that the local `fleetd` surface is unavailable; every
other command talks to the controller.

Finally, tell `fleetctl` where the controller is. It takes the URL from the
first of these that is set: `--url <controller>` on the command line, the
`FLEET_URL` environment variable, then `url` in the config file
`$XDG_CONFIG_HOME/fleet/config.toml` (or `~/.config/fleet/config.toml` when
`XDG_CONFIG_HOME` is unset or not absolute; `%APPDATA%\fleet\config.toml` on
Windows). Set it once per login:

```sh
(
  set -eu
  case "${XDG_CONFIG_HOME:-}" in
    /*) fleet_config="$XDG_CONFIG_HOME/fleet" ;;
    *) fleet_config="$HOME/.config/fleet" ;;
  esac
  mkdir -p "$fleet_config"
  printf 'url = "http://controller.example.ts.net:8080"\n' > "$fleet_config/config.toml"
  fleetctl --output json system   # client.urlSource is "config"
)
```

Or export `FLEET_URL=http://controller.example.ts.net:8080` in the login's
environment; it takes precedence over the file.

`fleetctl --output json system` shows the controller's version and which
source supplied the URL.
