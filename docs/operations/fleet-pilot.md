# Pilot: Fleet on a few Linux developer machines

How to run Fleet on a handful of your own Linux developer machines: enroll them, roll out the built-in `fleet` skill, let agents on them use the Registry, and keep the controller reachable only by you while authentication (M8) is missing.

Examples use placeholders: the controller is `controller.example.ts.net`, the pilot machines are `dev-1` and `dev-2`, their login is `dev`, and the operator is `you@example.com`. Every command is `fleetctl`; `fleetctl <command> --help` prints its usage.

## Scope

- **In scope:** Linux x86_64 Debian or Ubuntu machines, the primary target in the [supported platform baseline](../PLAN.md#supported-platform-baseline).
- **Out of scope:** Windows workstations (milestone M12, epic [#606](https://github.com/Frogbyte-io/fleet-manager/issues/606)), macOS (deferred), and Linux aarch64 (deferred).
- **Few machines, all yours.** Enroll only machines whose compromise you could accept. The [security section](#restrict-access-first) explains why.

## Prerequisites

- **A controller** on a Linux host in your tailnet, deployed with [deploy/README.md](../../deploy/README.md) or [deploy/COOLIFY.md](../../deploy/COOLIFY.md), with its master key (`FLEET_MASTER_KEY_FILE`) set so it can store secrets.
- **`fleetctl` built from the same commit as the controller** (`cargo build --release -p fleetctl`, then copy `target/release/fleetctl` into your `PATH`). There is no published `fleetctl` package yet. `fleetctl --url <controller> --output json system` shows the controller's version.
- **Each pilot machine** runs Debian or Ubuntu on x86_64, is joined to your tailnet, runs an OpenSSH server, and has `curl`, `sha256sum`, `base64`, and `jq`. Without `jq`, a rollout that updates an existing skill fails closed.
- **One login per machine for agents.** Skills Manager and the skills it deploys live in the SSH login's home directory. Use the account your coding agents run as (`dev` here).
- **SSH from the controller.** That login accepts a key the controller can present: `--auth agent` offers the keys in the controller's ssh-agent, then its default key files ([which keys](lab.md#which-keys-the-controller-offers)); `--auth identity-file --identity <path>` names a key file on the controller.
- **For `fleetd` only:** the SSH login is root or has passwordless `sudo`. If you do not want that on a pilot machine, keep it agentless; every step in this guide works without `fleetd`.
- **A Fleet Git repository** for desired state and the Registry, configured and activated once. Drift checks and Registry reads need an active revision. See [desired state](../architecture/desired-state.md) and the [Registry workflow](../guides/registry-workflow.md).

  ```sh
  fleetctl desired source credential < git-token.txt   # prints a reference; the token is read from stdin
  fleetctl desired source set <remote> --credential <ref>
  fleetctl desired fetch <commit-sha> --wait
  fleetctl --output json desired history                # the fetched commit and its contentDigest
  fleetctl desired activate <commit-sha> <content-digest> --wait
  ```

The commands below carry no global `--url` (the prerequisite check above passes it because no URL is configured yet). `fleetctl` takes the controller URL from the first of these that is set:

1. `--url <controller>` on the command line;
2. the `FLEET_URL` environment variable;
3. `url` in the config file `$XDG_CONFIG_HOME/fleet/config.toml`, or `~/.config/fleet/config.toml` when `XDG_CONFIG_HOME` is unset or not an absolute path (`%APPDATA%\fleet\config.toml` on Windows);
4. the default, `http://127.0.0.1:8080`.

Set it once on your own workstation:

```sh
# The directory fleetctl reads: an absolute XDG_CONFIG_HOME, otherwise ~/.config.
case "${XDG_CONFIG_HOME:-}" in
  /*) fleet_config="$XDG_CONFIG_HOME/fleet" ;;
  *) fleet_config="$HOME/.config/fleet" ;;
esac
mkdir -p "$fleet_config"
printf 'url = "http://controller.example.ts.net:8080"\n' > "$fleet_config/config.toml"
fleetctl --output json system   # client.urlSource is "config"
```

The URL must be `http` or `https` and must not contain a user name or password. A delegated credential goes in `FLEET_TOKEN`, never in the URL. `fleetctl` reads only the `url` key and ignores other keys. `system` reports which source supplied the URL in `client.urlSource` (`flag`, `env`, `config`, or `default`). `status` asks the local `fleetd` socket unless you pass `--url`. `FLEET_URL` and the config file do not change that.

## Restrict access first

**Before M8 there is no login. Anyone who can reach the controller is an administrator.** In trusted-LAN mode every caller, whether a browser, `fleetctl`, or an agent, acts as `anonymous-lan-admin`, which holds every permission. That includes running commands on enrolled machines, approving its own action requests, and reading the audit log ([security.md](../architecture/security.md#initial-trusted-lan-principal)). Network reachability is the only boundary.

> **Warning.** Until M8 lands ([#602](https://github.com/Frogbyte-io/fleet-manager/issues/602), [#603](https://github.com/Frogbyte-io/fleet-manager/issues/603), [#604](https://github.com/Frogbyte-io/fleet-manager/issues/604), [#605](https://github.com/Frogbyte-io/fleet-manager/issues/605)), do not enroll a machine whose compromise you cannot accept. A person or process that reaches the controller can run commands on every enrolled machine. An agent on a pilot machine can do the same through `fleetctl`, so prompt injection in one agent reaches the whole fleet. Do not enroll production servers, shared machines, or machines with credentials you could not rotate.

### Limit the controller to your own devices

Keep the controller's listener on loopback (the default) and expose it on the tailnet with Tailscale Serve, as [deploy/COOLIFY.md](../../deploy/COOLIFY.md#private-access-and-node-communication) describes. The `http://...:8080` endpoint is required because `fleetd` accepts only `http://` with an explicit port:

```sh
tailscale serve --bg --http=8080 http://127.0.0.1:8080
tailscale serve --bg --https=443 http://127.0.0.1:8080
```

Then let only your own devices reach those ports. Tag the controller host (`tag:fleet-controller`) and each pilot machine (`tag:fleet-pilot`), and remove any allow-all rule from the tailnet policy. A policy fragment:

```jsonc
{
  "tagOwners": {
    "tag:fleet-controller": ["you@example.com"],
    "tag:fleet-pilot": ["you@example.com"]
  },
  "grants": [
    // Your devices (browser, fleetctl) and the pilot machines (fleetd, the fleet skill) reach the controller.
    { "src": ["you@example.com", "tag:fleet-pilot"], "dst": ["tag:fleet-controller"], "ip": ["tcp:443", "tcp:8080"] },
    // The controller reaches only the tagged pilot machines over SSH, not every device you own.
    { "src": ["tag:fleet-controller"], "dst": ["tag:fleet-pilot"], "ip": ["tcp:22"] }
  ],
  "tests": [
    { "src": "you@example.com", "accept": ["tag:fleet-controller:443", "tag:fleet-controller:8080"] },
    { "src": "tag:fleet-pilot", "accept": ["tag:fleet-controller:443", "tag:fleet-controller:8080"] },
    { "src": "tag:fleet-controller", "accept": ["tag:fleet-pilot:22"] },
    { "src": "teammate@example.com", "deny": ["tag:fleet-controller:443", "tag:fleet-controller:8080"] }
  ]
}
```

Tagging a machine replaces its user ownership in Tailscale, so rules that matched it as one of your devices (Tailscale SSH, for example) need the tag added. This narrows who can reach the controller to you and the pilot machines. Every process on your devices still can, and still acts as administrator. Never publish the controller on the Internet.

### Optional: Tailscale Serve identity mode

Identity mode ([ADR 0010](../adr/0010-tailscale-serve-identity.md)) adds a loopback listener that accepts only requests Tailscale Serve forwards with a user identity, and audits requests under that Tailscale login instead of `anonymous-lan-admin`. Set `FLEET_TAILSCALE_SERVE_LISTEN=127.0.0.1:8081`, keep `FLEET_LISTEN` on loopback, run the controller as a host process or with `deploy/compose.tailscale.yaml` (the default bridged Compose deployment cannot use it), and point Serve at the identity listener:

```sh
tailscale serve --http=8080 off
tailscale serve --bg --https=443 http://127.0.0.1:8081
tailscale serve status
```

Remove the trusted-LAN `--http=8080` route first, and check `tailscale serve status` lists only the identity listener. Serve forwards to loopback, so any route left pointing at `127.0.0.1:8080` keeps the anonymous administrator listener reachable from the tailnet and bypasses identity mode. Drop the `tag:fleet-pilot` → controller grant and the `tcp:8080` port from the policy as well.

Know what it does not do:

- **Every Tailscale user it admits is still a full administrator.** It identifies people for the audit log. It does not authorize per user.
- **It blocks remote `fleetd`.** The node routes become host-local, so pilot machines stay agentless in this mode ([deploy/README.md](../../deploy/README.md)).
- **Tagged devices have no user identity** and are refused. The pilot machines are tagged (`tag:fleet-pilot`), so in identity mode neither `fleetd` nor the agents on them can reach the controller. Use identity mode only when the agents you pilot run on your own untagged devices; to pilot agents on the tagged machines, stay in trusted-LAN mode behind the policy above.

Delegated credentials ([ADR 0011](../adr/0011-delegated-lab-credentials.md), `fleetctl credentials issue`) narrow a caller to Lab leases on allowed templates. They do not restrict machine, skill, or Registry access, and anonymous callers stay administrators.

## Enroll a machine

### Agentless onboarding

The controller connects over SSH. You confirm the host key yourself.

```sh
fleetctl --output json machines onboard create --user dev --host dev-1.example.ts.net --name dev-1 --tag pilot --auth agent
fleetctl --output json machines onboard test <draft-id> --wait
fleetctl --output json machines onboard get <draft-id>
```

`onboard get` shows the host key fingerprints the machine presented. Compare one with the machine's own fingerprint, read on the machine itself (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`), and confirm only an exact match:

```sh
fleetctl --output json machines onboard confirm <draft-id> --fingerprint SHA256:<fingerprint>
fleetctl --output json machines onboard discover <draft-id> --wait
fleetctl --output json machines onboard add <draft-id>
fleetctl --output json machines list --tag pilot
fleetctl --output json machines get <machine-id>
```

`machines get` lists the machine's `endpoints`. The skill commands below take that endpoint id as `--endpoint`. The console's Add Machine flow does the same steps.

### Optional: install `fleetd`

`fleetd` keeps a live, outbound connection to the controller, so the machine reports `connected` instead of `agentless`. It needs root or passwordless `sudo` on the SSH login, and the controller's `http://` URL with its port. It is not available in identity mode.

```sh
fleetctl --output json machines install-node <machine-id> --endpoint <endpoint-id> --auth agent --controller-url http://controller.example.ts.net:8080 --wait
fleetctl --output json machines get <machine-id>
```

The controller picks the package from its own store, the machine checks its SHA-256, and the single-use enrollment token never touches the machine's disk or process list. A failed install removes what it created and leaves the agentless endpoint working ([deploy/fleetd/README.md](../../deploy/fleetd/README.md)).

## Skills Manager

Fleet deploys skills only through the Skills Manager CLI, pinned to `skills-manager-cli` 1.40.0. Another version is reported as unsupported.

Once [#600](https://github.com/Frogbyte-io/fleet-manager/issues/600) lands, onboarding and `fleetd` install will install Skills Manager automatically; `FLEET_SKILLS_MANAGER_AUTO_INSTALL` will turn that off. Until then, install `skills-manager-cli` 1.40.0 manually, or run a pinned `skills probe`. A pinned probe installs the release only when no CLI is present: it downloads the binary on the machine, checks the SHA-256, and places it in the login's `~/.local/bin`:

```sh
fleetctl --output json skills probe <machine-id> --endpoint <endpoint-id> --auth agent \
  --artifact-url https://github.com/xingkongliang/skills-manager/releases/download/v1.40.0/skills-manager-cli-Linux-x64 \
  --artifact-sha256 6edb154b290803cd652fa047cac2d980fd94dc75c1f16bd9acb7a0536544e61b \
  --wait
fleetctl --output json skills list <machine-id>
```

The digest is the one recorded in [docs/research/fixtures/README.md](../research/fixtures/README.md). To install by hand instead, put the same binary at `~/.local/bin/skills-manager-cli` for the agent login, make it executable, and run the probe without the two artifact flags. `skills list` should report `availability: available` and `cliVersion: 1.40.0`.

## Roll out the `fleet` skill and check drift

The controller ships the `fleet` skill as the catalog entry `builtin-fleet` ([ADR 0012](../adr/0012-builtin-skills.md)). Each controller release publishes a new immutable version. By default it is assigned to every machine for the `claude_code` and `codex` agents. A `SkillPreset` in Fleet Git can narrow or remove that assignment.

Find the current version, preview the rollout, then run it:

```sh
fleetctl --output json skills catalog versions builtin-fleet
fleetctl --output json skills catalog plan --request-json '{"versionId":"builtin-fleet@<sha256>","machineId":"<machine-id>","endpointId":"<endpoint-id>","auth":{"type":"agent"},"agents":["claude_code","codex"],"timeoutSeconds":300}'
fleetctl --output json skills catalog rollout --request-json '{"versionId":"builtin-fleet@<sha256>","machineId":"<machine-id>","endpointId":"<endpoint-id>","auth":{"type":"agent"},"agents":["claude_code","codex"],"timeoutSeconds":300}'
fleetctl --output json operations get <operation-id>
```

Follow the operation until its `state` is `succeeded` or `failed`. The console's Skills page does the same rollout.

Check drift after the rollout, and again after each controller upgrade:

```sh
fleetctl --output json skills probe <machine-id> --endpoint <endpoint-id> --auth agent --wait
fleetctl --output json skills matrix
fleetctl --output json plan <machine-id>
```

The probe refreshes the machine's observed inventory, and `skills matrix` shows it for every machine. `plan` compares the machine with the active Fleet Git revision, including the default `fleet` assignment. A plan with no steps means no drift. To converge, review the plan and run `fleetctl apply-plan <machine-id> --plan-id <id> --endpoint <endpoint-id> --auth agent --wait`, or roll out again. Do not edit agent skill directories or Skills Manager files by hand.

## Agents and the Registry

Agents use the `fleet` skill, which drives `fleetctl --output json`. Each pilot machine needs `fleetctl`, and it must reach the controller. The skill's commands carry no `--url`, so give the agent login a config file that names the controller.

Copy the `fleetctl` binary you built (see the prerequisites) to the pilot machine first, for example with `scp target/release/fleetctl dev-1:/tmp/fleetctl`. Then, on the pilot machine, as the agent login:

```sh
install -D -m 0755 /tmp/fleetctl ~/.local/bin/fleetctl && rm /tmp/fleetctl
# The directory fleetctl reads: an absolute XDG_CONFIG_HOME, otherwise ~/.config.
case "${XDG_CONFIG_HOME:-}" in
  /*) fleet_config="$XDG_CONFIG_HOME/fleet" ;;
  *) fleet_config="$HOME/.config/fleet" ;;
esac
mkdir -p "$fleet_config"
printf 'url = "http://controller.example.ts.net:8080"\n' > "$fleet_config/config.toml"
fleetctl --output json system
```

`FLEET_URL=http://controller.example.ts.net:8080` in the agent's environment also works and takes precedence over the file. The file is simpler because every shell and agent harness under that login reads it. Machine setup does not write this file yet.

`system` shows the controller version, the trust mode, and the principal you act as. In trusted-LAN mode that principal is `anonymous-lan-admin`. In identity mode, use the Serve URL (`https://controller.example.ts.net`) from your own untagged devices, and the principal is your Tailscale login; tagged pilot machines are refused there.

An agent looks things up before it asks you:

```sh
fleetctl --output json registry find <text>
fleetctl --output json registry get domain/example.com
fleetctl --output json registry list --type service
```

Reads come from the controller's active revision. Edits (`registry set`, `relate`, `validate`, `publish`) change YAML in a local checkout of Fleet Git and need push access from that machine. For the pilot, keep `registry.changeMode` at its default, `pull-request`, so an agent's edit arrives as a pull request you review (`fleetctl --output json desired settings`). The Registry never holds secrets. A `loginAt` field says where a login lives, never what it is. See the [Registry workflow](../guides/registry-workflow.md).

## Remove a machine or roll back

- **Remove the skill** from the agents, then from the machine's library:

  ```sh
  fleetctl --output json skills undeploy <machine-id> --skill fleet --agent claude_code --agent codex --endpoint <endpoint-id> --auth agent --wait
  fleetctl --output json skills remove <machine-id> --reference fleet --yes --endpoint <endpoint-id> --auth agent --wait
  ```

  Use the skill id that `skills list` reports. If Fleet Git still assigns the skill, add a `SkillPreset` with an empty `deployTo` for it, or the machine shows drift again.
- **Revoke `fleetd`** if you keep the machine but want its node gone. This revokes the node identity with every credential and session, as the console's Connections tab (**Revoke node**) does; `fleetd` cannot connect again until it is enrolled again:

  ```sh
  fleetctl --output json nodes revoke <machine-id> --yes
  ```

- **Remove the machine.** `machines remove` reviews first, then removes the machine record with its endpoints, facts, node identity, recorded skill installs, project checkouts and Skills Manager snapshot. It revokes the keys Fleet holds for the machine and unpins the machine's SSH host keys, unless another machine or an onboarding draft uses the same host. The audit trail and finished operations stay. Add `--uninstall` to run `deploy/fleetd/uninstall.sh --purge` over SSH first; if the uninstall fails, the machine is not removed. Without it, nothing on the machine is touched:

  ```sh
  fleetctl --output json machines remove <machine-id> --review-only
  fleetctl --output json machines remove <machine-id> --uninstall --endpoint <endpoint-id> --yes
  ```

  The review lists each blocker with what to do: a Lab provision (for a leased guest, destroy the lease, or retry a failed cleanup with `lab cleanup-retry`; for a pool member or an unleased provision, drain it with `lab pool drain <pool-id> --vmid <vmid>`; Lab's cleanup then removes the machine), a persistent marker (`machines persistent unregister`, or the reviewed destroy for a VM Fleet created), a USB device the machine holds (`machines usb detach`), an operation that has not finished, or, on a controller running without its secret store, stored keys or passwords it could not revoke. The review also counts the stored SSH keys and Windows administrator passwords the removal deletes, and warns before a stored administrator password is destroyed. `--uninstall` uses the install layout of the machine's last successful `machines install-node`, and fails when no fleetd unit or binary is found there. Removing needs `machine.delete`, which no delegated credential has.

  Without `--uninstall`, remove the service on the machine yourself, as `deploy/fleetd/uninstall.sh --purge` does:

  ```sh
  sudo systemctl disable --now fleetd
  sudo rm -f /etc/systemd/system/fleetd.service /etc/default/fleetd /usr/local/bin/fleetd
  sudo systemctl daemon-reload
  sudo rm -rf /var/lib/fleetd
  ```

  The `fleet` system account stays either way; remove it with `sudo userdel fleet` if you want.
- **Cut agentless access.** Remove the controller's key from the login's `~/.ssh/authorized_keys`. For a machine you keep, also clear any stored endpoint credential (`fleetctl machines endpoint-auth clear <machine-id> <endpoint-id>`; see [machine access](machine-access.md#revoke-access)); `machines remove` revokes the machine's own stored keys itself.
- **Remove Skills Manager** if Fleet installed it: delete `~/.local/bin/skills-manager-cli`. Its library and agent skill directories belong to Skills Manager, so remove skills through it first.
- **Roll back a Fleet Git change**: `fleetctl desired rollback <commit-sha> <content-digest> --wait`.

## What to report back

Open an issue in this repository for each finding. Scrub hostnames, IPs, user names, and secrets first, because the repository is public.

- Each step that failed or needed a manual workaround, with the `fleetctl` command, the operation id, and its error code.
- How long onboarding, `fleetd` install, the Skills Manager probe, and the first rollout took per machine.
- Drift that stayed after a rollout or `apply-plan`, with the `plan` output.
- Whether agents used the `fleet` skill correctly: Registry lookups, edits that arrived as pull requests, and commands they tried that do not exist.
- Anything that made the access restrictions above hard to keep, and any action you wanted to restrict to a single person or agent.
