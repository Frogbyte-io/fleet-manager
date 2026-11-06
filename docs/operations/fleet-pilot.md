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

In this guide, `fleetctl` stands for `fleetctl --url http://controller.example.ts.net:8080`. `fleetctl` has no environment variable or file for the URL. Pass `--url` yourself, or use the wrapper in [Agents and the Registry](#agents-and-the-registry).

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
    { "src": "tag:fleet-controller", "accept": ["tag:fleet-pilot:22"] },
    { "src": "teammate@example.com", "deny": ["tag:fleet-controller:443", "tag:fleet-controller:8080"] }
  ]
}
```

This narrows who can reach the controller to you. Every process on your devices still can, and still acts as administrator. Never publish the controller on the Internet.

### Optional: Tailscale Serve identity mode

Identity mode ([ADR 0010](../adr/0010-tailscale-serve-identity.md)) adds a loopback listener that accepts only requests Tailscale Serve forwards with a user identity, and audits requests under that Tailscale login instead of `anonymous-lan-admin`. Set `FLEET_TAILSCALE_SERVE_LISTEN=127.0.0.1:8081`, keep `FLEET_LISTEN` on loopback, run the controller as a host process or with `deploy/compose.tailscale.yaml` (the default bridged Compose deployment cannot use it), and point Serve at the identity listener:

```sh
tailscale serve --bg --https=443 http://127.0.0.1:8081
```

Know what it does not do:

- **Every Tailscale user it admits is still a full administrator.** It identifies people for the audit log. It does not authorize per user.
- **It blocks remote `fleetd`.** The node routes become host-local, so pilot machines stay agentless in this mode ([deploy/README.md](../../deploy/README.md)).
- **Tagged devices have no user identity** and are refused.

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

Agents use the `fleet` skill, which drives `fleetctl --output json`. Each pilot machine needs `fleetctl`, and it must reach the controller. Because the skill's commands carry no `--url`, a small wrapper in the agent login's `PATH` adds it:

Copy the `fleetctl` binary you built (see the prerequisites) to the pilot machine first, for example with `scp target/release/fleetctl dev-1:/tmp/fleetctl`, then on the pilot machine:

```sh
install -D -m 0755 /tmp/fleetctl ~/.local/libexec/fleetctl && rm /tmp/fleetctl
cat > ~/.local/bin/fleetctl <<'EOF'
#!/bin/sh
exec "$HOME/.local/libexec/fleetctl" --url http://controller.example.ts.net:8080 "$@"
EOF
chmod 0755 ~/.local/bin/fleetctl
fleetctl --output json system
```

`system` shows the controller version, the trust mode, and the principal you act as. In trusted-LAN mode that principal is `anonymous-lan-admin`. In identity mode, use the Serve URL (`https://controller.example.ts.net`) and the principal is your Tailscale login.

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
- **Revoke `fleetd`.** Use the machine page's Connections tab in the console (**Revoke node**). `fleetctl` has no revoke command yet. Then remove the service on the machine, as `deploy/fleetd/uninstall.sh --purge` does:

  ```sh
  sudo systemctl disable --now fleetd
  sudo rm -f /etc/systemd/system/fleetd.service /etc/default/fleetd /usr/local/bin/fleetd
  sudo systemctl daemon-reload
  sudo rm -rf /var/lib/fleetd
  ```

  The `fleet` system account stays; remove it with `sudo userdel fleet` if you want.
- **Cut agentless access.** Remove the controller's key from the login's `~/.ssh/authorized_keys`, and clear any stored endpoint credential (`fleetctl machines endpoint-auth clear <machine-id> <endpoint-id>`; see [machine access](machine-access.md#revoke-access)). The machine record stays in the inventory: there is no machine delete yet.
- **Remove Skills Manager** if Fleet installed it: delete `~/.local/bin/skills-manager-cli`. Its library and agent skill directories belong to Skills Manager, so remove skills through it first.
- **Roll back a Fleet Git change**: `fleetctl desired rollback <commit-sha> <content-digest> --wait`.

## What to report back

Open an issue in this repository for each finding. Scrub hostnames, IPs, user names, and secrets first, because the repository is public.

- Each step that failed or needed a manual workaround, with the `fleetctl` command, the operation id, and its error code.
- How long onboarding, `fleetd` install, the Skills Manager probe, and the first rollout took per machine.
- Drift that stayed after a rollout or `apply-plan`, with the `plan` output.
- Whether agents used the `fleet` skill correctly: Registry lookups, edits that arrived as pull requests, and commands they tried that do not exist.
- Anything that made the access restrictions above hard to keep, and any action you wanted to restrict to a single person or agent.
