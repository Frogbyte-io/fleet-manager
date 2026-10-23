# Persistent machines

A persistent machine is a long-lived VM that Fleet creates, registers and keeps. Lab leases are the opposite: cloned, used, destroyed. Decision record: [ADR 0018](../adr/0018-persistent-machines.md). This page is the operator guide for `fleetctl machines create`.

## Which controller

Persistent machines are **created and owned by the permanent controller**: the Compose-on-Coolify deployment in [`deploy/COOLIFY.md`](../../deploy/COOLIFY.md) with private ingress over Tailscale is the **reference setup**; `deploy/fleetd` (a host install) is the alternative. Register the Proxmox account in it (`fleetctl proxmox create`, `observe`, `confirm`). A trusted-LAN controller in `/tmp` or any controller whose data directory can disappear is **unsuitable**: the machine record, its endpoint, the host key it trusts and the SSH key Fleet generated live in that controller's database and master key. Lose them and the VM survives but Fleet can no longer reach it.

Back up the whole data volume and the master key separately, as `deploy/COOLIFY.md` ("Backup and recovery") describes, before creating machines you cannot recreate, and after creating them. A restore needs both: the generated private keys are encrypted under the master key.

## Create

Prerequisites: a promoted image version of a template with the QEMU guest agent and an SSH server, and a credential Fleet can log in with before it has its own key (the image's bootstrap key).

```
fleetctl machines create --account <account> --image-version <version> --name build-box \
  --cores 4 --memory 8192 --bootstrap-user root \
  --bootstrap-auth identity-file --bootstrap-identity /path/to/image-key
```

`--review-only` prints the spec as it will run and the review token without creating anything. The operation:

1. reserves the VMID (the next free one, or `--vmid`) and writes the **persistent marker**;
2. full-clones the promoted image's template (optionally `--node`, `--storage`);
3. waits for the clone's lock, grows the disk (`--disk`), and writes **one** allow-listed settings change: tags, description, `onboot` (default on), `protection` (default on), cores, memory, `net0` bridge, audio. The template's tags are never inherited; fixture and Lab tag prefixes are refused;
4. starts the guest and waits for the guest agent's IPv4 address;
5. registers the machine and its SSH endpoint, waits for SSH and records the host key: trust on first use with an audit event, or `--pin-fingerprint SHA256:...`, which fails the operation if the guest presents anything else;
6. links the guest to the machine;
7. rotates the credential (below), then, on Windows, the computer name, the administrator password and activation.

A failed run keeps the VM, the machine and the marker, and names the failing `step`. Run the same command again: it adopts the guest and continues. Nothing is deleted automatically.

### SSH key choice

- default / `--credential generate`: Fleet generates a per-machine ed25519 key. The private key is stored only in the encrypted secret store, bound to the machine (`machines/ssh/<machine>/<id>`); no API, CLI output, payload, log or audit event contains it.
- `--credential <reference>`: an existing Fleet SSH credential not bound to another machine.
- `--public-key '<line>'`: a key held outside Fleet. Fleet cannot log in with it, so it cannot verify it: it installs the key, **keeps** the bootstrap credential as the endpoint's default, and reports `bootstrapKeyRemoved: false`.
- `--login-user <user>`: a login user other than the image's, created if missing (needs a root bootstrap login on Linux).

Order for the first two: install the new key while the bootstrap credential works, verify a login with the new key, switch the endpoint's default auth, replace `authorized_keys` with only the new key over the new key, verify again. A failure before the switch leaves the bootstrap key working. Afterwards `fleetctl machines exec <machine> -- uname -a` uses the stored key.

### Windows

Persistent Windows machines must come from the **generalized base** (#452), never a Fleet clone image: clone images are specialized for Lab and carry no way to give each machine its own identity. Pass `--os windows`. The computer name is the machine name (at most 15 characters, validated) and is set by a post-boot step with a restart. The key goes to `administrators_authorized_keys` with its required ACL. `--admin-password store|discard` rotates the local administrator password to a value generated on the guest, stored as a Fleet secret or not kept at all (key login only).

Activation is optional; unactivated is a valid state.

- Product key: `fleetctl machines product-key store` (key on stdin) prints a reference; `--activate-key <reference>`. The key is stored encrypted, never returned by any API, and sent to the guest on the SSH session's **stdin** only; the output of `slmgr /ipk`, which echoes it, is discarded. Then `slmgr /ato`, and `SoftwareLicensingProduct.LicenseStatus` and `/xpr` are read back and recorded as the machine fact `windows/activation`.
- KMS: `--activate-kms <host[:port]>` (`slmgr /skms`).
- A failed activation (no internet, key in use, wrong edition) fails only that step, with Microsoft's error code; the VM stays created and registered. A retail key activates one machine at a time: to move it, deactivate the old machine first (`slmgr /upk`).

## Lab never selects it

The persistent marker (not the name) keeps the guest out of the Lab sweeper's inventory, Lab pools and Lab cleanup. Persistent names may not start with `fm-lab-`.

## Change settings and destroy

```
echo '{"description":"CI runner","tags":["ci"]}' | fleetctl proxmox config --account <a> --node <n> --vmid <v>
```

`proxmox config` accepts only tags, description, onboot, protection, cores and memoryMib, and refuses templates, promoted image artifacts, Lab guests and pool members. Destroying a persistent VM is a separate, confirmed act:

```
echo '{"protection":false}' | fleetctl proxmox config --account <a> --node <n> --vmid <v> --wait
fleetctl proxmox destroy <account> <node> <vmid> --confirm-persistent --wait
```

Then delete the machine record with `fleetctl machines` if it should go too.

## Not in this release

Creating from an ISO with an unattended install, LXC, cluster placement and HA, the console dialog, and listing persistent guests are separate work.
