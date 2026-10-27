# ADR 0018: Persistent machines are Fleet-managed VMs that Lab never selects

Status: Proposed

Proposed: 2026-10-22 (tracking issue [#489](https://github.com/Frogbyte-io/fleet-manager/issues/489)). Proposed for maintainer review. It composes the image pipeline ([ADR 0008](0008-durable-operations-and-lab-leases.md)), brokered SSH access with Fleet-held keys ([ADR 0017](0017-agent-ssh-access.md)) and the Windows guest transport ([ADR 0015](0015-windows-lab-guest-transport.md)); it reverses none of them.

## Context

Fleet makes guests only as Lab leases (cloned, then destroyed or reverted) and as image builds. A long-lived VM needed host-side `qm set` for the parts Fleet could not do, inherited the template's fixture tag (which fixture scripts treat as theirs to destroy), kept the image's shared SSH key and password, and lived in a throwaway controller. Two decisions are needed: how Fleet knows a guest is permanent, and what order protects reachability while the image's bootstrap credential is replaced.

## Decision

1. **A persistent marker, not a name.** `persistent_guests (account, VMID)` is written before the clone. Lab sweeps (inventory), pool membership, Lab cleanup and Lab's VMID choice consult it; the name rule (`fm-lab-*` refused for persistent names) is a second line only. The marker records whether the clone completed and guards a VMID only while it did or the guest there still has the marked name, so a stale marker (a failed clone) never shields another guest; an explicit, audited abandon drops one. The marker also makes creation resumable: a re-run finds its guest by (account, name) and adopts it instead of cloning twice.
2. **One reviewed create operation.** `machine.create` carries a spec of references and public keys (never secrets) and is created only through its dedicated review/create routes (the generic operations route refuses it, because its payload names credential references), with the FM-603 payload-bound review token and its own catalog entry (`machines.provision`). Image-based creation ships first; the ISO + unattend path is a separate issue because it needs an answer-file pipeline and an install runner.
3. **Guest config is an allow-listed reviewed action.** `proxmox.guest.config` (`proxmox.guest.config` in the catalog) can change tags, description, onboot, protection, cores and memory of a guest that is not a template, a promoted image artifact, a Lab clone or a pool member. The create saga writes through the same provider call. Tags are replaced as a whole, so the template's tags are never inherited; fixture and Lab tag prefixes are refused.
4. **Credential order.** Install the new key while the bootstrap credential works; verify a login with the new key; switch the endpoint's default auth (`MachineAccess::set_default_auth`); remove the image key over the new key; verify again. A failure before the switch leaves the bootstrap key working. An operator-held public key cannot be verified by Fleet, so the bootstrap credential is kept and the result says so. Generated keys are bound to the machine (`machines/ssh/<machine>/<id>`).
5. **Destroying is separate.** A destroy of a marked guest is refused unless the reviewed parameters carry `confirmPersistent`; the confirmation also lifts Proxmox protection (audited), and the marker goes when the guest does.
6. **Windows.** Persistent Windows machines come from the generalized base image (#452), never a Fleet clone image, which is specialized. The computer name is set by a fixed post-boot step. Activation sends the product key on SSH stdin only (output of `slmgr /ipk` discarded) and records the licence status as a machine fact; an activation failure fails only that step.

7. **Agents request; they do not provision (#496).** A restricted credential never holds `machines.provision`. It files an action request for `proxmox.machine.create` (the broker of [ADR 0016](0016-descriptive-registry-and-action-broker.md)) carrying the validated spec by reference. The class is `approve`; the operator may configure bounds (cores, memory, disk, image versions, nodes, storages, a per-principal count) inside which policy approves, and anything the request does not state or that falls outside waits for a person. The request's principal and purpose are stamped onto the spec and recorded by the executor on the persistent marker (never as a machine fact, which a node could forge); the executor otherwise runs unchanged; the broker re-checks the approver (or the requester and bounds) when the operation starts.

## Consequences

- The catalog gains two entries; delegated Lab credentials are refused both.
- The persistent controller must own the data: its database and master key are the machine's record, so temporary controllers are unsuitable (see `docs/operations/persistent-machines.md`).
- Machines created before the marker existed are not protected from Lab by it until they are registered (amendment 8 below).

## Amendment (#542)

8. **Registering an existing VM.** A VM that exists before Fleet keeps it (such as `win-gh-runner`) becomes persistent through a reviewed, audited registration, not a clone: `POST /machines/persistent/{account}/{vmid}/register/review` and `/register` (dedicated routes; the review token binds account, VMID and the optional machine id; `machines.provision`). A live guard requires a QEMU VM that is not a template, promoted image artifact, Lab clone (`fm-lab-` name) or Lab pool member, with no marker of its own VMID or name; a named machine must exist and not belong to another marker. The marker is written `cloned = true`, state `ready`, source `registered`, so Lab honours it at once. Nothing on the guest changes; protection, tags and credentials stay the operator's to change with `proxmox.guest.config` and key rotation. Listing is `GET /machines/persistent` (`machine.read`).
