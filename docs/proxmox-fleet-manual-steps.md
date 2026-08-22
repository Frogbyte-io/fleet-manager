# Manual steps — Proxmox fleet + frogenv setup

Things only you can do: physical console access, licensing, and a few
security-sensitive key ceremonies that shouldn't pass through an agent's
shell/transcript. Everything else (repo creation/transfer, npm publish, the
Proxmox adapter, template automation) happens during implementation with your
go-ahead at that point — it's not listed here.

Check items off in order; several later steps depend on earlier ones.

## 1. Proxmox host — done

- [x] `pveum acl modify / -token 'root@pam!agents' -role Administrator` — confirmed working, token now has full access.

## 2. Authorize an SSH key for the Proxmox host

We have no SSH access to `192.168.68.223` yet (confirmed by recon — both
`root` and `ananords` refused publickey auth). The API can do almost
everything, but template creation (disk import, cloud-init tweaks) and
emergency recovery are much easier with SSH.

- [ ] Open the Proxmox web UI (`https://192.168.68.223:8006`) → node `pve` →
      **Shell** (this is a browser-based console, no SSH needed to reach it).
- [ ] Generate a keypair for this purpose if you don't want to reuse an
      existing one, then paste the **public** key into
      `/root/.ssh/authorized_keys` via that Shell.
- [ ] Tell me once it's in place so I can verify a connection (I'll only ever
      use it for the fleet-manager/adapter work, never anything destructive
      without asking first).

## 3. Network bridge — needs physical console standby

The host currently has **no `vmbr*` bridge** — the only interface is `nic0`
(altname `enxa8a159157f99`, a **USB Ethernet dongle**). VMs can't reach the
LAN until a bridge exists over it.

**Risk:** this is the host's only network path. If the bridge config is
wrong, the box can drop off the network entirely, and recovery needs a
monitor+keyboard plugged directly into it (no IPMI/iKVM on this hardware).

- [ ] Have physical access to the machine (or be ready to walk over) before
      touching network config — don't do this remotely-only.
- [ ] Create `vmbr0` bridging `nic0` via the web UI (**pve → System → Network
      → Create → Linux Bridge**, bridge port `enxa8a159157f99`, carry over the
      existing IP config from `nic0` to the bridge) or hand it to me once your
      SSH key (step 2) is in place and I'll propose the exact commands for you
      to run at the console.
- [ ] Apply and confirm the host is still reachable at `192.168.68.223`
      before closing the physical session.

## 4. Acquire installer media

- [ ] **Windows 11 ISO** — must be obtained through your own Microsoft
      account/media creation tool; I can't fetch this for you (licensing).
      Also grab the **VirtIO driver ISO** (`virtio-win.iso`, needed for
      Windows to see the VM's virtio disk/NIC during install) from the
      Fedora-hosted VirtIO project.
- [ ] **Ubuntu Desktop 24.04 ISO** and **Bazzite ISO** — public downloads; if
      you give me the exact URLs you want used I can fetch/upload these to
      Proxmox's `local` storage for you (I won't guess download URLs myself).
- [ ] **Decision needed:** what should `dev-01` actually run? Its manifest
      just says `os: linux`, `lifecycle.mode: persistent` — no template. Pick
      a distro/ISO (e.g. Ubuntu Server 24.04) and let me know.

## 5. Interactive OS installs (your call — you chose manual installs)

Once ISOs are uploaded and the bridge exists, for each of `test-ubuntu`,
`test-bazzite`, `test-windows`, and `dev-01`:

- [ ] Create the VM (I can do this part via the API once the adapter exists).
- [ ] Open its **Console** (noVNC) in the Proxmox web UI and run through the
      installer by hand.
- [ ] **Windows only:** before shutting down for template conversion, run
      `sysprep /generalize /oobe /shutdown` inside the guest so the clone
      doesn't inherit a duplicate SID/machine identity.
- [ ] Shut the VM down cleanly when the install (and sysprep, for Windows) is
      done — I'll take it from there to convert to a template.

## 6. Physically connect the passthrough device

- [ ] Plug the `decker-controller` (Arduino, USB ID `2341:8036`) into the
      Proxmox host itself — it wasn't present in the last USB inventory, and
      it needs to be physically attached to that machine (not your
      workstation) for Proxmox USB passthrough to see it.

## 7. frogenv admin key ceremony

`frogenv init` generates an **offline admin/recovery age key** — its private
half is shown exactly once and must be stored somewhere durable outside any
git repo (password manager, etc.), since it's the ultimate recovery
mechanism if every machine's key is ever lost.

- [ ] Run `npx frogenv init` (or the local repo build, since 0.2.0 isn't
      published to npm yet — I'll tell you which when we get there)
      **yourself, in your own terminal**, not through me — this keeps the
      private key out of any agent transcript.
- [ ] Save the displayed admin private key somewhere durable immediately.
- [ ] Once `fleet-secrets` exists and `frogenv login` has run on your first
      workstation, run `frogenv machine approve <id> --groups workstation,infra`
      yourself for that first machine (bootstrapping needs one already-trusted
      machine to approve the rest — that first approval has to be you).

## 8. npm org for publishing `@frogbyte-io/fleet-manager`

- [ ] Confirm (or create) the `frogbyte-io` scope/org on npmjs.com.
- [ ] Run `npm login` on whichever machine will publish, so it has publish
      rights to that scope (I don't have npm credentials and won't ask for
      them).

---

Ping me after each numbered section and I'll pick up the automatable half
immediately rather than you waiting to do the whole list before we continue.
