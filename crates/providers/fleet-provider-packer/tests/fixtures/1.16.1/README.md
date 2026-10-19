# Packer machine-readable contract fixtures (1.16.1)

Real `packer -machine-readable` transcripts, captured on 2026-10-06 in the
Fleet development environment against the pinned toolchain from
[ADR-0005](../../../../../../docs/adr/0005-provider-and-external-cli-boundaries.md)
and `docs/research/ecosystem.md` ("Image building"):

- Packer v1.16.1 (release commit `8d3617fc`, inside the pinned
  `>= 1.15 < 2` range), checksum-verified against the published
  `packer_1.16.1_SHA256SUMS`
- `packer-plugin-proxmox` v1.2.4 (installed via `packer init`, inside the
  pinned `>= 1.2.4 < 2` range), verified against the plugin release
  `SHA256SUMS`

The scenario recipes were `proxmox-clone` templates written with the
fixture constants from the issue (`192.0.2.10`, `pve1`,
`fleet@pve!fixture`, `<redacted>`); no live endpoint tokens were ever
entered. `192.0.2.x` is TEST-NET-1 (RFC 5737).

## Files and exact commands (run with Packer 1.16.1)

| Fixture | Command | Exit |
|---|---|---|
| `version.txt` | `packer -machine-readable version` | 0 |
| `plugins-installed.txt` | `packer -machine-readable plugins installed` | 0 |
| `validate-valid.txt` | `packer -machine-readable validate valid.pkr.hcl` | 0 |
| `validate-invalid.txt` | `packer -machine-readable validate invalid.pkr.hcl` | 1 |
| `build-interrupted.txt` | `packer -machine-readable build valid.pkr.hcl`, process interrupted (SIGTERM) mid-build | not recorded |

The recipes for the validate/build scenarios packed a `packer {}` block
pinning `required_version >= 1.15.0, < 2.0.0` and the
`github.com/hashicorp/proxmox` plugin `>= 1.2.4, < 2.0.0`, plus one
`proxmox-clone` source (fixture constants above) and a shell provisioner;
`invalid.pkr.hcl` differs only in two wrong-typed attribute values
(`clone_vm_id` and `cores` as strings), so `validate` reports two
`Incorrect attribute value type` errors.

## Normalizations and redactions

The transcripts are byte-verbatim captures of the streams above except
for these documented substitutions, applied to every file:

1. **Timestamps**: each epoch stamp is normalized to the fixed dateline
   `1791542400` (2026-10-09T10:40:00Z), preserving every intra-transcript
   delta (the `build-interrupted.txt` cancel→errored gap is the real 7
   seconds). The capture date is recorded above.
2. **Local path**: the plugin-path message elides the local account:
   `/home/dev/.packer.d/...` became `~/.packer.d/...`. The path is the
   only local value Packer echoes in this scenario set.

No other bytes are changed. No private IPs, real hostnames, node names,
token IDs, token values, or credential material appear anywhere in these
fixtures; the recipe's `token` placeholder never reached any stream, and
nothing else in this scenario set echoes local values.

## What this set covers, and what it does not

`version`, `plugins installed`, both `validate` outcomes, and an
interrupted build are recorded here, and
[fixtures.rs](../../fixtures.rs) contract-tests the parser against every
byte. The interrupted transcript is a graceful-cancel record: Packer's
signal handler announces the cancellation, reports the build errored
from the (here unreachable) PVE API's connect timeout, and finishes with
its "Cleanly cancelled" line.

The issue's success-build and bad-VMID scenarios need a live
Proxmox endpoint; this environment has none (every build shows exactly
the connect-timeout symptom recorded here, coerced by the capture
timeout's interrupt). Capturing those two, plus a SIGINT-shaped
interrupt and re-transcribing them against the integration host from
[docs/operations/proxmox-test-cluster.md](../../../../../../docs/operations/proxmox-test-cluster.md),
is the remaining work of FM-703 and feeds the FM-704 suite.
