# Skills Manager CLI captures

These are candidate provider contract fixtures captured on 2026-09-25 from
upstream release binaries. The filenames in the `Usage:` lines were normalized
by invoking each binary through a temporary `skills-manager-cli` symlink; the
help's trailing alignment whitespace was stripped. Commands and all other
output are unedited.

| Release | Linux x64 binary SHA-256 | Captures |
|---|---|---|
| [v1.34.2](https://github.com/xingkongliang/skills-manager/releases/tag/v1.34.2) | `cada91bf43947e762b8b47a54b31459c4c02affdf59a9d2e79f3ecd132e41132` | [`--version` and focused command help](skills-manager-cli-v1.34.2-help.txt); [JSON argument error](skills-manager-cli-v1.34.2-invalid-argument.json), [exit status](skills-manager-cli-v1.34.2-invalid-argument.exit) |
| [v1.40.0](https://github.com/xingkongliang/skills-manager/releases/tag/v1.40.0) | `6edb154b290803cd652fa047cac2d980fd94dc75c1f16bd9acb7a0536544e61b` | [`--version` and focused command help](skills-manager-cli-v1.40.0-help.txt); [JSON argument error](skills-manager-cli-v1.40.0-invalid-argument.json), [exit status](skills-manager-cli-v1.40.0-invalid-argument.exit) |

The JSON error capture comes from:

```sh
skills-manager-cli --json skills deploy --agent codex
```

The missing `<REFERENCES>...` argument is a parser error, so this probe exits
before initializing or writing Skills Manager state. It records the JSON-mode
error envelope and is safe to reuse in CLI contract tests. It is not a sample
success payload; the success DTOs are defined by the upstream versioned CLI
source.

At v1.40.0 the upstream release also publishes
`skills-manager-cli-Linux-arm64` with SHA-256
`377e3538ce74a13118ba0c30ebaaff597c7be4f0bb2bec2598ea0da27064a187`. This
spike checked the release metadata but executed only the x64 binary.
