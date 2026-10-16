# Registry edits: from push to active revision

This guide covers how a Registry edit in your Fleet Git repository reaches the
console, the controller settings that govern it, and a ready-made GitHub
Actions workflow that validates Registry changes on every pull request. See
[ADR 0016](../adr/0016-descriptive-registry-and-action-broker.md) for the
decisions behind it and the [desired-state architecture](../architecture/desired-state.md)
for the activation rules.

## How an edit becomes active

1. A person or agent commits a Registry change (`RegistryType` or
   `RegistryEntry` YAML) and pushes it, directly or through a pull request.
2. The controller fetches that commit as a candidate. A fetch is the
   `source.fetch` operation: it clones the commit, validates every document,
   and records the candidate only when it is valid.
3. If the candidate is valid and **every** difference from the active
   revision is a `RegistryType` or `RegistryEntry` resource, the controller
   activates it. Any other change (a `FleetConfig`, a machine, a skill
   assignment) waits for a manual `fleetctl desired activate`.
4. An invalid candidate never becomes active, and the last valid revision
   stays active.

Auto-activation has these guards you can rely on:

- **No active revision, no auto-activation.** The first activation is always
  manual.
- **Registry-only means all of it.** The candidate's resources are compared
  with the active snapshot; one added, removed, or changed resource of any
  other kind keeps the whole revision waiting. Every tracked file that
  differs between the active and candidate commits must also hold only
  `RegistryType`/`RegistryEntry` documents, in both versions: a changed
  non-YAML file, `fleet.yaml`, or a file mixing in other kinds keeps it
  waiting.
- **Never backwards.** The candidate commit must be a descendant of the active
  commit (`git merge-base --is-ancestor`, in the controller's own clone, no
  hooks). An older or diverged commit waits for manual activation.
- **Never over a concurrent change.** The write is a compare-and-set against
  the revision the decision was made on, and re-reads `registry.autoActivate`
  in the same serialized section. If the active revision changed meanwhile
  (for example a manual activation), the auto-activation is skipped and a
  `registry_auto_activation_skipped` audit event records why.
- **It is audited.** Each automatic activation is an audit event under the
  controller's own identity (`system:fleet-controller`), carrying the commit
  SHA, the previous commit, `authorizedAs`, and a count per kind (for example
  `RegistryEntry:+1/-0/~2`, meaning one added, none removed, two changed).
  Resource contents are never recorded. `authorizedAs` names the principal
  the authorizer decided on; today that is the trusted-LAN principal, so the
  authorization is nominal until the controller has a real system principal.

There are two ways a pushed commit reaches the controller.

### Fetch on push (a webhook or CI step)

`POST /api/v1/desired/fetch` is the fetch-now endpoint. It takes the full
40-character commit SHA, always fetches from the configured source remote,
and returns the operation to follow:

```bash
curl -fsS -X POST "$FLEET_URL/api/v1/desired/fetch" \
  -H "Authorization: Bearer $FLEET_TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"commitSha\": \"$GITHUB_SHA\"}"
```

The same operation is `fleetctl desired fetch <commit-sha> --wait`. A webhook
sender cannot reshape its payload, so call the endpoint from a small relay
or a CI job that has the pushed SHA. The caller needs the `source.fetch`
permission; give a webhook its own delegated credential rather than an
operator's.

### Periodic fetch

Set `FLEET_DESIRED_FETCH_INTERVAL_SECONDS` (TOML
`desired_fetch_interval_seconds`) on the controller. The default is `0`: off.
A non-zero value must be at least 30. Each tick resolves the remote's `HEAD`
and queues an ordinary `source.fetch` for it when it is not already fetched.
It never overlaps: while any `source.fetch` operation is pending or running
the tick does nothing, and a failed fetch is retried on the next tick. The
first tick runs one interval after the controller starts.

## Settings

Two settings live in the controller and are readable by `fleetctl` and agents:

| Setting | Values | Default | Meaning |
| --- | --- | --- | --- |
| `registry.autoActivate` | `true`, `false` | `true` | Activate Registry-only revisions without a manual step. |
| `registry.changeMode` | `direct`, `pull-request` | `pull-request` | How Registry edits should reach the default branch. |

`registry.changeMode` is advice. `fleetctl` and the `fleet` skill follow it
when they publish an edit. Fleet does not enforce it: the Git host's branch
protection does, and the controller never writes to Fleet Git.

```bash
fleetctl desired settings --output json
fleetctl desired settings set --auto-activate false
fleetctl desired settings set --change-mode direct
```

The same settings are on the console's Settings page under Desired state, and
`GET`/`PUT /api/v1/desired/settings` is the API. Reading needs the
`source.fetch` permission; changing needs the dedicated `source.settings`
permission, which delegated Lab credentials do not get. Every change is audited
as an intent before the write and an outcome record after it.

## Validate Registry changes in CI

[`registry-validate.workflow.yml`](registry-validate.workflow.yml) is a
GitHub Actions workflow for your Fleet Git repository (not this one). It runs
`fleetctl registry validate` on every pull request that touches YAML, so a
broken Registry entry is refused before it can merge, and the controller never
sees a candidate that would fail validation.

> `fleetctl registry validate` is delivered by FM-1013 and does not exist yet.
> The workflow is written against that planned command: it runs the same
> validator the controller runs over the checkout, and exits non-zero when any
> document has a diagnostic. Until FM-1013 lands, the workflow's validate step
> fails with "unknown command". Adjust the install step to however your
> runners obtain `fleetctl`.

To use it:

1. Copy the file to `.github/workflows/registry-validate.yml` in your Fleet
   Git repository.
2. Make `fleetctl` available to the job: set the `FLEETCTL_URL` and
   `FLEETCTL_SHA256` repository variables to a release binary you trust, or
   replace the install step with your own.
3. Require the `registry-validate` check in your branch protection. That is
   where the pull-request change mode is enforced.

The job reads only the repository checkout. It needs no controller URL and no
secret, and it must not be given one.
