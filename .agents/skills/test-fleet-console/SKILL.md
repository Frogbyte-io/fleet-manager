---
name: test-fleet-console
description: Verify a Fleet Console (apps/web) change in a real browser against an isolated controller, capture screenshots, and publish them as PR evidence. Use for every GUI change — pages, components, styles, layout, copy, or theme — before opening or updating a PR.
---

# Test Fleet Console

A GUI change is done when a screenshot shows it working, not when the tests pass. Run the change against an isolated controller, drive it in a browser, capture evidence, and attach that evidence to the PR.

Design rules live in `DESIGN.md` and `bootstrap/fleet-console-labs/SKILL.md`; read them before judging what you see.

## 1. Start an isolated controller

The web app calls the API on its own origin (`/api/v1`) and Vite has no proxy, so the controller serves the built web app. Do not use `pnpm dev` for verification.

```bash
pnpm install --frozen-lockfile
pnpm --filter @frogbyte-io/fleet-web build

EVID=$(mktemp -d)                       # scratch dir: data + screenshots
FLEET_LISTEN=127.0.0.1:18080 \
FLEET_DATA_DIR="$EVID/data" \
FLEET_WEB_DIST="$PWD/apps/web/dist" \
  cargo run -p fleet-controller -- serve
```

- Always set `FLEET_DATA_DIR` to a scratch directory. Never point at a real controller's data or reuse `./data`.
- Pick a free port; reuse a controller you already started for this task instead of starting another.
- After editing web code, rebuild (`pnpm --filter @frogbyte-io/fleet-web build`) and reload the page.
- Stop only the processes you started. Kill by the PID you recorded, never by name pattern.
- The trusted-LAN release has no login: the page loads directly at `http://127.0.0.1:18080/`.

## 2. Seed meaningful data

An empty database only shows empty states. Seed what the changed screen renders with `fleetctl --url http://127.0.0.1:18080 …` (see `fleetctl --help`), for example `projects create`, `skills catalog create`, `desired source set`, `lab create`.

Pages backed by a real remote host (machine onboarding, probes, Proxmox) need a reachable host. When none exists, say so in the PR and show the states the controller can produce (empty, loading, error) rather than fabricating machine data.

## 3. Drive it in the browser

With the T3 Browser panel tools:

1. `preview_status`, then `preview_open` if no tab exists.
2. `preview_navigate` to the changed route.
3. `preview_snapshot` with `save=true` to capture a PNG; the returned `screenshotPath` is the evidence file.
4. Exercise the interaction with `preview_click` / `preview_type` / `preview_press`, and snapshot again after each state that matters.

Without those tools, use any headless browser that produces PNGs (for example Playwright) at the same URLs.

Capture, for every changed screen:

- **Dark and light**: append `?theme=dark` and `?theme=light`.
- **Desktop and narrow**: `preview_resize` to about 1440×900 and to a phone preset; the sidebar collapses to a rail and a sheet.
- **Each state the change touches**: populated, empty, loading, error, open dialog or drawer, focus/hover on the new control.
- **Before and after** when the change alters an existing screen (check out `main` for the "before" build if needed).

Check the console for errors with `preview_snapshot` diagnostics; a screenshot with a red console does not count as proof. Run `pnpm --filter @frogbyte-io/fleet-web run lint && pnpm --filter @frogbyte-io/fleet-web run typecheck && pnpm --filter @frogbyte-io/fleet-web run test` alongside; the screenshots prove behavior, the tests guard it.

## 4. Screenshots are public: review before publishing

This repository is public. Open every PNG before uploading and confirm it contains none of: tokens, key material, private hostnames or IPs, tailnet names, user home paths, real machine names, or real project remotes. Re-seed with placeholder data and recapture if any appear. `AGENTS.md` bans secrets in fixtures and output; a screenshot is output.

## 5. Publish evidence to the PR

GitHub has no API for attaching images to a PR, so push them to the orphan branch `pr-evidence` and embed by commit-pinned URL. That branch holds only screenshots and never merges.

```bash
REPO=Frogbyte-io/fleet-manager
KEY="pr-<number-or-branch-slug>"        # one folder per PR
WT=$(mktemp -d)
git fetch origin pr-evidence 2>/dev/null || true
git branch -D pr-evidence 2>/dev/null || true   # drop a stale local branch from an earlier attempt
if git rev-parse --verify origin/pr-evidence >/dev/null 2>&1; then
  git worktree add -b pr-evidence "$WT" origin/pr-evidence
else
  git worktree add --detach "$WT" && (cd "$WT" && git checkout --orphan pr-evidence && git rm -rf . >/dev/null)
fi
mkdir -p "$WT/$KEY" && cp <your-pngs> "$WT/$KEY/"
(cd "$WT" && git add "$KEY" && git commit -m "evidence: $KEY")
# Push; if another agent pushed first, rebase onto the new tip and retry. The worktree stays until the push lands.
PUSHED=
for attempt in 1 2 3 4 5; do
  if (cd "$WT" && git push origin pr-evidence:pr-evidence); then PUSHED=1; break; fi
  (cd "$WT" && git fetch origin pr-evidence && git rebase origin/pr-evidence) || break
done
if [ -n "$PUSHED" ]; then
  SHA=$(git -C "$WT" rev-parse HEAD)
  git worktree remove --force "$WT" && git branch -D pr-evidence
  # embed: ![caption](https://github.com/$REPO/blob/$SHA/$KEY/<file>.png?raw=true)
else
  echo "push failed; screenshots are kept in $WT (branch pr-evidence), fix the error and rerun the push loop" >&2
fi
```

Never push to `refs/t3/checkpoints`, and never `git push --mirror`.

## 6. Write the proof into the PR

Add a `## Verification` section to the PR description (and update it on each push that changes the GUI):

- The routes and states exercised, each with its embedded screenshot and a one-line caption saying what it proves (dark/light, desktop/narrow, before/after).
- The commands run and their outcome: build, lint, typecheck, tests, and `cargo xtask verify` when Rust changed.
- What could not be verified and why (for example, no reachable host for a machine-backed page).

Claims without a screenshot or a command result are not proof. If a check failed, report the failure and its output.

## Cleanup

Stop the controller you started, delete the scratch directory, and remove temporary worktrees. Leave the screenshots on `pr-evidence`.
