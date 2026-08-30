# Fleet web shell

This package is the static Vue client served by `fleet-controller`. It currently
contains only the M0 shell; routes, API integration, state management, and
product features belong to later issues.

## Build contract

Run `pnpm --filter @frogbyte-io/fleet-web build` from the repository root. The
production files are emitted to `apps/web/dist/`. FM-008 may copy or embed that
directory without depending on Vite's internal build layout.
