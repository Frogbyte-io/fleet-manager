# Proxmox Fleet Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build every part of the Proxmox-fleet + reusable-engine design that doesn't depend on the user's manual steps (SSH key, network bridge, ISOs, physical device, frogenv key ceremony, npm login) — a config-file-based registry pointer, an `init` command, a real Proxmox API adapter wired to the existing `lifecycle` schema, and the repo split into `fleet-manager` (engine) / `fleet` (data).

**Architecture:** The CLI currently assumes the registry data (`machines/`, `roles/`, etc.) lives in the same repo as the code (`repoRoot()` in `src/paths.js`). This plan replaces that assumption with an explicit, configurable registry root (flag > env var > `~/.config/fleet-manager/config.yaml`), adds an `init` command that clones the data repo and writes that config, adds a `src/proxmox/` adapter that talks to the live Proxmox API (already reachable, token already has full ACL), and finally splits this repo's data files out into their own repo/remote.

**Tech Stack:** Node.js (`>=18`, ESM), `yaml` package, `node:test` + `node:assert/strict`, `node:https` for the Proxmox client, `git`/`gh` CLI for the repo split.

**Spec:** `docs/superpowers/specs/2026-08-22-proxmox-fleet-design.md`

## Global Constraints

- Node >= 18, ESM (`"type": "module"` in `package.json`) — match existing style throughout.
- Tests use `node:test` + `node:assert/strict`, temp-dir fixtures via `mkdtempSync(join(tmpdir(), ...))`, cleaned up in a `finally` block — match `test/registry.test.js`'s existing pattern exactly.
- No secrets ever hardcoded in source. The Proxmox host, token id, API key, and TLS fingerprint are all read from environment variables — never string-literal values in `src/`.
- The Proxmox TLS fingerprint must be the **real** value read from the live host at implementation time (Task 6, Step 1) — never fabricated or approximated.
- Don't touch anything in `machines/`, `roles/`, `packs/`, `devices/`, `projects/`, `test-profiles/`, `AGENTS.md`, or `context/` until Task 9 (the repo split) — earlier tasks are additive, code-only changes.

---

### Task 1: Stop `.env` from being trackable

`.env` holds `PROXMOX_API_KEY` and is currently untracked only by luck — `.gitignore` doesn't exclude it, so a stray `git add -A` would commit a secret.

**Files:**
- Modify: `.gitignore`

**Interfaces:** none (no code).

- [ ] **Step 1: Add the ignore rule**

Add a line to `.gitignore`:
```
.env
```

- [ ] **Step 2: Verify it's ignored**

Run: `git status --porcelain`
Expected: `.env` no longer appears in the output (it was showing as `?? .env` before).

- [ ] **Step 3: Commit**

```bash
git add .gitignore
git commit -m "chore: ignore .env so the Proxmox token can't be accidentally committed"
```

---

### Task 2: Registry root config resolution

Replace the implicit "registry lives next to the code" assumption with an explicit, resolvable registry root: `--root` flag > `FLEET_REGISTRY_PATH` env var > `registry_path` key in a per-machine config file. No more implicit directory-guessing default — if none of the three are set, callers get a clear error telling them to run `init`.

**Files:**
- Create: `src/config.js`
- Test: `test/config.test.js`

**Interfaces:**
- Produces: `configFilePath({ platform = process.platform, env = process.env } = {})` → absolute path string. Linux/macOS: `join(env.HOME, '.config', 'fleet-manager', 'config.yaml')`. Windows (`platform === 'win32'`): `join(env.APPDATA, 'fleet-manager', 'config.yaml')`.
- Produces: `readConfig({ platform, env } = {})` → parsed YAML object from `configFilePath(...)`, or `{}` if the file doesn't exist.
- Produces: `writeConfig(config, { platform, env } = {})` → serializes `config` as YAML to `configFilePath(...)`, creating parent directories with `mkdirSync(..., { recursive: true })` first.
- Produces: `resolveRegistryRoot({ flags = {}, env = process.env, platform = process.platform } = {})` → returns `{ root: string, source: string }` using precedence `flags.root` (source `'--root'`) → `env.FLEET_REGISTRY_PATH` (source `'FLEET_REGISTRY_PATH'`) → `readConfig({ platform, env }).registry_path` (source `'config file'`). If none resolve, throws `new Error('No registry configured. Run "agents-registry init --repo-url <url>" first, or pass --root <dir>.')`.

- [ ] **Step 1: Write the failing tests**

```js
// test/config.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configFilePath, readConfig, writeConfig, resolveRegistryRoot } from '../src/config.js';

function fakeHome() {
  return mkdtempSync(join(tmpdir(), 'fleet-manager-config-test-'));
}

test('configFilePath uses ~/.config/fleet-manager/config.yaml on linux/darwin', () => {
  const home = fakeHome();
  try {
    const path = configFilePath({ platform: 'linux', env: { HOME: home } });
    assert.equal(path, join(home, '.config', 'fleet-manager', 'config.yaml'));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('configFilePath uses %APPDATA%/fleet-manager/config.yaml on win32', () => {
  const appData = fakeHome();
  try {
    const path = configFilePath({ platform: 'win32', env: { APPDATA: appData } });
    assert.equal(path, join(appData, 'fleet-manager', 'config.yaml'));
  } finally {
    rmSync(appData, { recursive: true, force: true });
  }
});

test('writeConfig then readConfig round-trips registry_path', () => {
  const home = fakeHome();
  try {
    const env = { HOME: home };
    writeConfig({ registry_path: '/some/fleet/clone' }, { platform: 'linux', env });
    const config = readConfig({ platform: 'linux', env });
    assert.equal(config.registry_path, '/some/fleet/clone');
    const raw = readFileSync(configFilePath({ platform: 'linux', env }), 'utf8');
    assert.match(raw, /registry_path: \/some\/fleet\/clone/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('readConfig returns {} when no config file exists yet', () => {
  const home = fakeHome();
  try {
    const config = readConfig({ platform: 'linux', env: { HOME: home } });
    assert.deepEqual(config, {});
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('resolveRegistryRoot prefers --root flag over env var over config file', () => {
  const home = fakeHome();
  try {
    const env = { HOME: home, FLEET_REGISTRY_PATH: '/from/env' };
    writeConfig({ registry_path: '/from/config' }, { platform: 'linux', env });

    const fromFlag = resolveRegistryRoot({ flags: { root: '/from/flag' }, env, platform: 'linux' });
    assert.deepEqual(fromFlag, { root: '/from/flag', source: '--root' });

    const fromEnv = resolveRegistryRoot({ flags: {}, env, platform: 'linux' });
    assert.deepEqual(fromEnv, { root: '/from/env', source: 'FLEET_REGISTRY_PATH' });

    const { FLEET_REGISTRY_PATH, ...envWithoutVar } = env;
    const fromConfig = resolveRegistryRoot({ flags: {}, env: envWithoutVar, platform: 'linux' });
    assert.deepEqual(fromConfig, { root: '/from/config', source: 'config file' });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('resolveRegistryRoot throws a clear error when nothing is configured', () => {
  const home = fakeHome();
  try {
    assert.throws(
      () => resolveRegistryRoot({ flags: {}, env: { HOME: home }, platform: 'linux' }),
      /No registry configured/,
    );
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/config.test.js`
Expected: FAIL — `Cannot find module '../src/config.js'`

- [ ] **Step 3: Implement `src/config.js`**

```js
// src/config.js
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml';

export function configFilePath({ platform = process.platform, env = process.env } = {}) {
  if (platform === 'win32') {
    return join(env.APPDATA, 'fleet-manager', 'config.yaml');
  }
  return join(env.HOME, '.config', 'fleet-manager', 'config.yaml');
}

export function readConfig({ platform = process.platform, env = process.env } = {}) {
  const path = configFilePath({ platform, env });
  if (!existsSync(path)) return {};
  return parseYaml(readFileSync(path, 'utf8')) ?? {};
}

export function writeConfig(config, { platform = process.platform, env = process.env } = {}) {
  const path = configFilePath({ platform, env });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, stringifyYaml(config));
}

export function resolveRegistryRoot({ flags = {}, env = process.env, platform = process.platform } = {}) {
  if (flags.root) return { root: flags.root, source: '--root' };
  if (env.FLEET_REGISTRY_PATH) return { root: env.FLEET_REGISTRY_PATH, source: 'FLEET_REGISTRY_PATH' };
  const config = readConfig({ platform, env });
  if (config.registry_path) return { root: config.registry_path, source: 'config file' };
  throw new Error('No registry configured. Run "agents-registry init --repo-url <url>" first, or pass --root <dir>.');
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/config.test.js`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/config.js test/config.test.js
git commit -m "feat: add config-file-based registry root resolution"
```

---

### Task 3: `init` command clones the data repo

**Files:**
- Create: `src/commands/init.js`
- Test: `test/init.test.js`

**Interfaces:**
- Consumes: `writeConfig(config, opts)` from `src/config.js` (Task 2).
- Produces: `runInit(rootDirUnused, { repoUrl, path, env = process.env, platform = process.platform, git = defaultGit } = {})` → returns `0` on success, `1` if `repoUrl` is missing (prints usage to `console.error`). `git` is an injectable `{ clone(url, dest), pull(dest) }` object (default implementation shells out via `node:child_process`'s `execFileSync`) so tests can fake it without touching the network. On success: clones `repoUrl` into `path` (or pulls if `path` already contains a `.git` dir), then calls `writeConfig({ registry_path: path }, { env, platform })`.

- [ ] **Step 1: Write the failing tests**

```js
// test/init.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInit } from '../src/commands/init.js';
import { readConfig } from '../src/config.js';

function fakeGit() {
  const calls = [];
  return {
    calls,
    clone(url, dest) {
      calls.push(['clone', url, dest]);
      mkdirSync(join(dest, '.git'), { recursive: true });
    },
    pull(dest) {
      calls.push(['pull', dest]);
    },
  };
}

test('runInit clones when the destination has no .git dir, then writes config', () => {
  const home = mkdtempSync(join(tmpdir(), 'fleet-manager-init-test-'));
  const dest = join(home, 'fleet-clone');
  try {
    const git = fakeGit();
    const env = { HOME: home };
    const code = runInit(null, { repoUrl: 'git@github.com:Frogbyte-io/fleet.git', path: dest, env, platform: 'linux', git });
    assert.equal(code, 0);
    assert.deepEqual(git.calls, [['clone', 'git@github.com:Frogbyte-io/fleet.git', dest]]);
    assert.equal(readConfig({ platform: 'linux', env }).registry_path, dest);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('runInit pulls instead of cloning when the destination already has a .git dir', () => {
  const home = mkdtempSync(join(tmpdir(), 'fleet-manager-init-test-'));
  const dest = join(home, 'fleet-clone');
  mkdirSync(join(dest, '.git'), { recursive: true });
  try {
    const git = fakeGit();
    const env = { HOME: home };
    const code = runInit(null, { repoUrl: 'git@github.com:Frogbyte-io/fleet.git', path: dest, env, platform: 'linux', git });
    assert.equal(code, 0);
    assert.deepEqual(git.calls, [['pull', dest]]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('runInit fails with a usage message when repoUrl is missing', () => {
  const home = mkdtempSync(join(tmpdir(), 'fleet-manager-init-test-'));
  try {
    const code = runInit(null, { path: join(home, 'x'), env: { HOME: home }, platform: 'linux', git: fakeGit() });
    assert.equal(code, 1);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/init.test.js`
Expected: FAIL — `Cannot find module '../src/commands/init.js'`

- [ ] **Step 3: Implement `src/commands/init.js`**

```js
// src/commands/init.js
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { writeConfig } from '../config.js';

const defaultGit = {
  clone(url, dest) {
    execFileSync('git', ['clone', url, dest], { stdio: 'inherit' });
  },
  pull(dest) {
    execFileSync('git', ['-C', dest, 'pull', '--ff-only'], { stdio: 'inherit' });
  },
};

export function runInit(rootDirUnused, { repoUrl, path, env = process.env, platform = process.platform, git = defaultGit } = {}) {
  if (!repoUrl) {
    console.error('Usage: agents-registry init --repo-url <url> [--path <dir>]');
    return 1;
  }
  if (existsSync(join(path, '.git'))) {
    git.pull(path);
  } else {
    git.clone(repoUrl, path);
  }
  writeConfig({ registry_path: path }, { env, platform });
  console.log(`Registry ready at ${path} (config written).`);
  return 0;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/init.test.js`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/commands/init.js test/init.test.js
git commit -m "feat: add init command to clone the fleet data repo and write config"
```

---

### Task 4: Wire `init` into the CLI and switch `--root` resolution over

**Files:**
- Modify: `bin/agents-registry.js`

**Interfaces:**
- Consumes: `runInit` (Task 3), `resolveRegistryRoot` (Task 2).
- Produces: `agents-registry init --repo-url <url> [--path <dir>]` on the command line; every other subcommand's `rootDir` now comes from `resolveRegistryRoot({ flags })` instead of `flags.root ?? repoRoot()`.

- [ ] **Step 1: Update `bin/agents-registry.js`**

Replace the `repoRoot` import and the `rootDir` line, and add the `init` case:

```js
#!/usr/bin/env node
import { runStatus } from '../src/commands/status.js';
import { runResolve } from '../src/commands/resolve.js';
import { runCapabilities } from '../src/commands/capabilities.js';
import { runValidate } from '../src/commands/validate.js';
import { runSync } from '../src/commands/sync.js';
import { runInit } from '../src/commands/init.js';
import { resolveRegistryRoot } from '../src/config.js';
```

(keep `parseFlags` and `usage` as-is, but add the `init` line to `usage()`'s command list: `  agents-registry init --repo-url <url> [--path <dir>]`)

Replace:
```js
  const rootDir = flags.root ?? repoRoot();
```
with:
```js
  if (command === 'init') {
    const path = typeof flags.path === 'string' ? flags.path : join(homedir(), '.fleet-manager', 'registry');
    process.exitCode = runInit(null, { repoUrl: typeof flags['repo-url'] === 'string' ? flags['repo-url'] : undefined, path });
    return;
  }

  let rootDir;
  try {
    ({ root: rootDir } = resolveRegistryRoot({ flags }));
  } catch (err) {
    console.error(err.message);
    process.exitCode = 1;
    return;
  }
```

Add the two needed imports at the top:
```js
import { homedir } from 'node:os';
import { join } from 'node:path';
```

- [ ] **Step 2: Manually verify the CLI still works end-to-end**

Run: `node bin/agents-registry.js status --root .`
Expected: the existing status table prints (same as before this task), proving `--root` still overrides correctly through the new resolution path.

Run: `node bin/agents-registry.js status` (no `--root`, and ensure `FLEET_REGISTRY_PATH` is unset in your shell)
Expected: prints `No registry configured. Run "agents-registry init --repo-url <url>" first, or pass --root <dir>.` and exits non-zero.

- [ ] **Step 3: Run the full test suite**

Run: `npm test`
Expected: PASS, no regressions in `test/registry.test.js` or `test/resolve.test.js`.

- [ ] **Step 4: Delete the now-dead `src/paths.js`**

`bin/agents-registry.js` was its only consumer (confirmed via `grep -rn "repoRoot\|paths.js" --include=*.js .` — only `src/paths.js` itself and `bin/agents-registry.js` matched), and Step 1 removed that import, so it's dead code:

```bash
rm src/paths.js
```

Run: `npm test`
Expected: still PASS (nothing else referenced it).

- [ ] **Step 5: Commit**

```bash
git add bin/agents-registry.js
git rm src/paths.js
git commit -m "feat: wire init command into CLI, resolve --root via config.js"
```

---

### Task 5: Add `machine.vmid` to the schema

The Proxmox adapter needs to know which numeric VM id on the hypervisor corresponds to each machine manifest. Nothing in the schema carries that today.

**Files:**
- Modify: `src/registry.js:73-84` (the `registry.machines.set(...)` block)
- Modify: `docs/schema.md` (the `machines/<id>.yaml` section)
- Modify: `test/registry.test.js` (extend the existing fixture test)

**Interfaces:**
- Produces: loaded machine objects now carry `vmid: machine.vmid ?? null` alongside the existing `id/host/os/roles/skills/capabilities/resources/lifecycle/requires/sourceFile` fields.

- [ ] **Step 1: Write the failing test**

Add to `test/registry.test.js` (in the existing `'loadRegistry loads machines...'` test, extend the fixture and assertion — or add a new test if you prefer isolation):

```js
test('loadRegistry carries an optional machine.vmid through', () => {
  const dir = makeFixture({
    'machines/test-ubuntu.yaml': 'machine:\n  id: test-ubuntu\n  vmid: 201\n  os: ubuntu-desktop-24.04\n  roles: []\n',
  });
  try {
    const registry = loadRegistry(dir);
    assert.deepEqual(registry.errors, []);
    assert.equal(registry.machines.get('test-ubuntu').vmid, 201);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRegistry defaults vmid to null when absent', () => {
  const dir = makeFixture({
    'machines/dev-01.yaml': 'machine:\n  id: dev-01\n  os: linux\n  roles: []\n',
  });
  try {
    const registry = loadRegistry(dir);
    assert.equal(registry.machines.get('dev-01').vmid, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/registry.test.js`
Expected: FAIL — `vmid` is `undefined`, assertion mismatch against `201`/`null`.

- [ ] **Step 3: Update `src/registry.js`**

In the `registry.machines.set(machine.id, { ... })` block (currently `src/registry.js:73-84`), add one line:

```js
    registry.machines.set(machine.id, {
      id: machine.id,
      host: machine.host ?? null,
      os: machine.os ?? null,
      vmid: machine.vmid ?? null,
      roles: machine.roles ?? [],
      skills: data.skills ?? {},
      capabilities: data.capabilities ?? [],
      resources: data.resources ?? null,
      lifecycle: data.lifecycle ?? null,
      requires: data.requires ?? {},
      sourceFile: path,
    });
```

- [ ] **Step 4: Update `docs/schema.md`**

In the `machines/<id>.yaml` example block, add `vmid` under `machine:` right after `host`:

```yaml
machine:
  id: test-windows        # required, must equal the filename stem
  host: proxmox-01         # optional, informational
  vmid: 210                # optional, the Proxmox VM id this machine maps to
  os: windows-11           # optional
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `node --test test/registry.test.js`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/registry.js docs/schema.md test/registry.test.js
git commit -m "feat: add optional machine.vmid field for the Proxmox adapter"
```

---

### Task 6: Proxmox API client

**Files:**
- Create: `src/proxmox/client.js`
- Test: `test/proxmox/client.test.js`

**Interfaces:**
- Produces: `class ProxmoxClient` with constructor `new ProxmoxClient({ host, tokenId, apiKey, fingerprint, fetchImpl })`. `fetchImpl` defaults to a real `https.request`-based implementation but is injectable for tests (matches the `git` injection pattern from Task 3).
- Produces: `client.request(method, path, body)` → returns parsed JSON `data` field of the Proxmox API response (Proxmox always wraps responses as `{ data: ... }`). Throws on non-2xx with the response body's `errors` if present.
- Produces: `client.waitForTask(node, upid, { pollIntervalMs = 1000, timeoutMs = 300000 } = {})` → polls `GET /nodes/<node>/tasks/<upid>/status` until `status !== 'running'`, resolves with the final status object, rejects if `timeoutMs` elapses first.
- Produces: `ProxmoxClient.fromEnv(env = process.env)` → reads `PROXMOX_HOST`, `PROXMOX_TOKEN_ID` (e.g. `root@pam!agents`), `PROXMOX_API_KEY`, `PROXMOX_FINGERPRINT` and constructs a client. Throws a clear error naming whichever of those four is missing.

**Before writing this task's implementation**, get the real TLS fingerprint from the live host (needed for both the pinning logic and the live smoke test in Step 5):

```bash
openssl s_client -connect 192.168.68.223:8006 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

That command's output (`SHA256 Fingerprint=AA:BB:...`) is the value to export as `PROXMOX_FINGERPRINT` when running the live test in Step 6 — do not hardcode it in source; it's read from the environment.

- [ ] **Step 1: Write the failing unit tests (mocked transport, no network)**

```js
// test/proxmox/client.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ProxmoxClient } from '../../src/proxmox/client.js';

function fakeTransport(responses) {
  const calls = [];
  return {
    calls,
    async fetchImpl(method, url) {
      calls.push([method, url]);
      const next = responses.shift();
      if (!next) throw new Error('fakeTransport ran out of canned responses');
      return next;
    },
  };
}

test('request returns the unwrapped data field on success', async () => {
  const { fetchImpl, calls } = fakeTransport([{ status: 200, body: { data: { version: '9.2.2' } } }]);
  const client = new ProxmoxClient({ host: 'h', tokenId: 't', apiKey: 'k', fingerprint: 'f', fetchImpl });
  const data = await client.request('GET', '/version');
  assert.deepEqual(data, { version: '9.2.2' });
  assert.equal(calls[0][0], 'GET');
  assert.match(calls[0][1], /\/api2\/json\/version$/);
});

test('request throws with the API error message on non-2xx', async () => {
  const { fetchImpl } = fakeTransport([{ status: 403, body: { errors: { '/': 'Permission check failed' } } }]);
  const client = new ProxmoxClient({ host: 'h', tokenId: 't', apiKey: 'k', fingerprint: 'f', fetchImpl });
  await assert.rejects(() => client.request('GET', '/nodes/pve/status'), /Permission check failed/);
});

test('waitForTask polls until status is not running', async () => {
  const { fetchImpl } = fakeTransport([
    { status: 200, body: { data: { status: 'running' } } },
    { status: 200, body: { data: { status: 'running' } } },
    { status: 200, body: { data: { status: 'stopped', exitstatus: 'OK' } } },
  ]);
  const client = new ProxmoxClient({ host: 'h', tokenId: 't', apiKey: 'k', fingerprint: 'f', fetchImpl });
  const result = await client.waitForTask('pve', 'UPID:pve:...', { pollIntervalMs: 1 });
  assert.equal(result.status, 'stopped');
  assert.equal(result.exitstatus, 'OK');
});

test('waitForTask rejects on timeout', async () => {
  const { fetchImpl } = fakeTransport([
    { status: 200, body: { data: { status: 'running' } } },
    { status: 200, body: { data: { status: 'running' } } },
    { status: 200, body: { data: { status: 'running' } } },
  ]);
  const client = new ProxmoxClient({ host: 'h', tokenId: 't', apiKey: 'k', fingerprint: 'f', fetchImpl });
  await assert.rejects(
    () => client.waitForTask('pve', 'UPID:pve:...', { pollIntervalMs: 1, timeoutMs: 2 }),
    /timed out/,
  );
});

test('fromEnv throws naming the missing variable', () => {
  assert.throws(
    () => ProxmoxClient.fromEnv({ PROXMOX_HOST: 'h', PROXMOX_TOKEN_ID: 't', PROXMOX_API_KEY: 'k' }),
    /PROXMOX_FINGERPRINT/,
  );
});

test('fromEnv constructs a client when all four vars are present', () => {
  const client = ProxmoxClient.fromEnv({
    PROXMOX_HOST: 'h', PROXMOX_TOKEN_ID: 't', PROXMOX_API_KEY: 'k', PROXMOX_FINGERPRINT: 'f',
  });
  assert.ok(client instanceof ProxmoxClient);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/proxmox/client.test.js`
Expected: FAIL — `Cannot find module '../../src/proxmox/client.js'`

- [ ] **Step 3: Implement `src/proxmox/client.js`**

```js
// src/proxmox/client.js
import https from 'node:https';

function realFetch({ host, fingerprint }) {
  return (method, path, body) => new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : undefined;
    const req = https.request({
      method,
      host,
      port: 8006,
      path,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
      rejectUnauthorized: false,
      checkServerIdentity: (_hostname, cert) => {
        const actual = cert.fingerprint256;
        if (actual.replace(/:/g, '').toUpperCase() !== fingerprint.replace(/:/g, '').toUpperCase()) {
          return new Error(`Proxmox TLS fingerprint mismatch: expected ${fingerprint}, got ${actual}`);
        }
        return undefined;
      },
    }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = null;
        }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

export class ProxmoxClient {
  constructor({ host, tokenId, apiKey, fingerprint, fetchImpl }) {
    this.host = host;
    this.tokenId = tokenId;
    this.apiKey = apiKey;
    this.fetchImpl = fetchImpl ?? realFetch({ host, fingerprint });
  }

  static fromEnv(env = process.env) {
    const required = ['PROXMOX_HOST', 'PROXMOX_TOKEN_ID', 'PROXMOX_API_KEY', 'PROXMOX_FINGERPRINT'];
    for (const key of required) {
      if (!env[key]) throw new Error(`Missing required env var ${key} for ProxmoxClient.fromEnv`);
    }
    return new ProxmoxClient({
      host: env.PROXMOX_HOST,
      tokenId: env.PROXMOX_TOKEN_ID,
      apiKey: env.PROXMOX_API_KEY,
      fingerprint: env.PROXMOX_FINGERPRINT,
    });
  }

  async request(method, path, body) {
    const url = `/api2/json${path}`;
    const { status, body: responseBody } = await this.fetchImpl(method, url, body);
    if (status < 200 || status >= 300) {
      const message = responseBody?.errors ? JSON.stringify(responseBody.errors) : `HTTP ${status}`;
      throw new Error(`Proxmox API error on ${method} ${path}: ${message}`);
    }
    return responseBody?.data;
  }

  async waitForTask(node, upid, { pollIntervalMs = 1000, timeoutMs = 300000 } = {}) {
    const start = Date.now();
    for (;;) {
      const status = await this.request('GET', `/nodes/${node}/tasks/${encodeURIComponent(upid)}/status`);
      if (status.status !== 'running') return status;
      if (Date.now() - start > timeoutMs) {
        throw new Error(`waitForTask timed out after ${timeoutMs}ms waiting for ${upid}`);
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }
  }
}
```

Note: `request` builds its `Authorization` header via `PVEAPIToken=${tokenId}=${apiKey}` — add that header inside `realFetch`'s request options (`headers: { Authorization: ... , 'Content-Type': ... }`); it's omitted from the mocked-transport tests above because those bypass `realFetch` entirely, but it must be present in the real implementation for live calls to authenticate.

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/proxmox/client.test.js`
Expected: PASS (6 tests)

- [ ] **Step 5: Add the Authorization header (covered by no unit test — verified live in Step 6)**

In `realFetch`'s `https.request` call, change `headers` to:
```js
      headers: {
        Authorization: `PVEAPIToken=${tokenId}=${apiKey}`,
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
```
and update `realFetch`'s signature to `realFetch({ host, tokenId, apiKey, fingerprint })`, and the constructor's call site to `realFetch({ host, tokenId, apiKey, fingerprint })`.

- [ ] **Step 6: Live smoke test against the real host (manual, not part of `npm test`)**

```bash
export PROXMOX_HOST=192.168.68.223
export PROXMOX_TOKEN_ID='root@pam!agents'
export PROXMOX_API_KEY=$(sed -n 's/^PROXMOX_API_KEY=//p' .env | tr -d '\r\n')
export PROXMOX_FINGERPRINT='<paste the openssl output from before Step 1>'
node -e "
import('./src/proxmox/client.js').then(async ({ ProxmoxClient }) => {
  const client = ProxmoxClient.fromEnv();
  console.log(await client.request('GET', '/version'));
});
"
```
Expected: prints `{ version: '9.2.2', ... }` — confirms auth header and TLS pinning both work against the real host.

- [ ] **Step 7: Commit**

```bash
git add src/proxmox/client.js test/proxmox/client.test.js
git commit -m "feat: add Proxmox API client with token auth, TLS pinning, and task polling"
```

---

### Task 7: Proxmox lifecycle adapter

Wraps `ProxmoxClient` with the operations named in `lifecycle.mode`/`reset_strategy` and reports power state.

Note on scope: `reset_strategy: clone` (used by `test-ubuntu`/`test-bazzite`) needs a template-name → vmid lookup (`base_template: ubuntu-desktop-24.04-v2` isn't a vmid) that doesn't exist yet — no templates exist on the host until the manual golden-image steps happen. This task implements the primitive (`cloneFromTemplate`, which takes an already-resolved `templateVmid`) fully, but `resetMachine`'s dispatch for `'clone'` deliberately throws a specific, actionable error rather than guessing at a lookup — wiring the name→vmid resolution is Phase 2 work, once templates actually exist (see the end of this plan).

**Files:**
- Create: `src/proxmox/lifecycle.js`
- Test: `test/proxmox/lifecycle.test.js`

**Interfaces:**
- Consumes: `ProxmoxClient` (Task 6) — specifically `client.request(method, path, body)` and `client.waitForTask(node, upid)`.
- Produces: `getPowerState(client, node, vmid)` → calls `GET /nodes/<node>/qemu/<vmid>/status/current`, returns the `status` string (`'running'`/`'stopped'`) from the response, or `'unmanaged'` if `vmid` is `null`/`undefined` (no adapter call made in that case).
- Produces: `cloneFromTemplate(client, node, { templateVmid, newVmid, name })` → `POST /nodes/<node>/qemu/<templateVmid>/clone` with body `{ newid: newVmid, name }`, then `client.waitForTask(node, upid)` on the returned UPID.
- Produces: `resetMachine(client, node, machine)` → dispatches on `machine.lifecycle.reset_strategy`: `'snapshot'` calls `rollbackSnapshot(client, node, machine.vmid, 'golden')`; `'clone'` calls `cloneFromTemplate(...)` after first destroying any existing `machine.vmid` (skip destroy if the status call in `getPowerState` shows nothing exists yet — see implementation). Throws for any other `reset_strategy` value naming it.
- Produces: `rollbackSnapshot(client, node, vmid, snapshotName)` → `POST /nodes/<node>/qemu/<vmid>/snapshot/<snapshotName>/rollback`, then `client.waitForTask(...)`.
- Produces: `startMachine(client, node, vmid)` / `stopMachine(client, node, vmid)` → `POST /nodes/<node>/qemu/<vmid>/status/start` / `.../status/stop`, then `waitForTask`.

- [ ] **Step 1: Write the failing tests**

```js
// test/proxmox/lifecycle.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  getPowerState, cloneFromTemplate, rollbackSnapshot, startMachine, stopMachine, resetMachine,
} from '../../src/proxmox/lifecycle.js';

function fakeClient(script) {
  const calls = [];
  return {
    calls,
    async request(method, path, body) {
      calls.push([method, path, body]);
      const next = script.shift();
      if (!next) throw new Error('fakeClient ran out of canned responses');
      return next;
    },
    async waitForTask(node, upid) {
      calls.push(['waitForTask', node, upid]);
      return { status: 'stopped', exitstatus: 'OK' };
    },
  };
}

test('getPowerState returns "unmanaged" when vmid is null', async () => {
  const client = fakeClient([]);
  const state = await getPowerState(client, 'pve', null);
  assert.equal(state, 'unmanaged');
  assert.deepEqual(client.calls, []);
});

test('getPowerState returns the live status for a real vmid', async () => {
  const client = fakeClient([{ status: 'running' }]);
  const state = await getPowerState(client, 'pve', 201);
  assert.equal(state, 'running');
  assert.deepEqual(client.calls, [['GET', '/nodes/pve/qemu/201/status/current', undefined]]);
});

test('cloneFromTemplate clones then waits for the task', async () => {
  const client = fakeClient(['UPID:pve:clone123']);
  await cloneFromTemplate(client, 'pve', { templateVmid: 900, newVmid: 201, name: 'test-ubuntu' });
  assert.deepEqual(client.calls, [
    ['POST', '/nodes/pve/qemu/900/clone', { newid: 201, name: 'test-ubuntu' }],
    ['waitForTask', 'pve', 'UPID:pve:clone123'],
  ]);
});

test('rollbackSnapshot rolls back then waits for the task', async () => {
  const client = fakeClient(['UPID:pve:rollback123']);
  await rollbackSnapshot(client, 'pve', 210, 'golden');
  assert.deepEqual(client.calls, [
    ['POST', '/nodes/pve/qemu/210/snapshot/golden/rollback', undefined],
    ['waitForTask', 'pve', 'UPID:pve:rollback123'],
  ]);
});

test('startMachine and stopMachine hit the right endpoints', async () => {
  const client = fakeClient(['UPID:pve:start1', 'UPID:pve:stop1']);
  await startMachine(client, 'pve', 201);
  await stopMachine(client, 'pve', 201);
  assert.deepEqual(client.calls, [
    ['POST', '/nodes/pve/qemu/201/status/start', undefined],
    ['waitForTask', 'pve', 'UPID:pve:start1'],
    ['POST', '/nodes/pve/qemu/201/status/stop', undefined],
    ['waitForTask', 'pve', 'UPID:pve:stop1'],
  ]);
});

test('resetMachine dispatches to rollbackSnapshot for reset_strategy: snapshot', async () => {
  const client = fakeClient(['UPID:pve:rollback1']);
  const machine = { vmid: 210, lifecycle: { reset_strategy: 'snapshot' } };
  await resetMachine(client, 'pve', machine);
  assert.deepEqual(client.calls, [
    ['POST', '/nodes/pve/qemu/210/snapshot/golden/rollback', undefined],
    ['waitForTask', 'pve', 'UPID:pve:rollback1'],
  ]);
});

test('resetMachine throws naming an unsupported reset_strategy', async () => {
  const client = fakeClient([]);
  const machine = { vmid: 210, lifecycle: { reset_strategy: 'something-else' } };
  await assert.rejects(() => resetMachine(client, 'pve', machine), /something-else/);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/proxmox/lifecycle.test.js`
Expected: FAIL — `Cannot find module '../../src/proxmox/lifecycle.js'`

- [ ] **Step 3: Implement `src/proxmox/lifecycle.js`**

```js
// src/proxmox/lifecycle.js
export async function getPowerState(client, node, vmid) {
  if (vmid === null || vmid === undefined) return 'unmanaged';
  const status = await client.request('GET', `/nodes/${node}/qemu/${vmid}/status/current`);
  return status.status;
}

export async function cloneFromTemplate(client, node, { templateVmid, newVmid, name }) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${templateVmid}/clone`, { newid: newVmid, name });
  return client.waitForTask(node, upid);
}

export async function rollbackSnapshot(client, node, vmid, snapshotName) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${vmid}/snapshot/${snapshotName}/rollback`);
  return client.waitForTask(node, upid);
}

export async function startMachine(client, node, vmid) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${vmid}/status/start`);
  return client.waitForTask(node, upid);
}

export async function stopMachine(client, node, vmid) {
  const upid = await client.request('POST', `/nodes/${node}/qemu/${vmid}/status/stop`);
  return client.waitForTask(node, upid);
}

export async function resetMachine(client, node, machine) {
  const strategy = machine.lifecycle?.reset_strategy;
  if (strategy === 'snapshot') {
    return rollbackSnapshot(client, node, machine.vmid, 'golden');
  }
  if (strategy === 'clone') {
    throw new Error('clone reset_strategy requires template/newVmid wiring — call cloneFromTemplate directly with the machine\'s base_template vmid');
  }
  throw new Error(`Unsupported reset_strategy "${strategy}" for machine ${machine.vmid}`);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/proxmox/lifecycle.test.js`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/proxmox/lifecycle.js test/proxmox/lifecycle.test.js
git commit -m "feat: add Proxmox lifecycle adapter (clone/reset/start/stop/status)"
```

---

### Task 8: Wire `status` command to real power state

**Files:**
- Modify: `src/commands/status.js`
- Test: `test/commands-status.test.js`

**Interfaces:**
- Consumes: `getPowerState(client, node, vmid)` (Task 7), `ProxmoxClient` (Task 6).
- Produces: `runStatus(rootDir, { client, node = 'pve' } = {})` — `client` is optional/injectable; when omitted, `runStatus` tries `ProxmoxClient.fromEnv()` inside a try/catch and falls back to reporting `'unmanaged'` for every row (with a one-line warning) if the env vars aren't set, so this command still works on machines that haven't configured Proxmox access.

- [ ] **Step 1: Write the failing test**

```js
// test/commands-status.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runStatus } from '../src/commands/status.js';

function makeFixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'status-test-'));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = join(dir, relPath);
    mkdirSync(join(fullPath, '..'), { recursive: true });
    writeFileSync(fullPath, content);
  }
  return dir;
}

test('runStatus reports live power state when a client and vmid are available', () => {
  const dir = makeFixture({
    'machines/test-ubuntu.yaml': 'machine:\n  id: test-ubuntu\n  vmid: 201\n  os: ubuntu\n  roles: []\n',
  });
  const fakeClient = { request: async () => ({ status: 'running' }) };
  const logs = [];
  const origLog = console.log;
  console.log = (line) => logs.push(line);
  try {
    runStatus(dir, { client: fakeClient });
  } finally {
    console.log = origLog;
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(logs.some((line) => line.includes('test-ubuntu') && line.includes('running')));
});

test('runStatus falls back to "unmanaged" when no client is available', () => {
  const dir = makeFixture({
    'machines/dev-01.yaml': 'machine:\n  id: dev-01\n  os: linux\n  roles: []\n',
  });
  const logs = [];
  const origLog = console.log;
  console.log = (line) => logs.push(line);
  try {
    runStatus(dir, { client: null });
  } finally {
    console.log = origLog;
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(logs.some((line) => line.includes('dev-01') && line.includes('unmanaged')));
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test test/commands-status.test.js`
Expected: FAIL — current `runStatus` signature doesn't accept a second argument and always prints `'unmanaged'`.

- [ ] **Step 3: Implement the change in `src/commands/status.js`**

Replace the whole file:

```js
import { loadRegistry } from '../registry.js';
import { resolveAllMachines } from '../resolve.js';
import { getPowerState } from '../proxmox/lifecycle.js';
import { ProxmoxClient } from '../proxmox/client.js';

function pad(str, width) {
  return str.length >= width ? `${str.slice(0, width - 1)}…` : str.padEnd(width);
}

function resolveClient(client) {
  if (client !== undefined) return client;
  try {
    return ProxmoxClient.fromEnv();
  } catch {
    return null;
  }
}

export function runStatus(rootDir, { client, node = 'pve' } = {}) {
  const resolvedClient = resolveClient(client);
  const registry = loadRegistry(rootDir);
  if (registry.errors.length > 0) {
    console.error(`Warning: ${registry.errors.length} registry load error(s); run \`agents-registry validate\` for details.`);
  }

  const { resolved, errors } = resolveAllMachines(registry);

  const header = ['NAME', 'STATE', 'ROLES', 'CAPABILITIES', 'DEVICES'];
  const widths = [16, 11, 26, 18, 16];
  console.log(header.map((h, i) => pad(h, widths[i])).join(' '));

  for (const machine of resolved.values()) {
    const source = registry.machines.get(machine.id);
    const vmid = source?.vmid ?? null;
    const state = resolvedClient ? undefined : 'unmanaged';
    const row = [
      machine.id,
      state ?? 'unmanaged',
      machine.roles.join(',') || '-',
      String(machine.capabilities.length),
      machine.devices.map((d) => d.id).join(',') || '-',
    ];
    console.log(row.map((v, i) => pad(v, widths[i])).join(' '));
  }

  if (errors.length > 0) {
    console.error(`\n${errors.length} machine(s) failed to resolve:`);
    for (const err of errors) console.error(`  - ${err}`);
  }

  if (!resolvedClient) {
    console.error('\nNote: STATE is not live - no PROXMOX_* env vars configured (see docs/schema.md).');
  }

  return errors.length > 0 ? 1 : 0;
}
```

This synchronous version can't actually call the async `getPowerState` per-row yet — fix that now by making the loop async. Replace the `for (const machine of resolved.values())` block with:

```js
  const rows = await Promise.all([...resolved.values()].map(async (machine) => {
    const source = registry.machines.get(machine.id);
    const vmid = source?.vmid ?? null;
    const state = resolvedClient ? await getPowerState(resolvedClient, node, vmid) : 'unmanaged';
    return [
      machine.id,
      state,
      machine.roles.join(',') || '-',
      String(machine.capabilities.length),
      machine.devices.map((d) => d.id).join(',') || '-',
    ];
  }));
  for (const row of rows) {
    console.log(row.map((v, i) => pad(v, widths[i])).join(' '));
  }
```

...and change `export function runStatus` to `export async function runStatus`. Update the two call sites (`bin/agents-registry.js`'s `case 'status':` and the two tests above) to `await`/handle a Promise — in `bin/agents-registry.js`, change `process.exitCode = runStatus(rootDir);` to `process.exitCode = await runStatus(rootDir);` and mark `main()` as already `async` (it already is, per the existing file).

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/commands-status.test.js`
Expected: PASS (2 tests)

- [ ] **Step 5: Run the full suite**

Run: `npm test`
Expected: PASS, no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/commands/status.js test/commands-status.test.js bin/agents-registry.js
git commit -m "feat: wire status command to real Proxmox power state"
```

---

### Task 9: Repo split — `fleet-manager` / `fleet` / `fleet-secrets`

**This task changes external, shared GitHub state (new repos, an ownership transfer) — confirm with the user immediately before running the `gh` commands in Steps 3-5, even though the names were already approved during design.**

**Files:**
- Move (to a new local directory, then a new repo): `AGENTS.md`, `machines/`, `roles/`, `packs/`, `devices/`, `projects/`, `test-profiles/`, `context/`
- Modify: `package.json` (`name` field), `README.md` (repo references)
- Delete: nothing tracked (`.env` stays local/untracked/ignored per Task 1)

**Interfaces:** none (infra/repo operations, not code).

- [ ] **Step 1: Create the local `fleet` data directory outside this repo**

```bash
mkdir -p ../fleet
git -C . mv AGENTS.md machines roles packs devices projects test-profiles context ../fleet/
```

(`git mv` across a repo boundary just does a filesystem move here since the destination isn't part of this git repo — that's fine, we're about to make it its own repo.)

- [ ] **Step 2: Initialize `fleet` as its own repo locally**

```bash
cd ../fleet
git init
git add AGENTS.md machines roles packs devices projects test-profiles context
git commit -m "Initial import: fleet data split out of agents-registry"
cd -
```

- [ ] **Step 3: Create the two new GitHub repos**

```bash
gh repo create Frogbyte-io/fleet --private --source=../fleet --remote=origin --push
gh repo create Frogbyte-io/fleet-secrets --private
```

- [ ] **Step 4: Update the stale `bazzite-dotx-dev` entry before pushing further**

In `../fleet/AGENTS.md`, remove (or clearly re-flag) the `bazzite-dotx-dev` section — recon confirmed that IP now runs Proxmox with a different SSH host key, so the entry no longer describes a reachable machine. Commit and push that fix:

```bash
cd ../fleet
git add AGENTS.md
git commit -m "docs: remove stale bazzite-dotx-dev entry (host reimaged to Proxmox)"
git push
cd -
```

- [ ] **Step 5: Transfer this repo to `Frogbyte-io/fleet-manager`**

```bash
gh api repos/Andreas-Froyland/agents-registry/transfer -f new_owner=Frogbyte-io -f new_name=fleet-manager --method POST
git remote set-url origin https://github.com/Frogbyte-io/fleet-manager.git
git fetch origin
```

- [ ] **Step 6: Update `package.json`**

Change:
```json
  "name": "agents-registry",
```
to:
```json
  "name": "@frogbyte-io/fleet-manager",
```

- [ ] **Step 7: Update `README.md` references**

Update the clone URL in the "First-time setup on a new machine" section and any other `agents-registry`-as-repo-name references to point at `Frogbyte-io/fleet-manager`, and add a short note pointing at `Frogbyte-io/fleet` as the data repo `init` should be pointed to.

- [ ] **Step 8: Run the full test suite one more time from the new remote**

Run: `npm test`
Expected: PASS — confirms nothing in the engine repo depended on the data directories that just moved out (Tasks 2-8 were already designed not to).

- [ ] **Step 9: Commit**

```bash
git add package.json README.md
git commit -m "chore: rename package for Frogbyte-io/fleet-manager, update repo references"
git push
```

---

## Deferred to a follow-up plan

Everything below is in the approved spec but depends on manual steps from
`docs/proxmox-fleet-manual-steps.md` that hadn't landed when this plan was
written. Write a Phase 2 plan against the same spec once the relevant manual
step(s) are done:

- **frogenv secrets bootstrap & token migration** — blocked on the admin key
  ceremony (manual-steps §7), which the user runs themselves so the private
  key never passes through an agent transcript. Once `fleet-secrets` exists
  and the first workstation is approved, migrate `PROXMOX_API_KEY` out of
  `.env` into `projects/proxmox/infra.enc.env` and update Task 6's
  `ProxmoxClient.fromEnv` call sites to run under `frogenv env run`.
- **Golden-image VM creation and template conversion** — blocked on ISOs
  (manual-steps §4, Windows licensing-gated) and the network bridge
  (manual-steps §3, needs physical-console standby). Once templates exist,
  this is also where `resetMachine`'s `'clone'` strategy gets its
  template-name → vmid lookup (see the note on Task 7).
- **USB passthrough for `decker-controller`** — blocked on physically
  connecting the device to the host (manual-steps §6).
- **npm publish of `@frogbyte-io/fleet-manager`** — blocked on npm org/login
  (manual-steps §8).
