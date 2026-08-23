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

test('runStatus reports live power state when a client and vmid are available', async () => {
  const dir = makeFixture({
    'machines/test-ubuntu.yaml': 'machine:\n  id: test-ubuntu\n  vmid: 201\n  os: ubuntu\n  roles: []\n',
  });
  const fakeClient = { request: async () => ({ status: 'running' }) };
  const logs = [];
  const origLog = console.log;
  console.log = (line) => logs.push(line);
  try {
    await runStatus(dir, { client: fakeClient });
  } finally {
    console.log = origLog;
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(logs.some((line) => line.includes('test-ubuntu') && line.includes('running')));
});

test('runStatus reports an error-state row instead of throwing when a Proxmox lookup rejects', async () => {
  const dir = makeFixture({
    'machines/broken-vm.yaml': 'machine:\n  id: broken-vm\n  vmid: 999\n  os: ubuntu\n  roles: []\n',
  });
  const fakeClient = { request: async () => { throw new Error('Proxmox API error on GET /nodes/pve/qemu/999/status/current: HTTP 500'); } };
  const logs = [];
  const origLog = console.log;
  console.log = (line) => logs.push(line);
  try {
    await assert.doesNotReject(() => runStatus(dir, { client: fakeClient }));
  } finally {
    console.log = origLog;
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(logs.some((line) => line.includes('broken-vm') && line.includes('error')));
});

test('runStatus falls back to "unmanaged" when no client is available', async () => {
  const dir = makeFixture({
    'machines/dev-01.yaml': 'machine:\n  id: dev-01\n  os: linux\n  roles: []\n',
  });
  const logs = [];
  const origLog = console.log;
  console.log = (line) => logs.push(line);
  try {
    await runStatus(dir, { client: null });
  } finally {
    console.log = origLog;
    rmSync(dir, { recursive: true, force: true });
  }
  assert.ok(logs.some((line) => line.includes('dev-01') && line.includes('unmanaged')));
});
