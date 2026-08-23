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

test('resetMachine throws a specific, actionable error for reset_strategy: clone (not yet wired - see Task 7 scope note)', async () => {
  const client = fakeClient([]);
  const machine = { vmid: 201, lifecycle: { reset_strategy: 'clone' } };
  await assert.rejects(() => resetMachine(client, 'pve', machine), /cloneFromTemplate/);
});
