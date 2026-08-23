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
