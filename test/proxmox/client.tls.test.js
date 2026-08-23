// test/proxmox/client.tls.test.js
//
// Exercises the *real* TLS fingerprint-pinning path in realFetch (src/proxmox/client.js)
// against an actual node:https server with a throwaway self-signed certificate.
// The other test file (client.test.js) only ever injects a fake fetchImpl, so it never
// touches realFetch/https.request/the secureConnect handler at all -- this file closes
// that gap.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ProxmoxClient } from '../../src/proxmox/client.js';

let server;
let port;
let fingerprint;

before(async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'proxmox-tls-test-'));
  const keyPath = path.join(tmpDir, 'key.pem');
  const certPath = path.join(tmpDir, 'cert.pem');
  try {
    // MSYS_NO_PATHCONV guards against MSYS/Git-Bash-flavored openssl builds on
    // Windows rewriting "/CN=..." as a filesystem path; harmless elsewhere.
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-keyout', keyPath, '-out', certPath,
      '-days', '1', '-subj', '/CN=127.0.0.1',
    ], { stdio: 'pipe', env: { ...process.env, MSYS_NO_PATHCONV: '1' } });

    const key = fs.readFileSync(keyPath, 'utf8');
    const cert = fs.readFileSync(certPath, 'utf8');
    fingerprint = new crypto.X509Certificate(cert).fingerprint256;

    let seq = 0;
    server = https.createServer({ key, cert }, (req, res) => {
      seq += 1;
      const body = JSON.stringify({ data: { seq, path: req.url } });
      const headers = { 'Content-Type': 'application/json' };
      // Forces the client's agent to open a brand-new TCP+TLS connection for
      // the next request instead of reusing the pooled/kept-alive socket.
      if (req.url.includes('closeme')) headers.Connection = 'close';
      res.writeHead(200, headers);
      res.end(body);
    });

    await new Promise((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        port = server.address().port;
        resolve();
      });
    });
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

after(() => new Promise((resolve, reject) => {
  server.close((err) => (err ? reject(err) : resolve()));
}));

test('realFetch: correct fingerprint lets a real request succeed', async () => {
  const client = new ProxmoxClient({
    host: '127.0.0.1', port, tokenId: 't', apiKey: 'k', fingerprint,
  });
  const data = await client.request('GET', '/version');
  assert.equal(typeof data.seq, 'number');
});

test('realFetch: wrong fingerprint rejects the request with a mismatch error', async () => {
  const lastByte = fingerprint.slice(-2);
  const flipped = lastByte === '00' ? '11' : '00';
  const wrongFingerprint = `${fingerprint.slice(0, -2)}${flipped}`;
  const client = new ProxmoxClient({
    host: '127.0.0.1', port, tokenId: 't', apiKey: 'k', fingerprint: wrongFingerprint,
  });
  await assert.rejects(
    () => client.request('GET', '/version'),
    /Proxmox TLS fingerprint mismatch/,
  );
});

test('realFetch: a correctly-configured client can make 2+ requests over its pooled keep-alive connection', async () => {
  const client = new ProxmoxClient({
    host: '127.0.0.1', port, tokenId: 't', apiKey: 'k', fingerprint,
  });
  // Regression guard for Critical #2: with a shared https.globalAgent, the 2nd+
  // request over an already-open keep-alive socket never re-fires 'secureConnect',
  // so it must still be routed correctly through THIS client's own verified socket.
  const first = await client.request('GET', '/a');
  const second = await client.request('GET', '/b');
  assert.equal(typeof first.seq, 'number');
  assert.equal(typeof second.seq, 'number');
  assert.notEqual(first.seq, second.seq);
});

test('realFetch: a correctly-configured client survives multiple separate TLS connections over time', async () => {
  const client = new ProxmoxClient({
    host: '127.0.0.1', port, tokenId: 't', apiKey: 'k', fingerprint,
  });
  // Regression guard for Critical #1: '/closeme' makes the server close the
  // socket after each response, forcing a brand-new TCP+TLS handshake for the
  // next request on this same client/agent. Without maxCachedSessions: 0, Node
  // may resume the cached TLS session on that new connection, which skips the
  // certificate message entirely and makes getPeerCertificate() return {} --
  // wrongly destroying a perfectly legitimate request.
  const first = await client.request('GET', '/closeme');
  await new Promise((resolve) => { setTimeout(resolve, 100); });
  const second = await client.request('GET', '/closeme');
  assert.equal(typeof first.seq, 'number');
  assert.equal(typeof second.seq, 'number');
});
