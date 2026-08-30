// src/proxmox/client.js
import https from 'node:https';

function realFetch({ host, port = 8006, tokenId, apiKey, fingerprint }) {
  // A private agent instance (never https.globalAgent) so:
  //   - only sockets this client created (and verified via 'secureConnect')
  //     can ever live in its connection pool — no other code in the process
  //     can inject an unverified socket into it.
  //   - maxCachedSessions: 0 disables TLS session resumption, forcing every
  //     new TCP connection to do a full handshake with a real certificate
  //     exchange, so getPeerCertificate() never returns {} from a resumed
  //     session. keepAlive stays on: reusing an already-verified socket for
  //     a second request over the SAME connection is fine, since the cert
  //     was already checked at that connection's own handshake.
  const agent = new https.Agent({ keepAlive: true, maxCachedSessions: 0 });

  return (method, path, body) => new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : undefined;
    const req = https.request({
      method,
      host,
      port,
      path,
      headers: {
        Authorization: `PVEAPIToken=${tokenId}=${apiKey}`,
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
      rejectUnauthorized: false,
      agent,
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
    req.on('socket', (socket) => {
      const verify = () => {
        const cert = socket.getPeerCertificate();
        const actual = cert.fingerprint256;
        if (!actual || actual.replace(/:/g, '').toUpperCase() !== fingerprint.replace(/:/g, '').toUpperCase()) {
          req.destroy(new Error(`Proxmox TLS fingerprint mismatch: expected ${fingerprint}, got ${actual}`));
        }
      };
      if (socket.secureConnecting === false) {
        verify(); // already-established, reused socket - verify synchronously right now
      } else {
        socket.once('secureConnect', verify); // fresh handshake - verify once it completes
      }
    });
    if (payload) req.write(payload);
    req.end();
  });
}

export class ProxmoxClient {
  constructor({
    host,
    port,
    tokenId,
    apiKey,
    fingerprint,
    fetchImpl,
    now = Date.now,
    sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  }) {
    this.host = host;
    this.fetchImpl = fetchImpl ?? realFetch({ host, port, tokenId, apiKey, fingerprint });
    this.now = now;
    this.sleep = sleep;
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
    if (!responseBody || !('data' in responseBody)) {
      throw new Error(`Proxmox API response for ${method} ${path} had no "data" field: ${JSON.stringify(responseBody)}`);
    }
    return responseBody.data;
  }

  async waitForTask(node, upid, { pollIntervalMs = 1000, timeoutMs = 300000 } = {}) {
    const start = this.now();
    for (;;) {
      const status = await this.request('GET', `/nodes/${node}/tasks/${encodeURIComponent(upid)}/status`);
      if (status.status !== 'running') return status;
      if (this.now() - start > timeoutMs) {
        throw new Error(`waitForTask timed out after ${timeoutMs}ms waiting for ${upid}`);
      }
      await this.sleep(pollIntervalMs);
    }
  }
}
