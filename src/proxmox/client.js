// src/proxmox/client.js
import https from 'node:https';

function realFetch({ host, tokenId, apiKey, fingerprint }) {
  return (method, path, body) => new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : undefined;
    const req = https.request({
      method,
      host,
      port: 8006,
      path,
      headers: {
        Authorization: `PVEAPIToken=${tokenId}=${apiKey}`,
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
    this.fetchImpl = fetchImpl ?? realFetch({ host, tokenId, apiKey, fingerprint });
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
