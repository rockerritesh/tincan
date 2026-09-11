import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../server/store.mjs';
import { Registry } from '../server/registry.mjs';
import { createServer } from '../server/broker.mjs';
import { createVerifier } from '../server/verify.mjs';
import { loadOrCreateIdentity, signedHeaders } from '../mcp/identity.mjs';

export function tempDir(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `tincan-${label}-`));
}

// Boots a real broker over a throwaway data folder, plus helpers to mint
// registered identities and link them — the setup every authorization test needs.
export async function startBroker() {
  const dataDir = tempDir('data');
  const registry = new Registry(dataDir);
  const store = new Store(dataDir);
  const verifier = createVerifier({ registry });
  const server = createServer(store, registry, { verifier });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const homes = [];

  return {
    store,
    registry,
    dataDir,
    verifier,
    baseUrl: `http://127.0.0.1:${port}`,

    // A registered, active identity.
    identity(label) {
      const home = tempDir(`id-${label}`);
      homes.push(home);
      const id = loadOrCreateIdentity({ home, label });
      registry.registerKey({
        fingerprint: id.fingerprint,
        publicKeyB64: id.publicKeyB64,
        label,
        via: 'test',
      });
      return id;
    },

    // An identity the broker has never seen.
    stranger(label) {
      const home = tempDir(`id-${label}`);
      homes.push(home);
      return loadOrCreateIdentity({ home, label });
    },

    link(a, b) {
      registry.createLink({ a: a.fingerprint ?? a, b: b.fingerprint ?? b, via: 'test' });
    },

    async stop() {
      verifier.stop();
      await new Promise((resolve) => server.close(resolve));
      fs.rmSync(dataDir, { recursive: true, force: true });
      for (const home of homes) fs.rmSync(home, { recursive: true, force: true });
    },
  };
}

// Signs as `identity`. Pass identity = null to send an unsigned request.
export async function signedApi(baseUrl, identity, method, pathname, body) {
  const url = new URL(`${baseUrl}${pathname}`);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  const headers = payload === undefined ? {} : { 'content-type': 'application/json' };

  if (identity) {
    Object.assign(headers, signedHeaders(identity, {
      method,
      pathname: url.pathname,
      searchParams: url.searchParams,
      body: payload,
    }));
  }

  const res = await fetch(url, { method, headers, body: payload });
  const isJson = (res.headers.get('content-type') ?? '').includes('application/json');
  return { status: res.status, body: isJson ? await res.json() : Buffer.from(await res.arrayBuffer()) };
}

// Raw binary PUT, signed. Used for payload uploads.
export async function signedUpload(baseUrl, identity, pathname, buffer, contentType) {
  const url = new URL(`${baseUrl}${pathname}`);
  const headers = {
    'content-type': contentType ?? 'application/octet-stream',
    ...signedHeaders(identity, {
      method: 'PUT',
      pathname: url.pathname,
      searchParams: url.searchParams,
      body: buffer,
    }),
  };
  const res = await fetch(url, { method: 'PUT', headers, body: buffer });
  const isJson = (res.headers.get('content-type') ?? '').includes('application/json');
  return { status: res.status, body: isJson ? await res.json() : Buffer.from(await res.arrayBuffer()) };
}
