// This agent's keypair. The private key is written once, at 0600 inside a 0700
// directory, and never leaves the machine — it is not sent, logged, or included
// in any request. What travels is the public key and a signature.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fingerprintFromPublicKey, shortFingerprint } from '../shared/fingerprint.mjs';
import { bodySha256, canonicalString, HEADERS } from '../shared/canonical.mjs';

export const IDENTITY_VERSION = 1;

export function defaultHome() {
  return process.env.TINCAN_HOME ?? path.join(os.homedir(), '.tincan');
}

function hydrate(record) {
  const privateKey = crypto.createPrivateKey({
    key: { kty: 'OKP', crv: 'Ed25519', d: record.private_key, x: record.public_key },
    format: 'jwk',
  });
  return {
    fingerprint: record.fingerprint,
    short: shortFingerprint(record.fingerprint),
    label: record.label,
    publicKeyB64: record.public_key,
    sign: (buffer) => crypto.sign(null, buffer, privateKey),
  };
}

export function loadOrCreateIdentity({ home = defaultHome(), label } = {}) {
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  const file = path.join(home, 'identity.json');

  if (fs.existsSync(file)) {
    const record = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (record.version !== IDENTITY_VERSION) {
      throw new Error(`unsupported identity.json version ${record.version} at ${file}`);
    }
    return hydrate(record);
  }

  if (!label) throw new Error('a label is required when creating a new identity');

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' });
  const priv = privateKey.export({ format: 'jwk' });
  const record = {
    version: IDENTITY_VERSION,
    label,
    fingerprint: fingerprintFromPublicKey(Buffer.from(pub.x, 'base64url')),
    public_key: pub.x,
    private_key: priv.d,
    created_at: new Date().toISOString(),
  };

  // Write with the restrictive mode from the start — never create it readable
  // and tighten afterwards, which leaves a window.
  fs.writeFileSync(file, JSON.stringify(record, null, 2), { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return hydrate(record);
}

export function signedHeaders(identity, { method, pathname, searchParams, body }) {
  const bodyHash = bodySha256(body);
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(16).toString('base64url');
  const signature = identity
    .sign(Buffer.from(canonicalString({ method, pathname, searchParams, bodyHash, timestamp, nonce }), 'utf8'))
    .toString('base64url');

  return {
    [HEADERS.key]: identity.publicKeyB64,
    [HEADERS.timestamp]: timestamp,
    [HEADERS.nonce]: nonce,
    [HEADERS.bodyHash]: bodyHash,
    [HEADERS.signature]: signature,
  };
}
