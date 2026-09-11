import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { loadOrCreateIdentity, signedHeaders, defaultHome } from '../mcp/identity.mjs';
import { canonicalString, bodySha256, HEADERS } from '../shared/canonical.mjs';
import { isFingerprint } from '../shared/fingerprint.mjs';
import { tempDir } from './helpers.mjs';

test('first run generates a keypair and persists it locked down', () => {
  const home = tempDir('identity');
  // Widen the directory to prove loadOrCreateIdentity tightens it back to 0o700.
  // If this assertion could pass without the chmod in mcp/identity.mjs, the test
  // gives false confidence about the highest-consequence security setting.
  fs.chmodSync(home, 0o755);
  assert.equal(fs.statSync(home).mode & 0o777, 0o755, 'precondition: directory widened');

  const id = loadOrCreateIdentity({ home, label: 'test-machine' });

  assert.ok(isFingerprint(id.fingerprint));
  assert.equal(id.label, 'test-machine');
  assert.match(id.short, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);

  const file = path.join(home, 'identity.json');
  assert.ok(fs.existsSync(file));
  assert.equal(fs.statSync(file).mode & 0o777, 0o600, 'private key must not be group/world readable');
  assert.equal(fs.statSync(home).mode & 0o777, 0o700, 'directory must be tightened by loadOrCreateIdentity');

  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(saved.version, 1);
  assert.equal(saved.fingerprint, id.fingerprint);
  assert.ok(saved.private_key && saved.public_key);
});

test('a second load reuses the same identity rather than rotating it', () => {
  const home = tempDir('identity');
  const first = loadOrCreateIdentity({ home, label: 'a' });
  const second = loadOrCreateIdentity({ home, label: 'ignored-on-reload' });
  assert.equal(second.fingerprint, first.fingerprint);
  assert.equal(second.label, 'a', 'the stored label wins; a new label does not silently rebrand');
});

test('signing produces a signature the public key verifies', () => {
  const id = loadOrCreateIdentity({ home: tempDir('identity'), label: 'a' });
  const message = Buffer.from('hello', 'utf8');
  const sig = id.sign(message);
  const pub = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: id.publicKeyB64 },
    format: 'jwk',
  });
  assert.equal(sig.length, 64);
  assert.equal(crypto.verify(null, message, pub, sig), true);
  assert.equal(crypto.verify(null, Buffer.from('hell0'), pub, sig), false);
});

test('signedHeaders returns all five headers and they verify against the canonical string', () => {
  const id = loadOrCreateIdentity({ home: tempDir('identity'), label: 'a' });
  const body = '{"to":"tc1x"}';
  const headers = signedHeaders(id, {
    method: 'POST',
    pathname: '/v1/messages',
    searchParams: new URLSearchParams(),
    body,
  });

  for (const name of Object.values(HEADERS)) {
    assert.ok(headers[name], `missing header ${name}`);
  }
  assert.equal(headers[HEADERS.key], id.publicKeyB64);
  assert.equal(headers[HEADERS.bodyHash], bodySha256(body));
  assert.ok(Math.abs(Date.now() - Number(headers[HEADERS.timestamp])) < 5000);

  const expected = canonicalString({
    method: 'POST',
    pathname: '/v1/messages',
    searchParams: new URLSearchParams(),
    bodyHash: headers[HEADERS.bodyHash],
    timestamp: headers[HEADERS.timestamp],
    nonce: headers[HEADERS.nonce],
  });
  const pub = crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'Ed25519', x: id.publicKeyB64 },
    format: 'jwk',
  });
  assert.equal(
    crypto.verify(null, Buffer.from(expected, 'utf8'), pub, Buffer.from(headers[HEADERS.signature], 'base64url')),
    true,
  );
});

test('every request gets a fresh nonce', () => {
  const id = loadOrCreateIdentity({ home: tempDir('identity'), label: 'a' });
  const seen = new Set();
  for (let i = 0; i < 50; i += 1) {
    const h = signedHeaders(id, { method: 'GET', pathname: '/v1/peers', searchParams: new URLSearchParams() });
    assert.equal(seen.has(h[HEADERS.nonce]), false, 'nonce reuse would be rejected as a replay');
    seen.add(h[HEADERS.nonce]);
  }
});

test('defaultHome honours TINCAN_HOME', () => {
  const previous = process.env.TINCAN_HOME;
  process.env.TINCAN_HOME = '/tmp/tincan-test-home';
  assert.equal(defaultHome(), '/tmp/tincan-test-home');
  if (previous === undefined) delete process.env.TINCAN_HOME;
  else process.env.TINCAN_HOME = previous;
});
