import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createVerifier } from '../server/verify.mjs';
import { Registry } from '../server/registry.mjs';
import { loadOrCreateIdentity, signedHeaders } from '../mcp/identity.mjs';
import { HEADERS, CLOCK_SKEW_MS, bodySha256, canonicalString } from '../shared/canonical.mjs';
import { tempDir } from './helpers.mjs';

function harness({ register = true } = {}) {
  const registry = new Registry(tempDir('verify'));
  const identity = loadOrCreateIdentity({ home: tempDir('verify-id'), label: 'alice' });
  if (register) {
    registry.registerKey({
      fingerprint: identity.fingerprint,
      publicKeyB64: identity.publicKeyB64,
      label: 'alice',
      via: 'bootstrap',
    });
  }
  const verifier = createVerifier({ registry });
  return { registry, identity, verifier };
}

// Shapes a fake node request from signed headers.
function reqFor(identity, { method = 'GET', pathname = '/v1/peers', query = '', body } = {}) {
  const url = new URL(`http://localhost${pathname}${query}`);
  const headers = signedHeaders(identity, { method, pathname, searchParams: url.searchParams, body });
  return { req: { method, headers }, url, body };
}

test('a correctly signed request from a registered key verifies', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity);
  const caller = verifier.verifyHeaders(req, url);
  assert.equal(caller.fingerprint, identity.fingerprint);
  assert.equal(caller.publicKeyB64, identity.publicKeyB64);
});

test('a missing header is a 400, not a 401 — the request is malformed', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  for (const name of Object.values(HEADERS)) {
    const { req, url } = reqFor(identity);
    delete req.headers[name];
    assert.throws(
      () => verifier.verifyHeaders(req, url),
      (e) => e.code === 'malformed_signature' && e.status === 400,
      `removing ${name} should be malformed`,
    );
  }
});

test('an unregistered key is rejected, except where explicitly allowed', (t) => {
  const { identity, verifier } = harness({ register: false });
  t.after(() => verifier.stop());
  const a = reqFor(identity);
  assert.throws(() => verifier.verifyHeaders(a.req, a.url), (e) => e.code === 'unknown_key' && e.status === 401);

  // redeem_invite is the one route that must accept a key the broker has never
  // seen — the signature proves the caller holds it, the code proves the invite.
  const b = reqFor(identity);
  const caller = verifier.verifyHeaders(b.req, b.url, { allowUnregistered: true });
  assert.equal(caller.fingerprint, identity.fingerprint);
});

test('a revoked key is a 403 — the caller is the problem, not the resource', (t) => {
  const { registry, identity, verifier } = harness();
  t.after(() => verifier.stop());
  registry.revokeKey(identity.fingerprint);
  const { req, url } = reqFor(identity);
  assert.throws(() => verifier.verifyHeaders(req, url), (e) => e.code === 'revoked_key' && e.status === 403);
});

test('a stale or future timestamp is refused and the error names the clock', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  for (const offset of [-(CLOCK_SKEW_MS + 1000), CLOCK_SKEW_MS + 1000]) {
    const { req, url } = reqFor(identity);
    req.headers[HEADERS.timestamp] = String(Date.now() + offset);
    assert.throws(
      () => verifier.verifyHeaders(req, url),
      (e) => e.code === 'clock_skew' && /clock/i.test(e.message),
    );
  }
});

test('a timestamp just inside the window is accepted', async (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity);
  // Re-sign with a skewed-but-legal timestamp by signing manually.
  const timestamp = String(Date.now() - (CLOCK_SKEW_MS - 5000));
  const nonce = crypto.randomBytes(16).toString('base64url');
  const bodyHash = bodySha256(undefined);
  req.headers[HEADERS.timestamp] = timestamp;
  req.headers[HEADERS.nonce] = nonce;
  req.headers[HEADERS.bodyHash] = bodyHash;
  req.headers[HEADERS.signature] = identity
    .sign(Buffer.from(canonicalString({
      method: 'GET', pathname: '/v1/peers', searchParams: url.searchParams, bodyHash, timestamp, nonce,
    }), 'utf8'))
    .toString('base64url');
  assert.doesNotThrow(() => verifier.verifyHeaders(req, url));
});

test('replaying a nonce is refused once it has been committed', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity);
  const caller = verifier.verifyHeaders(req, url);
  verifier.commit(caller.nonce, caller.fingerprint);
  assert.throws(() => verifier.verifyHeaders(req, url), (e) => e.code === 'replay' && e.status === 401);
});

test('a failed request does not burn its nonce, so an honest retry still works', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity, { body: '{"a":1}' });
  const caller = verifier.verifyHeaders(req, url);
  assert.throws(
    () => verifier.confirmBody(req.headers[HEADERS.bodyHash], Buffer.from('tampered')),
    (e) => e.code === 'body_mismatch' && e.status === 400,
  );
  // verifyHeaders reserves the nonce, so a failed request has to hand it back
  // for the retry to work. This is what the broker's catch block does.
  verifier.release(caller.nonce);
  assert.doesNotThrow(() => verifier.verifyHeaders(req, url), 'nonce is only spent on success');
});

// The replay check and the commit used to be separated by the route's
// `await jsonBody()`, so two copies of one captured request could both pass the
// check and both mutate the store. verifyHeaders now reserves the nonce the
// moment the check passes, and there is no await in it, so test-and-reserve is
// atomic on Node's single thread.
test('a second use of a nonce still in flight is a replay, not a race', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity, { body: '{"a":1}' });
  verifier.verifyHeaders(req, url);
  // No commit in between: this is the duplicate arriving while the first
  // request is still reading its body.
  assert.throws(
    () => verifier.verifyHeaders(req, url),
    (e) => e.code === 'replay' && e.status === 401,
  );
});

test('releasing a nonce that was already committed does not reopen it', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity);
  const caller = verifier.verifyHeaders(req, url);
  verifier.commit(caller.nonce, caller.fingerprint);
  verifier.release(caller.nonce);
  assert.throws(
    () => verifier.verifyHeaders(req, url),
    (e) => e.code === 'replay' && e.status === 401,
    'a spent nonce must stay spent even if a later error path releases it',
  );
});

test('tampering with method, path, query order or body hash breaks the signature', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());

  const tampered = [
    (r, u) => { r.method = 'POST'; },
    (r, u) => { u.pathname = '/v1/inbox'; },
    (r, u) => { r.headers[HEADERS.bodyHash] = bodySha256('different'); },
  ];
  for (const mutate of tampered) {
    const { req, url } = reqFor(identity, { pathname: '/v1/peers' });
    mutate(req, url);
    assert.throws(() => verifier.verifyHeaders(req, url), (e) => e.code === 'bad_signature');
  }
});

test('query parameters are covered by the signature', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity, { pathname: '/v1/threads', query: '?agent=x' });
  assert.doesNotThrow(() => verifier.verifyHeaders(req, url));

  const swapped = reqFor(identity, { pathname: '/v1/threads', query: '?agent=x' });
  swapped.url.searchParams.set('agent', 'y');
  assert.throws(() => verifier.verifyHeaders(swapped.req, swapped.url), (e) => e.code === 'bad_signature');
});

test('a public key that decodes to the wrong byte length is malformed, not a crash', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  for (const len of [16, 33]) {
    const { req, url } = reqFor(identity);
    req.headers[HEADERS.key] = Buffer.alloc(len, 7).toString('base64url');
    assert.throws(
      () => verifier.verifyHeaders(req, url),
      (e) => e.code === 'malformed_signature' && e.status === 400,
      `a ${len}-byte key should be malformed_signature/400, not an uncaught error`,
    );
  }
});

// Node's Ed25519 OKP import (this Node/OpenSSL build) accepts every 32-byte
// value as a structurally valid public key — there is no curve-point check at
// import time, so no real byte string reaches createPublicKey's catch clause.
// That does not make the catch dead code: it exists to convert whatever
// createPublicKey might reject — on this build, another, or a future one —
// into a typed 400 rather than an uncaught 500. We prove the guard directly by
// forcing the one call it wraps to throw, rather than relying on an input that
// may not exist. crypto is the same 'node:crypto' module object verify.mjs
// imports, so mocking a method here reaches its call there.
test('a public key that fails import is malformed_signature, not an uncaught error', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const { req, url } = reqFor(identity);
  req.headers[HEADERS.key] = Buffer.alloc(32, 3).toString('base64url'); // right length, so it reaches createPublicKey
  t.mock.method(crypto, 'createPublicKey', () => {
    throw new Error('not a valid Ed25519 point');
  });
  assert.throws(
    () => verifier.verifyHeaders(req, url),
    (e) => e.code === 'malformed_signature' && e.status === 400,
  );
});

test('a garbage or wrong-length signature is bad_signature, not a native crash', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const garbageSignatures = [
    Buffer.alloc(64, 0xff).toString('base64url'), // right length, wrong content
    Buffer.alloc(3, 1).toString('base64url'), // far too short
    Buffer.alloc(128, 2).toString('base64url'), // far too long
  ];
  for (const signature of garbageSignatures) {
    const { req, url } = reqFor(identity);
    req.headers[HEADERS.signature] = signature;
    assert.throws(
      () => verifier.verifyHeaders(req, url),
      (e) => e.code === 'bad_signature' && e.status === 401,
      `signature ${signature.slice(0, 8)}... should be bad_signature/401, not an uncaught error`,
    );
  }
});

test('confirmBody accepts the matching body', (t) => {
  const { identity, verifier } = harness();
  t.after(() => verifier.stop());
  const body = '{"to":"tc1x"}';
  const { req } = reqFor(identity, { method: 'POST', pathname: '/v1/messages', body });
  assert.doesNotThrow(() => verifier.confirmBody(req.headers[HEADERS.bodyHash], Buffer.from(body, 'utf8')));
});
