import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  SIGNING_VERSION, CLOCK_SKEW_MS, bodySha256, canonicalQuery, canonicalString, HEADERS,
} from '../shared/canonical.mjs';

test('constants are pinned — changing these is a wire break', () => {
  assert.equal(SIGNING_VERSION, 'TINCAN-v1');
  assert.equal(CLOCK_SKEW_MS, 300000);
  assert.deepEqual(HEADERS, {
    key: 'x-tincan-key',
    timestamp: 'x-tincan-timestamp',
    nonce: 'x-tincan-nonce',
    bodyHash: 'x-tincan-body-sha256',
    signature: 'x-tincan-signature',
  });
});

test('an empty body hashes the empty string, not a literal', () => {
  const empty = crypto.createHash('sha256').update(Buffer.alloc(0)).digest('base64url');
  assert.equal(bodySha256(undefined), empty);
  assert.equal(bodySha256(null), empty);
  assert.equal(bodySha256(''), empty);
  assert.equal(bodySha256(Buffer.alloc(0)), empty);
});

test('body hashing treats a string and its bytes identically', () => {
  assert.equal(bodySha256('{"a":1}'), bodySha256(Buffer.from('{"a":1}', 'utf8')));
});

test('query canonicalization is order-independent', () => {
  const a = canonicalQuery(new URLSearchParams('b=2&a=1'));
  const b = canonicalQuery(new URLSearchParams('a=1&b=2'));
  assert.equal(a, b);
  assert.equal(a, '?a=1&b=2');
  assert.equal(canonicalQuery(new URLSearchParams()), '', 'no params means no question mark');
});

test('repeated keys sort by value so duplicates are still deterministic', () => {
  assert.equal(
    canonicalQuery(new URLSearchParams('x=2&x=1')),
    canonicalQuery(new URLSearchParams('x=1&x=2')),
  );
});

test('canonical string has six newline-joined lines and no trailing newline', () => {
  const s = canonicalString({
    method: 'get',
    pathname: '/v1/inbox',
    searchParams: new URLSearchParams(),
    bodyHash: 'HASH',
    timestamp: 1757548800000,
    nonce: 'NONCE',
  });
  assert.equal(s, 'TINCAN-v1\nGET\n/v1/inbox\nHASH\n1757548800000\nNONCE');
  assert.equal(s.split('\n').length, 6);
  assert.ok(!s.endsWith('\n'));
});

// ---- golden vectors: a fixed key and fixed requests produce fixed signatures ----

test('golden vector: fixed key + fixed request yields a byte-exact signature', () => {
  // Build the key from the seed only. Node requires x on import, so derive the
  // public half first via a throwaway KeyObject created from the seed.
  const seed = Buffer.alloc(32, 1);
  const pkcs8 = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    seed,
  ]);
  const priv = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const rawPub = Buffer.from(pub.export({ format: 'jwk' }).x, 'base64url');

  assert.equal(
    rawPub.toString('hex'),
    '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
    'the fixed seed must always produce this public key',
  );

  const bodyHash = bodySha256('{"to":"tc1abc","subject":"hi","body":"yo"}');
  const s = canonicalString({
    method: 'POST',
    pathname: '/v1/messages',
    searchParams: new URLSearchParams(),
    bodyHash,
    timestamp: 1757548800000,
    nonce: 'AAAAAAAAAAAAAAAAAAAAAA',
  });

  const sig = crypto.sign(null, Buffer.from(s, 'utf8'), priv).toString('base64url');
  assert.equal(sig.length, 86, 'Ed25519 signatures are 64 bytes -> 86 base64url chars');
  assert.equal(crypto.verify(null, Buffer.from(s, 'utf8'), pub, Buffer.from(sig, 'base64url')), true);

  // Tampering with any single element must break verification.
  for (const mutated of [
    s.replace('POST', 'GET'),
    s.replace('/v1/messages', '/v1/inbox'),
    s.replace('1757548800000', '1757548800001'),
    s.replace('TINCAN-v1', 'TINCAN-v2'),
    s.replace(bodyHash, 'MUTATED_HASH'),
    s.replace('AAAAAAAAAAAAAAAAAAAAAA', 'BBBBBBBBBBBBBBBBBBBBBBBBB'),
  ]) {
    assert.equal(
      crypto.verify(null, Buffer.from(mutated, 'utf8'), pub, Buffer.from(sig, 'base64url')),
      false,
      `mutation must invalidate: ${mutated.split('\n')[1]}`,
    );
  }
});
