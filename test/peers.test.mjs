import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { PeerBook } from '../mcp/peers.mjs';
import { fingerprintFromPublicKey, shortFingerprint } from '../shared/fingerprint.mjs';
import { tempDir } from './helpers.mjs';

const fpA = fingerprintFromPublicKey(Buffer.alloc(32, 1));
const fpB = fingerprintFromPublicKey(Buffer.alloc(32, 2));

function book() {
  return new PeerBook({ home: tempDir('peers') });
}

test('a new peer gets its advertised label as the local alias', () => {
  const b = book();
  const { alias, collision } = b.upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  assert.equal(alias, 'bob');
  assert.equal(collision, false);
  assert.equal(b.resolve('bob'), fpA);
  assert.equal(b.aliasFor(fpA), 'bob');
});

test('a colliding label is suffixed and the collision is reported', () => {
  const b = book();
  b.upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  const second = b.upsert({ fingerprint: fpB, label: 'bob', status: 'active', linkedAt: 'now' });
  assert.equal(second.alias, 'bob-2');
  assert.equal(second.collision, true, 'the user must be told, not silently confused');
  assert.equal(b.resolve('bob'), fpA, 'the original keeps the plain name');
  assert.equal(b.resolve('bob-2'), fpB);
});

test('a fingerprint resolves to itself, so callers can always address directly', () => {
  const b = book();
  assert.equal(b.resolve(fpA), fpA);
});

test('an unknown alias fails with a message naming it', () => {
  const b = book();
  assert.throws(() => b.resolve('nobody'), /nobody/);
});

test('the book persists across instances', () => {
  const home = tempDir('peers');
  new PeerBook({ home }).upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  assert.equal(new PeerBook({ home }).resolve('bob'), fpA);
  assert.ok(fs.existsSync(path.join(home, 'peers.json')));
});

test('verifying requires the short form to actually match', () => {
  const b = book();
  b.upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  assert.throws(() => b.setVerified('bob', 'AAAA-BBBB-CCCC'), /does not match/i);
  assert.equal(b.list()[0].verified, false);

  const ok = b.setVerified('bob', shortFingerprint(fpA));
  assert.equal(ok.verified, true);
  assert.equal(b.list()[0].verified, true);
});

test('verification tolerates how a human retypes the code', () => {
  const b = book();
  b.upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  const messy = shortFingerprint(fpA).toLowerCase().replace(/-/g, ' ');
  assert.equal(b.setVerified('bob', messy).verified, true);
});

test('verifying with an invalid fingerprint is a distinct error from a mismatch', () => {
  const b = book();
  b.upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  assert.throws(() => b.setVerified('bob', 'not a valid code!'), /not a valid fingerprint/i);
  assert.equal(b.list()[0].verified, false);
});

test('diff reports newly linked peers and applies them', () => {
  const b = book();
  const events = b.diff([
    { fingerprint: fpA, label: 'bob', status: 'active', linked_at: 'now' },
  ]);
  assert.equal(events.linked.length, 1);
  assert.equal(events.linked[0].alias, 'bob');
  assert.equal(events.linked[0].short, shortFingerprint(fpA));
  assert.equal(b.resolve('bob'), fpA);

  // A second identical poll is quiet.
  assert.deepEqual(b.diff([{ fingerprint: fpA, label: 'bob', status: 'active', linked_at: 'now' }]), {
    linked: [], revoked: [],
  });
});

test('diff reports a peer who revoked from their side', () => {
  const b = book();
  b.diff([{ fingerprint: fpA, label: 'bob', status: 'active', linked_at: 'now' }]);
  const events = b.diff([{ fingerprint: fpA, label: 'bob', status: 'revoked', linked_at: 'now' }]);
  assert.equal(events.revoked.length, 1);
  assert.equal(events.revoked[0].alias, 'bob');
  assert.equal(b.list()[0].status, 'revoked', 'kept, so the user can see what happened');
});

test('removing a peer frees its alias', () => {
  const b = book();
  b.upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  b.remove(fpA);
  assert.throws(() => b.resolve('bob'));
  assert.equal(b.upsert({ fingerprint: fpB, label: 'bob', status: 'active', linkedAt: 'now' }).alias, 'bob');
});

test('peers.json and its directory are private to the owner', () => {
  const home = tempDir('peers');
  new PeerBook({ home }).upsert({ fingerprint: fpA, label: 'bob', status: 'active', linkedAt: 'now' });
  const file = path.join(home, 'peers.json');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(home).mode & 0o777, 0o700);
});
