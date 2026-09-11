import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { Registry, DATA_VERSION, INVITE_TTL_MS } from '../server/registry.mjs';
import { fingerprintFromPublicKey } from '../shared/fingerprint.mjs';
import { tempDir } from './helpers.mjs';

const fpA = fingerprintFromPublicKey(Buffer.alloc(32, 1));
const fpB = fingerprintFromPublicKey(Buffer.alloc(32, 2));
const fpC = fingerprintFromPublicKey(Buffer.alloc(32, 3));

function fresh() {
  return new Registry(tempDir('registry'));
}

test('a fresh directory is stamped with the data version', () => {
  const r = fresh();
  assert.equal(fs.readFileSync(path.join(r.root, 'VERSION'), 'utf8').trim(), String(DATA_VERSION));
});

test('a directory from an older layout is refused, not migrated', () => {
  const root = tempDir('registry');
  // Simulate a 0.1.x folder: message data present, no VERSION stamp.
  fs.mkdirSync(path.join(root, 'messages'), { recursive: true });
  fs.writeFileSync(path.join(root, 'messages', 'msg_old.json'), '{}');
  assert.throws(() => new Registry(root), (e) => e.code === 'data_version');
});

test('an empty directory with only empty store subfolders is accepted, not refused', () => {
  const root = tempDir('registry');
  // Store's constructor creates these directories on a brand-new data dir, but
  // never puts anything in them until something is actually stored. Registry
  // must not mistake "the directory exists" for "this folder holds old data".
  fs.mkdirSync(path.join(root, 'messages'), { recursive: true });
  fs.mkdirSync(path.join(root, 'threads'), { recursive: true });
  assert.doesNotThrow(() => new Registry(root));
});

test('keys register, are readable, and carry provenance', () => {
  const r = fresh();
  const rec = r.registerKey({ fingerprint: fpA, publicKeyB64: 'AAA', label: 'alice', via: 'bootstrap' });
  assert.equal(rec.status, 'active');
  assert.equal(rec.registered_via, 'bootstrap');
  assert.equal(r.getKey(fpA).label, 'alice');
  assert.equal(r.getKey(fpB), null);
});

test('registering an existing key is idempotent and does not reset provenance', () => {
  const r = fresh();
  r.registerKey({ fingerprint: fpA, publicKeyB64: 'AAA', label: 'alice', via: 'bootstrap' });
  const again = r.registerKey({ fingerprint: fpA, publicKeyB64: 'AAA', label: 'renamed', via: 'inv_x' });
  assert.equal(again.registered_via, 'bootstrap', 'first registration wins');
});

test('links live in one file per pair regardless of who initiated', () => {
  const r = fresh();
  assert.equal(r.linkPath(fpA, fpB), r.linkPath(fpB, fpA), 'sorted, so exactly one file exists');
  r.createLink({ a: fpB, b: fpA, via: 'inv_1' });
  assert.equal(r.linkStatus(fpA, fpB), 'active');
  assert.equal(r.linkStatus(fpB, fpA), 'active', 'links are undirected');
  assert.equal(r.linkStatus(fpA, fpC), 'none');
});

test('revoking a link keeps the record and blocks both directions', () => {
  const r = fresh();
  r.createLink({ a: fpA, b: fpB, via: 'inv_1' });
  const revoked = r.revokeLink({ a: fpA, b: fpB, by: fpA });
  assert.equal(revoked.status, 'revoked');
  assert.equal(revoked.revoked_by, fpA);
  assert.ok(revoked.revoked_at);
  assert.equal(r.linkStatus(fpA, fpB), 'revoked');
  assert.equal(r.linkStatus(fpB, fpA), 'revoked');
  assert.ok(fs.existsSync(r.linkPath(fpA, fpB)), 'kept on disk — a revoke is auditable, not an erasure');
});

test('re-linking a revoked pair reactivates the existing file', () => {
  const r = fresh();
  r.createLink({ a: fpA, b: fpB, via: 'inv_1' });
  r.revokeLink({ a: fpA, b: fpB, by: fpA });
  const relinked = r.createLink({ a: fpA, b: fpB, via: 'inv_2' });
  assert.equal(relinked.status, 'active');
  assert.equal(relinked.created_via, 'inv_2');
  assert.equal(relinked.revoked_at, null);
});

test('peersOf returns only this agent, with labels resolved', () => {
  const r = fresh();
  r.registerKey({ fingerprint: fpA, publicKeyB64: 'A', label: 'alice', via: 'bootstrap' });
  r.registerKey({ fingerprint: fpB, publicKeyB64: 'B', label: 'bob', via: 'inv_1' });
  r.registerKey({ fingerprint: fpC, publicKeyB64: 'C', label: 'carol', via: 'inv_2' });
  r.createLink({ a: fpA, b: fpB, via: 'inv_1' });
  r.createLink({ a: fpB, b: fpC, via: 'inv_2' });

  assert.deepEqual(r.peersOf(fpA).map((p) => p.label), ['bob']);
  assert.deepEqual(r.peersOf(fpB).map((p) => p.label).sort(), ['alice', 'carol']);
  assert.deepEqual(r.peersOf(fpC).map((p) => p.label), ['bob']);
});

test('an invite stores only the hash of its code', () => {
  const r = fresh();
  const { invite, code } = r.createInvite({ issuer: fpA, issuerLabel: 'alice' });
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.equal(invite.status, 'open');
  assert.equal(invite.code_sha256, crypto.createHash('sha256')
    .update(code.replace(/-/g, '')).digest('hex'));

  const onDisk = fs.readFileSync(path.join(r.root, 'invites', `${invite.code_sha256}.json`), 'utf8');
  assert.equal(onDisk.includes(code.replace(/-/g, '')), false, 'plaintext code must never be stored');
});

test('an invite is single use', () => {
  const r = fresh();
  const { code } = r.createInvite({ issuer: fpA, issuerLabel: 'alice' });
  const used = r.consumeInvite({ code, redeemer: fpB });
  assert.equal(used.status, 'used');
  assert.equal(used.redeemed_by, fpB);
  assert.throws(() => r.consumeInvite({ code, redeemer: fpC }), (e) => e.code === 'invite_spent');
});

test('an expired invite is refused and marked expired', () => {
  const r = fresh();
  const { invite, code } = r.createInvite({ issuer: fpA, issuerLabel: 'alice', now: 0 });
  assert.equal(new Date(invite.expires_at).getTime(), INVITE_TTL_MS);
  assert.throws(
    () => r.consumeInvite({ code, redeemer: fpB, now: INVITE_TTL_MS + 1 }),
    (e) => e.code === 'invite_expired',
  );
  assert.equal(r.getInviteByCode(code).status, 'expired');
});

test('an unknown code does not reveal whether any invite exists', () => {
  const r = fresh();
  assert.throws(
    () => r.consumeInvite({ code: 'ZZZZ-ZZZZ-ZZZZ-ZZZZ', redeemer: fpB }),
    (e) => e.code === 'unknown_invite' && e.status === 404,
  );
});

test('a malformed code is treated as unknown, not a crash', () => {
  const r = fresh();
  const malformed = 'ZZZZ-ZZZZ-ZZZZ-!!!!'; // '!' is outside the Crockford alphabet
  assert.doesNotThrow(() => r.getInviteByCode(malformed));
  assert.equal(r.getInviteByCode(malformed), null);
  assert.throws(
    () => r.consumeInvite({ code: malformed, redeemer: fpB }),
    (e) => e.code === 'unknown_invite' && e.status === 404,
  );
});

test('codes are normalized, so how a human types them does not matter', () => {
  const r = fresh();
  const { code } = r.createInvite({ issuer: fpA, issuerLabel: 'alice' });
  const messy = ` ${code.toLowerCase().replace(/-/g, ' ')} `;
  assert.doesNotThrow(() => r.consumeInvite({ code: messy, redeemer: fpB }));
});
