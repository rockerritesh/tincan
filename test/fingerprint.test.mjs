// test/fingerprint.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  encodeBase32, normalizeBase32, fingerprintFromPublicKey,
  shortFingerprint, isFingerprint, FP_PREFIX, FP_BODY_LENGTH,
} from '../shared/fingerprint.mjs';

test('base32 uses the Crockford alphabet and omits I L O U', () => {
  const encoded = encodeBase32(Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff]));
  assert.equal(encoded, 'ZZZZZZZZ');
  assert.equal(encodeBase32(Buffer.from([0x00])), '00');
  assert.match(encodeBase32(crypto.randomBytes(64)), /^[0-9A-HJKMNP-TV-Z]+$/);
});

test('normalizeBase32 forgives how a human types a code', () => {
  assert.equal(normalizeBase32('4k7m-2xq9'), '4K7M2XQ9');
  assert.equal(normalizeBase32(' 4K7M 2XQ9 '), '4K7M2XQ9');
  assert.equal(normalizeBase32('OIL'), '011', 'O->0, I->1, L->1');
  assert.throws(() => normalizeBase32('4K7M!'), /invalid base32/);
});

test('a fingerprint is derived from the key, is stable, and is 29 chars', () => {
  const pub = Buffer.alloc(32, 7);
  const fp = fingerprintFromPublicKey(pub);
  assert.equal(fp, fingerprintFromPublicKey(pub), 'deterministic');
  assert.equal(fp.length, FP_PREFIX.length + FP_BODY_LENGTH);
  assert.ok(fp.startsWith(FP_PREFIX));
  assert.match(fp, /^tc1[0-9a-hjkmnp-tv-z]{26}$/);
  assert.notEqual(fp, fingerprintFromPublicKey(Buffer.alloc(32, 8)), 'different key, different fp');
});

test('fingerprint rejects anything that is not a 32-byte key', () => {
  assert.throws(() => fingerprintFromPublicKey(Buffer.alloc(31)), /32-byte/);
  assert.throws(() => fingerprintFromPublicKey(Buffer.alloc(33)), /32-byte/);
});

test('a fingerprint is usable as a filesystem path segment', () => {
  // The store validates ids with this pattern; fingerprints must satisfy it,
  // because they become directory names under keys/ and inbox/. Spec §4.2.
  const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  assert.match(fingerprintFromPublicKey(crypto.randomBytes(32)), SAFE_ID);
});

test('the short form is 12 chars grouped for reading aloud', () => {
  const fp = fingerprintFromPublicKey(Buffer.alloc(32, 1));
  const short = shortFingerprint(fp);
  assert.match(short, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.equal(short.replace(/-/g, '').toLowerCase(), fp.slice(FP_PREFIX.length, FP_PREFIX.length + 12));
});

test('isFingerprint accepts real ones and rejects near-misses', () => {
  const fp = fingerprintFromPublicKey(Buffer.alloc(32, 3));
  assert.equal(isFingerprint(fp), true);
  assert.equal(isFingerprint(fp.toUpperCase()), false, 'canonical form is lowercase');
  assert.equal(isFingerprint(fp.slice(0, -1)), false, 'wrong length');
  assert.equal(isFingerprint('tc1' + 'i'.repeat(26)), false, 'i is not in the alphabet');
  assert.equal(isFingerprint('xx1' + fp.slice(3)), false, 'wrong prefix');
  assert.equal(isFingerprint(undefined), false);
});
