// shared/fingerprint.mjs
// An agent's identity is derived from its public key, so it can be proved and
// never merely claimed. Crockford base32 rather than RFC 4648 because the short
// form gets read aloud over a phone: I, L, O and U are absent by construction.

import crypto from 'node:crypto';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

const DECODE = new Map([...ALPHABET].map((c, i) => [c, i]));
DECODE.set('I', 1);
DECODE.set('L', 1);
DECODE.set('O', 0);

export const FP_PREFIX = 'tc1';
export const FP_BODY_LENGTH = 26;
export const FP_PATTERN = /^tc1[0-9a-hjkmnp-tv-z]{26}$/;
export const SHORT_LENGTH = 12;

export function encodeBase32(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function normalizeBase32(input) {
  const stripped = String(input).toUpperCase().replace(/[\s-]/g, '');
  let out = '';
  for (const char of stripped) {
    const value = DECODE.get(char);
    if (value === undefined) throw new Error(`invalid base32 character: ${char}`);
    out += ALPHABET[value];
  }
  return out;
}

export function fingerprintFromPublicKey(rawPublicKey) {
  if (!Buffer.isBuffer(rawPublicKey) || rawPublicKey.length !== 32) {
    throw new Error(`expected a 32-byte Ed25519 public key, got ${rawPublicKey?.length}`);
  }
  const digest = crypto.createHash('sha256').update(rawPublicKey).digest();
  return FP_PREFIX + encodeBase32(digest).slice(0, FP_BODY_LENGTH).toLowerCase();
}

export function shortFingerprint(fingerprint) {
  const body = fingerprint.slice(FP_PREFIX.length, FP_PREFIX.length + SHORT_LENGTH).toUpperCase();
  return body.match(/.{1,4}/g).join('-');
}

export function isFingerprint(value) {
  return typeof value === 'string' && FP_PATTERN.test(value);
}
