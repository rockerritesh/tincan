// Turns an incoming request into a proved identity, or refuses it.
//
// The order below is load-bearing. Cheap checks come first, and the registry
// lookup happens BEFORE any body is read, so an unauthorized 64MB upload costs
// nothing. The body hash arrives in a header precisely so the signature can be
// checked before a single byte of body is consumed.

import crypto from 'node:crypto';
import { StoreError } from './store.mjs';
import { fingerprintFromPublicKey } from '../shared/fingerprint.mjs';
import { canonicalString, bodySha256, HEADERS, CLOCK_SKEW_MS, NONCE_TTL_MS } from '../shared/canonical.mjs';

export function createVerifier({ registry, now = () => Date.now() }) {
  const seen = new Map(); // nonce -> expiry ms

  const sweep = setInterval(() => {
    const cutoff = now();
    for (const [nonce, expiry] of seen) if (expiry <= cutoff) seen.delete(nonce);
  }, 60000);
  sweep.unref?.();

  function header(req, name) {
    const value = req.headers[name];
    if (typeof value !== 'string' || value === '') {
      throw new StoreError('malformed_signature', `missing or empty ${name}`, 400);
    }
    return value;
  }

  return {
    verifyHeaders(req, url, { allowUnregistered = false } = {}) {
      // 1. all five headers present
      const publicKeyB64 = header(req, HEADERS.key);
      const timestamp = header(req, HEADERS.timestamp);
      const nonce = header(req, HEADERS.nonce);
      const claimedBodyHash = header(req, HEADERS.bodyHash);
      const signature = header(req, HEADERS.signature);

      // 2. derive the identity from the key itself
      let fingerprint;
      let publicKey;
      try {
        const rawKey = Buffer.from(publicKeyB64, 'base64url');
        fingerprint = fingerprintFromPublicKey(rawKey);
        publicKey = crypto.createPublicKey({
          key: { kty: 'OKP', crv: 'Ed25519', x: publicKeyB64 },
          format: 'jwk',
        });
      } catch (err) {
        throw new StoreError('malformed_signature', `unusable public key: ${err.message}`, 400);
      }

      // 3. freshness
      const ts = Number(timestamp);
      if (!Number.isFinite(ts) || Math.abs(now() - ts) > CLOCK_SKEW_MS) {
        throw new StoreError(
          'clock_skew',
          `timestamp is outside the ${CLOCK_SKEW_MS / 1000}s window — check this machine's clock`,
          401,
        );
      }

      // 4. not a replay
      if (seen.has(nonce)) throw new StoreError('replay', 'this nonce has already been used', 401);

      // 5. the signature itself, over the CLAIMED body hash — the actual body
      // is not read here, so this check happens before any bandwidth is spent.
      const expected = canonicalString({
        method: req.method,
        pathname: url.pathname,
        searchParams: url.searchParams,
        bodyHash: claimedBodyHash,
        timestamp,
        nonce,
      });
      let ok = false;
      try {
        ok = crypto.verify(null, Buffer.from(expected, 'utf8'), publicKey, Buffer.from(signature, 'base64url'));
      } catch {
        ok = false;
      }
      if (!ok) throw new StoreError('bad_signature', 'signature does not match this request', 401);

      // 6. registry — skipped only for invite redemption
      if (!allowUnregistered) {
        const record = registry.getKey(fingerprint);
        if (!record) throw new StoreError('unknown_key', 'this key is not registered on this broker', 401);
        if (record.status !== 'active') {
          throw new StoreError('revoked_key', 'this key has been revoked', 403);
        }
      }

      return { fingerprint, publicKeyB64, claimedBodyHash, nonce };
    },

    // 7. body integrity, after the cheap checks have already passed
    confirmBody(claimedBodyHash, buffer) {
      if (bodySha256(buffer) !== claimedBodyHash) {
        throw new StoreError('body_mismatch', 'body does not match the signed hash', 400);
      }
    },

    // 8. spend the nonce only once the request is known good, so a rejected
    // request does not stop an honest retry.
    commit(nonce, fingerprint) {
      seen.set(nonce, now() + NONCE_TTL_MS);
      registry.touchKey(fingerprint);
    },

    stop() {
      clearInterval(sweep);
    },
  };
}
