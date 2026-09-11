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
  // nonce -> { expiresAt, spent }. A nonce is *reserved* the moment the replay
  // check passes and *spent* once the request succeeds. Reserving matters
  // because a route's `await jsonBody()` sits between the two: without it, two
  // copies of one captured request would both pass the check and both act.
  // Reservations expire on the same TTL, so a crash between reserve and release
  // cannot wedge a nonce forever.
  const seen = new Map();

  const sweep = setInterval(() => {
    const cutoff = now();
    for (const [nonce, entry] of seen) if (entry.expiresAt <= cutoff) seen.delete(nonce);
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

      // 7. reserve the nonce. Nothing above this line awaits, so the check at
      // step 4 and this reservation are one atomic step — a duplicate arriving
      // while this request reads its body finds the reservation and is refused.
      // Reserved last so a request rejected above leaves nothing behind.
      seen.set(nonce, { expiresAt: now() + NONCE_TTL_MS, spent: false });

      return { fingerprint, publicKeyB64, claimedBodyHash, nonce };
    },

    // 8. body integrity, after the cheap checks have already passed
    confirmBody(claimedBodyHash, buffer) {
      if (bodySha256(buffer) !== claimedBodyHash) {
        throw new StoreError('body_mismatch', 'body does not match the signed hash', 400);
      }
    },

    // 9. drop a reservation, so a request that failed after verifying does not
    // stop an honest retry of the same signed request. A nonce that already
    // reached commit() is spent and stays spent: releasing it must not reopen
    // the replay window.
    release(nonce) {
      const entry = seen.get(nonce);
      if (entry && !entry.spent) seen.delete(nonce);
    },

    // 10. promote the reservation to spent, once the request is known good.
    commit(nonce, fingerprint) {
      seen.set(nonce, { expiresAt: now() + NONCE_TTL_MS, spent: true });
      registry.touchKey(fingerprint);
    },

    stop() {
      clearInterval(sweep);
    },
  };
}
