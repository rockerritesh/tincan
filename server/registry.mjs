// Who exists, who may talk to whom, and the invites that created those links.
// Separate from store.mjs on purpose: that file already owns messages, offers
// and threads at ~466 lines, and folding three more record types into it would
// push it past 700.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { StoreError } from './store.mjs';
import { isFingerprint, encodeBase32, normalizeBase32 } from '../shared/fingerprint.mjs';

export const DATA_VERSION = 2;
export const INVITE_TTL_MS = 900000;
const CODE_BYTES = 10; // 80 bits -> 16 base32 chars

function nowIso(ms) {
  return new Date(ms ?? Date.now()).toISOString();
}

function requireFingerprint(value, what) {
  if (!isFingerprint(value)) throw new StoreError('invalid_fingerprint', `${what} is not a fingerprint`, 400);
  return value;
}

function hashCode(code) {
  return crypto.createHash('sha256').update(normalizeBase32(code)).digest('hex');
}

export class Registry {
  constructor(root) {
    this.root = path.resolve(root);
    this.dirs = {
      keys: path.join(this.root, 'keys'),
      links: path.join(this.root, 'links'),
      invites: path.join(this.root, 'invites'),
    };
    this.#checkVersion();
    for (const dir of Object.values(this.dirs)) fs.mkdirSync(dir, { recursive: true });
  }

  // Refuse an incompatible folder rather than half-migrating it. A 0.1.x
  // directory has message data and no VERSION stamp.
  #checkVersion() {
    const stamp = path.join(this.root, 'VERSION');
    if (fs.existsSync(stamp)) {
      const found = Number(fs.readFileSync(stamp, 'utf8').trim());
      if (found !== DATA_VERSION) {
        throw new StoreError(
          'data_version',
          `${this.root} is data version ${found}, this broker speaks ${DATA_VERSION}. `
          + 'Point DATA_DIR at a fresh directory.',
          500,
        );
      }
      return;
    }
    // Store's constructor creates these directories on every fresh data dir,
    // so their mere existence proves nothing — check for actual files inside
    // them, which is what "holds data" really means.
    const looksUsed = ['messages', 'threads', 'offers', 'inbox']
      .some((d) => {
        const dir = path.join(this.root, d);
        return fs.existsSync(dir) && fs.readdirSync(dir).length > 0;
      });
    if (looksUsed) {
      throw new StoreError(
        'data_version',
        `${this.root} holds data from an older tincan with no VERSION stamp. `
        + 'Point DATA_DIR at a fresh directory; there is no migration.',
        500,
      );
    }
    fs.mkdirSync(this.root, { recursive: true });
    fs.writeFileSync(stamp, `${DATA_VERSION}\n`);
  }

  #writeJson(file, obj) {
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(obj, null, 2));
    fs.renameSync(tmp, file);
  }

  #readJson(file) {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
  }

  // ---- keys ---------------------------------------------------------------

  #keyPath(fingerprint) {
    return path.join(this.dirs.keys, `${requireFingerprint(fingerprint, 'key')}.json`);
  }

  // Trust boundary: the caller must already have cryptographically verified a
  // signature from `publicKeyB64` and derived `fingerprint` from that same
  // key before calling this. registerKey deliberately does not re-derive the
  // fingerprint from publicKeyB64 to check they agree — its only legitimate
  // caller has already done so. A second caller that skips that step could
  // register a fingerprint against a key that doesn't produce it.
  registerKey({ fingerprint, publicKeyB64, label, via }) {
    const existing = this.getKey(fingerprint);
    if (existing) return existing;
    const record = {
      fingerprint,
      public_key: publicKeyB64,
      label: label ?? fingerprint,
      status: 'active',
      registered_at: nowIso(),
      registered_via: via,
      last_seen: nowIso(),
    };
    this.#writeJson(this.#keyPath(fingerprint), record);
    return record;
  }

  getKey(fingerprint) {
    if (!isFingerprint(fingerprint)) return null;
    return this.#readJson(this.#keyPath(fingerprint));
  }

  touchKey(fingerprint) {
    const record = this.getKey(fingerprint);
    if (!record) return;
    record.last_seen = nowIso();
    this.#writeJson(this.#keyPath(fingerprint), record);
  }

  revokeKey(fingerprint) {
    const record = this.getKey(fingerprint);
    if (!record) throw new StoreError('unknown_key', `no key ${fingerprint}`, 404);
    record.status = 'revoked';
    this.#writeJson(this.#keyPath(fingerprint), record);
    return record;
  }

  // ---- links --------------------------------------------------------------

  // Sorted, so exactly one file exists per pair no matter who initiated.
  // Built only from already-validated fingerprints: '~' is not in the store's
  // safeId pattern, so this path must never be derived from request input.
  linkPath(a, b) {
    const [lo, hi] = [requireFingerprint(a, 'a'), requireFingerprint(b, 'b')].sort();
    return path.join(this.dirs.links, `${lo}~${hi}.json`);
  }

  getLink(a, b) {
    return this.#readJson(this.linkPath(a, b));
  }

  linkStatus(a, b) {
    if (a === b) return 'none';
    return this.getLink(a, b)?.status ?? 'none';
  }

  createLink({ a, b, via }) {
    const [lo, hi] = [requireFingerprint(a, 'a'), requireFingerprint(b, 'b')].sort();
    if (lo === hi) throw new StoreError('self_link', 'an agent cannot link to itself', 409);
    const record = this.getLink(lo, hi) ?? { a: lo, b: hi, created_at: nowIso() };
    record.status = 'active';
    record.created_via = via;
    record.created_at = record.created_at ?? nowIso();
    record.revoked_at = null;
    record.revoked_by = null;
    this.#writeJson(this.linkPath(lo, hi), record);
    return record;
  }

  // `revoked_by` is not an audit decoration — `authz.readableBetween` reads it
  // to decide who keeps access to the shared history, so it is authorization
  // input on every read surface. Two consequences, both load-bearing:
  //
  // 1. It is validated, not stored as whatever arrived. The only route that
  //    reaches here passes `caller.fingerprint`, so there is no injection
  //    today; the guard is here so that stays true of the next caller.
  // 2. Revoking an already-revoked link is idempotent — the existing record
  //    comes back untouched. Rewriting `revoked_by` would let the *revoked*
  //    peer send one revoke of their own, become the revoker, and invert the
  //    asymmetry: they regain the shared history and lock the original
  //    revoker out of their own copy. Spec §8 promises the opposite ("a
  //    revoke is one more auditable event, not an erasure"), so the first
  //    revocation is the one that stands. `disconnect_peer` stays safe to
  //    retry, and a stranger or an unknown fingerprint still gets a 404.
  revokeLink({ a, b, by }) {
    requireFingerprint(by, 'by');
    const record = this.getLink(a, b);
    if (!record) throw new StoreError('no_link', 'there is no link to revoke', 404);
    if (record.a !== by && record.b !== by) {
      throw new StoreError('not_a_party', 'only a party to a link may revoke it', 403);
    }
    if (record.status === 'revoked') return record;
    record.status = 'revoked';
    record.revoked_at = nowIso();
    record.revoked_by = by;
    this.#writeJson(this.linkPath(a, b), record);
    return record;
  }

  peersOf(fingerprint) {
    requireFingerprint(fingerprint, 'agent');
    const out = [];
    for (const file of fs.readdirSync(this.dirs.links)) {
      if (!file.endsWith('.json')) continue;
      const link = this.#readJson(path.join(this.dirs.links, file));
      if (!link) continue;
      if (link.a !== fingerprint && link.b !== fingerprint) continue;
      const other = link.a === fingerprint ? link.b : link.a;
      out.push({
        fingerprint: other,
        label: this.getKey(other)?.label ?? other,
        status: link.status,
        linked_at: link.created_at,
        revoked_at: link.revoked_at ?? null,
      });
    }
    return out.sort((x, y) => x.fingerprint.localeCompare(y.fingerprint));
  }

  // ---- invites ------------------------------------------------------------

  #invitePath(codeSha256) {
    return path.join(this.dirs.invites, `${codeSha256}.json`);
  }

  // A bootstrap invite (bootstrap: true) has no issuer at all — it is minted
  // from the filesystem side before any identity exists on this broker, so
  // there is no one to name. Registering a pseudo-identity purely to fill
  // that field would be a standing entry in the registry that authorizes
  // everything, for no benefit; issuer: null says plainly that none exists.
  // A normal invite keeps the existing validation unchanged.
  createInvite({
    issuer = null, issuerLabel = null, ttlMs = INVITE_TTL_MS, now = Date.now(), bootstrap = false,
  } = {}) {
    if (bootstrap) {
      if (issuer != null) {
        throw new StoreError('invalid_bootstrap_invite', 'a bootstrap invite must not name an issuer', 400);
      }
    } else {
      requireFingerprint(issuer, 'issuer');
    }
    const raw = encodeBase32(crypto.randomBytes(CODE_BYTES)).slice(0, 16);
    const code = raw.match(/.{1,4}/g).join('-');
    const code_sha256 = hashCode(code);
    const invite = {
      id: `inv_${crypto.randomBytes(6).toString('hex')}`,
      code_sha256,
      issuer: bootstrap ? null : issuer,
      issuer_label: bootstrap ? null : (issuerLabel ?? issuer),
      bootstrap,
      status: 'open',
      created_at: nowIso(now),
      expires_at: nowIso(now + ttlMs),
      redeemed_by: null,
      redeemed_at: null,
    };
    this.#writeJson(this.#invitePath(code_sha256), invite);
    // The plaintext code is returned exactly once and is never persisted.
    return { invite, code };
  }

  getInviteByCode(code) {
    // A code with a character outside the Crockford alphabet cannot have been
    // issued by createInvite, so it matches no invite — return null rather
    // than let normalizeBase32's native Error escape this public method.
    let hashed;
    try {
      hashed = hashCode(code);
    } catch {
      return null;
    }
    return this.#readJson(this.#invitePath(hashed));
  }

  consumeInvite({ code, redeemer, now = Date.now() }) {
    requireFingerprint(redeemer, 'redeemer');
    // getInviteByCode itself upholds the "record or null" contract — a
    // malformed code returns null rather than throwing — so no try/catch is
    // needed here.
    const invite = this.getInviteByCode(code);
    if (!invite) throw new StoreError('unknown_invite', 'no such invite', 404);

    if (invite.status !== 'open') {
      throw new StoreError('invite_spent', `this invite is already ${invite.status}`, 409);
    }
    if (now > new Date(invite.expires_at).getTime()) {
      invite.status = 'expired';
      this.#writeJson(this.#invitePath(invite.code_sha256), invite);
      throw new StoreError('invite_expired', 'this invite has expired', 409);
    }
    if (invite.issuer === redeemer) {
      throw new StoreError('self_link', 'an agent cannot redeem its own invite', 409);
    }

    invite.status = 'used';
    invite.redeemed_by = redeemer;
    invite.redeemed_at = nowIso(now);
    this.#writeJson(this.#invitePath(invite.code_sha256), invite);
    return invite;
  }
}
