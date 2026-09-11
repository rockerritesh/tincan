// HTTP face of the message folder. Zero dependencies — node:http only.
//
// Identity is cryptographic, not configured: every route except /v1/health
// derives its caller from a verified Ed25519 request signature. No route reads
// an actor from the body or the query string, so there is no `from`, `agent` or
// `to`-impersonation field left to lie in — the attacks die for lack of a lever.
//
// BROKER_TOKEN survives only as a coarse outer gate ("may you reach this broker
// at all", and a single kill switch). It is checked before signature
// verification and it is not identity.

import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Store, StoreError, MAX_INLINE_BYTES } from './store.mjs';
import { Registry } from './registry.mjs';
import { createVerifier } from './verify.mjs';
import {
  requireActiveLink, assertParticipant, assertReadable, assertTwoPartyThread, scopeThreads,
  readableBetween,
} from './authz.mjs';
import { shortFingerprint } from '../shared/fingerprint.mjs';

const MAX_JSON_BYTES = 1 * 1024 * 1024;
const MAX_BLOB_BYTES = Number(process.env.MAX_BLOB_BYTES ?? 64 * 1024 * 1024);

function send(res, status, payload, headers = {}) {
  const body = Buffer.from(JSON.stringify(payload, null, 2));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': body.length,
    ...headers,
  });
  res.end(body);
}

function fail(res, status, code, message) {
  send(res, status, { error: code, message });
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        reject(new StoreError('payload_too_large', `body exceeds ${limit} bytes`, 413));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

export function createServer(store, registry, { verifier = createVerifier({ registry }) } = {}) {
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
    const segments = url.pathname.split('/').filter(Boolean);
    const method = req.method;

    // Hoisted so the catch below can hand back a reserved nonce. Null until a
    // signature has actually been verified.
    let caller = null;

    try {
      if (segments[0] !== 'v1') {
        throw new StoreError('not_found', `no route for ${method} ${url.pathname}`, 404);
      }
      const [, resource, id, action] = segments;

      // The only unauthenticated route. It answers liveness and nothing else —
      // notably not the data directory, which it used to disclose.
      if (resource === 'health' && method === 'GET') {
        return send(res, 200, {
          ok: true,
          service: 'tincan-broker',
          version: '0.2.0',
          max_inline_bytes: MAX_INLINE_BYTES,
          max_blob_bytes: MAX_BLOB_BYTES,
          auth: 'signature',
        });
      }

      // Optional coarse gate. No longer identity — just "may you reach this
      // broker at all", and a single kill switch.
      if (process.env.BROKER_TOKEN) {
        const presented = (req.headers.authorization ?? '').startsWith('Bearer ')
          ? req.headers.authorization.slice(7)
          : null;
        if (presented !== process.env.BROKER_TOKEN) {
          throw new StoreError('unauthorized', 'valid bearer token required', 401);
        }
      }

      // Invite redemption is the one route that accepts a key the broker has
      // never seen: the signature proves the caller holds it, the code proves
      // the issuer invited them.
      const isRedeem = resource === 'invites' && method === 'POST' && id === 'redeem';
      caller = verifier.verifyHeaders(req, url, { allowUnregistered: isRedeem });

      // Reads the body when a route needs one, and proves it is the body that
      // was signed. Called only after the caller is known good.
      const jsonBody = async () => {
        const raw = await readBody(req, MAX_JSON_BYTES);
        verifier.confirmBody(caller.claimedBodyHash, raw);
        if (raw.length === 0) return {};
        try {
          const parsed = JSON.parse(raw.toString('utf8'));
          if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new StoreError('invalid_json', 'body must be a JSON object');
          }
          return parsed;
        } catch (err) {
          if (err instanceof StoreError) throw err;
          throw new StoreError('invalid_json', `could not parse JSON body: ${err.message}`);
        }
      };

      // Spends the nonce, then answers. Every route with a body must have
      // awaited jsonBody() before reaching here, so a body that failed
      // confirmation never burns the nonce an honest retry needs.
      const done = (status, payload) => {
        verifier.commit(caller.nonce, caller.fingerprint);
        return send(res, status, payload);
      };

      // ---- messages -------------------------------------------------------
      if (resource === 'messages' && method === 'POST' && !id) {
        const b = await jsonBody();
        requireActiveLink(registry, caller.fingerprint, b.to);
        assertTwoPartyThread(store, {
          caller: caller.fingerprint,
          to: b.to,
          threadId: b.thread_id,
          replyTo: b.reply_to,
        });
        const message = store.createMessage({
          from: caller.fingerprint,       // never b.from
          to: b.to,
          subject: b.subject,
          body: b.body ?? null,
          contentType: b.content_type,
          threadId: b.thread_id,
          replyTo: b.reply_to,
        });
        return done(201, message);
      }
      if (resource === 'messages' && method === 'GET' && id && !action) {
        return done(200, assertReadable(registry, store.getMessage(id), caller.fingerprint));
      }
      if (resource === 'messages' && method === 'POST' && id && action === 'ack') {
        await jsonBody();
        const message = assertParticipant(store.getMessage(id), caller.fingerprint);
        return done(200, store.ackRead(caller.fingerprint, message.id));
      }
      if (resource === 'messages' && method === 'GET' && id && action === 'payload') {
        const message = assertReadable(registry, store.getMessage(id), caller.fingerprint);
        const buffer = store.readBlob(message.id);
        verifier.commit(caller.nonce, caller.fingerprint);
        res.writeHead(200, {
          'content-type': message.content_type || 'application/octet-stream',
          'content-length': buffer.length,
        });
        return res.end(buffer);
      }

      // ---- inbox ----------------------------------------------------------
      if (resource === 'inbox' && method === 'GET') {
        return done(200, {
          agent: caller.fingerprint,
          messages: store.inbox(caller.fingerprint, {
            isVisible: (message) => registry.linkStatus(caller.fingerprint, message.from) === 'active',
          }),
        });
      }

      // ---- offers ---------------------------------------------------------
      if (resource === 'offers' && method === 'POST' && !id) {
        const b = await jsonBody();
        requireActiveLink(registry, caller.fingerprint, b.to);
        assertTwoPartyThread(store, {
          caller: caller.fingerprint,
          to: b.to,
          threadId: b.thread_id,
          replyTo: b.reply_to,
        });
        return done(201, store.createOffer({
          from: caller.fingerprint,
          to: b.to,
          subject: b.subject,
          sizeBytes: b.size_bytes,
          contentType: b.content_type,
          threadId: b.thread_id,
          replyTo: b.reply_to,
        }));
      }
      if (resource === 'offers' && method === 'GET' && !id) {
        // pendingOffersFor/answeredOffersBy filter on to/from + status only —
        // a pre-existing offer would otherwise stay listed (subject and all)
        // for a peer whose link has since been revoked. Filter through the
        // same predicate the singular offer read already uses.
        return done(200, {
          agent: caller.fingerprint,
          incoming: store.pendingOffersFor(caller.fingerprint)
            .filter((o) => readableBetween(registry, caller.fingerprint, o.from)),
          answered: store.answeredOffersBy(caller.fingerprint)
            .filter((o) => readableBetween(registry, caller.fingerprint, o.to)),
        });
      }
      if (resource === 'offers' && method === 'GET' && id && !action) {
        return done(200, assertReadable(registry, store.getOffer(id), caller.fingerprint));
      }
      if (resource === 'offers' && method === 'POST' && id && action === 'respond') {
        const b = await jsonBody();
        const offer = assertParticipant(store.getOffer(id), caller.fingerprint);
        // Writes need a genuinely active link, not just "you may still read
        // your own history" — the revoker does not get to keep transacting
        // either. requireActiveLink, not readableBetween, on purpose.
        requireActiveLink(registry, offer.from, offer.to);
        return done(200, store.respondOffer({
          agent: caller.fingerprint,
          offerId: id,
          accept: b.accept === true,
          reason: b.reason ?? null,
        }));
      }
      if (resource === 'offers' && method === 'PUT' && id && action === 'payload') {
        const offer = assertParticipant(store.getOffer(id), caller.fingerprint);
        requireActiveLink(registry, offer.from, offer.to);
        const buffer = await readBody(req, MAX_BLOB_BYTES);
        verifier.confirmBody(caller.claimedBodyHash, buffer);
        const { offer: updated, message } = store.attachPayload({ agent: caller.fingerprint, offerId: id, buffer });
        return done(201, { offer: updated, message });
      }
      if (resource === 'offers' && method === 'POST' && id && action === 'close') {
        await jsonBody();
        const offer = assertParticipant(store.getOffer(id), caller.fingerprint);
        requireActiveLink(registry, offer.from, offer.to);
        return done(200, store.closeOffer({ agent: caller.fingerprint, offerId: id }));
      }

      // ---- threads --------------------------------------------------------
      if (resource === 'threads' && method === 'GET' && !id) {
        const scoped = scopeThreads(store.listThreads(null), caller.fingerprint);
        const visible = scoped.filter((thread) => {
          const other = thread.participants.find((p) => p !== caller.fingerprint);
          return !other || readableBetween(registry, caller.fingerprint, other);
        });
        return done(200, { threads: visible });
      }
      if (resource === 'threads' && method === 'GET' && id) {
        const events = store.readThread(id);
        const participants = events[0]?.participants ?? [];
        if (!participants.includes(caller.fingerprint)) {
          throw new StoreError('not_found', 'no such thread', 404);
        }
        // A revoked peer keeps no read access to a thread's history either —
        // it carries subjects and byte counts, not just metadata. Same 404 a
        // nonexistent thread gets, so this cannot become an existence oracle.
        const other = participants.find((p) => p !== caller.fingerprint);
        if (other && !readableBetween(registry, caller.fingerprint, other)) {
          throw new StoreError('not_found', 'no such thread', 404);
        }
        return done(200, { thread_id: id, events });
      }

      // ---- pairing --------------------------------------------------------
      if (resource === 'invites' && method === 'POST' && !id) {
        const b = await jsonBody();
        const key = registry.getKey(caller.fingerprint);
        const { invite, code } = registry.createInvite({
          issuer: caller.fingerprint,
          issuerLabel: key?.label ?? caller.fingerprint,
          ttlMs: Number.isInteger(b.ttl_ms) && b.ttl_ms > 0 ? b.ttl_ms : undefined,
        });
        // The code is disclosed here and nowhere else, ever.
        return done(201, {
          invite: { id: invite.id, expires_at: invite.expires_at, status: invite.status },
          code,
        });
      }

      if (isRedeem) {
        const b = await jsonBody();
        if (typeof b.code !== 'string' || b.code.trim() === '') {
          throw new StoreError('missing_code', 'a code is required', 400);
        }

        // allowUnregistered is what lets a key the broker has never seen reach
        // this route — that is the whole point of redeem. But verify.mjs's
        // registry check is skipped entirely for this route, which means a
        // key the broker knows to be revoked would otherwise sail through
        // too. registerKey is idempotent (it returns the existing revoked
        // record unchanged), so a revoked caller gains no usable access from
        // this — but it would still burn someone else's invite and leave a
        // dead link behind. Reject it explicitly, before the invite is
        // consumed.
        const callerKey = registry.getKey(caller.fingerprint);
        if (callerKey && callerKey.status !== 'active') {
          throw new StoreError('revoked_key', 'this key has been revoked', 403);
        }

        // Peek before consuming so a revoked issuer fails without burning the
        // code. A bootstrap invite has no issuer to check.
        const peek = registry.getInviteByCode(b.code);
        if (peek && !peek.bootstrap && registry.getKey(peek.issuer)?.status !== 'active') {
          throw new StoreError('issuer_revoked', 'the agent who issued this invite is no longer active', 409);
        }

        const invite = registry.consumeInvite({ code: b.code, redeemer: caller.fingerprint });
        const key = registry.registerKey({
          fingerprint: caller.fingerprint,
          publicKeyB64: caller.publicKeyB64,
          label: typeof b.label === 'string' && b.label ? b.label : caller.fingerprint,
          via: invite.id,
        });

        // A bootstrap invite has no issuer — there is nobody to link the
        // first agent to. Register the key and say so, rather than naming a
        // peer that does not exist.
        if (invite.bootstrap) {
          return done(201, {
            bootstrap: true,
            agent: {
              fingerprint: caller.fingerprint,
              label: key.label,
              short: shortFingerprint(caller.fingerprint),
            },
          });
        }

        const link = registry.createLink({ a: caller.fingerprint, b: invite.issuer, via: invite.id });
        const issuerKey = registry.getKey(invite.issuer);
        return done(201, {
          peer: {
            fingerprint: invite.issuer,
            label: issuerKey?.label ?? invite.issuer,
            short: shortFingerprint(invite.issuer),
          },
          link: { created_at: link.created_at },
        });
      }

      // ---- peers ----------------------------------------------------------
      if (resource === 'peers' && method === 'GET' && !id) {
        return done(200, {
          agent: caller.fingerprint,
          peers: registry.peersOf(caller.fingerprint).map((peer) => ({
            ...peer,
            short: shortFingerprint(peer.fingerprint),
          })),
        });
      }
      if (resource === 'peers' && method === 'POST' && id && action === 'revoke') {
        await jsonBody();
        // revokeLink throws no_link/404 when there was never a link, which is
        // also what a stranger's fingerprint produces — nothing is disclosed.
        // It also validates `id` as a fingerprint internally (requireFingerprint),
        // so a malformed :fingerprint surfaces as a typed 400, not a native throw.
        const link = registry.revokeLink({ a: caller.fingerprint, b: id, by: caller.fingerprint });
        return done(200, {
          fingerprint: id,
          status: link.status,
          revoked_at: link.revoked_at,
        });
      }

      throw new StoreError('not_found', `no route for ${method} ${url.pathname}`, 404);
    } catch (err) {
      // Every failure path releases the nonce reserved by verifyHeaders, so a
      // rejected request never costs an honest client its retry. A nonce that
      // reached commit() is already spent and release leaves it that way.
      if (caller) verifier.release(caller.nonce);
      if (err instanceof StoreError) return fail(res, err.status, err.code, err.message);
      console.error('[broker] unhandled', err);
      return fail(res, 500, 'internal_error', err.message);
    }
  });
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const port = Number(process.env.PORT ?? 8787);
  const host = process.env.HOST ?? '127.0.0.1';
  const dataDir = process.env.DATA_DIR ?? path.join(process.cwd(), 'data');
  const registry = new Registry(dataDir);   // throws on an incompatible folder
  const store = new Store(dataDir);
  createServer(store, registry).listen(port, host, () => {
    console.log(`[tincan] listening on http://${host}:${port}`);
    console.log(`[tincan] message folder: ${store.root}`);
    console.log('[tincan] identity: Ed25519 request signatures');
    console.log(`[tincan] outer token gate: ${process.env.BROKER_TOKEN ? 'on' : 'off'}`);
  });
}
