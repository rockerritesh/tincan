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
import { requireActiveLink, assertParticipant, assertTwoPartyThread, scopeThreads } from './authz.mjs';

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
        return done(200, assertParticipant(store.getMessage(id), caller.fingerprint));
      }
      if (resource === 'messages' && method === 'POST' && id && action === 'ack') {
        await jsonBody();
        const message = assertParticipant(store.getMessage(id), caller.fingerprint);
        return done(200, store.ackRead(caller.fingerprint, message.id));
      }
      if (resource === 'messages' && method === 'GET' && id && action === 'payload') {
        const message = assertParticipant(store.getMessage(id), caller.fingerprint);
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
        return done(200, { agent: caller.fingerprint, messages: store.inbox(caller.fingerprint) });
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
        return done(200, {
          agent: caller.fingerprint,
          incoming: store.pendingOffersFor(caller.fingerprint),
          answered: store.answeredOffersBy(caller.fingerprint),
        });
      }
      if (resource === 'offers' && method === 'GET' && id && !action) {
        return done(200, assertParticipant(store.getOffer(id), caller.fingerprint));
      }
      if (resource === 'offers' && method === 'POST' && id && action === 'respond') {
        const b = await jsonBody();
        assertParticipant(store.getOffer(id), caller.fingerprint);
        return done(200, store.respondOffer({
          agent: caller.fingerprint,
          offerId: id,
          accept: b.accept === true,
          reason: b.reason ?? null,
        }));
      }
      if (resource === 'offers' && method === 'PUT' && id && action === 'payload') {
        assertParticipant(store.getOffer(id), caller.fingerprint);
        const buffer = await readBody(req, MAX_BLOB_BYTES);
        verifier.confirmBody(caller.claimedBodyHash, buffer);
        const { offer, message } = store.attachPayload({ agent: caller.fingerprint, offerId: id, buffer });
        return done(201, { offer, message });
      }
      if (resource === 'offers' && method === 'POST' && id && action === 'close') {
        await jsonBody();
        assertParticipant(store.getOffer(id), caller.fingerprint);
        return done(200, store.closeOffer({ agent: caller.fingerprint, offerId: id }));
      }

      // ---- threads --------------------------------------------------------
      if (resource === 'threads' && method === 'GET' && !id) {
        return done(200, { threads: scopeThreads(store.listThreads(null), caller.fingerprint) });
      }
      if (resource === 'threads' && method === 'GET' && id) {
        const events = store.readThread(id);
        const participants = events[0]?.participants ?? [];
        if (!participants.includes(caller.fingerprint)) {
          throw new StoreError('not_found', 'no such thread', 404);
        }
        return done(200, { thread_id: id, events });
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
