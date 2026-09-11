// Flat-file message store. The folder IS the database: every record is a file
// you can `cat`, every history is an append-only .jsonl you can `tail`.
//
// Layout under <root>:
//   messages/<message_id>.json   canonical message record
//   inbox/<agent>/<message_id>   index entry; exists until the recipient acks `read`
//   offers/<offer_id>.json       large-payload handshake records
//   blobs/<message_id>           raw payload for large messages
//   threads/<thread_id>.jsonl    append-only event log, first line is thread.created
//
// The broker is a single process, so it is the only writer. That makes
// write-tmp-then-rename sufficient for atomicity; readers never see a half file.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

import { MAX_INLINE_BYTES } from '../shared/limits.mjs';
export { MAX_INLINE_BYTES };

export class StoreError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

function newId(prefix) {
  return `${prefix}_${Date.now().toString(36)}${crypto.randomBytes(5).toString('hex')}`;
}

function nowIso() {
  return new Date().toISOString();
}

// Agent ids and thread ids arrive from the network and become path segments.
// Anything that could escape the data dir is rejected outright.
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function safeId(value, what) {
  if (typeof value !== 'string' || !SAFE_ID.test(value) || value.includes('..')) {
    throw new StoreError('invalid_id', `${what} must match ${SAFE_ID} (got ${JSON.stringify(value)})`);
  }
  return value;
}

export class Store {
  constructor(root) {
    this.root = path.resolve(root);
    this.dirs = {
      messages: path.join(this.root, 'messages'),
      inbox: path.join(this.root, 'inbox'),
      offers: path.join(this.root, 'offers'),
      blobs: path.join(this.root, 'blobs'),
      threads: path.join(this.root, 'threads'),
    };
    for (const dir of Object.values(this.dirs)) fs.mkdirSync(dir, { recursive: true });
  }

  // ---- primitives ---------------------------------------------------------

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

  #appendEvent(threadId, event) {
    const file = path.join(this.dirs.threads, `${threadId}.jsonl`);
    fs.appendFileSync(file, JSON.stringify({ at: nowIso(), ...event }) + '\n');
  }

  #ensureThread(threadId, participants) {
    const file = path.join(this.dirs.threads, `${threadId}.jsonl`);
    if (!fs.existsSync(file)) {
      this.#appendEvent(threadId, {
        type: 'thread.created',
        thread_id: threadId,
        participants: [...participants].sort(),
      });
    }
    return threadId;
  }

  #inboxDir(agent) {
    const dir = path.join(this.dirs.inbox, safeId(agent, 'agent id'));
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }

  // ---- messages -----------------------------------------------------------

  resolveThread({ threadId, replyTo, participants }) {
    if (replyTo) {
      const parent = this.getMessage(replyTo);
      if (!parent) throw new StoreError('unknown_message', `reply_to ${replyTo} not found`, 404);
      return this.#ensureThread(parent.thread_id, participants);
    }
    if (threadId) return this.#ensureThread(safeId(threadId, 'thread id'), participants);
    return this.#ensureThread(newId('thr'), participants);
  }

  createMessage({ from, to, subject, body = null, contentType = 'text/plain', threadId, replyTo, blob = null }) {
    safeId(from, 'from');
    safeId(to, 'to');
    if (from === to) throw new StoreError('self_send', 'from and to must differ');
    if (typeof subject !== 'string' || subject.trim() === '') {
      throw new StoreError('missing_subject', 'subject is required');
    }
    if (body === null && blob === null) {
      throw new StoreError('empty_message', 'a message needs either a body or a blob');
    }
    if (body !== null && Buffer.byteLength(body, 'utf8') > MAX_INLINE_BYTES) {
      throw new StoreError(
        'payload_too_large',
        `inline body exceeds ${MAX_INLINE_BYTES} bytes; use the offer flow`,
        413,
      );
    }

    const id = newId('msg');
    const thread_id = this.resolveThread({ threadId, replyTo, participants: [from, to] });
    const message = {
      id,
      thread_id,
      from,
      to,
      subject,
      body,
      blob,
      content_type: contentType,
      reply_to: replyTo ?? null,
      status: 'queued',
      created_at: nowIso(),
      delivered_at: null,
      read_at: null,
    };

    this.#writeJson(path.join(this.dirs.messages, `${id}.json`), message);
    fs.writeFileSync(path.join(this.#inboxDir(to), id), '');
    this.#appendEvent(thread_id, {
      type: 'message.sent',
      message_id: id,
      from,
      to,
      subject,
      inline: body !== null,
      bytes: blob ? blob.size : Buffer.byteLength(body ?? '', 'utf8'),
    });
    return message;
  }

  getMessage(id) {
    if (typeof id !== 'string' || !/^msg_[a-z0-9]+$/.test(id)) return null;
    return this.#readJson(path.join(this.dirs.messages, `${id}.json`));
  }

  #saveMessage(message) {
    this.#writeJson(path.join(this.dirs.messages, `${message.id}.json`), message);
    return message;
  }

  // Everything the recipient has not acked yet, oldest first. Fetching flips
  // queued -> delivered but leaves the inbox entry in place, so a crash between
  // fetch and ack redelivers rather than loses. Delivery is at-least-once.
  // The broker passes isVisible so revoked peers stop reaching this inbox. The
  // message file and its thread events stay on disk — only the index entry is
  // skipped, because a revoke is not an erasure.
  inbox(agent, { isVisible = () => true } = {}) {
    safeId(agent, 'agent id');
    const dir = this.#inboxDir(agent);
    const messages = [];
    for (const entry of fs.readdirSync(dir).sort()) {
      const message = this.getMessage(entry);
      if (!message) {
        fs.rmSync(path.join(dir, entry), { force: true });
        continue;
      }
      if (!isVisible(message)) continue;
      if (message.status === 'queued') {
        message.status = 'delivered';
        message.delivered_at = nowIso();
        this.#saveMessage(message);
        this.#appendEvent(message.thread_id, {
          type: 'message.delivered',
          message_id: message.id,
          to: agent,
        });
      }
      messages.push(message);
    }
    return messages.sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  ackRead(agent, messageId) {
    const message = this.getMessage(messageId);
    if (!message) throw new StoreError('unknown_message', `message ${messageId} not found`, 404);
    if (message.to !== agent) {
      throw new StoreError('not_recipient', `${agent} is not the recipient of ${messageId}`, 403);
    }
    if (message.status !== 'read') {
      message.status = 'read';
      message.read_at = nowIso();
      this.#saveMessage(message);
      this.#appendEvent(message.thread_id, {
        type: 'message.read',
        message_id: message.id,
        by: agent,
      });
    }
    fs.rmSync(path.join(this.#inboxDir(agent), messageId), { force: true });
    return message;
  }

  // ---- blobs --------------------------------------------------------------

  blobPath(messageId) {
    if (!/^msg_[a-z0-9]+$/.test(messageId)) throw new StoreError('invalid_id', 'bad message id');
    return path.join(this.dirs.blobs, messageId);
  }

  readBlob(messageId) {
    const file = this.blobPath(messageId);
    if (!fs.existsSync(file)) throw new StoreError('no_blob', `no payload stored for ${messageId}`, 404);
    return fs.readFileSync(file);
  }

  // ---- offers -------------------------------------------------------------

  createOffer({ from, to, subject, sizeBytes, contentType = 'application/octet-stream', threadId, replyTo }) {
    safeId(from, 'from');
    safeId(to, 'to');
    if (from === to) throw new StoreError('self_send', 'from and to must differ');
    if (typeof subject !== 'string' || subject.trim() === '') {
      throw new StoreError('missing_subject', 'subject is required');
    }
    if (!Number.isInteger(sizeBytes) || sizeBytes <= 0) {
      throw new StoreError('invalid_size', 'size_bytes must be a positive integer');
    }

    const id = newId('ofr');
    const thread_id = this.resolveThread({ threadId, replyTo, participants: [from, to] });
    const offer = {
      id,
      thread_id,
      from,
      to,
      subject,
      size_bytes: sizeBytes,
      content_type: contentType,
      reply_to: replyTo ?? null,
      status: 'pending',
      reason: null,
      message_id: null,
      created_at: nowIso(),
      responded_at: null,
      uploaded_at: null,
    };
    this.#writeJson(path.join(this.dirs.offers, `${id}.json`), offer);
    this.#appendEvent(thread_id, {
      type: 'offer.created',
      offer_id: id,
      from,
      to,
      subject,
      size_bytes: sizeBytes,
    });
    return offer;
  }

  getOffer(id) {
    if (typeof id !== 'string' || !/^ofr_[a-z0-9]+$/.test(id)) return null;
    return this.#readJson(path.join(this.dirs.offers, `${id}.json`));
  }

  #saveOffer(offer) {
    this.#writeJson(path.join(this.dirs.offers, `${offer.id}.json`), offer);
    return offer;
  }

  #allOffers() {
    return fs
      .readdirSync(this.dirs.offers)
      .filter((f) => f.endsWith('.json'))
      .map((f) => this.#readJson(path.join(this.dirs.offers, f)))
      .filter(Boolean);
  }

  // Offers this agent must answer.
  pendingOffersFor(agent) {
    safeId(agent, 'agent id');
    return this.#allOffers()
      .filter((o) => o.to === agent && o.status === 'pending')
      .sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  // Offers this agent sent that the recipient has now answered — the sender's
  // monitor tick uses this to upload (or discard) without the agent tracking it.
  answeredOffersBy(agent) {
    safeId(agent, 'agent id');
    return this.#allOffers()
      .filter((o) => o.from === agent && (o.status === 'accepted' || o.status === 'rejected'))
      .sort((a, b) => a.created_at.localeCompare(b.created_at));
  }

  respondOffer({ agent, offerId, accept, reason = null }) {
    const offer = this.getOffer(offerId);
    if (!offer) throw new StoreError('unknown_offer', `offer ${offerId} not found`, 404);
    if (offer.to !== agent) {
      throw new StoreError('not_recipient', `${agent} is not the recipient of ${offerId}`, 403);
    }
    if (offer.status !== 'pending') {
      throw new StoreError('offer_settled', `offer ${offerId} is already ${offer.status}`, 409);
    }
    offer.status = accept ? 'accepted' : 'rejected';
    offer.reason = reason;
    offer.responded_at = nowIso();
    this.#saveOffer(offer);
    this.#appendEvent(offer.thread_id, {
      type: accept ? 'offer.accepted' : 'offer.rejected',
      offer_id: offer.id,
      by: agent,
      reason,
    });
    return offer;
  }

  // Turn an accepted offer into a real message carrying a blob.
  attachPayload({ agent, offerId, buffer }) {
    const offer = this.getOffer(offerId);
    if (!offer) throw new StoreError('unknown_offer', `offer ${offerId} not found`, 404);
    if (offer.from !== agent) {
      throw new StoreError('not_sender', `${agent} did not send offer ${offerId}`, 403);
    }
    if (offer.status === 'uploaded') {
      throw new StoreError('offer_settled', `offer ${offerId} already uploaded`, 409);
    }
    if (offer.status !== 'accepted') {
      throw new StoreError('offer_not_accepted', `offer ${offerId} is ${offer.status}, not accepted`, 409);
    }
    if (buffer.length !== offer.size_bytes) {
      throw new StoreError(
        'size_mismatch',
        `offered ${offer.size_bytes} bytes but uploaded ${buffer.length}`,
      );
    }

    const message = this.createMessage({
      from: offer.from,
      to: offer.to,
      subject: offer.subject,
      body: null,
      contentType: offer.content_type,
      threadId: offer.thread_id,
      blob: {
        size: buffer.length,
        sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
        content_type: offer.content_type,
      },
    });

    const tmp = `${this.blobPath(message.id)}.tmp`;
    fs.writeFileSync(tmp, buffer);
    fs.renameSync(tmp, this.blobPath(message.id));

    offer.status = 'uploaded';
    offer.message_id = message.id;
    offer.uploaded_at = nowIso();
    this.#saveOffer(offer);
    this.#appendEvent(offer.thread_id, {
      type: 'offer.uploaded',
      offer_id: offer.id,
      message_id: message.id,
    });
    return { offer, message };
  }

  // Sender acknowledges it has seen and handled a rejection, so the monitor
  // stops reporting it. Rejected offers stay on disk as history.
  closeOffer({ agent, offerId }) {
    const offer = this.getOffer(offerId);
    if (!offer) throw new StoreError('unknown_offer', `offer ${offerId} not found`, 404);
    if (offer.from !== agent) {
      throw new StoreError('not_sender', `${agent} did not send offer ${offerId}`, 403);
    }
    offer.status = offer.status === 'rejected' ? 'closed' : offer.status;
    this.#saveOffer(offer);
    return offer;
  }

  // ---- threads ------------------------------------------------------------

  readThread(threadId) {
    safeId(threadId, 'thread id');
    const file = path.join(this.dirs.threads, `${threadId}.jsonl`);
    if (!fs.existsSync(file)) throw new StoreError('not_found', 'no such thread', 404);
    return fs
      .readFileSync(file, 'utf8')
      .split('\n')
      .filter((line) => line.trim() !== '')
      .map((line) => JSON.parse(line));
  }

  listThreads(agent) {
    const threads = [];
    for (const file of fs.readdirSync(this.dirs.threads)) {
      if (!file.endsWith('.jsonl')) continue;
      const threadId = file.slice(0, -'.jsonl'.length);
      let events;
      try {
        events = this.readThread(threadId);
      } catch {
        continue;
      }
      const created = events[0];
      const participants = created?.participants ?? [];
      if (agent && !participants.includes(agent)) continue;
      const last = events[events.length - 1];
      threads.push({
        thread_id: threadId,
        participants,
        events: events.length,
        created_at: created?.at ?? null,
        last_event_at: last?.at ?? null,
        last_event_type: last?.type ?? null,
      });
    }
    return threads.sort((a, b) => (b.last_event_at ?? '').localeCompare(a.last_event_at ?? ''));
  }
}
