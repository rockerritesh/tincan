// The agent-side logic, kept free of MCP protocol details so it can be tested
// directly against a real broker.
//
// Two pieces of state live here rather than in the broker. The outbox stash:
// when a payload is too large to send inline, the bytes wait on the sender's
// own disk until the recipient accepts — nothing crosses the wire until there
// is a yes. And the peer book: the aliases this machine uses for its peers,
// which the broker never sees. Everything on the wire is a fingerprint.
//
// Aliases are resolved here, before a request is built, so a typo fails
// locally with a message that names the alias instead of coming back as a
// broker error about a fingerprint nobody typed.

import fs from 'node:fs';
import path from 'node:path';
import { MAX_INLINE_BYTES } from '../shared/limits.mjs';
import { BrokerClient } from './client.mjs';
import { loadOrCreateIdentity, defaultHome } from './identity.mjs';
import { PeerBook } from './peers.mjs';
import { shortFingerprint } from '../shared/fingerprint.mjs';

const TEXTUAL = /^(text\/|application\/(json|xml|yaml|x-ndjson)|.*\+json$)/;
const MAX_INLINE_RETURN = 32 * 1024;

export class AgentLink {
  // No `agentId`: identity is the keypair on disk, and a label is only used
  // when there is no keypair yet. An id you can pass is an id you can forge.
  constructor({ baseUrl, label, token = null, home = defaultHome() }) {
    this.home = home;
    this.identityRecord = loadOrCreateIdentity({ home, label });
    this.peerBook = new PeerBook({ home });
    this.client = new BrokerClient({ baseUrl, identity: this.identityRecord, token });
    this.agentId = this.identityRecord.fingerprint;
    this.outboxDir = path.join(home, 'outbox', this.identityRecord.fingerprint);
    this.downloadDir = path.join(home, 'downloads', this.identityRecord.fingerprint);
    fs.mkdirSync(this.outboxDir, { recursive: true });
    fs.mkdirSync(this.downloadDir, { recursive: true });
  }

  // ---- naming -------------------------------------------------------------

  // Alias in, fingerprint out. Throws naming the alias the caller actually
  // typed, which is the only string they can fix.
  #fingerprintFor(alias) {
    return this.peerBook.resolve(alias);
  }

  // Fingerprint in, something a human can read out. Never an unreadable
  // 29-character string when a shorter form exists.
  #aliasOf(fingerprint) {
    if (!fingerprint) return null;
    if (fingerprint === this.identityRecord.fingerprint) return this.identityRecord.label;
    return this.peerBook.aliasFor(fingerprint) ?? shortFingerprint(fingerprint);
  }

  #stashPath(offerId) {
    if (!/^ofr_[a-z0-9]+$/.test(offerId)) throw new Error(`bad offer id ${offerId}`);
    return path.join(this.outboxDir, offerId);
  }

  // ---- identity and pairing -----------------------------------------------

  // Replaces the old hello(): the useful answer to "who am I" is the
  // fingerprint, with broker liveness folded in so it is still one call.
  async identity() {
    let reachable = true;
    let health = {};
    try {
      health = await this.client.health();
    } catch {
      reachable = false;
    }
    return {
      label: this.identityRecord.label,
      fingerprint: this.identityRecord.fingerprint,
      short: this.identityRecord.short,
      broker: this.client.baseUrl,
      broker_reachable: reachable,
      broker_version: health.version ?? null,
      note: 'Share the short fingerprint out of band so a peer can verify you.',
    };
  }

  async createInvite({ ttlMinutes } = {}) {
    const { invite, code } = await this.client.createInvite(
      ttlMinutes ? { ttlMs: ttlMinutes * 60 * 1000 } : {},
    );
    return {
      code,
      expires_at: invite.expires_at,
      note: 'Single use. Send it over a channel you already trust; it is shown only once.',
    };
  }

  // Redeem has two shapes. A normal invite links this agent to its issuer and
  // names that peer. A bootstrap invite — the first code an owner mints from
  // the CLI on a fresh broker — registers the key and creates no link, because
  // there is nobody yet to link to. Reading peer.fingerprint unconditionally
  // would throw on the very first thing a new owner does.
  async redeemInvite({ code }) {
    const result = await this.client.redeemInvite({ code, label: this.identityRecord.label });

    if (result.bootstrap) {
      return {
        bootstrap: true,
        label: result.agent.label,
        fingerprint: result.agent.fingerprint,
        short: result.agent.short,
        note: 'Registered as this broker\'s first agent. No peer yet — use create_invite '
          + 'to mint a code for whoever should connect to you.',
      };
    }

    const peer = result.peer;
    if (!peer?.fingerprint) {
      throw new Error('the broker accepted the code but named no peer; nothing was connected');
    }

    const { alias, collision } = this.peerBook.upsert({
      fingerprint: peer.fingerprint,
      label: peer.label,
      status: 'active',
      linkedAt: result.link?.created_at ?? new Date().toISOString(),
    });
    return {
      alias,
      fingerprint: peer.fingerprint,
      short: peer.short,
      alias_collision: collision,
      note: collision
        ? `Connected, but "${peer.label}" was taken locally, so this peer is "${alias}" here. `
          + `Compare ${peer.short} with them out of band, then call verify_peer.`
        : `Connected. Compare ${peer.short} with them out of band, then call verify_peer.`,
    };
  }

  // The broker is authoritative for status; the local book is authoritative
  // for names.
  //
  // This deliberately does NOT call peerBook.diff(): diff() reports by
  // mutating, so listing through it would leave a brand-new peer looking
  // already-known-and-unchanged, and the check_inbox tick that owes the agent
  // a peer_linked event would silently have nothing to say. Consuming events
  // is checkInbox's job alone.
  //
  // A peer the broker reports but this machine has not recorded yet is still
  // shown — this is the tool that answers "did my pairing work?" — but as a
  // read-only preview: aliased by its short fingerprint rather than its
  // advertised label, because the real alias is only decided when
  // upsert()/#freeAlias reserves one, and flagged `pending` so nobody tries to
  // address it before the tick has persisted it.
  async listPeers() {
    const { peers } = await this.client.peers();
    const remote = new Map(peers.map((p) => [p.fingerprint, p]));
    const known = this.peerBook.list().map((p) => ({
      ...p,
      status: remote.get(p.fingerprint)?.status ?? p.status,
      pending: false,
    }));
    const recorded = new Set(known.map((p) => p.fingerprint));
    const previews = peers
      .filter((p) => !recorded.has(p.fingerprint))
      .map((p) => ({
        alias: shortFingerprint(p.fingerprint),
        fingerprint: p.fingerprint,
        short: p.short ?? shortFingerprint(p.fingerprint),
        verified: false,
        status: p.status,
        linked_at: p.linked_at ?? null,
        advertised_label: p.label ?? null,
        pending: true,
        action: 'not in the local peer book yet — run check_inbox to name it, then send to that alias',
      }));
    return { peers: [...known, ...previews] };
  }

  // Async so a mismatch surfaces as a rejected promise like every other
  // failure on this class, rather than a synchronous throw callers have to
  // special-case.
  async verifyPeer({ alias, fingerprint }) {
    const result = this.peerBook.setVerified(alias, fingerprint);
    return { ...result, note: 'Fingerprints match. This connection is confirmed end to end.' };
  }

  async disconnectPeer({ alias }) {
    const target = this.#fingerprintFor(alias);
    const result = await this.client.revokePeer(target);
    this.peerBook.upsert({ fingerprint: target, status: 'revoked' });
    return {
      alias,
      fingerprint: target,
      status: result.status,
      revoked_at: result.revoked_at,
      note: 'Traffic is blocked both ways. Your copy of the history is untouched.',
    };
  }

  // ---- sending ------------------------------------------------------------

  // The caller never picks a mode. Anything that fits goes inline; anything
  // bigger becomes an offer whose bytes wait in the outbox for an accept.
  async send({ to, subject, body, contentType = 'text/plain', threadId, replyTo }) {
    const target = this.#fingerprintFor(to);
    const buffer = Buffer.from(body, 'utf8');

    if (buffer.length <= MAX_INLINE_BYTES) {
      const message = await this.client.sendMessage({
        to: target, subject, body, contentType, threadId, replyTo,
      });
      return {
        mode: 'inline',
        status: message.status,
        message_id: message.id,
        thread_id: message.thread_id,
        to: target,
        to_alias: to,
        bytes: buffer.length,
      };
    }

    const offer = await this.client.createOffer({
      to: target, subject, sizeBytes: buffer.length, contentType, threadId, replyTo,
    });
    fs.writeFileSync(this.#stashPath(offer.id), buffer);
    return {
      mode: 'offer',
      status: offer.status,
      offer_id: offer.id,
      thread_id: offer.thread_id,
      to: target,
      to_alias: to,
      bytes: buffer.length,
      note: `Payload is held locally. It uploads automatically on the check_inbox tick after ${to} accepts.`,
    };
  }

  // ---- the monitor tick ---------------------------------------------------

  // One call does four jobs: collect what arrived, surface offers waiting on
  // this agent's decision, finish off offers this agent sent that have since
  // been answered, and report pairings and revocations by diffing the broker's
  // peer list against the local book — no server-side event log needed.
  async checkInbox() {
    const [{ messages }, { incoming, answered }, { peers }] = await Promise.all([
      this.client.inbox(),
      this.client.offers(),
      this.client.peers(),
    ]);

    const peer_events = this.peerBook.diff(peers);

    const outbox_updates = [];
    for (const offer of answered) {
      try {
        outbox_updates.push(await this.#settle(offer));
      } catch (err) {
        outbox_updates.push({ offer_id: offer.id, status: 'error', error: err.message });
      }
    }

    return {
      agent: this.identityRecord.label,
      fingerprint: this.identityRecord.fingerprint,
      messages: messages.map((m) => ({ ...this.#summarize(m), from_alias: this.#aliasOf(m.from) })),
      offers_awaiting_response: incoming.map((o) => ({
        offer_id: o.id,
        thread_id: o.thread_id,
        from_alias: this.#aliasOf(o.from),
        subject: o.subject,
        size_bytes: o.size_bytes,
        content_type: o.content_type,
        action: 'call respond_offer to accept or reject',
      })),
      outbox_updates,
      peer_events,
      quiet: messages.length === 0
        && incoming.length === 0
        && outbox_updates.length === 0
        && peer_events.linked.length === 0
        && peer_events.revoked.length === 0,
    };
  }

  async #settle(offer) {
    const stash = this.#stashPath(offer.id);

    if (offer.status === 'rejected') {
      fs.rmSync(stash, { force: true });
      await this.client.closeOffer(offer.id);
      return {
        offer_id: offer.id,
        status: 'rejected',
        to: offer.to,
        to_alias: this.#aliasOf(offer.to),
        subject: offer.subject,
        reason: offer.reason,
      };
    }

    if (!fs.existsSync(stash)) {
      // Accepted, but the bytes are gone — a wipe of ~/.tincan, or the offer
      // was made from a different machine. Say so instead of hanging.
      await this.client.closeOffer(offer.id);
      return {
        offer_id: offer.id,
        status: 'error',
        error: 'accepted but the local payload stash is missing; resend the message',
      };
    }

    const buffer = fs.readFileSync(stash);
    const { message } = await this.client.uploadOffer({
      offerId: offer.id,
      buffer,
      contentType: offer.content_type,
    });
    fs.rmSync(stash, { force: true });
    return {
      offer_id: offer.id,
      status: 'sent',
      message_id: message.id,
      thread_id: message.thread_id,
      to: offer.to,
      to_alias: this.#aliasOf(offer.to),
      subject: offer.subject,
      bytes: buffer.length,
    };
  }

  #summarize(message) {
    return {
      message_id: message.id,
      thread_id: message.thread_id,
      from: message.from,
      subject: message.subject,
      content_type: message.content_type,
      status: message.status,
      created_at: message.created_at,
      reply_to: message.reply_to,
      ...(message.body !== null
        ? { body: message.body }
        : {
            body: null,
            payload: {
              size_bytes: message.blob?.size ?? null,
              sha256: message.blob?.sha256 ?? null,
              action: 'call fetch_payload with this message_id to read it',
            },
          }),
    };
  }

  // ---- responses ----------------------------------------------------------

  async ack(messageId) {
    const message = await this.client.ackMessage(messageId);
    return { message_id: message.id, status: message.status, read_at: message.read_at };
  }

  async respondOffer({ offerId, accept, reason = null }) {
    const offer = await this.client.respondOffer({ offerId, accept, reason });
    const from = this.#aliasOf(offer.from);
    return {
      offer_id: offer.id,
      status: offer.status,
      from: offer.from,
      from_alias: from,
      subject: offer.subject,
      note: accept
        ? `${from} uploads on its next check_inbox tick; the payload then shows up here as a normal message.`
        : 'Sender has been told no; nothing will be uploaded.',
    };
  }

  // Large payloads land on disk by default — an agent should not have a
  // multi-megabyte blob shoved into its context without asking.
  async fetchPayload(messageId, { inline = null } = {}) {
    const message = await this.client.getMessage(messageId);
    const buffer = await this.client.getPayload(messageId);
    const textual = TEXTUAL.test(message.content_type ?? '');
    const wantsInline = inline ?? (textual && buffer.length <= MAX_INLINE_RETURN);

    if (wantsInline) {
      return {
        message_id: messageId,
        bytes: buffer.length,
        content_type: message.content_type,
        body: buffer.toString('utf8'),
      };
    }

    const file = path.join(this.downloadDir, messageId);
    fs.writeFileSync(file, buffer);
    return {
      message_id: messageId,
      bytes: buffer.length,
      content_type: message.content_type,
      saved_to: file,
      note: 'Payload written to disk rather than returned inline. Read the file if you need its contents.',
    };
  }

  // ---- history and status -------------------------------------------------

  async status(messageId) {
    const m = await this.client.getMessage(messageId);
    return {
      message_id: m.id,
      thread_id: m.thread_id,
      from: m.from,
      to: m.to,
      from_alias: this.#aliasOf(m.from),
      to_alias: this.#aliasOf(m.to),
      subject: m.subject,
      status: m.status,
      created_at: m.created_at,
      delivered_at: m.delivered_at,
      read_at: m.read_at,
    };
  }

  listThreads() {
    return this.client.listThreads();
  }

  readThread(threadId) {
    return this.client.readThread(threadId);
  }
}
