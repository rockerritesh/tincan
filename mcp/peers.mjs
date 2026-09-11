// mcp/peers.mjs
// This machine's private petname book. The broker never sees it.
//
// Peers are addressed by a local alias that this machine controls, and the wire
// only ever carries fingerprints. That is what makes label spoofing impossible:
// a new peer may advertise itself as "bob", but it cannot become *your* bob,
// because your alias points at a fingerprint you already recorded.

import fs from 'node:fs';
import path from 'node:path';
import { isFingerprint, shortFingerprint, normalizeBase32 } from '../shared/fingerprint.mjs';

export class PeerBook {
  constructor({ home }) {
    fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    fs.chmodSync(home, 0o700);
    this.file = path.join(home, 'peers.json');
    this.peers = this.#load();
  }

  #load() {
    try {
      const parsed = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return Array.isArray(parsed.peers) ? parsed.peers : [];
    } catch (err) {
      if (err.code === 'ENOENT') return [];
      throw err;
    }
  }

  #save() {
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ version: 1, peers: this.peers }, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  #freeAlias(label) {
    const trimmed = String(label).trim();
    // A peer picks its own advertised label, so it can advertise a string that
    // is byte-identical to some other peer's real fingerprint. resolve() checks
    // the fingerprint format first, so an alias shaped like a fingerprint would
    // be permanently unreachable — silently shadowed by that literal lookup.
    const base = (trimmed && !isFingerprint(trimmed)) ? trimmed : 'peer';
    if (!this.peers.some((p) => p.alias === base)) return { alias: base, collision: false };
    for (let n = 2; n < 1000; n += 1) {
      const candidate = `${base}-${n}`;
      if (!this.peers.some((p) => p.alias === candidate)) return { alias: candidate, collision: true };
    }
    throw new Error(`could not find a free alias for ${base}`);
  }

  resolve(aliasOrFingerprint) {
    if (isFingerprint(aliasOrFingerprint)) return aliasOrFingerprint;
    const found = this.peers.find((p) => p.alias === aliasOrFingerprint);
    if (!found) {
      throw new Error(
        `no peer called "${aliasOrFingerprint}" — run list_peers to see who you are connected to`,
      );
    }
    return found.fingerprint;
  }

  aliasFor(fingerprint) {
    return this.peers.find((p) => p.fingerprint === fingerprint)?.alias ?? null;
  }

  upsert({ fingerprint, label, status, linkedAt }) {
    const existing = this.peers.find((p) => p.fingerprint === fingerprint);
    if (existing) {
      existing.status = status ?? existing.status;
      existing.linked_at = linkedAt ?? existing.linked_at;
      this.#save();
      return { alias: existing.alias, collision: false };
    }
    const { alias, collision } = this.#freeAlias(label ?? fingerprint);
    this.peers.push({
      alias,
      fingerprint,
      advertised_label: label ?? null,
      verified: false,
      status: status ?? 'active',
      linked_at: linkedAt ?? null,
    });
    this.#save();
    return { alias, collision };
  }

  setVerified(alias, shortForm) {
    const peer = this.peers.find((p) => p.alias === alias);
    if (!peer) throw new Error(`no peer called "${alias}"`);
    const expected = normalizeBase32(shortFingerprint(peer.fingerprint));
    let presented;
    try {
      presented = normalizeBase32(shortForm);
    } catch {
      throw new Error('that is not a valid fingerprint — check the characters and try again');
    }
    if (presented !== expected) {
      throw new Error(
        `that does not match ${alias}'s fingerprint. Do not trust this connection until it does.`,
      );
    }
    peer.verified = true;
    this.#save();
    return { alias, verified: true };
  }

  list() {
    return this.peers.map((p) => ({
      alias: p.alias,
      fingerprint: p.fingerprint,
      short: shortFingerprint(p.fingerprint),
      verified: p.verified,
      status: p.status,
      linked_at: p.linked_at,
    }));
  }

  remove(fingerprint) {
    this.peers = this.peers.filter((p) => p.fingerprint !== fingerprint);
    this.#save();
  }

  // Compares what the broker reports against what we already knew, so the agent
  // learns about pairings and revocations without the broker keeping per-agent
  // event state.
  diff(remotePeers) {
    const linked = [];
    const revoked = [];

    for (const remote of remotePeers) {
      const known = this.peers.find((p) => p.fingerprint === remote.fingerprint);
      if (!known) {
        const { alias, collision } = this.upsert({
          fingerprint: remote.fingerprint,
          label: remote.label,
          status: remote.status,
          linkedAt: remote.linked_at,
        });
        if (remote.status === 'active') {
          linked.push({
            alias,
            fingerprint: remote.fingerprint,
            short: shortFingerprint(remote.fingerprint),
            advertised_label: remote.label,
            alias_collision: collision,
            action: collision
              ? 'their label was taken, so this alias was assigned instead'
              : 'call verify_peer once you have compared fingerprints out of band',
          });
        }
        continue;
      }
      if (known.status !== remote.status) {
        known.status = remote.status;
        this.#save();
        if (remote.status === 'revoked') {
          revoked.push({
            alias: known.alias,
            fingerprint: known.fingerprint,
            short: shortFingerprint(known.fingerprint),
          });
        } else if (remote.status === 'active') {
          linked.push({
            alias: known.alias,
            fingerprint: known.fingerprint,
            short: shortFingerprint(known.fingerprint),
            advertised_label: remote.label,
            alias_collision: false,
            action: 'this connection was restored',
          });
        }
      }
    }

    return { linked, revoked };
  }
}
