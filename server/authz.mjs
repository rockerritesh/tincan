// The rules that decide what a proved identity may do. Kept separate from the
// routing so each rule can be tested on its own and read in one sitting.

import { StoreError } from './store.mjs';

// Sending requires an active link. The message distinguishes "never connected"
// from "you disconnected", because those need different fixes.
export function requireActiveLink(registry, a, b) {
  const status = registry.linkStatus(a, b);
  if (status === 'active') return;
  if (status === 'revoked') {
    throw new StoreError('no_link', 'this connection was revoked; pair again with a new invite', 403);
  }
  throw new StoreError('no_link', 'you are not connected to that agent; redeem an invite first', 403);
}

// 404 rather than 403 on purpose: a 403 would confirm the id exists, letting a
// caller probe for other people's message ids. Not-yours and not-there must
// look identical from outside.
export function assertParticipant(record, fingerprint) {
  if (!visibleToCaller(record, fingerprint)) {
    throw new StoreError('not_found', 'no such record', 404);
  }
  return record;
}

export function visibleToCaller(record, fingerprint) {
  if (!record) return false;
  return record.from === fingerprint || record.to === fingerprint;
}

export function scopeThreads(threads, fingerprint) {
  return threads.filter(
    (thread) => Array.isArray(thread.participants) && thread.participants.includes(fingerprint),
  );
}
