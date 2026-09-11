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

// Threads are two-party by design — group threads are an explicit non-goal — so
// a thread's participant list is written once, when it is created. That makes
// `reply_to` and `thread_id` a splice risk: following a parent into someone
// else's thread would file a message there without the record ever naming the
// new party. The spliced party would be a real participant that every
// participant check then denies, while the original pair could read message.sent
// metadata — from, to, subject, bytes — for traffic that is not theirs.
//
// So refuse the splice rather than teach threads to hold three parties: an
// existing thread must belong to exactly {caller, to}. Refusals reuse the
// not_found 404 a nonexistent thread gets, so this cannot become an oracle for
// which thread or message ids exist.
export function assertTwoPartyThread(store, { caller, to, threadId, replyTo }) {
  const refuse = () => new StoreError('not_found', 'no such thread', 404);

  let target = threadId;
  if (replyTo) {
    const parent = store.getMessage(replyTo);
    // A parent that is missing and a parent that belongs to another pair must
    // answer identically; the latter falls through to the participants check.
    if (!parent) throw refuse();
    target = parent.thread_id;
  }
  if (!target) return; // a brand new thread — the store records the pair itself

  let events;
  try {
    events = store.readThread(target);
  } catch (err) {
    // A thread_id the caller chose that does not exist yet is fine: the store
    // creates it, naming this pair. Anything else (a malformed id) is theirs.
    if (err instanceof StoreError && err.code === 'not_found') return;
    throw err;
  }

  const participants = events[0]?.participants ?? [];
  const expected = [caller, to];
  const exact = participants.length === expected.length
    && expected.every((party) => participants.includes(party));
  if (!exact) throw refuse();
}

export function scopeThreads(threads, fingerprint) {
  return threads.filter(
    (thread) => Array.isArray(thread.participants) && thread.participants.includes(fingerprint),
  );
}
