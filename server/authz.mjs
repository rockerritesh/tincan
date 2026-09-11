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

// Participancy only — it says nothing about whether the link is still live, so
// it is NEVER sufficient on its own. The name carries that: every caller must
// pair it with `requireActiveLink` (for a write) or reach for `assertReadable`
// / `assertReadableThread` instead (for a read). Calling it alone is the exact
// mistake that let a revoked peer ack — and read the body of — a message the
// read route correctly 404s.
//
// 404 rather than 403 on purpose: a 403 would confirm the id exists, letting a
// caller probe for other people's message ids. Not-yours and not-there must
// look identical from outside.
export function assertParticipantIgnoringLink(record, fingerprint) {
  if (!isParticipant(record, fingerprint)) {
    throw new StoreError('not_found', 'no such record', 404);
  }
  return record;
}

// Module-private. This was `visibleToCaller`, exported for one unit test and
// called from nowhere in server/ or mcp/. An exported half-check is an
// invitation to use it as a whole one, so it stays in here.
function isParticipant(record, fingerprint) {
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

// True when `caller` may still read records shared with `other`. A revoked
// peer loses access; whoever performed the revocation keeps their own copy —
// otherwise disconnecting someone would erase your own view of the
// conversation, which is the one thing this design promises never happens.
// This is the single predicate every read surface routes through, reached by
// one of three composers so a surface added later inherits the behaviour
// instead of repeating the leak:
//
//   record shape  -> assertReadable        (messages, payloads, offers)
//   thread shape  -> assertReadableThread  / threadReadableBy
//   list filter   -> readableBetween directly, against the known other party
//                    (the offers and inbox listings, which already hold it)
export function readableBetween(registry, caller, other) {
  const link = registry.getLink(caller, other);
  if (!link) return false;
  if (link.status === 'revoked' && link.revoked_by !== caller) return false;
  return true;
}

// A revoked peer keeps no read access to records you shared. Your own copy is
// unaffected: skip the link check when the caller is the record's `from` (or
// `to` — the participancy check above already narrowed us to a participant)
// and *they themselves* performed the revocation. Only the revoked peer loses
// access; the revoker does not — otherwise disconnecting someone would erase
// your own view of the conversation, which is the one thing this design
// promises never happens.
//
// This composes the *record* shape — anything with `from` and `to`. Threads
// carry a `participants` array instead, so they get their own composer below
// rather than each route re-deriving "the other party" by hand.
export function assertReadable(registry, record, fingerprint) {
  assertParticipantIgnoringLink(record, fingerprint);
  const other = record.from === fingerprint ? record.to : record.from;
  if (!readableBetween(registry, fingerprint, other)) {
    throw new StoreError('not_found', 'no such record', 404);
  }
  return record;
}

// The thread-shaped counterpart of `readableBetween`, for the list surface
// that needs a boolean rather than a throw. Takes the participant array
// straight off a thread summary or a thread.created event, so "who is the
// other party" is derived in exactly one place instead of inline at each
// route — which is how two of the six read surfaces came to hand-roll it.
//
// A non-array `participants` is not readable: a string containing the
// fingerprint as a substring must never authorize (see scopeThreads).
export function threadReadableBy(registry, participants, fingerprint) {
  if (!Array.isArray(participants)) return false;
  if (!participants.includes(fingerprint)) return false;
  // A solo thread (only the caller) has no peer whose link could be revoked.
  const other = participants.find((party) => party !== fingerprint);
  return !other || readableBetween(registry, fingerprint, other);
}

// Throwing form, for the singular thread read. Refusals reuse the not_found
// 404 a nonexistent thread gets, so neither a non-participant nor a revoked
// peer can tell "not yours" from "not there".
export function assertReadableThread(registry, events, fingerprint) {
  if (!threadReadableBy(registry, events?.[0]?.participants, fingerprint)) {
    throw new StoreError('not_found', 'no such thread', 404);
  }
  return events;
}

export function scopeThreads(threads, fingerprint) {
  return threads.filter(
    (thread) => Array.isArray(thread.participants) && thread.participants.includes(fingerprint),
  );
}
