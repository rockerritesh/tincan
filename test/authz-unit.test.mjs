import test from 'node:test';
import assert from 'node:assert/strict';
import {
  requireActiveLink,
  assertParticipantIgnoringLink,
  assertReadable,
  assertReadableThread,
  assertTwoPartyThread,
  threadReadableBy,
  scopeThreads,
} from '../server/authz.mjs';
import * as authz from '../server/authz.mjs';
import { Registry } from '../server/registry.mjs';
import { Store } from '../server/store.mjs';
import { fingerprintFromPublicKey } from '../shared/fingerprint.mjs';
import { tempDir } from './helpers.mjs';

const a = fingerprintFromPublicKey(Buffer.alloc(32, 1));
const b = fingerprintFromPublicKey(Buffer.alloc(32, 2));
const c = fingerprintFromPublicKey(Buffer.alloc(32, 3));

test('an active link permits, a missing one is refused by name', () => {
  const r = new Registry(tempDir('authz'));
  assert.throws(() => requireActiveLink(r, a, b), (e) => e.code === 'no_link' && /not connected/i.test(e.message));
  r.createLink({ a, b, via: 'inv_1' });
  assert.doesNotThrow(() => requireActiveLink(r, a, b));
});

test('a revoked link says revoked, not missing', () => {
  const r = new Registry(tempDir('authz'));
  r.createLink({ a, b, via: 'inv_1' });
  r.revokeLink({ a, b, by: a });
  assert.throws(
    () => requireActiveLink(r, a, b),
    (e) => e.code === 'no_link' && e.status === 403 && /revoked/i.test(e.message),
  );
});

test('a participant sees a record; a stranger gets 404, never 403', () => {
  const record = { id: 'msg_1', from: a, to: b };
  assert.equal(assertParticipantIgnoringLink(record, a), record);
  assert.equal(assertParticipantIgnoringLink(record, b), record);
  assert.throws(
    () => assertParticipantIgnoringLink(record, c),
    (e) => e.code === 'not_found' && e.status === 404,
    'a 403 here would confirm the id exists',
  );
});

test('a null record is also 404, so probing cannot tell the two apart', () => {
  assert.throws(() => assertParticipantIgnoringLink(null, a), (e) => e.code === 'not_found' && e.status === 404);
});

// The module's exported surface is itself a control. `visibleToCaller` was
// exported for this file alone and used nowhere in server/ or mcp/, and a bare
// participancy check is never sufficient on any route — its one unaccompanied
// call site was the ack bug. So the incomplete check is named for its
// incompleteness and the boolean half is module-private. This test fails if
// either is quietly re-exported under a name that reads as complete.
test('the module exports no check that reads as complete but is not', () => {
  assert.equal('visibleToCaller' in authz, false, 'folded into assertParticipantIgnoringLink');
  assert.equal(
    'assertParticipant' in authz,
    false,
    'the incompleteness must be in the name, so no route can call it alone by accident',
  );
  // The three complete entry points every route must come through.
  for (const name of ['assertReadable', 'assertReadableThread', 'requireActiveLink']) {
    assert.equal(typeof authz[name], 'function', `${name} must stay exported`);
  }
});

// ---- the thread-shaped read helper ---------------------------------------
//
// readableBetween's comment claimed to be "the single predicate every read
// surface should route through", but nothing composed the *thread* shape the
// way assertReadable composes the record shape, so two of six read surfaces
// hand-rolled `participants.find(p => p !== caller)` inline. These cover the
// helper that closes that gap directly, not just through a route.

function linkedRegistry({ revokedBy } = {}) {
  const r = new Registry(tempDir('authz-thread-read'));
  r.createLink({ a, b, via: 'inv_1' });
  if (revokedBy) r.revokeLink({ a, b, by: revokedBy });
  return r;
}

test('threadReadableBy: an active pair reads, a non-participant does not', () => {
  const r = linkedRegistry();
  assert.equal(threadReadableBy(r, [a, b], a), true);
  assert.equal(threadReadableBy(r, [a, b], b), true);
  assert.equal(threadReadableBy(r, [a, b], c), false);
});

test('threadReadableBy: after a revoke only the revoker reads', () => {
  const r = linkedRegistry({ revokedBy: a });
  assert.equal(threadReadableBy(r, [a, b], a), true, 'the revoker keeps their own copy');
  assert.equal(threadReadableBy(r, [a, b], b), false, 'the revoked peer loses it');
});

test('threadReadableBy: a solo thread has no peer link to consult', () => {
  const r = new Registry(tempDir('authz-thread-solo'));
  assert.equal(threadReadableBy(r, [a], a), true);
});

test('threadReadableBy refuses a non-array participants, substrings included', () => {
  const r = linkedRegistry();
  assert.equal(threadReadableBy(r, `someprefix${a}somesuffix`, a), false, 'substring must not authorize');
  assert.equal(threadReadableBy(r, { [a]: true }, a), false);
  assert.equal(threadReadableBy(r, undefined, a), false);
});

test('assertReadableThread throws the same 404 for not-a-participant and revoked', () => {
  const errors = [];
  for (const [registry, caller] of [
    [linkedRegistry(), c],                    // never a participant
    [linkedRegistry({ revokedBy: a }), b],    // participant, but revoked
    [linkedRegistry(), a],                    // and one that must NOT throw
  ]) {
    try {
      assertReadableThread(registry, [{ participants: [a, b] }], caller);
      errors.push(null);
    } catch (e) {
      errors.push(e);
    }
  }
  const [stranger, revoked, allowed] = errors;
  assert.equal(allowed, null, 'the revoker/participant must be let through');
  assert.equal(stranger.status, 404);
  assert.equal(revoked.status, 404);
  assert.equal(stranger.code, revoked.code, 'not-yours and revoked must be one answer');
  assert.equal(stranger.message, revoked.message);
});

test('assertReadableThread on an empty event log is 404, not a crash', () => {
  const r = linkedRegistry();
  assert.throws(() => assertReadableThread(r, [], a), (e) => e.status === 404);
});

test('assertReadable is the record-shaped sibling and honours the same asymmetry', () => {
  const record = { id: 'msg_1', from: a, to: b };
  const revoked = linkedRegistry({ revokedBy: a });
  assert.equal(assertReadable(revoked, record, a), record, 'the revoker keeps their copy');
  assert.throws(() => assertReadable(revoked, record, b), (e) => e.status === 404);
  assert.equal(assertReadable(linkedRegistry(), record, b), record, 'an active link reads both ways');
});

test('thread scoping keeps only threads the caller participates in', () => {
  const threads = [
    { thread_id: 't1', participants: [a, b] },
    { thread_id: 't2', participants: [b, c] },
    { thread_id: 't3', participants: [a, c] },
  ];
  assert.deepEqual(scopeThreads(threads, a).map((t) => t.thread_id), ['t1', 't3']);
  assert.deepEqual(scopeThreads(threads, b).map((t) => t.thread_id), ['t1', 't2']);
});

test('scopeThreads requires participants to be an array, not a malformed object', () => {
  // Omitted entirely — falls through correctly
  const threads = [{ thread_id: 't1' }];
  assert.deepEqual(scopeThreads(threads, a).map((t) => t.thread_id), []);
});

test('scopeThreads with participants as an object does not crash', () => {
  // If participants is an object, Array.isArray catches it before calling .includes
  const threads = [{ thread_id: 't1', participants: { [a]: true } }];
  assert.deepEqual(scopeThreads(threads, a).map((t) => t.thread_id), []);
});

test('scopeThreads with participants as a string excludes substring false-positives', () => {
  // This is the security case: a string containing the fingerprint as a substring
  // must not authorize access. The current code incorrectly uses String.prototype.includes
  // and would return the thread (false-positive). After the fix, Array.isArray rejects it.
  const threads = [{ thread_id: 't1', participants: `someprefix${a}somesuffix` }];
  assert.deepEqual(scopeThreads(threads, a).map((t) => t.thread_id), [], 'substring match must not authorize');
});

test('the two 404 errors (null record vs. non-participant) are indistinguishable', () => {
  // This guards against a future refactor that splits the throw into two statements.
  // If someone "improves" the error messages, this test fails, preventing the security
  // guarantee from breaking.
  const record = { id: 'msg_1', from: b, to: c };
  let nullError;
  let nonParticipantError;

  try {
    assertParticipantIgnoringLink(null, a);
  } catch (e) {
    nullError = e;
  }

  try {
    assertParticipantIgnoringLink(record, a);
  } catch (e) {
    nonParticipantError = e;
  }

  assert.ok(nullError, 'null record must throw');
  assert.ok(nonParticipantError, 'non-participant record must throw');
  assert.equal(nullError.code, nonParticipantError.code, 'error codes must match');
  assert.equal(nullError.status, nonParticipantError.status, 'error statuses must match');
  assert.equal(nullError.message, nonParticipantError.message, 'error messages must be identical (prevents future divergence)');
});

test('a thread may only be joined by the pair that owns it', () => {
  const store = new Store(tempDir('authz-thread'));
  const first = store.createMessage({ from: a, to: b, subject: 'q', body: '?' });

  // The owning pair, reached by either lever and in either direction.
  assert.doesNotThrow(() => assertTwoPartyThread(store, { caller: a, to: b, replyTo: first.id }));
  assert.doesNotThrow(() => assertTwoPartyThread(store, { caller: b, to: a, replyTo: first.id }));
  assert.doesNotThrow(() => assertTwoPartyThread(store, { caller: b, to: a, threadId: first.thread_id }));

  // A third party spliced in by either lever, refused as not_found so the
  // refusal cannot be told apart from a thread that does not exist.
  for (const args of [
    { caller: b, to: c, replyTo: first.id },
    { caller: b, to: c, threadId: first.thread_id },
    { caller: c, to: b, replyTo: first.id },
  ]) {
    assert.throws(
      () => assertTwoPartyThread(store, args),
      (e) => e.code === 'not_found' && e.status === 404,
    );
  }
});

test('a new thread is not refused, and a missing parent is refused as not_found', () => {
  const store = new Store(tempDir('authz-thread-new'));
  // Neither lever supplied: a brand new thread, nothing to check.
  assert.doesNotThrow(() => assertTwoPartyThread(store, { caller: a, to: b }));
  // A thread_id the caller chose that does not exist yet: the store will
  // create it naming this pair, so refusing here would break a legal send.
  assert.doesNotThrow(() => assertTwoPartyThread(store, { caller: a, to: b, threadId: 'thr_brandnew' }));
  // A reply_to that does not exist answers with the thread's code, not
  // unknown_message, so missing and not-yours stay indistinguishable.
  assert.throws(
    () => assertTwoPartyThread(store, { caller: a, to: b, replyTo: 'msg_nope' }),
    (e) => e.code === 'not_found' && e.status === 404,
  );
});
