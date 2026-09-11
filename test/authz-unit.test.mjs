import test from 'node:test';
import assert from 'node:assert/strict';
import {
  requireActiveLink,
  assertParticipant,
  assertTwoPartyThread,
  visibleToCaller,
  scopeThreads,
} from '../server/authz.mjs';
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
  assert.equal(assertParticipant(record, a), record);
  assert.equal(assertParticipant(record, b), record);
  assert.throws(
    () => assertParticipant(record, c),
    (e) => e.code === 'not_found' && e.status === 404,
    'a 403 here would confirm the id exists',
  );
});

test('a null record is also 404, so probing cannot tell the two apart', () => {
  assert.throws(() => assertParticipant(null, a), (e) => e.code === 'not_found' && e.status === 404);
});

test('visibleToCaller mirrors assertParticipant without throwing', () => {
  const record = { from: a, to: b };
  assert.equal(visibleToCaller(record, a), true);
  assert.equal(visibleToCaller(record, c), false);
  assert.equal(visibleToCaller(null, a), false);
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
    assertParticipant(null, a);
  } catch (e) {
    nullError = e;
  }

  try {
    assertParticipant(record, a);
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
