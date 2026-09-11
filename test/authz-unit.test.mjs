import test from 'node:test';
import assert from 'node:assert/strict';
import { requireActiveLink, assertParticipant, visibleToCaller, scopeThreads } from '../server/authz.mjs';
import { Registry } from '../server/registry.mjs';
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
