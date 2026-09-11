import test from 'node:test';
import assert from 'node:assert/strict';
import { startBroker, signedApi, signedUpload } from './helpers.mjs';
import { fingerprintFromPublicKey } from '../shared/fingerprint.mjs';

async function pairedPair(t) {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  broker.link(alice, bob);
  return { broker, alice, bob };
}

test('revoking blocks sending in both directions', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);

  const revoked = await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});
  assert.equal(revoked.status, 200);
  assert.equal(revoked.body.status, 'revoked');

  for (const [from, to, who] of [[alice, bob, 'alice->bob'], [bob, alice, 'bob->alice']]) {
    const res = await signedApi(broker.baseUrl, from, 'POST', '/v1/messages', {
      to: to.fingerprint, subject: 'still there?', body: 'x',
    });
    assert.equal(res.status, 403, who);
    assert.equal(res.body.error, 'no_link');
    assert.match(res.body.message, /revoked/i, 'the error should say revoked, not "never connected"');
  }
});

test('history survives a revoke and stays readable by its participants', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);

  const sent = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'before', body: 'said this earlier',
  });
  const { body: inbox } = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
  assert.equal(inbox.messages.length, 1);
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/messages/${sent.body.id}/ack`, {});

  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});

  // Alice keeps her copy: the append-only property is what makes "no context
  // loss" true, so a revoke must not erase it.
  const message = await signedApi(broker.baseUrl, alice, 'GET', `/v1/messages/${sent.body.id}`);
  assert.equal(message.status, 200);
  assert.equal(message.body.body, 'said this earlier');

  const threads = await signedApi(broker.baseUrl, alice, 'GET', '/v1/threads');
  assert.equal(threads.body.threads.length, 1);
  const history = await signedApi(broker.baseUrl, alice, 'GET', `/v1/threads/${sent.body.thread_id}`);
  assert.equal(history.status, 200);
  assert.ok(history.body.events.length >= 3);
});

test('undelivered messages from a revoked peer disappear from the inbox', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);

  await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'never read', body: 'x',
  });
  // Bob revokes before ever fetching it.
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/peers/${alice.fingerprint}/revoke`, {});

  const inbox = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
  assert.equal(inbox.body.messages.length, 0, 'a revoked peer stops reaching your inbox');
});

test('the revoked peer loses read access to shared records', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);
  const sent = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'x', body: 'y',
  });
  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});

  const res = await signedApi(broker.baseUrl, bob, 'GET', `/v1/messages/${sent.body.id}`);
  assert.equal(res.status, 404);
});

test('peers listing shows the revoked state rather than hiding it', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);
  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});
  const res = await signedApi(broker.baseUrl, alice, 'GET', '/v1/peers');
  assert.equal(res.body.peers.length, 1);
  assert.equal(res.body.peers[0].status, 'revoked');
  assert.ok(res.body.peers[0].revoked_at);
});

test('revoking someone you were never linked to is a 404', async (t) => {
  const { broker, alice } = await pairedPair(t);
  const carol = broker.identity('carol');
  const res = await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${carol.fingerprint}/revoke`, {});
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'no_link');
});

test('re-pairing after a revoke restores traffic', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);
  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});

  const { body: minted } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/invites', {});
  const redeemed = await signedApi(broker.baseUrl, bob, 'POST', '/v1/invites/redeem', {
    code: minted.code, label: 'bob',
  });
  assert.equal(redeemed.status, 201);

  const res = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'again', body: 'hello again',
  });
  assert.equal(res.status, 201);
});

// ---- carried forward from Task 9's review, now verified here --------------

test('revoking a stranger and revoking a nonexistent fingerprint are byte-identical', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  // A real keypair, never registered on this broker.
  const stranger = broker.stranger('stranger');
  // A well-formed fingerprint backed by no keypair anyone holds at all.
  const nonexistent = fingerprintFromPublicKey(Buffer.alloc(32, 0xee));

  const strangerRes = await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${stranger.fingerprint}/revoke`, {});
  const nonexistentRes = await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${nonexistent}/revoke`, {});

  assert.equal(strangerRes.status, 404);
  assert.equal(nonexistentRes.status, 404);
  assert.deepEqual(strangerRes.body, { error: 'no_link', message: 'there is no link to revoke' });
  assert.deepEqual(nonexistentRes.body, { error: 'no_link', message: 'there is no link to revoke' });
});

test('a malformed :fingerprint in the revoke path is a clean 400, not a crash', async (t) => {
  const { broker, alice } = await pairedPair(t);
  // Not a URL traversal (the URL parser normalizes `..` away before routing
  // ever sees it) — just a value that fails the fingerprint shape check, to
  // prove it surfaces as a typed 400 rather than an unhandled native throw.
  const res = await signedApi(broker.baseUrl, alice, 'POST', '/v1/peers/not-a-fingerprint/revoke', {});
  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_fingerprint');
});

// ---- fix round 1: four surfaces that skipped the revocation check ---------
//
// requireActiveLink guards the two create routes, assertReadable guards the
// three singular reads, and isVisible guards the inbox. Everything else that
// returns or mutates a shared record was left out. These four tests reproduce
// each leak against the pre-fix code, then (once server/authz.mjs grows
// `readableBetween` and the routes below are wired to it) confirm it is
// closed — in both directions, so the revoker's own view is never collateral
// damage.

test('thread detail 404s for the revoked peer; the revoker still reads it, both directions', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);
  const sent = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'leak me not', body: 'x',
  });
  const threadId = sent.body.thread_id;

  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});

  // bob is the revoked peer: he loses the thread, subjects and all.
  const bobRead = await signedApi(broker.baseUrl, bob, 'GET', `/v1/threads/${threadId}`);
  assert.equal(bobRead.status, 404);
  assert.equal(bobRead.body.error, 'not_found');

  // alice performed the revocation: her own copy of the conversation stands.
  const aliceRead = await signedApi(broker.baseUrl, alice, 'GET', `/v1/threads/${threadId}`);
  assert.equal(aliceRead.status, 200);
  assert.ok(aliceRead.body.events.length >= 1);
});

test('threads list drops a thread for the revoked peer; the revoker still sees it', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);
  await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'metadata still counts', body: 'x',
  });

  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});

  const bobList = await signedApi(broker.baseUrl, bob, 'GET', '/v1/threads');
  assert.equal(bobList.body.threads.length, 0, 'the revoked peer should not see the thread listed at all');

  const aliceList = await signedApi(broker.baseUrl, alice, 'GET', '/v1/threads');
  assert.equal(aliceList.body.threads.length, 1, "the revoker's own listing is unaffected");
});

test('offers list drops a pre-existing pending offer from the revoked peer; the revoker keeps theirs', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);

  // One offer in each direction, both created while the link was still active.
  const aliceToBob = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'alice->bob secret', size_bytes: 4,
  });
  const bobToAlice = await signedApi(broker.baseUrl, bob, 'POST', '/v1/offers', {
    to: alice.fingerprint, subject: 'bob->alice secret', size_bytes: 4,
  });

  // bob revokes alice: bob is the revoker, alice is the revoked peer.
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/peers/${alice.fingerprint}/revoke`, {});

  // alice is the revoked peer: the offer addressed to her disappears from her
  // own incoming list.
  const aliceOffers = await signedApi(broker.baseUrl, alice, 'GET', '/v1/offers');
  assert.equal(
    aliceOffers.body.incoming.some((o) => o.id === bobToAlice.body.id),
    false,
    'a revoked peer must not see a pre-existing offer addressed to them',
  );

  // bob is the revoker: the offer addressed to him is still listed.
  const bobOffers = await signedApi(broker.baseUrl, bob, 'GET', '/v1/offers');
  assert.ok(
    bobOffers.body.incoming.some((o) => o.id === aliceToBob.body.id),
    "the revoker's own incoming list is unaffected",
  );
});

test('offers list also filters the answered view: a revoked peer loses their own accepted offer', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);

  const offer = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'will be accepted', size_bytes: 4,
  });
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/offers/${offer.body.id}/respond`, { accept: true });

  // bob revokes alice: alice (the offer's sender) is the revoked peer here.
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/peers/${alice.fingerprint}/revoke`, {});

  const aliceOffers = await signedApi(broker.baseUrl, alice, 'GET', '/v1/offers');
  assert.equal(
    aliceOffers.body.answered.some((o) => o.id === offer.body.id),
    false,
    'a revoked peer must not see their own answered offer in the list either',
  );
});

test('offer respond, close and payload upload all require an active link, not just participancy', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);

  // Sanity: prove the write routes work normally while the link is active,
  // so the assertions below are about revocation, not a broken control.
  const control = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'control', size_bytes: 4,
  });
  const controlRespond = await signedApi(
    broker.baseUrl, bob, 'POST', `/v1/offers/${control.body.id}/respond`, { accept: true },
  );
  assert.equal(controlRespond.status, 200);

  const offerRespond = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'to-respond', size_bytes: 4,
  });
  const offerClose = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'to-close', size_bytes: 4,
  });
  const offerPayload = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'to-upload', size_bytes: 4,
  });

  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});

  const respondRes = await signedApi(
    broker.baseUrl, bob, 'POST', `/v1/offers/${offerRespond.body.id}/respond`, { accept: true },
  );
  assert.equal(respondRes.status, 403);
  assert.equal(respondRes.body.error, 'no_link');

  const closeRes = await signedApi(broker.baseUrl, alice, 'POST', `/v1/offers/${offerClose.body.id}/close`, {});
  assert.equal(closeRes.status, 403);
  assert.equal(closeRes.body.error, 'no_link');

  const payloadRes = await signedUpload(
    broker.baseUrl, alice, `/v1/offers/${offerPayload.body.id}/payload`, Buffer.from('data'), 'application/octet-stream',
  );
  assert.equal(payloadRes.status, 403);
  assert.equal(payloadRes.body.error, 'no_link');
});

// ---- fix round 2: the missing axis — revoked PARTICIPANT × MUTATING route --
//
// The suite could not see either of the two Critical blockers below because of
// a structural gap, not a missing assertion. test/authz.test.mjs pivots on
// *non-participant* attackers (eve, carol); everything above this line pivots
// on *read* routes. The intersection — a genuine participant whose link has
// been revoked, reaching a route that WRITES — had no tests in it at all, and
// that is exactly where both blockers lived.
//
// So enumerate it. Every mutating route a revoked participant can still reach
// gets an assertion here, whether or not it was broken: the ack route and the
// revoke route were the two bugs, and the three offer write routes were
// already gated in the previous round and stand here as regression guards. A
// route added to this surface later should be added to this list.

// Sets up alice -> bob with one message, one thread, one uploaded payload, then
// has alice revoke bob. Returns everything bob knows the id of, which is the
// worst realistic case: a peer who was a participant right up to the revoke.
async function revokedBob(t) {
  const { broker, alice, bob } = await pairedPair(t);

  const message = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'secret one', body: 'TOP SECRET ONE',
  });
  const unread = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'secret two', body: 'TOP SECRET TWO',
  });

  // A blob bob never downloads, so its 404 later cannot be a cache artifact.
  const offer = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'a file', size_bytes: 11,
  });
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/offers/${offer.body.id}/respond`, { accept: true });
  const up = await signedUpload(
    broker.baseUrl, alice, `/v1/offers/${offer.body.id}/payload`, Buffer.from('SECRETBLOB!'),
  );

  const revoke = await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});
  assert.equal(revoke.status, 200, 'the revoke itself must land');

  return {
    broker,
    alice,
    bob,
    messageId: message.body.id,
    unreadId: unread.body.id,
    threadId: message.body.thread_id,
    blobMessageId: up.body.message.id,
  };
}

function readEvents(thread) {
  return thread.body.events ?? [];
}

// ---- C1 -------------------------------------------------------------------
//
// The route checked only that *a* link record existed, and revokeLink rewrote
// `revoked_by` unconditionally. readableBetween decides read access solely
// from `revoked_by`, so one signed counter-revoke from the revoked peer
// inverted the whole asymmetry: bob regained every shared record — including
// a message he had never fetched — and alice was locked out of her own copy.
// Spec §8's central promise ("your copy of the history stays readable by you…
// a revoke is one more auditable event, not an erasure") became an erasure of
// the *revoker's* access.

test('a revoked peer cannot counter-revoke their way back into the history', async (t) => {
  const { broker, alice, bob, messageId, unreadId, threadId, blobMessageId } = await revokedBob(t);

  // Pre-condition: the revocation is doing its job before bob tries anything.
  assert.equal(
    (await signedApi(broker.baseUrl, bob, 'GET', `/v1/messages/${unreadId}`)).status, 404,
  );

  // The attack: one signed revoke of alice, from the peer alice just revoked.
  const counter = await signedApi(broker.baseUrl, bob, 'POST', `/v1/peers/${alice.fingerprint}/revoke`, {});

  // It is not an error — a revoke must stay safe to retry, and from bob's side
  // "this link is revoked" is simply true. It must also change nothing.
  assert.equal(counter.status, 200, 'idempotent, not an error: disconnect_peer must be retryable');
  assert.equal(counter.body.status, 'revoked');

  const link = broker.registry.getLink(alice.fingerprint, bob.fingerprint);
  assert.equal(link.revoked_by, alice.fingerprint, 'the first revocation is the one that stands');
  assert.equal(counter.body.revoked_at, link.revoked_at, 'revoked_at must not be rewritten either');

  // bob is still the revoked peer, on every surface.
  for (const [path, what] of [
    [`/v1/messages/${messageId}`, 'a message he had already seen'],
    [`/v1/messages/${unreadId}`, 'a message he never fetched'],
    [`/v1/messages/${blobMessageId}`, 'the offer message'],
    [`/v1/messages/${blobMessageId}/payload`, 'the payload bytes'],
    [`/v1/threads/${threadId}`, 'the thread history'],
  ]) {
    const res = await signedApi(broker.baseUrl, bob, 'GET', path);
    assert.equal(res.status, 404, `bob must stay locked out of ${what}`);
  }
  const bobThreads = await signedApi(broker.baseUrl, bob, 'GET', '/v1/threads');
  assert.equal(bobThreads.body.threads.length, 0, 'and out of the thread listing');

  // And alice — the revoker — still holds her own copy, which is the half of
  // the guarantee the inversion destroyed.
  const aliceMessage = await signedApi(broker.baseUrl, alice, 'GET', `/v1/messages/${unreadId}`);
  assert.equal(aliceMessage.status, 200, 'the revoker must never be locked out of her own record');
  assert.equal(aliceMessage.body.body, 'TOP SECRET TWO');

  const aliceThread = await signedApi(broker.baseUrl, alice, 'GET', `/v1/threads/${threadId}`);
  assert.equal(aliceThread.status, 200);
  assert.ok(
    readEvents(aliceThread).some((e) => e.type === 'message.sent' && e.message_id === messageId),
    "the revoker's thread history is intact, not merely reachable",
  );

  const aliceThreads = await signedApi(broker.baseUrl, alice, 'GET', '/v1/threads');
  assert.ok(aliceThreads.body.threads.length >= 1, "the revoker's listing survives too");

  const alicePayload = await signedApi(broker.baseUrl, alice, 'GET', `/v1/messages/${blobMessageId}/payload`);
  assert.equal(alicePayload.status, 200);
  assert.equal(alicePayload.body.toString(), 'SECRETBLOB!');
});

test('a second revoke by the revoker is idempotent too, so a retry is harmless', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);
  const first = await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});
  const second = await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});
  assert.equal(second.status, 200);
  assert.deepEqual(second.body, first.body, 'the standing record, byte for byte');
});

test('only a party to a link may revoke it, even with a valid signature', async (t) => {
  // Unreachable through the route (it always passes caller.fingerprint as
  // `by`), which is precisely why it is asserted at the Registry: `revoked_by`
  // is authorization input for every read surface now, not an audit field, so
  // the guard has to hold for the next caller as well as this one.
  const { broker, alice, bob } = await pairedPair(t);
  const carol = broker.identity('carol');
  assert.throws(
    () => broker.registry.revokeLink({ a: alice.fingerprint, b: bob.fingerprint, by: carol.fingerprint }),
    (e) => e.code === 'not_a_party' && e.status === 403,
  );
  assert.throws(
    () => broker.registry.revokeLink({ a: alice.fingerprint, b: bob.fingerprint, by: 'not-a-fingerprint' }),
    (e) => e.code === 'invalid_fingerprint' && e.status === 400,
    'revoked_by is validated, not stored as whatever arrived',
  );
  assert.equal(
    broker.registry.getLink(alice.fingerprint, bob.fingerprint).status, 'active',
    'a refused revoke must not have written anything',
  );
});

// ---- C2 -------------------------------------------------------------------
//
// POST /v1/messages/:id/ack used a bare participancy check and then returned
// store.ackRead(...), which is the complete message record, `body` included.
// So the same record GET /v1/messages/:id correctly 404s to a revoked peer
// came back 200 with its contents through the ack door: two doors on one
// record, one of them locked. It also flipped the status to `read` and
// appended a message.read event to the *revoker's* append-only thread log.

test('the ack route neither discloses nor acts for a revoked peer', async (t) => {
  const { broker, alice, bob, unreadId, threadId } = await revokedBob(t);

  const before = readEvents(await signedApi(broker.baseUrl, alice, 'GET', `/v1/threads/${threadId}`));
  assert.equal(
    before.some((e) => e.type === 'message.read' && e.message_id === unreadId), false,
    'pre-condition: nothing has acked this message yet',
  );

  const ack = await signedApi(broker.baseUrl, bob, 'POST', `/v1/messages/${unreadId}/ack`, {});

  // The same answer the read path gives, so the ack door cannot be used as an
  // oracle for a record the read door hides.
  const read = await signedApi(broker.baseUrl, bob, 'GET', `/v1/messages/${unreadId}`);
  assert.equal(ack.status, 404, 'the ack door must be as locked as the read door');
  assert.equal(ack.body.error, read.body.error);
  assert.equal(ack.body.message, read.body.message, 'byte-identical to the read refusal');
  assert.equal('body' in ack.body, false, 'and it must not carry the record it refused');

  // It must also not have acted. Both halves matter: the status on alice's
  // record, and her append-only log, which a revoked peer must not be able to
  // write to.
  const after = readEvents(await signedApi(broker.baseUrl, alice, 'GET', `/v1/threads/${threadId}`));
  assert.equal(
    after.some((e) => e.type === 'message.read' && e.message_id === unreadId), false,
    "a revoked peer must not append to the revoker's thread log",
  );
  assert.equal(after.length, before.length, 'no event of any type was appended');

  const aliceView = await signedApi(broker.baseUrl, alice, 'GET', `/v1/messages/${unreadId}`);
  assert.equal(aliceView.status, 200);
  assert.notEqual(aliceView.body.status, 'read', 'the message status was not flipped');
});

test('the revoker keeps their own ack, so the fix is not a blanket block', async (t) => {
  // The asymmetry has two halves and only one of them was broken. bob revokes
  // alice here, so bob is the revoker and the message addressed to him is
  // still his to ack.
  const { broker, alice, bob } = await pairedPair(t);
  const sent = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'mine to ack', body: 'x',
  });
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/peers/${alice.fingerprint}/revoke`, {});

  const ack = await signedApi(broker.baseUrl, bob, 'POST', `/v1/messages/${sent.body.id}/ack`, {});
  assert.equal(ack.status, 200, "the revoker's own ack must still work");
  assert.equal(ack.body.status, 'read');
});

test('a sender acking is still ackRead\'s own 403, not a 404', async (t) => {
  // Left deliberately as it was: not_recipient discloses nothing a sender does
  // not already know, and the global rule reserves 403 for "your own identity
  // is the problem", which this is. Pinned so the C2 fix cannot quietly widen
  // into it.
  const { broker, alice, bob } = await pairedPair(t);
  const sent = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'x', body: 'y',
  });
  const res = await signedApi(broker.baseUrl, alice, 'POST', `/v1/messages/${sent.body.id}/ack`, {});
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'not_recipient');
});

// ---- the rest of the axis, as regression guards ---------------------------
//
// Task 10 already gated these three with requireActiveLink. They belong in this
// list anyway: the axis is the control, and a route that is only correct by
// accident of when it was written is one refactor from joining C2.

test('every offer write route refuses the revoked peer, from the revoked side', async (t) => {
  const { broker, alice, bob } = await pairedPair(t);

  // Three offers FROM bob, so bob is the one who owns the close and upload
  // rights — the tests above this line only ever exercised those from the
  // revoker's side, which is the weaker direction.
  const toRespond = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'bob responds', size_bytes: 4,
  });
  const toClose = await signedApi(broker.baseUrl, bob, 'POST', '/v1/offers', {
    to: alice.fingerprint, subject: 'bob closes', size_bytes: 4,
  });
  const toUpload = await signedApi(broker.baseUrl, bob, 'POST', '/v1/offers', {
    to: alice.fingerprint, subject: 'bob uploads', size_bytes: 4,
  });
  await signedApi(broker.baseUrl, alice, 'POST', `/v1/offers/${toUpload.body.id}/respond`, { accept: true });

  await signedApi(broker.baseUrl, alice, 'POST', `/v1/peers/${bob.fingerprint}/revoke`, {});

  const respond = await signedApi(
    broker.baseUrl, bob, 'POST', `/v1/offers/${toRespond.body.id}/respond`, { accept: true },
  );
  assert.equal(respond.status, 403);
  assert.equal(respond.body.error, 'no_link');

  const close = await signedApi(broker.baseUrl, bob, 'POST', `/v1/offers/${toClose.body.id}/close`, {});
  assert.equal(close.status, 403);
  assert.equal(close.body.error, 'no_link');

  const upload = await signedUpload(
    broker.baseUrl, bob, `/v1/offers/${toUpload.body.id}/payload`, Buffer.from('data'),
  );
  assert.equal(upload.status, 403);
  assert.equal(upload.body.error, 'no_link');

  // And none of the three left a mark on the records.
  assert.equal(broker.store.getOffer(toRespond.body.id).status, 'pending');
  assert.equal(broker.store.getOffer(toClose.body.id).status, 'pending');
  assert.equal(broker.store.getOffer(toUpload.body.id).blob_bytes ?? null, null);
});

test('a revoked peer cannot open new traffic on the shared thread either', async (t) => {
  // The send routes are the other two mutating surfaces on the axis. They were
  // correct from the start (requireActiveLink was Task 7's first gate), but an
  // enumeration with a hole in it is how both blockers survived sixteen
  // reviews, so the hole is closed rather than assumed.
  const { broker, alice, bob, threadId } = await revokedBob(t);

  for (const [resource, body] of [
    ['/v1/messages', { to: alice.fingerprint, subject: 'still here', body: 'x', thread_id: threadId }],
    ['/v1/offers', { to: alice.fingerprint, subject: 'still here', size_bytes: 4, thread_id: threadId }],
  ]) {
    const res = await signedApi(broker.baseUrl, bob, 'POST', resource, body);
    assert.equal(res.status, 403, `${resource} must refuse the revoked peer`);
    assert.equal(res.body.error, 'no_link');
  }

  const thread = await signedApi(broker.baseUrl, alice, 'GET', `/v1/threads/${threadId}`);
  assert.equal(
    readEvents(thread).some((e) => e.subject === 'still here'), false,
    "nothing reached the revoker's thread",
  );
});
