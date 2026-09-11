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
