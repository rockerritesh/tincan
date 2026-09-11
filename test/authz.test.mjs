// One test per attack that worked in 0.1.x, when the broker trusted one shared
// bearer token and could not tell callers apart. Spec §1 lists them; each must
// now be refused, and refused for the *reason* named in the test — not merely
// with a non-200 status. A test that only checks "it failed" cannot tell a
// closed hole from a broken route.
//
// Non-participant reads must come back 404, not 403: a 403 would confirm the
// id exists, which is itself a probe. Several attacks below are also refused
// earlier than the attack name suggests (e.g. eve is registered but linked to
// nobody, so a send from her dies on no_link before impersonation ever
// matters) — each such test says explicitly which refusal it is asserting, so
// a future change that swaps one guard for another is visible here.
//
// Two attackers, two link topologies:
//   - eve  is registered but linked to nobody. She is refused by the very
//     first check on every route (no_link, or readableBetween finding no
//     link at all) — which means she can never tell a participant-only guard
//     apart from a plain link-existence guard: both refuse her identically.
//   - carol is linked to *both* alice and bob, but is not a party to any of
//     their records. She is the attacker who actually exercises the
//     participant check: with a real link on both sides, only a genuine
//     "are you from/to on this record, or in this thread's participant list"
//     guard stops her — a mutant that quietly narrows that guard to "is
//     there *a* link to *someone* on this record" would still refuse eve
//     (she has no link to anyone) but would wave carol through. Mutation
//     testing against this file confirmed exactly that: deleting
//     assertParticipant's call inside assertReadable, or deleting the
//     participants.includes() gate on the single-thread route, left the
//     suite green for eve-only attacks but red the moment carol was added —
//     and only once she was linked to *both* alice and bob, since a couple
//     of these checks resolve "the other participant" via a `.find()`/
//     ternary that degrades to picking an arbitrary stored participant once
//     the caller isn't one — participants are stored sorted, so which one
//     that is is an accident of alphabetical order, not something a single
//     link happens to reliably dodge.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startBroker, signedApi, signedUpload } from './helpers.mjs';

async function scenario(t) {
  const broker = await startBroker();
  t.after(() => broker.stop());

  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  const eve = broker.identity('eve');     // registered, but linked to nobody
  const carol = broker.identity('carol'); // linked to both, party to neither record
  broker.link(alice, bob);
  broker.link(alice, carol);
  broker.link(bob, carol);

  const seed = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'private', body: 'for bob only',
  });
  // If this seed silently failed, message would be undefined and every
  // not_found assertion below would pass for the wrong reason — there would
  // be nothing to read, not a guard refusing to let it be read.
  assert.equal(seed.status, 201, 'seed message must actually be created');
  return { broker, alice, bob, eve, carol, message: seed.body };
}

test('ATTACK: read another agent\'s inbox', async (t) => {
  const { broker, eve, bob } = await scenario(t);
  // In 0.1.x: GET /v1/inbox?agent=bob returned bob's messages. The route no
  // longer reads ?agent at all — the caller is the signature, so this can only
  // ever answer with your own mail.
  const res = await signedApi(broker.baseUrl, eve, 'GET', `/v1/inbox?agent=${bob.fingerprint}`);
  assert.equal(res.status, 200, 'the route still works');
  assert.equal(res.body.agent, eve.fingerprint, 'but it is always your own inbox');
  assert.equal(res.body.messages.length, 0);
});

test('ATTACK: send a message as someone else', async (t) => {
  const { broker, eve, alice, bob } = await scenario(t);
  // In 0.1.x: {"from":"alice"} was believed. Today `from` is never read from
  // the body, but this particular attempt is refused earlier still: eve has
  // no active link to bob, so requireActiveLink rejects it as no_link before
  // the forged `from` is ever considered. See the next test for the case
  // where the sender *does* have a link and the forgery itself is what's on
  // trial.
  const res = await signedApi(broker.baseUrl, eve, 'POST', '/v1/messages', {
    from: alice.fingerprint,
    to: bob.fingerprint,
    subject: 'forged',
    body: 'this should never arrive',
  });
  assert.equal(res.status, 403, 'eve is not linked to bob, so it fails before impersonation matters');
  assert.equal(res.body.error, 'no_link');

  const inbox = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
  assert.equal(inbox.body.messages.some((m) => m.subject === 'forged'), false);
});

test('ATTACK: forge `from` on a link you do have', async (t) => {
  const { broker, alice, bob } = await scenario(t);
  // Here the link is real (alice<->bob), so no_link can't fire — this isolates
  // the actual impersonation guard: `from` must come from the signature, not
  // the body, even when the caller is otherwise entitled to send. This is the
  // test that actually proves the body's `from` is ignored; the previous test
  // only proves a linkless sender never gets that far.
  const res = await signedApi(broker.baseUrl, bob, 'POST', '/v1/messages', {
    from: alice.fingerprint,      // bob claiming to be alice
    to: alice.fingerprint,
    subject: 'who sent this',
    body: 'x',
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.from, bob.fingerprint, 'the signature decides, not the body');
});

test('ATTACK: read a message you are not party to', async (t) => {
  const { broker, eve, carol, message } = await scenario(t);
  // eve (no link to anyone) and carol (linked to both alice and bob, but
  // party to neither) must both be refused — carol is the one who actually
  // exercises assertParticipant inside assertReadable rather than being
  // caught earlier by an absent link.
  for (const attacker of [eve, carol]) {
    const res = await signedApi(broker.baseUrl, attacker, 'GET', `/v1/messages/${message.id}`);
    assert.equal(res.status, 404, `${attacker.label}: a 403 here would confirm the id exists`);
    assert.equal(res.body.error, 'not_found');
  }
});

test('ATTACK: fetch a payload you are not party to', async (t) => {
  const { broker, eve, carol, message } = await scenario(t);
  for (const attacker of [eve, carol]) {
    const res = await signedApi(broker.baseUrl, attacker, 'GET', `/v1/messages/${message.id}/payload`);
    // Must be not_found from assertReadable, not no_blob from store.readBlob —
    // this message has an inline body and no stored blob at all, so if the
    // route ever read the blob before checking readability, a *legitimate*
    // participant would get no_blob too and this test would pass for a
    // reason that has nothing to do with authorization.
    assert.equal(res.status, 404, `${attacker.label}`);
    assert.equal(res.body.error, 'not_found');
  }
});

test('ATTACK: a nonexistent id and someone else\'s id are indistinguishable', async (t) => {
  const { broker, eve, message } = await scenario(t);
  const theirs = await signedApi(broker.baseUrl, eve, 'GET', `/v1/messages/${message.id}`);
  const nothing = await signedApi(broker.baseUrl, eve, 'GET', '/v1/messages/msg_doesnotexist');
  assert.equal(theirs.status, nothing.status);
  assert.equal(theirs.body.error, nothing.body.error);
});

test('ATTACK: ack a message addressed to someone else', async (t) => {
  const { broker, eve, bob, message } = await scenario(t);
  // The 0.1.x attack was POST .../ack {"agent":"<victim>"} — the body naming
  // whose read receipt this was. That field is never read now (the caller is
  // the signature), so send it anyway: the point is to prove the forged lever
  // itself is inert, not merely that some other request shape is refused.
  const res = await signedApi(broker.baseUrl, eve, 'POST', `/v1/messages/${message.id}/ack`, {
    agent: bob.fingerprint,
  });
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');

  // Prove no ack landed on bob's behalf: the message must still be sitting,
  // unacked, in his inbox. If the forged ack had gone through, ackRead would
  // have removed it from there.
  const inbox = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
  assert.equal(
    inbox.body.messages.some((m) => m.id === message.id),
    true,
    'still unacked — the forged ack did not remove it from bob\'s inbox',
  );

  // And the broker survives the attempt — this is the one test in the suite
  // whose point is as much "did not crash" as "was refused".
  const still = await signedApi(broker.baseUrl, broker.identity('probe'), 'GET', '/v1/health');
  assert.equal(still.status, 200, 'and the broker is unharmed');
});

test('ATTACK: read a thread you are not in', async (t) => {
  const { broker, alice, eve, carol } = await scenario(t);
  const { body: threads } = await signedApi(broker.baseUrl, alice, 'GET', '/v1/threads');
  const threadId = threads.threads[0].thread_id;

  // carol matters here specifically: the single-thread route resolves "the
  // other participant" with `participants.find((p) => p !== caller)`, which
  // for a non-participant caller silently returns whichever stored
  // participant isn't equal to them — arbitrary, since participants are
  // stored sorted. Linking carol to *both* alice and bob means that pick
  // can't accidentally dodge her; only a real participants.includes() gate
  // stops her.
  for (const attacker of [eve, carol]) {
    const res = await signedApi(broker.baseUrl, attacker, 'GET', `/v1/threads/${threadId}`);
    assert.equal(res.status, 404, `${attacker.label}`);
    assert.equal(res.body.error, 'not_found');
  }
});

test('ATTACK: list threads and see other people\'s', async (t) => {
  const { broker, eve, carol } = await scenario(t);
  for (const attacker of [eve, carol]) {
    const res = await signedApi(broker.baseUrl, attacker, 'GET', '/v1/threads');
    assert.equal(res.status, 200);
    assert.deepEqual(res.body.threads, [], `${attacker.label}: scoped to the caller`);
  }
});

test('ATTACK: enumerate every agent on the broker', async (t) => {
  const { broker, eve } = await scenario(t);
  // GET /v1/agents used to list every registered key. The route is gone
  // entirely now, so this must fall through to the generic router 404 —
  // not_found is the same code every other unmatched route produces.
  const gone = await signedApi(broker.baseUrl, eve, 'GET', '/v1/agents');
  assert.equal(gone.status, 404, '/v1/agents is removed');
  assert.equal(gone.body.error, 'not_found');

  const peers = await signedApi(broker.baseUrl, eve, 'GET', '/v1/peers');
  assert.equal(peers.status, 200);
  assert.deepEqual(peers.body.peers, [], 'and /v1/peers shows only your own links');
});

test('ATTACK: respond to an offer that is not yours', async (t) => {
  const { broker, alice, bob, eve } = await scenario(t);
  const offerRes = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'big', size_bytes: 100000, content_type: 'text/plain',
  });
  assert.equal(offerRes.status, 201, 'seed offer must actually be created');
  const offer = offerRes.body;

  // The route's assertParticipant gate is what refuses eve, as 404. The
  // store's own respondOffer would separately refuse a non-recipient with
  // not_recipient/403 — that guard exists too, but it is never reached here,
  // and the assertion below would catch it if the route's gate were removed
  // and that 403 leaked through instead.
  const res = await signedApi(broker.baseUrl, eve, 'POST', `/v1/offers/${offer.id}/respond`, { accept: true });
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');
});

test('ATTACK: upload a payload into someone else\'s accepted offer', async (t) => {
  const { broker, alice, bob, eve } = await scenario(t);
  const offerRes = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'big', size_bytes: 5, content_type: 'text/plain',
  });
  assert.equal(offerRes.status, 201, 'seed offer must actually be created');
  const offer = offerRes.body;

  const acceptRes = await signedApi(broker.baseUrl, bob, 'POST', `/v1/offers/${offer.id}/respond`, { accept: true });
  assert.equal(acceptRes.status, 200, 'bob must actually accept, or the upload below is refused for the wrong reason');

  // Same shape as the respond attack: the route's assertParticipant gate
  // refuses eve as 404 before the store's own not_sender/403 check is ever
  // reached.
  const res = await signedUpload(broker.baseUrl, eve, `/v1/offers/${offer.id}/payload`, Buffer.from('12345'));
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');
});

test('ATTACK: health leaks the broker\'s filesystem layout', async (t) => {
  const { broker } = await scenario(t);
  // /v1/health is the one unauthenticated route by design, so hit it
  // unsigned (identity: null) — the attack is unauthenticated reconnaissance,
  // not something an authenticated caller uniquely gets.
  const res = await signedApi(broker.baseUrl, null, 'GET', '/v1/health');
  assert.equal(res.status, 200);
  for (const leak of ['data_dir', 'root', 'path']) {
    assert.equal(leak in res.body, false, `health must not expose ${leak}`);
  }
});
