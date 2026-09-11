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
import test from 'node:test';
import assert from 'node:assert/strict';
import { startBroker, signedApi, signedUpload } from './helpers.mjs';

async function scenario(t) {
  const broker = await startBroker();
  t.after(() => broker.stop());

  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  const eve = broker.identity('eve');   // registered, but linked to nobody
  broker.link(alice, bob);

  const { body: message } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'private', body: 'for bob only',
  });
  return { broker, alice, bob, eve, message };
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
  // the body, even when the caller is otherwise entitled to send.
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
  const { broker, eve, message } = await scenario(t);
  const res = await signedApi(broker.baseUrl, eve, 'GET', `/v1/messages/${message.id}`);
  assert.equal(res.status, 404, 'a 403 here would confirm the id exists');
  assert.equal(res.body.error, 'not_found');
});

test('ATTACK: fetch a payload you are not party to', async (t) => {
  const { broker, eve, message } = await scenario(t);
  const res = await signedApi(broker.baseUrl, eve, 'GET', `/v1/messages/${message.id}/payload`);
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');
});

test('ATTACK: a nonexistent id and someone else\'s id are indistinguishable', async (t) => {
  const { broker, eve, message } = await scenario(t);
  const theirs = await signedApi(broker.baseUrl, eve, 'GET', `/v1/messages/${message.id}`);
  const nothing = await signedApi(broker.baseUrl, eve, 'GET', '/v1/messages/msg_doesnotexist');
  assert.equal(theirs.status, nothing.status);
  assert.equal(theirs.body.error, nothing.body.error);
});

test('ATTACK: ack a message addressed to someone else', async (t) => {
  const { broker, eve, message } = await scenario(t);
  const res = await signedApi(broker.baseUrl, eve, 'POST', `/v1/messages/${message.id}/ack`, {});
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');

  // And the broker survives the attempt — this is the one test in the suite
  // whose point is as much "did not crash" as "was refused".
  const still = await signedApi(broker.baseUrl, broker.identity('probe'), 'GET', '/v1/health');
  assert.equal(still.status, 200, 'and the broker is unharmed');
});

test('ATTACK: read a thread you are not in', async (t) => {
  const { broker, alice, eve } = await scenario(t);
  const { body: threads } = await signedApi(broker.baseUrl, alice, 'GET', '/v1/threads');
  const threadId = threads.threads[0].thread_id;

  const res = await signedApi(broker.baseUrl, eve, 'GET', `/v1/threads/${threadId}`);
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');
});

test('ATTACK: list threads and see other people\'s', async (t) => {
  const { broker, eve } = await scenario(t);
  const res = await signedApi(broker.baseUrl, eve, 'GET', '/v1/threads');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.threads, [], 'scoped to the caller');
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
  const { body: offer } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'big', size_bytes: 100000, content_type: 'text/plain',
  });
  const res = await signedApi(broker.baseUrl, eve, 'POST', `/v1/offers/${offer.id}/respond`, { accept: true });
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'not_found');
});

test('ATTACK: upload a payload into someone else\'s accepted offer', async (t) => {
  const { broker, alice, bob, eve } = await scenario(t);
  const { body: offer } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
    to: bob.fingerprint, subject: 'big', size_bytes: 5, content_type: 'text/plain',
  });
  await signedApi(broker.baseUrl, bob, 'POST', `/v1/offers/${offer.id}/respond`, { accept: true });

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
