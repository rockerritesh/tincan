import test from 'node:test';
import assert from 'node:assert/strict';
import { startBroker, signedApi, signedUpload } from './helpers.mjs';
import { signedHeaders } from '../mcp/identity.mjs';

test('the signed HTTP surface', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  broker.link(alice, bob);

  await t.test('health is open, reports liveness, and leaks no filesystem path', async () => {
    const res = await signedApi(broker.baseUrl, null, 'GET', '/v1/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
    assert.equal(res.body.auth, 'signature');
    assert.equal('data_dir' in res.body, false, 'an unauthenticated route must not disclose paths');
  });

  await t.test('an unsigned request to any other route is refused', async () => {
    for (const [method, p] of [['GET', '/v1/inbox'], ['GET', '/v1/peers'], ['GET', '/v1/threads']]) {
      const res = await signedApi(broker.baseUrl, null, method, p);
      assert.equal(res.status, 400, `${method} ${p} should be malformed without signature headers`);
      assert.equal(res.body.error, 'malformed_signature');
    }
  });

  await t.test('a signed send lands, and `from` comes from the signature', async () => {
    const sent = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
      from: bob.fingerprint,           // a lie, and it must be ignored
      to: bob.fingerprint,
      subject: 'ping',
      body: 'are you there?',
    });
    assert.equal(sent.status, 201);
    assert.equal(sent.body.from, alice.fingerprint, 'the claimed `from` must be discarded');
    assert.equal(sent.body.status, 'queued');
  });

  await t.test('inbox is always the caller\'s own — there is no agent parameter', async () => {
    const res = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
    assert.equal(res.status, 200);
    assert.equal(res.body.agent, bob.fingerprint);
    assert.equal(res.body.messages.length, 1);

    // Supplying one changes nothing, because it is not part of the contract.
    const withParam = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox?agent=' + alice.fingerprint);
    assert.equal(withParam.body.agent, bob.fingerprint);
  });

  await t.test('/v1/agents is gone', async () => {
    const res = await signedApi(broker.baseUrl, alice, 'GET', '/v1/agents');
    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'not_found');
  });

  await t.test('ack, status and thread history work for participants', async () => {
    const inbox = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
    const id = inbox.body.messages[0].id;

    const acked = await signedApi(broker.baseUrl, bob, 'POST', `/v1/messages/${id}/ack`);
    assert.equal(acked.status, 200);
    assert.equal(acked.body.status, 'read');

    const seen = await signedApi(broker.baseUrl, alice, 'GET', `/v1/messages/${id}`);
    assert.equal(seen.body.status, 'read');

    const threads = await signedApi(broker.baseUrl, alice, 'GET', '/v1/threads');
    assert.equal(threads.body.threads.length, 1);
    const history = await signedApi(broker.baseUrl, alice, 'GET', `/v1/threads/${threads.body.threads[0].thread_id}`);
    assert.equal(history.body.events[0].type, 'thread.created');
  });

  await t.test('sending to an agent you are not linked to is refused', async () => {
    const carol = broker.identity('carol');
    const res = await signedApi(broker.baseUrl, alice, 'POST', '/v1/messages', {
      to: carol.fingerprint,
      subject: 'hi',
      body: 'x',
    });
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'no_link');
  });

  await t.test('a key the broker has never seen is refused everywhere but redeem', async () => {
    const ghost = broker.stranger('ghost');
    const res = await signedApi(broker.baseUrl, ghost, 'GET', '/v1/inbox');
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'unknown_key');
  });
});

// The offer routes carry the same rule, and they are the ones where the signed
// body hash has to be confirmed by hand. flow.test.mjs used to cover this flow
// with a shared token; until it is rewritten, cover it here.
test('the signed offer flow', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  const carol = broker.identity('carol');
  broker.link(alice, bob);

  const payload = Buffer.from('x'.repeat(4096));
  let offerId;
  let messageId;

  await t.test('an offer takes its sender from the signature', async () => {
    const res = await signedApi(broker.baseUrl, alice, 'POST', '/v1/offers', {
      from: bob.fingerprint,           // a lie, and it must be ignored
      to: bob.fingerprint,
      subject: 'a file',
      size_bytes: payload.length,
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.from, alice.fingerprint);
    assert.equal(res.body.status, 'pending');
    offerId = res.body.id;
  });

  await t.test('offers listings are the caller\'s own', async () => {
    const mine = await signedApi(broker.baseUrl, bob, 'GET', '/v1/offers');
    assert.equal(mine.body.agent, bob.fingerprint);
    assert.equal(mine.body.incoming.length, 1);

    const theirs = await signedApi(broker.baseUrl, carol, 'GET', '/v1/offers?agent=' + bob.fingerprint);
    assert.equal(theirs.body.agent, carol.fingerprint, 'an agent parameter must not be honoured');
    assert.equal(theirs.body.incoming.length, 0);
  });

  await t.test('a non-participant cannot see or answer an offer', async () => {
    const peek = await signedApi(broker.baseUrl, carol, 'GET', `/v1/offers/${offerId}`);
    assert.equal(peek.status, 404, 'not-yours must look like not-there');
    assert.equal(peek.body.error, 'not_found');

    const answer = await signedApi(broker.baseUrl, carol, 'POST', `/v1/offers/${offerId}/respond`, {
      agent: bob.fingerprint,
      accept: true,
    });
    assert.equal(answer.status, 404);
    assert.equal(answer.body.error, 'not_found');
  });

  await t.test('the recipient accepts and the sender uploads', async () => {
    const answer = await signedApi(broker.baseUrl, bob, 'POST', `/v1/offers/${offerId}/respond`, {
      accept: true,
    });
    assert.equal(answer.status, 200);
    assert.equal(answer.body.status, 'accepted');

    const up = await signedUpload(broker.baseUrl, alice, `/v1/offers/${offerId}/payload`, payload);
    assert.equal(up.status, 201);
    assert.equal(up.body.message.from, alice.fingerprint);
    messageId = up.body.message.id;
  });

  await t.test('only a participant may download the payload', async () => {
    const got = await signedApi(broker.baseUrl, bob, 'GET', `/v1/messages/${messageId}/payload`);
    assert.equal(got.status, 200);
    assert.ok(payload.equals(got.body), 'the bytes must survive the round trip');

    const denied = await signedApi(broker.baseUrl, carol, 'GET', `/v1/messages/${messageId}/payload`);
    assert.equal(denied.status, 404);
    assert.equal(denied.body.error, 'not_found');
  });

  await t.test('a body the signature does not cover is refused, and keeps its nonce', async () => {
    // Sign an ack over the empty body a client really sends, then swap in a
    // different body on the wire. The signature still verifies — the body hash
    // it commits to does not match what arrived.
    const inbox = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
    const id = inbox.body.messages[0].id;
    const pathname = `/v1/messages/${id}/ack`;
    const headers = signedHeaders(bob, {
      method: 'POST',
      pathname,
      searchParams: new URLSearchParams(),
      body: undefined,
    });

    const tampered = await fetch(`${broker.baseUrl}${pathname}`, {
      method: 'POST',
      headers: { ...headers, 'content-type': 'application/json' },
      body: JSON.stringify({ agent: alice.fingerprint }),
    });
    assert.equal(tampered.status, 400);
    assert.equal((await tampered.json()).error, 'body_mismatch');

    // The nonce is spent in commit(), which every route reaches only after its
    // body is confirmed. So the request above burned nothing, and replaying
    // those same headers with the body they actually signed still works. If
    // commit() ever moved ahead of confirmBody, this would be a `replay` 401
    // and an honest client could never retry a corrupted upload.
    const honest = await fetch(`${broker.baseUrl}${pathname}`, { method: 'POST', headers });
    assert.equal(honest.status, 200, 'a rejected body must not spend the nonce');
    assert.equal((await honest.json()).status, 'read');
  });
});
