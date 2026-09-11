import test from 'node:test';
import http from 'node:http';
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

// Threads are two-party by design — group threads are an explicit non-goal.
// Without enforcement, reply_to lets a caller splice a third party into someone
// else's thread: the spliced party is a genuine participant the thread record
// never names, so they get a 404 on their own thread, while the original pair
// can read message.sent metadata for traffic that is none of their business.
test('threads stay two-party', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  const carol = broker.identity('carol');
  broker.link(alice, bob);
  broker.link(bob, carol);
  const call = (who, m, p, b) => signedApi(broker.baseUrl, who, m, p, b);

  const first = await call(alice, 'POST', '/v1/messages', {
    to: bob.fingerprint, subject: 'q', body: '?',
  });
  assert.equal(first.status, 201);
  const thread = first.body.thread_id;

  await t.test('a third party cannot be spliced in by reply_to', async () => {
    const res = await call(bob, 'POST', '/v1/messages', {
      to: carol.fingerprint, subject: 'fwd', body: 'x', reply_to: first.body.id,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'not_found');
  });

  await t.test('nor by naming the thread directly', async () => {
    const res = await call(bob, 'POST', '/v1/messages', {
      to: carol.fingerprint, subject: 'fwd', body: 'x', thread_id: thread,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'not_found');
  });

  await t.test('nor through the offer flow, which shares resolveThread', async () => {
    const res = await call(bob, 'POST', '/v1/offers', {
      to: carol.fingerprint, subject: 'fwd', size_bytes: 16, thread_id: thread,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'not_found');
  });

  await t.test('replying into a thread that is not yours is the same 404', async () => {
    const res = await call(carol, 'POST', '/v1/messages', {
      to: bob.fingerprint, subject: 'butting in', body: 'x', reply_to: first.body.id,
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'not_found');
  });

  await t.test('a reply_to that does not exist is indistinguishable from one that is not yours', async () => {
    const res = await call(bob, 'POST', '/v1/messages', {
      to: alice.fingerprint, subject: 'x', body: 'y', reply_to: 'msg_doesnotexist',
    });
    assert.equal(res.status, 404);
    assert.equal(res.body.error, 'not_found');
  });

  await t.test('the thread never gained a third party, and leaks no third-party metadata', async () => {
    const carolRead = await call(carol, 'GET', `/v1/threads/${thread}`);
    assert.equal(carolRead.status, 404, 'carol is not a participant and never became one');
    const carolList = await call(carol, 'GET', '/v1/threads');
    assert.deepEqual(carolList.body.threads, []);

    const read = await call(alice, 'GET', `/v1/threads/${thread}`);
    assert.equal(read.status, 200);
    assert.deepEqual(
      read.body.events[0].participants,
      [alice.fingerprint, bob.fingerprint].sort(),
    );
    const recipients = read.body.events
      .filter((e) => e.type === 'message.sent')
      .map((e) => e.to);
    assert.deepEqual(recipients, [bob.fingerprint], 'alice must not see traffic to a third party');
  });

  await t.test('the ordinary two-party reply still works', async () => {
    const res = await call(bob, 'POST', '/v1/messages', {
      to: alice.fingerprint, subject: 're: q', body: '!', reply_to: first.body.id,
    });
    assert.equal(res.status, 201);
    assert.equal(res.body.thread_id, thread, 'a legitimate reply stays in its thread');
  });
});

// The concrete attack behind the reserve-on-verify change: two copies of one
// captured signed request, the second arriving while the first is still inside
// `await jsonBody()`. Both used to pass the replay check and both used to act.
//
// Reproducing that needs the window held open deliberately: fetch serializes
// two identical requests to one origin, so the first completes (and commits)
// before the second is even parsed, and the race never happens. So send the
// first request's body in halves over a socket of its own and park it
// mid-body, deliver the duplicate while it waits, then let the first finish.
test('a captured request cannot be raced to double-send', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  broker.link(alice, bob);

  const body = JSON.stringify({ to: bob.fingerprint, subject: 'once', body: 'only once' });
  const { port } = new URL(broker.baseUrl);
  const headers = {
    'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body)),
    ...signedHeaders(alice, {
      method: 'POST',
      pathname: '/v1/messages',
      searchParams: new URLSearchParams(),
      body,
    }),
  };

  // One request, one fresh socket, body written in pieces under our control.
  const open = () => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: '/v1/messages',
      method: 'POST',
      headers,
      agent: new http.Agent({ keepAlive: false }),
    });
    const answered = new Promise((resolve, reject) => {
      req.on('response', (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { text += chunk; });
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
      });
      req.on('error', reject);
    });
    return { req, answered };
  };

  const half = Math.floor(body.length / 2);
  const first = open();
  first.req.write(body.slice(0, half));            // content-length promises more
  await new Promise((resolve) => setTimeout(resolve, 50));

  // The duplicate, delivered whole while the first is parked inside readBody.
  const second = open();
  second.req.end(body);
  const secondRes = await second.answered;

  first.req.end(body.slice(half));
  const firstRes = await first.answered;

  assert.deepEqual(
    [firstRes.status, secondRes.status].sort(),
    [201, 401],
    'exactly one of two identical requests may land',
  );
  const refused = [firstRes.body, secondRes.body].find((r) => r.error);
  assert.equal(refused.error, 'replay');

  const inbox = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
  assert.equal(inbox.body.messages.length, 1, 'the store must hold one message, not two');
});

// BROKER_TOKEN is no longer identity, but it is still a binding constraint: a
// coarse gate applied to every route except health, checked *before* signature
// verification. The old bearer-token suite died with the rewrite and nothing
// replaced it, so the constraint was unguarded. Kept last in the file and
// restored in teardown, because it mutates process-wide env.
test('the BROKER_TOKEN gate sits in front of signature verification', async (t) => {
  const broker = await startBroker();
  const previous = process.env.BROKER_TOKEN;
  process.env.BROKER_TOKEN = 'coarse-gate-secret';
  t.after(async () => {
    if (previous === undefined) delete process.env.BROKER_TOKEN;
    else process.env.BROKER_TOKEN = previous;
    await broker.stop();
  });
  const alice = broker.identity('alice');

  await t.test('health stays open with the gate on', async () => {
    const res = await signedApi(broker.baseUrl, null, 'GET', '/v1/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
  });

  // The load-bearing assertion: this request is perfectly signed and would
  // otherwise succeed, so only the gate can be refusing it.
  await t.test('a fully signed request without the token is refused', async () => {
    const res = await signedApi(broker.baseUrl, alice, 'GET', '/v1/inbox');
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'unauthorized');
  });

  await t.test('a signed request with the wrong token is refused', async () => {
    const res = await signedApi(broker.baseUrl, alice, 'GET', '/v1/inbox', undefined, { token: 'wrong' });
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'unauthorized');
  });

  await t.test('the correct token plus a valid signature succeeds', async () => {
    const res = await signedApi(broker.baseUrl, alice, 'GET', '/v1/inbox', undefined, {
      token: 'coarse-gate-secret',
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.agent, alice.fingerprint);
  });

  // And this pins the ordering: with the gate after verification, an unsigned
  // request would answer 400 malformed_signature instead.
  await t.test('the gate answers before the signature is even looked at', async () => {
    const res = await signedApi(broker.baseUrl, null, 'GET', '/v1/inbox');
    assert.equal(res.status, 401);
    assert.equal(res.body.error, 'unauthorized');
  });
});
