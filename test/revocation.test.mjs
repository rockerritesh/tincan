import test from 'node:test';
import assert from 'node:assert/strict';
import { startBroker, signedApi } from './helpers.mjs';
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
