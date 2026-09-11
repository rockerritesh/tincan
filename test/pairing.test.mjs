import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { startBroker, signedApi } from './helpers.mjs';
import { shortFingerprint } from '../shared/fingerprint.mjs';
import { INVITE_TTL_MS } from '../server/registry.mjs';

test('minting returns a code exactly once', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');

  const res = await signedApi(broker.baseUrl, alice, 'POST', '/v1/invites', {});
  assert.equal(res.status, 201);
  assert.match(res.body.code, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
  assert.ok(res.body.invite.expires_at);
  assert.equal('code_sha256' in res.body.invite, false, 'do not hand back the hash');

  // Nothing on the broker can produce the code again.
  const stored = broker.registry.getInviteByCode(res.body.code);
  assert.equal(stored.status, 'open');
  assert.equal('code' in stored, false);
});

test('a stranger redeems an invite and both sides become linked', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.stranger('bob');     // the broker has never seen this key

  const { body: minted } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/invites', {});

  const redeemed = await signedApi(broker.baseUrl, bob, 'POST', '/v1/invites/redeem', {
    code: minted.code,
    label: 'bob',
  });
  assert.equal(redeemed.status, 201);
  assert.equal(redeemed.body.peer.fingerprint, alice.fingerprint);
  assert.equal(redeemed.body.peer.label, 'alice');
  assert.equal(redeemed.body.peer.short, shortFingerprint(alice.fingerprint));

  assert.equal(broker.registry.linkStatus(alice.fingerprint, bob.fingerprint), 'active');
  assert.equal(broker.registry.getKey(bob.fingerprint).label, 'bob');

  // And now bob can actually use the broker.
  const inbox = await signedApi(broker.baseUrl, bob, 'GET', '/v1/inbox');
  assert.equal(inbox.status, 200);
});

test('alice sees the new peer, and only her own peers', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  const carol = broker.identity('carol');
  broker.link(alice, bob);
  broker.link(bob, carol);

  const res = await signedApi(broker.baseUrl, alice, 'GET', '/v1/peers');
  assert.equal(res.status, 200);
  assert.deepEqual(res.body.peers.map((p) => p.label), ['bob']);
  assert.equal(res.body.peers[0].short, shortFingerprint(bob.fingerprint));
  assert.equal(res.body.peers[0].status, 'active');
});

test('a code cannot be reused', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.stranger('bob');
  const carol = broker.stranger('carol');

  const { body: minted } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/invites', {});
  await signedApi(broker.baseUrl, bob, 'POST', '/v1/invites/redeem', { code: minted.code, label: 'bob' });

  const second = await signedApi(broker.baseUrl, carol, 'POST', '/v1/invites/redeem', {
    code: minted.code, label: 'carol',
  });
  assert.equal(second.status, 409);
  assert.equal(second.body.error, 'invite_spent');
  assert.equal(broker.registry.getKey(carol.fingerprint), null, 'a failed redeem registers nothing');
});

test('an expired code is refused', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.stranger('bob');

  const { code } = broker.registry.createInvite({
    issuer: alice.fingerprint, issuerLabel: 'alice', ttlMs: -1,
  });
  const res = await signedApi(broker.baseUrl, bob, 'POST', '/v1/invites/redeem', { code, label: 'bob' });
  assert.equal(res.status, 409);
  assert.equal(res.body.error, 'invite_expired');
});

test('an unknown code is a 404 and reveals nothing', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const bob = broker.stranger('bob');
  const res = await signedApi(broker.baseUrl, bob, 'POST', '/v1/invites/redeem', {
    code: 'ZZZZ-ZZZZ-ZZZZ-ZZZZ', label: 'bob',
  });
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'unknown_invite');
});

test('an unregistered key can reach redeem and nothing else', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const ghost = broker.stranger('ghost');
  for (const [method, p, body] of [
    ['POST', '/v1/invites', {}],
    ['GET', '/v1/inbox', undefined],
    ['GET', '/v1/peers', undefined],
    ['GET', '/v1/threads', undefined],
  ]) {
    const res = await signedApi(broker.baseUrl, ghost, method, p, body);
    assert.equal(res.status, 401, `${method} ${p}`);
    assert.equal(res.body.error, 'unknown_key');
  }
});

test('a revoked issuer cannot have their old invites redeemed', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.stranger('bob');

  const { body: minted } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/invites', {});
  broker.registry.revokeKey(alice.fingerprint);

  const res = await signedApi(broker.baseUrl, bob, 'POST', '/v1/invites/redeem', {
    code: minted.code, label: 'bob',
  });
  assert.equal(res.status, 409);
  assert.equal(res.body.error, 'issuer_revoked');
});

// CHANGE 2: task 5's review found that verify.mjs's single `if
// (!allowUnregistered)` block skips revoked-key detection on the redeem route
// along with unknown-key detection, since redeem is the one caller passing
// allowUnregistered: true. Not exploitable (registerKey returns the existing
// revoked record unchanged, so the redeemer ends up with a link but stays
// rejected everywhere else), but it lets a revoked key burn someone else's
// invite and leave a dead link behind. The route must reject a revoked caller
// itself, before consuming the invite.
test('a revoked caller cannot redeem, and the invite survives the attempt', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob'); // registered, then revoked
  broker.registry.revokeKey(bob.fingerprint);

  const { body: minted } = await signedApi(broker.baseUrl, alice, 'POST', '/v1/invites', {});

  const res = await signedApi(broker.baseUrl, bob, 'POST', '/v1/invites/redeem', {
    code: minted.code, label: 'bob',
  });
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'revoked_key');

  const stored = broker.registry.getInviteByCode(minted.code);
  assert.equal(stored.status, 'open', "a revoked caller must not burn someone else's invite");
});

// CHANGE 1: the brief's bootstrap design registered a pseudo-identity with an
// all-zero Ed25519 public key purely so the invite record had an issuer. That
// key encodes to a valid low-order curve point Node imports without
// complaint — registering an identity nobody holds the private key for, in
// the registry that authorizes everything, is a standing risk for no
// benefit. Instead: a bootstrap invite has no issuer at all (issuer: null,
// bootstrap: true). Redeeming it registers the key and creates no link —
// there is nobody to link the first agent to — and the response says so
// rather than naming a peer.
test('bootstrap mints the owner a code without any existing identity', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());

  const out = execFileSync(process.execPath, [
    'server/bootstrap.mjs', '--data-dir', broker.dataDir, '--label', 'owner',
  ], { encoding: 'utf8' });

  const code = out.trim().split('\n').pop().trim();
  assert.match(code, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);

  const owner = broker.stranger('owner-machine');
  const res = await signedApi(broker.baseUrl, owner, 'POST', '/v1/invites/redeem', {
    code, label: 'owner-machine',
  });
  assert.equal(res.status, 201);
  assert.equal(res.body.bootstrap, true);
  assert.equal(res.body.agent.fingerprint, owner.fingerprint);
  assert.equal(res.body.agent.label, 'owner-machine');
  assert.equal(res.body.agent.short, shortFingerprint(owner.fingerprint));
  assert.equal('peer' in res.body, false, 'a bootstrap redeem must not claim a peer');
  assert.equal('link' in res.body, false, 'a bootstrap redeem must not claim a link');

  assert.equal(broker.registry.getKey(owner.fingerprint).label, 'owner-machine');
  assert.deepEqual(broker.registry.peersOf(owner.fingerprint), [], 'a bootstrap redeem creates no link');
});
