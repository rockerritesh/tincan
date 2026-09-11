// End-to-end through the agent-facing layer: two AgentLinks, each with its own
// home directory and keypair, paired through a real invite and talking over a
// real broker. This is the suite that proves an agent can actually use the
// trust model — identity, pairing, aliases, transfers and disconnection.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { AgentLink } from '../mcp/agent.mjs';
import { MAX_INLINE_BYTES } from '../shared/limits.mjs';
import { startBroker, tempDir } from './helpers.mjs';

// Two AgentLinks, each with its own home, paired through a real invite.
async function pairedAgents(t) {
  const broker = await startBroker();
  const homeA = tempDir('home-a');
  const homeB = tempDir('home-b');
  t.after(() => {
    fs.rmSync(homeA, { recursive: true, force: true });
    fs.rmSync(homeB, { recursive: true, force: true });
    return broker.stop();
  });

  const alice = new AgentLink({ baseUrl: broker.baseUrl, label: 'alice', home: homeA });
  const bob = new AgentLink({ baseUrl: broker.baseUrl, label: 'bob', home: homeB });

  // Alice must exist on the broker before she can mint. Bootstrap her directly.
  broker.registry.registerKey({
    fingerprint: alice.identityRecord.fingerprint,
    publicKeyB64: alice.identityRecord.publicKeyB64,
    label: 'alice',
    via: 'test',
  });

  const { code } = await alice.createInvite({});
  await bob.redeemInvite({ code });
  await alice.checkInbox();   // lets alice's peer book learn about bob
  return { broker, alice, bob };
}

test('pairing gives each side a usable alias for the other', async (t) => {
  const { alice, bob } = await pairedAgents(t);

  assert.deepEqual((await alice.listPeers()).peers.map((p) => p.alias), ['bob']);
  assert.deepEqual((await bob.listPeers()).peers.map((p) => p.alias), ['alice']);

  const me = await alice.identity();
  assert.equal(me.label, 'alice');
  assert.match(me.short, /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/);
  assert.equal(me.broker_reachable, true);
});

test('messages are addressed by alias and the receipt still works', async (t) => {
  const { alice, bob } = await pairedAgents(t);

  const sent = await alice.send({ to: 'bob', subject: 'ping', body: 'are you there?' });
  assert.equal(sent.mode, 'inline');

  const tick = await bob.checkInbox();
  assert.equal(tick.messages.length, 1);
  assert.equal(tick.messages[0].from_alias, 'alice');
  assert.equal(tick.messages[0].body, 'are you there?');

  await bob.ack(sent.message_id);
  assert.equal((await alice.status(sent.message_id)).status, 'read');
});

test('sending to an unknown alias fails locally, before any request', async (t) => {
  const { alice } = await pairedAgents(t);
  await assert.rejects(
    alice.send({ to: 'stranger', subject: 'x', body: 'y' }),
    /no peer called "stranger"/,
  );
});

test('a new peer shows up as a peer_linked event on the next tick', async (t) => {
  const { broker, alice } = await pairedAgents(t);
  const homeC = tempDir('home-c');
  t.after(() => fs.rmSync(homeC, { recursive: true, force: true }));

  const carol = new AgentLink({ baseUrl: broker.baseUrl, label: 'carol', home: homeC });
  const { code } = await alice.createInvite({});
  await carol.redeemInvite({ code });

  const tick = await alice.checkInbox();
  assert.equal(tick.peer_events.linked.length, 1);
  assert.equal(tick.peer_events.linked[0].alias, 'carol');
  assert.ok(tick.peer_events.linked[0].short);
});

// list_peers must be able to answer "did my pairing work?" without stealing the
// event check_inbox owes the monitor loop. The ordering is the whole test:
// listing first, then ticking, and the event still has to arrive.
test('list_peers previews a new peer without consuming its peer_linked event', async (t) => {
  const { broker, alice } = await pairedAgents(t);
  const homeC = tempDir('home-c');
  t.after(() => fs.rmSync(homeC, { recursive: true, force: true }));

  const carol = new AgentLink({ baseUrl: broker.baseUrl, label: 'carol', home: homeC });
  const { code } = await alice.createInvite({});
  await carol.redeemInvite({ code });

  const listed = await alice.listPeers();
  const preview = listed.peers.find((p) => p.fingerprint === carol.identityRecord.fingerprint);
  assert.equal(preview.pending, true);
  assert.equal(preview.status, 'active');
  // Previewed under its short fingerprint, not its advertised label: the real
  // alias is only decided when check_inbox reserves it.
  assert.equal(preview.alias, carol.identityRecord.short);
  assert.equal(preview.advertised_label, 'carol');

  const tick = await alice.checkInbox();
  assert.equal(tick.peer_events.linked.length, 1);
  assert.equal(tick.peer_events.linked[0].alias, 'carol');

  const after = await alice.listPeers();
  const row = after.peers.find((p) => p.alias === 'carol');
  assert.equal(row.pending, false);
  assert.equal(row.fingerprint, carol.identityRecord.fingerprint);
  assert.equal(after.peers.filter((p) => p.pending).length, 0);
});

test('verify_peer confirms a matching fingerprint and rejects a wrong one', async (t) => {
  const { alice, bob } = await pairedAgents(t);
  const bobShort = (await bob.identity()).short;

  await assert.rejects(
    alice.verifyPeer({ alias: 'bob', fingerprint: 'AAAA-BBBB-CCCC' }),
    /does not match/i,
  );
  const ok = await alice.verifyPeer({ alias: 'bob', fingerprint: bobShort });
  assert.equal(ok.verified, true);
  assert.equal((await alice.listPeers()).peers[0].verified, true);
});

test('the large-payload handshake still rides the monitor tick', async (t) => {
  const { alice, bob } = await pairedAgents(t);
  const big = 'row,value\n'.repeat(10000);
  assert.ok(Buffer.byteLength(big) > MAX_INLINE_BYTES);

  const offered = await alice.send({ to: 'bob', subject: 'dataset', body: big, contentType: 'text/csv' });
  assert.equal(offered.mode, 'offer');

  const before = await bob.checkInbox();
  assert.equal(before.messages.length, 0);
  assert.equal(before.offers_awaiting_response.length, 1);
  assert.equal(before.offers_awaiting_response[0].from_alias, 'alice');

  await bob.respondOffer({ offerId: offered.offer_id, accept: true });

  const uploaded = await alice.checkInbox();
  assert.equal(uploaded.outbox_updates[0].status, 'sent');

  const after = await bob.checkInbox();
  const got = await bob.fetchPayload(after.messages[0].message_id, { inline: true });
  assert.equal(got.body, big);
});

// The first agent on a fresh broker redeems a code that has no issuer, so the
// response names no peer. Reading peer.fingerprint unconditionally would throw
// on the very first thing a new owner does.
test('redeeming a bootstrap invite registers this agent and links nobody', async (t) => {
  const broker = await startBroker();
  const home = tempDir('home-first');
  t.after(() => {
    fs.rmSync(home, { recursive: true, force: true });
    return broker.stop();
  });

  const first = new AgentLink({ baseUrl: broker.baseUrl, label: 'first', home });
  const { code } = broker.registry.createInvite({ bootstrap: true });

  const result = await first.redeemInvite({ code });
  assert.equal(result.bootstrap, true);
  assert.equal(result.fingerprint, first.identityRecord.fingerprint);
  assert.equal(result.short, first.identityRecord.short);
  assert.deepEqual((await first.listPeers()).peers, []);

  // Registered, so the signed routes now answer.
  assert.equal((await first.checkInbox()).quiet, true);
});

test('disconnecting stops traffic and surfaces on both sides', async (t) => {
  const { alice, bob } = await pairedAgents(t);

  const gone = await alice.disconnectPeer({ alias: 'bob' });
  assert.equal(gone.status, 'revoked');

  await assert.rejects(alice.send({ to: 'bob', subject: 'x', body: 'y' }), /revoked/i);

  const tick = await bob.checkInbox();
  assert.equal(tick.peer_events.revoked.length, 1);
  assert.equal(tick.peer_events.revoked[0].alias, 'alice');
});
