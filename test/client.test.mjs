import test from 'node:test';
import assert from 'node:assert/strict';
import { BrokerClient } from '../mcp/client.mjs';
import { startBroker } from './helpers.mjs';

test('the client signs every request it makes', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  broker.link(alice, bob);

  const client = new BrokerClient({ baseUrl: broker.baseUrl, identity: alice });

  const sent = await client.sendMessage({ to: bob.fingerprint, subject: 'hi', body: 'yo' });
  assert.equal(sent.from, alice.fingerprint);

  const bobClient = new BrokerClient({ baseUrl: broker.baseUrl, identity: bob });
  const { messages } = await bobClient.inbox();
  assert.equal(messages.length, 1);
  assert.equal(messages[0].body, 'yo');

  await bobClient.ackMessage(sent.id);
  assert.equal((await client.getMessage(sent.id)).status, 'read');
});

test('a GET with query parameters still verifies', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const client = new BrokerClient({ baseUrl: broker.baseUrl, identity: alice });
  const { threads } = await client.listThreads();
  assert.deepEqual(threads, []);
});

test('a binary upload is signed over its bytes', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const bob = broker.identity('bob');
  broker.link(alice, bob);

  const a = new BrokerClient({ baseUrl: broker.baseUrl, identity: alice });
  const b = new BrokerClient({ baseUrl: broker.baseUrl, identity: bob });
  const payload = Buffer.from('x'.repeat(70000));

  const offer = await a.createOffer({
    to: bob.fingerprint, subject: 'big', sizeBytes: payload.length, contentType: 'text/plain',
  });
  await b.respondOffer({ offerId: offer.id, accept: true });
  const { message } = await a.uploadOffer({ offerId: offer.id, buffer: payload, contentType: 'text/plain' });
  assert.deepEqual(await b.getPayload(message.id), payload);
});

test('an unreachable broker still fails with a clear code, not a stack trace', async (t) => {
  const broker = await startBroker();
  t.after(() => broker.stop());
  const alice = broker.identity('alice');
  const orphan = new BrokerClient({ baseUrl: 'http://127.0.0.1:1', identity: alice });
  await assert.rejects(orphan.inbox(), (e) => e.code === 'broker_unreachable');
});
