// test/mcp.test.mjs — replace the placeholder
// Drives mcp/server.mjs as a subprocess over stdio, the way Claude Code does.
// Catches protocol and schema mistakes the in-process tests cannot.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { startBroker, tempDir } from './helpers.mjs';

const SERVER = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'mcp', 'server.mjs');

async function connect(label, baseUrl, home) {
  const client = new Client({ name: 'test-harness', version: '0.0.0' }, { capabilities: {} });
  await client.connect(new StdioClientTransport({
    command: process.execPath,
    args: [SERVER],
    env: { ...process.env, AGENT_LABEL: label, BROKER_URL: baseUrl, TINCAN_HOME: home },
    stderr: 'ignore',
  }));
  return client;
}

function unwrap(result) {
  assert.equal(result.isError ?? false, false, JSON.stringify(result.content));
  return JSON.parse(result.content[0].text);
}

test('two MCP servers pair, talk, and disconnect', async (t) => {
  const broker = await startBroker();
  const homeA = tempDir('mcp-a');
  const homeB = tempDir('mcp-b');

  const alice = await connect('alice', broker.baseUrl, homeA);
  const bob = await connect('bob', broker.baseUrl, homeB);
  t.after(async () => {
    await alice.close();
    await bob.close();
    for (const h of [homeA, homeB]) fs.rmSync(h, { recursive: true, force: true });
    await broker.stop();
  });

  // The tool surface is the contract; assert it exactly.
  const { tools } = await alice.listTools();
  assert.deepEqual(tools.map((x) => x.name).sort(), [
    'ack_message',
    'broker_health',
    'check_inbox',
    'create_invite',
    'disconnect_peer',
    'fetch_payload',
    'list_peers',
    'list_threads',
    'message_status',
    'my_identity',
    'read_thread',
    'redeem_invite',
    'respond_offer',
    'send_message',
    'verify_peer',
  ]);
  assert.equal(tools.some((x) => x.name === 'list_agents'), false, 'removed in 0.2.0');
  for (const tool of tools) {
    assert.ok(tool.description?.length > 20, `${tool.name} needs a usable description`);
    assert.equal(tool.inputSchema.type, 'object');
  }

  const me = unwrap(await alice.callTool({ name: 'my_identity', arguments: {} }));
  assert.match(me.fingerprint, /^tc1[0-9a-hjkmnp-tv-z]{26}$/);

  // Alice needs to exist on the broker before she can invite.
  broker.registry.registerKey({
    fingerprint: me.fingerprint,
    publicKeyB64: JSON.parse(fs.readFileSync(path.join(homeA, 'identity.json'), 'utf8')).public_key,
    label: 'alice',
    via: 'test',
  });

  const invite = unwrap(await alice.callTool({ name: 'create_invite', arguments: {} }));
  assert.match(invite.code, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);

  const joined = unwrap(await bob.callTool({
    name: 'redeem_invite', arguments: { code: invite.code },
  }));
  assert.equal(joined.alias, 'alice');

  unwrap(await alice.callTool({ name: 'check_inbox', arguments: {} }));
  const peers = unwrap(await alice.callTool({ name: 'list_peers', arguments: {} }));
  assert.deepEqual(peers.peers.map((p) => p.alias), ['bob']);
  assert.equal(peers.peers[0].verified, false);

  const verified = unwrap(await alice.callTool({
    name: 'verify_peer', arguments: { alias: 'bob', fingerprint: peers.peers[0].short ?? joined.short },
  }));
  assert.equal(verified.verified, true);

  const sent = unwrap(await alice.callTool({
    name: 'send_message', arguments: { to: 'bob', subject: 'hello over MCP', body: 'it works' },
  }));
  assert.equal(sent.mode, 'inline');

  const tick = unwrap(await bob.callTool({ name: 'check_inbox', arguments: {} }));
  assert.equal(tick.messages[0].body, 'it works');
  assert.equal(tick.messages[0].from_alias, 'alice');

  unwrap(await bob.callTool({ name: 'ack_message', arguments: { message_id: sent.message_id } }));
  const status = unwrap(await alice.callTool({
    name: 'message_status', arguments: { message_id: sent.message_id },
  }));
  assert.equal(status.status, 'read');

  const gone = unwrap(await alice.callTool({ name: 'disconnect_peer', arguments: { alias: 'bob' } }));
  assert.equal(gone.status, 'revoked');

  const blocked = await alice.callTool({
    name: 'send_message', arguments: { to: 'bob', subject: 'after', body: 'x' },
  });
  assert.equal(blocked.isError, true);
  assert.match(blocked.content[0].text, /revoked/i);
});

test('a tool error is an MCP error result, not a crash', async (t) => {
  const broker = await startBroker();
  const home = tempDir('mcp-err');
  const alice = await connect('alice', broker.baseUrl, home);
  t.after(async () => {
    await alice.close();
    fs.rmSync(home, { recursive: true, force: true });
    await broker.stop();
  });

  const bad = await alice.callTool({ name: 'send_message', arguments: { to: 'nobody', subject: 'x', body: 'y' } });
  assert.equal(bad.isError, true);
  assert.match(bad.content[0].text, /no peer called/);

  const alive = unwrap(await alice.callTool({ name: 'my_identity', arguments: {} }));
  assert.ok(alive.fingerprint, 'the server survived');
});
