#!/usr/bin/env node
// MCP stdio server. Identical on both machines; only AGENT_LABEL and
// BROKER_URL differ. Uses the low-level SDK Server with plain JSON Schema so
// the tool surface does not depend on a validator version.
//
// The label is a display name, not a credential: this agent's identity is the
// keypair under its home directory, and the broker derives who is calling from
// the signature on every request.

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { AgentLink } from './agent.mjs';

// AGENT_ID is still accepted so an existing registration keeps working, but
// AGENT_LABEL is the name and the one the error message teaches.
const AGENT_LABEL = process.env.AGENT_LABEL ?? process.env.AGENT_ID;
const BROKER_URL = process.env.BROKER_URL ?? 'http://127.0.0.1:8787';
const BROKER_TOKEN = process.env.BROKER_TOKEN ?? null;

if (!AGENT_LABEL) {
  console.error('tincan: AGENT_LABEL env var is required (e.g. AGENT_LABEL=my-laptop)');
  process.exit(1);
}

const link = new AgentLink({ baseUrl: BROKER_URL, label: AGENT_LABEL, token: BROKER_TOKEN });

const TOOLS = [
  {
    name: 'check_inbox',
    description:
      'Monitor tick, and the only place four kinds of news arrive: new messages addressed to this agent, ' +
      'transfer offers waiting on this agent to accept or reject, updates on offers this agent sent ' +
      '(accepted payloads upload during this call), and peer events in `peer_events` — agents newly ' +
      'connected to this one, under the local alias assigned here, and connections that have been revoked ' +
      'by either side. Call on an interval to stay in sync with the other agent. `quiet: true` means all ' +
      'four were empty.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    handler: () => link.checkInbox(),
  },
  {
    name: 'send_message',
    description:
      'Send a message to another agent. Payload size is handled automatically: anything under 64KB goes ' +
      'straight through, anything larger is offered to the recipient first and uploads only once they accept.',
    inputSchema: {
      type: 'object',
      properties: {
        to: { type: 'string', description: 'Recipient alias from list_peers, e.g. "bob".' },
        subject: { type: 'string', description: 'Short one-line summary of what this message is.' },
        body: { type: 'string', description: 'Message content.' },
        content_type: { type: 'string', description: 'MIME type of the body. Defaults to text/plain.' },
        thread_id: { type: 'string', description: 'Continue an existing thread. Omit to start a new one.' },
        reply_to: { type: 'string', description: 'Message id being replied to; inherits that thread.' },
      },
      required: ['to', 'subject', 'body'],
      additionalProperties: false,
    },
    handler: (a) =>
      link.send({
        to: a.to,
        subject: a.subject,
        body: a.body,
        contentType: a.content_type,
        threadId: a.thread_id,
        replyTo: a.reply_to,
      }),
  },
  {
    name: 'ack_message',
    description:
      'Mark a message as read once it has been processed. This is the read receipt the sender sees, and it ' +
      'removes the message from this inbox. Unacked messages are redelivered on every check_inbox.',
    inputSchema: {
      type: 'object',
      properties: { message_id: { type: 'string' } },
      required: ['message_id'],
      additionalProperties: false,
    },
    handler: (a) => link.ack(a.message_id),
  },
  {
    name: 'respond_offer',
    description:
      'Accept or reject an incoming large-payload transfer offer surfaced by check_inbox. Nothing is ' +
      'transferred until accepted.',
    inputSchema: {
      type: 'object',
      properties: {
        offer_id: { type: 'string' },
        accept: { type: 'boolean' },
        reason: { type: 'string', description: 'Optional explanation, most useful when rejecting.' },
      },
      required: ['offer_id', 'accept'],
      additionalProperties: false,
    },
    handler: (a) => link.respondOffer({ offerId: a.offer_id, accept: a.accept, reason: a.reason ?? null }),
  },
  {
    name: 'fetch_payload',
    description:
      'Retrieve the payload of a large message. Small text payloads come back inline; anything else is ' +
      'written to disk and the path returned.',
    inputSchema: {
      type: 'object',
      properties: {
        message_id: { type: 'string' },
        inline: { type: 'boolean', description: 'Force inline (true) or force save-to-disk (false).' },
      },
      required: ['message_id'],
      additionalProperties: false,
    },
    handler: (a) => link.fetchPayload(a.message_id, { inline: a.inline ?? null }),
  },
  {
    name: 'message_status',
    description: 'Check whether a sent message is still queued, has been delivered, or has been read.',
    inputSchema: {
      type: 'object',
      properties: { message_id: { type: 'string' } },
      required: ['message_id'],
      additionalProperties: false,
    },
    handler: (a) => link.status(a.message_id),
  },
  {
    name: 'list_threads',
    description: 'List conversation threads this agent takes part in, most recently active first.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    handler: () => link.listThreads(),
  },
  {
    name: 'read_thread',
    description:
      'Read the full append-only history of one thread: every send, delivery, read receipt, offer and ' +
      'transfer, in order. Nothing is ever removed from a thread.',
    inputSchema: {
      type: 'object',
      properties: { thread_id: { type: 'string' } },
      required: ['thread_id'],
      additionalProperties: false,
    },
    handler: (a) => link.readThread(a.thread_id),
  },
  {
    name: 'broker_health',
    description:
      "Confirm the broker is reachable and report this agent's identity, the broker URL, and its version.",
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    handler: () => link.identity(),
  },
  {
    name: 'my_identity',
    description:
      "This agent's cryptographic identity: its label, its full fingerprint, and the short form to read "
      + 'aloud so a peer can verify you. Also reports whether the broker is reachable.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    handler: () => link.identity(),
  },
  {
    name: 'create_invite',
    description:
      'Mint a single-use code that lets one other agent connect to this one. Send it over a channel you '
      + 'already trust. The code is shown once and cannot be recovered; it expires in 15 minutes by default.',
    inputSchema: {
      type: 'object',
      properties: {
        ttl_minutes: { type: 'integer', description: 'Minutes until the code expires. Defaults to 15.' },
      },
      additionalProperties: false,
    },
    handler: (a) => link.createInvite({ ttlMinutes: a.ttl_minutes }),
  },
  {
    name: 'redeem_invite',
    description:
      'Connect to another agent using a code they gave you. Works even though this agent is unknown to '
      + 'their broker — the code is the introduction.',
    inputSchema: {
      type: 'object',
      properties: { code: { type: 'string', description: 'The invite code, dashes optional.' } },
      required: ['code'],
      additionalProperties: false,
    },
    handler: (a) => link.redeemInvite({ code: a.code }),
  },
  {
    name: 'list_peers',
    description:
      'Agents this one is connected to: local alias, short fingerprint, whether it has been verified out '
      + 'of band, and whether the connection is active or revoked. A peer the broker already knows but '
      + 'this machine has not named yet is listed with `pending: true` under a placeholder alias; run '
      + 'check_inbox to give it a real one before addressing it.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    handler: () => link.listPeers(),
  },
  {
    name: 'verify_peer',
    description:
      "Confirm a peer's identity by comparing the short fingerprint they read to you over a separate "
      + 'channel. Protects against a substituted key at pairing time. Refuses on a mismatch.',
    inputSchema: {
      type: 'object',
      properties: {
        alias: { type: 'string' },
        fingerprint: { type: 'string', description: 'The short form they gave you, e.g. 4K7M-2XQ9-VB3N.' },
      },
      required: ['alias', 'fingerprint'],
      additionalProperties: false,
    },
    handler: (a) => link.verifyPeer({ alias: a.alias, fingerprint: a.fingerprint }),
  },
  {
    name: 'disconnect_peer',
    description:
      'Revoke a connection. Blocks messages in both directions immediately. Your copy of the existing '
      + 'conversation history is kept and stays readable.',
    inputSchema: {
      type: 'object',
      properties: { alias: { type: 'string' } },
      required: ['alias'],
      additionalProperties: false,
    },
    handler: (a) => link.disconnectPeer({ alias: a.alias }),
  },
];

const byName = new Map(TOOLS.map((t) => [t.name, t]));

const server = new Server(
  { name: 'tincan', version: '0.2.0' },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const tool = byName.get(request.params.name);
  if (!tool) {
    return { isError: true, content: [{ type: 'text', text: `Unknown tool: ${request.params.name}` }] };
  }
  try {
    const result = await tool.handler(request.params.arguments ?? {});
    return { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] };
  } catch (err) {
    return {
      isError: true,
      content: [{ type: 'text', text: JSON.stringify({ error: err.code ?? 'error', message: err.message }, null, 2) }],
    };
  }
});

await server.connect(new StdioServerTransport());
console.error(`tincan: ${AGENT_LABEL} (${link.identityRecord.short}) connected to ${BROKER_URL}`);
