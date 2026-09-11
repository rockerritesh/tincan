#!/usr/bin/env node
// server/bootstrap.mjs
// The owner's key has no invite to redeem, and trust-on-first-use would be a
// race anyone who found the URL could win. So the installer mints one invite
// from the filesystem side, where it already has privileged access, and the
// owner redeems it through the ordinary route. No special case in the request
// path, no open window.
//
// This invite has no issuer. On a brand-new broker there is no identity to
// issue it from, and inventing one — even a pseudo-key nobody holds the
// private half of — would be a standing entry in the registry that
// authorizes everything, for no benefit: it exists only because the data
// model could not otherwise express "an invite with no issuer." Registry
// now can, via createInvite({ bootstrap: true }): the invite record carries
// issuer: null, and redeeming it (server/broker.mjs) registers the key and
// creates no link, rather than linking the first agent to a broker that is
// not itself an agent.

import path from 'node:path';
import { Registry } from './registry.mjs';

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? fallback : process.argv[i + 1];
}

const dataDir = path.resolve(arg('data-dir', process.env.DATA_DIR ?? path.join(process.cwd(), 'data')));
// --label is a note-to-self on this output only. A bootstrap invite carries no
// issuer and no intended recipient, and the label that actually lands in the
// registry is the one the redeemer sends with POST /v1/invites/redeem. Keeping
// the flag (rather than dropping it) is what lets an installer that mints
// several codes tell its own output apart; the printed line says so plainly so
// nobody reads it as "this code only works for that agent".
const label = arg('label', 'owner');
const ttlMinutes = Number(arg('ttl-minutes', '60'));

const registry = new Registry(dataDir);

const { invite, code } = registry.createInvite({
  bootstrap: true,
  ttlMs: ttlMinutes * 60 * 1000,
});

console.log(`tincan bootstrap invite — your note: "${label}"`);
console.log(`data dir : ${registry.root}`);
console.log(`expires  : ${invite.expires_at}`);
console.log('');
console.log('Note: --label only labels this printout. The code is not bound to any agent,');
console.log('and the label recorded in the registry is the one the redeemer sends.');
console.log('');
console.log('Redeem it on the machine that will own this broker, then delete this output.');
console.log('');
console.log(code);
