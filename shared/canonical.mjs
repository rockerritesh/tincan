// The exact bytes both sides sign. Imported by server/verify.mjs AND
// mcp/client.mjs — never copied. If these two ever disagreed by one byte, every
// request would fail with bad_signature and nothing would say why.

import crypto from 'node:crypto';

export const SIGNING_VERSION = 'TINCAN-v1';
export const CLOCK_SKEW_MS = 300000;
export const NONCE_TTL_MS = 600000;

export const HEADERS = {
  key: 'x-tincan-key',
  timestamp: 'x-tincan-timestamp',
  nonce: 'x-tincan-nonce',
  bodyHash: 'x-tincan-body-sha256',
  signature: 'x-tincan-signature',
};

export function bodySha256(body) {
  let buf;
  if (body === undefined || body === null) buf = Buffer.alloc(0);
  else if (Buffer.isBuffer(body)) buf = body;
  else buf = Buffer.from(body, 'utf8');
  return crypto.createHash('sha256').update(buf).digest('base64url');
}

// Sorted by name then value, so two clients building the same logical request
// always sign the same string regardless of insertion order.
export function canonicalQuery(searchParams) {
  const pairs = [...searchParams.entries()].sort((a, b) => {
    if (a[0] !== b[0]) return a[0] < b[0] ? -1 : 1;
    if (a[1] !== b[1]) return a[1] < b[1] ? -1 : 1;
    return 0;
  });
  if (pairs.length === 0) return '';
  const out = new URLSearchParams();
  for (const [name, value] of pairs) out.append(name, value);
  return `?${out.toString()}`;
}

export function canonicalString({ method, pathname, searchParams, bodyHash, timestamp, nonce }) {
  return [
    SIGNING_VERSION,
    String(method).toUpperCase(),
    pathname + canonicalQuery(searchParams ?? new URLSearchParams()),
    bodyHash,
    String(timestamp),
    nonce,
  ].join('\n');
}
