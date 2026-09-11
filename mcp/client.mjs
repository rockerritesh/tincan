// Thin HTTP client for the broker. One place that knows the wire format.

import { signedHeaders } from './identity.mjs';

export class BrokerError extends Error {
  constructor(status, code, message) {
    super(`${code}: ${message}`);
    this.status = status;
    this.code = code;
  }
}

export class BrokerClient {
  constructor({ baseUrl, identity, token = null, timeoutMs = 20000 }) {
    if (!identity) throw new Error('BrokerClient needs an identity to sign with');
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.identity = identity;
    this.agentId = identity.fingerprint; // convenience for callers and logs
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  // Every request is signed here, so no call site can forget.
  async #request(method, pathname, { body, raw, contentType } = {}) {
    const url = new URL(`${this.baseUrl}${pathname}`);
    const headers = {};
    let payload;

    if (raw !== undefined) {
      payload = raw;
      headers['content-type'] = contentType ?? 'application/octet-stream';
    } else if (body !== undefined) {
      payload = JSON.stringify(body);
      headers['content-type'] = 'application/json';
    }

    if (this.token) headers.authorization = `Bearer ${this.token}`;
    Object.assign(headers, signedHeaders(this.identity, {
      method,
      pathname: url.pathname,
      searchParams: url.searchParams,
      body: payload,
    }));

    let res;
    try {
      res = await fetch(url, {
        method,
        headers,
        body: payload,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      throw new BrokerError(0, 'broker_unreachable', `${this.baseUrl} — ${err.message}`);
    }

    const isJson = (res.headers.get('content-type') ?? '').includes('application/json');
    if (!res.ok) {
      const detail = isJson ? await res.json().catch(() => ({})) : {};
      throw new BrokerError(res.status, detail.error ?? 'http_error', detail.message ?? res.statusText);
    }
    if (!isJson) return Buffer.from(await res.arrayBuffer());
    return res.json();
  }

  health() {
    return this.#request('GET', '/v1/health');
  }

  sendMessage({ to, subject, body, contentType, threadId, replyTo }) {
    return this.#request('POST', '/v1/messages', {
      body: {
        to, subject, body,
        content_type: contentType,
        thread_id: threadId,
        reply_to: replyTo,
      },
    });
  }

  getMessage(id) {
    return this.#request('GET', `/v1/messages/${encodeURIComponent(id)}`);
  }

  ackMessage(id) {
    return this.#request('POST', `/v1/messages/${encodeURIComponent(id)}/ack`, { body: {} });
  }

  getPayload(id) {
    return this.#request('GET', `/v1/messages/${encodeURIComponent(id)}/payload`);
  }

  inbox() {
    return this.#request('GET', '/v1/inbox');
  }

  createOffer({ to, subject, sizeBytes, contentType, threadId, replyTo }) {
    return this.#request('POST', '/v1/offers', {
      body: {
        to, subject,
        size_bytes: sizeBytes,
        content_type: contentType,
        thread_id: threadId,
        reply_to: replyTo,
      },
    });
  }

  offers() {
    return this.#request('GET', '/v1/offers');
  }

  respondOffer({ offerId, accept, reason }) {
    return this.#request('POST', `/v1/offers/${encodeURIComponent(offerId)}/respond`, {
      body: { accept, reason },
    });
  }

  uploadOffer({ offerId, buffer, contentType }) {
    return this.#request('PUT', `/v1/offers/${encodeURIComponent(offerId)}/payload`, {
      raw: buffer,
      contentType,
    });
  }

  closeOffer(offerId) {
    return this.#request('POST', `/v1/offers/${encodeURIComponent(offerId)}/close`, { body: {} });
  }

  listThreads() {
    return this.#request('GET', '/v1/threads');
  }

  readThread(threadId) {
    return this.#request('GET', `/v1/threads/${encodeURIComponent(threadId)}`);
  }

  createInvite({ ttlMs } = {}) {
    return this.#request('POST', '/v1/invites', { body: ttlMs ? { ttl_ms: ttlMs } : {} });
  }

  redeemInvite({ code, label }) {
    return this.#request('POST', '/v1/invites/redeem', { body: { code, label } });
  }

  peers() {
    return this.#request('GET', '/v1/peers');
  }

  revokePeer(fingerprint) {
    return this.#request('POST', `/v1/peers/${encodeURIComponent(fingerprint)}/revoke`, { body: {} });
  }
}
