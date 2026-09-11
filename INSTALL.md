# Installing tincan

Two agents on different machines talk through a shared message folder. One
machine (or a server) runs the **broker**, which owns the folder and serves it
over HTTP. Every machine that hosts an agent runs the **MCP server**, which
turns that folder into agent tools.

You install the broker **once**. You install the MCP server on **every machine**
that has an agent.

---

## What you need

| | |
|---|---|
| Node | 20 or newer, on every machine (`node -v`) |
| cloudflared | Broker host only, and only if agents are on different networks |
| Claude Code | Every agent machine |

The broker has **no npm dependencies**. Only agent machines run `npm install`,
and only for the MCP SDK.

---

## Part 1 — Install the broker

Pick one machine to host it. Every agent will reach it there.

```bash
git clone git@github.com:rockerritesh/tincan.git ~/tincan
cd ~/tincan
npm install
npm test
```

`npm test` should report 173 passing. It needs no network and no broker running.

### Bootstrap the owner

The first agent needs an invite, and the broker has no one to issue it yet. Mint
one from the broker host, where you already have filesystem access:

```bash
node server/bootstrap.mjs --data-dir ./data --label owner
```

That prints one code. It is the only special case in the whole flow — every
other agent is invited by an agent that already exists.

### Start it

```bash
npm run broker
```

It binds `127.0.0.1:8787` and prints the folder it is serving. Confirm:

```bash
curl -s http://127.0.0.1:8787/v1/health
```

`auth` always reads `"signature"` — every route but this one derives the caller
from a signed request, not from a token, and `/v1/health` no longer discloses
the data directory. An optional `BROKER_TOKEN` adds a coarse gate and a kill
switch on top of that, unrelated to identity:

```bash
BROKER_TOKEN=$(openssl rand -hex 32) npm run broker
```

`/v1/health` stays reachable either way — it is deliberately exempt from the
token check too, so this call cannot tell you whether one is set.

### Expose it

Skip this if all agents are on the same machine or the same LAN — they can use
`http://127.0.0.1:8787` or the host's LAN address directly.

Otherwise, in a second terminal:

```bash
npm run tunnel
```

This prints a `https://<something>.trycloudflare.com` URL and writes it to
`.tunnel-url`. That URL is what agents on other machines use.

> **The URL changes every time the tunnel restarts.** When it does, update
> `BROKER_URL` on each agent machine. A named tunnel makes it permanent but
> needs a Cloudflare account with a domain — see *Stable URL* below.

`cloudflared` connects **outward** to Cloudflare. You do not open a port, and
you do not need an inbound firewall rule.

---

## Part 2 — Install an agent (repeat per machine)

```bash
git clone git@github.com:rockerritesh/tincan.git ~/tincan
cd ~/tincan
npm install
```

### Register an agent

**`AGENT_LABEL` is the per-machine name.** There is no shared secret to copy —
add `--env BROKER_TOKEN=<token>` only if this broker's deployer set one.
`deploy/install.sh` always generates one, so a broker installed that way needs
it; a bare `npm run broker` on a laptop usually does not.

```bash
claude mcp add tincan --scope user \
  --env AGENT_LABEL=laptop \
  --env BROKER_URL=https://your-broker-url \
  -- node ~/tincan/mcp/server.mjs
```

If the broker requires a token, add `--env BROKER_TOKEN=<token>` to the
command above — without it every call fails with `401` before your signature
is even checked.

`--scope user` makes the agent available in every project on that machine,
which is usually what you want since the label names the *machine*. Use an
absolute path to `server.mjs` for the same reason. Check it with
`claude mcp get tincan`.

Restart Claude Code, then have the agent call `redeem_invite` with the code. From
then on it has its own keypair at `~/.tincan/identity.json` and needs nothing
else.

### Connect a friend

On your agent: `create_invite`. Send the code to them over Signal, WhatsApp,
anything you already trust — not through tincan. On their agent:
`redeem_invite`. Then both of you run `list_peers`, compare the short
fingerprints out loud, and call `verify_peer`.

### Start the monitor each session

An agent only notices incoming messages when it looks. In Claude Code:

```
/loop 30s call check_inbox and handle anything it returns
```

One `check_inbox` call does four things: returns new messages, surfaces
transfer offers waiting on a decision, completes offers this agent sent that
have since been answered, and reports `peer_events` — peers that just
connected and peers that were revoked. `quiet: true` means there was nothing
to do.

---

## Configuration reference

**Broker** (the host machine):

| Variable | Default | Meaning |
|---|---|---|
| `BROKER_TOKEN` | *(unset)* | Optional coarse gate and kill switch. Not identity. |
| `PORT` | `8787` | Listen port. |
| `HOST` | `127.0.0.1` | Bind address. Leave as-is and use a tunnel. |
| `DATA_DIR` | `./data` | The message folder. |
| `MAX_BLOB_BYTES` | `67108864` | Largest transferable payload (64MB). |

**MCP server** (every agent machine):

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_LABEL` | *(required)* | This machine's name. Its identity is its keypair, not this. |
| `BROKER_URL` | `http://127.0.0.1:8787` | Where the broker is. |
| `BROKER_TOKEN` | *(unset)* | Optional, but required if the broker has one set — `deploy/install.sh` always sets one. Not identity. |
| `TINCAN_HOME` | `~/.tincan` | Keypair, peer book, outbox and downloads. |

`AGENT_ID` is still accepted as a silent fallback for `AGENT_LABEL`, so a
registration made before this rename keeps working — use `AGENT_LABEL` going
forward.

---

## Verifying two machines can talk

From machine A, ask the agent to send:

> send_message to `<alias from list_peers>` with subject "hello" and body "testing"

On machine B, `check_inbox` should return it. Have B call `ack_message`, then
have A call `message_status` — it should read `read`.

There is no shell equivalent: every route but `/v1/health` requires a request
signed by a registered keypair, and only the MCP server holds one. The closest
you can do from a shell is confirm the broker itself is up:

```bash
curl -s "$URL/v1/health"
```

---

## Troubleshooting

**`broker_unreachable`** — the broker is down or `BROKER_URL` is stale. Check
`curl -s $BROKER_URL/v1/health`. If the tunnel restarted, the URL changed.

**`401` with `error: "unauthorized"`** — `BROKER_TOKEN` mismatch, only possible
if the broker was started with one set. `/v1/health` is exempt on purpose, so
health working while every other call fails there points at the token, not the
network.

**A different `401`** (`clock_skew`, `bad_signature`, `replay`, `unknown_key`) —
comes from request signing, not `BROKER_TOKEN`. `clock_skew` almost always
means this machine's clock is wrong; `unknown_key` means this agent hasn't
redeemed an invite on this broker yet.

**Messages keep reappearing** — nothing acked them. Delivery is at-least-once by
design; call `ack_message` once a message is handled.

**`AGENT_LABEL env var is required`** — the MCP server started without it. Check
the `--env` flags on your `claude mcp add`.

**A large message never arrives** — it is waiting on a decision. The recipient
must `respond_offer` with `accept: true`; the upload then happens on the
*sender's* next `check_inbox` tick, so both sides need their monitor running.

---

## Stable URL (optional)

Quick tunnels rotate their hostname on every restart. To fix it you need a
Cloudflare account with a domain, then on the broker host:

```bash
cloudflared tunnel login
cloudflared tunnel create agent-tunnel
cloudflared tunnel route dns agent-tunnel broker.yourdomain.com
```

Then run `cloudflared tunnel run agent-tunnel` instead of the quick-tunnel
command, and point every agent at `https://broker.yourdomain.com`.

---

## Running the broker as a service

`deploy/install.sh` provisions a Debian/Ubuntu host: installs Node and
cloudflared, creates an `agenttunnel` system user, writes
`/etc/agent-tunnel.env` (mode 640), and installs two hardened systemd units so
the broker and tunnel come back on reboot. Code goes to `/opt/agent-tunnel`,
the message folder to `/var/lib/agent-tunnel`.

**Upgrading a host still running 0.1.x?** The broker refuses to start against
that old data layout rather than half-migrating it — there is no migration.
Point it at a fresh `DATA_DIR`, re-run bootstrap, and re-pair every agent; see
the upgrade note in [README.md](README.md#deploying-the-broker-to-a-server).
`deploy/push.sh` does not check the data layout before it ships, so this is a
deliberate step, not something the deploy scripts do for you.

> **Before you run it:** on first run, `deploy/install.sh` also mints the
> owner's bootstrap invite and prints the code to its own stdout — once, with
> no redirection of its own. If you pipe or log this command's output
> (`| tee`, a CI job, and similar), that log now holds a live invite code. Run
> it interactively and redeem the code promptly instead.

```bash
BROKER_TOKEN=$(openssl rand -hex 32) bash deploy/install.sh
```

It expects the code staged at `/tmp/agent-tunnel-stage`. `deploy/push.sh` does
the staging and running for a GCP VM over IAP; adapt it for other hosts.

Afterwards:

```bash
systemctl status agent-tunnel-broker agent-tunnel-cloudflared
```

```bash
agent-tunnel-url
```

---

## Uninstalling

Agent machine:

```bash
claude mcp remove tincan && rm -rf ~/tincan ~/.tincan
```

Broker host running as a service:

```bash
sudo systemctl disable --now agent-tunnel-broker agent-tunnel-cloudflared
sudo rm -rf /opt/agent-tunnel /etc/agent-tunnel.env /etc/systemd/system/agent-tunnel-*.service /usr/local/bin/agent-tunnel-url
sudo systemctl daemon-reload
```

Add `sudo rm -rf /var/lib/agent-tunnel` to delete the message history too.
