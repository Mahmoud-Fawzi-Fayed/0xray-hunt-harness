---
name: hunt-race-condition
description: Hunting skill for race condition and TOCTOU vulnerabilities. Covers coupon and gift-card double-redeem, balance double-spend, quota bypass, email-change token mixups, and HTTP/2 single-packet / last-byte sync (Kettle, DEF CON 2023). Use when a one-time or limited action may apply twice under concurrency. Not for password, OTP, PIN, or other keyspace exhaustion.
sources: github, hackerone_public, portswigger_research, flatt_security
report_count: 12
---

# HUNT-RACE — TOCTOU / single-packet races

A race finding is a **state** that applied more than once (two redeems, two credits, two seats, a token bound to the wrong email). Two HTTP 200s are not the bug. Parallelism is how you prove a logic bug the single request hides. It is not a way to guess secrets.

## Decision tree

1. Find a one-shot or capped action: redeem, vote, transfer, withdraw, invite, trial, "create" under a quota, email/phone change, password-reset confirm, follow, claim.
2. Do it **once**. Record the object (balance, `times_redeemed`, vote count, order count).
3. Can the target speak HTTP/2? `curl -sI --http2 https://$TARGET | head -1`. If `HTTP/2`, use last-byte sync. If not, use parallel connections and expect a wider, less reliable window.
4. Send N≈20 **identical** requests so they are processed together (template below). N≈10 is the floor. Do not climb into thousands.
5. Re-read state. Success is `applied >= 2` when the rule says 1. Repeat until it reproduces on a majority of fresh attempts (aim 3/5). One fluke is not a report.
6. If naive parallel `curl` fails, that is **not** "patched". Retry with last-byte sync before you drop the endpoint.

Skip endpoints that are naturally idempotent (`PUT` of the same document with a server-side idempotency key you cannot omit). If omitting `Idempotency-Key` or reusing one key changes the result, that difference is the bug.

## Last-byte sync (HTTP/2)

One TCP connection, N streams. Send every request except the last byte, then flush the last bytes in a single write so the origin sees them in one scheduler turn. James Kettle, "Smashing the State Machine" (DEF CON 31, 2023). Turbo Intruder:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

`engine.queue` without the `gate` argument does **not** last-byte-sync; `openGate` then does nothing useful. HTTP/1.1 `curl &` and Repeater "send group" are a weaker first pass (millisecond spread). Use them to find a candidate, then confirm with the gate above. On HTTP/2, warm the connection with one throwaway request before queuing the batch so connection setup does not stagger the first streams (Turbo Intruder does this automatically; raw clients must do it explicitly).

No Burp: HTTP/1.1 last-byte sync. Weaker than one HTTP/2 connection, stronger than unsynced `curl &`. N=20, one object, then re-read state.

```python
import socket, ssl, threading
HOST, PATH, COOKIE = "TARGET", "/redeem", "session=YOURTEST"
BODY = b"code=ONCE"
HEAD = (
    f"POST {PATH} HTTP/1.1\r\nHost: {HOST}\r\nCookie: {COOKIE}\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Content-Length: {len(BODY)}\r\nConnection: close\r\n\r\n"
).encode()
req = HEAD + BODY
N, bar = 20, threading.Barrier(20)
def one():
    raw = socket.create_connection((HOST, 443), timeout=10)
    s = ssl.create_default_context().wrap_socket(raw, server_hostname=HOST)
    s.sendall(req[:-1]); bar.wait(timeout=5); s.sendall(req[-1:])
    print(s.recv(2048).split(b"\r\n", 1)[0])
    s.close()
ts = [threading.Thread(target=one) for _ in range(N)]
[t.start() for t in ts]; [t.join() for t in ts]
```

**Cross-endpoint (same gate, two paths).** Limit-overrun is often not "the same POST × N". Queue the **write** and the **consume** together (apply coupon + checkout, change-email + confirm, hold seat + pay) so they share one `openGate`. Two different bodies, one flush. Re-read both objects. If only one endpoint exists, stay on the table below.

GraphQL: aliases in one document are concurrent only if the server actually parallelizes resolvers. If aliases run serially, send N HTTP requests instead (`hunt-graphql`).

h2 front / HTTP/1.1 back (some CDNs) can serialize the batch. If every response is slow and strictly ordered, the single-packet attempt never overlapped — try the origin directly when it is in scope, or note the edge serialized you.

## What to race

| Action | Parallel body | State you re-read |
|---|---|---|
| Coupon / gift card / promo | same code, N times | redemption count, balance |
| Wallet transfer | same `amount` and idempotency omitted | both balances |
| Vote / like / follow | same object id | counter |
| Free-tier create | same `POST /resource` | object count vs cap |
| Email change | two different new emails, same session, same moment | which address received the token, and which address the token confirms (GitLab/Devise class, CVE-2022-4037) |
| Reset confirm | same token, two passwords | which password actually works |
| Seat / inventory decrement | last item, N buyers | orders paid vs stock |

Email-change and reset races: two in-scope accounts you own. Do not race a victim's address.

## Limit-bypass myths

| Control | What actually happens | What you do |
|---|---|---|
| Per-user rate limit checked then incremented | The whole batch can pass a stale counter | Show N accepted actions, not N guesses of a secret |
| Unique DB constraint | Often one `200` and several `409`, and the side effect still happened once per winner | Read the ledger, not the status codes |
| In-process mutex | Other app nodes do not share it | Same packet is still the right test; do not spray the CDN |
| Idempotency key required | Reusing the key should collapse to one effect | Send the same key in the batch **and** a batch with the key omitted |

## Validation

- Before/after snapshot of the business object, plus the N response codes.
- At least two effects from one batch, reproduced on a fresh object (new coupon, new cart).
- n≥10 requests in the batch. A single duplicate in the logs is not enough.
- Timing-only claims (no state change) need n≥10 paired samples and still usually are not this class — prefer a state diff.
- Optional: one packet capture showing a single flush. It supports the write-up. It does not replace the balance diff. Do not block a proven double-credit on a missing pcap.

**Not a race:** two sequential clicks the UI allowed; a counter that includes your retries because the first attempt actually failed; OTP/PIN/password attempts sent concurrently. Keyspace exhaustion is out of scope, including single-packet OTP sprays. Rate-limit research that exists to guess PINs is not a technique you run here.

## Chains

- Double redeem → direct balance change (`hunt-business-logic`).
- Coupon + checkout in one gate → paid order with stacked discounts; quote the ledger, not two 200s.
- Email-change race → confirmation token for address B while the account shows A → `hunt-ato`.
- Quota race → extra admin seat or API key → use one extra object, stop.
- GraphQL alias or batch of the same mutation → this skill's HTTP layer if aliases are serial.
- Webhook replay in parallel → double fulfillment (`hunt-webhook`).

## Rails

- In-scope only. One object, N≈20, stop when the double effect is proven. No inventory wipe, no payment flood, no OTP/PIN/password guessing.
- Active testing only where the engagement allows the state change. Prefer a promo/test coupon over a production settlement path when both exist.
- Draft only — do not submit.

## Before you report — dedup gate

```bash
python3 engine/dedup.py check --program <program> --class race --url "<endpoint>" --title "<title>"
```

`NOVEL` → `/validate`. `LIKELY_DUP` → stop unless the endpoint or a bypass of the lock is a concrete differentiator.

Cross-refs: `hunt-business-logic`, `hunt-ato`, `hunt-graphql`, `hunt-webhook`, `triage-validation`.
