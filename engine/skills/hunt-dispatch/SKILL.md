---
name: hunt-dispatch
description: Skill-set loader for /hunt orchestrator. Fingerprints the target, then loads hunt-* skills whose names match the live bytes on disk. Use when /hunt has just received a mode answer (redteam or wapt + blackbox|greybox). Not for direct user invocation.
---

# hunt-dispatch

skill-set loader for `/hunt`. one concept (which skills to load), one place.

there is **no closed vuln-class menu**. a new `hunt-*` directory on disk is
eligible the next hunt. do not walk SQLi then XSS then IDOR because a list
said so.

invocation contract:

```
hunt-dispatch mode=redteam
hunt-dispatch mode=wapt box=blackbox
hunt-dispatch mode=wapt box=greybox
```

## step 1 — fingerprint (red team only)

fingerprint **every** live host, not just the apex. platform-skill routing
must be driven by banners on all hosts, not one host's.

use `-L` (follow redirects). identity-provider and CDN signals routinely sit
behind a 30x. pull both headers and the landing-page HTML (framework markers
live in the body, not headers).

```bash
HOSTS="$TARGET"
if [ -f "recon/$TARGET/live-hosts.txt" ]; then
  HOSTS=$(cat "recon/$TARGET/live-hosts.txt")
fi
for H in $HOSTS; do
  echo "=== $H ==="
  curl -sSL -m 12 -D - -o /tmp/fp_body "https://$H" 2>/dev/null | tr -d '\r'
  head -c 8000 /tmp/fp_body
done
rm -f /tmp/fp_body
```

if `live-hosts.txt` is absent, the loop still runs once against `$TARGET`.
record which signal came from which host.

### match skills from disk, not from a table

```bash
ls -1 ~/.claude/skills | grep -E '^(hunt-|okta-|m365-|enterprise-vpn|vmware-|cloud-iam|supply-chain|apk-redteam)'
```

for each directory name, take the tokens after the prefix (`hunt-nextjs` →
`nextjs`). if a token appears in the fingerprint blob (headers + body +
hostnames + detected tech), load that skill. examples of tokens matching
live bytes: `nextjs` vs `__NEXT_DATA__` / `/_next/`, `okta` vs an Okta
login host, `laravel` vs `laravel_session`.

always load `hunt-hypothesis` when it exists. it tells the agent to invent
the test from the bytes, not from a class list.

**load budget: cap at 8 matched skills** plus always-on mindset skills.
if more than 8 match, keep the ones whose tokens hit identity/SSO, VPN,
cloud IAM, then app framework. print the rest under `deferred:`.

**de-dup:**

- a CDN banner alone (Cloudflare / Akamai / Fastly) is **not** a skill match.
  it fingerprints the edge, not the app.
- do not load two skills for the same evidence.
- never load the entire hunt-* tree "just in case".

## step 2 — load skill set

invoke each skill in order via the Skill tool.

### mode=redteam

always-on (load first):

```
redteam-mindset
mid-engagement-ir-detection
dedup-novelty
hunt-hypothesis
```

platform + class (load second): only the fingerprint-matched skills from
step 1. do **not** preload hunt-rce, hunt-sqli, hunt-ssrf, or any other
class skill unless its name matched live bytes.

report format: `redteam-report-template`.

### mode=wapt

always-on:

```
bb-methodology
security-arsenal
triage-validation
dedup-novelty
hunt-hypothesis
```

plus fingerprint-matched hunt-* skills only. do **not** load the full OWASP
hunt-* set.

report format: `report-writing` (`bugcrowd-reporting` if the target is on
bugcrowd).

box=greybox: creds already captured by `/hunt`, available in session memory.

**do not fan out across authenticated tests until the creds are validated.**
`/hunt` only prompts for and stores creds — it does not confirm they work.
run a single low-cost auth preflight first against **the URL that proved
login** (session `probe` / the page that returned the logged-in app). there
is no built-in `/api/me` path.

```bash
# cookie session: GET the probe URL (or the session host / if no probe yet)
curl -sS -m 12 -b "$SESSION_COOKIE" "$PROBE_URL" -w '\n%{http_code}\n'
# bearer: same with Authorization
curl -sS -m 12 -H "Authorization: Bearer $TOKEN" "$PROBE_URL" -w '\n%{http_code}\n'
```

confirm three things from the preflight:

1. **live** — not 401.
2. **role/privilege** — the body shows the expected identity. IDOR needs a
   known baseline.
3. **not MFA-gated** — login did not stop at a 2fa/step-up challenge.

if the preflight fails, do **not** silently continue as blackbox — surface
"greybox creds did not validate" so the operator can re-supply.

## step 3 — taxonomy print (once, at session start)

emit a deterministic block. plain text, lowercase, colon-delimited.

```
loaded for {red team|wapt}: {N} skills
  mindset:    {always-on list}
  matched:    {fingerprint-matched skills (<=8), or "none detected"}
  deferred:   {matched past the 8-cap, or omit if none}
  hypothesis: hunt-hypothesis
```

do not print inj/auth/api class buckets. those are a hunt menu.

## step 4 — return control to /hunt

after taxonomy print, hand control back to `/hunt`. do not run probes here.

## privacy

never echo back, log, or persist:
- SOW / scope-of-work / engagement-letter content
- grey box credentials
- client identifiers in user-level memory

## Related Skills & Chains

- **`hunt-hypothesis`** — always. invent the test from live bytes.
- **`bb-methodology`** / **`redteam-mindset`** — mode confirmation and
  operator discipline.
- any `hunt-*` on disk whose name matches the fingerprint.
- **`report-writing`** vs **`redteam-report-template`** — deliverable format.
