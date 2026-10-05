---
name: hunt-baas
description: "Hunt Backend-as-a-Service misconfiguration — Firebase (Firestore / Realtime DB / Storage rules like allow read, write: if true, or auth != null with no ownership check, or test-mode), Supabase (Row Level Security disabled or USING(true) on API-exposed tables, the anon key treated as a secret, SECURITY DEFINER RPCs bypassing RLS, public storage buckets, predictable signed URLs), plus PocketBase / Appwrite / Nhost equivalents. The anon/publishable key is MEANT to be public — the control is the server-side rule, so an anonymous REST read of another user's data is a real finding. Use whenever a target's JS bundle or app reveals a Firebase config, a *.supabase.co URL + anon key, or any BaaS SDK."
sources: 0xray-authored
---

# HUNT-BAAS — Backend-as-a-Service misconfiguration (Firebase / Supabase / …)

BaaS lets the browser talk straight to the database with a **public** key; the only thing between an
anonymous attacker and the data is a server-side rule/policy. In AI- and "vibe-coded" apps these
rules are routinely left open — UpGuard and others found **tens of thousands** of Supabase projects
with RLS off (incl. plaintext passwords/tokens), and Firebase `if true` leaks are endemic.

## The core idea (do not misreport it)
Finding the anon/publishable key in client JS is **NOT** the vulnerability — it is public by design
(see `ywh-triager-grade-reports`: Firebase browser keys are not findings on their own). The finding is
that the **rule/policy lets you read or write data you shouldn't**. Prove the data access, anonymously
or cross-account.

## Recon (get the project coordinates from client-side)
- Firebase: `apiKey`, `projectId`, `databaseURL`, `storageBucket` in the JS/firebase config; collection
  names from `collection(db,'x')` / `doc(db,'x/y')` (see `hunt-source-leak`, `changed-js-deepdive`).
- Supabase: the `https://<ref>.supabase.co` URL + the `anon` JWT (`apikey`) in the bundle; table names
  from `.from('<table>')` calls.

## Firebase
- **Firestore (REST, anonymous):**
  `GET https://firestore.googleapis.com/v1/projects/<pid>/databases/(default)/documents/<collection>`
  → 200 with documents = world-readable collection.
- **Realtime DB:** `GET https://<db>.firebaseio.com/<path>.json` → data = open `.read` rule. Append a
  path to probe nodes; a bare `/.json` dumping the tree is the jackpot (and the worst rule).
- **Storage:** list/download objects via the Storage REST API if `allow read: if true`.
- **Auth:** anonymous sign-in enabled + rules keyed only on `auth != null` → sign in anon, re-read.
  Open signup to a privileged tenant is an escalation path.

## Supabase
- **PostgREST (anonymous):**
  `GET https://<ref>.supabase.co/rest/v1/<table>?select=*` with headers `apikey:<anon>` and
  `Authorization: Bearer <anon>` → rows = **RLS disabled or `USING (true)`**. (RLS is NOT auto-enabled
  on tables created via the API / by coding agents — the common leak.)
- **Write test (careful, read-only by default):** only probe write where the program allows it; a 201 on
  an anon `POST /rest/v1/<table>` proves an open write policy — stop at the primitive, do not mass-insert.
- **RPC / SECURITY DEFINER:** `POST /rest/v1/rpc/<fn>` — a definer function runs as owner and can bypass
  RLS; test whether it returns rows your role shouldn't see.
- **Storage:** `/storage/v1/object/public/<bucket>/…` public buckets; check predictable/guessable paths.

## PocketBase / Appwrite / Nhost (same footgun, different label)
| BaaS | Open-rule footgun | Dashboard says |
|---|---|---|
| PocketBase | empty collection API rule | "Public" |
| Appwrite | `any` role on Read | "configured" |
| Nhost | `anonymous` role with `{}` filter | "configured" |

## PoC minimum & severity honesty
- Show the **actual data** returned anonymously or cross-account (redact others' PII per
  `evidence-hygiene`). A single table of other users' records is a real High; a full dump of PII /
  credentials is Critical. "Anon key is exposed" with no readable data is **not** a finding.

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class baas --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different table/collection/impact, or a bypass of a deployed rule fix -> report as a regression).

Cross-references: `hunt-cloud-misconfig`, `hunt-idor`, `hunt-source-leak`, `changed-js-deepdive`,
`hunt-api-misconfig`, `evidence-hygiene`, `triage-validation`.
