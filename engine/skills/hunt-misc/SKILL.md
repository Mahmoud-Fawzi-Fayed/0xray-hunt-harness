---
name: hunt-misc
description: Hunting skill for misc vulnerabilities. Built from 225 public bug bounty reports. Use when hunting misc on any target.
sources: github, hackerone_public
report_count: 225
---

# HUNT-MISC — Logic, access, and odd sinks

Use this when the bug is not a named injection class: broken object access, skipped state, mass assignment, token scope, invitation and removal, CRLF, a URL the server fetches, a subdomain claim, a package name the build pulls. If the sink is SQL, XML, a template, a file path, or a cache, switch to that skill and come back only for the chain.

## Rails
- In-scope only. Two accounts you control (A and B) for every access test.
- No brute force, credential stuffing, password spraying, or keyspace exhaustion. A missing rate limit is not a finding by itself and is not permission to guess secrets.
- No ReDoS, no catastrophic backtracking payloads, no mail-bomb, no mass export.
- Dependency confusion: only if the program allows publishing a package. One canary callback, nothing else, then unpublish.
- Stop at draft. Never auto-submit.
- Status code is not impact. Body-diff against a baseline is.

## Decision tree

1. **Who is the caller, and which object is in the response?** Map roles the product actually has (owner, member, guest, removed). Unique marker per object: 8+ random alphanumerics, not `test` or `admin`. If the marker appears in a baseline that never received it, pick another marker.
2. **ID swap.** With A's session, request B's id (and the reverse) on each endpoint that echoes an id. **Body must differ** and must contain B's marker. Identical 200s are not IDOR. Try one old API version, one method swap, and one content-type only if the first request was checked and denied — not as a fuzz campaign.
3. **State skip.** Invitation, email change, password reset, checkout, "verify later". Replay a token in a second session, skip a step, reuse a token after it should be dead. Proof is the privileged body, not a 200.
4. **Mass assignment.** Add `role`, `is_admin`, `org_id`, `owner_id`, `email_verified`, `price`, `plan` to a normal JSON update. Proof is a later GET that shows the field stuck, and an action only that field should allow.
5. **Removal and expiry.** Remove A from the org (or expire the invite). A's old session and PAT must fail. If they still return B's data, that response is the bug.
6. **Scope of a token.** Mint the lowest scope the UI offers. Call one endpoint that scope should not allow. Show the forbidden control with a no-scope token and the success with the low-scope token.
7. **Server-side fetch.** Any setting that stores a URL (webhook, SSO metadata, "import from", error-tracker DSN, avatar URL). Point it at `http://UNIQUE.collab/`. A hit is SSRF (`hunt-ssrf`) — follow that skill's metadata rules before claiming cloud keys.
8. **CRLF.** If a value you send is copied into a header (`Location`, `Set-Cookie`, a custom `X-`), try `%0d%0aX-Misc-UNIQ: 1`. Proof is that header on the response (`curl -D -`), not a browser quirk. Cache impact only if `hunt-cache-poison` second-client rules pass.
9. **Subdomain / redirect allow-list.** NXDOMAIN or a dangling CNAME is a lead. Claim takeover only after you control the name and a unique HTTP or DNS marker answers. OAuth `redirect_uri` on that name is ATO only if a code for your test client lands on it (`hunt-host-header`, `hunt-oauth`).
10. **SAML / OIDC logic** → `hunt-saml` / `hunt-oauth`. A signature you stripped that still logs you in as a user you name is the bug. Parser-differential (ruby-saml CVE-2025-25291 / CVE-2025-25292 class, samlify CVE-2025-47949 class) only on stacks that use that library — prove the NameID you injected is the session you received.

Missing SPF, DKIM, DMARC, security headers, or a "spoofing risk" with no accepted mail is not a finding (`security-arsenal` always-rejected list).

## Proof patterns

**Body-diff.** Save A-on-A, A-on-B, and logged-out. Report A-on-B only when the body contains B's marker and A-on-A does not.

**Invitation.** Accept the token with a session whose email is not the invited one. Show the role on a later GET. If the product requires a mailbox you control, use yours.

**CRLF**
```bash
curl -sD - "https://TARGET/redirect?next=https://TARGET.example/%0d%0aX-Misc-UNIQ:%201" -o /dev/null
```
`X-Misc-UNIQ` must be a response header. URL-encoded `%0d%0a` and a raw `\r\n` if the client is a raw socket. Unicode `\u000d\u000a` when the JSON parser runs before the header writer.

**URL setting.** One POST of your collaborator, one inbound hit, stop. Do not point it at `169.254.169.254` until the collaborator has fired, and then follow `hunt-ssrf` (IMDSv2 401 is not keys).

**Package name.** If an error or a lockfile names a private package that does not exist on the public registry, stop and check the program rules before publishing anything. Canary = one DNS/HTTP callback from `install`. No postinstall payload beyond that callback.

## Validation
- Concrete action: you read B's marker, you kept access after removal, the low-scope token performed the denied action, the header appeared, the collaborator fired, or the OAuth code arrived on a name you control.
- "Could potentially", a UI-only hide, a 403 body that is the same for every id, and a policy block that returns the same error for existing and missing paths are not oracles. SharePoint-style extension blocks (`blocked by the server administrators` for `.config` / `.asmx` whether or not the file exists) are that pattern — do not inventory "found" files from them.
- Reproduce from a clean client in a few requests. Write the preconditions (you must be a member, you must hold a low-scope token).

## Chains
| Primitive | Needs | Result you can claim |
|---|---|---|
| ID in a response | A-on-B body-diff | Read of that object |
| Soft-delete / removal | Old token still returns data | Access after removal |
| Invite token in the wrong session | Role shows on GET | Membership you should not have |
| CRLF in a header | `hunt-cache-poison` second client, or a `Set-Cookie` you can show | Splitting. Not cache poison until the cache skill passes |
| SAML signature ignored | Session is the injected NameID | SSO ATO. One user you can demonstrate |
| Dangling name you now control | `redirect_uri` or reset link receives a code/token | ATO of your test user, described as the victim path |
| Low-scope token writes | Control request with no scope fails | Scope bypass on that route |

Do not cite GitLab H1 #1160407 as CRLF. That report is cache poisoning via `X-HTTP-Method-Override` (`hunt-cache-poison`).

## Before you report — dedup gate

Fresh/changed surface first (see `dedup-novelty`, `changed-js-deepdive`), and hunt classes in yield
order (`/yield`). Before drafting ANY finding from this skill, run the dedup gate:

```bash
python3 engine/dedup.py check --program <program> --class <class> --url "<endpoint>" --title "<title>"
```

`NOVEL` -> proceed to `/validate`. `LIKELY_DUP` -> stop unless you can prove a concrete differentiator
(different endpoint/param/impact, or a bypass of the deployed fix -> report as a regression).
