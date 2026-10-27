---
name: profile
description: Build a structured understanding of a target before hunting — tech stack, user roles, crown jewels, high-value flows, API surface. Usage: /profile target.com
---

# /profile

Understand a target before you hunt it. This command builds a structured profile that feeds into yield ranking and hunt prioritization.

## Usage

```
/profile target.com
/profile https://app.target.com
```

## What This Does

Builds a `target_profile.json` in `recon/<target>/` with:

1. **Narrative** — What does this app do? (homepage, docs, about page)
2. **Tech stack** — Detected from headers, JS bundles, error pages, meta tags
3. **User roles** — Identified from signup flow, pricing page, API docs
4. **Crown jewels** — Highest-value assets (PII, payments, admin, sensitive data)
5. **High-value flows** — Auth, payments, data export, API, admin actions
6. **API surface** — OpenAPI/Swagger, GraphQL introspection, REST endpoints
7. **Auth mechanism** — Cookie, JWT, OAuth, API key, SAML

## Steps

### Step 1: Homepage & Narrative

```bash
TARGET="$1"
mkdir -p recon/$TARGET

# Fetch homepage through the scoped transport, extract what the product does
python3 engine/engine/netget.py GET "https://$TARGET/" --slug "$TARGET" > recon/$TARGET/homepage.html
# Extract title, meta description, and og tags
grep -oP '(?<=<title>).*?(?=</title>)' recon/$TARGET/homepage.html
grep -oP 'content="[^"]*"' recon/$TARGET/homepage.html | head -10
```

Read the homepage and write a 2-3 sentence narrative of what this product does and who uses it.

### Step 2: Tech Stack Detection

```bash
# HTTP headers reveal framework/server
curl -sI "https://$TARGET/" | grep -iE "^(server|x-powered|x-frame|x-content|set-cookie|x-request)"

# Check for common frameworks in HTML/JS
curl -s "https://$TARGET/" | grep -oE '(react|angular|vue|next|nuxt|svelte|jquery|bootstrap|tailwind|wordpress|laravel|django|rails|express|fastify|spring|asp\.net)' | sort -u
```

### Step 3: Auth Mechanism

```bash
# Check signup/login endpoints
for path in /login /signin /signup /register /api/auth /oauth /auth/login; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET$path")
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "$STATUS https://$TARGET$path"
done

# Check for JWT in responses (Set-Cookie or API response)
curl -sI "https://$TARGET/api/auth/session" 2>/dev/null | grep -i "set-cookie"
```

Determine: cookie-based, JWT (header), OAuth (external provider), API key, or SAML/SSO.

### Step 4: User Roles

Check pricing page, docs, and signup flow for role types:
- Free / paid tiers (different feature access = authz bugs)
- Admin / user / viewer roles (privilege escalation surface)
- Organization / team / member hierarchy (tenant isolation bugs)
- API-only users vs UI users (different validation paths)

### Step 5: Crown Jewels

Identify the highest-value data and actions:
- **PII**: user profiles, emails, addresses, phone numbers
- **Financial**: payment methods, transactions, invoices, balances
- **Admin**: user management, config, feature flags, billing
- **Secrets**: API keys, tokens, credentials, integrations
- **Content**: private documents, messages, files

### Step 6: API Surface

```bash
# Run the built-in recon
python3 ~/0xray-hunt-harness/engine/engine/recon.py "https://$TARGET/" "$TARGET"
```

This runs `spa_recon()` → `openapi_recon()` → `graphql_recon()` → `platform_recon()` and classifies every endpoint by vuln class.

### Step 7: Write Profile

Store the profile for the hunt engine:

```python
import json, sys
sys.path.insert(0, "engine/engine")
from brain import Brain
b = Brain.load("<target>")
b.set_profile(
    narrative="<what the app does>",
    roles=["admin", "user", "viewer"],
    crown_jewels=["PII", "payments", "API keys"],
    flows=[
        {"what": "user registration", "url": "/api/auth/register", "why": "account takeover surface"},
        {"what": "payment processing", "url": "/api/billing/charge", "why": "financial impact"},
    ],
    deprioritized=["marketing pages", "help center"]
)
b.save()
```

## Output

After profiling, the hunt knows:
- Which vuln classes to prioritize (payment app → IDOR + logic > XSS)
- Which endpoints to focus on (API + auth > static pages)
- Which user roles to test across (admin vs user = authz testing)
- What to skip (marketing, docs, CDN)

## What to Do Next

Run `/hunt <target>` — the profile feeds into yield ranking automatically.
