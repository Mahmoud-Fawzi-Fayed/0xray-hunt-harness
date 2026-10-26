---
name: hunt-discovery
description: Exhaustive function/endpoint discovery — map the ENTIRE attack surface before any testing begins. Covers UI features, API endpoints, auth flows, org/permission boundaries, sharing/transfer flows, integrations, credentials, billing, admin/internal paths. "No function left behind."
triggers:
  - discovery
  - surface mapping
  - endpoint inventory
  - function enumeration
  - attack surface
priority: 200
---

# hunt-discovery — Exhaustive Attack Surface Discovery

## Why This Exists

The #1 reason bug bounty hunters miss bugs: **testing starts before discovery is complete.**
On a typical web app, public recon (robots.txt, JS bundles, OpenAPI) discovers ~30-50% of the
real surface. The rest — org boundaries, permission models, transfer/sharing flows, credential
management, billing manipulation, admin endpoints — only appears through authenticated exploration
and systematic probing.

**Rule: NEVER start testing until discovery covers ≥80% of function categories.**

## Discovery Checklist (mandatory — every category must be attempted)

### 1. API Schema Mining
```bash
python3 ~/0xray-hunt-harness/engine/engine/discovery.py discover --slug <program> --scope <scope.json>
```
- Parse OpenAPI/Swagger for EVERY path, method, parameter, security requirement
- Note which operations are declared-secured vs open
- Note body parameters and their types (the injection surface)

### 2. Authenticated Browser Walk
```bash
python3 ~/0xray-hunt-harness/engine/engine/browser.py capture --url <seed> --slug <program> --as A --scope <host>
```
- Walk every menu, tab, modal, dropdown, settings page
- Capture all XHR/fetch calls the SPA makes
- Note feature flags and conditional UI elements
- Identify different views per role (admin vs member vs viewer)

### 3. UI Feature Enumeration
Log in as the test user and systematically visit:
- Dashboard/home — what actions are available?
- Settings — user, org, project, billing, security
- Team/members — invite, roles, permissions
- Projects/workspaces — create, edit, share, transfer, delete
- Integrations — webhooks, OAuth apps, third-party connections
- API keys/tokens — create, list, rotate, revoke
- Billing — plans, usage, invoices, spending limits
- File/storage — upload, download, manage

### 4. Organization & Permission Boundary Mapping
For each target with multi-tenancy:
- How are organizations/teams/workspaces structured?
- What roles exist? (admin, member, viewer, billing, guest, API)
- How are permissions assigned and checked?
- Can users be invited? What's the invitation flow?
- Are there project transfer mechanisms?
- Are there sharing/collaboration features?

### 5. Credential & Secret Surface
- API key management (create, list, rotate, revoke, scoped?)
- Connection strings (are passwords revealed? to whom?)
- OAuth client secrets
- Session tokens / JWT structure
- Service account credentials

### 6. Admin & Internal Endpoints
```bash
# Probe common admin/debug/internal paths
for path in /admin /console /dashboard /internal /debug /actuator /metrics /health /graphql /graphiql; do
  python3 ~/0xray-hunt-harness/engine/engine/netget.py GET "https://target.com${path}" --as A
done
```

### 7. Response Mining
For each discovered endpoint that returns JSON:
- Parse response for linked URLs, resource IDs, nested endpoints
- Follow pagination to discover more resources
- Note field names that suggest additional endpoints (e.g., `transfer_url`, `webhook_endpoint`)

### 8. Error-Based Discovery
For each discovered endpoint:
- Try all HTTP methods (not just GET) — which aren't 405?
- Send malformed requests to trigger error messages that reveal routes
- Try path traversal variations to discover sibling endpoints

### 9. Documentation & Changelog
- Read API documentation (often lists endpoints recon missed)
- Check changelog/release notes for recently added features (lowest dup risk)
- Check blog posts for feature announcements

### 10. Database/Storage Layer
For database-as-a-service targets:
- What database extensions are available?
- What roles/permissions does the user get?
- Can new roles be created?
- Are there federation/linking features (dblink, FDW)?
- What I/O capabilities exist?

## Output Format

After discovery, produce a structured inventory:
```json
{
  "total_endpoints": 150,
  "categories_covered": 9,
  "categories_total": 11,
  "coverage_pct": 81.8,
  "by_category": {
    "api_endpoints": {"count": 45, "sample": ["GET /api/v1/users", "POST /api/v1/projects"]},
    "org_boundaries": {"count": 12, "sample": ["GET /api/v1/organizations", "PATCH /api/v1/members/{id}/role"]},
    "credential_management": {"count": 8, "sample": ["POST /api/v1/api-keys", "GET /api/v1/connection_uri"]},
    ...
  },
  "high_value_targets": [
    "POST /api/v1/projects/{id}/transfer — project ownership transfer",
    "GET /api/v1/connection_uri — reveals database password",
    "PATCH /api/v1/members/{id}/role — role escalation surface"
  ]
}
```

## Coverage Gate

Discovery is NOT complete until:
1. ≥80% of function categories have at least one endpoint discovered
2. All documented API endpoints are accounted for
3. Auth boundaries are mapped (which endpoints require auth, which don't)
4. Role boundaries are mapped (which roles can access what)
5. Cross-account/cross-org test vectors are identified

If coverage is below 80%, repeat discovery with:
- Authenticated browser exploration (different roles)
- Documentation crawl
- GraphQL introspection
- Response mining from existing endpoints

## What Happens After Discovery

The discovery inventory feeds directly into the hunt pipeline:
- Each discovered endpoint becomes a surface item with a priority
- High-value categories (credentials, admin, org boundaries) get priority boosts
- The hunt phase tests every discovered endpoint, not just the ones recon found
- Coverage tracking ensures no function is left untested
