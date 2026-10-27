---
name: discovery
description: Run exhaustive function/endpoint discovery on a target. Maps ALL features, APIs, roles, boundaries before testing. Usage: /discovery <target> [--slug <program>]
---

# /discovery

Run the discovery phase manually to map the full attack surface.

## Usage
```
/discovery target.com                    # discover all endpoints
/discovery target.com --slug myprogram   # with specific program slug
/discovery --show myprogram              # show existing inventory
```

## What It Does

1. Runs `discovery.py discover` — OpenAPI, admin probing, resource probing, error-based, response mining
2. Runs browser capture — authenticated SPA endpoint discovery
3. Runs GraphQL introspection — query/mutation surface
4. Outputs `discovery-inventory.json` and `discovery-inventory.md`
5. Reports coverage against the 11-category checklist

## Commands
```bash
# Full discovery
python3 ~/0xray-hunt-harness/engine/engine/discovery.py discover --slug <program>

# Browser capture (adds SPA endpoints)
python3 ~/0xray-hunt-harness/engine/engine/browser.py capture --url <seed> --slug <program> --as A --scope <host>

# Show existing inventory
python3 ~/0xray-hunt-harness/engine/engine/discovery.py show --slug <program>
```

## Coverage Gate
Discovery must produce validated in-scope operations and attempt every required source. Guessed paths are leads only. Missing categories stay PARTIAL/unknown and drive role-aware browser, documentation, GraphQL, and response-mining passes.

## After Discovery

The inventory feeds directly into the hunt pipeline:
- Each endpoint becomes a surface item with a priority
- High-value categories (credentials, admin, org boundaries) get priority boosts
- Run `/hunt` or `/autopilot` to test the discovered surface
