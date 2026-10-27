---
name: web2-recon
description: Web2 recon pipeline for subdomain enumeration, live hosts, URLs, JavaScript analysis, parameters, and continuous novelty monitoring. Use for asset discovery and attack-surface mapping.
---

# Web2 Recon Pipeline

Tool-specific commands and monitoring examples: [references/full-guide.md](references/full-guide.md).

## Pipeline

Enumerate → resolve → probe → crawl scoped surface → analyze JS and parameters → prioritize novelty.

Passive sources may enumerate broadly, but every active target request must pass the current scope policy. External crawlers without per-request containment stay disabled; use internal scoped discovery. Feed new hosts, endpoints, params, and changed bundles into the prioritized worklist rather than treating novelty as a log-only event.
