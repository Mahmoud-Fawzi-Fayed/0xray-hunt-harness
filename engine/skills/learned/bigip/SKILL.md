---
name: bigip
description: Playbook for BigIP (tech). Auto-authored by the harness after it hit this as a gap. Use when a target involves BigIP. Review and refine before relying on it.
auto_authored: true
created: 2026-10-04T12:21:22.101586+00:00
---

# BigIP — learned playbook

> Auto-drafted from a capability gap. Context that triggered it: Detected BigIP, no existing skill

## When to use
- A target involves **BigIP** (tech).
- The existing skills have no specific playbook for it.

## Recon / fingerprint
- Confirm BigIP is in use (headers, JS bundles, error pages, docs, version strings).
- Map its endpoints, auth model, and any admin/debug surface.

## Likely weak points
- Known CVEs for the detected version (check NVD / GitHub advisories).
- Default configs, exposed debug/actuator/admin, verbose errors.
- The usual class bugs the stack is prone to (injection, authz, deserialization, SSRF).

## Validation discipline
- Prove impact concretely; no "could potentially". OOB confirmation for blind cases.
- Stay in-scope and read-only unless an authorized test account is provisioned.

## Research notes
- Explore the latest vulnerabilities and security issues of Big-ip in the CVE database
- The BIG-IP system in Appliance mode is also vulnerable. This is a data plane issue; there is no control plane exposure. Security Advisory Status F5 Product Development has assigned ID 2524777 ( BIG-IP
- On October 15, 2025, CVE -2025-58424 was discovered, describing a vulnerability affecting F5's BIG-IP systems where undisclosed traffic can cause data corruption and unauthorized data modification in 
- The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has added a newly disclosed vulnerability affecting F5 BIG-IP systems to its Known Exploited Vulnerabilities (KEV) catalog, warning tha
- Security Advisory Description When SNMP v1 or v2c are disabled on the BIG-IP system, undisclosed requests can cause an increase in memory resource utilization. ( CVE -2025-21091) Impact System perform

## References
- [Big-ip CVEs and Security Vulnerabilities - OpenCVE](https://app.opencve.io/cve/?product=big-ip&vendor=f5)
- [K000162605: BIG-IP APM vulnerability CVE-2026-94127](https://my.f5.com/manage/s/article/K000162605)
- [BIG-IP Integrity Vulnerability Threat Report - Cyber Florida at USF](https://cyberflorida.org/big-ip-integrity-vulnerability-threat-report/)
- [CISA Warns of F5 BIG-IP Vulnerability Actively Exploited in Attacks](https://cybersecuritynews.com/f5-big-ip-vulnerability-actively-exploited/)
- [K000140933: BIG-IP SNMP vulnerability CVE-2025-21091](https://my.f5.com/manage/s/article/K000140933)
