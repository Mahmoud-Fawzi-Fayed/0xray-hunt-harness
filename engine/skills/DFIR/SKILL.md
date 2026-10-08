---
name: analysing-attack
description: Analyse Mitre ATT&CK tactics, techniques and sub-techniques. Use when performing analysis of threat detections, threat models, security risks or cyber threat intelligence
---

# Analysing ATT&CK Tactics and Techniques

## Overview

This document provides best practices and resources for use when mapping ATT&CK tactics and techniques to threat detections, threat models, security risks or cyber threat intelligence.

Map against the current Enterprise catalog. As of August 2026 that is **v19.2** (v18.1 ended April 2026). Confirm the version at `https://attack.mitre.org/resources/versions/` before citing an ID. This skill does not ship a local technique index — the `resources/` greps in older copies 404.

## Available Resources

Resolve every ID on the live catalog. Do not invent a technique number from memory when the page disagrees.

- Technique: `https://attack.mitre.org/techniques/TXXXX/` and sub-technique `https://attack.mitre.org/techniques/TXXXX/YYY/`
- STIX: `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`
- Deprecations and renames: the changelog linked from the version you are mapping. Older reports often use IDs that were revoked or folded into a parent.

Tactics are abbreviated: REC=Reconnaissance, RD=Resource Development, IA=Initial Access, EX=Execution, PE=Persistence, PRV=Privilege Escalation, ST=Stealth (TA0005), DI=Defense Impairment (TA0112), CA=Credential Access, DIS=Discovery, LM=Lateral Movement, COL=Collection, C2=Command and Control, EXF=Exfiltration, IMP=Impact

**v19 Defense Evasion split (do not map to the old single tactic).** v19 retired *Defense Evasion* and split it by adversary intent: **Stealth** inherits TA0005 (blending in — LOLBins, obfuscation, masquerading; your controls still work) and **Defense Impairment** is the new TA0112 (breaking controls — killing EDR, tampering logging, subverting trust). A behavior can map to BOTH. Structural change: parent `T1562 Impair Defenses` is revoked — `T1562`, `T1562.001`, `T1562.006` merged into new `T1685 Disable or Modify Tools`; the other `T1562.*` subs were reissued under new IDs. `T1211` was renamed Exploitation for Stealth and `T1687 Exploitation for Defense Impairment` is its complement. Any pre-v19 mapping to a `T1562.*` sub-technique must be re-resolved via the official crosswalk (`https://attack.mitre.org/docs/subtechniques/de-split-crosswalk.csv`).

## Best Practice

Use your judgment alongside these guidelines to generate high-quality ATT&CK analysis.

- Do not assume your knowledge is 100% complete or up to date. Use the resources provided
- Carefully read any supplied information, perform deep analysis line by line if needed
- Search broadly for keywords, you may need to iterate multiple times to find every correct technique
- Think about the specific procedure being performed and consider the attacker (or defender) intent before determining appropriate tactic, technique or sub-technique
- Some techniques are part of multiple tactics (for ex. T1078 Valid Accounts) and may appear different for each tactic
- Other techniques are similar but distinct depending on tactic (for ex. T1213.003 and T1593.003 are both Code Repositories)
- Map to the most specific sub-technique when possible

### When Analysing CTI Reports

- IMPORTANT: Read the whole report fully, including tables of IOCs, appendixes or linked STIX files
- Screenshots contain valuable intelligence, ensure they are processed
- Break down the report into granular procedures when mapping to techniques
- Think about attacker objectives. Why did they take that action? What did they hope to achieve?
- Avoid inferring techniques that are not contained in the report
- Once initial analysis is complete, perform a second analysis to validate your findings and identify any missed techniques

### When Analysing Detections

- Detection logic may detect multiple techniques, map all that are applicable
- Analyse detection log sources and fields, these can help determine distinct tactics or techniques
- Consider the intent (hypothesis) of the detection, what was the engineers objective?

## Commonly Missed Techniques

### Command-Line Indicators
`-windowstyle hidden`|`-w hidden` -> T1564.003 Hidden Window
`-encodedcommand`|`-enc`|`base64` -> T1027.010 Command Obfuscation
`-noprofile`|`-ep bypass` -> T1059.001 PowerShell

### Encoding
Encoded payload delivered -> T1027.013 Encrypted/Encoded File
Decoded at runtime -> T1140 Deobfuscate/Decode

### RDP-Related
RDP connection|`.rdp` file -> T1021.001 Remote Desktop Protocol
Clipboard redirect -> T1115 Clipboard Data
Drive mapping|attached drives -> T1039 Data from Network Shared Drive
Auth redirect|intercept -> T1557 Adversary-in-the-Middle

### Infrastructure
DDNS|dynamic DNS|No-IP|FreeDNS|Dynu -> T1583.001 Domains (a provider hostname, not an algorithm). T1568.002 is Domain Generation Algorithms only — gibberish or word-concat names computed by the malware. Fast-flux rotation of many IPs is T1568.001, not DDNS.
Typosquat|lookalike domain -> T1583.001 Domains
Compromised server -> T1584.004 Server

### Network
SSH tunnel|port forward -> T1572 Protocol Tunneling
Downloaded|fetched payload -> T1105 Ingress Tool Transfer
Over port 80/443 -> T1071.001 Web Protocols

### Social Engineering
Masqueraded|posed as|impersonated -> T1656 Impersonation
Spoofed|mimicked|fake page -> T1036.005 Match Legitimate Name
Fake or modified login that captures passwords -> T1056.003 Web Portal Capture. The phish that delivers the link is T1566.002 (or T1598.003 only while the activity is still reconnaissance and no credential was captured).

### Technique Pairs
T1566 Spearphishing -> check T1204 User Execution
T1027 Obfuscation -> check T1140 Deobfuscation
T1053 Scheduled Task -> check T1059 Interpreter
T1021.001 RDP -> check T1115, T1039, T1557
T1059.001 PowerShell -> check T1564.003 Hidden Window

### Red Flag Phrases
"downloads and executes" -> T1105 + T1059
"persistence via task" -> T1053 + T1059
"C2 over HTTPS" -> T1071.001 + T1573.002
"compromised infrastructure" -> T1584.004
"redirects traffic" -> T1572 or T1090
"harvests credentials via fake page" -> T1056.003 (T1566.002 if a phish delivered it)
"ClickFix" | "press Win+R and paste" | fake CAPTCHA copy-paste -> T1204.004 + the interpreter (often T1059.001)
"MFA fatigue" | repeated push prompts -> T1621
"added an access key" | "new cloud role" | "registered a device" on a stolen account -> T1098.001 / T1098.003 / T1098.005
"AiTM" | reverse-proxy phish that stole the session cookie -> T1557 + T1539
"valid cloud principal" (not a domain user) -> T1078.004
"discord.com/api/webhooks" | "hooks.slack.com" | "webhook.site" POST of stolen data -> T1567.004 (not C2 unless that channel also issues commands)
"C2 over Slack/Discord/Telegram/Teams" -> T1102 (use .001/.002/.003 when the report says dead-drop vs bidirectional)
"AD CS" | "ESC1" | "forged authentication certificate" -> T1649
"excluded from CA policy" | "disabled MFA on the account" (Entra Conditional Access change) -> T1556.009
