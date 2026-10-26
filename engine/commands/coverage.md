---
name: coverage
description: Show hunt coverage — what's been tested vs what's left, by endpoint and vuln class. Usage: /coverage [--slug <program>]
---

# /coverage

Show the current hunt coverage status.

## Usage
```
/coverage                    # current engagement
/coverage --slug myprogram   # specific program
```

## What It Shows

1. **Endpoint coverage**: tested / total (with list of untested)
2. **Vuln class coverage**: which classes tested on which endpoints
3. **Category coverage**: discovery categories with test status
4. **Test plan progress**: executed / total cases, confirmed / disproved
5. **Time analysis**: average time per endpoint, estimated remaining

## Commands
```bash
python3 ~/0xray-hunt-harness/engine/engine/coverage.py show --slug <program>
```

## Interpreting Results

- **Green zone (>80%)**: Most surface tested, focus on high-value untested endpoints
- **Yellow zone (50-80%)**: Good progress, prioritize credential/admin/org endpoints
- **Red zone (<50%)**: Still early, keep hunting — don't validate yet
