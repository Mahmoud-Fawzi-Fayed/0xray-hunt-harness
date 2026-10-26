---
name: metrics
description: Show hunt effectiveness metrics — endpoints tested, hypotheses formed/confirmed, time on target, findings verified. Usage: /metrics [--slug <program>]
---

# /metrics

Show hunt effectiveness metrics for the current engagement.

## Usage

```
/metrics [--slug <program>]
```

## What to run

```bash
python3 ~/0xray-hunt-harness/engine/engine/state.py metrics --slug <program> --base ~/.bughunter-engagements
```

If no `--slug` is given, use the current engagement from scope.json.

## What to show

Present the metrics in a clear table:

| Metric | Value |
|--------|-------|
| Time on target | Xs (Xh Xm) |
| Endpoints discovered | N |
| Endpoints tested | N (X%) |
| Hypotheses formed | N |
| Hypotheses confirmed | N (X% hit rate) |
| Findings verified | N |
| Phase times | recon: Xs, discover: Xs, hunt: Xs |

## Interpretation guidance

- **Hit rate < 5%** = normal for a hardened target. Don't panic.
- **Tested < 30%** = still too much surface untested. Keep grinding.
- **Tested > 80% with 0 findings** = target may be solid. Consider switching programs.
- **Time < 4 hours** = too early to judge. Minimum 8 hours focused on one target.
