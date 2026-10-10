---
name: yield
description: Print hunt order from THIS program's journal — classes you confirmed rise, classes you keep duplicating sink. No canned vuln-class menu. Usage: /yield
---

# /yield

Order live work from this program's own outcomes, not a global class catalog.

```bash
python3 engine/yieldrank.py rank            # classes that appeared in hunt-memory/journal.jsonl
python3 engine/yieldrank.py rank --json     # machine-readable
python3 engine/yieldrank.py rank-targets    # which registered programs have untested surface
```

## How the order is computed

- **Your confirmed history** (+) — classes you've been landing here get nudged up.
- **Your dup history** (−) — classes where you keep getting duplicated sink.
- Learned from `hunt-memory/journal.jsonl` + this program's dedup corpus.
- Empty journal → empty list. Invent tests from live bytes; do not walk a class menu.

Pair with `/dedup watch` so fresh surface is hunted before picked-over surface.
