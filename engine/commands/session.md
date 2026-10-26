---
name: session
description: Manage authenticated test sessions — check health, rotate, add identities. Usage: /session [check|rotate|add|list]
---

# /session

Manage authenticated test sessions for the current hunt.

## Usage
```
/session check                     # check all session health
/session rotate                    # rotate expired sessions
/session add --ident C             # add a third test identity
/session list                      # list all active sessions
```

## What It Does

- **check**: Tests each session against the target, reports which are alive/expired
- **rotate**: Calls `authsession.relogin()` for expired sessions
- **add**: Creates a new test identity via `identity.py new`
- **list**: Shows all sessions with user, host, expiry status

## Commands
```bash
# Check session health
python3 ~/0xray-hunt-harness/engine/engine/authsession.py check --slug <program>

# Rotate/refresh an expired session
python3 ~/0xray-hunt-harness/engine/engine/authsession.py relogin --slug <program> --ident A

# Create a new test identity
python3 ~/0xray-hunt-harness/engine/engine/identity.py new --program <program>

# List all sessions
python3 ~/0xray-hunt-harness/engine/engine/authsession.py list --slug <program>
```

## When to Use

- Before starting a hunt (ensure sessions are alive)
- Mid-hunt when you see 401/403 errors (session expired)
- When you need a third identity for multi-role testing (admin/member/viewer)
