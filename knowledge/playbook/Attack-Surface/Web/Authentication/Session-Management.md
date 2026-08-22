> Source: https://bugbounty.info/Attack-Surface/Web/Authentication/Session-Management

# Session Management

Session management is unsexy but consequential. A broken session system undermines everything else  -  even a perfect authentication flow means nothing if the session token is predictable, doesn't expire, or persists after logout.

## Session Fixation

The attack: set a known session ID on the victim before they authenticate. After authentication, if the app doesn't rotate the session ID, you already have a valid authenticated session.

**Classic HTTP flow:**

```http
# 1. Attacker obtains a pre-auth session token (just visit the site)
GET / HTTP/1.1
Host: target.com
# Response: Set-Cookie: session=ATTACKER_KNOWN_VALUE
 
# 2. Attacker sends victim a link with that session baked in
https://target.com/login?sessionid=ATTACKER_KNOWN_VALUE
 
# 3. If the app accepts session IDs from URL parameters and doesn't rotate on login...
# Attacker's known session is now authenticated
```

Test by:

1. Getting a session cookie before login
2. Logging in with a fresh account
3. Checking if the session cookie value changed  -  it must change post-authentication

## Token Entropy

Weak tokens are rare on Rails/Django/Express apps using built-in session handling. They appear on custom-built auth systems, legacy PHP apps, and anything where a developer rolled their own.

```bash
# Collect a bunch of session tokens
# Look for patterns  -  timestamp-based, sequential, short length
 
# Check token length
echo -n "SESSION_TOKEN_VALUE" | wc -c
# Anything under 16 bytes (32 hex chars) is worth investigating
 
# Check if it decodes to something readable
echo "SESSION_TOKEN" | base64 -d 2>/dev/null
```

If tokens look like `user_id + timestamp + weak_hmac`, that's a finding. Compute the HMAC yourself if you can guess the key.

## Concurrent Session Handling

Does the app allow unlimited concurrent sessions? Should it?

- Log in from two different browsers simultaneously  -  both sessions active?
- Does the app notify the user of a new login?
- Does logging out of one session invalidate the other?

On apps where sessions should be exclusive (banking, healthcare), unlimited concurrent sessions is a valid medium finding. More importantly, if a user changes their password, do all other sessions get invalidated? Test:

```text
1. Log in from Browser A  -  get session A
2. Log in from Browser B  -  get session B
3. From Browser A: change password
4. From Browser B: try to access a protected endpoint using session B
```

If step 4 works  -  existing sessions survive password changes. That's almost always a P3.

## Logout Failures

**Server-side invalidation**  -  the most common failure. The app clears the cookie client-side but never invalidates the session token server-side. Capture the session token before logout, logout, then replay the token.

```http
GET /api/profile HTTP/1.1
Host: target.com
Cookie: session=OLD_SESSION_TOKEN_CAPTURED_BEFORE_LOGOUT
```

If you get a 200  -  server-side invalidation is broken.

**JWT-specific issue**  -  stateless JWTs can't be "invalidated" without a denylist. If the app uses JWTs and doesn't maintain a token denylist, logout is purely cosmetic. See [Privilege Escalation](../../../Attack-Surface/Web/Authorization/Privilege-Escalation) for JWT manipulation.

## Cookie Flags

Always check. Missing flags are informational but chain well with other bugs.

| Flag | Missing Means |
| --- | --- |
| `Secure` | Token sent over HTTP, interceptable on network |
| `HttpOnly` | Token accessible via `document.cookie`  -  enables XSS-to-session-hijack |
| `SameSite=Strict/Lax` | Token sent on cross-site requests  -  enables CSRF (if relevant) |

```http
# Good
Set-Cookie: session=TOKEN; Secure; HttpOnly; SameSite=Strict; Path=/
 
# Bad  -  missing everything
Set-Cookie: session=TOKEN
```

## Session After Password Reset / Account Compromise

When a user resets their password, existing sessions should be invalidated. Test:

1. Login -> get session S1
2. Trigger password reset (as if attacker did it)
3. Complete the reset
4. Try using session S1 to access resources

If S1 still works  -  session invalidation on password reset is missing.

## Token Storage in Frontend

Check where the token is stored:

- `localStorage`  -  survives tab close, accessible to JS, XSS = full session theft
- `sessionStorage`  -  gone on tab close, still accessible to JS
- `HttpOnly` cookie  -  not accessible to JS, XSS can't directly steal it (but can use it via CSRF)

Not a standalone finding, but context for XSS severity and session security posture.

## Related Pages

- [Login Bypass](../../../Attack-Surface/Web/Authentication/Login-Bypass)  -  sessions start here
- [MFA Bypass](../../../Attack-Surface/Web/Authentication/MFA-Bypass)  -  partial session states
- [Privilege Escalation](../../../Attack-Surface/Web/Authorization/Privilege-Escalation)  -  JWT manipulation to escalate roles
