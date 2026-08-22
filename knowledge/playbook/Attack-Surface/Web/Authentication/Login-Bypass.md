> Source: https://bugbounty.info/Attack-Surface/Web/Authentication/Login-Bypass

# Login Bypass

Login endpoints are almost always in scope and almost always have something wrong with them. The bug class ranges from trivial (default creds) to genuinely tricky (logic flaws in multi-step flows). Start here on every target.

## Rate Limit Bypass

Most rate limiting is IP-based. That means it's broken by design.

**Header rotation**  -  many apps trust forwarded headers from proxies and CDNs without validating them. Cycle through these on every blocked request:

```text
X-Forwarded-For: 1.2.3.4
X-Real-IP: 1.2.3.4
X-Originating-IP: 1.2.3.4
X-Remote-IP: 1.2.3.4
X-Client-IP: 1.2.3.4
CF-Connecting-IP: 1.2.3.4
True-Client-IP: 1.2.3.4
```

In Burp, use Pitchfork with a list of IPs in column A and passwords in column B. Or use the **IP Rotate** extension to cycle through AWS API Gateway endpoints  -  effectively unlimited unique IPs.

**Account-based lockouts**  -  if the lockout is on the account, not the IP, distribute your attempts across accounts. If you're testing credential stuffing resilience, use a single password across 100 accounts before an account trips the lockout threshold.

**Slow attack**  -  some rate limits are requests-per-minute. One request every 90 seconds often flies under the radar.

## Credential Stuffing Vectors

Not about cracking passwords  -  about testing whether the app has any protection at all:

- Does the error message differ between "no account" and "wrong password"? That's a valid user enumeration finding on its own.
- Try `admin:admin`, `admin:password`, `admin:123456`, `test:test` before anything clever.
- Check for legacy endpoints  -  `/api/v1/login` when the app uses `/api/v3/login`. Old endpoints often lack modern rate limiting.

## Default Credentials

Do this before anything else. It takes 30 seconds and occasionally wins immediately:

| Stack | Creds |
| --- | --- |
| Jenkins | `admin:admin` |
| Grafana | `admin:admin` |
| Kibana | no auth by default |
| phpMyAdmin | `root:` (empty) |
| Tomcat manager | `tomcat:tomcat`, `admin:admin` |
| Routers/IoT | vendor-specific, check `cirt.net` |

## Authentication Logic Flaws

These are the juicy ones. Look for multi-step login flows  -  anything with more than one POST request.

**Step skipping**  -  if login is `/auth/step1` -> `/auth/step2` -> `/auth/complete`, try hitting `/auth/complete` directly after step 1. Some apps only check that step 1 completed, not that step 2 did.

**Response manipulation**  -  if step 2 returns `{"mfa_required": true}`, change it to `false` in the proxy. See [MFA Bypass](../../../Attack-Surface/Web/Authentication/MFA-Bypass) for more on this.

**Parameter pollution**  -  send `username=victim&username=attacker` and see which one the app uses for authentication vs. which one it logs.

**SQL injection in login**  -  still happens. Try `' OR '1'='1` in the username field with any password. Also try `admin'--` as the username.

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
 
username=admin'--&password=anything
```

## Burp Workflow

1. Send login request to Intruder
2. Mark the password field as the payload position
3. Use Sniper with a short list first (top 20 passwords) to check for rate limiting behavior
4. Check response length differences  -  a successful login often has a different response length even if the status code is the same (302 either way)

## Passkeys and WebAuthn Misuse

Passkeys (WebAuthn credentials) are increasingly the primary auth method on modern apps. The spec is solid but the server-side implementation is where things go wrong.

**Challenge not validated**  -  the server issues a challenge and the client signs it with the private key. If the server doesn't verify the signature covers the correct challenge, replay the assertion from a different session:

```javascript
// Capture a valid authenticatorAssertionResponse from one session
// Replay the clientDataJSON + authenticatorData + signature to a different session
// If the server accepts it  -  challenges aren't being bound to sessions
```

**Cross-origin credential use**  -  WebAuthn credentials are origin-bound. A credential registered at `app.target.com` should not be accepted at `admin.target.com`. If a multi-tenant app uses the same relying party ID (`rpId`) across origins and doesn't validate the `origin` field in the client data:

```json
// clientDataJSON from a valid assertion
{
  "type": "webauthn.get",
  "challenge": "...",
  "origin": "https://app.target.com"  // change to https://admin.target.com
}
```

Re-sign or modify and replay. The server should compare `origin` against its expected origin.

**Missing attestation validation**  -  attestation verifies that the authenticator hardware is genuine. Most consumer apps skip attestation verification (it's complex), which is fine. The issue is apps that *claim* to require strong attestation but don't actually validate the attestation statement. Test by submitting a self-attestation (`fmt: "none"`) when the app's policy supposedly requires `packed` or `fido-u2f` attestation.

## Magic-Link Reuse

Magic links  -  one-click login via a tokenised URL  -  are vulnerable when the token lifetime or usage controls are weak.

**Single-use not enforced**  -  request a magic link, use it to log in, then paste the same URL into a fresh private window. If you're logged in again, the token wasn't invalidated:

```text
https://target.com/auth/magic?token=abc123  # should fail on second use
```

**Token in Referer**  -  if the magic link page loads third-party resources (analytics, fonts, anything external), the full URL including the token appears in the `Referer` header of those requests. Check the network tab after clicking a magic link.

**Predictable tokens**  -  some apps generate magic link tokens from: `md5(email + timestamp)`, sequential IDs, or short random strings. Request 5-10 tokens for your own account and look for a pattern. If you find one, it may be brute-forceable for another user's current token.

## Device-Fingerprint Bypass

When an app uses device fingerprinting as a second factor  -  "we recognise this device, skip MFA"  -  the fingerprint is typically stored in a cookie or localStorage.

**Cookie injection**  -  if the trusted-device signal is a cookie value, you can copy it from one browser session to another. This defeats the purpose of device trust entirely:

```text
# Copy from trusted browser's DevTools
document_trust_token=XXXXXXXX
 
# Paste into untrusted browser via DevTools or Burp
# If MFA is skipped  -  the device check is purely client-side
```

**Header spoofing**  -  some implementations factor in `User-Agent` or `Accept-Language`. Match the victim's browser headers (obtainable from a phishing ping) and combine with a leaked session cookie.

**Repeat-submit race**  -  a few apps set the trusted-device cookie only after MFA completion. If you can race the response (send the MFA completion request and immediately send a follow-up authenticated request before the cookie check updates), the transition window may allow access without the trust cookie being present on the protected resource.

## Rate-Limit-Defeating Credential Stuffing

Distinct from generic rate-limit bypass: this is about apps that implement rate limiting specifically on the authentication counter but miss adjacent endpoints.

**Legacy API versions**  -  the main `/api/v3/login` has rate limiting; `/api/v1/login` or `/api/v2/authenticate` does not. Always check older API versions for the same endpoint.

**Password reset as an auth oracle**  -  if login returns a generic "invalid credentials" after lockout, but the password reset endpoint still differentiates between "email not registered" and "reset link sent"  -  that's your enumeration oracle while login is locked.

**Per-account vs per-IP counter reset**  -  some apps lock accounts for N minutes then reset the counter. If the lockout timer resets on any valid response (even a failed login after the lockout expires), you can stuff credentials in batches: attempt N-1 times, wait for lockout to clear, repeat. The lockout never permanently blocks because you never exceed N in a single window.

**Sub-request authentication**  -  API-backed apps sometimes have internal auth flows used by mobile clients or partner integrations. Look for `/auth`, `/token`, `/oauth/password` endpoints that accept `grant_type=password`  -  these RFC 6749 password grant endpoints often predate modern rate limiting.

## Checklist

- Try default credentials before anything else (30 seconds, occasionally wins immediately)
- Check for user enumeration via different error messages or response times
- Test rate-limit bypass via IP header rotation (`X-Forwarded-For`, `X-Real-IP`, etc.)
- For multi-step flows: try skipping straight to the final step
- Intercept MFA responses and try flipping `mfa_required: false`
- For WebAuthn: check challenge binding to session, cross-origin acceptance, and attestation enforcement
- For magic links: test single-use enforcement and predictability; check Referer on the landing page
- If device trust is used: copy the trust cookie to a fresh session; test header spoofing
- Check legacy API versions for the same auth endpoint without modern rate limiting
- Test `grant_type=password` OAuth endpoint if it exists
- Try SQL injection in the username field: `admin'--` and `' OR '1'='1`
- Check password reset for user enumeration even when login is locked out

## Public Reports

- Authentication bypass via response manipulation on Slack - [HackerOne #737140](https://hackerone.com/reports/737140)
- Rate limit bypass on login via X-Forwarded-For header rotation - [HackerOne #1067416](https://hackerone.com/reports/1067416)
- Magic link reuse allowing account takeover on Flickr - [HackerOne #808839](https://hackerone.com/reports/808839)
- Login CSRF via missing state parameter chained with account takeover - [HackerOne #1042756](https://hackerone.com/reports/1042756)

## See Also

- [MFA Bypass](../../../Attack-Surface/Web/Authentication/MFA-Bypass)  -  most login bypasses lead here next
- [Password Reset](../../../Attack-Surface/Web/Authentication/Password-Reset)  -  complementary auth attack surface
- [Session Management](../../../Attack-Surface/Web/Authentication/Session-Management)  -  what you get after a successful login bypass
- [JWT Attacks](../../../JWT-Attacks)  -  token-based auth has its own bypass category
