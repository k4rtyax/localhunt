> Source: https://bugbounty.info/Attack-Surface/Web/Authorization/IDOR

# IDOR Patterns

IDOR (Insecure Direct Object Reference) is the most consistently rewarded bug class in bug bounty. Programs pay for it reliably, it's everywhere, and finding it is mostly a matter of systematically testing every endpoint that accepts an ID. If you're going to master one thing, make it this.

## The Core Idea

The app exposes an identifier in a request. The app uses that identifier to fetch/modify a resource. The app doesn't verify that the requesting user owns that resource. That's it.

```http
GET /api/v1/invoices/1847 HTTP/1.1
Host: target.com
Cookie: session=YOUR_ACCOUNT_SESSION
 
# Change 1847 to 1846  -  does it return another user's invoice?
```

## Where to Find Them

**Every API endpoint that takes an ID.** That's not an exaggeration. Build a list of every parameter in the app that looks like an identifier:

- URL path segments: `/users/123`, `/orders/abc-def`, `/files/upload_id`
- Query parameters: `?user_id=123`, `?document=4592`, `?account=B77F`
- Request body: `{"recipient_id": 445, "message": "hello"}`
- Response bodies  -  IDs in responses that aren't in the request (and that you can then use in subsequent requests)

Use Burp's **Logger++** or just **HTTP History** with the filter set to show only authenticated requests. Go through every unique endpoint.

## UUID vs Sequential IDs

Sequential integers (`/orders/1001`, `/orders/1002`) are trivially enumerable. UUIDs feel "secure" but aren't a security control  -  they're just obscure. If you can find a UUID through another vector (leaky API response, another user's shared content, email headers), UUIDs are equally vulnerable.

UUIDs in one endpoint often appear in another:

```http
# Your profile response returns:
{"user_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479", "name": "attacker"}
 
# Try that ID in other endpoints:
GET /api/admin/users/f47ac10b-58cc-4372-a567-0e02b2c3d479 HTTP/1.1
GET /api/messages?sender_id=f47ac10b-58cc-4372-a567-0e02b2c3d479 HTTP/1.1
```

## Horizontal vs Vertical IDOR

**Horizontal**  -  access another user's data at the same privilege level. Your account reads another user's private documents.

**Vertical**  -  access data or functions above your privilege level. Regular user reads admin records. This is higher severity and often overlaps with [Privilege Escalation](../../../Attack-Surface/Web/Authorization/Privilege-Escalation).

## Parameter Tampering Patterns

Don't just change the obvious ID in the URL. Look for IDs in:

```http
# JSON body
POST /api/transfer HTTP/1.1
{"from_account": 1001, "to_account": 1002, "amount": 100}
# Try changing from_account to another user's account
 
# Form data
POST /profile/update HTTP/1.1
user_id=123&email=newemail@attacker.com
# Change user_id to victim
 
# Hidden fields  -  check the HTML source
<input type="hidden" name="owner_id" value="456">
 
# Multipart upload
Content-Disposition: form-data; name="folder_id"
789
```

## Encoded/Hashed IDs

Don't give up when you see what looks like a hash or opaque ID. Common patterns:

```bash
# Base64
echo "eyJ1c2VySWQiOiAiMTIzIn0=" | base64 -d
# {"userId": "123"}   -  just change 123
 
# URL-safe base64
echo "eyJ1c2VySWQiOiAiMTIzIn0" | base64 -d -  # add == padding
 
# Check if it's a JWT (three base64 parts separated by dots)
# See [[Privilege Escalation]]
 
# MD5/SHA1 of known values
echo -n "123" | md5sum
# If the ID in the app matches, increment the input and compute the next hash
```

## Two-Account Testing Workflow

This is the methodology  -  don't skip it:

```text
Account A (attacker): create resources, generate IDs, note them
Account B (victim): log in, note your own resource IDs
 
From Account A's session:
-> Try accessing Account B's resource IDs
-> Try modifying Account B's resources
-> Try deleting Account B's resources
 
From Account B's session:
-> Confirm that those resources belong to B and are accessible to B
```

Always confirm the object exists and belongs to the other user *before* claiming IDOR  -  false positives waste everyone's time.

## Public Reports

Real-world IDOR findings across bug bounty programs:

- IDOR in HackerOne Bugs overview enabling access to private program data - [HackerOne #663431](https://hackerone.com/reports/663431)
- IDOR exposing order information on Affirm - [HackerOne #1323406](https://hackerone.com/reports/1323406)
- IDOR to view user order history on Bohemia Interactive - [HackerOne #287789](https://hackerone.com/reports/287789)
- IDOR accessing private report data via HackerOne bugs.json endpoint - [HackerOne #2487889](https://hackerone.com/reports/2487889)

## Related Pages

- [BOLA](../../../Attack-Surface/Web/Authorization/BOLA)  -  IDOR at the API/object level, with more precise framing
- [Privilege Escalation](../../../Attack-Surface/Web/Authorization/Privilege-Escalation)  -  vertical IDORs lead here
- [Multi-Tenancy](../../../Attack-Surface/Web/Authorization/Multi-Tenancy)  -  IDOR across tenant boundaries is a higher-severity variant
