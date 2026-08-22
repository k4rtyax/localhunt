> Source: https://bugbounty.info/Recon/SaaS-Enumeration

# SaaS Enumeration

The company's main domain might be locked down tight. Their Zendesk instance  -  provisioned three years ago by someone who left  -  is a different story. Every organisation running at scale has a constellation of third-party SaaS platforms, each with its own subdomain, its own configuration surface, and its own class of misconfigurations. Enumerating these is one of the highest-return moves in scope-adjacent recon.

---

## Why SaaS Platforms Matter

These platforms sit outside the normal security review cycle. They're provisioned by product or customer success teams, not engineering. They authenticate with their own user systems. They often expose customer data, support tickets, or internal records to unauthenticated users because a checkbox was left in the wrong position during setup.

---

## Common Platforms and Their Fingerprints

### Zendesk

```bash
# Default subdomain pattern
# https://target.zendesk.com
 
# Check if open  -  unauthenticated ticket submission exposed
curl -s -o /dev/null -w "%{http_code}" https://target.zendesk.com/hc/en-us
 
# Known misconfigurations:
# - "Help Centre" search leaks private internal tickets
# - Zendesk email-based ticketing accepts submissions from any address
# - /api/v2/users.json exposed (returns customer list)
curl -s "https://target.zendesk.com/api/v2/users.json" | jq '.users[].email' 2>/dev/null
```

### Salesforce Communities

```bash
# Common URL patterns
# https://target.my.salesforce.com
# https://target.force.com
# https://targetcommunity.force.com
# https://help.target.com (custom domain pointing to SF)
 
# Guest record exposure check  -  the classic SFDC community misconfiguration
# If the community allows guest access, try hitting object APIs without auth
curl -s "https://target.my.salesforce.com/services/data/v52.0/sobjects/" \
  -H "Authorization: Bearer GUEST_TOKEN_FROM_COMMUNITY_INIT"
 
# Find SFDC community pages
curl -s "https://target.my.salesforce.com/sfsites/picasso/core/config/app.css" | \
  grep -o "aura_app_[a-zA-Z0-9]*"
```

### ServiceNow

```bash
# Pattern: customername.service-now.com
# Check for public widget access (unauthenticated)
curl -s -o /dev/null -w "%{http_code}" \
  "https://target.service-now.com/sp"
 
# Public REST API check  -  sometimes returns records without auth
curl -s "https://target.service-now.com/api/now/table/sys_user?sysparm_limit=5" | \
  jq '.result[].name' 2>/dev/null
 
# Check for exposed knowledge base
curl -s "https://target.service-now.com/kb" -o /dev/null -w "%{http_code}\n"
```

### Atlassian (JIRA & Confluence)

```bash
# JIRA Cloud pattern
# https://target.atlassian.net/jira
 
# Confluence Cloud
# https://target.atlassian.net/wiki
 
# Check for public issue access
curl -s "https://target.atlassian.net/rest/api/2/project" | jq '.[].key'
 
# Confluence public spaces  -  often contain internal documentation
curl -s "https://target.atlassian.net/wiki/rest/api/space?limit=50" | \
  jq -r '.results[] | select(.type=="global") | [.key, .name] | @tsv'
 
# Self-hosted JIRA: look for these during port scanning
# Default port 8080, path /jira  or /
# nuclei has templates for JIRA CVEs  -  use them
nuclei -u https://jira.target.com -t http/cves/2019/CVE-2019-8449.yaml
```

### HubSpot

```bash
# HubSpot forms leak internal form IDs and portal IDs
# Check page source on marketing pages
curl -s https://target.com | grep -oE "portalId['\"]?:['\"]?[0-9]+" | head -5
 
# Forms API  -  public
PORTAL_ID=12345
curl -s "https://api.hsforms.com/submissions/v3/integration/submit/${PORTAL_ID}/" | head -20
 
# Sometimes the portal has a full public API exposed
curl -s "https://api.hubapi.com/contacts/v1/lists/all/contacts/all?hapikey=LEAKED_KEY"
```

### Okta

```bash
# Okta tenant discovery
# https://target.okta.com
# https://target.okta.com/.well-known/openid-configuration  -  reveals IdP config
 
# Check for username enumeration
curl -s "https://target.okta.com/api/v1/authn" \
  -H "Content-Type: application/json" \
  -d '{"username":"test@target.com","password":"invalid"}' | \
  jq '.errorCode'
# "E0000095" = account locked (user exists)
# "E0000095" vs "E0000095" differences can enumerate users
 
# Okta misconfiguration: open registration
curl -s "https://target.okta.com/login/register" -o /dev/null -w "%{http_code}\n"
```

---

## Enumeration Approach

```bash
# Build a candidate list of SaaS subdomains to check
TARGET="target"
for platform in \
  "${TARGET}.zendesk.com" \
  "${TARGET}.my.salesforce.com" \
  "${TARGET}.force.com" \
  "${TARGET}.service-now.com" \
  "${TARGET}.atlassian.net" \
  "${TARGET}.okta.com" \
  "${TARGET}.okta.com/login" \
  "${TARGET}.sharepoint.com" \
  "${TARGET}.freshdesk.com" \
  "${TARGET}.freshservice.com" \
  "${TARGET}.intercom.io" \
  "${TARGET}.hubspot.com" \
  "${TARGET}.desk.com" \
  "${TARGET}.helpscout.net"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$platform")
  echo "$status $platform"
done | grep -v "^[04][0-9][0-9]"
 
# httpx over the list for richer output
echo "${TARGET}.zendesk.com
${TARGET}.atlassian.net
${TARGET}.service-now.com" | httpx -silent -title -status-code -tech-detect
```

---

## SaaS Enumeration Workflow

```mermaid
graph TD
    A[Target Company Name] --> B[Build candidate SaaS subdomain list]
    B --> C[httpx probe  -  check which resolve + respond]
    C --> D{Platform found?}
    D -->|Zendesk| E[Check help centre search + API endpoints]
    D -->|Salesforce| F[Check community guest access + sobjects]
    D -->|ServiceNow| G[Check public portal + REST API auth]
    D -->|Atlassian| H[Check public projects + Confluence spaces]
    D -->|Okta| I[Check registration + user enumeration]
    E --> J[Document findings and test authentication gaps]
    F --> J
    G --> J
    H --> J
    I --> J
```

---

## Related

- [Subdomain Enumeration](../Recon/Subdomain-Enumeration)  -  custom-domain SaaS instances sometimes appear in CT logs
- [OSINT on Employees](../Recon/OSINT-on-Employees)  -  LinkedIn job descriptions reveal which platforms a company uses
- [Tech Fingerprinting](../Recon/Tech-Fingerprinting)  -  SaaS platforms have their own CVE history
- [API Documentation Discovery](../Recon/API-Documentation-Discovery)  -  JIRA and ServiceNow have extensive public API docs
