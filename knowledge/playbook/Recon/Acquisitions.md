> Source: https://bugbounty.info/Recon/Acquisitions

# Acquisitions

When a large company acquires a smaller one, the acquired company's infrastructure doesn't magically become secure. It stays on its original stack  -  often for years  -  with its original team, its original vulnerabilities, and none of the security controls the acquirer might have on their main product. This is one of the most consistently overlooked edges in bug bounty.

---

## Why Acquisitions Matter for Bug Hunters

The program scope says `*.bigcorp.com`. BigCorp acquired StartupCo two years ago. StartupCo still runs on `*.startupco.com` and `*.startup-app.io`  -  but those domains are now BigCorp infrastructure, and they're in scope under the acquisition. Fewer hunters tested them. The team maintaining them is smaller. The security budget didn't follow the acquisition.

I've found critical SQLi, SSRF, and account takeovers on acquired infrastructure that had zero bug bounty history.

---

## Finding Acquisition History

### Crunchbase

Crunchbase is the most complete acquisition database. Free tier gets you a lot.

```bash
# Search approach
1. Go to crunchbase.com
2. Search for target company
3. Click "Acquisitions" tab on their profile
4. List every acquired company with dates
 
# Or use the API
curl -s "https://api.crunchbase.com/api/v4/entities/organizations/bigcorp/cards/acquiree_acquisitions?user_key=YOUR_KEY" | \
  jq '.cards.acquiree_acquisitions[] | {acquired: .acquiree_identifier.value, date: .announced_on}'
```

### News and Press Releases

```bash
# Google dork for acquisition announcements
site:businesswire.com OR site:prnewswire.com "bigcorp" "acquires" OR "acquisition"
 
# Also check
site:techcrunch.com bigcorp acquisition
site:sec.gov bigcorp merger  # Public companies file 8-K for acquisitions
```

### LinkedIn

"Company: StartupCo" profiles that now say "Acquired by BigCorp"  -  and the employees' current employer listed as BigCorp. This tells you the acquisition is recent and the infrastructure may still be transitioning.

---

## Finding Acquired Company Infrastructure

Once you have a list of acquisitions, treat each acquired company as a sub-target.

```bash
# For each acquired company, run your standard recon
ACQUIRED="startupco.com"
 
# Subdomain enumeration on the acquired domain
subfinder -d $ACQUIRED -silent -all -o startupco_subs.txt
chaos -d $ACQUIRED -silent -o startupco_chaos.txt
puredns bruteforce /opt/wordlists/dns/combined.txt $ACQUIRED -r resolvers.txt -w startupco_brute.txt
 
# Certificate transparency  -  often reveals ALL their old infra
curl -s "https://crt.sh/?q=%25.$ACQUIRED&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > startupco_certs.txt
```

### Cross-Domain Correlation

Acquired infrastructure often links back to the main company in ways that help you confirm it's in-scope.

```bash
# Look for bigcorp references in startupco's DNS/HTTP responses
httpx -l startupco_subs.txt -silent -title -H "User-Agent: Mozilla/5.0" | \
  grep -i "bigcorp\|bigcorporation"
 
# Check NS records  -  if they moved DNS management to bigcorp's registrar
for sub in $(cat startupco_subs.txt); do
  ns=$(dig +short NS $sub 2>/dev/null)
  echo "$sub NS: $ns"
done | grep -i "bigcorp\|bigdns"
 
# Check SSL cert issuer  -  shared cert infrastructure
echo | openssl s_client -connect startupco.com:443 2>/dev/null | \
  openssl x509 -noout -issuer -subject -san
```

---

## ASN and IP Range Cross-Reference

If bigcorp and startupco share IP ranges, that confirms the infrastructure migration.

```bash
# Get bigcorp's ASN
whois target.com | grep -i "org-name\|orgname\|owner"
 
# Alternatively
curl -s "https://ipinfo.io/$(dig +short target.com)/org"
 
# Find all IPs in that ASN
curl -s "https://api.bgpview.io/asn/AS12345/prefixes" | \
  jq -r '.data.ipv4_prefixes[].prefix'
 
# Check if startupco's IPs fall in the same ranges
for ip in $(dig +short +all startupco.com); do
  curl -s "https://ipinfo.io/$ip/org"
done
```

---

## Checking Scope Coverage

Before spending time on acquired infrastructure, confirm it's in scope. Programs handle this differently.

**Explicit inclusion**: Scope says `*.bigcorp.com AND all acquired subsidiaries`  -  you're clear.

**Implicit inclusion**: Scope says `all assets owned and operated by BigCorp, Inc.`  -  if you can show the acquisition and the infrastructure ownership, you're likely covered. Ask before reporting if unsure.

**Not included**: Some programs explicitly exclude certain subsidiaries. Read the scope carefully.

```bash
# A quick WHOIS check to confirm ownership
whois startupco.com | grep -E "(Registrant|Organization|Email)" | head -10
 
# Check if they redirect to the main domain
curl -sI https://startupco.com | grep "Location"
```

---

## The Acquisition Recon Workflow

```mermaid
graph TD
    A[Target Company] --> B[Crunchbase acquisition search]
    A --> C[News/press release search]
    B --> D[List of acquired companies]
    C --> D
    D --> E[For each acquisition]
    E --> F[Subdomain enum on acquired domain]
    E --> G[crt.sh certificate history]
    E --> H[ASN / IP range check]
    F --> I[Merge with main target recon]
    G --> I
    H --> I
    I --> J[Confirm in-scope with program]
    J --> K[Test acquired infra as new surface]
```

---

## What to Look For on Acquired Infra

Acquired companies typically have weaker security posture than the acquirer's main product. Target these specifically:

- **Outdated software**  -  old frameworks, unpatched CMS installations
- **Legacy APIs**  -  the startup's original API before they had a security team
- **SSO integration gaps**  -  are they using bigcorp's SSO or still their own auth?
- **Shared secrets**  -  credentials that work across both environments
- **Exposed admin panels**  -  startups often have less hardened admin infra

```bash
# Quick tech fingerprint on acquired domains
httpx -l acquired_live_hosts.txt -silent -tech-detect -title -status-code | \
  grep -E "(WordPress|Drupal|Laravel|Rails|Django|struts)" | \
  awk '{print $1}' > acquired_interesting.txt
 
# Check for outdated software versions
whatweb -i acquired_live_hosts.txt --log-brief acquired_tech.txt
```

---

## Related

- [Subdomain Enumeration](../Recon/Subdomain-Enumeration)  -  run the full pipeline on each acquired domain
- [Monitoring](../Recon/Monitoring)  -  add acquired domains to your continuous monitoring
- [GitHub Dorking](../Recon/GitHub-Dorking)  -  acquired company's GitHub org often has loose code
- [Cloud Range Discovery](../Recon/Cloud-Range-Discovery)  -  acquired companies frequently have orphaned cloud assets
