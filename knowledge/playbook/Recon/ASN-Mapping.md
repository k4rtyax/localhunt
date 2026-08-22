> Source: https://bugbounty.info/Recon/ASN-Mapping

# ASN Mapping

Most hunters start with a domain name. ASN mapping starts with a company name and works down to raw IP space  -  blocks of addresses that host infrastructure without any DNS entry pointing at them. These are the assets nobody else is testing because they never show up in subdomain enumeration.

---

## Why DNS Isn't Enough

Subdomain enumeration finds what's in DNS. IP ranges contain what's on the network. Dev boxen, internal-facing services accidentally reachable from the internet, acquired infrastructure still on the old network, staging environments with no DNS record. A company can have hundreds of live IPs with open HTTP ports and zero publicly registered hostnames. ASN mapping finds those.

---

## Step 1: Company Name to ASN

### BGPView  -  Start Here

```bash
# Web API  -  no key required
curl -s "https://api.bgpview.io/search?query_term=Target+Inc" | \
  jq '.data.asns[] | {asn: .asn, name: .name, description: .description}'
 
# Example output shape:
# {
#   "asn": 12345,
#   "name": "TARGET-INC",
#   "description": "Target Inc, US"
# }
```

### metabigor

```bash
# Install
go install github.com/j3ssie/metabigor@latest
 
# Org name to ASN
echo "Target Inc" | metabigor net --org -o asns.txt
 
# Output shape:
# AS12345 | TARGET-INC | Target Inc
# AS67890 | TARGET-CDN | Target content delivery
```

### amass intel

```bash
# amass has a built-in org lookup that returns ASNs
amass intel -org "Target Inc" -o amass_asns.txt
 
# Also works with -asn to expand from a known ASN
amass intel -asn 12345 -o amass_prefixes.txt
```

### asnlookup

```bash
# asnlookup.com  -  paste-friendly web UI or API
curl -s "https://asnlookup.com/api/lookup?org=Target+Inc" | \
  jq '.[] | {asn: .asn, cidr: .cidr}'
```

---

## Step 2: ASN to CIDR Ranges

Once you have one or more ASNs, pull all the IP prefixes they announce.

```bash
# BGPView  -  most reliable for this
ASN=12345
curl -s "https://api.bgpview.io/asn/AS${ASN}/prefixes" | \
  jq -r '.data.ipv4_prefixes[].prefix' > cidr_ranges.txt
 
# Output shape:
# 203.0.113.0/24
# 198.51.100.0/22
# 192.0.2.0/23
 
# Combine multiple ASNs
for asn in 12345 67890 11111; do
  curl -s "https://api.bgpview.io/asn/AS${asn}/prefixes" | \
    jq -r '.data.ipv4_prefixes[].prefix'
done | sort -u > all_cidrs.txt
 
wc -l all_cidrs.txt
# 14 all_cidrs.txt
```

### whoisxmlapi

Useful when the company name has noise  -  it does fuzzy matching and returns structured WHOIS data for each prefix.

```bash
curl -s "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=YOUR_KEY&domainName=targetinc&outputFormat=json" | \
  jq '.WhoisRecord.registryData'
```

---

## Step 3: Feed CIDRs Into Port Scanners

This is the payoff. Scan the IP space directly.

```bash
# masscan  -  fast sweep across a /22
# Requires root or cap_net_raw
masscan -iL all_cidrs.txt \
  -p80,443,8080,8443,8888,3000,4000,5000,9000,9443,22,21,25 \
  --rate=5000 \
  -oJ asn_masscan.json
 
# naabu  -  lower noise alternative, integrates with nmap
cat all_cidrs.txt | naabu -top-ports 1000 -o naabu_open.txt
 
# httpx on discovered open web ports
cat naabu_open.txt | httpx -silent -title -status-code -tech-detect \
  -o asn_web_hosts.txt
```

---

## Reading the Results

The IPs you find fall into a few buckets:

- **Live web service, no hostname** - probe with httpx, screenshot with gowitness, look for admin panels, internal tools, and dev environments
- **Resolves to a known subdomain** - confirms scope, less interesting
- **Resolves to an unknown subdomain** - add it to your subdomain list, it was never in DNS enumeration
- **Ports open but no HTTP** - check for SSH, FTP, SMTP, database ports depending on program scope

```bash
# Find IPs with open ports that have no PTR record (no reverse DNS)
# These are your most likely "forgotten" assets
while read ip; do
  ptr=$(dig +short -x "$ip" 2>/dev/null)
  if [ -z "$ptr" ]; then
    echo "No PTR: $ip"
  fi
done < discovered_ips.txt
```

---

## ASN Mapping Workflow

```mermaid
graph TD
    A[Company Name] --> B[BGPView / metabigor search]
    A --> C[amass intel -org]
    B --> D[ASN list]
    C --> D
    D --> E[BGPView  -  ASN to CIDR prefixes]
    E --> F[all_cidrs.txt]
    F --> G[masscan  -  fast port sweep]
    G --> H[naabu + httpx  -  web service probe]
    H --> I[IPs with no PTR record]
    H --> J[IPs with unexpected services]
    I --> K[Manual investigation]
    J --> K
```

---

## Common Pitfalls

**CDN inflation**: Large companies use Cloudflare, Akamai, Fastly. Their ASN lookup may return CDN ranges, not company ranges. Cross-reference multiple ASNs and discard obvious CDN providers.

**Shared hosting**: /24 ranges don't always mean the whole block belongs to the target. Confirm ownership with WHOIS on individual IPs before spending time on them.

**Rate limiting**: BGPView and similar APIs rate-limit aggressively. Cache your results  -  there's no point re-fetching the same ASN prefix list every run.

---

## Related

- [Port Scanning](../Recon/Port-Scanning)  -  after you have CIDRs, this is the next step
- [Acquisitions](../Recon/Acquisitions)  -  acquired companies often retain their original ASNs
- [Subdomain Enumeration](../Recon/Subdomain-Enumeration)  -  correlate ASN IPs against your subdomain list
- [Cloud Range Discovery](../Recon/Cloud-Range-Discovery)  -  some cloud IPs fall outside standard ASN lookups
