> Source: https://bugbounty.info/Recon/Shodan-Censys-Fofa

# Shodan, Censys & FOFA

Three organisations have spent years scanning every routable IP on the internet, recording banners, parsing TLS certificates, and indexing what they found. Their databases are a recon shortcut that no amount of active scanning can replicate cheaply. The question isn't whether to use them  -  it's knowing the right query syntax and which engine answers which question fastest.

---

## Shodan

Shodan is the oldest and most widely known internet scan database. Its query syntax is compact and its data includes banner grabs, HTTP responses, favicons, and TLS cert metadata.

### Core Query Syntax

```bash
# Everything in an org's netblock
org:"Target Inc"
 
# All hosts serving a cert with target.com in the SAN
ssl:"target.com"
 
# Specific product version  -  good for finding unpatched instances
product:"Apache httpd" version:"2.4.49"
 
# HTTP title match  -  catches admin panels and internal tools
http.title:"Admin Panel"
http.title:"Jenkins"
http.title:"Kibana"
http.title:"Grafana"
 
# Combine them
org:"Target Inc" http.title:"Admin"
ssl:"target.com" product:"nginx" port:8443
```

### Favicon Hash Dorks

Favicons rarely change between environments. If you hash the production favicon, you can find every host serving the same app  -  including staging instances with no DNS record.

**Computing the hash:**

```python
import mmh3
import requests
import base64
 
def favicon_hash(url):
    r = requests.get(url, timeout=10)
    favicon = base64.encodebytes(r.content)
    return mmh3.hash(favicon)
 
# Usage
hash_val = favicon_hash("https://target.com/favicon.ico")
print(f"http.favicon.hash:{hash_val}")
# http.favicon.hash:-1234567890
```

```bash
# Install dependencies
pip install mmh3 requests
 
# Then search Shodan
shodan search 'http.favicon.hash:-1234567890' --fields ip_str,port,org
 
# Common hashes for known panels  -  worth checking on every target
# Jupyter Notebook: http.favicon.hash:1335394149
# phpMyAdmin:       http.favicon.hash:1531044888
# Grafana:          http.favicon.hash:-939714854
```

### Shodan CLI

```bash
# Install
pip install shodan
 
# Set API key
shodan init YOUR_API_KEY
 
# Search and output as JSON
shodan search --fields ip_str,port,org,product 'org:"Target Inc"' > shodan_results.json
 
# Count results before downloading
shodan count 'ssl:"target.com"'
 
# Get all info about a specific IP
shodan host 203.0.113.42
 
# Download full result set (uses credits)
shodan download target_results 'org:"Target Inc"'
shodan parse --fields ip_str,port,product target_results.json.gz
```

### High-Value Shodan Dorks

```bash
# Exposed internal services
org:"Target Inc" port:27017              # MongoDB
org:"Target Inc" port:9200 product:"Elastic"  # Elasticsearch
org:"Target Inc" port:6379 product:"Redis"
org:"Target Inc" port:5432 product:"PostgreSQL"
 
# Development environments
org:"Target Inc" http.title:"staging"
org:"Target Inc" ssl.cert.subject.cn:"*.staging.target.com"
 
# Cloud metadata  -  exposed instances with interesting banners
org:"Target Inc" http.html:"X-Amz-Request-Id"
 
# Default credentials / login pages
org:"Target Inc" http.html:"admin" http.status:200
```

---

## Censys

Censys runs its own scan infrastructure and indexes differently from Shodan. Its certificate data is richer, and the query language (Censys Query Language) is more structured.

### Censys Query Syntax

```bash
# Requires API key or web UI
# Install CLI
pip install censys
 
# Hosts with target.com in TLS cert
censys search 'services.tls.certificates.leaf_data.names: target.com' --index hosts
 
# Services on a specific port with banner match
censys search 'services.port=9200 and services.service_name=ELASTICSEARCH' --index hosts
 
# Filter by autonomous system
censys search 'autonomous_system.name="TARGET INC"' --index hosts
 
# Full text search across HTTP responses
censys search 'services.http.response.body="target.com" and services.port=443' --index hosts
```

```bash
# CLI usage
censys view --index hosts 203.0.113.42
censys search 'services.tls.certificates.leaf_data.subject.organization="Target Inc"' \
  --index hosts --pages 5 | jq -r '.ip' | sort -u > censys_ips.txt
```

### Censys vs Shodan

| Use Case | Better Engine |
| --- | --- |
| Certificate pivoting | Censys |
| Banner/product version | Shodan |
| HTTP response body search | Censys |
| Favicon hash search | Shodan |
| Raw IP metadata | Either |
| Historical data | Shodan |

---

## FOFA

FOFA is a Chinese internet scan engine operated by Baimaohui. Its data coverage skews heavily towards Asia-Pacific infrastructure  -  when a target operates in China, Japan, Korea, or Southeast Asia, FOFA often surfaces hosts that Shodan and Censys miss entirely.

### FOFA Query Syntax

```bash
# Basic domain search  -  finds hosts serving the domain in any context
domain="target.com"
 
# Body content match
body="target.com" && title="login"
body="Powered by Target Inc"
 
# Header search
header="X-Target-Version"
header="Server: Target-Custom/1.2"
 
# Certificate
cert="target.com"
cert.subject="Target Inc"
 
# IP range
ip="203.0.113.0/24"
 
# Combine  -  FOFA uses && and ||
domain="target.com" && country="CN"
cert="target.com" && port="8443"
```

```bash
# FOFA API  -  returns base64-encoded results
API_KEY="your_fofa_key"
EMAIL="your@email.com"
QUERY=$(echo -n 'domain="target.com"' | base64)
 
curl -s "https://fofa.info/api/v1/search/all?email=${EMAIL}&key=${API_KEY}&qbase64=${QUERY}&fields=ip,port,host,title,country&size=1000" | \
  jq -r '.results[] | @tsv'
```

### When to Use FOFA

- Target has operations in China, Japan, or South-East Asia
- Shodan shows sparse results for a large org  -  FOFA may have different scan timing
- Looking for Asia-Pacific CDN or hosting providers
- Searching for Chinese-language admin panels on international targets

---

## ZoomEye

ZoomEye is another Chinese internet scan engine. Narrower feature set than FOFA but worth a quick check.

```bash
# Web-only: zoomeye.org
# Query syntax similar to Shodan
# app:"nginx" +site:target.com
# service:"http" +site:target.com +country:"CN"
```

---

## Workflow: Combining All Three

```mermaid
graph TD
    A[Target] --> B[Shodan: org + ssl + favicon hash]
    A --> C[Censys: certificate pivot + ASN]
    A --> D[FOFA: APAC coverage + body search]
    B --> E[Shodan hits]
    C --> F[Censys hits]
    D --> G[FOFA hits]
    E --> H[Merge IPs and hosts]
    F --> H
    G --> H
    H --> I[httpx probe  -  confirm live services]
    I --> J[Screenshot with gowitness]
    J --> K[Triage: admin panels, internal tools, unusual ports]
```

---

## Practical Tips

**Don't trust rate limits.** Free Shodan searches return 100 results max. If `shodan count` shows 2,400 results, you need API credits or a creative narrowing strategy.

**Export and diff.** Run these searches at the start of a target and again two weeks later. New hosts appearing in Shodan often mean a new deployment  -  and those deployments are frequently the ones with misconfigurations from a rushed launch.

**Cross-reference with ASN data.** If your [ASN Mapping](../Recon/ASN-Mapping) work found three CIDRs, restrict your Shodan/Censys queries to those ranges to cut noise significantly.

---

## Related

- [ASN Mapping](../Recon/ASN-Mapping)  -  get CIDRs before running Shodan org queries
- [Tech Fingerprinting](../Recon/Tech-Fingerprinting)  -  Shodan product/version data feeds into tech fingerprinting
- [Certificate Transparency](../Recon/Certificate-Transparency)  -  Censys cert data overlaps with CT log queries
- [Port Scanning](../Recon/Port-Scanning)  -  verify Shodan open ports with your own scan before reporting
