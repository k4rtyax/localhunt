> Source: https://bugbounty.info/Recon/Tech-Fingerprinting

# Tech Fingerprinting

Knowing the stack isn't a nice-to-have. It's how you decide which of the 50 live hosts in your recon output is worth testing first. A host running Struts 2.5.10 is a different conversation than a host running a modern Go microservice. Fingerprinting gives you that triage signal before you touch the app.

---

## httpx  -  Fast First Pass

httpx with `-tech-detect` runs Wappalyzer's detection engine against every response in one shot. Run it across your full live host list.

```bash
# Tech detection across all live hosts
httpx -l live_hosts.txt \
  -tech-detect \
  -title \
  -status-code \
  -content-length \
  -server \
  -silent \
  -o tech_results.json \
  -json
 
# Parse out just the tech field
cat tech_results.json | jq -r '[.url, (.technologies // [] | join(", "))] | @tsv'
 
# Filter for specific stacks worth investigating
cat tech_results.json | jq -r 'select(.technologies[]? | test("WordPress|Drupal|Laravel|Struts")) | .url'
 
# Example output shape:
# https://api.target.com          Spring Boot, Java, Apache Tomcat
# https://blog.target.com         WordPress 6.1, PHP 8.0, MySQL
# https://legacy.target.com       PHP 5.6, Apache 2.2  <-- interesting
```

---

## whatweb

whatweb does active fingerprinting and returns more granular version data than httpx in many cases.

```bash
# Single target
whatweb https://target.com -v
 
# File of targets
whatweb -i live_hosts.txt --log-brief=whatweb_results.txt
 
# Aggressive mode  -  more requests, more detail
whatweb https://target.com -a 3
 
# Output JSON for parsing
whatweb https://target.com -a 3 --log-json=whatweb.json
 
# Example output:
# https://target.com [200 OK] Apache[2.4.41], Bootstrap[4.5.2],
#   Cookies[PHPSESSID], Country[US], HTTPServer[Apache/2.4.41 (Ubuntu)],
#   IP[203.0.113.42], PHP[7.4.3], Title[Target Inc - Dashboard]
```

---

## Wappalyzer CLI

```bash
# Install
npm install -g wappalyzer
 
# Analyse a URL
wappalyzer https://target.com --pretty
 
# Output shape:
# {
#   "urls": { "https://target.com/": { "status": 200 } },
#   "technologies": [
#     { "name": "React", "version": "18.2.0", "categories": ["JavaScript frameworks"] },
#     { "name": "Webpack", "version": "", "categories": ["Miscellaneous"] },
#     { "name": "Nginx", "version": "1.20.1", "categories": ["Web servers"] }
#   ]
# }
```

---

## Header Fingerprinting

Response headers leak stack information even when a site tries to hide it.

```bash
# Grab headers from a host
curl -sI https://target.com | grep -iE "(server|x-powered-by|x-aspnet-version|x-generator|via|x-cache|cf-ray|x-amz|x-goog)"
 
# Interesting header patterns:
# Server: Apache/2.4.41  -  direct version disclosure
# X-Powered-By: PHP/7.4.3  -  direct PHP version
# X-Powered-By: ASP.NET  -  .NET without version (hardened)
# Via: 1.1 vegur  -  Heroku
# X-Served-By: cache-syd10125-SYD  -  Fastly CDN
# CF-Ray: 7abc123-SYD  -  Cloudflare
# X-Amz-Request-Id:  -  AWS origin
# X-Amz-Cf-Id:  -  CloudFront
 
# CDN indicator: important because WAF is likely present too
# Check if origin is reachable directly (bypasses WAF)
curl -sI https://203.0.113.42 -H "Host: target.com"
```

---

## Nuclei Technology Templates

Nuclei has a dedicated technology detection template library that catches specific versions and misconfigurations.

```bash
# Run all technology detection templates
nuclei -l live_hosts.txt \
  -t http/technologies/ \
  -silent \
  -o nuclei_tech.txt
 
# Specific tech categories
nuclei -l live_hosts.txt \
  -t http/technologies/wordpress/ \
  -o nuclei_wp.txt
 
nuclei -l live_hosts.txt \
  -t http/technologies/spring/ \
  -t http/technologies/java/ \
  -o nuclei_java.txt
 
# Exposed panels and admin interfaces
nuclei -l live_hosts.txt \
  -t http/exposed-panels/ \
  -silent \
  -o exposed_panels.txt
```

---

## Favicon Hashing for Tech Detection

Same technique as in [Shodan Censys Fofa](../Recon/Shodan-Censys-Fofa)  -  the hash identifies the framework or product, not just the company.

```bash
# Known hashes  -  check against your targets
# Jenkins:      http.favicon.hash:81586312
# Grafana:      http.favicon.hash:-939714854
# Kibana:       http.favicon.hash:-1438785029
# phpMyAdmin:   http.favicon.hash:1531044888
# Jupyter:      http.favicon.hash:1335394149
# GitLab:       http.favicon.hash:1278323681
# Jira:         http.favicon.hash:-1399890347
 
# Compute a hash from a live target's favicon
python3 -c "
import mmh3, requests, base64
r = requests.get('https://target.com/favicon.ico', timeout=10)
h = mmh3.hash(base64.encodebytes(r.content))
print(f'Favicon hash: {h}')
"
```

---

## Mapping Tech to CVEs

Once you know the stack, look for known vulnerabilities before spending time on manual testing.

```bash
# Search vulners.com via their API
PRODUCT="Apache Tomcat"
VERSION="9.0.56"
curl -s "https://vulners.com/api/v3/search/lucene/?query=${PRODUCT}+${VERSION}&skip=0&size=10" | \
  jq -r '.data.search[] | [.id, .cvss.score, .title] | @tsv' | sort -t$'\t' -k2 -rn | head -10
 
# Nuclei CVE templates  -  run after you know the tech
nuclei -l live_hosts.txt \
  -t http/cves/ \
  -tags apache,tomcat \
  -silent \
  -o cve_hits.txt
 
# Search for public PoCs on a specific version
# GitHub dork: "CVE-2021-XXXX" "Apache Tomcat 9.0.56"
```

---

## Fingerprint Workflow

```mermaid
graph TD
    A[Live Host List] --> B[httpx -tech-detect]
    A --> C[Header analysis  -  curl -sI]
    B --> D[Tech stack per host]
    C --> D
    D --> E{Interesting tech found?}
    E -->|Old version| F[Search vulners / NVD]
    E -->|Admin panel| G[nuclei exposed-panels]
    E -->|Known framework| H[nuclei CVE templates for that tech]
    F --> I[Prioritise hosts with known CVEs]
    G --> I
    H --> I
    I --> J[Manual investigation]
```

---

## Common Pitfalls

**Version headers can lie.** Some ops teams change `Server:` headers to mislead scanners. whatweb's full response analysis  -  parsing JS library versions from HTML  -  is often more reliable than a single header.

**CDN masking.** If Cloudflare or Akamai is in the path, the tech stack you see is the CDN's, not the origin's. Use [Shodan Censys Fofa](../Recon/Shodan-Censys-Fofa) to find the real origin IP and probe that directly.

**Don't nuclei-blast without calibrating.** Run `nuclei -l hosts.txt -t http/technologies/ -stats` first to see volume. On a target with 400 live hosts, a full CVE template run will generate noise  -  filter by relevant technology tags.

---

## Related

- [Shodan Censys Fofa](../Recon/Shodan-Censys-Fofa)  -  favicon hashes and product version queries
- [Content Discovery](../Recon/Content-Discovery)  -  tech stack determines which wordlist to use
- [Port Scanning](../Recon/Port-Scanning)  -  non-HTTP ports also reveal stack info
- [JavaScript Analysis](../Recon/JavaScript-Analysis)  -  framework version often visible in bundled JS
