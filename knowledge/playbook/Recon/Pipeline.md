> Source: https://bugbounty.info/Recon/Pipeline

# Building a Recon Pipeline

A recon pipeline is tooling that runs continuously against your target list without you babysitting it. The goal: wake up every morning with fresh data. New subdomains, new ports, new paths, new JS endpoints - collected, deduplicated, and ready for manual testing. The tools aren't the hard part. Wiring them together reliably is.

## Pipeline Architecture

```mermaid
flowchart TD
    A[Target List: domains + programs] --> B[Subdomain Enumeration]
    B --> C[DNS Resolution + Validation]
    C --> D[HTTP Probing]
    D --> E[Port Scanning]
    D --> F[Content Discovery]
    D --> G[JS Analysis]
    E & F & G --> H[Output Normalization]
    H --> I[Deduplication]
    I --> J[Delta Detection: what's new?]
    J --> K{New asset found?}
    K -->|Yes| L[Alert: Slack/Discord/Telegram]
    K -->|No| M[Store to DB, continue monitoring]
    L --> N[Manual investigation queue]
```

## Stage 1: Subdomain Enumeration

Run multiple sources in parallel. No single tool covers everything.

```bash
#!/bin/bash
DOMAIN=$1
OUTPUT_DIR="./recon/$DOMAIN"
mkdir -p "$OUTPUT_DIR/subs"
 
# Passive enumeration -- runs fast, no active connections
subfinder -d "$DOMAIN" -all -silent -o "$OUTPUT_DIR/subs/subfinder.txt" &
amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/subs/amass.txt" &
assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/subs/assetfinder.txt" &
findomain --target "$DOMAIN" --quiet -u "$OUTPUT_DIR/subs/findomain.txt" &
 
# Certificate transparency
curl -s "https://crt.sh/?q=%.${DOMAIN}&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u \
  > "$OUTPUT_DIR/subs/crtsh.txt" &
 
wait
 
# Merge and deduplicate
cat "$OUTPUT_DIR/subs/"*.txt | sort -u > "$OUTPUT_DIR/subs/all_subs.txt"
wc -l "$OUTPUT_DIR/subs/all_subs.txt"
```

## Stage 2: DNS Resolution and Validation

Don't work with unresolved subdomains. Resolve first, then work with live hosts only.

```bash
# massdns for fast bulk resolution
massdns -r resolvers.txt -t A -o S \
  "$OUTPUT_DIR/subs/all_subs.txt" \
  > "$OUTPUT_DIR/subs/resolved.txt"
 
# Extract just the live hostnames
grep " A " "$OUTPUT_DIR/subs/resolved.txt" | \
  awk '{print $1}' | sed 's/\.$//' | sort -u \
  > "$OUTPUT_DIR/subs/live_subs.txt"
 
# puredns as an alternative (handles wildcard filtering)
puredns resolve "$OUTPUT_DIR/subs/all_subs.txt" \
  -r resolvers.txt \
  -w "$OUTPUT_DIR/subs/live_subs.txt"
```

Don't skip wildcard detection. Some domains resolve `*.example.com` to a sinkhole IP, making every subdomain look "live." puredns handles this. massdns doesn't.

## Stage 3: HTTP Probing

Find which live hosts are running web services and on what ports.

```bash
# httpx probes multiple ports by default and returns rich metadata
httpx -l "$OUTPUT_DIR/subs/live_subs.txt" \
  -ports 80,443,8080,8443,8888,3000,4000,5000,9000 \
  -title -tech-detect -status-code -content-length \
  -json -o "$OUTPUT_DIR/http_probe.json"
 
# Extract just URLs for downstream tools
cat "$OUTPUT_DIR/http_probe.json" | jq -r '.url' | sort -u \
  > "$OUTPUT_DIR/live_urls.txt"
```

## Stage 4: Port Scanning

Don't assume everything is on 80/443.

```bash
# Get IPs from resolved subdomains
grep " A " "$OUTPUT_DIR/subs/resolved.txt" | \
  awk '{print $3}' | sort -u > "$OUTPUT_DIR/ips.txt"
 
# Fast scan with masscan first (requires root or cap_net_raw)
masscan -iL "$OUTPUT_DIR/ips.txt" \
  -p1-65535 --rate=10000 \
  -oJ "$OUTPUT_DIR/masscan.json"
 
# Targeted nmap on open ports for service detection
# Parse masscan output to get host:port pairs
python3 parse_masscan.py "$OUTPUT_DIR/masscan.json" | \
  xargs -I{} nmap -sV -p {} --open -oA "$OUTPUT_DIR/nmap_{}" {}
```

## Stage 5: Content Discovery

Run this on all live HTTP hosts, not just the main domain.

```bash
# ffuf with a good wordlist
cat "$OUTPUT_DIR/live_urls.txt" | while read url; do
    domain=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1 | tr ':' '_')
    ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt \
      -u "${url}/FUZZ" \
      -mc 200,201,204,301,302,307,401,403 \
      -ac \
      -t 50 \
      -o "$OUTPUT_DIR/content/$domain.json" \
      -of json \
      2>/dev/null &
done
wait
```

## Stage 6: JS Analysis

JS files are where you find undocumented API endpoints, hardcoded keys, and internal tooling references.

```bash
# Collect JS URLs
cat "$OUTPUT_DIR/live_urls.txt" | \
  xargs -P10 -I{} sh -c "gau {} && waybackurls {}" | \
  grep "\.js$" | sort -u \
  > "$OUTPUT_DIR/js_urls.txt"
 
# Download and analyze with LinkFinder + secretfinder
cat "$OUTPUT_DIR/js_urls.txt" | while read jsurl; do
    curl -sk "$jsurl" >> "$OUTPUT_DIR/all_js_combined.txt"
done
 
# Extract endpoints
python3 /opt/LinkFinder/linkfinder.py \
  -i "$OUTPUT_DIR/all_js_combined.txt" \
  -o cli > "$OUTPUT_DIR/js_endpoints.txt"
 
# Extract secrets
trufflehog filesystem "$OUTPUT_DIR/all_js_combined.txt" \
  --only-verified > "$OUTPUT_DIR/js_secrets.txt"
```

## Stage 7: Delta Detection (The Whole Point)

Running recon once is useful. Running it continuously and alerting on new findings is how you get first blood on new features.

```bash
# Compare today's subdomain list to yesterday's
comm -23 \
  <(sort "$OUTPUT_DIR/subs/live_subs.txt") \
  <(sort "$OUTPUT_DIR/subs/live_subs_yesterday.txt") \
  > "$OUTPUT_DIR/new_subs_today.txt"
 
if [ -s "$OUTPUT_DIR/new_subs_today.txt" ]; then
  # Notify via Slack webhook
  NEW_COUNT=$(wc -l < "$OUTPUT_DIR/new_subs_today.txt")
  NEW_SUBS=$(cat "$OUTPUT_DIR/new_subs_today.txt" | head -10 | tr '\n' ', ')
  curl -s -X POST "$SLACK_WEBHOOK" \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"[$DOMAIN] $NEW_COUNT new subdomains: $NEW_SUBS\"}"
fi
 
# Roll files
cp "$OUTPUT_DIR/subs/live_subs.txt" "$OUTPUT_DIR/subs/live_subs_yesterday.txt"
```

## Scheduling with Cron

```bash
# Run full pipeline daily at 3am
0 3 * * * /opt/recon/pipeline.sh example.com >> /var/log/recon/example.log 2>&1
 
# Lighter subdomain-only check every 6 hours
0 */6 * * * /opt/recon/subdomain_check.sh example.com >> /var/log/recon/subs.log 2>&1
```

Or use a proper job scheduler (systemd timers, Airflow, GitHub Actions on a schedule) if you're managing multiple targets.

## Tool Dependencies

| Stage | Primary Tools | Alternates |
| --- | --- | --- |
| Subdomain | subfinder, amass, assetfinder | findomain, chaos |
| DNS resolve | puredns, massdns | dnsx |
| HTTP probe | httpx | httprobe |
| Port scan | masscan + nmap | rustscan |
| Content discovery | ffuf | feroxbuster, gobuster |
| JS analysis | LinkFinder, gau | getJS, katana |
| Secrets | trufflehog | gitleaks, SecretFinder |

## Related

- [Data Management](../Recon/Data-Management) - storing and querying the output from this pipeline
- [Subdomain Enumeration](../Recon/Subdomain-Enumeration) - deep dive on the enumeration stage
- [JavaScript Analysis](../Recon/JavaScript-Analysis) - deeper JS analysis methodology
- [Content Discovery](../Recon/Content-Discovery) - wordlist selection and tuning
