> Source: https://bugbounty.info/Recon/Data-Management

# Recon Data Management

Running tools is easy. Dealing with the output isn't. A recon pipeline across 50 programs generates gigabytes of text files fast. Without a strategy for storing, querying, and deduplicating that data, you end up with a pile of flat files you can't query efficiently and no reliable way to detect what's new. This page covers how to manage recon output at scale.

## The Problems with Flat Files

The naive approach: run subfinder, pipe to a text file, grep when you need something. This works for one target. It breaks down when:

- You're running the same tools against 50 programs
- You want to find all live hosts across all programs running a specific technology
- You need to know which subdomains are new since yesterday
- You want to correlate a new CVE against your existing port scan data

Flat files don't support relational queries. When you need "show me all hosts running Apache 2.4.49 across all my programs," you need a database.

## Storage Architecture

For most researchers at scale, SQLite is enough. It's zero-config, file-based, portable, and handles millions of rows without breaking a sweat. Move to PostgreSQL only when you have multiple machines writing to the same DB or you're storing hundreds of millions of rows.

```sql
-- Core schema for recon data
 
CREATE TABLE programs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT,   -- hackerone, bugcrowd, intigriti
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
 
CREATE TABLE subdomains (
    id INTEGER PRIMARY KEY,
    program_id INTEGER REFERENCES programs(id),
    subdomain TEXT NOT NULL,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_live INTEGER DEFAULT 0,
    resolved_ip TEXT,
    UNIQUE(program_id, subdomain)
);
 
CREATE TABLE http_services (
    id INTEGER PRIMARY KEY,
    subdomain_id INTEGER REFERENCES subdomains(id),
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    tech TEXT,   -- JSON array of detected technologies
    content_length INTEGER,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(subdomain_id, url)
);
 
CREATE TABLE ports (
    id INTEGER PRIMARY KEY,
    subdomain_id INTEGER REFERENCES subdomains(id),
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    banner TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(ip, port)
);
 
CREATE TABLE js_findings (
    id INTEGER PRIMARY KEY,
    http_service_id INTEGER REFERENCES http_services(id),
    js_url TEXT,
    finding_type TEXT,  -- endpoint, secret, credential
    value TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Inserting Data: Parsing Tool Output

Most tools support JSON output. Parse it programmatically instead of grepping text.

```python
#!/usr/bin/env python3
import json
import sqlite3
import sys
from datetime import datetime
 
def insert_httpx_output(db_path, program_id, httpx_json_file):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
 
    with open(httpx_json_file) as f:
        for line in f:
            try:
                record = json.loads(line.strip())
            except json.JSONDecodeError:
                continue
 
            subdomain = record.get('host', '').split(':')[0]
            url = record.get('url', '')
            status = record.get('status-code', 0)
            title = record.get('title', '')
            tech = json.dumps(record.get('tech', []))
            content_length = record.get('content-length', 0)
            resolved_ip = record.get('a', [None])[0] if record.get('a') else None
 
            # Upsert subdomain
            cur.execute("""
                INSERT INTO subdomains (program_id, subdomain, is_live, resolved_ip, last_seen)
                VALUES (?, ?, 1, ?, ?)
                ON CONFLICT(program_id, subdomain) DO UPDATE SET
                    is_live=1, resolved_ip=excluded.resolved_ip, last_seen=excluded.last_seen
            """, (program_id, subdomain, resolved_ip, datetime.now()))
 
            sub_id = cur.execute(
                "SELECT id FROM subdomains WHERE program_id=? AND subdomain=?",
                (program_id, subdomain)
            ).fetchone()[0]
 
            # Upsert http service
            cur.execute("""
                INSERT INTO http_services (subdomain_id, url, status_code, title, tech, content_length, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(subdomain_id, url) DO UPDATE SET
                    status_code=excluded.status_code, title=excluded.title,
                    tech=excluded.tech, last_seen=excluded.last_seen
            """, (sub_id, url, status, title, tech, content_length, datetime.now()))
 
    conn.commit()
    conn.close()
 
if __name__ == "__main__":
    insert_httpx_output(sys.argv[1], int(sys.argv[2]), sys.argv[3])
```

## Delta Detection: Querying for New Findings

The whole point of storing data over time is detecting what changed. Query for new assets found since the last check.

```python
import sqlite3
from datetime import datetime, timedelta
 
def get_new_subdomains(db_path, program_id, hours=24):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
 
    cutoff = datetime.now() - timedelta(hours=hours)
 
    results = cur.execute("""
        SELECT subdomain, resolved_ip, first_seen
        FROM subdomains
        WHERE program_id = ?
          AND first_seen > ?
          AND is_live = 1
        ORDER BY first_seen DESC
    """, (program_id, cutoff)).fetchall()
 
    conn.close()
    return results
 
def get_new_http_services(db_path, program_id, hours=24):
    """New HTTP services -- interesting: might be a newly deployed app"""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cutoff = datetime.now() - timedelta(hours=hours)
 
    return cur.execute("""
        SELECT h.url, h.status_code, h.title, h.tech, s.subdomain
        FROM http_services h
        JOIN subdomains s ON h.subdomain_id = s.id
        WHERE s.program_id = ?
          AND h.last_seen > ?
        ORDER BY h.last_seen DESC
    """, (program_id, cutoff)).fetchall()
```

## Deduplication

Deduplication happens at multiple levels. Get it wrong and you either miss bugs (over-dedup) or drown in noise (under-dedup).

```python
def deduplicate_subdomains(sub_list):
    """Remove exact duplicates and obvious wildcard responses"""
    seen = set()
    deduplicated = []
 
    for sub in sub_list:
        # Normalize: lowercase, strip trailing dot
        normalized = sub.strip().lower().rstrip('.')
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduplicated.append(normalized)
 
    return deduplicated
 
 
def filter_wildcard_ips(subdomains_with_ips, threshold=10):
    """
    If more than `threshold` subdomains resolve to the same IP,
    that IP is likely a wildcard sinkhole. Filter it out.
    """
    from collections import Counter
    ip_counts = Counter(ip for _, ip in subdomains_with_ips if ip)
    wildcard_ips = {ip for ip, count in ip_counts.items() if count > threshold}
 
    return [
        (sub, ip) for sub, ip in subdomains_with_ips
        if ip not in wildcard_ips
    ]
```

## Querying at Scale

Useful queries once you have data:

```sql
-- All live hosts across all programs running a specific tech
SELECT s.subdomain, h.url, h.tech, p.name as program
FROM http_services h
JOIN subdomains s ON h.subdomain_id = s.id
JOIN programs p ON s.program_id = p.id
WHERE h.tech LIKE '%Apache%'
  AND s.is_live = 1;
 
-- Programs with the most new subdomains in last 7 days
SELECT p.name, COUNT(*) as new_subs
FROM subdomains s
JOIN programs p ON s.program_id = p.id
WHERE s.first_seen > datetime('now', '-7 days')
GROUP BY p.name
ORDER BY new_subs DESC;
 
-- Open ports by service across all targets
SELECT protocol, service, COUNT(*) as count
FROM ports
GROUP BY protocol, service
ORDER BY count DESC;
 
-- Find all hosts with port 9200 open (Elasticsearch)
SELECT s.subdomain, p.ip, p.port, p.banner, prog.name
FROM ports p
JOIN subdomains s ON p.subdomain_id = s.id
JOIN programs prog ON s.program_id = prog.id
WHERE p.port = 9200;
```

## File Organization (When You Still Need Files)

For raw tool output you're not yet importing to the DB:

```text
recon/
  target.com/
    2024-01-15/         <- date-stamped runs
      subs/
        subfinder.txt
        amass.txt
        all_subs.txt
        live_subs.txt
      http/
        httpx.json
        live_urls.txt
      ports/
        masscan.json
        nmap/
      content/
        admin.example.com.json
        api.example.com.json
      js/
        urls.txt
        endpoints.txt
        secrets.txt
    latest -> 2024-01-15/   <- symlink to most recent run
```

The symlink to `latest` means scripts can always reference `./target.com/latest/` without knowing the current date.

## Related

- [Pipeline](../Recon/Pipeline) - the pipeline that generates this data
- [Subdomain Enumeration](../Recon/Subdomain-Enumeration) - subdomain tool output formats
- [Monitoring](../Recon/Monitoring) - alerting on new findings from this data
