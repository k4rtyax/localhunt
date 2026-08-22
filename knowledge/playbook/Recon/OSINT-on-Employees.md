> Source: https://bugbounty.info/Recon/OSINT-on-Employees

# OSINT on Employees

The engineering and security teams at a target company are a public map of their technology decisions. Their LinkedIn profiles, GitHub activity, conference talks, and leaked credential databases tell you what stack they run, what tooling they use internally, and sometimes hand you credentials that are still valid. This is not social engineering  -  it's passive intelligence gathering on publicly available information.

---

## LinkedIn: Mapping the Tech Stack

Job postings and employee profiles reveal more about a company's internal infrastructure than most security documents.

```bash
# Manual search patterns
# Search: site:linkedin.com "Target Inc" "software engineer"
# Look at tech listed in job descriptions and employee summaries:
#   - Framework versions ("migrating from Rails 5 to 7")
#   - Infrastructure ("Kubernetes on GKE", "HashiCorp Vault")
#   - Internal tooling names that appear in multiple profiles
#   - Security team specialisations (what they defend tells you what exists)
 
# Google-assisted LinkedIn recon
site:linkedin.com/in/ "Target Inc" "engineer" "kubernetes"
site:linkedin.com/in/ "Target Inc" "backend" "python" "aws"
 
# Job postings reveal stack detail too
site:linkedin.com/jobs/ "Target Inc" "senior backend"
```

What to note:

- Teams using Vault/Terraform/Ansible  -  secrets management and IaC exist
- Teams mentioning "internal platform" or "developer portal"  -  likely a self-hosted tool
- Security engineer specialisations  -  AppSec vs cloud vs identity tells you where they focus

---

## Employee GitHub Profiles

Employees who work on open source or push personal projects often reference internal hostnames, internal tooling names, and architecture decisions.

```bash
# Find employee GitHub handles
# 1. LinkedIn -> profile -> check for GitHub link
# 2. GitHub search: "Target Inc" in profile
# 3. Search for commits referencing target.com domain
 
# GitHub search for employees mentioning the company
# (web UI)  -  filter: type:users + "Target Inc" in bio
 
# Once you have handles, look at:
# - Public repos with target.com references
# - Stars  -  what tools do they use personally
# - Gists  -  often contain snippets from work projects
 
# For a known handle
curl -s "https://api.github.com/users/employeehandle/repos?per_page=100" | \
  jq -r '.[].full_name'
 
# Search gists
curl -s "https://api.github.com/users/employeehandle/gists?per_page=100" | \
  jq -r '.[].files | to_entries[].value.filename'
```

---

## Breach Databases: Leaked Credentials

Employees reuse passwords. A credential from a 2018 breach of an unrelated service may still work on the company's VPN, Okta, or admin panel today.

```bash
# HaveIBeenPwned API  -  check if a known email address is in breach data
EMAIL="employee@target.com"
API_KEY="YOUR_HIBP_KEY"
 
curl -s -H "hibp-api-key: $API_KEY" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/${EMAIL}" | \
  jq -r '.[].Name'
 
# IntelX API  -  has credential pairs (email:password from breaches)
curl -s "https://2.intelx.io/phonebook/search" \
  -H "X-Key: YOUR_INTELX_KEY" \
  -d '{"term":"@target.com","buckets":[],"lookuplevel":0,"maxresults":100,"timeout":0,"datefrom":"","dateto":"","sort":4,"media":0,"terminate":[]}' | \
  jq -r '.selectors[].selectorvalue'
 
# dehashed.com (paid)  -  search by email domain to get all breached accounts
# API: curl -u email:apikey "https://api.dehashed.com/search?query=email:@target.com"
```

Once you have a credential, checking validity is straightforward  -  try it against the login page. Do not use it to access data. A successful authentication response is enough for a valid report.

---

## Username Enumeration Across Platforms

The same handle across platforms builds a picture of what an employee worked on before joining, what tools they personally prefer, and sometimes surfaces private repos or old forum posts.

```bash
# sherlock  -  checks 300+ platforms
pip install sherlock-project
sherlock employeehandle --timeout 10 --output sherlock_results.txt
 
# whatsmyname (broader database)
git clone https://github.com/WebBreacher/WhatsMyName
cd WhatsMyName
python3 whatsmyname.py -u employeehandle -o whatsmyname_results.txt
 
# Interesting platforms to check manually:
# - HackerNews: news.ycombinator.com/user?id=handle
# - Dev.to, Medium: articles may reference internal projects
# - Keybase: public key associations + other account links
# - Speakerdeck / Slideshare: conference talks often contain architecture diagrams
```

---

## Slack and Discord Presence

Lots of companies have public or semi-public Slack/Discord communities. Employees in those spaces sometimes reference internal issues, tooling, or architecture.

```bash
# Look for community Slack invites
site:target.com slack.com/join
"target.com" "slack.com/join" inurl:t=
 
# Developer Discord servers  -  search for target company name
# Employees may discuss architecture in public open-source channels
 
# Search for leaked Slack tokens in GitHub
# (see GitHub Dorking page)
"xoxb-" "target" OR "target.com"
"xoxp-" site:github.com "target.com"
```

---

## Employee OSINT Workflow

```mermaid
graph TD
    A[Target Company] --> B[LinkedIn  -  engineering team mapping]
    A --> C[GitHub  -  employee handle search]
    B --> D[Tech stack signals]
    B --> E[Employee email format  -  firstname.lastname@target.com]
    C --> F[Personal repos / gists referencing internal tools]
    E --> G[HIBP + IntelX  -  breach lookup by email domain]
    F --> H[Internal hostnames and tooling names]
    G --> I[Credential pairs]
    H --> J[Add to recon scope]
    I --> K[Test against VPN / Okta / login portals]
    D --> L[Informs tech fingerprinting and wordlist selection]
```

---

## What This Is Not

This page is about understanding the attack surface through passive intelligence gathering. It is not about:

- Contacting or impersonating employees
- Using credentials to access systems beyond authentication confirmation
- Accessing private data even if an account logs in successfully

When you find valid credentials, document the source, confirm they authenticate (one request, observe the response), and report. The value is in demonstrating the credential works  -  not in what you do with the access.

---

## Related

- [GitHub Dorking](../Recon/GitHub-Dorking)  -  employee repos are a primary target
- [SaaS Enumeration](../Recon/SaaS-Enumeration)  -  knowing which SaaS platforms employees use narrows your SaaS search
- [Acquisitions](../Recon/Acquisitions)  -  former employees of acquired companies often retain access longer than expected
