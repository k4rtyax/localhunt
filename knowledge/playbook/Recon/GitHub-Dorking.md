> Source: https://bugbounty.info/Recon/GitHub-Dorking

# GitHub Dorking

GitHub is an unintentional secrets vault for a shocking number of companies. Developers commit keys and move on. The key gets rotated eventually  -  maybe  -  but the old code, the internal paths, the config structure, the infrastructure naming conventions? That stuff stays searchable for years. I've found live production credentials in public repos more times than I can count.

---

## Why This Works

- Developers accidentally commit `.env` files, config files, credentials
- CI/CD configs expose internal hostnames and service names
- Old branches and forks contain code that was "deleted" from main
- Third-party contractors commit client code to personal repos
- Employees push work to personal accounts

---

## GitHub Search Syntax That Matters

```bash
# Exact org search  -  everything in a company's org
org:targetcorp
 
# Specific filename
filename:.env
filename:config.yml
filename:database.yml
filename:credentials.json
 
# File extension
extension:pem
extension:key
extension:pfx
extension:p12
 
# Content search
"target.com" password
"target.com" api_key
"internal.target.com"
 
# Combine them
org:targetcorp filename:.env
org:targetcorp extension:pem
org:targetcorp "BEGIN RSA PRIVATE KEY"
```

---

## High-Value Dork Queries

Copy-paste these with your target name substituted in.

```bash
# Credentials and secrets
org:TARGETCORP password
org:TARGETCORP secret_key
org:TARGETCORP api_key
org:TARGETCORP "-----BEGIN RSA PRIVATE KEY-----"
org:TARGETCORP "-----BEGIN OPENSSH PRIVATE KEY-----"
org:TARGETCORP aws_access_key_id
org:TARGETCORP AWS_SECRET_ACCESS_KEY
org:TARGETCORP STRIPE_SECRET
org:TARGETCORP "jdbc:mysql://"
org:TARGETCORP "jdbc:postgresql://"
 
# Internal infrastructure
org:TARGETCORP internal.targetcorp.com
org:TARGETCORP staging.targetcorp.com
org:TARGETCORP "10.0.0." OR "192.168." OR "172.16."
org:TARGETCORP vpn
 
# Config files
org:TARGETCORP filename:.env
org:TARGETCORP filename:config.php
org:TARGETCORP filename:database.yml
org:TARGETCORP filename:settings.py
org:TARGETCORP filename:application.properties
org:TARGETCORP filename:web.config
org:TARGETCORP filename:docker-compose.yml
org:TARGETCORP filename:.npmrc
org:TARGETCORP filename:.pypirc
org:TARGETCORP filename:credentials
 
# Leaked files from CI/CD
org:TARGETCORP filename:.travis.yml
org:TARGETCORP filename:.circleci/config.yml
org:TARGETCORP filename:Jenkinsfile
org:TARGETCORP filename:.github/workflows
```

---

## Searching Beyond the Official Org

Many companies have code outside their official org. Contractors, employees, forks.

```bash
# Search by target domain across all of GitHub
"target.com" filename:.env
"target.com" api_key
"api.target.com" key
"@target.com" password
"target.com" "-----BEGIN"
 
# Look for employees' personal repos
# Find employee names/handles from LinkedIn, then:
user:employeehandle target
```

---

## Tools for Automated GitHub Dorking

### trufflehog

trufflehog scans repos for secrets using regex patterns and Shannon entropy analysis  -  finds things that look like keys even without keyword context.

```bash
# Scan a whole org
trufflehog github --org=targetcorp --token=YOUR_GITHUB_TOKEN
 
# Scan a specific repo
trufflehog github --repo=https://github.com/targetcorp/webapp
 
# Scan including git history
trufflehog git https://github.com/targetcorp/webapp --since-commit HEAD~100
```

### gitleaks

```bash
# Scan a remote repo
gitleaks detect --source . --repo-url https://github.com/targetcorp/app
 
# Scan the whole org (needs token)
gitleaks detect --source . --github-org targetcorp --github-token YOUR_TOKEN
```

### github-search (Offside)

```bash
python3 github-search.py -q "org:targetcorp filename:.env" -t YOUR_TOKEN
```

---

## Don't Miss: Git History

A secret committed and then deleted is still in git history. This is a massive blind spot for many developers.

```bash
# Clone the repo
git clone https://github.com/targetcorp/app
cd app
 
# Search full history for secrets
git log --all --full-history -- "*.env"
git log -p --all | grep -E "(password|secret|key|token)" | head -50
 
# Look at a specific deleted file
git show HEAD~5:config/database.yml
 
# Grep across all commits
git grep "password" $(git rev-list --all)
```

---

## What to Look For in CI/CD Configs

Jenkinsfiles, `.travis.yml`, and GitHub Actions workflows often contain the most sensitive operational details.

```bash
# GitHub Actions  -  secrets are referenced but environment variables are often hardcoded in test runs
org:TARGETCORP filename:*.yml "env:" "KEY" OR "SECRET" OR "PASSWORD"
 
# Common patterns in CI configs
"DEPLOY_KEY"
"SSH_PRIVATE_KEY"
"NPM_TOKEN"
"DOCKER_PASSWORD"
"KUBECONFIG"
```

---

## GitHub Dorking Workflow

```mermaid
graph TD
    A[Target Company Name] --> B[Search GitHub  -  org: dorks]
    A --> C[Search by domain  -  target.com]
    B --> D[Review matches]
    C --> D
    D --> E{Type of finding}
    E -->|Credentials| F[Verify if live  -  CAREFULLY]
    E -->|Internal hostnames| G[Add to recon scope]
    E -->|Config structure| H[Infer tech stack]
    F --> I[Report if valid]
    G --> J[Enumerate new assets]
```

---

## A Note on Responsible Handling

When you find live credentials  -  don't use them beyond confirming they're valid (e.g., checking if a key can authenticate). Don't access data. Document the credential type, the source repo, and that it resolves to their infrastructure. That's your report.

---

## Related

- [Wayback Mining](../Recon/Wayback-Mining)  -  archived code and pages from before deletions
- [Cloud Range Discovery](../Recon/Cloud-Range-Discovery)  -  credentials found here often are cloud keys
- [Acquisitions](../Recon/Acquisitions)  -  acquired companies' repos are often publicly linked
