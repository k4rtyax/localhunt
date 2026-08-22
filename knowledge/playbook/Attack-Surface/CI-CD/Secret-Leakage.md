> Source: https://bugbounty.info/Attack-Surface/CI-CD/Secret-Leakage

# Secret Leakage in CI/CD

Secrets in CI/CD pipelines leak in predictable ways. Build logs are the most common vector - masking fails silently, debug flags print everything, and error messages helpfully include the value that caused the problem. Artifacts are the second-most-common: test reports, coverage files, and debug dumps end up in artifact storage that's sometimes public.

## How Masking Fails

Every CI platform has some form of secret masking ("redact this value from logs"). It's not reliable:

1. **Base64 encoding defeats masking** - if your secret is `mysecret123` and it's base64-encoded before use, the masked value `mysecret123` won't match `bXlzZWNyZXQxMjM=` in the logs
2. **Multi-line secrets** - most platforms mask line-by-line, so a multi-line private key has only the first line masked
3. **Partial exposure** - error messages show the first N chars of the value that failed
4. **Command echo before masking** - shell `set -x` or `xtrace` prints commands before secrets are injected, but sometimes the injection happens after echo
5. **Sub-process handling** - secrets passed to Docker `--build-arg` or subprocess env sometimes don't inherit masking

```bash
# GitHub Actions masking bypass via encoding
echo $SECRET | base64    # base64 value won't be masked
echo $SECRET | rev       # reversed value won't be masked
echo ${SECRET:0:10}      # partial value won't be masked (but shorter, might not be useful)
```

## Build Log Enumeration

```bash
# GitHub Actions - logs are downloadable via API
curl -H "Authorization: token GH_TOKEN" \
  "https://api.github.com/repos/ORG/REPO/actions/runs/RUN_ID/logs" \
  -L -o logs.zip
 
# GitLab CI - job logs accessible via API
curl "https://gitlab.com/api/v4/projects/PROJECT_ID/jobs/JOB_ID/trace" \
  -H "PRIVATE-TOKEN: TOKEN"
 
# Jenkins - often no auth required
curl "https://jenkins.target.com/job/JOB_NAME/BUILD_NUMBER/consoleText"
 
# CircleCI - build artifacts and logs
curl "https://circleci.com/api/v2/project/github/ORG/REPO/pipeline" \
  -H "Circle-Token: TOKEN"
```

For public repos on GitHub, the Actions logs are publicly readable without auth if the repo is public. I always check recent failed builds - failures are more likely to print debug info.

## Artifact Exposure

Build artifacts are the underrated vector. They're stored separately from the code and often have different (weaker) access controls.

What to look for in artifacts:

- `.env` files copied into artifact directory during build
- Test configuration files with real credentials used in integration tests
- Coverage reports that include source code snippets with secrets
- Docker build context archives
- Deployment packages with embedded configs
- Debug dumps and heap snapshots

```bash
# GitHub Actions artifacts via API
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/ORG/REPO/actions/artifacts"
 
# Download artifact
curl -H "Authorization: token TOKEN" \
  "https://api.github.com/repos/ORG/REPO/actions/artifacts/ARTIFACT_ID/zip" \
  -L -o artifact.zip
 
# GitLab artifacts
curl "https://gitlab.com/ORG/REPO/-/jobs/JOB_ID/artifacts/download"
# Or browse artifact files
curl "https://gitlab.com/api/v4/projects/ID/jobs/JOB_ID/artifacts/path/to/file"
```

## Secret Scanning Bypass

If a program has automated secret scanning (GitHub secret scanning, GitLab secret detection, trufflehog in CI), developers sometimes obfuscate secrets to avoid detection:

```python
# Rotation -- breaking up the string
key = "AKIA" + "XXXXXXXXXXXXXXXXXXX"
 
# Environment variable indirection
# REAL_KEY=actual_value stored separately, code does os.environ['REAL_KEY']
 
# Config file split across multiple commits
# First commit: key prefix
# Second commit: key suffix
# History scan needed, not just HEAD
```

For scanning git history rather than just HEAD:

```bash
# trufflehog - scans all commits
trufflehog git https://github.com/target/repo --only-verified
 
# gitleaks
gitleaks detect --source /path/to/repo --log-opts="--all"
 
# Manual - find commits that touched credential-adjacent files
git log --all --diff-filter=D -- "**/.env" "**/*.pem" "**/credentials*"
git show COMMIT_SHA
```

## Container Image Layers

Docker images are build artifacts and they retain secrets baked into intermediate layers even if a later layer deletes them.

```bash
# Pull the image
docker pull target/app:latest
 
# Inspect all layers
docker history target/app:latest --no-trunc
 
# Use dive for interactive layer inspection
dive target/app:latest
 
# Extract and grep all layers
docker save target/app:latest | tar -xO | tar -tz 2>/dev/null | head -50
# Or more thoroughly:
docker create --name temp_container target/app:latest
docker export temp_container | tar -x -C /tmp/image_contents/
grep -r "password\|secret\|key\|token" /tmp/image_contents/ 2>/dev/null
```

## Environment Variable Dumps in Test Suites

Integration tests often dump environment at failure time. If test results are public:

```bash
# Check test result artifacts for env dumps
# Common patterns in test output:
# "KeyError: 'DATABASE_URL'" -> reveals the variable name and sometimes context
# pytest --capture=no output
# npm test verbose output with process.env
# Java system property dumps in stack traces
```

## .npmrc, .pypirc, .netrc in Build Contexts

Package manager config files with authentication tokens end up in build contexts and sometimes artifacts:

```bash
# Search artifact content for these files
find /extracted_artifact/ -name ".npmrc" -o -name ".pypirc" -o -name ".netrc" \
  -o -name "pip.conf" -o -name "*.npmrc" 2>/dev/null
 
# .npmrc format:
# //registry.npmjs.org/:_authToken=TOKEN
# //registry.company.com/:_authToken=PRIVATE_TOKEN
 
# .netrc format:
# machine api.example.com login user password SECRETPASSWORD
```

## Public Reports

- AWS credentials leaked in public GitHub Actions build log - [HackerOne #751894](https://hackerone.com/reports/751894)
- Private keys exposed in Docker image layer not cleaned up between build steps - [HackerOne #1293489](https://hackerone.com/reports/1293489)
- NPM auth token in .npmrc committed to public repo and baked into artifact - [HackerOne #1275685](https://hackerone.com/reports/1275685)
- Stripe secret key leaked in CircleCI artifact test coverage report - [HackerOne #1222018](https://hackerone.com/reports/1222018)
- Database credentials exposed in Jest test output uploaded as public CI artifact - [HackerOne Hacktivity search](https://hackerone.com/hacktivity?querystring=credentials+ci+artifact)

## Related

- [GitHub Actions](../../Attack-Surface/CI-CD/GitHub-Actions) - masking bypass and log exfiltration
- [GitLab CI](../../Attack-Surface/CI-CD/GitLab-CI) - variable exposure and artifact access
- [Jenkins](../../Attack-Surface/CI-CD/Jenkins) - build log access and credential dumping
- [CD Overview](../../)
