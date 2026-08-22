> Source: https://bugbounty.info/Attack-Surface/Cloud/AWS/S3-Misconfiguration

# S3 Misconfiguration

S3 buckets are still one of the most reliable ways to get a medium-high on a cloud program. Public listing is usually P3/medium, but write access or exposed PII bumps it to P2/high easily. Bucket policy misconfigs are the sneaky ones - the bucket isn't "public" in the classic sense but the policy grants `s3:GetObject` to `*` on specific prefixes.

## Finding Buckets

Start with permutations of the company name, product names, and known subdomains:

```bash
# s3scanner - fast bulk checking
s3scanner scan --buckets-file wordlist.txt
 
# Manual permutations to try
company-name
company-name-assets
company-name-backup
company-name-dev
company-name-staging
company-name-prod
company-name-logs
company-name-data
assets.company.com (CNAME -> S3 sometimes)
```

Also check:

- JS files for bucket names (hardcoded S3 URLs)
- Network traffic in Burp while using the app (S3 presigned URLs reveal bucket names)
- GitHub/GitLab for config files, terraform, CloudFormation templates

## Testing Access

```bash
# Check if listing is enabled (unauthenticated)
aws s3 ls s3://BUCKET_NAME --no-sign-request
 
# List all objects if listing is on
aws s3 ls s3://BUCKET_NAME --recursive --no-sign-request
 
# Check read access on a specific object
aws s3 cp s3://BUCKET_NAME/somefile.txt /tmp/test --no-sign-request
 
# Check write access - always use a clearly-named bounty file
echo "bugbounty-test-$(date +%s)" > /tmp/bb_test.txt
aws s3 cp /tmp/bb_test.txt s3://BUCKET_NAME/bugbounty-test.txt --no-sign-request
# Clean up immediately after confirming
aws s3 rm s3://BUCKET_NAME/bugbounty-test.txt --no-sign-request
 
# Check ACL on bucket
aws s3api get-bucket-acl --bucket BUCKET_NAME --no-sign-request
```

## Policy Abuse

Even when a bucket isn't fully public, the bucket policy might grant access under certain conditions. Check the policy if you have any authenticated access:

```bash
aws s3api get-bucket-policy --bucket BUCKET_NAME
```

Watch for:

- `"Principal": "*"` with any action - fully public
- `"Principal": {"AWS": "arn:aws:iam::*:root"}` - any AWS account
- Conditions keyed on `aws:Referer` or `aws:SourceIp` - bypass with the right header/IP
- Overly broad resource ARNs: `arn:aws:s3:::bucket/*` grants access to everything

## Presigned URL Abuse

Presigned URLs are time-limited but can expose more than intended:

- Long expiry times (days or weeks) - report as misconfig
- Predictable key names - if you can guess the key, you can generate valid paths
- Presigned URLs for write (PUT) operations shared with users who shouldn't have write
- URL in logs or referrer headers that gets captured by third parties

## Bucket Takeover

If a subdomain CNAMEs to an S3 bucket that no longer exists, you can register that bucket name and serve content from their subdomain. Classic subdomain takeover via S3.

```bash
# Check if a CNAME points to S3
dig CNAME assets.company.com
# If it resolves to something.s3.amazonaws.com and returns 404/NoSuchBucket, it's takeable
```

## Impact Tiers

| Finding | Typical Severity |
| --- | --- |
| Public listing only (no sensitive content) | P4/Low |
| Public listing with PII/sensitive data | P2/High |
| Unauthenticated write access | P2/High |
| Bucket takeover via CNAME | P2/High |
| Sensitive backup/config files publicly readable | P1/Critical depending on content |

## Public Reports

- Public S3 bucket contains database backups with full PII for all customers - [HackerOne #631529](https://hackerone.com/reports/631529)
- S3 bucket write access allows uploading malicious files served from company subdomain - [HackerOne #1062803](https://hackerone.com/reports/1062803)
- Subdomain CNAME pointing to deleted S3 bucket allows full takeover - [HackerOne #1287696](https://hackerone.com/reports/1287696)
- Bucket policy with Principal * grants unauthenticated read to internal config files - [HackerOne #1553386](https://hackerone.com/reports/1553386)
- Presigned S3 URL with 7-day expiry leaks private user documents via Referer header - [HackerOne #1042750](https://hackerone.com/reports/1042750)

## Related

- [IAM Privilege Escalation](../../../Attack-Surface/Cloud/AWS/IAM-Privilege-Escalation) - if you find creds in an exposed bucket
- [AWS Overview](../../../Attack-Surface/Cloud/AWS/)
