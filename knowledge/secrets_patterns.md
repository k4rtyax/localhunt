# Secrets and Credential Patterns

## Pattern Signatures

### Cloud Providers
```regex
# AWS
AKIA[0-9A-Z]{16}
[0-9a-zA-Z/+]{40}
arn:aws:[a-zA-Z0-9:/_-]+

# GCP
AIza[0-9A-Za-z\-_]{35}
[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com

# Azure
[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}
```

### Payment and Billing
```regex
# Stripe
sk_live_[0-9a-zA-Z]{24,}
pk_live_[0-9a-zA-Z]{24,}
rk_live_[0-9a-zA-Z]{24,}

# PayPal
access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}

# Square
sq0atp-[0-9A-Za-z\-_]{22}
sq0csp-[0-9A-Za-z\-_]{43}
```

### Communications
```regex
# Twilio
AC[a-zA-Z0-9]{32}
SK[a-zA-Z0-9]{32}

# SendGrid
SG\.[a-zA-Z0-9\-_\.]{66}

# Mailgun
key-[0-9a-zA-Z]{32}

# Slack
xox[baprs]-[0-9a-zA-Z]{10,48}
T[0-9A-Z]{10}/B[0-9A-Z]{10}/[0-9a-zA-Z]{24}
```

### Version Control
```regex
# GitHub
ghp_[0-9a-zA-Z]{36}
gho_[0-9a-zA-Z]{36}
ghs_[0-9a-zA-Z]{36}
github_pat_[0-9a-zA-Z]{82}

# GitLab
glpat-[0-9a-zA-Z\-_]{20}
```

### JSON Web Tokens
```regex
eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+
```

### Generic Assignment Signatures
```javascript
apiKey: '...'
api_key = '...'
secret: '...'
password: '...'
token: '...'
private_key: '-----BEGIN RSA PRIVATE KEY-----'
```

---

## Validation Context

### Exclusions and Placeholders
```javascript
apiKey: process.env.API_KEY
token: '<YOUR_TOKEN_HERE>'
password: 'changeme'
secret: '{{secret}}'
```

### Environment Variable Exposure
```
DB_PASSWORD=
DATABASE_URL=
REDIS_URL=
SECRET_KEY=
JWT_SECRET=
```
