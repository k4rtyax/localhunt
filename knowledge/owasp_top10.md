# OWASP Top 10 Security Reference

## A01:2021 - Broken Access Control

### Common Patterns in JavaScript
- IDOR: Predictable identifiers in routes (e.g., `/api/user/1234`)
- Client-side role checks: `if (user.role === 'admin')` in frontend assets
- Missing authorization middleware on API routes
- Routing header overrides (`X-Original-URL`, `X-Rewrite-URL`)

### Detection Signals
```javascript
localStorage.getItem('role')
user.isAdmin
/api/v1/user/[0-9]+/
```

---

## A02:2021 - Cryptographic Failures

### Weak Algorithms and Secrets
- MD5 or SHA1 used for credential hashing
- DES, 3DES, or RC4 used for payload encryption
- Static symmetric keys or IVs embedded in client files
- `Math.random()` used for token generation or session state

### Detection Signals
```javascript
CryptoJS.MD5(password)
crypto.createHash('md5')
Math.random().toString(36)
btoa(secret)
```

---

## A03:2021 - Injection

### XSS Execution Sinks
```javascript
element.innerHTML = userInput
document.write(data)
eval(userInput)
setTimeout(userInput, 1000)
new Function(userInput)()
location.href = input
jQuery.html(input)
ReactDOM.dangerouslySetInnerHTML
```

### XSS Input Sources
```javascript
location.search
location.hash
document.referrer
window.name
postMessage
localStorage / sessionStorage
```

---

## A04:2021 - Insecure Design

### Business Logic Weaknesses
- Price or quantity parameters supplied and calculated client-side
- Discount and coupon validation executed in frontend bundles
- Feature flag checks executed without server-side verification

---

## A05:2021 - Security Misconfiguration

### Common Configuration Issues
```javascript
debug: true
CORS: "*"
sourceMaps: true
```

---

## A06:2021 - Vulnerable and Outdated Components

### Common Component Risks
- `lodash` versions vulnerable to prototype pollution
- `jquery` versions with DOM parsing vulnerabilities
- Deprecated serialization packages handling untrusted objects

---

## A07:2021 - Identification and Authentication Failures

### Authentication Risks
```javascript
jwt.verify(token, 'secret123')
alg: 'none'
jwt.decode()
document.cookie
```

---

## A08:2021 - Software and Data Integrity Failures

### Missing Subresource Integrity
```html
<script src="https://cdn.example.com/lib.js"></script>
```

---

## A09:2021 - Security Logging and Monitoring Failures

### Sensitive Data in Logs
```javascript
console.log(userPassword)
console.log(apiKey)
console.log(token)
```

---

## A10:2021 - Server-Side Request Forgery

### Request Dispatching Patterns
```javascript
fetch(userControlledUrl)
axios.get(req.body.url)
request(params.callback)
```
