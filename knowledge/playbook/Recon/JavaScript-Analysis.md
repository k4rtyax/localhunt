> Source: https://bugbounty.info/Recon/JavaScript-Analysis

# JavaScript Analysis

This is the highest-ROI recon activity in my workflow, full stop. Modern web apps ship their entire routing table, API client, internal endpoint paths, and sometimes literal credentials inside their JavaScript bundles. Developers know this intellectually but keep doing it because the alternative is more work.

I find something actionable in JS analysis on roughly 7 out of 10 targets. Not always a vulnerability directly. Sometimes it's an undocumented admin API, a staging endpoint baked into a config object, or a feature flag that reveals upcoming functionality. But it consistently gives you a better map of the application than anything else.

## What You're Looking For

```mermaid
flowchart TD
    R["JS Bundle Analysis"]
    R --> A["API Endpoints"]
    R --> S["Secrets and Tokens"]
    R --> L["Application Logic"]
    R --> I["Infrastructure"]
    R --> D["Dangerous Sinks"]
```

## The Workflow

### Step 1: Collect All JavaScript

Don't just grab the files you see in the HTML source. SPAs lazy-load chunks. Webpack splits code by route. There are JS files that only load when you visit specific pages or trigger specific actions.

```bash
# Passive: extract JS URLs from a crawl
cat wayback_urls.txt | grep -iE "\.js(\?|$)" | sort -u > js_urls.txt
 
# Active: use a headless browser to trigger lazy loading
# katana does this well, it executes JS and captures dynamic requests
katana -u https://target.com -js-crawl -depth 3 -field url | \
    grep -iE "\.js(\?|$)" | sort -u >> js_urls.txt
 
# Download everything
cat js_urls.txt | httpx -silent -mc 200 | xargs -P 10 -I{} wget -q {}
```

Also check for source maps. They're the holy grail. They contain the original, unminified source code with comments, variable names, and file structure intact.

```bash
# Check for source maps
for js in *.js; do
    map_url=$(grep -oP '//# sourceMappingURL=\K.*' "$js")
    if [ -n "$map_url" ]; then
        echo "[+] Source map found: $js -> $map_url"
    fi
done
 
# Also try appending .map to each JS URL
cat js_urls.txt | while read url; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "${url}.map")
    if [ "$status" = "200" ]; then
        echo "[+] Source map accessible: ${url}.map"
    fi
done
```

If you find a source map, use `shuji` or `source-map-explorer` to reconstruct the original project structure. You'll get the full React/Vue/Angular source tree with component names, service files, and often inline comments from the developers.

### Step 2: Extract Endpoints and Secrets

Automated first pass:

```bash
# LinkFinder - extracts relative and absolute URLs from JS
python3 linkfinder.py -i https://target.com/app.js -o cli
 
# SecretFinder - regex-based secret detection
python3 SecretFinder.py -i https://target.com/app.js -o cli
 
# Bulk processing:
cat js_urls.txt | while read url; do
    echo "=== $url ==="
    python3 linkfinder.py -i "$url" -o cli
done > endpoints.txt
```

But don't stop at automated tools. They miss context. Open the JS in a proper editor and search manually:

```bash
# Patterns I always grep for
grep -rn "api_key\|apikey\|api-key\|apiKey" *.js
grep -rn "secret\|token\|password\|credential" *.js
grep -rn "admin\|internal\|staging\|debug" *.js
grep -rn "amazonaws\.com\|s3\..*\.amazonaws" *.js
grep -rn "firebase\|firebaseConfig\|apiKey.*firebase" *.js
grep -rn "\.env\|process\.env\|REACT_APP_" *.js
grep -rn "graphql\|/graphql\|__schema" *.js
grep -rn "postMessage\|addEventListener.*message\|onmessage" *.js
grep -rn "innerHTML\|outerHTML\|document\.write\|\.html(" *.js
grep -rn "eval\|Function(" *.js
grep -rn "redirect\|returnUrl\|next=\|goto=" *.js
```

### Step 3: Understand the Application Architecture

This is the step that separates good JS analysis from running LinkFinder and calling it a day.

Look at the bundle structure. Most modern apps use Webpack or Vite, and the chunk names often reveal the app's route structure:

```text
app.js                    # Main bundle
chunk-vendor.js           # Third-party libraries
chunk-auth.a1b2c3.js      # Authentication module
chunk-admin.d4e5f6.js     # Admin panel
chunk-billing.g7h8i9.js   # Payment/billing
chunk-reports.j0k1l2.js   # Reporting features
```

That `chunk-admin` file contains the admin panel's routing, API calls, and permission checks. Read it. Even if you can't access the admin panel through the UI, you now know what endpoints it calls.

```mermaid
flowchart TD
    A["Identify bundle chunks"] --> B["Map chunks to features"]
    B --> C["Read auth/admin chunks"]
    C --> D["Extract API endpoints + params"]
    D --> E["Test with your auth token"]
    E --> F{"Server-side access control?"}
    F -->|"No"| G["BOLA / BFLA vulnerability"]
    F -->|"Yes"| H["Note for privilege testing"]
```

### Step 4: Trace Data Flows for DOM XSS

If you're hunting DOM XSS specifically, you need to trace how user input flows through the JavaScript to dangerous sinks. Automated tools (DOM Invader in Burp, taint tracking) help, but reading the code is still the most reliable approach for complex apps.

Look for patterns where URL parameters, hash fragments, or postMessage data flow into:

```javascript
// Dangerous sinks. Anything user-controlled that reaches these is DOM XSS.
element.innerHTML = userInput;           // Direct HTML injection
element.outerHTML = userInput;           // Same
document.write(userInput);              // Classic
document.writeln(userInput);            // Same
eval(userInput);                        // Code execution
new Function(userInput);                // Code execution
setTimeout(userInput, 0);              // If string argument
setInterval(userInput, 0);             // If string argument
element.setAttribute('href', userInput); // javascript: protocol
element.setAttribute('src', userInput);  // Script loading
location = userInput;                   // Open redirect / javascript:
location.href = userInput;              // Same
$.html(userInput);                      // jQuery sink
$(userInput);                           // jQuery selector injection
v-html="userInput"                      // Vue sink
dangerouslySetInnerHTML={{__html: userInput}} // React sink
```

## What to Do With What You Find

| Discovery | Next Step |
| --- | --- |
| Undocumented API endpoints | Test with your auth token. Test without auth. Test with different user roles. |
| Hardcoded API keys | Identify the service (AWS, Stripe, Firebase, etc). Test the key's permissions. See Credential Validation. |
| Internal hostnames / staging URLs | Add to your target list. Check if they're accessible. Often less hardened than production. |
| Feature flags | Toggle them. Some are enforced client-side only. |
| Admin panel routes | Try accessing them directly. Even if the UI hides the nav link, the route might still work. |
| postMessage handlers | Follow the methodology in [postMessage Vulnerabilities](../Attack-Surface/Web/Client-Side/postMessage-Vulnerabilities). |
| Dangerous sinks with user input | Trace the full flow. Build a DOM XSS PoC. |

## See Also

- [postMessage Vulnerabilities](../Attack-Surface/Web/Client-Side/postMessage-Vulnerabilities)
- [DOM XSS](../Attack-Surface/Web/Injection/XSS/DOM-XSS)
- [Content Discovery](../Recon/Content-Discovery)
- [API Endpoint Discovery](../Recon/API-Discovery)
