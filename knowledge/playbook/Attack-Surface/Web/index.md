> Source: https://bugbounty.info/Attack-Surface/Web/index

# Web Applications

Widest attack surface and deepest section of this playbook. Organized by category rather than alphabetically because the categories reflect how you actually think about testing. You test authentication as a system, not individual bugs in isolation.

## Authentication

How users prove who they are. Every auth implementation is custom in ways that matter.

- [Login Bypass Patterns](../../Attack-Surface/Web/Authentication/Login-Bypass)- [Password Reset Flows](../../Attack-Surface/Web/Authentication/Password-Reset)- [OAuth Misconfigurations](../../Attack-Surface/Web/Authentication/OAuth)- [SSO & SAML Attacks](../../Attack-Surface/Web/Authentication/SSO)- [MFA Bypass](../../Attack-Surface/Web/Authentication/MFA-Bypass)- [Session Management](../../Attack-Surface/Web/Authentication/Session-Management)- [JWT Attacks](../../Attack-Surface/Web/Authentication/JWT)

## Authorization

How the app decides what you're allowed to do. Most consistently rewarded bug class in my experience.

- [IDOR Patterns](../../Attack-Surface/Web/Authorization/IDOR)- [BOLA & BFLA](../../Attack-Surface/Web/Authorization/BOLA)- [Privilege Escalation](../../Attack-Surface/Web/Authorization/Privilege-Escalation)- [Multi-Tenancy Bugs](../../Attack-Surface/Web/Authorization/Multi-Tenancy)

## Injection

Putting data where the application expects instructions.

- [XSS](../../Attack-Surface/Web/Injection/XSS/) - Reflected, stored, DOM, mXSS, framework-specific, WAF bypass
- [SQL Injection](../../Attack-Surface/Web/Injection/SQLi/) - Error-based, blind, second-order, ORM-specific- [Server-Side Template Injection](../../Attack-Surface/Web/Injection/SSTI)- [Host Header Injection](../../Attack-Surface/Web/Injection/Host-Header)- [NoSQL Injection](../../Attack-Surface/Web/Injection/NoSQLi)- [Deserialization](../../Attack-Surface/Web/Injection/Deserialization)- [Command Injection](../../Attack-Surface/Web/Injection/Command-Injection)

## SSRF

Making the server send requests on your behalf. Gateway to cloud metadata and internal networks.

- [SSRF](../../Attack-Surface/Web/SSRF/) - Full methodology, bypass techniques, blind SSRF, cloud exploitation

## Client-Side

Bugs that execute in the user's browser.

- [CSRF](../../Attack-Surface/Web/Client-Side/CSRF)- [postMessage Vulnerabilities](../../Attack-Surface/Web/Client-Side/postMessage-Vulnerabilities) - Full methodology, origin bypass, widget exploitation
- [CORS Misconfigurations](../../Attack-Surface/Web/Client-Side/CORS)- [WebSocket Security](../../Attack-Surface/Web/Client-Side/WebSocket)- [Subdomain Takeover](../../Attack-Surface/Web/Client-Side/Subdomain-Takeover)- [Clickjacking](../../Attack-Surface/Web/Client-Side/Clickjacking)- [Prototype Pollution](../../Attack-Surface/Web/Client-Side/Prototype-Pollution)

## Business Logic

The bugs no scanner will ever find.

- [Race Conditions](../../Attack-Surface/Web/Business-Logic/Race-Conditions)- [Price & Quantity Manipulation](../../Attack-Surface/Web/Business-Logic/Price-Manipulation)- [State Machine Bugs](../../Attack-Surface/Web/Business-Logic/State-Machine)- [Mass Assignment](../../Attack-Surface/Web/Business-Logic/Mass-Assignment)

## Infrastructure

Server and proxy layer misconfigurations.

- [Cache Poisoning](../../Attack-Surface/Web/Infrastructure/Cache-Poisoning)- [HTTP Request Smuggling](../../Attack-Surface/Web/Infrastructure/Request-Smuggling)- [Open Redirect](../../Attack-Surface/Web/Infrastructure/Open-Redirect)- [Web Cache Deception](../../Attack-Surface/Web/Infrastructure/Web-Cache-Deception)- [2 Attacks](../../Attack-Surface/Web/Infrastructure/HTTP2-Attacks)
