> Source: https://bugbounty.info/Attack-Surface/index

# Attack Surface

Organized by what you're attacking, not by vulnerability class. The same bug class (say IDOR) looks completely different on a REST API vs. a GraphQL endpoint vs. a mobile app's local storage. Context matters.

## [Web Applications](../Attack-Surface/Web/)

The bread and butter. Authentication, authorization, injection, SSRF, client-side vulns, business logic, infrastructure misconfigs. Deepest section because it's where most of the bounty money is.

```mermaid
flowchart TD
    W["Web Attack Surface"]
    W --> W1["Authentication"]
    W --> W2["Authorization"]
    W --> W3["Injection"]
    W --> W4["SSRF"]
    W --> W5["Client-Side"]
    W --> W6["Business Logic"]
    W --> W7["Infrastructure"]
```

## [APIs](../Attack-Surface/API/)

REST, GraphQL, gRPC, and WebSocket APIs. Attack patterns overlap with web but enumeration and testing approach is different enough for its own section.

## [Mobile Applications](../Attack-Surface/Mobile/)

Android and iOS. The app itself is a goldmine of hardcoded secrets, API endpoints, and client-side logic you can reverse engineer. The interesting bugs are usually in how the mobile app talks to the backend, not in the app itself.

## [Cloud Infrastructure](../Attack-Surface/Cloud/)

AWS, Azure, GCP. Bucket misconfigs, IAM privilege escalation, serverless exploitation, the ever-popular metadata endpoint. Natural escalation path for SSRF findings.

## [CD Pipelines](../Attack-Surface/CI-CD/)

GitHub Actions, GitLab CI, Jenkins. Supply chain attacks through build pipelines. Increasingly popular attack surface as more companies expose their CI/CD to external contributors.

## [AI & LLM Applications](../Attack-Surface/AI-LLM/)

LLM-powered apps, chatbots, agents, and MCP servers. The newest paid attack surface. Prompt injection, indirect prompt injection through retrieved content, tool abuse by agents, and MCP supply-chain flaws. Programs with AI in scope grew 270% in 2025 and valid prompt-injection reports rose 540%.

## [Web3 & Smart Contracts](../Attack-Surface/Web3/)

Solidity contracts, EVM-based protocols, cross-chain bridges. Immunefi's highest historical single bounty was over $10M. Public code means the code review is the whole game; reentrancy, oracle manipulation, signature replay, and bridge consensus bugs are the persistent paid classes.

## Choosing Your Focus

You don't need to be good at all of these. Most successful hunters specialise in one or two attack surfaces and go deep. If you're starting out, web applications are the best investment. Largest number of programs, most documentation, widest variety of bugs.

If you want to differentiate yourself though, the less crowded surfaces (cloud, CI/CD, mobile, AI/LLM, web3) have a better competition-to-reward ratio. Fewer hunters means fewer duplicates. AI/LLM is the newest of these and the fastest growing  -  only about 10% of researchers specialise in it as of 2025 and the scope keeps expanding. Web3 has the highest individual bounty ceilings of any surface, but the skill floor is higher  -  you need to read Solidity comfortably before you can compete.
