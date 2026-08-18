# lokalHunt

Code security analysis utility using local Qwen models via Ollama. Supports local vector retrieval (RAG) using ChromaDB.

Note: This project is in its early stages of development and is currently experimental.

---

## Output Workflow

- Full analysis reports are automatically written to markdown (`.md`) files in `reports/` (or a custom path via `-o`).
- Terminal displays a structured summary indicating findings by severity, key observations, and report location.

---

## Architecture

```
+--------------------+                    +--------------------+
|    Windows Host    |   HTTP (LAN/WiFi)  |    macOS Host      |
|                    |                    |                    |
|  hunt.py scan      | -----------------> |  ollama serve      |
|  ChromaDB (local)  | <----------------- |  - qwen3:4b        |
|                    |                    |  - nomic-embed     |
+--------------------+                    +--------------------+
```

---

## Setup

### 1. Ollama Server (macOS)
```bash
brew install ollama
ollama pull qwen3:4b
ollama pull nomic-embed-text
OLLAMA_HOST=0.0.0.0 ollama serve
```

Identify the host IP address:
```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
```

### 2. Client (Windows)
```powershell
cd C:\Users\Kevin\Desktop\lokalHunt
pip install -r requirements.txt
python hunt.py set-host 192.168.1.5
python hunt.py check
```

---

## Usage

### Single File Analysis
```powershell
python hunt.py scan --file target.js
python hunt.py scan --file bundle.js --mode secrets
python hunt.py scan --file app.js --mode xss
python hunt.py scan --file payload.js --mode obfuscated
python hunt.py scan --file target.js -o ./report.md
python hunt.py scan --file target.js --stream
```

### Directory Analysis
```powershell
python hunt.py scan --dir C:\path\to\webapp\
python hunt.py scan --dir .\webapp\ --ext .js --ext .php
```

### Retrieval-Augmented Generation (RAG)
```powershell
# Index reference documents from knowledge/
python hunt.py index

# Scan with RAG context enabled
python hunt.py scan --file target.js --rag

# Manage knowledge base
python hunt.py knowledge --list
python hunt.py knowledge --search "prototype pollution"
python hunt.py knowledge --add ./writeup.md
```

### Interactive Session
```powershell
python hunt.py chat
python hunt.py chat --rag
```

---

## Agent Swarm

`swarm` replaces the single "find everything" prompt with a fleet of narrow
specialists, then spends most of its effort deleting their mistakes. On a 4B
model the narrowing matters more than the fan-out.

```
PLAN    pick agents per file from extension + a regex pre-scan
HUNT    every (agent x window) pair runs concurrently, structured JSON out
SIFT    confidence floor, evidence must exist in the source, dedupe
VERIFY  an adversarial skeptic tries to refute each finding
SYNTH   one triage pass writes the summary
```

```powershell
python hunt.py agents                                  # list the specialists
python hunt.py swarm -f target.js                      # auto-select agents
python hunt.py swarm -d .\webapp --ext .js --ext .php
python hunt.py swarm -f app.py -a secrets-hunter -a sqli-hunter
python hunt.py swarm -f app.js --stdout-json           # for scripts and CI
python hunt.py swarm -d .\src --fail-on high           # exit 2 on high+
```

| Agent | Covers |
|---|---|
| `secrets-hunter` | Hardcoded keys, tokens, connection strings, private keys |
| `xss-hunter` | DOM/reflected XSS sources and sinks, prototype pollution |
| `sqli-hunter` | SQL/NoSQL injection, unsafe query construction |
| `rce-hunter` | Command injection, SSRF, path traversal, deserialization |
| `authz-auditor` | Broken access control, IDOR, JWT handling, mass assignment |
| `crypto-auditor` | Weak hashes and ciphers, predictable randomness, TLS bypass |
| `config-auditor` | Permissive CORS, debug mode, cookie flags, IAM wildcards |
| `endpoint-mapper` | Attack-surface recon: routes, hosts, buckets, debug paths |
| `deobfuscator` | Packed scripts, skimmers, exfiltration channels |
| `skeptic` | Adversarial verifier - refutes findings the finders produced |
| `triage-lead` | Merges what survived into an executive summary |

Every finding carries `verdict`, `confidence`, and `unverified_evidence` - the
last one flags a citation that could not be located in the source file, which
is the cheapest way to catch a model that invented its evidence.

Reports are written to `reports/` as paired `.md` and `.json`. That directory
is gitignored: findings routinely contain live secrets.

### Resource notes

Ollama allocates `num_ctx x OLLAMA_NUM_PARALLEL` of KV cache on top of the
model. For `qwen3:4b` that is roughly 1.2 GB per parallel slot at the default
`NUM_CTX = 8192`, plus 2.5 GB for the weights - the shipped defaults
(concurrency 2) are sized for an 8 GB host. Drop to `--concurrency 1` if the
machine starts swapping.

---

## Connecting to a remote Ollama

Ollama has no authentication, so binding it to `0.0.0.0` exposes the model and
every prompt to anyone who can route to the port. An SSH tunnel is safer and
needs no server-side change:

```powershell
ssh -N -L 11434:127.0.0.1:11434 user@host
```

The default host is `127.0.0.1`, so nothing else needs configuring. Override
without editing source via `LOKALHUNT_HOST`, `LOKALHUNT_PORT`, or
`OLLAMA_BASE_URL`.

---

## Analysis Modes

| Mode | Target Scope |
|---|---|
| `full` | Comprehensive review |
| `secrets` | Hardcoded keys, tokens, credentials |
| `xss` | DOM sinks, sources, injection vectors |
| `endpoints` | Route definitions, internal APIs |
| `obfuscated` | Deobfuscation and script behavior |
| `sqli` | Query concatenation and injection patterns |

---

## Project Structure

```
localhunt/
├── hunt.py
├── config.py
├── requirements.txt
├── knowledge/
│   ├── owasp_top10.md
│   ├── malware_js_patterns.md
│   ├── secrets_patterns.md
│   └── TEMPLATE_FINDINGS.md
├── modules/
│   ├── analyzer.py
│   ├── rag.py
│   ├── indexer.py
│   ├── scanner.py
│   ├── reporter.py
│   └── prompts.py
└── reports/
```
