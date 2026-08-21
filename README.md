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
|    Client Host     |    SSH tunnel      |    Ollama Host     |
|                    |  -L 11434:11434    |                    |
|  hunt.py scan      | =================> |  ollama serve      |
|  ChromaDB (local)  | <================= |  - qwen3:4b        |
|                    |                    |  - nomic-embed     |
+--------------------+                    +--------------------+
```

Both hosts can be the same machine. Ollama stays bound to loopback either way;
see "Connecting to a remote Ollama" below.

---

## Setup

### 1. Ollama Server

```bash
brew install ollama
ollama pull qwen3:4b
ollama pull nomic-embed-text   # only needed for RAG
ollama serve                   # loopback only, no flags
```

### 2. Client

```powershell
pip install -r requirements.txt
python hunt.py check
```

`check` verifies the server, the model, and the knowledge base in that order.
It reports each separately, so a missing embedding model or an uninstalled
`chromadb` shows up as a warning rather than a failure.

If Ollama runs on another machine, open a tunnel first (see below) and leave
the default host alone. `python hunt.py set-host <IP>` is there for the case
where you deliberately expose the port, and carries the risk described below.

### 3. Optional: skip the RAG stack

`chromadb` accounts for most of the install and is only used by `index`,
`knowledge`, and the `--rag` flag. Leave it out and everything else still
works: `index` and `knowledge` exit with an install hint, `--rag` prints a
warning and scans without retrieval.

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

Documents are filed into categories from their filename (`owasp`, `malware`,
`custom`, `cve`, `writeup`, `target_doc`), and each swarm agent reads only the
categories that concern it, so `deobfuscator` is not fed access-control notes.
A document that matches nothing is filed as `general` and no agent retrieves
it, which is where report templates belong.

In `swarm`, the retrieval query is the agent's topic plus the regex signals
actually found in the file being scanned, so two files pull different context.

`nomic-embed-text` is sent the `search_document` and `search_query` prefixes it
was trained with. Any index built before that change must be rebuilt with
`python hunt.py index --force`.

The knowledge base ships with three short documents. Retrieval only begins to
earn its cost once there is enough material for ranking to mean something;
target-specific notes and real writeups are worth more here than restatements
of OWASP, which the model already knows.

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

| Agent             | Covers                                                       |
| ----------------- | ------------------------------------------------------------ |
| `secrets-hunter`  | Hardcoded keys, tokens, connection strings, private keys     |
| `xss-hunter`      | DOM/reflected XSS sources and sinks, prototype pollution     |
| `sqli-hunter`     | SQL/NoSQL injection, unsafe query construction               |
| `rce-hunter`      | Command injection, SSRF, path traversal, deserialization     |
| `authz-auditor`   | Broken access control, IDOR, JWT handling, mass assignment   |
| `crypto-auditor`  | Weak hashes and ciphers, predictable randomness, TLS bypass  |
| `config-auditor`  | Permissive CORS, debug mode, cookie flags, IAM wildcards     |
| `endpoint-mapper` | Attack-surface recon: routes, hosts, buckets, debug paths    |
| `deobfuscator`    | Packed scripts, skimmers, exfiltration channels              |
| `skeptic`         | Adversarial verifier - refutes findings the finders produced |
| `triage-lead`     | Merges what survived into an executive summary               |

Every finding carries `verdict`, `confidence`, and `unverified_evidence` - the
last one flags a citation that could not be located in the source file, which
is the cheapest way to catch a model that invented its evidence.

`verdict` is `real`, `refuted`, or `unverified`:

| Verdict      | Meaning                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------ |
| `real`       | The skeptic tried to refute it and could not                                                                 |
| `refuted`    | The skeptic showed the flaw is not present, and the finding is dropped from the findings list into `refuted` |
| `unverified` | The skeptic's refutation was thrown out, or the verifier itself crashed. The finding is kept                 |

A refutation is thrown out when it rests on what the file _is_ rather than on
what the code _does_: that it is a demo, a test, a fixture, or not production.
The skeptic prompt directs that judgement to `adjusted_severity` instead, but a
4B model ignores the rule often enough that it is enforced in code rather than
trusted to the prompt. The proposed severity is still applied, so the finding
survives at a lower rank with the verifier's own words recorded in
`verdict_reason`. Run stats count these as `verify_overridden`.

`VERIFIER_VOTES` in `config.py` sets how many skeptics vote per finding. It
ships at 1, where a single confused vote decides everything. Raise it to 3 for
a real majority at three times the verification cost.

Reports are written to `reports/` as paired `.md` and `.json`. That directory
is gitignored: findings routinely contain live secrets.

### Resource notes

Ollama allocates `num_ctx x OLLAMA_NUM_PARALLEL` of KV cache on top of the
model. For `qwen3:4b` at the default `NUM_CTX = 8192` that is roughly 1.2 GB
per parallel slot in f16, plus 2.5 GB for the weights. The shipped defaults
(concurrency 2) are sized for an 8 GB host. Drop to `--concurrency 1` if the
machine starts swapping.

Two server-side settings change that arithmetic and are worth checking with
`ollama show` before tuning anything here:

```bash
OLLAMA_KV_CACHE_TYPE=q8_0     # roughly halves the KV cache
OLLAMA_FLASH_ATTENTION=1
OLLAMA_NUM_PARALLEL=2         # unset means Ollama picks, which may exceed
                              # what --concurrency assumes
```

`RESERVE_OUTPUT_TOKENS` holds back part of `NUM_CTX` for the model's own
answer; code windows are clamped to whatever is left, and `swarm` prints that
budget in its plan panel.

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

| Mode         | Target Scope                               |
| ------------ | ------------------------------------------ |
| `full`       | Comprehensive review                       |
| `secrets`    | Hardcoded keys, tokens, credentials        |
| `xss`        | DOM sinks, sources, injection vectors      |
| `endpoints`  | Route definitions, internal APIs           |
| `obfuscated` | Deobfuscation and script behavior          |
| `sqli`       | Query concatenation and injection patterns |

---

## Project Structure

```
localhunt/
├── hunt.py              CLI: check, set-host, index, knowledge, scan, chat,
│                        agents, swarm
├── config.py            hosts, models, budgets, thresholds
├── requirements.txt
├── knowledge/           RAG source documents (.md / .txt)
├── modules/
│   ├── agents.py        AgentSpec registry: the specialists and their prompts
│   ├── orchestrator.py  Swarm: plan, hunt, sift, verify, synth
│   ├── llm.py           Ollama client: JSON schema output, retries, pooling
│   ├── schema.py        Finding record and the JSON schemas agents answer in
│   ├── analyzer.py      single-prompt path behind scan and chat
│   ├── prompts.py       system prompts for the scan modes
│   ├── rag.py           embeddings and ChromaDB search
│   ├── indexer.py       chunks knowledge/ and loads it into the store
│   ├── scanner.py       file discovery and reading
│   ├── reporter.py      terminal output and report files
│   └── textutil.py      token counting, line numbering, window splitting
├── reports/             gitignored: findings routinely contain live secrets
└── db/                  gitignored: ChromaDB vector store
```

Collab with claude Opus 5
