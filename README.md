# lokalHunt

Code security analysis with local Qwen models via Ollama. Nothing leaves the
machine. Optional local vector retrieval (RAG) through ChromaDB.

Note: this project is early stage and experimental.

---

## Setup

On the Ollama host:

```bash
ollama pull qwen3:4b
ollama pull nomic-embed-text   # only needed for RAG
ollama serve                   # loopback only, no flags
```

On the client:

```powershell
pip install -r requirements.txt
python hunt.py check
```

`check` reports the server, the model and the knowledge base separately, so a
missing embedding model or an uninstalled `chromadb` shows up as a warning
rather than a failure.

`chromadb` is most of the install and only `index`, `knowledge` and `--rag`
use it. Leave it out and everything else still works: those two commands exit
with an install hint, `--rag` warns and scans without retrieval.

---

## Usage

```powershell
python hunt.py swarm -f target.js                      # specialist fleet
python hunt.py swarm -d .\webapp --ext .js --ext .php
python hunt.py swarm -f app.py -a secrets-hunter -a sqli-hunter
python hunt.py swarm -f app.js --stdout-json           # for scripts and CI
python hunt.py swarm -d .\src --fail-on high           # exit 2 on high+

python hunt.py scan -f target.js --mode secrets        # single prompt
python hunt.py scan -d .\webapp\ -o ./report.md
python hunt.py chat --rag                              # interactive
```

`scan` modes: `full`, `secrets`, `xss`, `endpoints`, `obfuscated`, `sqli`.

Reports are written to `reports/` as paired `.md` and `.json`, with a severity
summary on the terminal. That directory is gitignored: findings routinely
contain live secrets.

`swarm` exits 2 when `--fail-on` trips, and 3 when every agent call failed. The
second one matters more than it looks: a run that analysed nothing would
otherwise report a clean result.

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

`python hunt.py agents` prints the fleet:

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

Every finding carries `verdict`, `confidence` and `unverified_evidence` - the
last one flags a citation that could not be located in the source file, which
is the cheapest way to catch a model that invented its evidence.

| Verdict      | Meaning                                                                     |
| ------------ | --------------------------------------------------------------------------- |
| `real`       | The skeptic tried to refute it and could not                                |
| `refuted`    | The skeptic showed the flaw is not present; the finding moves to `refuted`  |
| `unverified` | The refutation was thrown out, or the verifier crashed; the finding is kept |

A refutation is thrown out on either of two grounds. The first is resting on
what the file _is_ rather than on what the code _does_: a demo, a test, a
fixture, not production, or a secret excused because the file is a `.env` that
nobody committed. The second is contradicting itself, since a 4B skeptic will
reason its way to "the finding is real" and then return a refutation anyway.
The skeptic prompt directs the first judgement to `adjusted_severity` instead,
but the model ignores the rule often enough that both are enforced in code.
The proposed severity is still applied, so the finding survives at a lower rank
with the verifier's own words in `verdict_reason`. Run stats count these as
`verify_overridden`.

Tuning lives in `config.py` and is commented there rather than here:
`VERIFIER_VOTES`, `MIN_CONFIDENCE`, `SWARM_CONCURRENCY`, `NUM_CTX`,
`RESERVE_OUTPUT_TOKENS`.

### Resource notes

Ollama allocates `num_ctx x OLLAMA_NUM_PARALLEL` of KV cache on top of the
weights. For `qwen3:4b` at the default `NUM_CTX = 8192` that is roughly 1.2 GB
per parallel slot in f16, plus 2.5 GB for the model. The shipped defaults
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

---

## Knowledge base (RAG)

```powershell
python hunt.py index                                # index knowledge/
python hunt.py scan -f target.js --rag
python hunt.py knowledge --list
python hunt.py knowledge --search "prototype pollution"
python hunt.py knowledge --add ./writeup.md
```

`knowledge/` holds three pattern notes, a report template, and `playbook/`:
133 generic technique notes filed by attack surface (90 under Attack-Surface,
24 Recon, 19 Chains).

Documents are filed into categories by folder first, then by filename. The
playbook folders map to `custom`, `writeup` and `target_doc`; anything outside
them is detected from the name. Each swarm agent reads only the categories
that concern it, so `deobfuscator` is not fed access-control notes. A document
that matches nothing is filed as `general` and no agent retrieves it, which is
where report templates belong.

In `swarm`, the retrieval query is the agent's topic plus the regex signals
actually found in the file being scanned, so two files pull different context.

`nomic-embed-text` is sent the `search_document` and `search_query` prefixes
it was trained with. Any index built before that change must be rebuilt with
`python hunt.py index --force`.

---

## Remote Ollama

```
+--------------------+                    +--------------------+
|    Client Host     |    SSH tunnel      |    Ollama Host     |
|                    |  -L 11434:11434    |                    |
|  hunt.py scan      | =================> |  ollama serve      |
|  ChromaDB (local)  | <================= |  - qwen3:4b        |
|                    |                    |  - nomic-embed     |
+--------------------+                    +--------------------+
```

Both hosts can be the same machine, and Ollama stays bound to loopback either
way. It has no authentication, so binding it to `0.0.0.0` exposes the model
and every prompt to anyone who can route to the port. A tunnel is safer and
needs no server-side change:

```powershell
ssh -N -L 11434:127.0.0.1:11434 user@host
```

The default host is `127.0.0.1`, so nothing else needs configuring. Override
via `LOKALHUNT_HOST`, `LOKALHUNT_PORT` or `OLLAMA_BASE_URL`. `set-host` is
there for the case where you deliberately expose the port, and carries the
risk above.

---

## Layout

```
lokalHunt/
├── hunt.py              CLI: check, set-host, index, knowledge, scan, chat,
│                        agents, swarm
├── config.py            hosts, models, budgets, thresholds
├── requirements.txt
├── knowledge/           RAG sources; playbook/ holds the technique notes
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
