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
