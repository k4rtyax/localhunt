"""
lokalHunt - Agent registry
Each AgentSpec is a specialist the orchestrator can spawn against a file:
one narrow job, one system prompt, one structured output contract.
"""

import re
from dataclasses import dataclass, field

from modules.schema import FINDINGS_SCHEMA, VERDICT_SCHEMA, SUMMARY_SCHEMA

# Shared by every finder prompt.
FINDER_RULES = """
Ground rules - follow all of them:
1. Report ONLY what is visible in the code provided. Never guess at code you
   cannot see, and never invent file names, functions, or variables.
2. Every line number must be copied from the "NN |" prefix on the source line
   the issue is on. A wrong line number makes the finding useless.
3. "evidence" must be a VERBATIM copy of the offending code, without the
   "NN |" prefix. Do not paraphrase it.
4. Returning {"findings": []} is a correct and expected answer. A clean file is
   a real outcome - do not manufacture findings to look thorough.
5. Skip generic best-practice advice, style issues, and anything you cannot tie
   to a concrete line of the given code.
6. Set "confidence" honestly: 0.9+ only when the code alone proves the issue,
   around 0.5 when it depends on caller context you cannot see, below 0.4 when
   it is a hunch.
7. Test fixtures, mock data, documentation examples, and obvious placeholders
   ("your-api-key-here", "changeme", "example.com") are NOT findings.
"""


@dataclass(frozen=True)
class AgentSpec:
    """One specialist agent the orchestrator can spawn."""

    name: str
    description: str
    focus: str                                  # the body of the system prompt
    extensions: tuple[str, ...] = ()            # empty = any file type
    signals: tuple[str, ...] = ()               # regex hints for this class
    needs_signal: bool = False                  # only run when a signal matches
    temperature: float = 0.1
    rag_query: str = ""
    _compiled: list = field(default_factory=list, repr=False, compare=False)

    @property
    def system_prompt(self) -> str:
        return (
            f"You are {self.name}, a specialist code security agent.\n"
            f"{self.focus.strip()}\n{FINDER_RULES}"
        )

    @property
    def schema(self) -> dict:
        return FINDINGS_SCHEMA

    def matches_extension(self, ext: str) -> bool:
        return not self.extensions or ext.lower() in self.extensions

    def find_signals(self, content: str) -> list[str]:
        """Return the distinct regex hits for this agent's class, if any."""
        if not self.signals:
            return []
        if not self._compiled:
            self._compiled.extend(
                re.compile(p, re.IGNORECASE) for p in self.signals
            )
        hits: list[str] = []
        for rx in self._compiled:
            m = rx.search(content)
            if m:
                hit = m.group(0).strip()[:60]
                if hit not in hits:
                    hits.append(hit)
        return hits

FINDERS: tuple[AgentSpec, ...] = (
    AgentSpec(
        name="secrets-hunter",
        description="Hardcoded credentials, API keys, tokens, private keys",
        focus="""
Your only job is finding secrets committed into source code:
- Cloud credentials (AWS AKIA/ASIA keys, GCP service-account JSON, Azure keys)
- API tokens, bearer tokens, JWTs with real payloads, webhook URLs with tokens
- Database connection strings carrying a password
- Private keys (RSA/EC/OpenSSH/PGP blocks) and certificate material
- Session secrets, signing keys, and encryption keys assigned as literals

Judge whether the value looks REAL: high entropy, correct prefix, correct
length. A variable merely NAMED "apiKey" that reads from process.env is safe
and must not be reported.
""",
        signals=(
            r"AKIA[0-9A-Z]{16}",
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            r"(?:api[_-]?key|secret|passwd|password|token|credential)"
            r"\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']",
            r"(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s\"']*:[^\s\"'@]+@",
            r"gh[pousr]_[A-Za-z0-9]{20,}",
            r"sk-[A-Za-z0-9]{20,}",
            r"xox[baprs]-[A-Za-z0-9-]{10,}",
        ),
        rag_query="hardcoded secrets api keys credentials detection patterns",
    ),
    AgentSpec(
        name="xss-hunter",
        description="DOM/reflected XSS, unsafe sinks, prototype pollution",
        focus="""
Your only job is client-side injection. Trace untrusted data from source to
sink and report the pair:
- Sources: location.*, document.URL, referrer, postMessage data, localStorage,
  sessionStorage, URL query parameters, WebSocket messages, server-rendered
  template variables
- Sinks: innerHTML, outerHTML, insertAdjacentHTML, document.write, eval,
  Function(), setTimeout/setInterval with a string, jQuery .html()/.append(),
  dangerouslySetInnerHTML, v-html, script src assignment, location assignment
- Prototype pollution: recursive merge/extend/clone reached by attacker keys,
  and __proto__ / constructor / prototype used as a dynamic property key

Report a finding only when a sink receives data you can trace to a source, or
when the sink takes a parameter the caller controls. A sink fed a hardcoded
constant is not a finding.
""",
        extensions=(
            ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
            ".html", ".htm", ".vue", ".svelte", ".php", ".ejs", ".hbs",
        ),
        signals=(
            r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"insertAdjacentHTML",
            r"document\.write", r"dangerouslySetInnerHTML", r"v-html",
            r"\beval\s*\(", r"new\s+Function\s*\(",
            r"\$\([^)]*\)\.(?:html|append|prepend|after|before)\s*\(",
            r"location\.(?:hash|search|href)", r"document\.referrer",
            r"addEventListener\s*\(\s*[\"']message[\"']",
            r"__proto__|constructor\s*\[|prototype\s*\[",
        ),
        rag_query="dom xss sources sinks prototype pollution payloads",
    ),
    AgentSpec(
        name="sqli-hunter",
        description="SQL/NoSQL injection and unsafe query construction",
        focus="""
Your only job is database query construction:
- String concatenation or interpolation of variables into SQL text
- Template literals building queries from request data
- ORM escape hatches: raw(), literal(), whereRaw(), .query(), execute() with
  an interpolated string
- Dynamic table or column names taken from input
- NoSQL operator injection: $where, $regex, $ne, $gt built from request bodies
- Stored procedure calls assembled from user input

A parameterised query (placeholders plus a separate values array) is safe and
must not be reported. Interpolating a value that is provably a constant or an
integer already cast with a strict parser is also not a finding.
""",
        extensions=(
            ".js", ".jsx", ".ts", ".tsx", ".php", ".py", ".rb",
            ".java", ".cs", ".go", ".sql", ".kt", ".scala",
        ),
        signals=(
            r"(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:\+|\$\{|%s|%\(|\bformat\()",
            r"\bexecute\s*\(\s*[f\"'`]", r"\bquery\s*\(\s*[f\"'`]",
            r"whereRaw|\.raw\s*\(|sequelize\.literal",
            r"\$where|\$regex|\$ne\b",
            r"cursor\.execute\s*\(.*%",
        ),
        rag_query="sql injection nosql injection unsafe query concatenation",
    ),
    AgentSpec(
        name="rce-hunter",
        description="Command injection, SSRF, path traversal, unsafe deserialization",
        focus="""
Your only job is server-side execution and request-forgery flaws:
- Command execution: exec, execSync, spawn with shell:true, system(), popen,
  subprocess with shell=True, backticks, Runtime.exec - built from input
- Unsafe deserialization: pickle.loads, yaml.load without SafeLoader,
  unserialize(), ObjectInputStream, Marshal.load on untrusted bytes
- Path traversal: file paths joined from request data without normalisation
  and containment checks, archive extraction without a path guard (zip slip)
- SSRF: outbound HTTP where the URL, host, or port comes from input
- Server-side template injection and dynamic import/require of an input value

Report the sink together with the input path that reaches it.
""",
        extensions=(
            ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php",
            ".java", ".cs", ".go", ".sh", ".ps1",
        ),
        signals=(
            r"child_process|exec(?:Sync|File)?\s*\(|spawn\s*\(",
            r"shell\s*[:=]\s*(?:True|true)",
            r"subprocess\.(?:run|call|Popen|check_output)",
            r"os\.system|popen\s*\(|Runtime\.getRuntime",
            r"pickle\.loads|yaml\.load\s*\((?![^)]*Safe)|unserialize\s*\(",
            r"path\.join\s*\([^)]*req\.|\.\./",
            r"requests\.get\s*\(|axios\.get\s*\(|fetch\s*\(|urlopen\s*\(",
            r"__import__|importlib\.import_module|require\s*\(\s*[^\"'）)]",
        ),
        rag_query="command injection ssrf path traversal insecure deserialization",
    ),
    AgentSpec(
        name="authz-auditor",
        description="Broken access control, IDOR, missing authentication",
        focus="""
Your only job is authorization and authentication logic:
- Routes and handlers that read or mutate data with no auth/permission check
- IDOR: an object id taken straight from the request and used to fetch or
  update a record without an ownership check
- Authorization decided client-side, or from a header/cookie/body field the
  client controls (isAdmin, role, userId in the body)
- Mass assignment: request body spread directly into a model update
- JWT handled without signature verification, with alg "none" accepted, or
  decoded rather than verified
- Middleware ordering that leaves a route unprotected

Compare protected routes against unprotected ones in the same file - the
inconsistency is usually the finding.
""",
        extensions=(
            ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".php",
            ".java", ".cs", ".go",
        ),
        signals=(
            r"router\.(?:get|post|put|patch|delete)|app\.(?:get|post|put|patch|delete)",
            r"@(?:app|router|bp)\.route|@(?:Get|Post|Put|Delete|RequestMapping)",
            r"jwt\.decode|verify\s*\(|isAdmin|is_admin|req\.user|current_user",
            r"findById|findOne|get_object_or_404|\.objects\.get",
        ),
        rag_query="broken access control idor jwt verification mass assignment",
    ),
    AgentSpec(
        name="crypto-auditor",
        description="Weak cryptography, bad randomness, insecure transport",
        focus="""
Your only job is cryptography and transport security:
- Broken hashes used for security purposes: MD5, SHA1, or an unsalted fast
  hash for passwords instead of bcrypt/scrypt/argon2
- Weak or misused ciphers: DES, RC4, AES-ECB, a static or zero IV, a key
  derived from a short constant
- Predictable randomness for tokens, session ids, password resets, or nonces
  (Math.random, rand(), time-seeded PRNGs) instead of a CSPRNG
- Certificate validation disabled (rejectUnauthorized:false, verify=False,
  InsecureSkipVerify, NODE_TLS_REJECT_UNAUTHORIZED=0)
- Plain-text http:// for credentialed or sensitive traffic
- Comparing secrets with == instead of a constant-time compare
""",
        signals=(
            r"\bmd5\b|\bsha1\b|createHash\s*\(\s*[\"'](?:md5|sha1)",
            r"\bDES\b|\bRC4\b|AES[-_/]?ECB|MODE_ECB",
            r"Math\.random|\brand\s*\(|mt_rand|random\.random",
            r"rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify",
            r"NODE_TLS_REJECT_UNAUTHORIZED",
            r"http://(?!localhost|127\.0\.0\.1)",
        ),
        rag_query="weak cryptography insecure randomness tls verification disabled",
    ),
    AgentSpec(
        name="config-auditor",
        description="Insecure configuration, permissive CORS, exposed debug",
        focus="""
Your only job is configuration and deployment security:
- CORS: wildcard origin, origin reflected from the request, or a wildcard
  combined with credentials:true
- Debug or development mode left enabled, verbose error pages, stack traces
  returned to clients
- Cookies missing HttpOnly, Secure, or SameSite on session material
- Missing or unsafe security headers, and CSP with unsafe-inline/unsafe-eval
- Services bound to 0.0.0.0, admin ports exposed, default credentials
- Over-broad cloud IAM ("Action": "*", "Principal": "*"), public buckets
- Dependency pinning to a known-abandoned or wildcard version range
""",
        extensions=(
            ".json", ".yml", ".yaml", ".xml", ".env", ".config", ".toml",
            ".ini", ".conf", ".js", ".ts", ".py", ".php",
        ),
        signals=(
            r"Access-Control-Allow-Origin|cors\s*\(|credentials\s*:\s*true",
            r"debug\s*[:=]\s*(?:true|True|1)",
            r"httpOnly\s*:\s*false|secure\s*:\s*false|sameSite",
            r"unsafe-inline|unsafe-eval",
            r"0\.0\.0\.0|\"Action\"\s*:\s*\"\*\"|\"Principal\"\s*:\s*\"\*\"",
        ),
        rag_query="insecure configuration cors misconfiguration security headers",
    ),
    AgentSpec(
        name="endpoint-mapper",
        description="Attack-surface recon: routes, APIs, hosts, storage",
        focus="""
Your only job is mapping attack surface. This is reconnaissance, not bug
hunting - most entries here are severity "info", raised to "low" or "medium"
only when the path itself is dangerous (admin, debug, internal, backup).

Catalog:
- HTTP routes with their method and path
- GraphQL endpoints, and mutations that change state
- WebSocket and SSE URLs
- Hardcoded hosts, internal IPs, cloud storage buckets, third-party APIs
- Debug, admin, health, metrics, and backup paths
- Feature flags and hidden parameters that alter behaviour

Set "title" to the method and path, "evidence" to the route definition line.
""",
        signals=(
            r"router\.(?:get|post|put|patch|delete)|app\.(?:get|post|put|patch|delete)",
            r"fetch\s*\(|axios\.|XMLHttpRequest|\$\.ajax",
            r"https?://[a-z0-9.-]+", r"wss?://", r"/api/|/graphql|/v[0-9]/",
            r"s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com",
        ),
        rag_query="api endpoint enumeration attack surface mapping",
    ),
    AgentSpec(
        name="deobfuscator",
        description="Packed or obfuscated code, malware behaviour, exfiltration",
        focus="""
Your only job is obfuscated and malicious code. You are looking at code that
was deliberately made hard to read.

- Identify the packing technique: string arrays with a rotating decoder,
  hex/unicode escape soup, charCodeAt/fromCharCode chains, base64 blobs fed to
  eval or atob, control-flow flattening, packed eval(function(p,a,c,k,e,d))
- State what the code actually DOES once decoded
- Extract every network destination, exfiltration channel, and dropped payload
- Flag skimmer behaviour: form and keystroke hooks, card-field selectors,
  beacons on submit or unload
- Flag persistence, anti-analysis, and environment fingerprinting

Severity reflects intent: confirmed exfiltration is critical, unexplained
obfuscation on its own is medium.
""",
        signals=(
            r"eval\s*\(\s*(?:function|atob|unescape|String\.fromCharCode)",
            r"String\.fromCharCode|charCodeAt|\\x[0-9a-f]{2}\\x[0-9a-f]{2}",
            r"atob\s*\(|btoa\s*\(|base64_decode",
            r"_0x[0-9a-f]{4,}",
            r"\[[\"'](?:push|shift|splice)[\"']\]\s*\(",
            r"navigator\.sendBeacon|new\s+Image\s*\(\s*\)\.src",
        ),
        needs_signal=True,
        temperature=0.2,
        rag_query="javascript obfuscation malware skimmer exfiltration patterns",
    ),
)

SKEPTIC = AgentSpec(
    name="skeptic",
    description="Adversarial verifier - tries to refute each finding",
    focus="""
You are a skeptical senior reviewer. Another agent reported a finding and your
job is to test it against the code rather than agree with it.

Answer exactly one question: does the code shown actually contain the flaw
described? Nothing else.

Set "real": false when:
- The cited line does not contain what the finding claims
- The input is not attacker-controlled, or is validated or escaped before it
  reaches the sink
- The API in use is already safe: a parameterised query, an auto-escaping
  template, a CSPRNG, a constant-time compare
- The value is a published documentation sample or an obvious placeholder
  (AKIAIOSFODNN7EXAMPLE, "changeme", "your-api-key-here", example.com)
- The code path is dead or unreachable

Set "real": true when the shown code does contain the flaw - INCLUDING when:
- The file looks like a demo, sample, fixture, exercise, or is commented as
  intentionally vulnerable. That changes how much the bug MATTERS, not whether
  it is present. Lower "adjusted_severity" instead of refuting.
- You cannot see the caller. Say so in "reason" and lower the severity.
- The project looks small, unfinished, or not production code.

Never refute a finding on the grounds that the file is "only a test", "a
sample", or "not a real application" - that is a judgement about context, and
"adjusted_severity" is where context belongs. Judge the code in front of you.

When the technical claim is genuinely ambiguous, answer false and explain what
extra code you would need to see. Put your real reasoning in "reason".
""",
    temperature=0.0,
)

SYNTHESIZER = AgentSpec(
    name="triage-lead",
    description="Merges verified findings into an executive summary",
    focus="""
You are the triage lead. You receive the findings that survived verification
and write the summary a human reads first.

- Two or three sentences on what the target is and where its real risk sits
- "top_priorities": the specific fixes worth doing first, most urgent first,
  each naming the file and the concrete action
- "risk_level": the overall level, driven by the worst confirmed finding

Describe only the findings you were given. If the list is empty, say plainly
that nothing was confirmed and note that this reflects the files scanned, not
a guarantee.
""",
    temperature=0.3,
)

AGENTS: dict[str, AgentSpec] = {a.name: a for a in FINDERS}
AGENT_NAMES: list[str] = list(AGENTS)

VERDICT_SCHEMA = VERDICT_SCHEMA
SUMMARY_SCHEMA = SUMMARY_SCHEMA


def get_agent(name: str) -> AgentSpec:
    try:
        return AGENTS[name]
    except KeyError:
        raise KeyError(
            f"Unknown agent '{name}'. Available: {', '.join(AGENT_NAMES)}"
        ) from None


def select_agents(
    content: str,
    extension: str,
    *,
    only: list[str] | None = None,
    run_all: bool = False,
) -> list[tuple[AgentSpec, list[str]]]:
    """
    Pick the agents worth spawning for this file.

    Returns (agent, signals) pairs, where signals are the regex hits that made
    the agent relevant. They are passed into the prompt as leads.
    """
    if only:
        chosen = [get_agent(n) for n in only]
        return [(a, a.find_signals(content)) for a in chosen]

    selected: list[tuple[AgentSpec, list[str]]] = []
    for agent in FINDERS:
        if not run_all and not agent.matches_extension(extension):
            continue
        signals = agent.find_signals(content)
        if not run_all and agent.needs_signal and not signals:
            continue
        selected.append((agent, signals))

    selected.sort(key=lambda pair: -len(pair[1]))
    return selected
