"""
lokalHunt — Prompts Module
System prompts for target code analysis modes.
"""

BASE_SYSTEM = """Analyze the provided source code for security flaws, configuration issues, and sensitive data.
Provide concise, technical findings with relevant line numbers or code references, risk assessment, and specific evidence.
"""

PROMPTS = {
    "secrets": BASE_SYSTEM + """
Focus on hardcoded secrets and credentials:
- Cloud access keys and service account tokens (AWS, GCP, Azure)
- API tokens, bearer keys, and JWT artifacts
- Database credentials and connection strings
- OAuth secrets, webhook tokens, and private keys
- Sensitive internal endpoints or environment variables
""",

    "xss": BASE_SYSTEM + """
Focus on client-side injection vectors:
- Input sources (location properties, postMessage, storage reads, document referrer)
- DOM sinks (innerHTML, outerHTML, eval, Function, dynamic script tags, location assignments)
- Framework-specific bypasses and prototype pollution vectors
""",

    "endpoints": BASE_SYSTEM + """
Extract and catalog all exposed endpoints and network routes:
- REST API routes (GET, POST, PUT, DELETE, PATCH)
- GraphQL endpoints and queries
- WebSocket URIs
- Internal or debugging paths
- Cloud storage buckets and external dependencies
""",

    "obfuscated": BASE_SYSTEM + """
Analyze obfuscated or packed script logic:
- Identify packing and encoding patterns (string arrays, char codes, dynamic evaluations)
- Describe the core functional behavior of the deobfuscated logic
- Identify external communication destinations or exfiltration channels
""",

    "sqli": BASE_SYSTEM + """
Focus on database query construction and injection vectors:
- Raw query concatenation with user-controlled input
- ORM bypassing and unsafe clause handling
- NoSQL injection patterns ($where, regex conditions)
""",

    "full": BASE_SYSTEM + """
Perform a comprehensive security review covering:
1. Hardcoded secrets and credentials
2. Injection vulnerabilities (XSS, SQLi, SSRF)
3. API endpoints and sensitive internal routes
4. Obfuscation techniques or suspicious payload delivery
5. Insecure cryptography or broken access control patterns
"""
}

def get_prompt(mode: str) -> str:
    """Return the system prompt for the specified mode."""
    return PROMPTS.get(mode, PROMPTS["full"])

AVAILABLE_MODES = list(PROMPTS.keys())
