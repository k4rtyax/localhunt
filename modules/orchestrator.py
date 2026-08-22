"""
lokalHunt - Swarm orchestrator

    PLAN   pick agents per file from extension + pre-scan signals
    HUNT   run every (agent x window) pair concurrently against Ollama
    SIFT   drop low confidence, check evidence exists, deduplicate
    VERIFY spawn skeptics per finding; majority vote decides
    SYNTH  one triage pass writes the executive summary
"""

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable

from config import (
    CHUNK_TOKENS, CHUNK_OVERLAP_LINES, SWARM_CONCURRENCY,
    VERIFIER_VOTES, MIN_CONFIDENCE, RESERVE_OUTPUT_TOKENS,
)
from modules.agents import (
    AgentSpec, SKEPTIC, SYNTHESIZER, select_agents,
    VERDICT_SCHEMA, SUMMARY_SCHEMA,
)
from modules.schema import Finding, SEVERITIES
from modules.textutil import (
    count_tokens, number_lines, window_by_lines, normalize_snippet, squash,
    truncate,
)


# Grounds the skeptic is told to put in adjusted_severity, never in the
# verdict. qwen3:4b breaks that rule in practice, so the rule is enforced here
# instead of trusted to the prompt. These match claims about the FILE, not
# about a value: "documentation sample key" is a legitimate refutation, while
# "this file is a sample" is not.
# The adjective slot matters: a skeptic wrote "the .env file is a common
# practice", which the earlier pattern missed by exactly one word.
_OUT_OF_BOUNDS = re.compile(
    r"(?:"
    r"(?:file|code|script|snippet|project|app|application|repo\w*)\s+(?:is|are|looks?|seems?|appears?)"
    r"\s+(?:like\s+)?(?:a|an)?\s*(?:\w+\s+){0,2}"
    r"(?:demo|sample|example|test|mock|dummy|practice|convention|exercise)"
    r"|(?:demo|sample|example|test|mock|dummy|practice|training)\s+"
    r"(?:file|code|script|snippet|project|app|application|repo\w*|environment)"
    r"|not\s+(?:a\s+)?real\s+(?:app|application|project|codebase|code|system)"
    r"|not\s+(?:intended\s+for\s+)?production"
    r"|non-production"
    r"|(?:intentionally|deliberately|purposely)\s+vulnerable"
    r"|for\s+(?:demonstration|educational|learning|teaching)\s+purposes"
    # Where the file sits and whether it ships are not claims about the code,
    # and the skeptic cannot see any of it from the file content anyway.
    r"|(?:not|never)\s+(?:be\s+)?(?:committed|checked\s+in|pushed|tracked)"
    r"(?:\s+\w+){0,3}?\s+(?:version\s+control|source\s+control|git\b|vcs|the\s+repo\w*)"
    r"|gitignored|in\s+\.gitignore|excluded\s+from\s+(?:the\s+)?repo\w*"
    r")",
    re.IGNORECASE,
)

# A 4B skeptic regularly argues its way to "the finding is real" and then
# returns real=false anyway. The prose is not authoritative, but a refutation
# that contradicts itself is not one either, so it does not get to delete a
# finding.
_ASSERTS_REAL = re.compile(
    r"(?:"
    r"(?:finding|issue|vulnerability|vuln|flaw|report)\s+(?:is|does\s+(?:appear|seem))"
    r"\s+(?:in\s+fact\s+)?(?:to\s+be\s+)?(?:real|valid|genuine|correct|legitimate|accurate)"
    r"|is\s+(?:a|an)\s+(?:\w+\s+){0,2}(?:real|valid|genuine|legitimate)\s+"
    r"(?:finding|issue|vulnerability|vuln|flaw|concern|risk)"
    r"|(?:cannot|can\s?not|can't|could\s+not|couldn't|unable\s+to)\s+(?:be\s+)?refute"
    r"|(?:i\s+)?confirm(?:s|ed)?\s+(?:the\s+|this\s+)?(?:finding|issue|vulnerability)"
    r")",
    re.IGNORECASE,
)


def refuses_on_context(reason: str) -> bool:
    """True when a refutation rests on what the file IS rather than what it does."""
    return bool(_OUT_OF_BOUNDS.search(reason or ""))


def asserts_real(reason: str) -> bool:
    """True when a refutation's own words conclude the finding is real."""
    return bool(_ASSERTS_REAL.search(reason or ""))


@dataclass
class SwarmEvent:
    """Progress signal emitted as the run proceeds."""

    phase: str          # plan | hunt | sift | verify | synth
    status: str         # start | done | error | skip
    agent: str = ""
    file: str = ""
    detail: str = ""
    count: int = 0


@dataclass
class SwarmResult:
    findings: list[Finding] = field(default_factory=list)
    refuted: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    agents_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    stats: dict = field(default_factory=dict)

    def counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def worst_severity(self) -> str | None:
        return min(self.findings, key=lambda f: f.rank).severity if self.findings else None

    def to_dict(self) -> dict:
        return {
            "files": self.files,
            "agents_run": self.agents_run,
            "counts": self.counts(),
            "worst_severity": self.worst_severity(),
            "summary": self.summary,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
            "refuted": [f.to_dict() for f in self.refuted],
            "errors": self.errors,
        }


class Swarm:
    """Runs a fleet of specialist agents against one or more files."""

    def __init__(
        self,
        client,
        *,
        rag=None,
        rag_top_k: int = 3,
        concurrency: int = SWARM_CONCURRENCY,
        verifier_votes: int = VERIFIER_VOTES,
        min_confidence: float = MIN_CONFIDENCE,
        chunk_tokens: int = CHUNK_TOKENS,
        on_event: Callable[[SwarmEvent], None] | None = None,
    ):
        self.client = client
        self.rag = rag
        self.rag_top_k = rag_top_k
        self.concurrency = max(1, concurrency)
        self.verifier_votes = max(0, verifier_votes)
        self.min_confidence = min_confidence
        self.verify_overrides = 0
        # Agent calls that raised. A run where every call failed produced no
        # analysis at all, and must not be reported as a clean result.
        self.hunt_failures = 0
        # RESERVE_OUTPUT_TOKENS is the model's room to answer inside num_ctx;
        # code windows have to fit in what is left.
        self.context_budget = max(0, client.num_ctx - RESERVE_OUTPUT_TOKENS)
        self.chunk_tokens = min(chunk_tokens, max(512, self.context_budget))
        self.on_event = on_event
        self._rag_cache: dict[tuple, str] = {}
        self._rag_lock = threading.Lock()
        self._errors_lock = threading.Lock()
        self._errors: list[str] = []

    def _emit(self, phase: str, status: str, **kw):
        if self.on_event:
            self.on_event(SwarmEvent(phase=phase, status=status, **kw))

    def plan(
        self,
        files: list[dict],
        *,
        only_agents: list[str] | None = None,
        run_all: bool = False,
    ) -> list[dict]:
        """
        Build the task list: one entry per (file window x relevant agent).

        Windows carry absolute line numbers, so a finding inside a window still
        points at the right line of the whole file.
        """
        tasks: list[dict] = []
        for info in files:
            content = info["content"]
            agents = select_agents(
                content,
                info.get("extension", ""),
                only=only_agents,
                run_all=run_all,
            )
            if not agents:
                self._emit(
                    "plan", "skip", file=info["name"],
                    detail="no agent matches this file type",
                )
                continue

            windows = list(
                window_by_lines(content, self.chunk_tokens, CHUNK_OVERLAP_LINES)
            )
            for agent, signals in agents:
                for start_line, chunk in windows:
                    tasks.append({
                        "agent": agent,
                        "file": info,
                        "start_line": start_line,
                        "chunk": chunk,
                        "signals": signals,
                        "window_count": len(windows),
                    })

            self._emit(
                "plan", "done", file=info["name"],
                detail=(
                    f"{len(agents)} agents x {len(windows)} window(s): "
                    + ", ".join(a.name for a, _ in agents)
                ),
            )
        return tasks

    def stats_for(self, files: list[dict], tasks: list[dict]) -> dict:
        """The plan numbers, so the CLI panel and the report cannot disagree."""
        return {
            "files": len(files),
            "agent_calls": len(tasks),
            "windows": len({(t["file"]["path"], t["start_line"]) for t in tasks}),
            "code_tokens": sum(count_tokens(f["content"]) for f in files),
            "context_budget": self.context_budget,
        }

    def _rag_context(self, agent: AgentSpec, signals: list[str]) -> str:
        """
        Retrieve knowledge-base context for this agent and for what the regex
        pre-scan actually found in the file, so the lookup depends on the code
        under review instead of being a fixed per-agent string. Identical
        (agent, signals) pairs reuse the cached result.
        """
        if not self.rag or not agent.rag_query:
            return ""
        leads = tuple(sorted(set(signals or ())))[:5]
        key = (agent.name, leads)
        with self._rag_lock:
            if key in self._rag_cache:
                return self._rag_cache[key]

        query = agent.rag_query
        if leads:
            query += " " + " ".join(leads)
        try:
            ctx = self.rag.format_context(
                query,
                top_k=self.rag_top_k,
                categories=agent.rag_categories or None,
            ) or ""
        except Exception as e:
            self._record_error(f"RAG lookup failed for {agent.name}: {e}")
            ctx = ""
        with self._rag_lock:
            self._rag_cache[key] = ctx
        return ctx

    def _hunt_one(self, task: dict) -> list[Finding]:
        agent: AgentSpec = task["agent"]
        info = task["file"]
        start_line = task["start_line"]
        chunk = task["chunk"]

        window_note = ""
        if task["window_count"] > 1:
            end_line = start_line + len(chunk.splitlines()) - 1
            window_note = (
                f"\nThis is a PARTIAL view: lines {start_line}-{end_line} of "
                f"{len(info['content'].splitlines())}. Judge only what is here.\n"
            )

        leads = ""
        if task["signals"]:
            leads = (
                "\nA regex pre-scan flagged these patterns in this file. Check "
                "each one, and keep looking beyond them:\n"
                + "\n".join(f"  - {s}" for s in task["signals"][:8])
                + "\n"
            )

        system = agent.system_prompt
        rag_ctx = self._rag_context(agent, task["signals"])
        if rag_ctx:
            system = f"{system}\n\n{rag_ctx}"

        user = (
            f"File: {info['name']}\n"
            f"Type: {info.get('extension') or 'unknown'}\n"
            f"{window_note}{leads}\n"
            f"Source (the number before each | is the real line number):\n"
            f"```\n{number_lines(chunk, start=start_line)}\n```"
        )

        self._emit("hunt", "start", agent=agent.name, file=info["name"])

        data = self.client.chat_json(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            agent.schema,
            temperature=agent.temperature,
        )

        max_line = len(info["content"].splitlines())
        findings: list[Finding] = []
        for raw in data.get("findings") or []:
            if not isinstance(raw, dict):
                continue
            f = Finding.from_model(
                raw, agent=agent.name, file=info["path"], max_line=max_line
            )
            if f is not None:
                findings.append(f)

        self._emit(
            "hunt", "done", agent=agent.name, file=info["name"],
            detail=f"{len(findings)} raw",
        )
        return findings

    def hunt(self, tasks: list[dict]) -> list[Finding]:
        """Run every planned task concurrently."""
        findings: list[Finding] = []
        self.hunt_failures = 0
        if not tasks:
            return findings

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {pool.submit(self._hunt_one, t): t for t in tasks}
            try:
                for fut in as_completed(futures):
                    task = futures[fut]
                    try:
                        findings.extend(fut.result())
                    except Exception as e:
                        self.hunt_failures += 1
                        self._record_error(
                            f"{task['agent'].name} on {task['file']['name']}: {e}"
                        )
                        self._emit(
                            "hunt", "error", agent=task["agent"].name,
                            file=task["file"]["name"], detail=str(e),
                        )
            except KeyboardInterrupt:
                for fut in futures:
                    fut.cancel()
                raise
        return findings

    def sift(self, findings: list[Finding], files: list[dict]) -> list[Finding]:
        """
        Narrow deterministically: drop anything under the confidence floor,
        mark findings whose evidence is absent from the source, and collapse
        duplicates reported by several agents or windows.
        """
        by_path = {f["path"]: f["content"] for f in files}
        kept: list[Finding] = []

        for f in findings:
            if f.confidence < self.min_confidence:
                continue
            source = by_path.get(f.file, "")
            if f.evidence and source:
                needle = normalize_snippet(f.evidence)
                haystack = normalize_snippet(source)
                if len(needle) >= 8 and needle not in haystack:
                    # The model may have reflowed the statement while quoting.
                    if squash(f.evidence) not in squash(source):
                        f.unverified_evidence = True
                        f.confidence = min(f.confidence, 0.4)
            kept.append(f)

        merged: dict[tuple, Finding] = {}
        for f in kept:
            key = f.dedupe_key()
            existing = merged.get(key)
            if existing is None:
                merged[key] = f
                continue
            winner, loser = (
                (f, existing)
                if (f.rank, -f.confidence) < (existing.rank, -existing.confidence)
                else (existing, f)
            )
            agents = {a for a in (winner.agent + "," + loser.agent).split(",") if a}
            winner.agent = ",".join(sorted(agents))
            merged[key] = winner

        out = list(merged.values())
        out.sort(key=lambda f: (f.rank, -f.confidence, f.file, f.line))
        self._emit(
            "sift", "done",
            detail=f"{len(findings)} raw -> {len(out)} unique",
            count=len(out),
        )
        return out

    def _context_around(self, finding: Finding, files: list[dict], radius: int = 20) -> str:
        for info in files:
            if info["path"] == finding.file:
                lines = info["content"].splitlines()
                start = max(1, finding.line - radius)
                end = min(len(lines), finding.line + radius)
                excerpt = "\n".join(lines[start - 1:end])
                return number_lines(excerpt, start=start)
        return ""

    def _verify_one(self, finding: Finding, files: list[dict]) -> Finding:
        context = self._context_around(finding, files)
        prompt = (
            f"Finding reported by {finding.agent}:\n"
            f"  Title      : {finding.title}\n"
            f"  Severity   : {finding.severity}\n"
            f"  Category   : {finding.category}\n"
            f"  Location   : {finding.file}:{finding.line}\n"
            f"  Evidence   : {truncate(finding.evidence, 400)}\n"
            f"  Impact     : {truncate(finding.impact, 300)}\n"
            + (
                "  NOTE       : the quoted evidence was NOT found in the source "
                "file. Treat this as a strong sign of a fabricated finding.\n"
                if finding.unverified_evidence else ""
            )
            + f"\nSurrounding code:\n```\n{context}\n```\n\n"
            "Refute this finding if you can."
        )

        self._emit("verify", "start", agent=SKEPTIC.name, file=finding.file,
                   detail=truncate(finding.title, 50))

        votes: list[dict] = []
        for _ in range(self.verifier_votes):
            data = self.client.chat_json(
                [
                    {"role": "system", "content": SKEPTIC.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                VERDICT_SCHEMA,
                temperature=SKEPTIC.temperature,
            )
            votes.append({
                "real": bool(data.get("real")),
                "reason": str(data.get("reason") or "").strip(),
                "adjusted_severity": str(data.get("adjusted_severity") or "").lower(),
            })

        finding.votes = votes
        real_votes = sum(1 for v in votes if v["real"])
        # Strict majority: more than half must call it real, so a tie (possible
        # only with an even vote count) falls to refuted. With one vote this is
        # just that vote, not a majority of anything.
        finding.verdict = "real" if real_votes * 2 > len(votes) else "refuted"
        finding.verdict_reason = next(
            (v["reason"] for v in votes if v["real"] == (finding.verdict == "real")),
            "",
        )

        if finding.verdict == "refuted":
            # A refutation may only rest on what the code does. Two kinds are
            # thrown out: one that argues from what the file is, and one whose
            # own reasoning concludes the finding is real.
            out_of_bounds = [
                v for v in votes
                if not v["real"] and refuses_on_context(v["reason"])
            ]
            contradicts_itself = [
                v for v in votes
                if not v["real"] and asserts_real(v["reason"])
            ]
            rejected = out_of_bounds or contradicts_itself
            if rejected:
                for v in rejected:
                    v["policy_override"] = True
                finding.verdict = "unverified"
                grounds = (
                    "Refuted on out-of-bounds grounds (what the file is, not "
                    "what the code does)"
                    if out_of_bounds else
                    "The refutation's own reasoning concludes the finding is real"
                )
                finding.verdict_reason = (
                    grounds
                    + ", so the refutation was discarded and this finding is "
                    "kept for a human. Verifier said: "
                    + truncate(rejected[0]["reason"], 240)
                )

        if finding.verdict in ("real", "unverified"):
            # Accept a downgrade, ignore an upgrade. Across several votes take
            # the harshest severity proposed, so one lenient skeptic cannot
            # bury a finding on its own.
            from modules.schema import SEVERITY_RANK
            # An overridden refutation still carries the severity the verifier
            # thought fit. That is where its context judgement belonged, so
            # honour it rather than discarding the whole vote.
            proposed = [
                v["adjusted_severity"] for v in votes
                if (v["real"] or v.get("policy_override"))
                and v["adjusted_severity"] in SEVERITIES
            ]
            if proposed:
                adjusted = min(proposed, key=lambda sev: SEVERITY_RANK[sev])
                if SEVERITY_RANK[adjusted] > finding.rank:
                    finding.severity = adjusted

        self._emit("verify", "done", agent=SKEPTIC.name, file=finding.file,
                   detail=f"{finding.verdict}: {truncate(finding.title, 40)}")
        return finding

    def verify(
        self, findings: list[Finding], files: list[dict]
    ) -> tuple[list[Finding], list[Finding]]:
        """Adversarially verify each finding. Returns (confirmed, refuted)."""
        if not findings or self.verifier_votes == 0:
            return findings, []

        confirmed: list[Finding] = []
        refuted: list[Finding] = []
        self.verify_overrides = 0

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {
                pool.submit(self._verify_one, f, files): f for f in findings
            }
            try:
                for fut in as_completed(futures):
                    finding = futures[fut]
                    try:
                        result = fut.result()
                    except Exception as e:
                        # A verifier crash must not delete the finding.
                        self._record_error(f"verify {finding.title}: {e}")
                        finding.verdict = "unverified"
                        finding.verdict_reason = f"verifier failed: {e}"
                        confirmed.append(finding)
                        continue
                    if result.verdict in ("real", "unverified"):
                        confirmed.append(result)
                    else:
                        refuted.append(result)
            except KeyboardInterrupt:
                for fut in futures:
                    fut.cancel()
                raise

        self.verify_overrides = sum(
            1 for f in confirmed
            if any(v.get("policy_override") for v in f.votes)
        )
        confirmed.sort(key=lambda f: (f.rank, -f.confidence, f.file, f.line))
        refuted.sort(key=lambda f: (f.rank, f.file, f.line))
        return confirmed, refuted

    def synthesize(self, findings: list[Finding], files: list[dict]) -> dict:
        listing = "\n".join(
            f"- [{f.severity}] {f.title} ({f.file}:{f.line}) "
            f"- {truncate(f.impact, 160)}"
            for f in findings[:40]
        ) or "(no findings survived verification)"

        prompt = (
            f"Files scanned: {', '.join(f['name'] for f in files[:20])}\n"
            f"Confirmed findings: {len(findings)}\n\n{listing}"
        )

        self._emit("synth", "start", agent=SYNTHESIZER.name)
        try:
            data = self.client.chat_json(
                [
                    {"role": "system", "content": SYNTHESIZER.system_prompt},
                    {"role": "user", "content": prompt},
                ],
                SUMMARY_SCHEMA,
                temperature=SYNTHESIZER.temperature,
            )
        except Exception as e:
            self._record_error(f"synthesis failed: {e}")
            self._emit("synth", "error", agent=SYNTHESIZER.name, detail=str(e))
            return {}
        self._emit("synth", "done", agent=SYNTHESIZER.name)
        return data

    def run(
        self,
        files: list[dict],
        *,
        only_agents: list[str] | None = None,
        run_all: bool = False,
        verify: bool = True,
        synthesize: bool = True,
        tasks: list[dict] | None = None,
    ) -> SwarmResult:
        result = SwarmResult(files=[f["name"] for f in files])
        self._errors = result.errors

        if tasks is None:
            tasks = self.plan(files, only_agents=only_agents, run_all=run_all)
        result.agents_run = sorted({t["agent"].name for t in tasks})
        result.stats = self.stats_for(files, tasks)
        if not tasks:
            return result

        raw = self.hunt(tasks)
        result.stats["raw_findings"] = len(raw)
        result.stats["agent_failures"] = self.hunt_failures

        sifted = self.sift(raw, files)
        result.stats["unique_findings"] = len(sifted)

        if verify:
            confirmed, refuted = self.verify(sifted, files)
        else:
            confirmed, refuted = sifted, []
        result.findings = confirmed
        result.refuted = refuted
        result.stats["confirmed"] = len(confirmed)
        result.stats["refuted"] = len(refuted)
        if verify and self.verify_overrides:
            result.stats["verify_overridden"] = self.verify_overrides

        if synthesize:
            result.summary = self.synthesize(confirmed, files)

        return result

    def _record_error(self, message: str):
        with self._errors_lock:
            self._errors.append(message)
