"""DevSecGuard AI core engine.

Two detection layers run on every file:

1. A deterministic regex layer that catches hardcoded credentials instantly and
   works offline.
2. An LLM layer (NVIDIA Nemotron served on Nebius Token Factory) that reasons
   about the code and finds contextual flaws such as SQL injection, command
   injection or unsafe deserialization.

Detected secrets are masked *before* any code is sent to the model, so live
credentials never leave the machine.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"

SEVERITIES = ("low", "medium", "high", "critical")
RANK = {name: i for i, name in enumerate(SEVERITIES)}

# Per the hackathon brief: Nano / Super for fast everyday calls, Ultra for heavy reasoning.
MODEL_PREFERENCE = ("super", "nano", "ultra")
MODEL_EXCLUDE = ("embed", "rerank", "guard", "safety", "reward", "parse", "omni")

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sh",
    ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".tf", ".sql", ".cs",
    ".rs", ".kt", ".swift", ".c", ".cpp", ".h",
}
SKIP_DIRS = {
    ".git", "venv", ".venv", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build",
}


class LLMError(RuntimeError):
    """Raised when the model call or its response cannot be used."""


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    severity: str
    title: str
    line: Optional[int] = None
    explanation: str = ""
    fix: str = ""
    source: str = "regex"  # "regex" or "llm"
    snippet: str = ""


@dataclass
class FileResult:
    path: str
    findings: List[Finding] = field(default_factory=list)
    llm_used: bool = False
    llm_error: str = ""
    llm_seconds: float = 0.0
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Layer 1: secret rules
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SecretRule:
    name: str
    pattern: "re.Pattern[str]"
    severity: str
    group: int = 0
    generic: bool = False


RULES: Tuple[SecretRule, ...] = (
    SecretRule("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    SecretRule("Stripe live secret key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{10,}\b"), "critical"),
    SecretRule("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "critical"),
    SecretRule("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "critical"),
    SecretRule("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "critical"),
    SecretRule("NVIDIA API key", re.compile(r"\bnvapi-[A-Za-z0-9_\-]{20,}\b"), "critical"),
    SecretRule("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "critical"),
    SecretRule("OpenAI-style secret key", re.compile(r"\bsk-[A-Za-z0-9_\-]{32,}\b"), "critical"),
    SecretRule(
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        "critical",
    ),
    SecretRule(
        "AWS secret access key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "critical",
        group=1,
    ),
    # Must stay last: it only fires if no specific rule already matched the same text.
    SecretRule(
        "Hardcoded credential",
        re.compile(
            r"""(?i)[A-Za-z0-9_\-]*(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|passwd|password|pwd)['"]?\s*[:=]\s*['"]([^'"\s]{8,})['"]"""
        ),
        "high",
        group=1,
        generic=True,
    ),
)

PLACEHOLDER_HINTS = (
    "your", "example", "placeholder", "changeme", "change_me", "dummy",
    "sample", "xxxx", "****", "<", ">", "${", "{{", "{%", "todo", "redacted",
)
ENV_READ_HINTS = ("os.environ", "getenv", "process.env", "secrets.", "os.getenv")


_TEMPLATE_RE = re.compile(r"\{[^{}]*\}|%[sd]|%\([^)]*\)s")


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    if any(hint in low for hint in PLACEHOLDER_HINTS):
        return True
    # f-string / format-string interpolation such as {token} or %s is not a literal secret
    return _TEMPLATE_RE.fullmatch(value) is not None


def _reads_from_env(line: str) -> bool:
    return any(hint in line for hint in ENV_READ_HINTS)


def _find_spans(line: str) -> List[Tuple[int, int, SecretRule]]:
    spans: List[Tuple[int, int, SecretRule]] = []
    for rule in RULES:
        for match in rule.pattern.finditer(line):
            start, end = match.span(rule.group) if rule.group else match.span()
            if start == -1:
                continue
            value = line[start:end]
            if rule.generic and (_looks_like_placeholder(value) or _reads_from_env(line)):
                continue
            if any(start < o_end and o_start < end for o_start, o_end, _ in spans):
                continue
            spans.append((start, end, rule))
    spans.sort(key=lambda s: s[0])
    return spans


def _mask(value: str) -> str:
    return value[:4] + "********" if len(value) > 8 else "********"


def scan_secrets(text: str) -> List[Finding]:
    """Deterministic secret scan. Returns findings with masked snippets."""
    findings: List[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for start, end, rule in _find_spans(line):
            masked = line[:start] + _mask(line[start:end]) + line[end:]
            findings.append(
                Finding(
                    severity=rule.severity,
                    title=f"{rule.name} detected",
                    line=number,
                    explanation=(
                        "A credential appears to be committed in source code. Anyone with "
                        "access to the repository or its history can use it."
                    ),
                    fix=(
                        "Revoke and rotate the credential now, then load it from an "
                        "environment variable or a secret manager instead of the source."
                    ),
                    source="regex",
                    snippet=masked.strip()[:160],
                )
            )
    return findings


def redact_for_llm(text: str) -> str:
    """Replace every detected secret with a marker. Line numbers are preserved."""
    out_lines = []
    for line in text.splitlines():
        for start, end, _ in reversed(_find_spans(line)):
            line = line[:start] + "[REDACTED_SECRET]" + line[end:]
        out_lines.append(line)
    return "\n".join(out_lines)


# --------------------------------------------------------------------------- #
# Layer 2: LLM analysis (Nemotron on Nebius Token Factory)
# --------------------------------------------------------------------------- #
SYSTEM_PROMPT = """You are DevSecGuard AI, a DevSecOps code-security reviewer running in a CI/CD pipeline.
Review the user's source file and report real security problems only.

Severity guide:
- critical: exposed live credentials, private keys, API tokens
- high: SQL injection, command injection, remote code execution (eval/exec), unsafe deserialization, authentication bypass, path traversal, SSRF
- medium: weak or missing input validation, missing rate limiting, insecure TLS or crypto settings
- low: minor hardening or hygiene issues

Rules:
- Secrets were already replaced with [REDACTED_SECRET]. Do not report the redaction itself.
- Do not invent problems. If the file is safe, return an empty list.
- Reply with ONE JSON object and nothing else (no markdown, no prose):
{"findings":[{"severity":"critical|high|medium|low","title":"short title","line":<line number or null>,"explanation":"why it is risky","fix":"how to fix it"}]}"""


def build_messages(path: str, code: str) -> List[dict]:
    numbered = "\n".join(f"{i}: {line}" for i, line in enumerate(code.splitlines(), start=1))
    user = f"File: {path}\n\n{numbered}"
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def make_client(api_key: Optional[str] = None, base_url: Optional[str] = None):
    """Create an OpenAI-compatible client pointed at Nebius Token Factory."""
    from openai import OpenAI  # imported lazily so the regex layer works without it

    key = api_key or os.getenv("NEBIUS_API_KEY")
    if not key:
        raise LLMError("NEBIUS_API_KEY is not set.")
    return OpenAI(base_url=base_url or os.getenv("NEBIUS_BASE_URL") or DEFAULT_BASE_URL, api_key=key)


def list_nemotron_models(client) -> List[str]:
    ids = [m.id for m in client.models.list().data]
    return sorted(i for i in ids if "nemotron" in i.lower())


def pick_model(client, preferred: Optional[str] = None) -> str:
    """Return the model id to use: explicit choice, NEBIUS_MODEL, or best Nemotron available."""
    explicit = preferred or os.getenv("NEBIUS_MODEL")
    if explicit:
        return explicit
    candidates = list_nemotron_models(client)
    if not candidates:
        raise LLMError(
            "No NVIDIA Nemotron model found on this Nebius account. "
            "Run `python agent.py --list-models` or set NEBIUS_MODEL."
        )
    usable = [c for c in candidates if not any(x in c.lower() for x in MODEL_EXCLUDE)] or candidates
    for tier in MODEL_PREFERENCE:
        for cid in usable:
            if tier in cid.lower():
                return cid
    return usable[0]


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json(text: str) -> object:
    """Pull a JSON value out of a model reply (handles <think> blocks and code fences)."""
    cleaned = _THINK_RE.sub("", text or "").strip()
    fence = _FENCE_RE.search(cleaned)
    if fence:
        cleaned = fence.group(1).strip()
    try:
        return json.loads(cleaned)
    except ValueError:
        pass
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(cleaned[start : end + 1])
        except ValueError:
            pass
    raise LLMError("Model reply was not valid JSON.")


def normalize_findings(data: object) -> List[Finding]:
    items = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise LLMError("JSON did not contain a findings list.")
    out: List[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity", "low")).strip().lower()
        if severity not in RANK:
            severity = "low"
        line = item.get("line")
        line = line if isinstance(line, int) and line > 0 else None
        out.append(
            Finding(
                severity=severity,
                title=str(item.get("title", "Security issue"))[:120],
                line=line,
                explanation=str(item.get("explanation", ""))[:600],
                fix=str(item.get("fix", ""))[:600],
                source="llm",
            )
        )
    return out


def llm_scan(client, model: str, code: str, path: str = "<input>", timeout: float = 90.0):
    """Ask the model to review `code`. Returns (findings, seconds)."""
    started = time.perf_counter()
    try:
        response = client.chat.completions.create(
            model=model,
            messages=build_messages(path, code),
            temperature=0.1,
            max_tokens=1500,
            timeout=timeout,
        )
        content = response.choices[0].message.content or ""
    except Exception as exc:  # network, auth, model-not-found, ...
        raise LLMError(f"{type(exc).__name__}: {exc}") from exc
    findings = normalize_findings(extract_json(content))
    return findings, time.perf_counter() - started


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
_SECRETISH = ("secret", "credential", "api key", "api_key", "token", "password", "private key")


def _merge(regex_findings: Sequence[Finding], llm_findings: Sequence[Finding]) -> List[Finding]:
    regex_lines = {f.line for f in regex_findings}
    merged = list(regex_findings)
    for f in llm_findings:
        duplicate = f.line in regex_lines and any(w in f.title.lower() for w in _SECRETISH)
        if not duplicate:
            merged.append(f)
    return merged


def scan_text(
    text: str,
    path: str = "<input>",
    client=None,
    model: Optional[str] = None,
    max_chars: int = 12000,
) -> FileResult:
    """Scan one piece of source text with both layers (LLM layer only if a client is given)."""
    started = time.perf_counter()
    regex_findings = scan_secrets(text)
    result = FileResult(path=path, findings=list(regex_findings))
    if client is not None and model and text.strip():
        try:
            llm_findings, secs = llm_scan(client, model, redact_for_llm(text)[:max_chars], path)
            result.llm_used = True
            result.llm_seconds = secs
            result.findings = _merge(regex_findings, llm_findings)
        except LLMError as exc:
            result.llm_error = str(exc)[:300]
    result.findings.sort(key=lambda f: (-RANK[f.severity], f.line or 0))
    result.seconds = time.perf_counter() - started
    return result


def max_severity(results: Iterable[FileResult]) -> Optional[str]:
    best = None
    for r in results:
        for f in r.findings:
            if best is None or RANK[f.severity] > RANK[best]:
                best = f.severity
    return best


def is_blocked(results: Iterable[FileResult], fail_on: str = "high") -> bool:
    top = max_severity(results)
    return top is not None and RANK[top] >= RANK[fail_on]


def _is_excluded(rel_path: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        clean = pattern.strip().rstrip("/")
        if not clean:
            continue
        if fnmatch.fnmatch(rel_path, clean) or rel_path == clean or rel_path.startswith(clean + "/"):
            return True
    return False


def collect_files(root: str, exclude: Sequence[str] = (), max_bytes: int = 200_000) -> List[str]:
    """Walk `root` and return scannable source files (sorted, absolute paths)."""
    root = os.path.abspath(root)
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1].lower()
            is_env_file = name == ".env" or name.startswith(".env.")
            if ext not in SCAN_EXTENSIONS and not is_env_file:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if _is_excluded(rel, exclude):
                continue
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            found.append(full)
    return found


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
ICON = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def render_console(results: Sequence[FileResult], root: str = "") -> str:
    lines: List[str] = []
    for r in results:
        if not r.findings and not r.llm_error:
            continue
        shown = os.path.relpath(r.path, root) if root and os.path.isabs(r.path) else r.path
        lines.append(f"\n{shown}  ({r.seconds:.2f}s)")
        for f in r.findings:
            where = f":{f.line}" if f.line else ""
            lines.append(f"  [{ICON[f.severity]}] {f.title}{where}  ({f.source})")
            if f.snippet:
                lines.append(f"      code: {f.snippet}")
            if f.explanation:
                lines.append(f"      risk: {f.explanation}")
            if f.fix:
                lines.append(f"      fix : {f.fix}")
        if r.llm_error:
            lines.append(f"  [note] LLM layer skipped: {r.llm_error}")
    return "\n".join(lines) if lines else "No findings."


def render_markdown(results: Sequence[FileResult], blocked: bool, fail_on: str, model: str, seconds: float) -> str:
    status = "BLOCKED" if blocked else "PASSED"
    rows = ["| Severity | File | Line | Finding | Source |", "|---|---|---|---|---|"]
    count = 0
    for r in results:
        for f in r.findings:
            count += 1
            rows.append(f"| {f.severity.upper()} | `{r.path}` | {f.line or ''} | {f.title} | {f.source} |")
    head = (
        f"## DevSecGuard AI: {status}\n\n"
        f"- Threshold: `{fail_on}` or higher blocks the push\n"
        f"- Model: `{model or 'regex-only'}`\n"
        f"- Files scanned: {len(results)}, findings: {count}, time: {seconds:.2f}s\n\n"
    )
    return head + ("\n".join(rows) if count else "No findings.") + "\n"


def to_json(results: Sequence[FileResult], blocked: bool, fail_on: str, model: str, seconds: float) -> str:
    payload = {
        "blocked": blocked,
        "fail_on": fail_on,
        "model": model or None,
        "total_seconds": round(seconds, 3),
        "files": [r.to_dict() for r in results],
    }
    return json.dumps(payload, indent=2)


# --------------------------------------------------------------------------- #
# Demo input (built at runtime so no live-looking secret is stored in the repo)
# --------------------------------------------------------------------------- #
def demo_code() -> str:
    fake_key = "sk_" + "live_" + "DEMO0123456789abcdefghij"
    return (
        "import os\n"
        "import sqlite3\n"
        "\n"
        f'STRIPE_API_KEY = "{fake_key}"\n'
        "\n"
        "def get_user(conn, user_id):\n"
        "    query = \"SELECT * FROM users WHERE id = '%s'\" % user_id\n"
        "    return conn.execute(query).fetchone()\n"
        "\n"
        "def ping(host):\n"
        "    os.system(\"ping -c 1 \" + host)\n"
    )
