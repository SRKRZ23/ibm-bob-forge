"""
FORGE Scanner — LLM call-site detection and vulnerability mapping.

Scans a codebase for:
1. LLM call sites (OpenAI SDK, LangChain, LlamaIndex, Anthropic, etc.)
2. User-controlled input flowing into LLM prompts (prompt injection risk)
3. Missing governance layers (no output validation, no input sanitisation)
4. OWASP LLM Top 10 vulnerability patterns

Output: list of Finding objects, one per detected issue.
"""
from __future__ import annotations

import ast
import os
import re
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── Security limits ───────────────────────────────────────────────────────────
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FILES_PER_SCAN = 10_000
MAX_SCAN_DURATION_SECONDS = 60

# ── OWASP LLM Top 10 mapping ──────────────────────────────────────────────────
OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Insecure Output Handling",
    "LLM03": "Training Data Poisoning",
    "LLM04": "Model Denial of Service",
    "LLM05": "Supply Chain Vulnerabilities",
    "LLM06": "Sensitive Information Disclosure",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Excessive Agency",
    "LLM09": "Overreliance",
    "LLM10": "Model Theft",
}

# ── LLM call-site patterns ────────────────────────────────────────────────────
LLM_CALL_PATTERNS = [
    # OpenAI SDK
    (r"openai\.(ChatCompletion|Completion|chat\.completions)\.create", "openai_sdk", "LLM02"),
    (r"client\.chat\.completions\.create", "openai_sdk_v1", "LLM02"),
    (r"AsyncOpenAI|OpenAI\(\)", "openai_client_init", "LLM06"),

    # Anthropic SDK
    (r"anthropic\.Anthropic\(\)|AsyncAnthropic\(\)", "anthropic_client", "LLM06"),
    (r"client\.messages\.create", "anthropic_messages_create", "LLM02"),

    # LangChain
    (r"from langchain", "langchain_import", "LLM05"),
    (r"LLMChain|ConversationChain|RetrievalQA|AgentExecutor", "langchain_chain", "LLM08"),
    (r"ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI", "langchain_llm", "LLM02"),
    (r"PromptTemplate|ChatPromptTemplate|HumanMessagePromptTemplate", "langchain_prompt", "LLM01"),

    # LlamaIndex
    (r"from llama_index|import llama_index", "llamaindex_import", "LLM05"),
    (r"OpenAIEmbedding|LLM\(\)|OpenAI\(model=", "llamaindex_llm", "LLM02"),

    # Google AI
    (r"genai\.GenerativeModel|google\.generativeai", "google_genai", "LLM02"),
    (r"GenerativeModel\(", "gemini_model", "LLM02"),

    # Hugging Face
    (r"pipeline\(['\"]text-generation", "hf_pipeline", "LLM02"),
    (r"AutoModelForCausalLM|AutoTokenizer\.from_pretrained", "hf_model_load", "LLM05"),

    # Generic prompt concatenation risks
    (r"f['\"].*\{(user_input|query|prompt|message|text|content|request)\}", "fstring_injection", "LLM01"),
    (r'\.format\(.*(?:user_input|query|prompt|message)\)', "str_format_injection", "LLM01"),
    (r"system_prompt\s*\+|prompt\s*\+=|messages\.append\(.*user", "prompt_concat", "LLM01"),
    
    # System Prompt Leakage (LLM07)
    (r"system_prompt\s*=\s*['\"](?:[^'\"]{50,}|.*(?:You are|Act as|Your role).*)['\"]", "hardcoded_system_prompt", "LLM07"),
    (r"['\"]role['\"]\s*:\s*['\"]system['\"]\s*,\s*['\"]content['\"]\s*:\s*['\"](?:[^'\"]{50,}|.*(?:You are|Act as|assistant))", "hardcoded_system_message", "LLM07"),
    (r"(?:print|log|logger\.\w+|console\.log)\s*\(.*(?:system_prompt|system_message|system_instruction)", "system_prompt_logging", "LLM07"),
    (r"system_prompt\s*\+\s*(?:user_input|query|request|message)|(?:user_input|query|request|message)\s*\+\s*system_prompt", "system_prompt_user_concat", "LLM07"),
    (r"['\"]role['\"]\s*:\s*['\"]system['\"]\s*,\s*['\"]content['\"]\s*:\s*(?:f['\"]|.*\.format\()", "system_prompt_fstring", "LLM07"),
]

# ── Missing governance patterns ───────────────────────────────────────────────
GOVERNANCE_ANTI_PATTERNS = [
    # No output validation
    (r"\.content\s*$|response\[.message.\]\[.content.\]\s*$", "raw_output_use", "LLM02"),
    # Hardcoded API keys
    (r"(?:sk-|pk-|api_key\s*=\s*)[\"'][A-Za-z0-9_\-]{20,}", "hardcoded_api_key", "LLM06"),
    # No rate limiting
    (r"while True.*\.(chat|completion|generate|predict)", "unbounded_loop_llm", "LLM04"),
    # Direct tool use without validation
    (r"exec\(|subprocess\.run\(|os\.system\(", "unsafe_code_exec", "LLM08"),
    # Sensitive data in prompts
    (r"(?:SSN|password|credit.card|api.key).*\{", "pii_in_prompt_template", "LLM06"),
]


@dataclass
class LLMCallSite:
    file: str
    line: int
    code: str
    pattern_name: str
    owasp_id: str
    owasp_name: str
    severity: str  # HIGH / MEDIUM / LOW
    suggested_action: str


@dataclass
class ScanResult:
    repo_path: str
    scan_time_ms: float
    total_files_scanned: int
    total_lines_scanned: int
    call_sites: list[LLMCallSite] = field(default_factory=list)
    governance_gaps: list[LLMCallSite] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.call_sites) + len(self.governance_gaps)

    def by_owasp(self) -> dict[str, list[LLMCallSite]]:
        out: dict[str, list[LLMCallSite]] = {}
        for f in self.call_sites + self.governance_gaps:
            out.setdefault(f.owasp_id, []).append(f)
        return out

    def summary(self) -> dict:
        by_owasp = self.by_owasp()
        return {
            "repo": self.repo_path,
            "scan_time_ms": round(self.scan_time_ms, 1),
            "files_scanned": self.total_files_scanned,
            "lines_scanned": self.total_lines_scanned,
            "call_sites": len(self.call_sites),
            "governance_gaps": len(self.governance_gaps),
            "total_findings": self.total_findings,
            "owasp_breakdown": {k: len(v) for k, v in sorted(by_owasp.items())},
            "severity_breakdown": {
                "HIGH": sum(1 for f in self.call_sites + self.governance_gaps if f.severity == "HIGH"),
                "MEDIUM": sum(1 for f in self.call_sites + self.governance_gaps if f.severity == "MEDIUM"),
                "LOW": sum(1 for f in self.call_sites + self.governance_gaps if f.severity == "LOW"),
            },
        }


def _severity(owasp_id: str, pattern_name: str) -> str:
    high = {"LLM01", "LLM02", "LLM06", "LLM07", "LLM08"}
    if owasp_id in high:
        return "HIGH"
    if pattern_name in ("hardcoded_api_key", "pii_in_prompt_template"):
        return "HIGH"
    if owasp_id in {"LLM04", "LLM05"}:
        return "MEDIUM"
    return "LOW"


def _suggested_action(owasp_id: str) -> str:
    actions = {
        "LLM01": "Add SOUF AI DPI input sanitisation before LLM call",
        "LLM02": "Add output validation and content filtering post-LLM",
        "LLM04": "Add rate limiting middleware (SOUF AI rate_limits config)",
        "LLM05": "Pin dependency versions, audit supply chain",
        "LLM06": "Move credentials to env vars; add output PII filter (SOUF AI egress rule)",
        "LLM07": "Move system prompts to config; add ingress validation and egress logging (SOUF AI)",
        "LLM08": "Add human-in-the-loop gate for agentic tool calls",
    }
    return actions.get(owasp_id, "Review and add appropriate governance layer")


def _should_skip(path: Path) -> bool:
    skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                 "dist", "build", ".mypy_cache", ".pytest_cache"}
    skip_exts = {".pyc", ".pyo", ".so", ".dll", ".bin", ".jpg", ".png",
                 ".gif", ".ico", ".svg", ".pdf", ".zip", ".tar"}
    if any(p in skip_dirs for p in path.parts):
        return True
    return path.suffix in skip_exts


def scan_file_lines(
    file_path: Path,
    patterns: list[tuple[str, str, str]],
    compiled: list[re.Pattern],
    max_size_bytes: int = MAX_FILE_SIZE_BYTES,
) -> list[LLMCallSite]:
    findings = []
    
    # Security: Check file size before reading
    try:
        file_size = file_path.stat().st_size
        if file_size > max_size_bytes:
            # Skip files larger than max size
            return []
    except (OSError, PermissionError):
        return []
    
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        for (regex_src, name, owasp_id), compiled_re in zip(patterns, compiled):
            if compiled_re.search(line):
                findings.append(LLMCallSite(
                    file=str(file_path),
                    line=i,
                    code=stripped[:120],
                    pattern_name=name,
                    owasp_id=owasp_id,
                    owasp_name=OWASP_LLM.get(owasp_id, ""),
                    severity=_severity(owasp_id, name),
                    suggested_action=_suggested_action(owasp_id),
                ))
                break  # one finding per line per pattern group
    return findings


class ScanTimeoutError(Exception):
    """Raised when scan exceeds maximum duration."""
    pass


def _timeout_handler(signum, frame):
    """Signal handler for scan timeout."""
    raise ScanTimeoutError("Scan exceeded maximum duration")


def scan_repo(
    repo_path: str, 
    extensions: tuple[str, ...] = (".py", ".js", ".ts", ".go"),
    max_files: int = MAX_FILES_PER_SCAN,
    max_duration: int = MAX_SCAN_DURATION_SECONDS,
) -> ScanResult:
    root = Path(repo_path).resolve()
    t0 = time.perf_counter()

    # Pre-compile patterns
    call_compiled = [re.compile(p[0]) for p in LLM_CALL_PATTERNS]
    gov_compiled = [re.compile(p[0]) for p in GOVERNANCE_ANTI_PATTERNS]

    call_sites: list[LLMCallSite] = []
    gov_gaps: list[LLMCallSite] = []
    total_files = 0
    total_lines = 0
    
    # Security: Set timeout alarm (Unix-like systems only)
    timeout_set = False
    if hasattr(signal, 'SIGALRM') and max_duration > 0:
        try:
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(max_duration)
            timeout_set = True
        except (ValueError, OSError):
            # Signal not supported or can't set alarm
            pass

    try:
        for path in root.rglob("*"):
            # Security: Check if we've exceeded max files
            if total_files >= max_files:
                import logging
                logging.warning(f"Scan stopped: exceeded max files limit ({max_files})")
                break
            
            if not path.is_file():
                continue
            if _should_skip(path):
                continue
            if path.suffix not in extensions:
                continue
            
            total_files += 1
            
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").count("\n")
            except Exception:
                lines = 0
            total_lines += lines

            call_sites.extend(scan_file_lines(path, LLM_CALL_PATTERNS, call_compiled))
            gov_gaps.extend(scan_file_lines(path, GOVERNANCE_ANTI_PATTERNS, gov_compiled))
            
            # Manual timeout check for non-Unix systems
            if not timeout_set and max_duration > 0:
                if (time.perf_counter() - t0) > max_duration:
                    import logging
                    logging.warning(f"Scan stopped: exceeded max duration ({max_duration}s)")
                    break
    
    except ScanTimeoutError:
        import logging
        logging.warning(f"Scan timed out after {max_duration}s")
    
    finally:
        # Security: Cancel alarm
        if timeout_set:
            signal.alarm(0)

    elapsed_ms = (time.perf_counter() - t0) * 1000

    return ScanResult(
        repo_path=str(root),
        scan_time_ms=elapsed_ms,
        total_files_scanned=total_files,
        total_lines_scanned=total_lines,
        call_sites=call_sites,
        governance_gaps=gov_gaps,
    )
