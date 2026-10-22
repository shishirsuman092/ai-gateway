"""Guardrails for plain-text queries and their results.

Input:  length and control-character limits, prompt-injection patterns (block), secret and PII redaction.
SQL:    generated SQL must be read-only; write or DDL statements are dropped from the result.
Output: secrets and PII are redacted before the answer reaches the caller or the audit log.

These are heuristics. They reduce risk; they do not replace Unity Catalog permissions,
which remain the real data boundary.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_QUESTION_CHARS = 2000

INJECTION_PATTERNS = [
    re.compile(r"ignore (all |any |the )?(previous|prior|above) (instructions|prompts?|rules)", re.I),
    re.compile(r"disregard (all |any |the )?(previous|prior|above|your) (instructions|rules|guidelines)", re.I),
    re.compile(r"(reveal|print|show|dump) (your |the )?(system prompt|hidden instructions|api keys?|secrets?)", re.I),
    re.compile(r"you are now (in )?(developer|dan|jailbreak) mode", re.I),
    re.compile(r"</?(system|assistant)>", re.I),
]

SECRET_PATTERNS = [
    ("databricks_pat", re.compile(r"\bdapi[0-9a-f]{32}\b", re.I)),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b", re.I)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("password_assignment", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*\S+")),
]

PII_PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
]

WRITE_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|DROP|ALTER|CREATE|TRUNCATE|GRANT|REVOKE|REPLACE|COPY|CALL|EXEC)\b",
    re.I,
)


class GuardrailBlock(Exception):
    """Raised when an input violates policy. The message is safe to show the caller."""


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(text: str) -> tuple[str, list[str]]:
    """Replace secrets and PII with [REDACTED:<kind>]. Returns the text and the kinds found."""
    found: list[str] = []
    for kind, pattern in SECRET_PATTERNS:
        text, n = pattern.subn(f"[REDACTED:{kind}]", text)
        if n:
            found.append(kind)
    for kind, pattern in PII_PATTERNS:
        def repl(match: re.Match, kind: str = kind) -> str:
            if kind == "card" and not _luhn_ok(re.sub(r"\D", "", match.group(0))):
                return match.group(0)
            found.append(kind)
            return f"[REDACTED:{kind}]"

        text = pattern.sub(repl, text)
    return text, sorted(set(found))


@dataclass
class InputVerdict:
    question: str  # redacted question to send onward
    redactions: list[str] = field(default_factory=list)


def check_input(question: str, *, max_chars: int = MAX_QUESTION_CHARS) -> InputVerdict:
    if len(question) > max_chars:
        raise GuardrailBlock(f"question is longer than {max_chars} characters")
    if any(ord(c) < 32 and c not in "\n\t" for c in question):
        raise GuardrailBlock("question contains control characters")
    for pattern in INJECTION_PATTERNS:
        if pattern.search(question):
            raise GuardrailBlock("question matches a prompt-injection pattern")
    redacted, kinds = redact(question)
    return InputVerdict(question=redacted, redactions=kinds)


def check_output(result: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Redact the answer and drop write/DDL SQL. Returns the cleaned result and the kinds applied."""
    cleaned = dict(result)
    applied: list[str] = []
    if isinstance(cleaned.get("answer"), str):
        cleaned["answer"], kinds = redact(cleaned["answer"])
        applied += kinds
    if isinstance(cleaned.get("sql"), str):
        if WRITE_SQL.search(cleaned["sql"]):
            cleaned["sql"] = None
            applied.append("write_sql_removed")
        else:
            cleaned["sql"], kinds = redact(cleaned["sql"])
            applied += kinds
    return cleaned, sorted(set(applied))
