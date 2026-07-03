#!/usr/bin/env python3
"""
scan_markdown.py

Scans converted Markdown (output of doc-to-markdown) for content that should
not reach an embedding index, vector store, or LLM context window:

  - Secrets/credentials (API keys, private keys, cloud access keys, tokens)
  - PII (emails, AU phone numbers, AU Tax File Numbers, credit card numbers)
  - Prompt-injection payloads, following the attack taxonomy in the OWASP
    LLM Prompt Injection Prevention Cheat Sheet:
    https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
      * Direct instruction override / role reassignment / fake system turns
      * Data exfiltration requests, bracketed directive markers
      * Jailbreak framing (DAN/developer-mode personas, hypothetical bypass)
      * System prompt extraction attempts
      * HTML/Markdown exfiltration markup (img/iframe/script with remote src)
      * Encoding obfuscation: base64/hex-encoded injection payloads, decoded
        and re-scanned
      * Typoglycemia keyword variants (scrambled middle letters) via
        Damerau-Levenshtein edit distance
      * Best-of-N character-spacing evasion ("i g n o r e")
      * Forged agent-trace lines (Thought:/Observation:/Action:) aimed at
        hijacking a downstream agent parser
  - Suspicious URLs (raw IP-address links, common URL shorteners)

Injection signals are split into two confidence tiers: HARD signals (specific
enough to auto-block) and SOFT signals -- typoglycemia/spacing/agent-trace
detectors, which have a higher false-positive rate against ordinary prose --
which contribute to a WARN rather than a BLOCK.

This is a text-level scanner. It does NOT scan for macros/embedded
executables/OLE objects in source Office files -- that has to happen on the
*original* file, before conversion, since that content doesn't survive being
turned into Markdown. Pair this with a separate pre-conversion scanner if
your source files are untrusted.

Usage:
    python3 scan_markdown.py FILE.md [FILE2.md ...]
    python3 scan_markdown.py --batch DIR
    python3 scan_markdown.py FILE.md --redact
    python3 scan_markdown.py FILE.md --json-only   (machine-readable, no stdout prose)

Exit codes (designed to gate a pipeline, same convention as a PreToolUse hook):
    0 = clean, nothing found
    1 = warnings only (PII, suspicious URLs, or soft/review-tier injection
        signals) -- review recommended, not blocking
    2 = blocking findings (secrets, private keys, or hard-tier prompt-injection
        patterns)
"""

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

try:
    from rapidfuzz.distance import DamerauLevenshtein
    RAPIDFUZZ_AVAILABLE = True
except ImportError:
    RAPIDFUZZ_AVAILABLE = False

# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?(secret|access)?(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "generic_api_key": re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "generic_bearer_token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}"),
}

PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "tfn_au_candidate": re.compile(r"\b\d{3}[ -]?\d{3}[ -]?\d{3}\b"),
    "phone_au": re.compile(
        r"\b(?:\+?61[-.\s]?|0)4\d{2}[-.\s]?\d{3}[-.\s]?\d{3}\b"                # mobile: 04xx xxx xxx / +61 4xx xxx xxx
        r"|(?:\+?61[-.\s]?|\()?0?[2378]\)?[-.\s]?\d{4}[-.\s]?\d{4}\b"          # landline: 0x xxxx xxxx / (0x) xxxx xxxx / +61 x xxxx xxxx
    ),
    "credit_card_candidate": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}

# --- Prompt-injection detectors -------------------------------------------
# Categories below follow the attack taxonomy in the OWASP LLM Prompt
# Injection Prevention Cheat Sheet:
# https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html
# Split into two confidence tiers: HARD (specific enough to auto-block) and
# SOFT (real signal, but higher false-positive rate -- warn/review instead).

# HARD: direct instruction override / role reassignment / fake turns / exfil
# requests / bracketed directive markers (OWASP "Direct Prompt Injection",
# "Data Exfiltration")
INJECTION_PATTERNS_HARD = {
    "instruction_override": re.compile(
        r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)\b"
    ),
    "role_reassignment": re.compile(
        r"(?i)\byou\s+are\s+now\s+(a|an|the)\b|\bnew\s+system\s+prompt\b|\bact\s+as\s+(if\s+you\s+are\s+)?a?\s*(different|new)\s+(ai|assistant|model)\b"
    ),
    "fake_system_turn": re.compile(r"(?i)^\s*(system|assistant)\s*:\s*", re.MULTILINE),
    "exfiltration_request": re.compile(
        r"(?i)\b(reveal|print|output|send)\s+(your\s+)?(system\s+prompt|instructions|api\s+key|credentials)\b"
    ),
    "hidden_directive_marker": re.compile(r"(?i)\[\s*(system|instruction|directive)\s*[:\]]"),
    # OWASP "Jailbreaking Techniques": DAN/developer-mode personas and
    # hypothetical-scenario framing used to bypass safety behavior
    "jailbreak_framing": re.compile(
        r"(?i)\b(DAN\s+mode|do\s+anything\s+now|developer\s+mode)\b"
        r"|\b(pretend|imagine)\s+(you|there)\b.{0,60}\b(no\s+(rules|restrictions)|without\s+(any\s+)?(restrictions|limits|filters))\b"
    ),
    # OWASP "System Prompt Extraction"
    "system_prompt_extraction": re.compile(
        r"(?i)\b(what\s+(were|are)\s+your\s+(exact\s+)?instructions|repeat\s+the\s+(text|words)\s+above|print\s+your\s+(system\s+)?prompt)\b"
    ),
    # OWASP "HTML and Markdown Injection": hidden tags used for exfiltration
    # once a document is rendered/processed downstream
    "html_exfil_markup": re.compile(
        r"(?i)<(img|iframe|script)\b[^>]*\bsrc\s*=\s*['\"]https?://[^'\"]+['\"]"
    ),
}

# SOFT: real signal, higher false-positive rate against ordinary documents --
# contributes to WARN, not BLOCK.
INJECTION_PATTERNS_SOFT = {
    # OWASP "Agent-Specific Attacks" -> Thought/Observation Injection: forged
    # ReAct-style agent scratchpad lines embedded in ingested content, aimed
    # at hijacking an agent that parses this format out of retrieved text
    "agent_trace_forgery": re.compile(r"(?im)^\s*(Thought|Observation|Action(?:\s+Input)?)\s*:\s*\S"),
}

# OWASP "Typoglycemia-Based Attacks": scrambled-middle-letter variants of
# high-signal keywords that survive human reading but are meant to dodge
# literal keyword filters, e.g. "ignroe" for "ignore", "bpyass" for "bypass".
TYPOGLYCEMIA_KEYWORDS = ["ignore", "bypass", "override", "reveal", "delete", "system"]

# OWASP "Best-of-N (BoN) Jailbreaking": character-spacing variants of the
# same keywords, e.g. "i g n o r e" or "i.g.n.o.r.e", meant to defeat exact
# substring matching.
SPACED_LETTER_PATTERNS = {
    kw: re.compile(r"\b" + r"[\s\-_.]+".join(list(kw)) + r"\b", re.IGNORECASE)
    for kw in TYPOGLYCEMIA_KEYWORDS
}

# OWASP "Encoding and Obfuscation Techniques": base64/hex-encoded payloads
# hiding an injection string from plain-text pattern matching. We decode
# candidates and re-scan the decoded text against the hard injection patterns.
BASE64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
HEX_CANDIDATE = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,}\b")

URL_PATTERN = re.compile(r"https?://[^\s\)\]\>]+")
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")


def luhn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# ATO Tax File Number check-digit algorithm: 9 digits, weighted modulus 11.
TFN_WEIGHTS = [1, 4, 3, 7, 5, 8, 6, 9, 10]


def tfn_valid(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) != 9 or digits[0] == 0:
        return False
    total = sum(d * w for d, w in zip(digits, TFN_WEIGHTS))
    return total % 11 == 0


def _edit_distance(a: str, b: str) -> int:
    if RAPIDFUZZ_AVAILABLE:
        return DamerauLevenshtein.distance(a, b)
    # Minimal fallback (plain Levenshtein) if rapidfuzz isn't installed --
    # won't credit adjacent transpositions as a single edit, so typoglycemia
    # variants score one point higher than with the Damerau-aware version.
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def find_typoglycemia_hits(text: str) -> list[dict]:
    """OWASP 'Typoglycemia-Based Attacks': scrambled-middle-letter keyword
    variants (first/last letter intact) that read fine to a human but are
    meant to dodge literal substring filters. Flags near-misses, not exact
    matches -- exact keyword hits are already covered by INJECTION_PATTERNS_HARD."""
    hits = []
    for m in re.finditer(r"\b[a-zA-Z]+\b", text):
        word = m.group(0)
        wl = word.lower()
        for target in TYPOGLYCEMIA_KEYWORDS:
            if wl == target or len(wl) < 4 or abs(len(wl) - len(target)) > 1:
                continue
            if wl[0] != target[0]:
                continue
            if _edit_distance(wl, target) <= 1:
                hits.append({"type": "typoglycemia_keyword", "detail": f"'{word}' ~ '{target}'", "offset": m.start()})
                break
    return hits


def find_spaced_letter_hits(text: str) -> list[dict]:
    """OWASP 'Best-of-N (BoN) Jailbreaking': character-spaced keyword
    variants like 'i g n o r e' meant to defeat exact substring matching."""
    hits = []
    for kw, pattern in SPACED_LETTER_PATTERNS.items():
        for m in pattern.finditer(text):
            hits.append({"type": "spaced_letter_keyword", "detail": f"matches '{kw}'", "offset": m.start()})
    return hits


def find_encoded_payload_hits(text: str) -> list[dict]:
    """OWASP 'Encoding and Obfuscation Techniques': base64/hex-encoded
    injection strings. Decodes candidates and re-scans the decoded text
    against the hard injection patterns."""
    hits = []
    for m in BASE64_CANDIDATE.finditer(text):
        candidate = m.group(0)
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if not decoded.isprintable():
            continue
        for label, pattern in INJECTION_PATTERNS_HARD.items():
            if pattern.search(decoded):
                hits.append({
                    "type": "base64_encoded_injection",
                    "detail": f"decodes to content matching '{label}'",
                    "offset": m.start(),
                })
                break

    for m in HEX_CANDIDATE.finditer(text):
        candidate = m.group(0)
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if not decoded.isprintable():
            continue
        for label, pattern in INJECTION_PATTERNS_HARD.items():
            if pattern.search(decoded):
                hits.append({
                    "type": "hex_encoded_injection",
                    "detail": f"decodes to content matching '{label}'",
                    "offset": m.start(),
                })
                break
    return hits


def scan_text(text: str) -> dict:
    findings = {
        "secrets": [], "pii": [],
        "prompt_injection": [], "prompt_injection_review": [],
        "suspicious_urls": [],
    }

    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            findings["secrets"].append({"type": label, "match_preview": _preview(m.group(0)), "offset": m.start()})

    for label, pattern in PII_PATTERNS.items():
        for m in pattern.finditer(text):
            if label == "credit_card_candidate":
                digits_only = re.sub(r"[ -]", "", m.group(0))
                if not luhn_valid(digits_only):
                    continue
                label_out = "credit_card"
            elif label == "tfn_au_candidate":
                if not tfn_valid(m.group(0)):
                    continue
                label_out = "tfn_au"
            else:
                label_out = label
            findings["pii"].append({"type": label_out, "match_preview": _preview(m.group(0)), "offset": m.start()})

    # Hard (blocking) injection signals
    for label, pattern in INJECTION_PATTERNS_HARD.items():
        for m in pattern.finditer(text):
            findings["prompt_injection"].append({"type": label, "match_preview": _preview(m.group(0)), "offset": m.start()})
    for hit in find_encoded_payload_hits(text):
        findings["prompt_injection"].append({"type": hit["type"], "match_preview": hit["detail"], "offset": hit["offset"]})

    # Soft (review-only) injection signals
    for label, pattern in INJECTION_PATTERNS_SOFT.items():
        for m in pattern.finditer(text):
            findings["prompt_injection_review"].append({"type": label, "match_preview": _preview(m.group(0)), "offset": m.start()})
    for hit in find_typoglycemia_hits(text):
        findings["prompt_injection_review"].append({"type": hit["type"], "match_preview": hit["detail"], "offset": hit["offset"]})
    for hit in find_spaced_letter_hits(text):
        findings["prompt_injection_review"].append({"type": hit["type"], "match_preview": hit["detail"], "offset": hit["offset"]})

    for m in URL_PATTERN.finditer(text):
        url = m.group(0)
        domain_flag = None
        if IP_URL_PATTERN.match(url):
            domain_flag = "raw_ip_url"
        elif any(short in url for short in SHORTENER_DOMAINS):
            domain_flag = "url_shortener"
        if domain_flag:
            findings["suspicious_urls"].append({"type": domain_flag, "match_preview": _preview(url), "offset": m.start()})

    return findings


def _preview(s: str, max_len: int = 40) -> str:
    """Redact-friendly preview: show first/last few chars only, mask the middle."""
    if len(s) <= max_len:
        return s[:4] + "…" + s[-4:] if len(s) > 10 else "[redacted]"
    return s[:6] + "…" + s[-6:]


def severity(findings: dict) -> tuple[str, int]:
    """Returns (level, exit_code)."""
    if findings["secrets"] or findings["prompt_injection"]:
        return "BLOCK", 2
    if findings["pii"] or findings["suspicious_urls"] or findings["prompt_injection_review"]:
        return "WARN", 1
    return "CLEAN", 0


def redact_text(text: str, findings: dict) -> str:
    """Rebuilds redactions by re-running detectors with sub(), rather than
    using the stored offsets, since overlapping fuzzy/encoded detectors make
    offset-based splicing unreliable."""
    for pattern in list(SECRET_PATTERNS.values()):
        text = pattern.sub("[REDACTED:SECRET]", text)

    for label, pattern in PII_PATTERNS.items():
        if label == "credit_card_candidate":
            def _cc_sub(m):
                return "[REDACTED:PII]" if luhn_valid(re.sub(r"[ -]", "", m.group(0))) else m.group(0)
            text = pattern.sub(_cc_sub, text)
        elif label == "tfn_au_candidate":
            def _tfn_sub(m):
                return "[REDACTED:PII]" if tfn_valid(m.group(0)) else m.group(0)
            text = pattern.sub(_tfn_sub, text)
        else:
            text = pattern.sub("[REDACTED:PII]", text)

    for pattern in list(INJECTION_PATTERNS_HARD.values()):
        text = pattern.sub("[REDACTED:INJECTION]", text)
    for pattern in list(INJECTION_PATTERNS_SOFT.values()):
        text = pattern.sub("[REDACTED:INJECTION_REVIEW]", text)
    for pattern in list(SPACED_LETTER_PATTERNS.values()):
        text = pattern.sub("[REDACTED:INJECTION_REVIEW]", text)

    def _b64_sub(m):
        candidate = m.group(0)
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return candidate
        if decoded.isprintable() and any(p.search(decoded) for p in INJECTION_PATTERNS_HARD.values()):
            return "[REDACTED:INJECTION]"
        return candidate
    text = BASE64_CANDIDATE.sub(_b64_sub, text)

    def _hex_sub(m):
        candidate = m.group(0)
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return candidate
        if decoded.isprintable() and any(p.search(decoded) for p in INJECTION_PATTERNS_HARD.values()):
            return "[REDACTED:INJECTION]"
        return candidate
    text = HEX_CANDIDATE.sub(_hex_sub, text)

    def _typo_sub(m):
        word = m.group(0)
        wl = word.lower()
        for target in TYPOGLYCEMIA_KEYWORDS:
            if wl == target or len(wl) < 4 or abs(len(wl) - len(target)) > 1 or wl[0] != target[0]:
                continue
            if _edit_distance(wl, target) <= 1:
                return "[REDACTED:INJECTION_REVIEW]"
        return word
    text = re.sub(r"\b[a-zA-Z]+\b", _typo_sub, text)

    return text


def scan_file(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    findings = scan_text(text)
    level, code = severity(findings)
    total = sum(len(v) for v in findings.values())
    return {
        "file": str(path),
        "level": level,
        "exit_code": code,
        "total_findings": total,
        "findings": findings,
    }


def main():
    parser = argparse.ArgumentParser(description="Scan converted Markdown for secrets, PII, and prompt-injection payloads before AI ingestion.")
    parser.add_argument("paths", nargs="*", help="Markdown file(s) to scan")
    parser.add_argument("--batch", metavar="DIR", help="Scan all .md files in a directory")
    parser.add_argument("--redact", action="store_true", help="Write a redacted copy alongside each scanned file")
    parser.add_argument("--json-only", action="store_true", help="Print only the JSON report, no prose")
    args = parser.parse_args()

    files = []
    if args.batch:
        files.extend(sorted(Path(args.batch).rglob("*.md")))
    files.extend(Path(p) for p in args.paths)

    if not files:
        print("No files to scan. Provide file paths or --batch DIR.", file=sys.stderr)
        sys.exit(1)

    reports = []
    worst_code = 0
    for f in files:
        report = scan_file(f)
        reports.append(report)
        worst_code = max(worst_code, report["exit_code"])

        if args.redact and report["total_findings"] > 0:
            text = f.read_text(encoding="utf-8", errors="replace")
            redacted = redact_text(text, report["findings"])
            redacted_path = f.with_suffix(".redacted.md")
            redacted_path.write_text(redacted, encoding="utf-8")
            report["redacted_output"] = str(redacted_path)

        if not args.json_only:
            icon = {"CLEAN": "OK  ", "WARN": "WARN", "BLOCK": "FAIL"}[report["level"]]
            print(f"{icon} {f}  [{report['level']}, {report['total_findings']} finding(s)]")
            for category, items in report["findings"].items():
                for item in items:
                    print(f"       - {category}: {item['type']} @ offset {item['offset']} ({item['match_preview']})")

    if args.json_only:
        print(json.dumps(reports, indent=2))
    else:
        report_path = Path("security-scan-report.json")
        report_path.write_text(json.dumps(reports, indent=2))
        print(f"\nFull report written to {report_path}")

    sys.exit(worst_code)


if __name__ == "__main__":
    main()
