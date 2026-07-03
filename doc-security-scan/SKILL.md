---
name: doc-security-scan
description: Scan converted Markdown documents for secrets/credentials, PII, prompt-injection payloads, and suspicious URLs before they reach an embedding index, vector store, or LLM context. Use after converting documents to markdown, before ingesting content into a RAG pipeline, or whenever the user asks to check documents for sensitive data or injection attacks before AI ingestion.
allowed-tools: Bash(python3:*)
---

# Document Security Scanner (pre-ingestion gate)

Scans **already-converted Markdown** (e.g. output of the `doc-to-markdown`
skill) for content that should not be embedded, indexed, or fed into an LLM
context window.

## Scope — read this first

This is a **text-level** scanner, not a file-format scanner. It catches:

- Secrets/credentials left in document text (API keys, AWS keys, private
  key blocks, tokens)
- PII (emails, AU phone numbers — mobile + landline, AU Tax File Numbers and
  credit card numbers — both checksum-validated to cut false positives)
- **Prompt-injection payloads**: text embedded in a document specifically to
  manipulate a downstream LLM that later retrieves this content from a vector
  store. Detection follows the attack taxonomy in the
  [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html),
  split into two confidence tiers:
  - **Hard (auto-block)**: instruction override ("ignore all previous
    instructions"), role reassignment, fake system/assistant turns,
    exfiltration requests, bracketed directive markers, jailbreak framing
    (DAN/developer-mode personas, hypothetical-scenario bypass), system
    prompt extraction attempts, HTML/Markdown exfiltration markup
    (`<img>`/`<iframe>`/`<script>` with a remote `src`), and base64/hex-encoded
    payloads that decode to any of the above
  - **Soft (review-only, contributes to WARN not BLOCK)**: typoglycemia
    keyword variants (scrambled middle letters, e.g. "ignroe" for "ignore",
    detected via Damerau-Levenshtein edit distance), Best-of-N character-spacing
    evasion ("i g n o r e"), and forged agent-trace lines
    (`Thought:`/`Observation:`/`Action:`) aimed at hijacking a downstream
    agent parser
- Suspicious URLs (raw IP-address links, common shorteners)

It does **not** detect macros, embedded OLE objects, or PDF JavaScript — that
content lives in the original binary file and doesn't survive conversion to
Markdown. If your source files are untrusted, that needs a separate
pre-conversion file-format scanner running on the raw DOCX/XLSX/PPTX/PDF
*before* `doc-to-markdown` touches them.

## Pipeline position

```
raw documents → [doc-to-markdown skill] → clean .md files → [doc-security-scan] → ingestion
                                                                    │
                                                        exit 0 = clean, proceed
                                                        exit 1 = PII/warnings, review
                                                        exit 2 = secrets/injection, BLOCK
```

## How to invoke

Scan one or more files:
```bash
python3 scripts/scan_markdown.py output/report.md
```

Batch a directory (e.g. everything doc-to-markdown just produced):
```bash
python3 scripts/scan_markdown.py --batch ./converted
```

Write redacted copies alongside flagged files:
```bash
python3 scripts/scan_markdown.py --batch ./converted --redact
```

Machine-readable output only (for piping into another tool/CI step):
```bash
python3 scripts/scan_markdown.py file.md --json-only
```

## Exit codes (same convention as a Claude Code PreToolUse hook)

- `0` — clean, nothing found
- `1` — warnings only (PII/suspicious URLs found) — flag for human review, don't hard-block
- `2` — blocking findings (secrets, private keys, or prompt-injection patterns) — should stop the pipeline

## Chaining after doc-to-markdown

**As a manual two-step workflow:**
```bash
python3 doc-to-markdown/scripts/convert_to_markdown.py --batch raw_docs converted
python3 doc-security-scan/scripts/scan_markdown.py --batch converted
```

**As a Claude Code PostToolUse hook**, so it fires automatically whenever
Claude writes a `.md` file into a `converted/` directory:
```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write",
        "hooks": [
          { "type": "command", "command": "python3 .claude/skills/doc-security-scan/scripts/scan_markdown.py \"$CLAUDE_TOOL_INPUT_FILE_PATH\"" }
        ]
      }
    ]
  }
}
```
Note: a PostToolUse hook can report and warn but cannot undo the write that
already happened — pair it with follow-up logic (delete/quarantine the file,
or block the *next* step, e.g. an ingestion script) if you need a true
hard-stop rather than a flagged warning.

## Dependencies

Requires `rapidfuzz` for typoglycemia (edit-distance) detection:
```bash
pip install rapidfuzz --break-system-packages
```
Everything else is Python standard library.

## Gotchas

- **Regex-based, not exhaustive.** This catches common/obvious patterns, not
  every possible secret format or every conceivable injection phrasing.
  Treat it as a first-pass gate, not a complete DLP solution.
- **Credit card detection uses Luhn validation** to avoid flagging every
  13-19 digit number (invoice numbers, tracking numbers, etc.) as a card —
  but Luhn-valid numbers can still occasionally be coincidental.
- **TFN detection uses the ATO's weighted modulus-11 check-digit algorithm**
  for the same reason — a bare "9 digits in groups of 3" pattern would flag
  huge numbers of ordinary reference numbers. Checksum validation cuts that
  down substantially, but roughly 1 in 11 random 9-digit sequences will pass
  the checksum coincidentally, so treat a hit as "worth a human look," not
  certain proof of a real TFN.
- **Prompt-injection detection is pattern/heuristic-level**, not a trained
  classifier. Base64/hex encoding and typoglycemia scrambling are now
  covered, but more advanced obfuscation — unicode homoglyphs, nested/
  double encoding, non-English injection phrasings, or novel attack framings
  not in the OWASP taxonomy — will not be caught. The OWASP cheat sheet
  itself recommends pairing deterministic checks like this one with a
  model-based guardrail (a purpose-trained classifier or "LLM-as-judge")
  for anything high-stakes; treat this scanner as the fast, cheap first
  layer, not the only layer.
- **The hard/soft split is a deliberate false-positive tradeoff.** Soft-tier
  detectors (typoglycemia, character-spacing, agent-trace forgery) will
  occasionally flag legitimate content — technical docs that discuss ReAct
  agents, or prose with coincidental near-miss spellings — which is why they
  contribute to WARN, not BLOCK. If your corpus generates a lot of soft-tier
  noise, that's a signal to review your source documents' typical vocabulary,
  not necessarily to disable the check.
- **Redaction is best-effort**, not cryptographically guaranteed removal —
  always keep the original source file access-controlled separately; don't
  rely on redacted markdown alone as your only safeguard.
