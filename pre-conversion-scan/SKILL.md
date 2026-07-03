---
name: pre-conversion-scan
description: Scan raw source documents (DOCX, XLSX, PPTX, DOC, XLS, PPT, PDF) for file-format-level security risks BEFORE converting them to markdown -- VBA macros, embedded executables, remote template injection, XXE, zip bombs, extension spoofing, and malicious PDF JavaScript/Launch actions. Use before doc-to-markdown whenever source files are untrusted, user-uploaded, or from an external/unknown source.
allowed-tools: Bash(python3:*)
---

# Pre-Conversion Binary Scanner (stage 1 of the ingestion pipeline)

Scans **raw, unconverted** source files for threats that live in the binary
container itself and would be invisible once the file becomes Markdown.
This is the first of three stages:

```
raw docs → [pre-conversion-scan] → doc-to-markdown → doc-security-scan → ingestion
                  │                                        │
          file-format threats                    content/text threats
     (macros, embedded exe, XXE,           (secrets, PII, prompt injection
      remote injection, PDF JS,             embedded in the extracted text)
      zip bombs, spoofed extensions)
```

Run this **before** any tool opens or parses the file — including before
`doc-to-markdown`, since MarkItDown and the underlying office-document
libraries will happily open a file containing an active exploit.

## What it detects

- **VBA macros** — real decompilation and suspicious-keyword analysis via
  `oletools` (not just "does a macro exist"). Flags autoexec triggers
  (`AutoOpen`, `Document_Open`, etc.) and dangerous API calls (`Shell`,
  `CreateObject`, `powershell`, `URLDownloadToFile`, ...) inside the macro
  code itself. Works on both legacy OLE (`.doc/.xls/.ppt`) and OOXML
  (`.docm/.xlsm/.pptm`) containers.
- **Embedded executables/scripts** hidden inside the ZIP structure of an
  Office file (`.exe`, `.dll`, `.ps1`, `.vbs`, `.jar`, etc. tucked into
  `word/embeddings/` or similar).
- **Remote template injection** — external relationship targets in OOXML
  `.rels` files, a known technique for fetching a malicious remote template
  at open-time.
- **XXE indicators** — `DOCTYPE`/`ENTITY` declarations in the XML parts of
  an OOXML file.
- **Zip bombs** — extreme compression ratios or oversized archives, checked
  before extraction.
- **Extension/magic-byte mismatch** — a `.docx` that isn't actually a ZIP, a
  `.pdf` that doesn't start with `%PDF`, or an OOXML-extensioned file that's
  actually an OLE compound file (a strong signal of password-protection or
  mislabeling).
- **PDF-specific risks** — `/Launch` actions, `/JavaScript` or `/JS` combined
  with `/OpenAction` (auto-running script on open), embedded files, and
  encryption.

## How to invoke

```bash
python3 scripts/scan_binary.py path/to/document.docx
python3 scripts/scan_binary.py --batch ./raw_docs
python3 scripts/scan_binary.py file.pdf --json-only
```

## Exit codes (consistent across all three pipeline stages)

- `0` — clean
- `1` — warnings: macro present but not flagged malicious, encrypted PDF,
  legacy OLE format, XXE markers present — review before proceeding
- `2` — blocking: malicious macro indicators, embedded executable, remote
  template injection, spoofed extension, zip bomb, auto-running PDF
  JavaScript — do **not** pass this file to `doc-to-markdown`

## Chaining into the full pipeline

```bash
python3 pre-conversion-scan/scripts/scan_binary.py --batch raw_docs
if [ $? -le 1 ]; then
  python3 doc-to-markdown/scripts/convert_to_markdown.py --batch raw_docs converted
  python3 doc-security-scan/scripts/scan_markdown.py --batch converted
fi
```

As a Claude Code **PreToolUse hook** on Bash/Read, so it fires before Claude
even opens an untrusted uploaded file:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          { "type": "command", "command": "python3 .claude/skills/pre-conversion-scan/scripts/scan_binary.py \"$CLAUDE_TOOL_INPUT_FILE_PATH\" --json-only | python3 -c \"import json,sys; sys.exit(2 if json.load(sys.stdin)[0]['exit_code']==2 else 0)\"" }
        ]
      }
    ]
  }
}
```
Unlike the `doc-security-scan` PostToolUse hook (which can only flag *after*
a write already happened), this is a **PreToolUse** hook — it can genuinely
block the read from ever occurring, which is the true hard-stop the earlier
stage couldn't provide.

## Gotchas

- **oletools does real macro decompilation**, but its keyword list here is a
  representative, not exhaustive, set of dangerous API calls. Treat a WARN
  on macro presence as "needs human review," not "definitely safe."
- **Legacy OLE files (`.doc/.xls/.ppt`) get less structural scrutiny** than
  OOXML — there's no ZIP container to inspect for embedded executables or
  remote relationships, only the macro layer. If you regularly receive
  legacy-format files from untrusted sources, treat any WARN/BLOCK on them
  as higher priority for manual review.
- **This does not sandbox-execute or fully render the file** — it's static
  analysis of the container structure and macro code, not dynamic detonation.
  For high-assurance environments, pair this with an actual sandboxed
  detonation service; this scanner is a fast first-pass filter, not a
  replacement for one.
- **Zip bomb thresholds are heuristic defaults** (100x compression ratio,
  500MB uncompressed) — tune them in the script if your legitimate documents
  are unusually large or dense.

## Dependencies

```bash
pip install oletools pikepdf --break-system-packages
```
