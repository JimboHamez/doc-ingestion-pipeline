---
name: doc-to-markdown
description: Convert documents (PDF, DOCX, PPTX, XLSX, HTML, TXT, CSV) into clean, UTF-8, Unicode-normalized Markdown ready for AI ingestion (RAG, embeddings, fine-tuning corpora). Strips invisible/control characters, BOMs, and zero-width characters; normalizes line endings and whitespace; de-hyphenates PDF line-wraps; falls back to Tesseract OCR for scanned/image-only PDF pages. Use when the user asks to convert a document to markdown, prepare files for RAG/ingestion/embeddings, clean up text encoding issues, OCR a scanned PDF, or batch-process a folder of documents into a corpus.
allowed-tools: Bash(python3:*)
---

# Document to Markdown (AI-ingestion ready)

Converts documents into Markdown suitable for feeding into embeddings, RAG
pipelines, or any downstream AI system that expects clean, normalized UTF-8 text.

## When to use this

- "Convert this PDF/DOCX/PPTX to markdown"
- "Prepare these documents for our vector store / RAG pipeline"
- "Clean up the encoding on this text file"
- "Batch convert this folder of docs into a corpus"

## What it does

1. Detects source text encoding and transcodes to UTF-8 (handles BOM, Latin-1,
   Windows-1252, etc.)
2. Converts structured formats (PDF, DOCX, PPTX, XLSX, HTML) to Markdown,
   preserving headings, lists, and tables where possible
2a. For PDFs, detects pages with a missing/thin text layer (scanned or
   image-only) and recovers their text with Tesseract OCR — see "OCR" below
3. Unicode-normalizes the output (default form: NFC)
4. Strips invisible and control characters: zero-width spaces, BOMs, soft
   hyphens, directional marks, C0/C1 control codes — while preserving
   legitimate `\n` and `\t`
5. Normalizes line endings to `\n`, collapses excessive blank lines, strips
   trailing whitespace
6. De-hyphenates words that were split across a line-wrap (common PDF artifact)
7. Validates the output is strict UTF-8 with no leftover control characters
8. Writes a `.meta.json` sidecar alongside each output file recording the
   source file's SHA-256 hash, byte/char counts, and any warnings — for
   traceability back to the original document

## How to invoke

Single file:
```bash
python3 scripts/convert_to_markdown.py path/to/document.pdf
# -> writes path/to/document.md + path/to/document.md.meta.json
```

Specify output path:
```bash
python3 scripts/convert_to_markdown.py input.docx output/clean.md
```

Batch a whole directory:
```bash
python3 scripts/convert_to_markdown.py --batch ./raw_docs ./converted
```

## OCR for scanned / image-only PDFs

By default (`--ocr auto`) the script inspects each PDF page's extractable text
layer and runs Tesseract OCR **only** on pages that are missing text or fall
below `--ocr-min-chars` (default 100) — so clean digital PDFs are untouched and
fast, while scanned pages are recovered.

- **Fully scanned PDF** → the whole document is rebuilt from OCR text.
- **Mixed PDF** (some digital, some scanned pages) → the digital MarkItDown
  extraction is preserved and the OCR'd pages are appended under an
  `## OCR-recovered pages` section with `### Page N (OCR)` markers, so nothing
  extracted digitally is lost or silently reordered.

```bash
python3 scripts/convert_to_markdown.py scanned.pdf            # auto (default)
python3 scripts/convert_to_markdown.py scan.pdf --ocr force   # OCR every page
python3 scripts/convert_to_markdown.py doc.pdf  --ocr never   # disable OCR
python3 scripts/convert_to_markdown.py scan.pdf --ocr-lang eng+deu --ocr-dpi 400
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--ocr {auto,never,force}` | `auto` | `auto` = OCR only thin pages; `never` = today's text-only behavior; `force` = OCR every page |
| `--ocr-lang` | `eng` | Tesseract language(s), e.g. `eng+deu` |
| `--ocr-dpi` | `300` | Rasterization DPI (higher = slower, more accurate) |
| `--ocr-min-chars` | `100` | In `auto` mode, OCR a page whose extractable text is below this |

The `.meta.json` sidecar records an `ocr` block (`ocr_applied`, `ocr_pages`,
`ocr_engine`, lang, dpi, and per-page character counts) for full traceability.

**Security note:** OCR should run *after* `pre-conversion-scan` (rasterizing a
PDF is an active parse). The payoff is that prompt-injection or PII text baked
into a *scanned image* — previously invisible to the pipeline — is now
extracted and therefore caught by the downstream `doc-security-scan` stage.

Choose a different Unicode normalization form (rarely needed — NFC is correct
for almost all ingestion pipelines; NFKC is more aggressive and will fold
things like ligatures, fullwidth characters, and some semantically-distinct
symbols into a canonical form, which can lose information):
```bash
python3 scripts/convert_to_markdown.py input.pdf --normalize-form NFKC
```

## Supported input formats

PDF, DOCX, PPTX, XLSX/XLS, HTML/HTM, TXT, MD, CSV, JSON, XML

## Gotchas

- **PDF quality varies by source.** Scanned/image-only PDFs contain no
  extractable text layer; in `--ocr auto` (default) the script now OCRs those
  pages automatically. OCR requires `PyMuPDF`, `pytesseract`, and the system
  `tesseract-ocr` binary — if they're missing, `auto` still succeeds on
  digital pages but *raises* on a page that actually needs OCR (rather than
  silently emitting empty text). Use `--ocr never` to force the old
  text-only behavior. OCR accuracy also depends on scan quality and the
  chosen `--ocr-lang`/`--ocr-dpi`.
- **NFC vs NFKC**: default is NFC (canonical, lossless-ish). Only switch to
  NFKC if you specifically need compatibility folding (e.g. removing
  full-width/half-width distinctions) — it can silently change meaning for
  some symbol-heavy text.
- **Tables from PDFs** convert less reliably than DOCX/XLSX tables, since PDF
  has no native table structure — always spot-check PDF table output.
- **This does not scrub PII or run malware/macro scanning.** If source files
  are untrusted or may contain sensitive data, add a separate screening step
  before or after this conversion.
- **Batch mode continues past individual failures** but exits non-zero if any
  file failed, so it's CI-safe (fails the pipeline) while still processing
  everything it can.

## Dependencies

Requires `markitdown[all]` and `charset-normalizer`:
```bash
pip install "markitdown[all]" charset-normalizer --break-system-packages
```

OCR fallback additionally needs `PyMuPDF` + `pytesseract` (Python) and the
`tesseract-ocr` system binary. These are optional — only loaded when a PDF
actually needs OCR:
```bash
pip install PyMuPDF pytesseract Pillow --break-system-packages
# and the engine itself:
apt-get install tesseract-ocr      # Debian/Ubuntu
brew install tesseract             # macOS
```
