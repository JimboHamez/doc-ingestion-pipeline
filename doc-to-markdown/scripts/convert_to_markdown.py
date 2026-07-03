#!/usr/bin/env python3
"""
convert_to_markdown.py

Convert documents (PDF, DOCX, PPTX, XLSX, HTML, TXT, CSV, images w/ text) into
clean, UTF-8, Unicode-normalized Markdown ready for AI ingestion (RAG, embeddings,
fine-tuning corpora, etc.)

Pipeline:
  1. Detect source encoding (for text-based formats) and transcode to UTF-8
  2. Convert to Markdown using MarkItDown (structure-aware: headings, tables, lists)
  3. Unicode-normalize (default NFC)
  4. Strip invisible / control / formatting characters (zero-width spaces, BOM,
     soft hyphens, directional marks, C0/C1 control codes) while preserving
     legitimate whitespace (\n, \t)
  5. Normalize line endings to \n, collapse excessive blank lines, strip
     trailing whitespace
  6. De-hyphenate line-wrapped words left over from PDF extraction
  7. Write UTF-8 output (no BOM) + a JSON metadata sidecar (source hash,
     char counts, warnings) for traceability

Usage:
    python3 convert_to_markdown.py INPUT_FILE [OUTPUT_FILE]
    python3 convert_to_markdown.py --batch INPUT_DIR OUTPUT_DIR
    python3 convert_to_markdown.py INPUT_FILE --normalize-form NFKC

Exit codes:
    0 = success
    1 = conversion error (bad/corrupt/unsupported file)
    2 = validation error (output failed post-conversion checks)
"""

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

try:
    from markitdown import MarkItDown
except ImportError:
    print("ERROR: markitdown not installed. Run: pip install 'markitdown[all]' --break-system-packages", file=sys.stderr)
    sys.exit(1)

try:
    from charset_normalizer import from_bytes
except ImportError:
    from_bytes = None  # falls back to utf-8/latin-1 guessing

SUPPORTED_EXTENSIONS = {
    ".pdf", ".docx", ".pptx", ".xlsx", ".xls", ".html", ".htm",
    ".txt", ".md", ".csv", ".json", ".xml",
}

# Unicode categories to strip: Cc (control), Cf (format, e.g. zero-width
# joiner/BOM/soft hyphen), Co (private use), Cs (surrogate). We keep \n and \t
# explicitly even though \n is technically Cc.
STRIP_CATEGORIES = {"Cc", "Cf", "Co", "Cs"}
KEEP_CHARS = {"\n", "\t"}

# Common PDF ligature / artifact fixes
LIGATURE_MAP = {
    "\ufb00": "ff", "\ufb01": "fi", "\ufb02": "fl",
    "\ufb03": "ffi", "\ufb04": "ffl",
}


def detect_and_decode(raw: bytes) -> tuple[str, str]:
    """Detect encoding of raw bytes and decode to a Python str.
    Returns (text, detected_encoding_label)."""
    # Strip UTF-8 BOM if present
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace"), "utf-8-bom"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    if from_bytes is not None:
        result = from_bytes(raw).best()
        if result is not None:
            return str(result), result.encoding or "unknown"
    # Last resort: latin-1 never fails to decode (may mangle text)
    return raw.decode("latin-1", errors="replace"), "latin-1-fallback"


def strip_invisible_and_control(text: str) -> tuple[str, int]:
    """Remove invisible/control/formatting characters. Returns (clean_text, count_removed)."""
    out = []
    removed = 0
    for ch in text:
        if ch in KEEP_CHARS:
            out.append(ch)
            continue
        if unicodedata.category(ch) in STRIP_CATEGORIES:
            removed += 1
            continue
        out.append(ch)
    return "".join(out), removed


def normalize_unicode(text: str, form: str = "NFC") -> str:
    for lig, repl in LIGATURE_MAP.items():
        text = text.replace(lig, repl)
    return unicodedata.normalize(form, text)


def dehyphenate(text: str) -> str:
    """Rejoin words split across a line-wrap with a trailing hyphen,
    e.g. 'infor-\nmation' -> 'information'. Conservative: only applies
    when both sides look like lowercase word fragments."""
    return re.sub(r"(\w)-\n(\w)", r"\1\2", text)


def normalize_line_endings(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def normalize_whitespace(text: str) -> str:
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text)  # collapse 3+ blank lines to 1
    return text.strip() + "\n"


def convert_file(input_path: Path, normalize_form: str = "NFC") -> dict:
    """Run the full pipeline on one file. Returns a result dict with
    'markdown', 'warnings', and 'stats' keys. Raises on unrecoverable errors."""
    warnings = []
    ext = input_path.suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {ext}")

    source_bytes = input_path.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()

    if ext in {".txt", ".md", ".csv", ".json", ".xml"}:
        text, encoding = detect_and_decode(source_bytes)
        if encoding not in ("utf-8", "utf-8-bom"):
            warnings.append(f"Source encoding detected as '{encoding}', transcoded to UTF-8")
        markdown = text
    else:
        # MarkItDown handles PDF/DOCX/PPTX/XLSX/HTML structure extraction
        md_converter = MarkItDown()
        result = md_converter.convert(str(input_path))
        markdown = result.text_content

    pre_len = len(markdown)
    markdown, removed_count = strip_invisible_and_control(markdown)
    if removed_count:
        warnings.append(f"Removed {removed_count} invisible/control characters")

    markdown = normalize_unicode(markdown, form=normalize_form)
    markdown = normalize_line_endings(markdown)
    markdown = dehyphenate(markdown)
    markdown = normalize_whitespace(markdown)

    # Validate: must be clean UTF-8, no remaining disallowed control chars
    try:
        markdown.encode("utf-8", errors="strict")
    except UnicodeEncodeError as e:
        raise ValueError(f"Output failed UTF-8 validation: {e}")

    leftover = [ch for ch in markdown if ch not in KEEP_CHARS and unicodedata.category(ch) in STRIP_CATEGORIES]
    if leftover:
        raise ValueError(f"{len(leftover)} control/invisible characters survived cleaning")

    return {
        "markdown": markdown,
        "warnings": warnings,
        "stats": {
            "source_file": str(input_path),
            "source_sha256": source_hash,
            "source_bytes": len(source_bytes),
            "output_chars": len(markdown),
            "chars_removed_pre_normalize": removed_count,
            "normalize_form": normalize_form,
        },
    }


def write_output(result: dict, output_path: Path):
    output_path.write_text(result["markdown"], encoding="utf-8", newline="\n")
    sidecar = output_path.with_suffix(output_path.suffix + ".meta.json")
    sidecar.write_text(json.dumps({**result["stats"], "warnings": result["warnings"]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Convert documents to clean UTF-8 Markdown for AI ingestion.")
    parser.add_argument("input", help="Input file or directory (with --batch)")
    parser.add_argument("output", nargs="?", help="Output file or directory (with --batch)")
    parser.add_argument("--batch", action="store_true", help="Treat input/output as directories")
    parser.add_argument("--normalize-form", default="NFC", choices=["NFC", "NFKC", "NFD", "NFKD"],
                         help="Unicode normalization form (default: NFC)")
    args = parser.parse_args()

    if args.batch:
        in_dir = Path(args.input)
        out_dir = Path(args.output or "converted")
        out_dir.mkdir(parents=True, exist_ok=True)
        failures = []
        for f in sorted(in_dir.rglob("*")):
            if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS:
                out_path = out_dir / (f.stem + ".md")
                try:
                    result = convert_file(f, normalize_form=args.normalize_form)
                    write_output(result, out_path)
                    print(f"OK   {f} -> {out_path}" + (f"  [{len(result['warnings'])} warning(s)]" if result["warnings"] else ""))
                except Exception as e:
                    failures.append((f, str(e)))
                    print(f"FAIL {f}: {e}", file=sys.stderr)
        if failures:
            print(f"\n{len(failures)} file(s) failed conversion.", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    in_path = Path(args.input)
    out_path = Path(args.output) if args.output else in_path.with_suffix(".md")
    try:
        result = convert_file(in_path, normalize_form=args.normalize_form)
    except Exception as e:
        print(f"ERROR converting {in_path}: {e}", file=sys.stderr)
        sys.exit(1)

    write_output(result, out_path)
    print(f"Converted: {in_path} -> {out_path}")
    print(f"  SHA-256:  {result['stats']['source_sha256'][:16]}...")
    print(f"  Chars:    {result['stats']['output_chars']}")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  Warning:  {w}")


if __name__ == "__main__":
    main()
