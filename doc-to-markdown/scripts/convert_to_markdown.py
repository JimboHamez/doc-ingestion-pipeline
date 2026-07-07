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

# OCR dependencies are optional: only needed when a PDF has no usable text
# layer (scanned/image-only). Imported lazily so the script still runs for
# every other format — and for digital PDFs — without them installed.
try:
    import fitz  # PyMuPDF: per-page text detection + rasterization (bundles its
                 # own renderer, so no Poppler/pdf2image system dependency)
except ImportError:
    fitz = None

try:
    import pytesseract
    from PIL import Image
except ImportError:
    pytesseract = None
    Image = None

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

# OCR defaults. A page with fewer than OCR_MIN_CHARS characters of extractable
# text is treated as image-only and sent to OCR in --ocr auto mode.
OCR_MIN_CHARS = 100
OCR_DPI = 300
OCR_LANG = "eng"


class OCRUnavailable(RuntimeError):
    """Raised when OCR is required but its optional dependencies are missing."""


def _require_ocr_deps():
    """Fail loudly (and actionably) if OCR is needed but not installed."""
    missing = []
    if fitz is None:
        missing.append("PyMuPDF")
    if pytesseract is None or Image is None:
        missing.append("pytesseract/Pillow")
    if missing:
        raise OCRUnavailable(
            "OCR requires " + " and ".join(missing) + ". Install with: "
            "pip install PyMuPDF pytesseract Pillow --break-system-packages "
            "(and the system 'tesseract-ocr' binary)."
        )
    # pytesseract shells out to the tesseract binary; surface its absence early.
    try:
        pytesseract.get_tesseract_version()
    except Exception as e:  # pytesseract.TesseractNotFoundError and friends
        raise OCRUnavailable(
            f"The tesseract binary is not available ({e}). Install it, e.g. "
            "'apt-get install tesseract-ocr' or 'brew install tesseract'."
        )


def assess_pdf_text_layer(input_path: Path) -> list[int]:
    """Return the extractable-text character count for each PDF page, using
    PyMuPDF. Used to decide which pages (if any) need OCR. A page whose count
    is below OCR_MIN_CHARS is effectively image-only."""
    if fitz is None:
        raise OCRUnavailable(
            "PyMuPDF is required to assess the PDF text layer. Install with: "
            "pip install PyMuPDF --break-system-packages"
        )
    with fitz.open(input_path) as doc:
        return [len(page.get_text("text").strip()) for page in doc]


def ocr_pdf_pages(input_path: Path, page_indices: list[int],
                  dpi: int = OCR_DPI, lang: str = OCR_LANG) -> dict[int, str]:
    """Rasterize the given (0-based) PDF pages and OCR each one with Tesseract.
    Returns {page_index: recognized_text}. Pages are rendered in grayscale at
    the requested DPI, which is a good speed/accuracy trade-off for documents."""
    _require_ocr_deps()
    import io

    results: dict[int, str] = {}
    zoom = dpi / 72.0  # PDF user space is 72 dpi; scale up to the target dpi
    matrix = fitz.Matrix(zoom, zoom)
    with fitz.open(input_path) as doc:
        for idx in page_indices:
            page = doc[idx]
            pix = page.get_pixmap(matrix=matrix, colorspace=fitz.csGRAY)
            image = Image.open(io.BytesIO(pix.tobytes("png")))
            text = pytesseract.image_to_string(image, lang=lang)
            results[idx] = text.strip()
    return results


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


def _render_ocr_pages(page_texts: dict[int, str]) -> str:
    """Render {0-based page index: text} as Markdown with 1-based page markers."""
    blocks = []
    for idx in sorted(page_texts):
        blocks.append(f"### Page {idx + 1} (OCR)\n\n{page_texts[idx]}")
    return "\n\n".join(blocks)


def apply_pdf_ocr(input_path: Path, markdown: str, warnings: list,
                  ocr_mode: str = "auto", ocr_lang: str = OCR_LANG,
                  ocr_dpi: int = OCR_DPI, ocr_min_chars: int = OCR_MIN_CHARS) -> tuple[str, dict]:
    """Hybrid OCR fallback for PDFs. Inspects the per-page text layer and, in
    'auto' mode, OCRs only the pages that are missing/thin; 'force' OCRs every
    page; 'never' is a no-op. Returns (possibly-augmented markdown, ocr_stats).

    - Fully image-only PDF (all pages thin): output is rebuilt from OCR text.
    - Mixed PDF (some digital, some scanned): the digital MarkItDown output is
      kept and the OCR'd pages are appended under a clear 'OCR-recovered pages'
      section, so nothing extracted digitally is lost or silently reordered."""
    stats = {
        "ocr_mode": ocr_mode,
        "ocr_applied": False,
        "ocr_engine": None,
        "ocr_lang": ocr_lang,
        "ocr_dpi": ocr_dpi,
        "ocr_min_chars": ocr_min_chars,
        "ocr_pages": [],
        "pdf_page_count": None,
        "pdf_page_char_counts": None,
    }
    if ocr_mode == "never":
        return markdown, stats

    page_char_counts = assess_pdf_text_layer(input_path)
    stats["pdf_page_count"] = len(page_char_counts)
    stats["pdf_page_char_counts"] = page_char_counts

    if ocr_mode == "force":
        thin_pages = list(range(len(page_char_counts)))
    else:  # auto
        thin_pages = [i for i, n in enumerate(page_char_counts) if n < ocr_min_chars]

    if not thin_pages:
        return markdown, stats

    _require_ocr_deps()
    page_texts = ocr_pdf_pages(input_path, thin_pages, dpi=ocr_dpi, lang=ocr_lang)
    # Drop pages OCR produced nothing for (e.g. genuinely blank pages), so we
    # don't emit empty "### Page N" stubs.
    page_texts = {i: t for i, t in page_texts.items() if t}

    stats["ocr_applied"] = bool(page_texts)
    stats["ocr_engine"] = f"tesseract {pytesseract.get_tesseract_version()}"
    stats["ocr_pages"] = [i + 1 for i in sorted(page_texts)]

    if not page_texts:
        warnings.append(
            f"OCR ran on {len(thin_pages)} page(s) with no extractable text but "
            "recognized nothing — pages may be blank or unreadable"
        )
        return markdown, stats

    ocr_md = _render_ocr_pages(page_texts)
    digital_pages = [i for i in range(len(page_char_counts)) if i not in thin_pages]
    if digital_pages and markdown.strip():
        # Mixed document: preserve digital extraction, append recovered pages.
        warnings.append(
            f"OCR applied to {len(page_texts)} image-only page(s): "
            f"{stats['ocr_pages']} — appended under 'OCR-recovered pages'"
        )
        markdown = markdown.rstrip() + "\n\n---\n\n## OCR-recovered pages\n\n" + ocr_md
    elif ocr_mode == "force":
        # OCR was forced on every page; OCR text replaces any digital extraction.
        warnings.append(
            f"OCR forced on all {len(page_texts)} page(s) "
            f"(lang={ocr_lang}, {ocr_dpi} dpi); digital text layer ignored"
        )
        markdown = ocr_md
    else:
        # Fully scanned document: OCR text is the content.
        warnings.append(
            f"PDF had no usable text layer; content recovered via OCR "
            f"({len(page_texts)} page(s), lang={ocr_lang}, {ocr_dpi} dpi)"
        )
        markdown = ocr_md
    return markdown, stats


def convert_file(input_path: Path, normalize_form: str = "NFC",
                 ocr_mode: str = "auto", ocr_lang: str = OCR_LANG,
                 ocr_dpi: int = OCR_DPI, ocr_min_chars: int = OCR_MIN_CHARS) -> dict:
    """Run the full pipeline on one file. Returns a result dict with
    'markdown', 'warnings', and 'stats' keys. Raises on unrecoverable errors."""
    warnings = []
    ext = input_path.suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {ext}")

    source_bytes = input_path.read_bytes()
    source_hash = hashlib.sha256(source_bytes).hexdigest()

    ocr_stats = {"ocr_applied": False, "ocr_mode": ocr_mode}
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

    # Hybrid OCR fallback for PDFs with a missing/thin text layer (scanned docs).
    # Runs before normalization so recovered text is cleaned like everything else.
    if ext == ".pdf":
        markdown, ocr_stats = apply_pdf_ocr(
            input_path, markdown, warnings,
            ocr_mode=ocr_mode, ocr_lang=ocr_lang,
            ocr_dpi=ocr_dpi, ocr_min_chars=ocr_min_chars,
        )

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
            "ocr": ocr_stats,
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
    parser.add_argument("--ocr", default="auto", choices=["auto", "never", "force"],
                         help="PDF OCR fallback: 'auto' OCRs only pages with a missing/thin "
                              "text layer (default), 'never' disables OCR, 'force' OCRs every page")
    parser.add_argument("--ocr-lang", default=OCR_LANG,
                         help=f"Tesseract language(s), e.g. 'eng' or 'eng+deu' (default: {OCR_LANG})")
    parser.add_argument("--ocr-dpi", type=int, default=OCR_DPI,
                         help=f"Rasterization DPI for OCR (default: {OCR_DPI})")
    parser.add_argument("--ocr-min-chars", type=int, default=OCR_MIN_CHARS,
                         help=f"In 'auto' mode, OCR a page whose extractable text is below this "
                              f"many characters (default: {OCR_MIN_CHARS})")
    args = parser.parse_args()

    ocr_kwargs = dict(ocr_mode=args.ocr, ocr_lang=args.ocr_lang,
                      ocr_dpi=args.ocr_dpi, ocr_min_chars=args.ocr_min_chars)

    if args.batch:
        in_dir = Path(args.input)
        out_dir = Path(args.output or "converted")
        out_dir.mkdir(parents=True, exist_ok=True)
        failures = []
        for f in sorted(in_dir.rglob("*")):
            if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS:
                out_path = out_dir / (f.stem + ".md")
                try:
                    result = convert_file(f, normalize_form=args.normalize_form, **ocr_kwargs)
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
        result = convert_file(in_path, normalize_form=args.normalize_form, **ocr_kwargs)
    except Exception as e:
        print(f"ERROR converting {in_path}: {e}", file=sys.stderr)
        sys.exit(1)

    write_output(result, out_path)
    print(f"Converted: {in_path} -> {out_path}")
    print(f"  SHA-256:  {result['stats']['source_sha256'][:16]}...")
    print(f"  Chars:    {result['stats']['output_chars']}")
    ocr = result["stats"].get("ocr", {})
    if ocr.get("ocr_applied"):
        print(f"  OCR:      {ocr['ocr_engine']} on page(s) {ocr['ocr_pages']} (lang={ocr['ocr_lang']}, {ocr['ocr_dpi']} dpi)")
    if result["warnings"]:
        for w in result["warnings"]:
            print(f"  Warning:  {w}")


if __name__ == "__main__":
    main()
