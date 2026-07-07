#!/usr/bin/env python3
"""
scan_binary.py

Scans RAW source documents (before conversion to Markdown) for file-format-level
threats that only exist in the binary and do not survive conversion:

  - VBA macros in Office files (OOXML and legacy OLE), with real decompilation
    and suspicious-keyword analysis via oletools -- not just "does a macro exist"
  - Embedded executables/scripts hidden inside an Office ZIP container
  - Remote template injection (external relationship targets in OOXML .rels files)
  - XXE indicators (DOCTYPE/ENTITY declarations in OOXML XML parts)
  - Zip-bomb characteristics (extreme compression ratios / oversized archives)
  - Extension vs magic-byte mismatch (a .docx that isn't actually a zip, etc.)
  - PDF-specific risks: embedded JavaScript, auto-run OpenActions, Launch actions,
    embedded files, encryption

This is the FIRST stage of a three-stage pipeline:

    raw docs --[this scanner]--> doc-to-markdown --> doc-security-scan --> ingestion

Run this BEFORE doc-to-markdown ever opens/parses an untrusted file.

Usage:
    python3 scan_binary.py FILE [FILE2 ...]
    python3 scan_binary.py --batch DIR
    python3 scan_binary.py FILE --json-only

Exit codes (same convention as the other two skills in this pipeline):
    0 = clean
    1 = warnings (e.g. macros present but not flagged malicious, encrypted PDF,
        legacy OLE format needing manual review) -- review recommended
    2 = blocking findings (malicious macro indicators, embedded executables,
        remote template injection, extension/magic-byte spoofing, zip bomb,
        auto-running PDF JavaScript) -- do not proceed to conversion
"""

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Any

try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Magic bytes / format identification
# ---------------------------------------------------------------------------

MAGIC_SIGNATURES = {
    b"PK\x03\x04": "zip_ooxml",       # docx/xlsx/pptx/odt are zip containers
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "ole_compound",  # legacy doc/xls/ppt, or encrypted OOXML
    b"%PDF": "pdf",
}

EXTENSION_EXPECTED_FORMAT = {
    ".docx": "zip_ooxml", ".xlsx": "zip_ooxml", ".pptx": "zip_ooxml",
    ".docm": "zip_ooxml", ".xlsm": "zip_ooxml", ".pptm": "zip_ooxml",
    ".doc": "ole_compound", ".xls": "ole_compound", ".ppt": "ole_compound",
    ".pdf": "pdf",
}

DANGEROUS_ARCHIVE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe",
    ".js", ".jse", ".jar", ".msi", ".com", ".pif", ".hta", ".wsf",
}

# oletools suspicious-keyword categories we treat as auto-block vs. warn
OLEVBA_BLOCK_KEYWORDS = {
    "Shell", "WScript.Shell", "CreateObject", "powershell", "cmd.exe",
    "Kill", "URLDownloadToFile", "Environ", "ShellExecute",
}
OLEVBA_AUTOEXEC = {
    "AutoOpen", "AutoExec", "Auto_Open", "Document_Open", "Workbook_Open",
}

PDF_BLOCK_KEYWORDS = [b"/Launch"]
PDF_WARN_KEYWORDS = [b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/EmbeddedFile", b"/RichMedia"]
PDF_ENCRYPT_KEYWORD = b"/Encrypt"

ZIP_BOMB_RATIO_THRESHOLD = 100        # uncompressed/compressed ratio
ZIP_BOMB_UNCOMPRESSED_LIMIT = 500 * 1024 * 1024  # 500 MB


# ---------------------------------------------------------------------------
# Core detection
# ---------------------------------------------------------------------------

def identify_format(raw_head: bytes) -> str:
    for sig, fmt in MAGIC_SIGNATURES.items():
        if raw_head.startswith(sig):
            return fmt
    return "unknown"


def check_extension_mismatch(path: Path, detected_format: str) -> list[dict]:
    findings = []
    expected = EXTENSION_EXPECTED_FORMAT.get(path.suffix.lower())
    if expected and detected_format == "unknown":
        findings.append({"type": "unreadable_or_corrupt", "detail": f"File has extension {path.suffix} but content doesn't match any known format signature"})
    elif expected and expected != detected_format:
        # ole_compound masquerading as zip_ooxml extension is a real pattern:
        # encrypted OOXML files are stored as OLE compound files. Flag but
        # distinguish from a hard spoof (e.g. .docx that's secretly a PDF).
        if expected == "zip_ooxml" and detected_format == "ole_compound":
            findings.append({"type": "encrypted_or_legacy_ooxml", "detail": "File has an OOXML extension but is stored as an OLE compound file -- likely password-protected, or mislabeled legacy format"})
        else:
            findings.append({"type": "extension_spoofing", "detail": f"Extension {path.suffix} implies '{expected}' but content signature is '{detected_format}'"})
    return findings


def _read_zip_member(zf: zipfile.ZipFile, name: str) -> str | None:
    """Read and UTF-8-decode a zip member, returning None if it can't be read
    (a corrupt/unreadable member shouldn't abort the scan of the rest)."""
    try:
        return zf.read(name).decode("utf-8", errors="replace")
    except Exception:
        return None


def scan_zip_container(path: Path) -> dict:
    findings: dict[str, Any] = {"macros": [], "embedded_executables": [], "remote_injection": [], "xxe": [], "zip_bomb": []}
    try:
        with zipfile.ZipFile(path) as zf:
            infolist = zf.infolist()

            total_uncompressed = sum(i.file_size for i in infolist)
            total_compressed = sum(max(i.compress_size, 1) for i in infolist)
            ratio = total_uncompressed / max(total_compressed, 1)
            if ratio > ZIP_BOMB_RATIO_THRESHOLD or total_uncompressed > ZIP_BOMB_UNCOMPRESSED_LIMIT:
                findings["zip_bomb"].append({
                    "type": "suspicious_compression_ratio",
                    "detail": f"Compression ratio {ratio:.0f}x, uncompressed size {total_uncompressed / 1_000_000:.1f} MB",
                })

            names = [i.filename for i in infolist]

            if any(n.lower().endswith("vbaproject.bin") for n in names):
                findings["macros"].append({"type": "vba_project_present", "detail": "vbaProject.bin found in archive"})

            for n in names:
                ext = Path(n).suffix.lower()
                if ext in DANGEROUS_ARCHIVE_EXTENSIONS:
                    findings["embedded_executables"].append({"type": "embedded_dangerous_file", "detail": n})

            for n in names:
                if n.endswith(".rels"):
                    content = _read_zip_member(zf, n)
                    if content is None:
                        continue
                    for m in re.finditer(r'TargetMode="External"[^>]*Target="([^"]+)"|Target="([^"]+)"[^>]*TargetMode="External"', content):
                        target = m.group(1) or m.group(2)
                        findings["remote_injection"].append({"type": "external_relationship_target", "detail": f"{n} -> {target}"})

            for n in names:
                if n.endswith(".xml"):
                    content = _read_zip_member(zf, n)
                    if content is None:
                        continue
                    if "<!DOCTYPE" in content or "<!ENTITY" in content:
                        findings["xxe"].append({"type": "doctype_or_entity_declaration", "detail": n})

    except zipfile.BadZipFile:
        findings["zip_bomb"].append({"type": "corrupt_or_not_a_zip", "detail": "File could not be opened as a zip archive"})

    return findings


def scan_macros_with_oletools(path: Path) -> dict:
    """Real VBA decompilation + suspicious-keyword scan. Works on both
    legacy OLE (.doc/.xls/.ppt) and OOXML (.docm/.xlsm/.pptm) containers."""
    findings: dict[str, Any] = {"autoexec": [], "suspicious_keywords": [], "parse_error": None}
    if not OLETOOLS_AVAILABLE:
        findings["parse_error"] = "oletools not installed -- macro content analysis skipped"
        return findings
    try:
        parser = VBA_Parser(str(path))
        if not parser.detect_vba_macros():
            return findings
        for (_, _, _, code) in parser.extract_macros():
            if not code:
                continue
            for kw in OLEVBA_AUTOEXEC:
                if kw.lower() in code.lower():
                    findings["autoexec"].append(kw)
            for kw in OLEVBA_BLOCK_KEYWORDS:
                if kw.lower() in code.lower():
                    findings["suspicious_keywords"].append(kw)
        parser.close()
    except Exception as e:
        findings["parse_error"] = f"oletools failed to parse macros: {e}"
    findings["autoexec"] = sorted(set(findings["autoexec"]))
    findings["suspicious_keywords"] = sorted(set(findings["suspicious_keywords"]))
    return findings


def scan_pdf(path: Path) -> dict:
    findings: dict[str, Any] = {"launch_actions": [], "js_or_autorun": [], "encrypted": []}
    raw = path.read_bytes()
    for kw in PDF_BLOCK_KEYWORDS:
        if kw in raw:
            findings["launch_actions"].append(kw.decode())
    for kw in PDF_WARN_KEYWORDS:
        if kw in raw:
            findings["js_or_autorun"].append(kw.decode())
    if PDF_ENCRYPT_KEYWORD in raw:
        findings["encrypted"].append("document is encrypted/password-protected")
    return findings


def scan_file(path: Path) -> dict:
    raw_head = path.read_bytes()[:8]
    detected_format = identify_format(raw_head)

    report: dict[str, Any] = {
        "file": str(path),
        "detected_format": detected_format,
        "extension_findings": check_extension_mismatch(path, detected_format),
        "zip_findings": {},
        "macro_findings": {},
        "pdf_findings": {},
    }

    if detected_format == "zip_ooxml":
        report["zip_findings"] = scan_zip_container(path)
        if path.suffix.lower() in {".docm", ".xlsm", ".pptm"} or report["zip_findings"].get("macros"):
            report["macro_findings"] = scan_macros_with_oletools(path)
    elif detected_format == "ole_compound":
        report["macro_findings"] = scan_macros_with_oletools(path)
    elif detected_format == "pdf":
        report["pdf_findings"] = scan_pdf(path)

    report["level"], report["exit_code"] = classify_severity(report)
    return report


def classify_severity(report: dict) -> tuple[str, int]:
    block_reasons, warn_reasons = [], []

    for f in report["extension_findings"]:
        if f["type"] in ("extension_spoofing", "unreadable_or_corrupt"):
            block_reasons.append(f["type"])
        else:
            warn_reasons.append(f["type"])

    zf = report.get("zip_findings", {})
    if zf.get("zip_bomb"):
        block_reasons.append("zip_bomb")
    if zf.get("embedded_executables"):
        block_reasons.append("embedded_executable")
    if zf.get("remote_injection"):
        block_reasons.append("remote_template_injection")
    if zf.get("xxe"):
        warn_reasons.append("xxe_indicator")
    if zf.get("macros"):
        warn_reasons.append("macro_present")

    mf = report.get("macro_findings", {})
    if mf.get("autoexec") and mf.get("suspicious_keywords"):
        block_reasons.append("autoexec_with_suspicious_keywords")
    elif mf.get("suspicious_keywords"):
        warn_reasons.append("suspicious_macro_keywords")
    elif mf.get("autoexec"):
        warn_reasons.append("macro_autoexec")

    pf = report.get("pdf_findings", {})
    if pf.get("launch_actions"):
        block_reasons.append("pdf_launch_action")
    if pf.get("js_or_autorun"):
        # auto-run JS (OpenAction + JS together) is worse than JS alone
        if "/OpenAction" in pf["js_or_autorun"] and ("/JS" in pf["js_or_autorun"] or "/JavaScript" in pf["js_or_autorun"]):
            block_reasons.append("pdf_autorun_javascript")
        else:
            warn_reasons.append("pdf_js_or_embedded_content")
    if pf.get("encrypted"):
        warn_reasons.append("pdf_encrypted")

    if block_reasons:
        return "BLOCK", 2
    if warn_reasons:
        return "WARN", 1
    return "CLEAN", 0


def main():
    parser = argparse.ArgumentParser(description="Scan raw source documents for file-format-level security risks before conversion.")
    parser.add_argument("paths", nargs="*", help="File(s) to scan")
    parser.add_argument("--batch", metavar="DIR", help="Scan all supported files in a directory")
    parser.add_argument("--json-only", action="store_true", help="Print only the JSON report")
    args = parser.parse_args()

    files = []
    if args.batch:
        exts = set(EXTENSION_EXPECTED_FORMAT.keys())
        files.extend(sorted(f for f in Path(args.batch).rglob("*") if f.is_file() and f.suffix.lower() in exts))
    files.extend(Path(p) for p in args.paths)

    if not files:
        print("No files to scan. Provide file paths or --batch DIR.", file=sys.stderr)
        sys.exit(1)

    reports = []
    worst_code = 0
    for f in files:
        try:
            report = scan_file(f)
        except Exception as e:
            report = {"file": str(f), "level": "BLOCK", "exit_code": 2, "error": str(e)}
        reports.append(report)
        worst_code = max(worst_code, report["exit_code"])

        if not args.json_only:
            icon = {"CLEAN": "OK  ", "WARN": "WARN", "BLOCK": "FAIL"}[report["level"]]
            print(f"{icon} {f}  [{report['level']}]")
            if report.get("error"):
                print(f"       - error: {report['error']}")
            for f_item in report.get("extension_findings", []):
                print(f"       - format: {f_item['type']}: {f_item['detail']}")
            for cat, items in report.get("zip_findings", {}).items():
                for item in items:
                    print(f"       - archive/{cat}: {item['type']}: {item['detail']}")
            mf = report.get("macro_findings", {})
            if mf.get("autoexec"):
                print(f"       - macro autoexec triggers: {', '.join(mf['autoexec'])}")
            if mf.get("suspicious_keywords"):
                print(f"       - macro suspicious keywords: {', '.join(mf['suspicious_keywords'])}")
            if mf.get("parse_error"):
                print(f"       - macro scan note: {mf['parse_error']}")
            pf = report.get("pdf_findings", {})
            for cat, items in pf.items():
                if items:
                    print(f"       - pdf/{cat}: {items}")

    if args.json_only:
        print(json.dumps(reports, indent=2))
    else:
        Path("pre-conversion-scan-report.json").write_text(json.dumps(reports, indent=2))
        print(f"\nFull report written to pre-conversion-scan-report.json")

    sys.exit(worst_code)


if __name__ == "__main__":
    main()
