#!/usr/bin/env python3
# AOV Universal Bytes Analyzer
# Read-only analyzer: does not modify source files or attempt to rebuild unknown formats.

from __future__ import annotations
import argparse
import collections
import hashlib
import json
import math
import os
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path

MAX_SAMPLE = 1024 * 1024
MAX_STRINGS = 250
MAX_NESTED_DEPTH = 4

MAGICS = [
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x28\xb5\x2f\xfd", "Zstandard frame"),
    (b"\x1f\x8b", "GZIP"),
    (b"\x78\x01", "ZLIB (no/low compression)"),
    (b"\x78\x9c", "ZLIB"),
    (b"\x78\xda", "ZLIB (best compression)"),
    (b"UnityFS", "UnityFS AssetBundle"),
    (b"UnityRaw", "UnityRaw AssetBundle"),
    (b"UnityWeb", "UnityWeb AssetBundle"),
    (b"\x7fELF", "ELF binary"),
    (b"MZ", "Windows PE"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"<?xml", "XML text"),
    (b"{", "Possible JSON"),
    (b"[", "Possible JSON array"),
]

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

def printable_strings(data: bytes, min_len: int = 4):
    found = []
    # ASCII runs
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        found.append((m.start(), m.group().decode("ascii", "replace"), "ASCII"))
    # UTF-16 LE runs (basic heuristic)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data):
        try:
            s = m.group().decode("utf-16le", "replace")
            found.append((m.start(), s, "UTF-16LE"))
        except Exception:
            pass
    found.sort(key=lambda x: x[0])
    # deduplicate overlapping identical strings
    seen = set()
    result = []
    for item in found:
        key = (item[0], item[1])
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result[:MAX_STRINGS]

def detect_magic(data: bytes):
    matches = []
    for magic, label in MAGICS:
        if data.startswith(magic):
            matches.append(label)
    # AOV wrapper observed in supplied examples; do not assume payload semantics.
    if data.startswith(bytes.fromhex("22 4A 00 EF")):
        matches.append("AOV-style wrapper candidate (22 4A 00 EF)")
    if len(data) >= 8 and data[8:12] == bytes.fromhex("28 B5 2F FD"):
        matches.append("Zstandard frame at offset 8")
    return matches or ["Unknown / custom binary"]

def zstd_info(data: bytes, offset: int = 0):
    frame = data[offset:]
    if not frame.startswith(bytes.fromhex("28 B5 2F FD")):
        return None
    info = {"frame_offset": offset, "frame_magic": "28b52ffd"}
    try:
        import zstandard as zstd
        p = zstd.get_frame_parameters(frame)
        info.update({
            "window_size": getattr(p, "window_size", None),
            "content_size": getattr(p, "content_size", None),
            "dict_id": getattr(p, "dict_id", None),
            "checksum": getattr(p, "has_checksum", None),
            "library": "python-zstandard",
        })
        try:
            dctx = zstd.ZstdDecompressor()
            decoded = dctx.decompress(frame, max_output_size=64 * 1024 * 1024)
            info["decompression"] = "success without external dictionary"
            info["decompressed_size"] = len(decoded)
            info["decompressed_sha256"] = hashlib.sha256(decoded).hexdigest()
            info["decompressed_preview_hex"] = decoded[:64].hex(" ")
            info["decompressed_strings"] = [
                {"offset": o, "text": s, "encoding": enc}
                for o, s, enc in printable_strings(decoded)[:40]
            ]
        except Exception as e:
            info["decompression"] = "failed"
            info["decompression_error"] = str(e)[:300]
    except ImportError:
        info["library"] = "python-zstandard not installed"
        info["decompression"] = "not attempted"
    except Exception as e:
        info["parameter_error"] = str(e)[:300]
    return info

def inspect_blob(name: str, data: bytes, depth: int = 0):
    result = {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "header_hex": data[:64].hex(" "),
        "entropy_first_1mb": round(entropy(data[:MAX_SAMPLE]), 4),
        "magic": detect_magic(data),
        "strings": [
            {"offset": o, "text": s, "encoding": enc}
            for o, s, enc in printable_strings(data)[:MAX_STRINGS]
        ],
    }
    # Common 8-byte wrapper candidate: 4-byte marker + little-endian declared size.
    if len(data) >= 8 and data[:4] == bytes.fromhex("22 4A 00 EF"):
        result["wrapper_candidate"] = {
            "marker": data[:4].hex(" "),
            "declared_size_le_u32": struct.unpack("<I", data[4:8])[0],
            "payload_offset": 8,
            "payload_header_hex": data[8:24].hex(" "),
        }
        zi = zstd_info(data, 8)
        if zi:
            result["zstandard"] = zi
    else:
        zi = zstd_info(data, 0)
        if zi:
            result["zstandard"] = zi

    # ZIP contents can be inspected recursively without extracting to disk.
    if depth < MAX_NESTED_DEPTH and data.startswith(b"PK\x03\x04"):
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                entries = []
                for info in zf.infolist()[:1000]:
                    item = {
                        "name": info.filename,
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "is_dir": info.is_dir(),
                    }
                    if not info.is_dir() and info.file_size <= 32 * 1024 * 1024:
                        try:
                            child = zf.read(info)
                            item["analysis"] = inspect_blob(info.filename, child, depth + 1)
                        except Exception as e:
                            item["read_error"] = str(e)[:200]
                    entries.append(item)
                result["zip"] = {
                    "entry_count": len(zf.infolist()),
                    "entries": entries,
                }
        except Exception as e:
            result["zip_error"] = str(e)[:300]
    return result

def analyze_path(path: Path):
    if path.is_file():
        data = path.read_bytes()
        return inspect_blob(path.name, data)
    if path.is_dir():
        files = []
        for p in sorted(path.rglob("*")):
            if p.is_file():
                try:
                    data = p.read_bytes()
                    files.append(inspect_blob(str(p.relative_to(path)), data))
                except Exception as e:
                    files.append({"name": str(p), "error": str(e)[:300]})
        return {"root": str(path), "file_count": len(files), "files": files}
    raise FileNotFoundError(path)

def summarize(report):
    items = report.get("files", [report])
    lines = []
    lines.append("AOV UNIVERSAL BYTES ANALYZER")
    lines.append("=" * 72)
    for item in items:
        lines.append(f"\nFILE: {item.get('name')}")
        lines.append(f"SIZE: {item.get('size')} bytes")
        lines.append(f"SHA256: {item.get('sha256')}")
        lines.append(f"MAGIC: {', '.join(item.get('magic', []))}")
        lines.append(f"ENTROPY: {item.get('entropy_first_1mb')}")
        lines.append(f"HEADER: {item.get('header_hex')}")
        if "wrapper_candidate" in item:
            w = item["wrapper_candidate"]
            lines.append(f"WRAPPER SIZE (LE): {w['declared_size_le_u32']}")
            lines.append(f"PAYLOAD OFFSET: {w['payload_offset']}")
        if "zstandard" in item:
            z = item["zstandard"]
            lines.append(f"ZSTD: {json.dumps({k:v for k,v in z.items() if k not in ('decompressed_strings',)}, ensure_ascii=False)}")
        strings = item.get("strings", [])[:50]
        if strings:
            lines.append("STRINGS:")
            for s in strings:
                lines.append(f"  0x{s['offset']:08X} [{s['encoding']}] {s['text'][:180]}")
        if "zip" in item:
            lines.append(f"ZIP ENTRIES: {item['zip']['entry_count']}")
            for e in item["zip"]["entries"]:
                lines.append(f"  {e['name']} ({e['size']} bytes)")
    return "\n".join(lines) + "\n"

def main():
    ap = argparse.ArgumentParser(description="Read-only analyzer for AOV .bytes and nested package files")
    ap.add_argument("input", help="file or folder to analyze")
    ap.add_argument("-o", "--output", default="aov_bytes_report", help="output basename (without extension)")
    args = ap.parse_args()
    src = Path(args.input).expanduser()
    report = analyze_path(src)
    base = Path(args.output).expanduser()
    base.parent.mkdir(parents=True, exist_ok=True)
    json_path = base.with_suffix(".json")
    txt_path = base.with_suffix(".txt")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    txt_path.write_text(summarize(report), encoding="utf-8")
    print("ANALISIS SELESAI")
    print(f"JSON: {json_path.resolve()}")
    print(f"TXT : {txt_path.resolve()}")
    print("Mode: READ-ONLY — file sumber tidak diubah.")

if __name__ == "__main__":
    main()
