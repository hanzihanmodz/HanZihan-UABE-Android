"""Small Android-facing adapter. No Flask, sockets, or local web server."""
from pathlib import Path
import json
import aov_bytes_analyzer as analyzer


def analyze_file(input_path: str, output_dir: str) -> str:
    src = Path(input_path)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    report = analyzer.analyze_path(src)
    summary = analyzer.summarize(report)
    json_path = out / "aov_bytes_report.json"
    text_path = out / "aov_bytes_report.txt"
    json_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    text_path.write_text(summary, encoding="utf-8")
    return json.dumps({
        "summary": summary,
        "json_path": str(json_path),
        "text_path": str(text_path),
        "file_name": src.name,
        "file_size": src.stat().st_size,
    }, ensure_ascii=False)


def replace_utf8_text(input_path: str, output_dir: str, old_text: str, new_text: str) -> str:
    """Create an edited copy using the legacy app's exact UTF-8 byte replacement rules.

    The source file is never overwritten. This is a raw byte replacement, not a
    decompressor or a semantic AOV format editor.
    """
    import time

    if not old_text:
        raise ValueError("Teks lama wajib diisi.")
    old_bytes = old_text.encode("utf-8")
    new_bytes = new_text.encode("utf-8")
    if len(old_bytes) > 1024 * 1024 or len(new_bytes) > 1024 * 1024:
        raise ValueError("Maksimal 1 MiB untuk teks lama atau pengganti.")

    src = Path(input_path)
    if not src.is_file():
        raise FileNotFoundError("File sumber tidak ditemukan.")
    data = src.read_bytes()
    count = data.count(old_bytes)
    if count == 0:
        raise ValueError("Teks tidak ditemukan sebagai teks UTF-8. Jika file terkompresi atau terenkripsi, teks mungkin tidak terbaca langsung.")
    if count > 10000:
        raise ValueError(f"Ditemukan {count} kemunculan. Terlalu banyak untuk satu operasi; gunakan teks yang lebih spesifik.")

    updated = data.replace(old_bytes, new_bytes)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in src.name)
    target = out / f"{safe_name}.edited.{int(time.time() * 1000)}"
    temp = target.with_name(target.name + ".writing")
    try:
        temp.write_bytes(updated)
        temp.replace(target)
    finally:
        if temp.exists():
            temp.unlink()

    return json.dumps({
        "output_path": str(target),
        "file_name": target.name,
        "replacement_count": count,
        "old_size": len(data),
        "new_size": len(updated),
    }, ensure_ascii=False)


def probe_unitypy() -> str:
    """Report whether UnityPy and its required modules are importable.

    This does not install packages or open user files. Native imports are
    attempted only when the module is present in the embedded environment.
    """
    import importlib
    import importlib.util
    from importlib import metadata

    checks = [
        ("UnityPy", "UnityPy"),
        ("lz4", "lz4"),
        ("brotli", "brotli"),
        ("Pillow", "PIL"),
        ("texture2ddecoder", "texture2ddecoder"),
        ("etcpak", "etcpak"),
        ("astc-encoder-py", "astc_encoder"),
        ("fmod-toolkit", "fmod_toolkit"),
        ("fsspec", "fsspec"),
        ("attrs", "attrs"),
        ("tpk-ar", "tpk_ar"),
    ]
    rows = []
    ready = True
    for distribution, module_name in checks:
        try:
            spec = importlib.util.find_spec(module_name)
        except (ImportError, ValueError, ModuleNotFoundError):
            spec = None
        if spec is None:
            rows.append({"distribution": distribution, "module": module_name,
                         "status": "missing", "version": None, "error": None})
            ready = False
            continue
        try:
            module = importlib.import_module(module_name)
            try:
                version = metadata.version(distribution)
            except metadata.PackageNotFoundError:
                version = getattr(module, "__version__", "unknown")
            rows.append({"distribution": distribution, "module": module_name,
                         "status": "ok", "version": str(version), "error": None})
        except Exception as exc:
            rows.append({"distribution": distribution, "module": module_name,
                         "status": "import_error", "version": None,
                         "error": str(exc)[:300]})
            ready = False
    return json.dumps({"ready": ready, "checks": rows}, ensure_ascii=False)


def inspect_bytes(input_path: str, offset_text: str = "0", length_text: str = "256") -> str:
    """Inspect a bounded byte window without modifying the source file."""
    src = Path(input_path)
    if not src.is_file():
        raise FileNotFoundError("File sumber tidak ditemukan.")
    try:
        offset = int(offset_text, 0)
        length = int(length_text, 0)
    except (TypeError, ValueError):
        raise ValueError("Offset dan panjang harus berupa angka desimal atau 0x heksadesimal.")
    if offset < 0 or length < 1 or length > 4096:
        raise ValueError("Offset minimal 0 dan panjang harus 1–4096 byte.")
    size = src.stat().st_size
    if offset > size:
        raise ValueError(f"Offset melewati ukuran file ({size} byte).")
    with src.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(length)
    lines = []
    for start in range(0, len(data), 16):
        chunk = data[start:start + 16]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset + start:08X}  {hex_part:<47}  |{ascii_part}|")
    return json.dumps({
        "file_name": src.name,
        "file_size": size,
        "offset": offset,
        "bytes_read": len(data),
        "hex_dump": "\\n".join(lines),
    }, ensure_ascii=False)


def extract_ascii_strings(input_path: str, minimum_text_length: str = "4") -> str:
    """List up to 300 readable ASCII runs, matching the legacy AOV editor.

    The source is memory-mapped read-only so large files aren't copied into RAM.
    Each result includes its absolute byte offset. No file content is modified.
    """
    import mmap
    import re

    src = Path(input_path)
    if not src.is_file():
        raise FileNotFoundError("File sumber tidak ditemukan.")
    try:
        minimum = int(minimum_text_length, 10)
    except (TypeError, ValueError):
        raise ValueError("Panjang minimum harus berupa angka.")
    if minimum < 4 or minimum > 128:
        raise ValueError("Panjang minimum harus 4–128 karakter.")

    size = src.stat().st_size
    found = []
    if size:
        with src.open("rb") as stream:
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                pattern = re.compile(rb"[ -~]{" + str(minimum).encode("ascii") + rb",}")
                for match in pattern.finditer(data):
                    value = match.group().decode("ascii")
                    found.append({"offset": match.start(), "text": value})
                    if len(found) >= 300:
                        break
    return json.dumps({
        "file_name": src.name,
        "file_size": size,
        "minimum_length": minimum,
        "count": len(found),
        "limit": 300,
        "truncated": len(found) == 300,
        "strings": found,
    }, ensure_ascii=False)


def open_bundle_readonly(input_path: str, max_assets_text: str = "1000") -> str:
    """Load a Unity bundle with UnityPy and return a bounded read-only inventory.

    This intentionally does not call save(), mutate objects, or export payloads.
    The object metadata mirrors the legacy Flask load_bundle() implementation.
    """
    import importlib.util

    src = Path(input_path)
    if not src.is_file():
        raise FileNotFoundError("File bundle tidak ditemukan.")
    try:
        max_assets = int(max_assets_text, 10)
    except (TypeError, ValueError):
        raise ValueError("Batas asset harus berupa angka.")
    if max_assets < 1 or max_assets > 5000:
        raise ValueError("Batas tampilan harus 1–5000 asset.")

    if importlib.util.find_spec("UnityPy") is None:
        raise RuntimeError("UnityPy belum tersedia di runtime Android. Jalankan pemeriksaan kompatibilitas terlebih dahulu.")
    try:
        import UnityPy
    except Exception as exc:
        raise RuntimeError("UnityPy gagal dimuat: " + str(exc)[:250])

    try:
        env = UnityPy.load(str(src))
    except Exception as exc:
        raise RuntimeError("UnityPy tidak dapat membuka file ini: " + str(exc)[:300])

    try:
        objects = env.objects
    except Exception as exc:
        raise RuntimeError("Daftar objek bundle tidak dapat dibaca: " + str(exc)[:250])

    try:
        total = len(objects)
    except Exception:
        objects = list(objects)
        total = len(objects)

    types = {}
    assets = []
    modified = int(src.stat().st_mtime)
    for index, obj in enumerate(objects):
        try:
            type_name = obj.type.name
        except Exception:
            try:
                type_name = str(obj.type)
            except Exception:
                type_name = "Unknown"
        try:
            path_id = int(obj.path_id)
        except Exception:
            path_id = str(getattr(obj, "path_id", "Unknown"))
        try:
            class_id = int(obj.type)
        except Exception:
            class_id = "Unknown"
        try:
            asset_name = obj.peek_name() or f"{type_name}_{path_id}"
        except Exception:
            asset_name = f"{type_name}_{path_id}"
        types[type_name] = types.get(type_name, 0) + 1
        if len(assets) < max_assets:
            try:
                asset_size = len(obj.get_raw_data())
            except Exception:
                asset_size = 0
            assets.append({
                "index": index, "name": str(asset_name), "type": str(type_name),
                "path_id": path_id, "class_id": class_id, "size": asset_size,
                "modified": modified
            })

    return json.dumps({
        "file_name": src.name, "file_size": src.stat().st_size,
        "total_assets": total, "shown_assets": len(assets),
        "truncated": total > len(assets), "types": types, "assets": assets,
        "read_only": True
    }, ensure_ascii=False)
