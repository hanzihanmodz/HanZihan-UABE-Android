# Next migration phase

## Current verified baseline
- Native Java Activity exists.
- Chaquopy embeds Python 3.11 for the 32-bit ARM target (`armeabi-v7a`).
- `aov_bytes_analyzer.py` and `android_bridge.py` are included.
- AOV analyzer is read-only; it creates reports and does not edit source `.bytes` files.
- `legacy_reference/app_flask_reference.py` preserves the supplied Flask source for feature-by-feature migration. It is not imported or executed by the Android app.

## Phase order
1. Stabilize Android file access, analyzer report export, and raw UTF-8 AOV text replacement.
2. Add local workspace/history and app preferences (no server account system).
3. Byte-offset HEX/ASCII inspection and legacy-compatible ASCII string extraction are implemented as read-only tools. String extraction returns the first 300 printable ASCII runs and reports their offsets.
4. Run the in-app UnityPy dependency probe on Android armeabi-v7a (32-bit ARM). It checks UnityPy plus lz4, brotli, Pillow, texture2ddecoder, etcpak, astc-encoder-py, fmod-toolkit, fsspec, attrs, and tpk-ar.
5. A guarded, read-only UnityPy Bundle Browser has been added. It mirrors the legacy `load_bundle()` metadata fields and caps the displayed inventory at 1000 objects.
6. Run the dependency probe and test the Bundle Browser on-device with a harmless test bundle. Do not enable export/edit until this passes.
7. Port each asset editor with round-trip tests and preserve the original file until export succeeds.

## Release gates
- Debug APK builds in GitHub Actions.
- Install and launch on Android 13 armeabi-v7a (32-bit ARM).
- Test small and large files, cancellation, invalid files, low storage, and report export.
- For every editing operation: compare input/output, reopen output, and verify unrelated assets remain unchanged.

## Known blockers
- UnityPy and its transitive native dependencies have not yet been proven compatible with Chaquopy on Android armeabi-v7a (32-bit ARM). The new in-app probe is diagnostic only; it does not install packages or prove bundle parsing/export. The Bundle Browser can fail gracefully if UnityPy or native dependencies are unavailable.
- The analyzer is read-only; the separately ported text editor only performs literal UTF-8 byte replacement, matching the legacy Flask route.
- Flask authentication/session behavior must be deliberately redesigned for a single-device offline app; do not copy password/session handling blindly.
