# HanZihan UABE Android

Native Android migration of the supplied HanZihan UABE Flask project. Runtime does **not** use Flask, WebView, a local HTTP server, or Termux.

## Implemented baseline
- Native Java Android activity (no WebView).
- Chaquopy embeds Python 3.11 in the APK for 32-bit ARM devices.
- Supplied `aov_bytes_analyzer.py` is integrated.
- Android document picker is used for local file selection and report export.
- AOV analysis produces TXT and JSON reports.
- AOV text replacement now creates a separate edited copy using the legacy app’s UTF-8 byte-replacement rules; the original file is never overwritten.
- Edited output can be exported with Android’s document picker.
- A bounded byte-offset inspector displays HEX and printable ASCII without modifying the source; each request is limited to 4096 bytes.
- An ASCII string extractor lists up to 300 printable ASCII runs with byte offsets; it is read-only and supports minimum lengths of 4–128 characters.
- An in-app UnityPy dependency probe reports whether UnityPy and its compression/texture dependencies can import in the Android runtime. It is diagnostic only and does not install packages.
- A guarded UnityPy Bundle Browser now attempts to load a selected bundle and list object metadata (name, type, Path ID, Class ID, raw size, type counts). It is read-only, displays at most 1000 objects, and requires UnityPy to be importable at runtime.

**Important:** the supplied analyzer remains read-only. The separate text editor implements the original Flask route’s raw UTF-8 byte replacement; it is not a decoder or semantic editor for compressed/encrypted AOV structures. The Bundle Browser is an initial read-only integration and remains unverified on a physical Android device. The dependency probe must pass on-device before relying on bundle parsing; asset editing and export are not enabled.

## Preserved migration reference
`legacy_reference/app_flask_reference.py` is the original uploaded Flask source, kept only as a reference while porting features. It is not packaged as an active Flask server. `docs/FLASK_ROUTE_INVENTORY.md` lists its routes. `docs/NEXT_PHASE.md` describes the migration order and release gates.

## Build on GitHub
1. Create a GitHub repository and upload the **contents** of this folder to its root.
2. Push to `main` or `master`, or open **Actions → Build HanZihan UABE APK → Run workflow**.
3. Download artifact `HanZihan-UABE-debug-apk` from the completed workflow run.

The workflow builds a debug APK for `armeabi-v7a` (32-bit ARM). Project settings: Android Gradle Plugin 8.13.2, Gradle 8.13, JDK 17, Chaquopy 17.2.0, Python 3.11, minSdk 24, target/compile SDK 35.

## Local build
With JDK 17, Android SDK 35, and Gradle 8.13 installed:

```bash
gradle --no-daemon assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk`.

## Status
This is an incremental migration source, **not a completed clone** of every Flask feature. See `docs/NEXT_PHASE.md` before treating any pending editor as available.


## 32-bit device target

This source is configured for `armeabi-v7a` only and Python 3.11 because Chaquopy supports 32-bit ARM only through Python 3.11. The Android APK has not yet been built or installed on a 32-bit device. UnityPy and its native/transitive dependencies are not confirmed for this ABI.

## Automated 32-bit build checks

The GitHub Actions workflow now runs Python syntax checks and unit tests before Gradle, builds the debug APK, then verifies that the APK contains `armeabi-v7a` native libraries and no other native ABI directories. On success it uploads `HanZihan-UABE-32bit-debug-apk`. Build logs and APK-entry diagnostics are uploaded separately when available.

These checks validate the build artifact's ABI packaging; they do not replace installation and runtime testing on the actual 32-bit phone. UnityPy remains an optional runtime probe and is not guaranteed to import on `armeabi-v7a`.
