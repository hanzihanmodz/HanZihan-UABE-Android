# Migration status from the supplied Flask app.py

| Source capability | Android status |
|---|---|
| Account creation / login / logout | Not ported; local app profile design still needed |
| Dashboard / upload flow | Native file picker exists for AOV analyzer only |
| AOV bytes analysis | Implemented locally using the supplied analyzer module |
| AOV editing | Not present in the supplied analyzer (it is explicitly read-only) |
| AOV TXT / JSON report export | Implemented |
| Raw byte-offset inspection | Implemented; read-only HEX/ASCII window, max 4096 bytes |
| ASCII string extraction | Implemented; read-only printable ASCII runs, minimum length 4–128, first 300 matches with byte offsets |
| UnityPy dependency probe | Implemented; checks 11 runtime modules without installing packages |
| UnityPy bundle loading and asset browser | Pending on-device dependency probe and minimal load/export test |
| Asset JSON preview/import/export | Pending UnityPy migration |
| Mesh manager/import/edit/export | Pending UnityPy migration |
| Texture2D preview/import/export | Pending UnityPy + image dependency migration |
| AnimationClip manager/delete | Pending UnityPy migration |

Important: the supplied `aov_bytes_analyzer.py` declares itself read-only. Do not label its output as an AOV editor or imply that it modifies `.bytes` files.


## Latest increment — read-only Bundle Browser
- Added `open_bundle_readonly()` to the Android Python bridge. It mirrors the original Flask `load_bundle()` metadata inventory: asset name, type, Path ID, Class ID, and raw data size.
- Added native Android UI to invoke it on the selected file. The displayed list is capped at 1000 assets; the bridge accepts 1–5000.
- The feature does not save, modify, or export bundle contents. UnityPy must be importable in the Android runtime.
- Verified with a mocked UnityPy API contract test only; real UnityPy parsing and Android armeabi-v7a (32-bit ARM) compatibility remain unverified.
