# Flask route inventory (migration reference)

Extracted from the supplied `app.py`; this is a route inventory, not a claim that these endpoints are already implemented in Android.

| Route | Methods | Handler |
|---|---|---|
| `/` | GET | `index` |
| `/animationclip-delete/<uid>/<path:path_id>` | POST | `animationclip_delete` |
| `/animationclip-manager/<uid>` | GET | `animationclip_manager` |
| `/aov-analysis/<uid>` | GET | `aov_analysis` |
| `/aov-edit/<uid>` | GET,POST | `aov_edit` |
| `/aov-export/<uid>` | GET | `aov_export` |
| `/aov-report/<uid>/<fmt>` | GET | `aov_report_download` |
| `/asset-json-export/<uid>/<path:path_id>` | GET | `asset_json_export` |
| `/asset-json-import/<uid>/<path:path_id>` | GET,POST | `asset_json_import` |
| `/asset-json-preview/<uid>/<path:path_id>` | GET,POST | `asset_json_preview` |
| `/assets/<uid>/<category>` | GET | `asset_category` |
| `/create-account` | GET,POST | `create_account` |
| `/dashboard` | GET | `index` |
| `/download-modified/<uid>` | GET | `download_modified` |
| `/download/<uid>` | GET | `download` |
| `/health` | GET | `health` |
| `/login` | GET,POST | `login` |
| `/logout` | POST | `logout` |
| `/mesh-delete-all/<uid>` | POST | `mesh_delete_all` |
| `/mesh-delete/<uid>/<path:path_id>` | POST | `mesh_delete` |
| `/mesh-edit/<uid>/<path:path_id>` | GET,POST | `mesh_edit` |
| `/mesh-export/<uid>/<path:path_id>` | GET | `mesh_export` |
| `/mesh-import/<uid>/<path:path_id>` | POST | `mesh_import` |
| `/mesh-manager/<uid>` | GET | `mesh_manager` |
| `/preview/<uid>/<int:index>` | GET | `preview` |
| `/texture-export/<uid>/<path:path_id>` | GET | `texture_export` |
| `/texture-import/<uid>/<path:path_id>` | GET,POST | `texture_import` |
| `/texture-manager/<uid>` | GET | `texture_manager` |
| `/texture-preview/<uid>/<path:path_id>` | GET | `texture_preview` |
| `/upload` | POST | `upload` |

**Total routes:** 30

## Migration rule

Implement each operation as a native screen or repository/service method. Do not recreate Flask routing, cookies, sessions, or an embedded HTTP server in the APK. Keep file parsing and editing independent from UI so the same engine can be tested.
