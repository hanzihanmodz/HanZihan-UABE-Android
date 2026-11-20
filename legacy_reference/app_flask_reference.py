from flask import (
    Flask, request, redirect, url_for,
    render_template_string, send_file, flash, session, abort
)
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
from functools import wraps
import sqlite3
import secrets
import re
import UnityPy
import aov_bytes_analyzer as aov_analyzer
import uuid
import os
import json
import shutil
import time

app = Flask(__name__)
BASE = Path(__file__).resolve().parent

# Secret key persisten agar sesi login tidak terputus setiap server restart.
SECRET_FILE = BASE / ".secret_key"
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    try:
        SECRET_FILE.chmod(0o600)
    except OSError:
        pass
app.secret_key = SECRET_FILE.read_text(encoding="utf-8").strip()
app.config.update(
    MAX_CONTENT_LENGTH=300 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

UPLOADS = BASE / "uploads"
UPLOADS.mkdir(exist_ok=True)
DB_PATH = BASE / "accounts.sqlite3"

def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_accounts_db():
    with db_connect() as conn:
        info = conn.execute("PRAGMA table_info(accounts)").fetchall()
        if info:
            columns = {row["name"]: row for row in info}
            # Migrasi database lama yang masih mewajibkan email.
            if "email" in columns and columns["email"]["notnull"]:
                conn.execute("ALTER TABLE accounts RENAME TO accounts_old")
                conn.execute("""
                    CREATE TABLE accounts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    INSERT INTO accounts(id, username, password_hash, created_at)
                    SELECT id, username, password_hash, created_at FROM accounts_old
                """)
                conn.execute("DROP TABLE accounts_old")
        else:
            conn.execute("""
                CREATE TABLE accounts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            """)

init_accounts_db()

def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

def valid_csrf():
    sent = request.form.get("_csrf_token", "")
    saved = session.get("_csrf_token", "")
    return bool(sent and saved and secrets.compare_digest(sent, saved))

@app.before_request
def require_login():
    public_endpoints = {"login", "create_account", "health"}
    if request.endpoint not in public_endpoints and not session.get("user_id"):
        return redirect(url_for("login"))

@app.context_processor
def inject_auth_helpers():
    return {"csrf_token": csrf_token}

@app.before_request
def block_cross_site_posts():
    # CSRF defence for every state-changing request: browsers always send
    # Origin (or Referer) on cross-site POSTs, so a host mismatch is rejected.
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        from urllib.parse import urlparse
        source = request.headers.get("Origin") or request.headers.get("Referer")
        if source and urlparse(source).netloc != request.host:
            abort(403)

@app.before_request
def enforce_session_owner():
    # Uploaded sessions belong to the account that created them.
    uid = (request.view_args or {}).get("uid")
    item = sessions.get(uid) if uid else None
    if item is not None and item.get("owner") not in (None, session.get("user_id")):
        abort(404)

MENU_JS = ("<script>document.addEventListener('click',function(e){var b=document.body;"
           "if(b.classList.contains('sidebar-open')&&!e.target.closest('.sidebar,.menu-toggle'))"
           "b.classList.remove('sidebar-open')});document.addEventListener('keydown',function(e){"
           "if(e.key==='Escape')document.body.classList.remove('sidebar-open')});</script>")

PREMIUM_CSS = r"""@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@400;500;600;700&family=Noto+Serif+JP:wght@500;700&display=swap');
:root{--ink:#0e1017;--surface:#151824;--raised:#1c2030;--line:#2a2f42;--text:#ebe7e0;--muted:#9499ad;--gold:#c8a45f;--rose:#b83552;--rose-hi:#cb4562;--link:#e58aa0;--serif:'Noto Serif JP','Hiragino Mincho ProN',Georgia,serif;--sans:'Noto Sans JP','Hiragino Sans',system-ui,-apple-system,'Segoe UI',sans-serif}
html body{background:radial-gradient(900px 500px at 92% -5%,#2a1a2688,transparent 60%),var(--ink)!important;color:var(--text)!important;font-family:var(--sans)!important;font-size:14px;line-height:1.6;animation:none!important}
html body::before,html body::after{display:none!important}
html body h1,html body h2,html body h3,html body .logo,html body .brand{font-family:var(--serif)!important;font-weight:700;letter-spacing:.01em!important;text-transform:none!important}
html body header{background:#0e1017d9!important;backdrop-filter:blur(14px);border-bottom:1px solid var(--line)!important;box-shadow:none!important;animation:none!important}
html body header:after{display:none}
html body .logo{color:var(--text)!important;font-size:20px;animation:none!important;text-shadow:none!important}
html body .sub{color:var(--muted)!important;letter-spacing:.04em!important;text-transform:none}
html body .sidebar{background:#0f121a!important;border-right:1px solid var(--line)!important;box-shadow:none}
html body .side-brand strong{color:var(--text)!important;letter-spacing:.02em!important}
html body .side-brand small,html body .nav-label{color:var(--muted)!important;letter-spacing:.06em!important;font-weight:600}
html body .sidebar a,html body .category-link{border-radius:9px!important;color:#b9bdcc!important;font-size:13px;border:1px solid transparent!important;transition:background .15s,color .15s}
html body .sidebar a:hover,html body .category-link:hover{background:var(--raised)!important;color:var(--text)!important;border-color:var(--line)!important}
html body .sidebar a span,html body .category-link span{color:var(--gold)!important}
html body .side-status{background:#12161f!important;border:1px solid var(--line)!important;color:#a9c9b5!important;border-radius:10px!important}
html body .panel{background:var(--surface)!important;border:1px solid var(--line)!important;border-radius:14px!important;box-shadow:0 1px 0 #ffffff08 inset,0 18px 40px -24px #000!important;animation:none!important}
html body .panel:before,html body .panel h2:before{display:none!important}
html body .panel:hover{border-color:#3a4058!important;transform:none}
html body .panel h2{font-size:16px!important;color:var(--text)!important;border-bottom:1px solid var(--line)!important;padding-bottom:12px!important;margin-bottom:16px!important}
html body .muted,html body small{color:var(--muted)!important}
html body a{color:var(--link)}
html body .stat{background:var(--raised)!important;border:1px solid var(--line)!important;border-radius:11px!important;animation:none!important}
html body .stat b{font-family:var(--serif);color:var(--text)!important;font-weight:700;font-variant-numeric:tabular-nums}
html body button,html body .btn,html body input[type=submit]{background:var(--rose)!important;color:#fff6f1!important;border:1px solid #ffffff22!important;border-radius:9px!important;min-height:40px;padding:10px 18px;font:600 13px/1.2 var(--sans)!important;letter-spacing:0!important;text-transform:none!important;box-shadow:none!important;transition:background .15s,transform .1s}
html body button:hover,html body .btn:hover,html body input[type=submit]:hover{background:var(--rose-hi)!important;filter:none!important;transform:none!important}
html body button:active,html body .btn:active{transform:scale(.98)!important}
html body .action-danger{background:transparent!important;border-color:#b83552aa!important;color:#f2a0b0!important}
html body .action-danger:hover{background:#b8355222!important}
html body .menu-toggle{background:var(--raised)!important;border:1px solid var(--line)!important}
html body input,html body select,html body textarea{background:#0e1017!important;color:var(--text)!important;border:1px solid var(--line)!important;border-radius:9px!important;font-family:var(--sans)!important}
html body input::placeholder,html body textarea::placeholder{color:#6d7288}
html body input:focus,html body select:focus,html body textarea:focus{border-color:var(--gold)!important;box-shadow:0 0 0 3px #c8a45f26!important;outline:none}
html body :focus-visible{outline:2px solid var(--gold);outline-offset:2px}
html body .scroll{border:1px solid var(--line)!important;border-radius:12px!important;background:#11141d}
html body table{font-size:13px;font-variant-numeric:tabular-nums}
html body th{background:var(--raised)!important;color:var(--muted)!important;font-weight:600;letter-spacing:0!important;text-transform:none!important;font-size:12px}
html body th,html body td{border-bottom:1px solid #232839!important}
html body tbody tr:nth-child(even){background:transparent!important}
html body tbody tr:hover{background:#ffffff08!important}
html body .tag{color:var(--gold)!important}
html body .action-group a{display:inline-flex;align-items:center;min-height:32px;padding:6px 11px!important;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--text)!important;font-size:12px!important;font-weight:500;letter-spacing:0!important;text-transform:none!important;text-decoration:none;transition:background .15s,border-color .15s}
html body .action-group a:hover{background:#ffffff0a;border-color:#4a5070;transform:none!important;box-shadow:none!important}
html body .action-group button{min-height:32px!important;padding:6px 12px!important;font-size:12px!important}
html body td:nth-child(n+4):nth-child(-n+6){white-space:nowrap}
html body .sidebar .developer-link{display:flex!important;align-items:center;gap:12px;min-height:46px;margin:8px 0}
html body .sidebar .developer-link .developer-icon{display:flex!important;align-items:center;justify-content:center;width:30px!important;flex:none}
html body .sidebar .developer-link .external-icon{margin-left:auto}
html body .sidebar .side-status{position:static!important;margin-top:20px}
html body .sidebar .developer-footer{margin-top:20px}
html body .notice,html body .msg{background:#2a1c26!important;border:1px solid #6b2f45!important;color:#f6d8df!important;border-radius:10px!important}
html body .native-menu-button{background:var(--raised)!important;border:1px solid var(--line)!important;color:var(--text)!important}
html body .native-dropdown{background:var(--raised)!important;border:1px solid var(--line)!important;box-shadow:0 20px 40px -12px #000!important;border-radius:11px!important}
html body .dropdown-option{background:transparent!important;color:var(--text)!important;font-weight:500!important;font-size:14px!important;border-radius:0!important}
html body .dropdown-option:hover,html body .dropdown-option.active{background:#ffffff0d!important}
html body .game-picker-grid label{background:var(--raised)!important;border:1px solid var(--line)!important;border-radius:12px!important;transition:border-color .15s,background .15s}
html body .game-picker-grid label:hover{border-color:#4a5070!important}
html body .game-picker-grid label:has(input:checked){border-color:var(--gold)!important;background:#c8a45f14!important}
html body .game-picker-grid label span{letter-spacing:0!important;text-transform:none}
html body .developer-card{background:var(--raised)!important;border:1px solid var(--line)!important}
html body .developer-avatar{border:2px solid var(--gold)!important;box-shadow:none!important;background:var(--rose)!important}
html body .developer-link{border:1px solid var(--line)!important;color:var(--text)!important}
html body .developer-link:hover{background:#ffffff08!important;border-color:#4a5070!important}
html body .developer-badge,html body .external-icon{color:var(--gold)!important}
html body .auth-card{background:var(--surface)!important;border:1px solid var(--line)!important;border-radius:18px!important;box-shadow:0 30px 80px -30px #000!important}
html body .auth-card .japan-mark{background:var(--rose)!important;box-shadow:0 0 0 5px #b8355226!important}
html body .kamon{color:var(--muted)!important;letter-spacing:.2em!important}
::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-thumb{background:#343a52;border-radius:9px}::-webkit-scrollbar-track{background:transparent}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
/* ---- Layout: top bar + drawer menu + two-column workbench ---- */
html body header{left:0!important;right:0!important;justify-content:flex-start!important;gap:16px;padding:0 28px!important}
html body header form{margin-left:auto!important}
html body .menu-toggle{display:inline-flex!important;align-items:center;order:-1;min-height:38px;padding:8px 14px;background:var(--raised)!important}
html body .sidebar{width:min(320px,88vw)!important;transform:translateX(-105%);transition:transform .22s ease;z-index:60!important;box-shadow:24px 0 60px -20px #000!important;overflow-y:auto}
html body.sidebar-open .sidebar{transform:none!important}
@media (max-width:760px){
html body header{padding:0 12px!important;gap:10px}
html body header .logo{font-size:15px!important;white-space:nowrap}
html body header .sub{display:none!important}
html body header .menu-toggle,html body header form button{white-space:nowrap;min-height:38px;padding:8px 12px!important;font-size:12px!important}
html body header form button{max-width:42vw;overflow:hidden;text-overflow:ellipsis}
}
html body.sidebar-open::after{display:block!important;content:"";position:fixed;inset:64px 0 0 0;background:#05060acc;z-index:55;pointer-events:none}
@media (min-width:1101px){
html body header{height:64px!important;padding-top:0!important;padding-bottom:0!important}
html body .sidebar{top:64px!important}
html body main{width:auto!important;max-width:1480px;margin:64px auto 0!important;padding:28px 32px 64px!important;display:grid!important;grid-template-columns:minmax(300px,4fr) minmax(0,8fr)!important;column-gap:20px;row-gap:0!important;align-items:start}
html body main>.notice{grid-column:1/-1!important;margin:0 0 16px}
html body main>.panel{margin:0 0 20px!important}
html body main #upload-panel{grid-column:1!important;grid-row:10}
html body main #info-panel{grid-column:1!important;grid-row:11}
html body main #explorer-panel{grid-column:2!important;grid-row:10/span 2}
html body main #obj-preview-panel{grid-column:1/-1!important;grid-row:12}
html body main #summary-panel{grid-column:1/2!important;grid-row:13}
html body main #tools-panel{grid-column:2!important;grid-row:13}
html body #explorer-panel .scroll{max-height:calc(100vh - 280px);min-height:360px}
html body #info-panel .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
html body main:not(:has(#explorer-panel)){grid-template-columns:minmax(0,7fr) minmax(0,5fr)!important}
html body main:not(:has(#explorer-panel)) #tools-panel{grid-column:2!important;grid-row:10}
html body main:not(:has(#explorer-panel)) .game-picker-grid{grid-template-columns:repeat(3,minmax(0,1fr))!important}
}
"""

UPGRADE_CSS = r"""/* ===== UPGRADE v3: gaya Android Material 3 (gelap) + animasi ===== */
:root{
--m-bg:#10131a;--m-surface:#1b1e26;--m-surface-hi:#252932;--m-card-line:#4a4d57;--m-chip-line:#6b6e78;--m-divider:#33363f;
--m-on:#e2e2e9;--m-muted:#8d909a;--m-accent:#aac7ff;--m-btn:#2d3a56;--m-btn-hi:#38486b;--m-on-btn:#dbe2ff;--m-tonal:#2d3a56;--m-on-tonal:#dbe2ff;
--ink:var(--m-bg);--surface:var(--m-surface);--raised:var(--m-surface-hi);--line:var(--m-divider);--text:var(--m-on);--muted:var(--m-muted);
--gold:var(--m-accent);--rose:var(--m-btn);--rose-hi:var(--m-btn-hi);--link:var(--m-accent);--ease:cubic-bezier(.22,1,.36,1);
--ic-filter:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M10 18h4v-2h-4v2zM3 6v2h18V6H3zm3 7h12v-2H6v2z'/%3E%3C/svg%3E");
--ic-sort:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M3 18h6v-2H3v2zM3 6v2h18V6H3zm0 7h12v-2H3v2z'/%3E%3C/svg%3E");
--ic-more:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z'/%3E%3C/svg%3E");
--ic-menu:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z'/%3E%3C/svg%3E");
--ic-heart:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z'/%3E%3C/svg%3E");
--ic-star:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 0l2.6 9.4L24 12l-9.4 2.6L12 24l-2.6-9.4L0 12l9.4-2.6z'/%3E%3C/svg%3E");
--ic-moon:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 0 1-4.4 2.26 5.403 5.403 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z'/%3E%3C/svg%3E");
--ic-check:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z'/%3E%3C/svg%3E");
}
@keyframes rise{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}
@keyframes slideDown{from{opacity:0;transform:translateY(-100%)}to{opacity:1;transform:none}}
@keyframes itemIn{from{opacity:0;transform:translateX(-14px)}to{opacity:1;transform:none}}
@keyframes rowIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
@keyframes pop{from{opacity:0;transform:translateY(-6px) scale(.96)}to{opacity:1;transform:none}}
@keyframes toastIn{from{opacity:0;transform:translate(-50%,20px)}to{opacity:1;transform:translate(-50%,0)}}
@keyframes toastOut{to{opacity:0;transform:translate(-50%,12px)}}
@keyframes pulseBtn{0%{box-shadow:0 0 0 0 var(--m-accent)}100%{box-shadow:0 0 0 14px transparent}}

::selection{background:color-mix(in srgb,var(--m-accent) 40%,transparent);color:#fff}
html{scroll-behavior:smooth;color-scheme:dark}
html body{background:var(--m-bg)!important;color:var(--m-on)!important;font-family:'Noto Sans JP',Roboto,system-ui,sans-serif;transition:background .6s}
html body::before,html body::after{display:none!important}
html body main,html body .wrap{position:relative;z-index:1}

/* ---- Tombol ---- */
html body :is(button,.btn,input[type=submit],input[type=button]){display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:40px;padding:0 20px!important;border:1px solid var(--m-chip-line)!important;border-radius:20px!important;background:transparent!important;color:var(--m-accent)!important;box-shadow:none!important;font:500 13px/1 'Noto Sans JP',sans-serif!important;letter-spacing:.06em!important;text-transform:uppercase;text-decoration:none;cursor:pointer;transition:box-shadow .2s,transform .2s var(--ease),background .2s!important}
html body :is(button[type=submit],.btn,input[type=submit]){border:0!important;background:var(--m-btn)!important;color:var(--m-on-btn)!important}
html body :is(button,.btn,input[type=submit]):hover{box-shadow:inset 0 0 0 999px #ffffff14!important;transform:none!important}
html body :is(button,.btn):active{box-shadow:inset 0 0 0 999px #ffffff24!important;transform:scale(.98)!important}
html body button:is(.action-danger,.danger),html body a:is(.action-danger,.danger){background:transparent!important;color:#ffb4ab!important;border:1px solid #8c4a52!important}
html body .action-group{gap:8px}
html body .action-group :is(a,button){min-height:32px;padding:0 12px!important;border:1px solid var(--m-chip-line)!important;border-radius:8px!important;background:transparent!important;color:var(--m-accent)!important;font:600 11px/1 'Noto Sans JP',sans-serif!important;letter-spacing:.05em!important}
html body .action-group a:hover{box-shadow:inset 0 0 0 999px #ffffff14!important}

/* ---- App bar ---- */
html body header{display:flex!important;align-items:center;gap:4px;padding:0 8px 0 20px!important;min-height:64px;background:var(--m-bg)!important;border:0!important;border-bottom:1px solid var(--m-divider)!important;box-shadow:none!important;backdrop-filter:none!important;animation:slideDown .6s var(--ease) both!important}
html body header::before,html body header::after{display:none!important}
html body header .logo{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:none!important;-webkit-text-fill-color:currentColor!important;color:var(--m-on)!important;font:400 22px/1.2 'Noto Sans JP',Roboto,sans-serif!important;letter-spacing:0!important;text-transform:none!important;text-shadow:none!important}
html body header .sub,html body header>form[action="/logout"]{display:none!important}
html body header .appbar-actions{display:flex;align-items:center;gap:2px;margin-left:auto;flex:none}
html body header .appbar-btn,html body header .appbar-icon,html body header .menu-toggle{position:relative;border:0!important;background:transparent!important;box-shadow:none!important;color:var(--m-on)!important;cursor:pointer;transition:box-shadow .2s!important}
html body header .appbar-btn{height:40px;padding:0 14px!important;border-radius:20px!important;font:500 14px/1 'Noto Sans JP',Roboto,sans-serif!important;letter-spacing:.08em!important;text-transform:uppercase!important}
html body header .appbar-icon,html body header .menu-toggle{width:40px;height:40px;padding:0!important;border-radius:50%!important;font-size:0!important;order:-1;margin-right:4px}
html body header .appbar-icon{order:0;margin:0}
html body header .appbar-icon::before,html body header .menu-toggle::before{content:"";position:absolute;inset:8px;background:currentColor;-webkit-mask:var(--ic-more) center/contain no-repeat;mask:var(--ic-more) center/contain no-repeat;display:block!important}
html body header .menu-toggle::before{-webkit-mask-image:var(--ic-menu);mask-image:var(--ic-menu)}
html body header .appbar-btn:hover,html body header .appbar-icon:hover,html body header .menu-toggle:hover{box-shadow:inset 0 0 0 999px #ffffff14!important;transform:none!important}
html body header .appbar-btn:active,html body header .appbar-icon:active{box-shadow:inset 0 0 0 999px #ffffff22!important}
html body .appmenu{position:fixed;right:8px;top:60px;z-index:70;display:none;width:min(300px,calc(100vw - 16px));max-height:calc(100vh - 80px);overflow:auto;padding:8px 0;background:var(--m-surface-hi);border-radius:14px;box-shadow:0 10px 34px #000b,0 0 0 1px #ffffff10}
html body .appmenu.open{display:block;animation:pop .2s var(--ease)}
html body .appmenu-h{padding:10px 16px 4px;font:600 11px 'Noto Sans JP',sans-serif;letter-spacing:.1em;text-transform:uppercase;color:var(--m-muted)}
html body .appmenu hr{border:0;border-top:1px solid var(--m-divider);margin:6px 0}
html body button.appmenu-item{display:flex!important;justify-content:flex-start!important;align-items:center;gap:12px;width:100%;height:46px;padding:0 16px!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;color:var(--m-on)!important;font:400 15px 'Noto Sans JP',sans-serif!important;letter-spacing:0!important;text-transform:none!important;text-align:left;cursor:pointer}
html body button.appmenu-item:hover{background:#ffffff12!important;transform:none!important}
html body .appmenu-item .ck{width:18px;height:18px;flex:none;background:var(--m-accent);-webkit-mask:var(--ic-check) center/contain no-repeat;mask:var(--ic-check) center/contain no-repeat;opacity:0}
html body .appmenu-item.on{color:var(--m-accent)!important}
html body .appmenu-item.on .ck{opacity:1}
html body .appmenu-item small{margin-left:auto;color:var(--m-muted);font-size:12px}

/* ---- Sidebar (navigation drawer) ---- */
html body .sidebar{background:var(--m-bg)!important;border-right:1px solid var(--m-divider)!important;padding:16px 12px!important;box-shadow:none}
html body .side-brand{margin:4px 8px 8px}
html body .side-brand strong{font:500 18px 'Noto Sans JP',sans-serif!important;letter-spacing:0!important;color:var(--m-on)!important;text-transform:capitalize}
html body .nav-label{padding:18px 16px 8px!important;font:600 11px 'Noto Sans JP',sans-serif!important;letter-spacing:.1em!important;color:var(--m-muted)!important}
html body .sidebar a{display:flex!important;align-items:center;gap:12px;min-height:48px;padding:0 16px!important;border:0!important;border-radius:28px!important;background:transparent!important;color:var(--m-on)!important;font:500 14px 'Noto Sans JP',sans-serif!important;letter-spacing:.01em!important;box-shadow:none!important;transition:background .2s,transform .25s var(--ease)}
html body .sidebar a:hover{background:#ffffff10!important;transform:translateX(3px)}
html body .sidebar a.active{background:var(--m-tonal)!important;color:var(--m-on-tonal)!important}
html body .developer-card{border:1px solid var(--m-card-line)!important;border-radius:20px!important;background:transparent!important;text-align:center}
html body .developer-link{min-height:48px}
html body.sidebar-open .sidebar>*{animation:itemIn .45s var(--ease) backwards;animation-delay:calc(var(--i,0)*40ms + 60ms)}
html body.sidebar-open::after{display:block!important;backdrop-filter:blur(2px)}

/* ---- Kartu (outlined card) ---- */
html body :is(.panel,#upload-panel,#info-panel,#explorer-panel,#tools-panel,#summary-panel,#obj-preview-panel){position:relative;background:transparent!important;border:1px solid var(--m-card-line)!important;border-radius:24px!important;box-shadow:none!important;padding:20px 24px!important;animation:rise .7s var(--ease) backwards;animation-delay:calc(var(--i,0)*80ms + 80ms)}
html body .panel h2{display:block;margin:0 0 10px!important;font:500 17px/1.3 'Noto Sans JP',sans-serif!important;letter-spacing:0!important;color:var(--m-on)!important;text-transform:lowercase!important;border:0!important;padding:0!important}
html body .panel h2::first-letter{text-transform:uppercase!important}
html body .panel h2::before{display:none!important}
html body .panel p,html body .panel label{color:var(--m-on)}
html body .muted,html body .empty-tip{color:var(--m-muted)!important}
html body .empty-card{padding:18px 24px!important}
html body .empty-title{margin:0 0 6px;font:400 18px/1.4 'Noto Sans JP',sans-serif;color:var(--m-on)}
html body .empty-tip{margin:0;font-size:16px;line-height:1.5}
html body .empty-chips{margin:16px 0 4px!important}
html body .rv{opacity:0;transform:translateY(22px)}
html body .rv.rv-in{opacity:1;transform:none;transition:opacity .7s var(--ease),transform .7s var(--ease)}
html body .stats{gap:12px!important}
html body .stat{background:var(--m-surface)!important;border:0!important;border-radius:16px!important;padding:16px!important;transition:transform .3s var(--ease)}
html body .stat:hover{transform:translateY(-2px)}
html body .stat b{font:400 32px/1.1 'Noto Sans JP',sans-serif!important;color:var(--m-on)!important}
html body .notice,html body .msg{background:var(--m-tonal)!important;color:var(--m-on-tonal)!important;border:0!important;border-radius:12px!important;animation:rise .5s var(--ease) both}

/* ---- Chip Filter / Menyortir ---- */
html body .asset-controls{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:16px 0!important}
html body button.native-menu-button{display:inline-flex!important;align-items:center;gap:12px;height:40px;min-height:40px;padding:0 14px 0 16px!important;border:1px solid var(--m-chip-line)!important;border-radius:10px!important;background:transparent!important;color:var(--m-on)!important;font:600 16px/1 'Noto Sans JP',sans-serif!important;letter-spacing:0!important;text-transform:none!important;box-shadow:none!important}
html body .native-menu-button .menu-icon{display:inline-block;width:20px;height:20px;font-size:0!important;background:currentColor;-webkit-mask:var(--ic-filter) center/contain no-repeat;mask:var(--ic-filter) center/contain no-repeat}
html body :is(#sortButton,.chip-sort) .menu-icon{-webkit-mask-image:var(--ic-sort);mask-image:var(--ic-sort)}
html body button.native-menu-button:hover{box-shadow:inset 0 0 0 999px #ffffff12!important}
html body .asset-count{margin-left:auto;color:var(--m-muted)!important;font-size:13px}
html body .native-dropdown{background:var(--m-surface-hi)!important;border:0!important;border-radius:14px!important;box-shadow:0 10px 34px #000b,0 0 0 1px #ffffff10!important;padding:8px 0!important;min-width:210px;max-height:60vh;overflow:auto;animation:pop .2s var(--ease)}
html body button.dropdown-option{width:100%;justify-content:flex-start!important;min-height:46px!important;padding:0 16px!important;border:0!important;border-radius:0!important;background:transparent!important;color:var(--m-on)!important;font:400 15px 'Noto Sans JP',sans-serif!important;letter-spacing:0!important;text-transform:none!important;text-align:left}
html body button.dropdown-option:hover{background:#ffffff12!important}
html body button.dropdown-option.active{color:var(--m-accent)!important;background:#ffffff08!important}

html body .asset-controls .dropdown-wrap,html body .asset-controls button.native-menu-button{width:auto!important;flex:0 0 auto!important}
html body .asset-controls{justify-content:flex-start}
html body .game-picker-grid{grid-template-columns:1fr!important}
/* ---- Form ---- */
html body :is(input:not([type=checkbox]):not([type=radio]):not([type=file]):not([type=submit]):not([type=button]),select,textarea){background:transparent!important;border:1px solid var(--m-chip-line)!important;border-radius:12px!important;color:var(--m-on)!important;padding:13px 16px!important;font:400 16px 'Noto Sans JP',sans-serif!important;box-shadow:none!important;transition:border-color .2s,box-shadow .2s}
html body :is(input,select,textarea):hover{border-color:var(--m-muted)!important}
html body :is(input,select,textarea):focus{outline:0!important;border-color:var(--m-accent)!important;box-shadow:0 0 0 1px var(--m-accent)!important}
html body :is(#search,input[type=search]){border-radius:28px!important;background:var(--m-surface)!important;border-color:transparent!important;padding-left:20px!important}
html body input[type=file]{color:var(--m-muted)!important}
html body input[type=file]::file-selector-button{margin-right:12px;height:36px;padding:0 16px;border:0;border-radius:18px;background:var(--m-btn);color:var(--m-on-btn);font:500 12px 'Noto Sans JP',sans-serif;letter-spacing:.06em;text-transform:uppercase;cursor:pointer}
html body label{font:500 12px 'Noto Sans JP',sans-serif!important;letter-spacing:.08em;color:var(--m-muted)!important}
html body .game-picker-grid label{background:transparent!important;border:1px solid var(--m-card-line)!important;border-radius:16px!important;color:var(--m-on)!important;transition:border-color .25s,transform .3s var(--ease),box-shadow .3s}
html body .game-picker-grid label:hover{transform:translateY(-2px)}
html body .game-picker-grid label:has(input:checked){border-color:var(--m-accent)!important;box-shadow:0 0 0 1px var(--m-accent)}
html body .game-picker-grid label span{color:var(--m-on)!important}

/* ---- Tabel ---- */
html body .scroll{background:transparent!important;border:1px solid var(--m-card-line)!important;border-radius:16px!important}
html body table{border-collapse:collapse}
html body th{position:sticky;top:0;z-index:2;background:var(--m-bg)!important;color:var(--m-muted)!important;font:600 11px 'Noto Sans JP',sans-serif!important;letter-spacing:.1em!important;border-bottom:1px solid var(--m-divider)!important}
html body td{color:var(--m-on)!important;border-bottom:1px solid var(--m-divider)!important}
html body tbody tr{background:transparent!important;transition:background .2s}
html body tbody tr:hover{background:#ffffff08!important}
html body tbody tr.row-in{animation:rowIn .45s var(--ease) backwards;animation-delay:calc(var(--r,0)*22ms)}
html body .tag{color:var(--m-accent)!important}
html body pre,html body code{background:var(--m-surface)!important;color:var(--m-on)!important;border-radius:10px}

/* ---- Layout desktop: sidebar tetap ---- */
@media (min-width:1101px){
html body:has(.sidebar) .menu-toggle{display:none!important}
html body:has(.sidebar) .sidebar{transform:none!important;width:272px!important;top:64px!important;box-shadow:none!important}
html body:has(.sidebar) main{margin:64px 0 0 272px!important;max-width:1640px;padding:28px 36px 80px!important}
html body:has(.sidebar).sidebar-open::after{display:none!important}
html body:has(.sidebar) main:has(#explorer-panel){grid-template-columns:minmax(300px,340px) minmax(0,1fr)!important}
html body:has(.sidebar) .sidebar>*{animation:itemIn .5s var(--ease) backwards;animation-delay:calc(var(--i,0)*40ms + 250ms)}
html body:has(.sidebar) #evbar{left:272px}
}
@media (max-width:760px){
html body :is(.panel,#upload-panel,#info-panel,#explorer-panel,#tools-panel){padding:16px 18px!important}
html body main{padding-left:16px!important;padding-right:16px!important}
}

/* ---- Login ---- */
html body .auth-card{background:var(--m-surface)!important;border:1px solid var(--m-card-line)!important;border-radius:28px!important;box-shadow:none!important;animation:rise .8s var(--ease) both!important}
html body .auth-card h1{font:400 26px 'Noto Sans JP',sans-serif!important;color:var(--m-on)!important}
html body .auth-card button{width:100%}
html body .foot a{color:var(--m-accent)!important}

/* ---- Snackbar / toast ---- */
.ev-toast{position:fixed;left:50%;width:max-content;bottom:24px;z-index:90;max-width:min(92vw,460px);padding:14px 20px;border-radius:12px;background:var(--m-surface-hi);color:var(--m-on);font:400 14px/1.4 'Noto Sans JP',sans-serif;box-shadow:0 8px 26px #000a;animation:toastIn .45s var(--ease) both,toastOut .45s 4.2s ease forwards;pointer-events:none}
.pulse-attn{animation:pulseBtn 1s ease-out 3}
@media (prefers-reduced-motion:reduce){html body .rv{opacity:1;transform:none}}

/* ===== TEMA EVENT (aktif otomatis lewat html[data-event]) ===== */
@keyframes blink{0%,100%{opacity:1;filter:brightness(1.25)}50%{opacity:.35;filter:brightness(.7)}}
@keyframes swing{0%,100%{transform:rotate(-5deg)}50%{transform:rotate(5deg)}}
@keyframes flicker{0%,100%{box-shadow:0 0 18px 4px var(--g,#ffb347aa)}45%{box-shadow:0 0 28px 8px var(--g,#ffb347aa)}70%{box-shadow:0 0 14px 2px var(--g,#ffb347aa)}}
@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(14px)}}
@keyframes wave{0%,100%{transform:skewY(-8deg) scaleX(1)}50%{transform:skewY(8deg) scaleX(.82)}}
@keyframes waveflag{0%,100%{transform:scaleX(1)}50%{transform:scaleX(.8)}}
@keyframes foil{0%{background-position:0% 50%}100%{background-position:200% 50%}}
@keyframes twinkle{0%,100%{transform:scale(.8) rotate(0);opacity:.5}50%{transform:scale(1.15) rotate(45deg);opacity:1}}
@keyframes dripgrow{0%,100%{transform:scaleY(1)}50%{transform:scaleY(1.45)}}
@keyframes beat{0%,100%{transform:scale(1)}20%{transform:scale(1.28)}40%{transform:scale(1)}60%{transform:scale(1.18)}}

#evbar{position:fixed;left:0;right:0;top:64px;height:60px;z-index:15;pointer-events:none;overflow:visible}
#evbar svg{position:absolute;left:0;top:0;width:100%;height:42px}
#evfx{position:fixed;inset:0;z-index:6;pointer-events:none}
.bulb{position:absolute;width:9px;height:13px;margin-left:-4px;border-radius:50% 50% 45% 45%;background:var(--c);box-shadow:0 0 10px 2px var(--c);animation:blink 1.9s ease-in-out infinite}
.bulb::before{content:"";position:absolute;left:1px;top:-4px;width:7px;height:5px;border-radius:2px 2px 0 0;background:#1a2a20}
.bulb.hl{width:15px;height:14px;margin-left:-7px;border-radius:0;box-shadow:none;background:var(--c);-webkit-mask:var(--ic-heart) center/contain no-repeat;mask:var(--ic-heart) center/contain no-repeat;filter:drop-shadow(0 0 4px var(--c))}
.bulb.hl::before{display:none}
.ribbon{position:absolute;top:0;width:6px;border-radius:0 0 4px 4px;background:var(--c);transform-origin:top;animation:swing 3.2s ease-in-out infinite;opacity:.9}
.lantern{position:absolute;top:0;width:34px;margin-left:-17px;transform-origin:top center;animation:swing 4.2s ease-in-out infinite}
.lantern i{display:block;width:2px;height:16px;margin:0 auto;background:#ffd66b}
.lantern b{display:block;position:relative;width:34px;height:40px;border-radius:50%/46%;background:radial-gradient(circle at 50% 40%,#ff5a4f,#c4141c 70%);--g:#ff3b30aa;animation:flicker 2.6s ease-in-out infinite;border-top:4px solid #ffd66b;border-bottom:4px solid #ffd66b}
.lantern b::after{content:"";position:absolute;left:50%;top:100%;margin:4px 0 0 -3px;width:6px;height:18px;border-radius:0 0 3px 3px;background:linear-gradient(#ffd66b,#e0a82e)}
.lantern.fa b{width:30px;height:44px;border-radius:30% 30% 50% 50%/16% 16% 40% 40%;background:repeating-linear-gradient(90deg,#8a5a12 0 2px,transparent 2px 7px),radial-gradient(circle at 50% 45%,#ffe9a3,#e0a82e 75%);border-color:#8a5a12;--g:#ffd66baa}
.lantern.fa{width:30px;margin-left:-15px}
.moon{position:absolute;right:18px;top:4px;width:34px;height:34px;background:#f6e7b4;-webkit-mask:var(--ic-moon) center/contain no-repeat;mask:var(--ic-moon) center/contain no-repeat;filter:drop-shadow(0 0 8px #f6e7b4aa)}
.web{position:absolute;top:0;width:110px;height:110px;background:repeating-radial-gradient(circle at 0 0,transparent 0 13px,#ffffff3a 14px 15px),repeating-conic-gradient(from 0deg at 0 0,#ffffff3a 0 1.2deg,transparent 1.2deg 22.5deg);-webkit-mask:linear-gradient(135deg,#000 45%,transparent 78%);mask:linear-gradient(135deg,#000 45%,transparent 78%)}
.web.l{left:0}.web.r{right:0;transform:scaleX(-1)}
.spider{position:absolute;top:0;width:16px;margin-left:-8px;animation:bob 3.4s ease-in-out infinite}
.spider i{display:block;width:1px;height:26px;margin:0 auto;background:#ffffff66}
.spider b{display:block;width:16px;height:14px;border-radius:50%;background:radial-gradient(circle at 30% 45%,#ff8a1f 0 1.5px,transparent 2px),radial-gradient(circle at 70% 45%,#ff8a1f 0 1.5px,transparent 2px),#0b0912;box-shadow:-5px 0 0 -2px #0b0912,5px 0 0 -2px #0b0912,-8px 3px 0 -3px #0b0912,8px 3px 0 -3px #0b0912}

/* ===== NATAL: tombol beku, salju di kartu, lampu natal ===== */
html[data-event=natal]{--m-bg:#0a1521;--m-surface:#13263a;--m-surface-hi:#1a3350;--m-card-line:#33597c;--m-chip-line:#5d8db3;--m-divider:#1f3a54;--m-on:#e8f4ff;--m-muted:#8fb0c9;--m-accent:#9fdcff;--m-btn:#cfeaff;--m-btn-hi:#e9f6ff;--m-on-btn:#0b3050;--m-tonal:#1d4468;--m-on-tonal:#d9f0ff}
html[data-event=natal] body{background:radial-gradient(900px 500px at 50% -10%,#1d4468aa,transparent 65%),var(--m-bg)!important}
html[data-event=natal] :is(button[type=submit],.btn,.native-menu-button,.action-group a,.action-group button){position:relative;overflow:visible}
html[data-event=natal] :is(button[type=submit],.btn){background:radial-gradient(circle at 18% 30%,#fff 0 1px,transparent 2px),radial-gradient(circle at 72% 62%,#fff 0 1px,transparent 2px),radial-gradient(circle at 46% 82%,#fff 0 1px,transparent 2px),linear-gradient(160deg,#f6fcff,#bfe6ff 48%,#86c8f2)!important;color:#0b3050!important;border:1px solid #fffffff0!important;box-shadow:inset 0 1px 6px #fff,inset 0 -8px 14px #5aa9de66,0 6px 18px -8px #6ec1ff!important;text-shadow:0 1px 0 #ffffffaa}
html[data-event=natal] .native-menu-button{background:linear-gradient(180deg,#ffffff22,#9fdcff10)!important;border-color:#bfe6ffa0!important;box-shadow:inset 0 1px 0 #ffffff66!important}
html[data-event=natal] :is(button[type=submit],.btn,.native-menu-button,.action-group a,.action-group button)::before{content:"";position:absolute;inset:0;border-radius:inherit;pointer-events:none;background:linear-gradient(115deg,transparent 35%,#ffffffb0 50%,transparent 65%) 160% 0/260% 100% no-repeat;transition:background-position .9s var(--ease)}
html[data-event=natal] :is(button[type=submit],.btn,.native-menu-button,.action-group a,.action-group button):hover::before{background-position:-60% 0}
html[data-event=natal] :is(button[type=submit],.btn,.native-menu-button,.action-group a,.action-group button)::after{content:"";position:absolute;left:10px;right:10px;top:calc(100% - 1px);height:11px;pointer-events:none;background:conic-gradient(from -45deg at 50% 100%,#eaf7ff 0 90deg,transparent 0) 0 0/10px 5px repeat-x,conic-gradient(from -27deg at 50% 100%,#cfeeff 0 54deg,transparent 0) 6px 0/24px 11px repeat-x;filter:drop-shadow(0 1px 1px #5aa9de99);transform-origin:top;transition:transform .5s var(--ease)}
html[data-event=natal] :is(button[type=submit],.btn,.native-menu-button,.action-group a,.action-group button):hover::after{transform:scaleY(1.7)}
html[data-event=natal] .action-group :is(a,button)::after{display:none}
html[data-event=natal] .panel::before{display:block!important;content:"";position:absolute;z-index:2;left:22px;right:22px;top:-2px;height:13px;pointer-events:none;background:radial-gradient(circle at 12px 100%,#fff 0 9px,transparent 10px) 0 0/26px 13px repeat-x,radial-gradient(circle at 0 100%,#e4f4ff 0 6px,transparent 7px) 13px 0/26px 13px repeat-x;filter:drop-shadow(0 -1px 3px #ffffff55)}
html[data-event=natal] .scroll,html[data-event=natal] .stat{backdrop-filter:blur(4px)}

/* ===== TAHUN BARU: foil emas + kembang api ===== */
html[data-event=tahunbaru]{--m-bg:#0b0912;--m-surface:#17131f;--m-surface-hi:#221c2e;--m-card-line:#5a4a22;--m-chip-line:#8c7430;--m-divider:#2e2616;--m-on:#fff4d6;--m-muted:#b3a47a;--m-accent:#f5d36b;--m-btn:#f4c542;--m-btn-hi:#ffe08a;--m-on-btn:#2a1d00;--m-tonal:#3a2f10;--m-on-tonal:#ffe9a6}
html[data-event=tahunbaru] :is(button[type=submit],.btn){position:relative;overflow:visible;background:linear-gradient(110deg,#fff3b0 0%,#f4c542 25%,#b8860b 50%,#f9e08a 75%,#fff3b0 100%)!important;background-size:200% 100%!important;animation:foil 5s linear infinite;color:#2a1d00!important;border:1px solid #fff0b0!important;box-shadow:0 0 0 1px #b8860b66,0 8px 22px -8px #f4c542aa!important}
html[data-event=tahunbaru] :is(button[type=submit],.btn)::after{content:"";position:absolute;right:-6px;top:-9px;width:16px;height:16px;background:#fff6c8;-webkit-mask:var(--ic-star) center/contain no-repeat;mask:var(--ic-star) center/contain no-repeat;filter:drop-shadow(0 0 5px #ffd54a);animation:twinkle 1.6s ease-in-out infinite;pointer-events:none}
html[data-event=tahunbaru] .native-menu-button{border-color:#c9a53a!important;box-shadow:0 0 12px -4px #f5d36b88!important;position:relative}
html[data-event=tahunbaru] .panel{border-image:linear-gradient(135deg,#f5d36b88,#5a4a2244,#f5d36b88) 1;border-radius:0!important}

/* ===== IMLEK: angpao merah-emas + lentera ===== */
html[data-event=imlek]{--m-bg:#160a0c;--m-surface:#2a1115;--m-surface-hi:#3a171c;--m-card-line:#7a2e34;--m-chip-line:#b0505a;--m-divider:#3a1a1e;--m-on:#fff0d2;--m-muted:#c9a08a;--m-accent:#ffcf5a;--m-btn:#c4141c;--m-btn-hi:#e5282f;--m-on-btn:#ffe29a;--m-tonal:#7a0f16;--m-on-tonal:#ffe7a6}
html[data-event=imlek] body{background:radial-gradient(800px 420px at 50% -8%,#7a0f1699,transparent 65%),var(--m-bg)!important}
html[data-event=imlek] :is(button[type=submit],.btn){position:relative;overflow:visible;background:linear-gradient(180deg,#ec2c34,#a90f18)!important;color:#ffe29a!important;border:1px solid #ffd66b!important;box-shadow:inset 0 0 0 2px #a90f18,inset 0 0 0 3px #ffd66b99,0 6px 16px -6px #e5282fcc!important}
html[data-event=imlek] :is(button[type=submit],.btn)::after{content:"";position:absolute;left:50%;top:100%;width:12px;height:18px;margin-left:-6px;pointer-events:none;background:linear-gradient(#ffd66b,#ffd66b) 50% 0/2px 7px no-repeat,radial-gradient(ellipse at 50% 0,#ffd66b 0 3px,transparent 4px) 50% 6px/12px 6px no-repeat,linear-gradient(#e0a82e,#ffd66b) 50% 9px/8px 9px no-repeat;border-radius:0 0 4px 4px;transform-origin:top;animation:swing 2.6s ease-in-out infinite}
html[data-event=imlek] .native-menu-button{border-color:#ffd66b99!important;position:relative}
html[data-event=imlek] .panel{border-color:#b0505a!important;box-shadow:inset 0 0 0 4px #160a0c,inset 0 0 0 5px #ffd66b33!important}

/* ===== RAMADAN & IDUL FITRI: emerald + lentera + bulan sabit ===== */
html[data-event=ramadan]{--m-bg:#07140f;--m-surface:#0f2a20;--m-surface-hi:#163a2c;--m-card-line:#2f6a54;--m-chip-line:#3f8a6e;--m-divider:#153226;--m-on:#eafaf1;--m-muted:#8fb9a5;--m-accent:#e8c872;--m-btn:#126148;--m-btn-hi:#187a5a;--m-on-btn:#f6e7b4;--m-tonal:#0f4a37;--m-on-tonal:#d6f5e5}
html[data-event=ramadan] body{background:radial-gradient(700px 400px at 85% -6%,#e8c87226,transparent 65%),var(--m-bg)!important}
html[data-event=ramadan] :is(button[type=submit],.btn){position:relative;overflow:visible;background:radial-gradient(circle at 100% 0,#e8c87255 0 20px,transparent 21px),repeating-linear-gradient(45deg,#ffffff0a 0 6px,transparent 6px 12px),linear-gradient(180deg,#16805e,#0b4130)!important;color:#f6e7b4!important;border:1px solid #e8c872!important;box-shadow:0 6px 16px -8px #16805e!important}
html[data-event=ramadan] :is(button[type=submit],.btn)::after{content:"";position:absolute;right:12px;top:-8px;width:16px;height:16px;background:#f6e7b4;-webkit-mask:var(--ic-moon) center/contain no-repeat;mask:var(--ic-moon) center/contain no-repeat;filter:drop-shadow(0 0 4px #f6e7b4aa);pointer-events:none;transform:rotate(-20deg)}
html[data-event=ramadan] .native-menu-button{border-color:#e8c87299!important}

/* ===== 17 AGUSTUS: bendera merah putih + bunting ===== */
html[data-event=kemerdekaan]{--m-bg:#140a0c;--m-surface:#241013;--m-surface-hi:#321619;--m-card-line:#6b2a30;--m-chip-line:#a04650;--m-divider:#331a1d;--m-on:#fff5f5;--m-muted:#c9a0a4;--m-accent:#ffb3b8;--m-btn:#d7202b;--m-btn-hi:#ef2e3a;--m-on-btn:#ffffff;--m-tonal:#8f121b;--m-on-tonal:#ffffff}
html[data-event=kemerdekaan] :is(button[type=submit],.btn){position:relative;overflow:visible;background:#d7202b!important;color:#fff!important;border:0!important;border-bottom:5px solid #fff!important;border-radius:10px!important;box-shadow:0 6px 16px -8px #d7202b!important}
html[data-event=kemerdekaan] :is(button[type=submit],.btn)::after{content:"";position:absolute;right:16px;top:-15px;width:18px;height:18px;border-left:2px solid #d9d9d9;background:linear-gradient(#e0222c 0 50%,#ffffff 50%) 0 0/16px 11px no-repeat;transform-origin:left center;animation:waveflag 1.6s ease-in-out infinite;pointer-events:none}
html[data-event=kemerdekaan] .native-menu-button{border-color:#ff8f98!important;border-bottom:3px solid #fff!important}
html[data-event=kemerdekaan] #evbar{height:30px;background:conic-gradient(from -25deg at 50% 100%,#e0222c 0 50deg,transparent 0) 0 0/40px 22px repeat-x,conic-gradient(from -25deg at 50% 100%,#ffffff 0 50deg,transparent 0) 20px 0/40px 22px repeat-x;filter:drop-shadow(0 2px 2px #0008)}
html[data-event=kemerdekaan] #evbar::before{content:"";position:absolute;left:0;right:0;top:-1px;height:2px;background:#cfa86a}

/* ===== HALLOWEEN: tombol meleleh + sarang laba-laba ===== */
html[data-event=halloween]{--m-bg:#0d0913;--m-surface:#1a1224;--m-surface-hi:#271a36;--m-card-line:#4a2f63;--m-chip-line:#7b4fa0;--m-divider:#2a1b3a;--m-on:#f6e9ff;--m-muted:#a995bd;--m-accent:#ff9a2e;--m-btn:#4a2370;--m-btn-hi:#5d2c8a;--m-on-btn:#ffb347;--m-tonal:#3b2150;--m-on-tonal:#ffd9a3}
html[data-event=halloween] body{background:radial-gradient(600px 400px at 90% 0,#ff8a1f22,transparent 65%),var(--m-bg)!important}
html[data-event=halloween] :is(button[type=submit],.btn,.native-menu-button){position:relative;overflow:visible}
html[data-event=halloween] :is(button[type=submit],.btn){background:linear-gradient(180deg,#6a2f9d,#38175a)!important;color:#ffb347!important;border:1px solid #ff8a1f!important;box-shadow:0 0 16px -2px #ff8a1f77,inset 0 0 10px #0008!important}
html[data-event=halloween] .native-menu-button{border-color:#ff8a1fa0!important}
html[data-event=halloween] :is(button[type=submit],.btn,.native-menu-button)::after{content:"";position:absolute;left:8px;right:8px;top:calc(100% - 2px);height:18px;pointer-events:none;transform-origin:top;animation:dripgrow 3.6s ease-in-out infinite;background:radial-gradient(ellipse 3px 9px at 14% 0,#ff8a1f 68%,transparent 72%),radial-gradient(ellipse 3px 15px at 38% 0,#ff8a1f 68%,transparent 72%),radial-gradient(ellipse 3px 7px at 61% 0,#ff8a1f 68%,transparent 72%),radial-gradient(ellipse 3px 12px at 86% 0,#ff8a1f 68%,transparent 72%)}
html[data-event=halloween] :is(button[type=submit],.btn,.native-menu-button):nth-child(even)::after{animation-delay:-1.4s}

/* ===== VALENTINE: hati berdetak ===== */
html[data-event=valentine]{--m-bg:#160a12;--m-surface:#2a1220;--m-surface-hi:#3a182c;--m-card-line:#6e2f50;--m-chip-line:#a85a82;--m-divider:#381a2a;--m-on:#ffeaf2;--m-muted:#c79ab0;--m-accent:#ff8fb1;--m-btn:#e0457a;--m-btn-hi:#f0568c;--m-on-btn:#ffffff;--m-tonal:#5c1a3a;--m-on-tonal:#ffd9e6}
html[data-event=valentine] :is(button[type=submit],.btn){position:relative;overflow:visible;background:linear-gradient(180deg,#f2609a,#d63a73)!important;color:#fff!important;border-radius:22px!important;box-shadow:0 8px 20px -8px #e0457a!important}
html[data-event=valentine] :is(button[type=submit],.btn)::after{content:"";position:absolute;right:-5px;top:-9px;width:18px;height:18px;background:#ff3d71;-webkit-mask:var(--ic-heart) center/contain no-repeat;mask:var(--ic-heart) center/contain no-repeat;filter:drop-shadow(0 0 4px #ff8fb1);animation:beat 1.4s ease-in-out infinite;pointer-events:none}
html[data-event=valentine] .native-menu-button{border-color:#ff8fb1aa!important;border-radius:20px!important}

@media (max-width:600px){#evbar .lantern.hide-s,#evbar .ribbon.hide-s{display:none}}
@media (prefers-reduced-motion:reduce){#evbar *,html[data-event] :is(button,.btn)::after{animation:none!important}}
"""

UPGRADE_JS = "<script>" + r"""(function(){
'use strict';
var LS='uabe_event',DAY=864e5;
var IMLEK=['2026-02-17','2027-02-06','2028-01-26','2029-02-13','2030-02-03','2031-01-23'];
var RAMADAN=['2026-02-18','2027-02-08','2028-01-28','2029-01-16','2030-01-05','2030-12-26','2031-12-15'];
var NAMES={natal:'Natal',tahunbaru:'Tahun Baru',imlek:'Imlek',ramadan:'Ramadan & Idul Fitri',kemerdekaan:'17 Agustus',halloween:'Halloween',valentine:'Valentine'};
function ymd(s){var a=s.split('-');return new Date(+a[0],+a[1]-1,+a[2]).getTime()}
function inWin(t,s,b,a){var x=ymd(s);return t>=x-b*DAY&&t<=x+a*DAY}
function detect(now){
  var t=new Date(now.getFullYear(),now.getMonth(),now.getDate()).getTime(),m=now.getMonth()+1,d=now.getDate(),i;
  for(i=0;i<IMLEK.length;i++)if(inWin(t,IMLEK[i],7,15))return 'imlek';
  for(i=0;i<RAMADAN.length;i++)if(inWin(t,RAMADAN[i],3,33))return 'ramadan';
  if(m===2&&d>=7&&d<=14)return 'valentine';
  if(m===8&&d>=10&&d<=18)return 'kemerdekaan';
  if((m===10&&d>=24)||(m===11&&d===1))return 'halloween';
  if(m===12&&d<=26)return 'natal';
  if((m===12&&d>=27)||(m===1&&d<=2))return 'tahunbaru';
  return '';
}
function pref(){try{return localStorage.getItem(LS)||'auto'}catch(e){return 'auto'}}
function setPref(v){try{localStorage.setItem(LS,v)}catch(e){}}
function resolve(){
  var q=/[?&]event=([a-z]+)/.exec(location.search);
  var p=q?q[1]:pref();
  if(p==='off')return '';
  if(NAMES[p])return p;
  return detect(new Date());
}
var current=resolve();
document.documentElement.setAttribute('data-event',current);
var reduce=window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches;
function el(tag,cls,css){var e=document.createElement(tag);if(cls)e.className=cls;if(css)e.style.cssText=css;return e}
function rnd(a,b){return a+Math.random()*(b-a)}
function snack(msg){
  var o=document.querySelector('.ev-toast');if(o)o.remove();
  var t=el('div','ev-toast');t.textContent=msg;document.body.appendChild(t);
  setTimeout(function(){t.remove()},4800);
}

/* ---------- dekorasi (lampu, lentera, bunting, dll) ---------- */
function teardownDeco(){var b=document.getElementById('evbar');if(b)b.remove()}
function buildDeco(ev){
  teardownDeco();
  if(!ev)return;
  var bar=el('div');bar.id='evbar';document.body.appendChild(bar);
  var h=document.querySelector('header');
  function place(){bar.style.top=(h?h.offsetHeight:64)+'px'}
  place();addEventListener('resize',place);addEventListener('load',place);setTimeout(place,300);
  var w=innerWidth,i;
  if(ev==='natal'||ev==='valentine'){
    var n=Math.max(8,Math.floor(w/32)),arcs=Math.max(2,Math.round(w/240)),pts=[],cols=ev==='natal'?['#ff4040','#ffd54a','#3bd16f','#4aa8ff']:['#ff3d71','#ff8fb1','#ffd1e0','#e0457a'];
    var d='M0 2';
    for(i=0;i<=60;i++){var u=i/60*arcs,f=u-Math.floor(u);d+=' L'+(i/60*w).toFixed(1)+' '+(2+16*Math.sin(Math.PI*f)).toFixed(1)}
    var svg=document.createElementNS('http://www.w3.org/2000/svg','svg');svg.setAttribute('viewBox','0 0 '+w+' 42');svg.setAttribute('preserveAspectRatio','none');
    var p=document.createElementNS('http://www.w3.org/2000/svg','path');p.setAttribute('d',d);p.setAttribute('fill','none');p.setAttribute('stroke',ev==='natal'?'#2e5b3f':'#7a2f50');p.setAttribute('stroke-width','2');svg.appendChild(p);bar.appendChild(svg);
    for(i=0;i<n;i++){
      var u2=(i+.5)/n*arcs,f2=u2-Math.floor(u2),y=2+16*Math.sin(Math.PI*f2);
      var b=el('span','bulb'+(ev==='valentine'?' hl':''),'left:'+((i+.5)/n*100)+'%;top:'+(y+1)+'px;--c:'+cols[i%cols.length]+';animation-delay:'+(-rnd(0,2))+'s');
      bar.appendChild(b);
    }
  }else if(ev==='tahunbaru'){
    var rc=['#f5d36b','#ff7ab6','#7ad3ff','#c9f27a','#ffffff'],rn=Math.floor(w/46);
    for(i=0;i<rn;i++)bar.appendChild(el('span','ribbon'+(i%3===0?' hide-s':''),'left:'+((i+.5)/rn*100)+'%;height:'+rnd(14,44)+'px;--c:'+rc[i%rc.length]+';animation-delay:'+(-rnd(0,3))+'s'));
  }else if(ev==='imlek'){
    var lp=w<600?[12,88]:[7,28,72,93];
    lp.forEach(function(x,k){var l=el('div','lantern','left:'+x+'%;animation-delay:'+(-k*.7)+'s');l.appendChild(el('i'));l.appendChild(el('b'));bar.appendChild(l)});
  }else if(ev==='ramadan'){
    var rp=w<600?[10]:[8,24,60];
    rp.forEach(function(x,k){var l=el('div','lantern fa','left:'+x+'%;animation-delay:'+(-k*.9)+'s');l.appendChild(el('i'));l.appendChild(el('b'));bar.appendChild(l)});
    bar.appendChild(el('span','moon'));
  }else if(ev==='halloween'){
    bar.appendChild(el('span','web l'));bar.appendChild(el('span','web r'));
    var s=el('div','spider','left:'+(w<600?72:24)+'%');s.appendChild(el('i'));s.appendChild(el('b'));bar.appendChild(s);
  }
}

/* ---------- mesin partikel ---------- */
var FX=null;
function stopFX(){if(FX){FX.stop();FX=null}}
function startFX(ev){
  stopFX();
  if(!ev||reduce)return;
  var cv=el('canvas');cv.id='evfx';document.body.appendChild(cv);
  var cx=cv.getContext('2d'),W=0,H=0,dpr=Math.min(window.devicePixelRatio||1,2),parts=[],sparks=[],raf=0,last=0,fw=0,T=0;
  function size(){W=innerWidth;H=innerHeight;cv.width=W*dpr;cv.height=H*dpr;cv.style.width=W+'px';cv.style.height=H+'px';cx.setTransform(dpr,0,0,dpr,0,0)}
  size();addEventListener('resize',size);
  var K=innerWidth<600?.6:1;
  var N=Math.round(({natal:90,imlek:10,ramadan:40,kemerdekaan:30,halloween:6,valentine:20,tahunbaru:26})[ev]*K);
  var CONF=ev==='kemerdekaan'?['#e0222c','#ffffff']:['#f5d36b','#ff7ab6','#7ad3ff','#c9f27a','#ffffff'];
  function mk(init){
    var p={x:rnd(0,W),ph:rnd(0,6.28),a:rnd(.5,.95)};
    if(ev==='natal'){p.r=rnd(1,3.6);p.y=init?rnd(0,H):-8;p.vy=rnd(22,60)*(p.r/2.4)}
    else if(ev==='imlek'){p.s=rnd(14,24);p.y=init?rnd(0,H):H+40;p.vy=-rnd(14,32)}
    else if(ev==='ramadan'){p.y=rnd(0,H);p.r=rnd(5,11);p.tw=rnd(.6,1.6)}
    else if(ev==='kemerdekaan'||ev==='tahunbaru'){p.y=init?rnd(0,H):-10;p.w=rnd(4,8);p.h=rnd(2,4.5);p.rot=rnd(0,6.28);p.vr=rnd(-4,4);p.vy=rnd(40,90);p.c=CONF[Math.floor(rnd(0,CONF.length))]}
    else if(ev==='halloween'){p.dir=Math.random()<.5?1:-1;p.x=p.dir>0?-40:W+40;p.y=rnd(90,H*.6);p.sp=rnd(50,110);p.s=rnd(.8,1.4)}
    else if(ev==='valentine'){p.s=rnd(5,10);p.y=init?rnd(0,H):H+20;p.vy=-rnd(20,48)}
    return p;
  }
  for(var i=0;i<N;i++)parts.push(mk(true));
  function rr(x,y,w,h,r){cx.beginPath();if(cx.roundRect)cx.roundRect(x,y,w,h,r);else cx.rect(x,y,w,h)}
  function star(x,y,r){cx.beginPath();cx.moveTo(x,y-r);cx.quadraticCurveTo(x,y,x+r,y);cx.quadraticCurveTo(x,y,x,y+r);cx.quadraticCurveTo(x,y,x-r,y);cx.quadraticCurveTo(x,y,x,y-r);cx.closePath()}
  function heart(x,y,s){cx.beginPath();cx.moveTo(x,y+s*.3);cx.bezierCurveTo(x,y-s*.3,x-s,y-s*.3,x-s,y+s*.2);cx.bezierCurveTo(x-s,y+s*.7,x,y+s*.9,x,y+s*1.2);cx.bezierCurveTo(x,y+s*.9,x+s,y+s*.7,x+s,y+s*.2);cx.bezierCurveTo(x+s,y-s*.3,x,y-s*.3,x,y+s*.3);cx.closePath()}
  function bat(x,y,s,f){cx.save();cx.translate(x,y);cx.scale(s,s);cx.fillStyle='#1d1230';cx.strokeStyle='#b57cff';cx.lineWidth=1.2;cx.beginPath();cx.moveTo(0,-2);cx.lineTo(-3,-8);cx.lineTo(-1,-4);cx.lineTo(1,-4);cx.lineTo(3,-8);cx.lineTo(0,-2);cx.moveTo(0,0);cx.bezierCurveTo(8,-10*f-4,20,-8*f-2,28,-2*f);cx.bezierCurveTo(24,6,18,4,14,10);cx.bezierCurveTo(10,5,6,8,0,6);cx.bezierCurveTo(-6,8,-10,5,-14,10);cx.bezierCurveTo(-18,4,-24,6,-28,-2*f);cx.bezierCurveTo(-20,-8*f-2,-8,-10*f-4,0,0);cx.fill();cx.stroke();cx.restore()}
  function burst(x,y,big){
    var n=big?64:(ev==='natal'?22:ev==='tahunbaru'?46:26),cols,shape,g=110,sp=[80,230];
    if(ev==='natal'){cols=['#ffffff','#bfe6ff','#86c8f2'];shape='shard'}
    else if(ev==='tahunbaru'){cols=['#f5d36b','#ff7ab6','#7ad3ff','#ffffff'];shape='dot';g=90;sp=[110,280]}
    else if(ev==='imlek'){cols=['#ffd66b','#ff5a4f','#ffe9a3'];shape='coin'}
    else if(ev==='ramadan'){cols=['#f6e7b4','#e8c872','#ffffff'];shape='star'}
    else if(ev==='kemerdekaan'){cols=['#e0222c','#ffffff'];shape='rect'}
    else if(ev==='halloween'){cols=['#ff8a1f','#b57cff','#ffd9a3'];shape='dot'}
    else{cols=['#ff3d71','#ff8fb1','#ffd1e0'];shape='heart';g=-30}
    for(var i=0;i<n;i++){var a=rnd(0,6.283),v=rnd(sp[0],sp[1]);sparks.push({x:x,y:y,vx:Math.cos(a)*v,vy:Math.sin(a)*v-(shape==='heart'?40:0),g:g,life:0,max:rnd(.7,1.3),c:cols[i%cols.length],shape:shape,s:rnd(2,5),rot:rnd(0,6.28)})}
  }
  function frame(ts){
    raf=requestAnimationFrame(frame);
    if(document.hidden){last=0;return}
    var dt=last?Math.min((ts-last)/1000,.05):.016;last=ts;T+=dt;
    cx.clearRect(0,0,W,H);
    for(var i=0;i<parts.length;i++){
      var p=parts[i];
      if(ev==='natal'){p.y+=p.vy*dt;p.x+=Math.sin(T*.8+p.ph)*18*dt;if(p.y>H+8)parts[i]=mk(false);cx.fillStyle='rgba(255,255,255,'+p.a+')';cx.beginPath();cx.arc(p.x,p.y,p.r,0,6.283);cx.fill()}
      else if(ev==='imlek'){p.y+=p.vy*dt;p.x+=Math.sin(T*.6+p.ph)*14*dt;if(p.y<-50)parts[i]=mk(false);var s=p.s;cx.save();cx.translate(p.x,p.y);cx.globalAlpha=.8;cx.shadowColor='#ff3b30';cx.shadowBlur=18;cx.fillStyle='#e0262d';rr(-s*.5,-s*.62,s,s*1.24,s*.35);cx.fill();cx.shadowBlur=0;cx.fillStyle='#ffd66b';cx.fillRect(-s*.22,-s*.72,s*.44,s*.12);cx.fillRect(-s*.22,s*.6,s*.44,s*.12);cx.restore()}
      else if(ev==='ramadan'){var al=.3+.7*Math.abs(Math.sin(T*p.tw+p.ph));cx.fillStyle='rgba(246,231,180,'+al+')';star(p.x,p.y,p.r*(.5+al*.5))}
      else if(ev==='kemerdekaan'||ev==='tahunbaru'){p.y+=p.vy*dt;p.x+=Math.sin(T+p.ph)*20*dt;p.rot+=p.vr*dt;if(p.y>H+10)parts[i]=mk(false);cx.save();cx.translate(p.x,p.y);cx.rotate(p.rot);cx.fillStyle=p.c;cx.globalAlpha=.85;cx.fillRect(-p.w/2,-p.h/2,p.w,p.h);cx.restore()}
      else if(ev==='halloween'){p.x+=p.dir*p.sp*dt;p.y+=Math.sin(T*2+p.ph)*30*dt;if((p.dir>0&&p.x>W+50)||(p.dir<0&&p.x<-50))parts[i]=mk(false);bat(p.x,p.y,p.s,Math.sin(T*10+p.ph))}
      else if(ev==='valentine'){p.y+=p.vy*dt;p.x+=Math.sin(T*.9+p.ph)*16*dt;if(p.y<-30)parts[i]=mk(false);cx.fillStyle='rgba(255,100,150,'+(p.a*.7)+')';heart(p.x,p.y,p.s);cx.fill()}
    }
    if(ev==='tahunbaru'){fw-=dt;if(fw<=0){fw=rnd(1.2,2.4);burst(rnd(W*.15,W*.85),rnd(H*.12,H*.5),true)}}
    cx.globalCompositeOperation=ev==='tahunbaru'?'lighter':'source-over';
    for(var j=sparks.length-1;j>=0;j--){
      var s2=sparks[j];s2.life+=dt;if(s2.life>s2.max){sparks.splice(j,1);continue}
      s2.vy+=s2.g*dt;s2.vx*=.985;s2.x+=s2.vx*dt;s2.y+=s2.vy*dt;s2.rot+=dt*5;
      var k=1-s2.life/s2.max;cx.globalAlpha=Math.max(k,0);cx.fillStyle=s2.c;cx.strokeStyle=s2.c;
      if(s2.shape==='dot'){cx.beginPath();cx.arc(s2.x,s2.y,s2.s*.7,0,6.283);cx.fill()}
      else if(s2.shape==='shard'){cx.save();cx.translate(s2.x,s2.y);cx.rotate(s2.rot);cx.fillRect(-s2.s,-.8,s2.s*2,1.6);cx.fillRect(-.8,-s2.s,1.6,s2.s*2);cx.restore()}
      else if(s2.shape==='coin'){cx.beginPath();cx.arc(s2.x,s2.y,s2.s,0,6.283);cx.fill()}
      else if(s2.shape==='star'){star(s2.x,s2.y,s2.s*1.6);cx.fill()}
      else if(s2.shape==='rect'){cx.save();cx.translate(s2.x,s2.y);cx.rotate(s2.rot);cx.fillRect(-s2.s,-s2.s/2,s2.s*2,s2.s);cx.restore()}
      else{heart(s2.x,s2.y,s2.s*1.4);cx.fill()}
    }
    cx.globalAlpha=1;cx.globalCompositeOperation='source-over';
  }
  raf=requestAnimationFrame(frame);
  FX={stop:function(){cancelAnimationFrame(raf);removeEventListener('resize',size);cv.remove()},burst:function(x,y){burst(x,y,false)}};
}

/* ---------- app bar + menu ---------- */
var menu=null;
function buildAppBar(){
  var h=document.querySelector('header');
  if(!h||h.querySelector('.appbar-actions'))return;
  var logo=h.querySelector('.logo');
  if(logo){var tx=logo.textContent.trim();if(tx&&tx===tx.toUpperCase())logo.textContent=tx.toLowerCase().replace(/(^|\s)\S/g,function(c){return c.toUpperCase()})}
  var logout=h.querySelector('form[action="/logout"]');
  var box=el('div','appbar-actions');
  var up=document.getElementById('upload-panel');
  if(up){
    var f=up.querySelector('input[type=file]'),bk=el('button','appbar-btn');bk.type='button';bk.textContent='Buka';
    bk.onclick=function(){up.scrollIntoView({behavior:'smooth',block:'center'});if(f)f.click()};
    if(f)f.addEventListener('change',function(){
      var sub=up.querySelector('button[type=submit]');
      if(f.files&&f.files[0]){snack('Terpilih: '+f.files[0].name+'. Tekan Analyze Bundle untuk membuka.');if(sub){sub.classList.remove('pulse-attn');void sub.offsetWidth;sub.classList.add('pulse-attn')}}
    });
    box.appendChild(bk);
  }
  var kb=el('button','appbar-icon');kb.type='button';kb.setAttribute('aria-label','Menu lainnya');
  box.appendChild(kb);h.appendChild(box);
  menu=el('div','appmenu');document.body.appendChild(menu);
  function item(label,on,fn,extra){
    var b=el('button','appmenu-item'+(on?' on':''));b.type='button';
    b.appendChild(el('span','ck'));var s=el('span');s.textContent=label;b.appendChild(s);
    if(extra){var sm=el('small');sm.textContent=extra;b.appendChild(sm)}
    b.onclick=fn;return b;
  }
  function render(){
    menu.innerHTML='';
    var pf=pref(),auto=detect(new Date());
    var hd=el('div','appmenu-h');hd.textContent='Tema event';menu.appendChild(hd);
    menu.appendChild(item('Otomatis',pf==='auto',function(){choose('auto')},auto?NAMES[auto]:'tidak ada event'));
    Object.keys(NAMES).forEach(function(k){menu.appendChild(item(NAMES[k],pf===k,function(){choose(k)}))});
    menu.appendChild(item('Matikan efek',pf==='off',function(){choose('off')}));
    if(logout){
      menu.appendChild(document.createElement('hr'));
      var un=(logout.textContent||'').split('·')[1];
      menu.appendChild(item('Logout'+(un?' · '+un.trim():''),false,function(){logout.requestSubmit?logout.requestSubmit():logout.submit()}));
    }
  }
  function place(){menu.style.top=(h.offsetHeight-4)+'px'}
  kb.onclick=function(e){e.stopPropagation();render();place();menu.classList.toggle('open')};
  document.addEventListener('click',function(e){if(!menu.contains(e.target))menu.classList.remove('open')});
  addEventListener('resize',place);
}
function apply(ev){
  current=ev;document.documentElement.setAttribute('data-event',ev);
  buildDeco(ev);startFX(ev);
}
function greeting(ev){
  var y=new Date().getFullYear(),m={natal:'Selamat Natal! Tombol-tombolnya lagi membeku.',tahunbaru:'Selamat Tahun Baru '+(new Date().getMonth()===0?y:y+1)+'! Klik tombol untuk kembang api.',imlek:'Gong Xi Fa Cai! Selamat Tahun Baru Imlek.',ramadan:'Ramadan Kareem. Selamat Idul Fitri bagi yang merayakan.',kemerdekaan:'Dirgahayu Republik Indonesia ke-'+(y-1945)+'! Merdeka!',halloween:'Happy Halloween! Awas kelelawar.',valentine:"Happy Valentine's Day!"}[ev];
  if(!m)return;
  var key='uabe_greet_'+ev+'_'+new Date().toDateString();
  try{if(sessionStorage.getItem(key))return;sessionStorage.setItem(key,'1')}catch(e){}
  snack(m);
}
function choose(v){
  setPref(v);
  var ev=v==='auto'?detect(new Date()):(v==='off'?'':v);
  apply(ev);greeting(ev);
  if(menu)menu.classList.remove('open');
}

function ready(f){document.readyState!=='loading'?f():document.addEventListener('DOMContentLoaded',f)}
ready(function(){
  /* kartu kosong + chip seperti aplikasi Android */
  var up=document.getElementById('upload-panel');
  if(up&&!document.getElementById('explorer-panel')){
    var card=el('div','panel empty-card');
    card.innerHTML='<p class="empty-title">Buka bundel untuk memulai.</p><p class="empty-tip">Tip: pilih game, unggah bundle, lalu pakai tombol aksi di tiap item untuk ekspor/impor.</p>';
    var chips=el('div','asset-controls empty-chips');
    [['Filter',''],['Menyortir','chip-sort']].forEach(function(c){
      var w=el('div','dropdown-wrap'),b=el('button','native-menu-button '+c[1]);b.type='button';
      b.innerHTML=c[0]+' <span class="menu-icon"></span>';
      b.onclick=function(){snack('Buka bundel dulu untuk memakai '+c[0].toLowerCase()+'.')};
      w.appendChild(b);chips.appendChild(w);
    });
    up.parentNode.insertBefore(card,up);up.parentNode.insertBefore(chips,up);
  }
  buildAppBar();
  document.querySelectorAll('.panel').forEach(function(e,i){e.style.setProperty('--i',Math.min(i,6))});
  document.querySelectorAll('.sidebar>*').forEach(function(e,i){e.style.setProperty('--i',i)});
  var path=location.pathname.replace(/\/$/,'')||'/';
  document.querySelectorAll('.sidebar a[href^="/"]').forEach(function(a){
    var hh=a.getAttribute('href').split('?')[0].replace(/\/$/,'')||'/';
    if(hh===path||(hh==='/dashboard'&&path==='/'))a.classList.add('active');
  });
  apply(current);
  if(current)setTimeout(function(){greeting(current)},700);
  document.addEventListener('pointerdown',function(e){
    if(FX&&e.target.closest&&e.target.closest('button,.btn,.action-group a,.native-menu-button'))FX.burst(e.clientX,e.clientY);
  },true);
  if(reduce)return;
  document.querySelectorAll('.stat b').forEach(function(b){
    var t=b.textContent.trim();if(!/^\d[\d.,]*$/.test(t))return;
    var n=parseFloat(t.replace(/,/g,''));if(!isFinite(n)||n<2||n>1e9)return;
    var dec=(t.split('.')[1]||'').length,t0=null;
    function step(ts){if(!t0)t0=ts;var p=Math.min((ts-t0)/900,1),e=p===1?1:1-Math.pow(2,-10*p),v=n*e;
      b.textContent=dec?v.toFixed(dec):Math.round(v).toLocaleString('en-US').replace(/,/g,t.indexOf(',')>-1?',':'');
      if(p<1)requestAnimationFrame(step);else b.textContent=t}
    b.textContent='0';requestAnimationFrame(step);
  });
  document.querySelectorAll('tbody').forEach(function(tb){var r=tb.rows;for(var i=0;i<r.length&&i<28;i++){r[i].classList.add('row-in');r[i].style.setProperty('--r',i)}});
  if('IntersectionObserver' in window){
    var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('rv-in');io.unobserve(e.target)}})},{threshold:.08});
    document.querySelectorAll('.panel').forEach(function(e){if(e.getBoundingClientRect().top>innerHeight*.9){e.classList.add('rv');io.observe(e)}});
  }
});
})();
""" + "</script>"

@app.after_request
def apply_premium_theme(resp):
    try:
        if (resp.mimetype == "text/html" and resp.status_code == 200
                and not resp.direct_passthrough):
            body = resp.get_data(as_text=True)
            if "</head>" in body and "premium-theme" not in body:
                body = body.replace(
                    "</head>", '<style id="premium-theme">' + PREMIUM_CSS + UPGRADE_CSS + "</style>" + MENU_JS + UPGRADE_JS + "</head>", 1)
                resp.set_data(body)
    except Exception:
        pass
    return resp

sessions = {}

import base64 as _template_base64
_HTML_B64 = 'CjwhRE9DVFlQRSBodG1sPgo8aHRtbCBsYW5nPSJpZCI+CjxoZWFkPgo8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CjxtZXRhIG5hbWU9InZpZXdwb3J0IiBjb250ZW50PSJ3aWR0aD1kZXZpY2Utd2lkdGgsaW5pdGlhbC1zY2FsZT0xIj4KPHRpdGxlPkhhblppaGFuIE1vYmEgfCBTYWt1cmEgSmFwYW5lc2UgV29ya3NwYWNlPC90aXRsZT4KCjxzdHlsZT4KOnJvb3QgewogLS1iZzojMDgwOTBkOwogLS1wYW5lbDojMTExMzFhOwogLS1wYW5lbDI6IzE3MTkyMzsKIC0tcmVkOiNmMDJiNDg7CiAtLXJlZDI6IzhlMTQyYjsKIC0tbGluZTojMjkyZDM5OwogLS1tdXRlZDojODU4YjliOwp9Cip7Ym94LXNpemluZzpib3JkZXItYm94fQpodG1se3Njcm9sbC1iZWhhdmlvcjpzbW9vdGh9CmJvZHl7CiBtYXJnaW46MDsKIG1pbi13aWR0aDowOwogYmFja2dyb3VuZDp2YXIoLS1iZyk7CiBjb2xvcjojZjNmM2Y3OwogZm9udC1mYW1pbHk6SW50ZXIsQXJpYWwsc2Fucy1zZXJpZjsKIG92ZXJmbG93LXg6aGlkZGVuOwp9CmhlYWRlcnsKIHBvc2l0aW9uOmZpeGVkOwogei1pbmRleDoyMDsKIHRvcDowOwogbGVmdDoyNTBweDsKIHJpZ2h0OjA7CiBoZWlnaHQ6ODJweDsKIHBhZGRpbmc6MTdweCAzMnB4OwogZGlzcGxheTpmbGV4OwogYWxpZ24taXRlbXM6Y2VudGVyOwoganVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47CiBiYWNrZ3JvdW5kOiMxMDExMTk7CiBib3JkZXItYm90dG9tOjFweCBzb2xpZCB2YXIoLS1saW5lKTsKfQoubG9nb3sKIGZvbnQtc2l6ZToyNXB4OwogZm9udC13ZWlnaHQ6OTUwOwogbGV0dGVyLXNwYWNpbmc6MnB4OwogY29sb3I6I2ZmMzA0ZTsKfQouc3ViewogbWFyZ2luLXRvcDo1cHg7CiBmb250LXNpemU6MTBweDsKIGNvbG9yOiM5Mjk2YTU7CiBsZXR0ZXItc3BhY2luZzozcHg7Cn0KaGVhZGVyOmFmdGVyewogY29udGVudDoiREVTS1RPUCBXT1JLU1BBQ0UiOwogY29sb3I6Izc3N2Q4ZTsKIGZvbnQtc2l6ZToxMHB4OwogbGV0dGVyLXNwYWNpbmc6MnB4Owp9Ci5zaWRlYmFyewogcG9zaXRpb246Zml4ZWQ7CiB6LWluZGV4OjMwOwogdG9wOjA7CiBib3R0b206MDsKIGxlZnQ6MDsKIHdpZHRoOjI1MHB4OwogcGFkZGluZzoyNXB4IDE2cHg7CiBiYWNrZ3JvdW5kOiMwZTEwMTc7CiBib3JkZXItcmlnaHQ6MXB4IHNvbGlkIHZhcigtLWxpbmUpOwp9Ci5zaWRlLWJyYW5kewogcGFkZGluZzo4cHggMTJweCAyOHB4OwogYm9yZGVyLWJvdHRvbToxcHggc29saWQgdmFyKC0tbGluZSk7CiBtYXJnaW4tYm90dG9tOjI1cHg7Cn0KLnNpZGUtYnJhbmQgc3Ryb25newogZGlzcGxheTpibG9jazsKIGZvbnQtc2l6ZToxNnB4OwogY29sb3I6I2ZmMzA0ZTsKIGxldHRlci1zcGFjaW5nOjFweDsKfQouc2lkZS1icmFuZCBzbWFsbHsKIGRpc3BsYXk6YmxvY2s7CiBtYXJnaW4tdG9wOjdweDsKIGNvbG9yOiM3NDdiOGQ7CiBmb250LXNpemU6OXB4OwogbGV0dGVyLXNwYWNpbmc6MnB4Owp9Ci5uYXYtbGFiZWx7CiBwYWRkaW5nOjEwcHggMTJweDsKIGNvbG9yOiM2NDZiN2I7CiBmb250LXNpemU6MTBweDsKIGxldHRlci1zcGFjaW5nOjJweDsKIGZvbnQtd2VpZ2h0OmJvbGQ7Cn0KLnNpZGViYXIgYXsKIGRpc3BsYXk6YmxvY2s7CiBtYXJnaW46NXB4IDA7CiBwYWRkaW5nOjEzcHggMTRweDsKIGNvbG9yOiNhZWIzYzA7CiB0ZXh0LWRlY29yYXRpb246bm9uZTsKIGZvbnQtc2l6ZToxM3B4OwogYm9yZGVyLXJhZGl1czo3cHg7CiBib3JkZXI6MXB4IHNvbGlkIHRyYW5zcGFyZW50OwogdHJhbnNpdGlvbjouMnM7Cn0KLnNpZGViYXIgYTpob3ZlcnsKIGNvbG9yOndoaXRlOwogYmFja2dyb3VuZDojMjExMzFhOwogYm9yZGVyLWNvbG9yOiM2OTIwMzM7Cn0KLnNpZGViYXIgYSBzcGFuewogZGlzcGxheTppbmxpbmUtYmxvY2s7CiB3aWR0aDoyN3B4OwogY29sb3I6I2ZmNDA1YjsKfQouc2lkZS1zdGF0dXN7CiBwb3NpdGlvbjphYnNvbHV0ZTsKIGxlZnQ6MTZweDsKIHJpZ2h0OjE2cHg7CiBib3R0b206MjJweDsKIHBhZGRpbmc6MTRweDsKIGJvcmRlcjoxcHggc29saWQgIzI5MzUyZTsKIGJhY2tncm91bmQ6IzEwMWExNjsKIGJvcmRlci1yYWRpdXM6OHB4OwogY29sb3I6IzliZTNiMDsKIGZvbnQtc2l6ZToxMXB4Owp9Cm1haW57CiB3aWR0aDpjYWxjKDEwMCUgLSAyNTBweCk7CiBtYXJnaW4tbGVmdDoyNTBweDsKIG1hcmdpbi10b3A6ODJweDsKIHBhZGRpbmc6MzBweDsKIGRpc3BsYXk6Z3JpZDsKIGdyaWQtdGVtcGxhdGUtY29sdW1uczptaW5tYXgoMCwxLjVmcikgbWlubWF4KDMwMHB4LC44ZnIpOwogZ2FwOjE4cHg7CiBhbGlnbi1pdGVtczpzdGFydDsKfQoucGFuZWx7CiBtaW4td2lkdGg6MDsKIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE0NWRlZywjMTUxNzIxLCMxMDExMTcpOwogYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsKIGJvcmRlci1yYWRpdXM6MTFweDsKIHBhZGRpbmc6MjJweDsKIG1hcmdpbjowOwogYm94LXNoYWRvdzowIDhweCAzMHB4ICMwMDA1Owp9Ci5wYW5lbCBoMnsKIG1hcmdpbjowIDAgMThweDsKIHBhZGRpbmctYm90dG9tOjEzcHg7CiBib3JkZXItYm90dG9tOjFweCBzb2xpZCAjMmIyZTNhOwogY29sb3I6I2ZmNDA1YjsKIGZvbnQtc2l6ZToxNHB4OwogbGV0dGVyLXNwYWNpbmc6MS41cHg7Cn0KI3VwbG9hZC1wYW5lbCwjaW5mby1wYW5lbCwjZXhwbG9yZXItcGFuZWwsI3Rvb2xzLXBhbmVsewogZ3JpZC1jb2x1bW46MS8tMTsKfQojc3VtbWFyeS1wYW5lbHtncmlkLWNvbHVtbjoyfQojbWVzaC1wYW5lbHtncmlkLWNvbHVtbjoxfQojdGV4dHVyZS1wYW5lbHtncmlkLWNvbHVtbjoyfQpidXR0b24sLmJ0bnsKIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEyMGRlZywjZWQyMzQ0LCM5NDE0MmQpOwogY29sb3I6d2hpdGU7CiBib3JkZXI6MXB4IHNvbGlkICNmZjQwNWI7CiBib3JkZXItcmFkaXVzOjZweDsKIHBhZGRpbmc6MTJweCAxOXB4OwogZm9udC13ZWlnaHQ6ODAwOwogZm9udC1zaXplOjExcHg7CiBsZXR0ZXItc3BhY2luZzoxcHg7CiBjdXJzb3I6cG9pbnRlcjsKIHRleHQtZGVjb3JhdGlvbjpub25lOwogZGlzcGxheTppbmxpbmUtYmxvY2s7CiB0cmFuc2l0aW9uOi4yczsKfQpidXR0b246aG92ZXIsLmJ0bjpob3ZlcnsKIGZpbHRlcjpicmlnaHRuZXNzKDEuMik7CiB0cmFuc2Zvcm06dHJhbnNsYXRlWSgtMXB4KTsKfQppbnB1dFt0eXBlPWZpbGVdLGlucHV0W3R5cGU9c2VhcmNoXXsKIHdpZHRoOjEwMCU7CiBwYWRkaW5nOjE0cHg7CiBiYWNrZ3JvdW5kOiMwOTBhMTA7CiBib3JkZXI6MXB4IHNvbGlkICMzNTM5NDg7CiBjb2xvcjp3aGl0ZTsKIGJvcmRlci1yYWRpdXM6NnB4OwogbWFyZ2luOjEwcHggMDsKfQppbnB1dDpmb2N1c3sKIG91dGxpbmU6bm9uZTsKIGJvcmRlci1jb2xvcjojZTgzMjUwOwp9Ci5zdGF0c3sKIGRpc3BsYXk6Z3JpZDsKIGdyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMixtaW5tYXgoMCwxZnIpKTsKIGdhcDoxMnB4Owp9Ci5zdGF0ewogYmFja2dyb3VuZDojMWExYzI3OwogYm9yZGVyOjFweCBzb2xpZCAjMzAzMzQxOwogcGFkZGluZzoxOHB4OwogYm9yZGVyLXJhZGl1czo4cHg7Cn0KLnN0YXQgYnsKIGZvbnQtc2l6ZToyN3B4OwogY29sb3I6I2ZmNDA1YjsKIGRpc3BsYXk6YmxvY2s7CiBtYXJnaW4tYm90dG9tOjVweDsKfQpzbWFsbCwubXV0ZWR7Y29sb3I6dmFyKC0tbXV0ZWQpfQp0YWJsZXsKIHdpZHRoOjEwMCU7CiBib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7CiBmb250LXNpemU6MTJweDsKfQp0aCx0ZHsKIHRleHQtYWxpZ246bGVmdDsKIHBhZGRpbmc6MTRweCAxMXB4OwogYm9yZGVyLWJvdHRvbToxcHggc29saWQgIzI5MmMzNzsKfQp0aHsKIGNvbG9yOiNmZjUyNmI7CiBiYWNrZ3JvdW5kOiMxOTFiMjU7CiBsZXR0ZXItc3BhY2luZzoxcHg7CiBwb3NpdGlvbjpzdGlja3k7CiB0b3A6MDsKfQp0Ym9keSB0cjpob3ZlcntiYWNrZ3JvdW5kOiMyMDE1MWN9Ci5zY3JvbGx7CiBvdmVyZmxvdzphdXRvOwogbWF4LWhlaWdodDo2NTBweDsKIGJvcmRlcjoxcHggc29saWQgIzI5MmMzNzsKIGJvcmRlci1yYWRpdXM6N3B4Owp9Ci50YWd7Y29sb3I6I2ZmNjk3Zn0KYXtjb2xvcjojZmY2NDc3fQoubm90aWNlewogcGFkZGluZzoxM3B4OwogYmFja2dyb3VuZDojMjgxOTFmOwogYm9yZGVyOjFweCBzb2xpZCAjNjEyNTM2OwogYm9yZGVyLXJhZGl1czo3cHg7CiBtYXJnaW46MTJweCAwOwogZ3JpZC1jb2x1bW46MS8tMTsKfQojdXBsb2FkLXBhbmVsIGZvcm17bWF4LXdpZHRoOjc1MHB4fQojdG9vbHMtcGFuZWwgcHtkaXNwbGF5OmlubGluZS1ibG9jazttYXJnaW4tcmlnaHQ6MzVweH0KQG1lZGlhKG1heC13aWR0aDoxMTAwcHgpewogYm9keXttaW4td2lkdGg6MTEwMHB4fQp9CgovKiBIQU5aSUhBTiBNT0JBIE1PQklMRSBERVNLVE9QIE1PREUgKi8KLm1lbnUtdG9nZ2xlewogZGlzcGxheTpub25lOwogYmFja2dyb3VuZDojZDUxZjM1OwogY29sb3I6d2hpdGU7CiBib3JkZXI6MDsKIGJvcmRlci1yYWRpdXM6NnB4OwogcGFkZGluZzoxMHB4IDEzcHg7CiBmb250LXdlaWdodDpib2xkOwp9Ci5jYXRlZ29yeS1saW5rewogZGlzcGxheTpibG9jazsKIHBhZGRpbmc6MTFweCAxMnB4OwogbWFyZ2luOjRweCAwOwogYm9yZGVyOjFweCBzb2xpZCB0cmFuc3BhcmVudDsKIGJvcmRlci1yYWRpdXM6N3B4OwogY29sb3I6I2I5YmRjOTsKIHRleHQtZGVjb3JhdGlvbjpub25lOwogZm9udC1zaXplOjEycHg7Cn0KLmNhdGVnb3J5LWxpbms6aG92ZXJ7CiBiYWNrZ3JvdW5kOiMyNTEzMWE7CiBib3JkZXItY29sb3I6Izc2MjUzYTsKIGNvbG9yOndoaXRlOwp9Ci5jYXRlZ29yeS1saW5rIHNwYW57CiBkaXNwbGF5OmlubGluZS1ibG9jazsKIHdpZHRoOjI3cHg7CiBjb2xvcjojZmY0MDViOwogZm9udC13ZWlnaHQ6Ym9sZDsKfQpAbWVkaWEobWF4LXdpZHRoOjc2MHB4KXsKIGhlYWRlcnsKICBsZWZ0OjA7CiAgaGVpZ2h0OjcwcHg7CiAgcGFkZGluZzoxMHB4IDE0cHg7CiB9CiBoZWFkZXI6YWZ0ZXJ7ZGlzcGxheTpub25lfQogLmxvZ297Zm9udC1zaXplOjE3cHg7bGV0dGVyLXNwYWNpbmc6MXB4fQogLnN1Yntmb250LXNpemU6OHB4O2xldHRlci1zcGFjaW5nOjEuNXB4fQogLm1lbnUtdG9nZ2xle2Rpc3BsYXk6YmxvY2t9CiAuc2lkZWJhcnsKICB3aWR0aDoyNDVweDsKICB0b3A6NzBweDsKICB0cmFuc2Zvcm06dHJhbnNsYXRlWCgtMTA1JSk7CiAgdHJhbnNpdGlvbjp0cmFuc2Zvcm0gLjIycyBlYXNlOwogIGJveC1zaGFkb3c6MTBweCAwIDMwcHggIzAwMDk7CiAgb3ZlcmZsb3cteTphdXRvOwogIHBhZGRpbmctYm90dG9tOjg1cHg7CiB9CiBib2R5LnNpZGViYXItb3BlbiAuc2lkZWJhcnsKICB0cmFuc2Zvcm06dHJhbnNsYXRlWCgwKTsKIH0KIG1haW57CiAgd2lkdGg6MTAwJTsKICBtYXJnaW46NzBweCAwIDA7CiAgcGFkZGluZzoxM3B4OwogIGRpc3BsYXk6ZmxleDsKICBmbGV4LWRpcmVjdGlvbjpjb2x1bW47CiAgZ2FwOjEzcHg7CiB9CiBtYWluPi5wYW5lbHt3aWR0aDoxMDAlfQogLnBhbmVse3BhZGRpbmc6MTVweH0KIC5zdGF0c3tncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsbWlubWF4KDAsMWZyKSl9CiAuc3RhdHtwYWRkaW5nOjEzcHh9CiAuc3RhdCBie2ZvbnQtc2l6ZToyMnB4fQogdGFibGV7bWluLXdpZHRoOjY1MHB4fQogLnNjcm9sbHttYXgtd2lkdGg6MTAwJX0KfQoKCi5hc3NldC1jb250cm9sc3tkaXNwbGF5OmZsZXg7YWxpZ24taXRlbXM6Y2VudGVyO2dhcDoxMnB4O2ZsZXgtd3JhcDp3cmFwO21hcmdpbjoxNHB4IDB9Ci5kcm9wZG93bi13cmFwe3Bvc2l0aW9uOnJlbGF0aXZlfQoubmF0aXZlLW1lbnUtYnV0dG9uewogZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTRweDttaW4taGVpZ2h0OjQ1cHg7CiBwYWRkaW5nOjlweCAxN3B4O2JhY2tncm91bmQ6IzIwMjMyYjtjb2xvcjojZWVlOwogYm9yZGVyOjFweCBzb2xpZCAjODU4NThlO2JvcmRlci1yYWRpdXM6OXB4OwogZm9udC1zaXplOjE1cHg7Zm9udC13ZWlnaHQ6NzAwO2xldHRlci1zcGFjaW5nOjAKfQoubWVudS1pY29ue2ZvbnQtc2l6ZToxOHB4O2NvbG9yOiNjY2N9Ci5uYXRpdmUtZHJvcGRvd257CiBkaXNwbGF5Om5vbmU7cG9zaXRpb246YWJzb2x1dGU7ei1pbmRleDoxMDA7dG9wOmNhbGMoMTAwJSArIDdweCk7bGVmdDowOwogbWluLXdpZHRoOjI0NXB4O21heC13aWR0aDo4NXZ3O21heC1oZWlnaHQ6NjV2aDtvdmVyZmxvdy15OmF1dG87CiBwYWRkaW5nOjdweCAwO2JhY2tncm91bmQ6IzI5MmMzNDtib3JkZXI6MXB4IHNvbGlkICM0MTQ0NGU7CiBib3JkZXItcmFkaXVzOjlweDtib3gtc2hhZG93OjAgMTJweCAyOHB4ICMwMDBhCn0KLm5hdGl2ZS1kcm9wZG93bi5vcGVue2Rpc3BsYXk6YmxvY2t9Ci5kcm9wZG93bi1vcHRpb257CiBkaXNwbGF5OmJsb2NrO3dpZHRoOjEwMCU7cGFkZGluZzoxM3B4IDE2cHg7dGV4dC1hbGlnbjpsZWZ0OwogYmFja2dyb3VuZDp0cmFuc3BhcmVudDtjb2xvcjojZWVlO2JvcmRlcjowO2JvcmRlci1yYWRpdXM6MDsKIGZvbnQtc2l6ZToxNnB4O2ZvbnQtd2VpZ2h0OjQwMDtsZXR0ZXItc3BhY2luZzowCn0KLmRyb3Bkb3duLW9wdGlvbjpob3ZlciwuZHJvcGRvd24tb3B0aW9uLmFjdGl2ZXsKIGJhY2tncm91bmQ6IzQxNDU1MDtjb2xvcjp3aGl0ZTt0cmFuc2Zvcm06bm9uZQp9Ci5hc3NldC1jb3VudHttYXJnaW4tbGVmdDphdXRvO2NvbG9yOiM5OTk7Zm9udC1zaXplOjEycHh9CkBtZWRpYShtYXgtd2lkdGg6NzYwcHgpewogLmFzc2V0LWNvbnRyb2xze2dhcDo5cHh9CiAubmF0aXZlLWRyb3Bkb3due21pbi13aWR0aDoyMjBweH0KIC5kcm9wZG93bi1vcHRpb257cGFkZGluZzoxNHB4IDE2cHh9Cn0KCi5hY3Rpb24tY2VsbHttaW4td2lkdGg6MjIwcHh9Ci5hY3Rpb24tZ3JvdXB7ZGlzcGxheTpmbGV4O2ZsZXgtd3JhcDp3cmFwO2dhcDo1cHh9Ci5hY3Rpb24tZ3JvdXAgYSwuYWN0aW9uLWdyb3VwIGJ1dHRvbnsKIGRpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6N3B4IDlweDttYXJnaW46MnB4OwogZm9udC1zaXplOjEwcHg7dGV4dC1kZWNvcmF0aW9uOm5vbmUKfQouYWN0aW9uLWdyb3VwIGZvcm17ZGlzcGxheTppbmxpbmV9Ci5hY3Rpb24tZ3JvdXAgLm1lc2gtaW1wb3J0LWZvcm17ZGlzcGxheTppbmxpbmUtZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjVweDtmbGV4LXdyYXA6d3JhcDttYXgtd2lkdGg6MjYwcHh9Ci5hY3Rpb24tZ3JvdXAgLm1lc2gtaW1wb3J0LWZvcm0gaW5wdXRbdHlwZT1maWxlXXttYXgtd2lkdGg6MTU1cHg7bWluLXdpZHRoOjA7cGFkZGluZzo1cHg7Zm9udC1zaXplOjEwcHh9Ci5hY3Rpb24tZ3JvdXAgLm1lc2gtaW1wb3J0LWZvcm0gYnV0dG9ue2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEyMGRlZywjZWQyMzQ0LCM5NDE0MmQpO2NvbG9yOndoaXRlO2JvcmRlcjoxcHggc29saWQgI2ZmNDA1Yjtib3JkZXItcmFkaXVzOjZweDtjdXJzb3I6cG9pbnRlcn0KLmFjdGlvbi1kYW5nZXJ7YmFja2dyb3VuZDojODYxYTJiO2NvbG9yOndoaXRlO2JvcmRlcjowfQoKLyogREVWRUxPUEVSIFNJREVCQVIgKi8KLmRldmVsb3Blci1jYXJkewogYmFja2dyb3VuZDojMTUxNzIyOwogYm9yZGVyOjFweCBzb2xpZCAjMjkyZDNiOwogYm9yZGVyLXJhZGl1czoxMnB4OwogcGFkZGluZzoyMHB4IDEycHg7CiBtYXJnaW46MThweCAwIDI2cHg7CiBkaXNwbGF5OmZsZXg7CiBmbGV4LWRpcmVjdGlvbjpjb2x1bW47CiBhbGlnbi1pdGVtczpjZW50ZXI7CiB0ZXh0LWFsaWduOmNlbnRlcjsKIGdhcDo5cHg7Cn0KLmRldmVsb3Blci1hdmF0YXJ7CiB3aWR0aDo2NnB4OwogaGVpZ2h0OjY2cHg7CiBib3JkZXItcmFkaXVzOjUwJTsKIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE0NWRlZywjZmY0MDVkLCM3OTE2MjkpOwogZGlzcGxheTpmbGV4OwogYWxpZ24taXRlbXM6Y2VudGVyOwoganVzdGlmeS1jb250ZW50OmNlbnRlcjsKIGJvcmRlcjoycHggc29saWQgI2ZmNjQ3YjsKIGJveC1zaGFkb3c6MCAwIDIwcHggI2ZmMzA0NTJiOwp9CgouZGV2ZWxvcGVyLWF2YXRhcntvdmVyZmxvdzpoaWRkZW59Ci5kZXZlbG9wZXItYXZhdGFyIGltZ3sKIHdpZHRoOjEwMCU7CiBoZWlnaHQ6MTAwJTsKIGRpc3BsYXk6YmxvY2s7CiBvYmplY3QtZml0OmNvdmVyOwogb2JqZWN0LXBvc2l0aW9uOmNlbnRlcjsKIGJvcmRlci1yYWRpdXM6NTAlOwp9CgouZGV2ZWxvcGVyLWF2YXRhciBzcGFuewogY29sb3I6d2hpdGU7CiBmb250LXNpemU6MjJweDsKIGZvbnQtd2VpZ2h0OjkwMDsKIGxldHRlci1zcGFjaW5nOjFweDsKfQouZGV2ZWxvcGVyLWNhcmQgc3Ryb25newogY29sb3I6I2ZmZjsKIGZvbnQtc2l6ZToxNnB4Owp9Ci5kZXZlbG9wZXItY2FyZCBzbWFsbHsKIGNvbG9yOiM5NjliYWQ7CiBmb250LXNpemU6MTFweDsKfQouZGV2ZWxvcGVyLWJhZGdlewogY29sb3I6I2ZmNTI2YjsKIGZvbnQtc2l6ZTo5cHg7CiBsZXR0ZXItc3BhY2luZzoxLjVweDsKIGZvbnQtd2VpZ2h0OmJvbGQ7CiBtYXJnaW4tdG9wOjRweDsKfQouZGV2ZWxvcGVyLWxpbmt7CiBkaXNwbGF5OmZsZXg7CiBhbGlnbi1pdGVtczpjZW50ZXI7CiBnYXA6MTBweDsKIHBhZGRpbmc6MTNweCAxMHB4OwogbWFyZ2luOjdweCAwOwogYm9yZGVyOjFweCBzb2xpZCAjMjkyZDNiOwogYm9yZGVyLXJhZGl1czo4cHg7CiBjb2xvcjojZDVkN2UwOwogdGV4dC1kZWNvcmF0aW9uOm5vbmU7CiBmb250LXNpemU6MTNweDsKfQouZGV2ZWxvcGVyLWxpbms6aG92ZXJ7CiBib3JkZXItY29sb3I6I2ZmNDA1ZDsKIGJhY2tncm91bmQ6IzE5MTkyMzsKfQoKLmRldmVsb3Blci1pY29uewogd2lkdGg6MzBweDsKIGhlaWdodDozMHB4OwogbWluLXdpZHRoOjMwcHg7CiBib3JkZXItcmFkaXVzOjdweDsKIGRpc3BsYXk6ZmxleDsKIGFsaWduLWl0ZW1zOmNlbnRlcjsKIGp1c3RpZnktY29udGVudDpjZW50ZXI7CiBmbGV4LXNocmluazowOwp9Ci55b3V0dWJlLWljb257YmFja2dyb3VuZDojZTYyMTMyfQoud2hhdHNhcHAtaWNvbntiYWNrZ3JvdW5kOiMxNjhiNTB9Ci5kZXZlbG9wZXItaWNvbiBzdmd7CiB3aWR0aDoyMHB4OwogaGVpZ2h0OjIwcHg7CiBkaXNwbGF5OmJsb2NrOwogZmxleC1zaHJpbms6MDsKfQouZGV2ZWxvcGVyLWxpbmt7CiBkaXNwbGF5OmZsZXg7CiBmbGV4LWRpcmVjdGlvbjpyb3c7CiBmbGV4LXdyYXA6bm93cmFwOwogYWxpZ24taXRlbXM6Y2VudGVyOwogZ2FwOjhweDsKIHBhZGRpbmc6MTFweCA4cHg7CiB3aGl0ZS1zcGFjZTpub3dyYXA7Cn0KLmRldmVsb3Blci1saW5rIC5leHRlcm5hbC1pY29uewogbWFyZ2luLWxlZnQ6YXV0bzsKIGZsZXgtc2hyaW5rOjA7Cn0KLmV4dGVybmFsLWljb257CiBtYXJnaW4tbGVmdDphdXRvOwogY29sb3I6I2ZmNTI2YjsKfQouZGV2ZWxvcGVyLWZvb3RlcnsKIGJvcmRlci10b3A6MXB4IHNvbGlkICMyOTJkM2I7CiBtYXJnaW4tdG9wOjI4cHg7CiBwYWRkaW5nLXRvcDoxOHB4OwogZGlzcGxheTpmbGV4OwogZmxleC1kaXJlY3Rpb246Y29sdW1uOwogZ2FwOjdweDsKfQouZGV2ZWxvcGVyLWZvb3RlciBzcGFuewogY29sb3I6Izg1OGI5YzsKIGZvbnQtc2l6ZTo5cHg7CiBsZXR0ZXItc3BhY2luZzoxLjVweDsKfQouZGV2ZWxvcGVyLWZvb3RlciBzbWFsbHsKIGNvbG9yOiM2NDZiN2Q7CiBmb250LXNpemU6MTBweDsKfQoKCi8qIE1PQklMRSBSRVNQT05TSVZFIFBBVENIIFYxICovCkBtZWRpYShtYXgtd2lkdGg6MTEwMHB4KXsKICAgIGh0bWwsYm9keXsKICAgICAgICB3aWR0aDoxMDAlOwogICAgICAgIG1pbi13aWR0aDowICFpbXBvcnRhbnQ7CiAgICAgICAgbWF4LXdpZHRoOjEwMCU7CiAgICAgICAgb3ZlcmZsb3cteDpoaWRkZW47CiAgICB9CiAgICBtYWluewogICAgICAgIGJveC1zaXppbmc6Ym9yZGVyLWJveDsKICAgICAgICB3aWR0aDoxMDAlOwogICAgICAgIG1pbi13aWR0aDowOwogICAgICAgIG1heC13aWR0aDoxMDAlOwogICAgfQogICAgbWFpbj4qLAogICAgLnBhbmVsLAogICAgLmFzc2V0LWNvbnRyb2xzewogICAgICAgIGJveC1zaXppbmc6Ym9yZGVyLWJveDsKICAgICAgICBtaW4td2lkdGg6MDsKICAgICAgICBtYXgtd2lkdGg6MTAwJTsKICAgIH0KICAgIC5wYW5lbHsKICAgICAgICBvdmVyZmxvdzpoaWRkZW47CiAgICB9CiAgICAuc2Nyb2xsewogICAgICAgIGRpc3BsYXk6YmxvY2s7CiAgICAgICAgd2lkdGg6MTAwJTsKICAgICAgICBtYXgtd2lkdGg6MTAwJTsKICAgICAgICBvdmVyZmxvdy14OmF1dG87CiAgICAgICAgb3ZlcmZsb3cteTpoaWRkZW47CiAgICAgICAgLXdlYmtpdC1vdmVyZmxvdy1zY3JvbGxpbmc6dG91Y2g7CiAgICB9CiAgICB0YWJsZXsKICAgICAgICB3aWR0aDoxMDAlOwogICAgICAgIG1pbi13aWR0aDo2NTBweDsKICAgIH0KICAgIGlucHV0LHNlbGVjdCx0ZXh0YXJlYXsKICAgICAgICBib3gtc2l6aW5nOmJvcmRlci1ib3g7CiAgICAgICAgbWF4LXdpZHRoOjEwMCU7CiAgICB9CiAgICBidXR0b24sYXsKICAgICAgICB0b3VjaC1hY3Rpb246bWFuaXB1bGF0aW9uOwogICAgfQp9CkBtZWRpYShtYXgtd2lkdGg6NzYwcHgpewogICAgaGVhZGVyewogICAgICAgIGJveC1zaXppbmc6Ym9yZGVyLWJveDsKICAgICAgICB3aWR0aDoxMDAlOwogICAgICAgIG1heC13aWR0aDoxMDAlOwogICAgfQogICAgbWFpbnsKICAgICAgICBwYWRkaW5nOjEycHg7CiAgICAgICAgZ2FwOjEycHg7CiAgICB9CiAgICAucGFuZWx7CiAgICAgICAgcGFkZGluZzoxM3B4OwogICAgICAgIGJvcmRlci1yYWRpdXM6MTJweDsKICAgIH0KICAgIC5zdGF0c3sKICAgICAgICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsbWlubWF4KDAsMWZyKSk7CiAgICB9CiAgICAuYXNzZXQtY29udHJvbHN7CiAgICAgICAgZ2FwOjhweDsKICAgIH0KICAgIC5hc3NldC1jb250cm9scyBidXR0b24sCiAgICAuYXNzZXQtY29udHJvbHMgc2VsZWN0ewogICAgICAgIG1pbi1oZWlnaHQ6NDJweDsKICAgIH0KICAgIC5uYXRpdmUtZHJvcGRvd257CiAgICAgICAgbWluLXdpZHRoOjIwMHB4OwogICAgICAgIG1heC13aWR0aDpjYWxjKDEwMHZ3IC0gMzVweCk7CiAgICB9CiAgICAuYWN0aW9uLWNlbGx7CiAgICAgICAgbWluLXdpZHRoOjE4MHB4OwogICAgfQogICAgLmFjdGlvbi1ncm91cHsKICAgICAgICBnYXA6NnB4OwogICAgfQogICAgLmFjdGlvbi1ncm91cCBhLAogICAgLmFjdGlvbi1ncm91cCBidXR0b257CiAgICAgICAgbWluLWhlaWdodDozNHB4OwogICAgICAgIHBhZGRpbmc6OHB4IDEwcHg7CiAgICAgICAgZm9udC1zaXplOjExcHg7CiAgICB9CiAgICBpbWcsdmlkZW8sY2FudmFzewogICAgICAgIG1heC13aWR0aDoxMDAlOwogICAgICAgIGhlaWdodDphdXRvOwogICAgfQp9CgoKLyogTUxCQiBBTklNQVRJT04gUEFDSyBWMSAqLwpAa2V5ZnJhbWVzIG1sYmJGYWRlSW4gewogICAgZnJvbSB7IG9wYWNpdHk6MDsgdHJhbnNmb3JtOnRyYW5zbGF0ZVkoMTNweCk7IH0KICAgIHRvICAgeyBvcGFjaXR5OjE7IHRyYW5zZm9ybTp0cmFuc2xhdGVZKDApOyB9Cn0KQGtleWZyYW1lcyBtbGJiR2xvdyB7CiAgICAwJSwxMDAlIHsgYm94LXNoYWRvdzowIDAgNXB4ICNmZjMwNDUyMjsgfQogICAgNTAlICAgICB7IGJveC1zaGFkb3c6MCAwIDE3cHggI2ZmMzA0NTY2OyB9Cn0KQGtleWZyYW1lcyBtbGJiUHVsc2UgewogICAgMCUsMTAwJSB7IG9wYWNpdHk6Ljc1OyB9CiAgICA1MCUgICAgIHsgb3BhY2l0eToxOyB9Cn0KQGtleWZyYW1lcyBtbGJiU2hpbmUgewogICAgZnJvbSB7IGJhY2tncm91bmQtcG9zaXRpb246MjAwJSBjZW50ZXI7IH0KICAgIHRvICAgeyBiYWNrZ3JvdW5kLXBvc2l0aW9uOi0yMDAlIGNlbnRlcjsgfQp9Cgpib2R5IHsKICAgIGFuaW1hdGlvbjptbGJiRmFkZUluIC40NXMgZWFzZS1vdXQgYm90aDsKfQpoZWFkZXIgewogICAgYW5pbWF0aW9uOm1sYmJGYWRlSW4gLjVzIGVhc2Utb3V0IGJvdGg7Cn0KLnBhbmVsIHsKICAgIGFuaW1hdGlvbjptbGJiRmFkZUluIC41NXMgZWFzZS1vdXQgYm90aDsKfQouc3RhdHMgLnN0YXQgewogICAgYW5pbWF0aW9uOm1sYmJGYWRlSW4gLjU1cyBlYXNlLW91dCBib3RoOwp9Ci5zdGF0cyAuc3RhdDpudGgtY2hpbGQoMikgeyBhbmltYXRpb24tZGVsYXk6LjA3czsgfQouc3RhdHMgLnN0YXQ6bnRoLWNoaWxkKDMpIHsgYW5pbWF0aW9uLWRlbGF5Oi4xNHM7IH0KLnN0YXRzIC5zdGF0Om50aC1jaGlsZCg0KSB7IGFuaW1hdGlvbi1kZWxheTouMjFzOyB9CgpidXR0b24sIC5idG4sIC5hY3Rpb24tZ3JvdXAgYSB7CiAgICB0cmFuc2l0aW9uOgogICAgICAgIHRyYW5zZm9ybSAuMnMgZWFzZSwKICAgICAgICBib3gtc2hhZG93IC4ycyBlYXNlLAogICAgICAgIGJhY2tncm91bmQtY29sb3IgLjJzIGVhc2UsCiAgICAgICAgYm9yZGVyLWNvbG9yIC4ycyBlYXNlOwp9CmJ1dHRvbjpob3ZlciwgLmJ0bjpob3ZlciwgLmFjdGlvbi1ncm91cCBhOmhvdmVyIHsKICAgIHRyYW5zZm9ybTp0cmFuc2xhdGVZKC0ycHgpOwogICAgYm94LXNoYWRvdzowIDVweCAxOHB4ICNmZjMwNDUzMzsKfQpidXR0b246YWN0aXZlLCAuYnRuOmFjdGl2ZSwgLmFjdGlvbi1ncm91cCBhOmFjdGl2ZSB7CiAgICB0cmFuc2Zvcm06c2NhbGUoLjk3KTsKfQoucGFuZWw6aG92ZXIgewogICAgYm9yZGVyLWNvbG9yOiNmZjQwNWI2NjsKfQoubG9nbyB7CiAgICBhbmltYXRpb246bWxiYlB1bHNlIDNzIGVhc2UtaW4tb3V0IGluZmluaXRlOwp9Ci5tZW51LXRvZ2dsZSB7CiAgICB0cmFuc2l0aW9uOnRyYW5zZm9ybSAuMnMgZWFzZSwgYm94LXNoYWRvdyAuMnMgZWFzZTsKfQoubWVudS10b2dnbGU6YWN0aXZlIHsKICAgIHRyYW5zZm9ybTpzY2FsZSguOTQpOwp9CmlucHV0LCBzZWxlY3QsIHRleHRhcmVhIHsKICAgIHRyYW5zaXRpb246Ym9yZGVyLWNvbG9yIC4ycyBlYXNlLCBib3gtc2hhZG93IC4ycyBlYXNlOwp9CmlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMsIHRleHRhcmVhOmZvY3VzIHsKICAgIG91dGxpbmU6bm9uZTsKICAgIGJvcmRlci1jb2xvcjojZmY0MDViICFpbXBvcnRhbnQ7CiAgICBib3gtc2hhZG93OjAgMCAwIDNweCAjZmY0MDViMjI7Cn0KLm5hdGl2ZS1kcm9wZG93biB7CiAgICB0cmFuc2Zvcm0tb3JpZ2luOnRvcCBsZWZ0Owp9Ci5uYXRpdmUtZHJvcGRvd24ub3BlbiB7CiAgICBhbmltYXRpb246bWxiYkZhZGVJbiAuMThzIGVhc2Utb3V0IGJvdGg7Cn0KLmFjdGlvbi1kYW5nZXI6aG92ZXIgewogICAgYm94LXNoYWRvdzowIDAgMTVweCAjZmYzMDQ1NjY7Cn0KQG1lZGlhKG1heC13aWR0aDo3NjBweCkgewogICAgYnV0dG9uOmhvdmVyLCAuYnRuOmhvdmVyLCAuYWN0aW9uLWdyb3VwIGE6aG92ZXIgewogICAgICAgIHRyYW5zZm9ybTpub25lOwogICAgfQogICAgLnBhbmVsOmhvdmVyIHsKICAgICAgICBib3JkZXItY29sb3I6aW5oZXJpdDsKICAgIH0KfQpAbWVkaWEocHJlZmVycy1yZWR1Y2VkLW1vdGlvbjpyZWR1Y2UpIHsKICAgICosICo6OmJlZm9yZSwgKjo6YWZ0ZXIgewogICAgICAgIGFuaW1hdGlvbi1kdXJhdGlvbjouMDFtcyAhaW1wb3J0YW50OwogICAgICAgIGFuaW1hdGlvbi1pdGVyYXRpb24tY291bnQ6MSAhaW1wb3J0YW50OwogICAgICAgIHNjcm9sbC1iZWhhdmlvcjphdXRvICFpbXBvcnRhbnQ7CiAgICAgICAgdHJhbnNpdGlvbi1kdXJhdGlvbjouMDFtcyAhaW1wb3J0YW50OwogICAgfQp9CgoKLyogTUxCQiBQUkVNSVVNIExBWU9VVCBWMiAqLwo6cm9vdCB7CiAgLS1iZzojMDgwOTBlOwogIC0tcGFuZWw6IzEyMTUxZjsKICAtLXBhbmVsMjojMTkxZDI5OwogIC0tcmVkOiNmZjM2NTc7CiAgLS1saW5lOiMyOTJlM2I7CiAgLS1tdXRlZDojOTY5YmFkOwp9CgoqIHsKICBib3gtc2l6aW5nOmJvcmRlci1ib3g7Cn0KCmh0bWwgewogIHdpZHRoOjEwMCU7CiAgbWluLXdpZHRoOjA7CiAgc2Nyb2xsLWJlaGF2aW9yOnNtb290aDsKfQoKYm9keSB7CiAgd2lkdGg6MTAwJTsKICBtaW4td2lkdGg6MCAhaW1wb3J0YW50OwogIG1heC13aWR0aDoxMDAlOwogIG92ZXJmbG93LXg6aGlkZGVuOwogIGJhY2tncm91bmQ6CiAgICByYWRpYWwtZ3JhZGllbnQoZWxsaXBzZSBhdCA4MCUgMCUsIzM1MTAxYzMzLHRyYW5zcGFyZW50IDM4JSksCiAgICB2YXIoLS1iZyk7CiAgY29sb3I6I2Y0ZjVmYTsKfQoKaGVhZGVyIHsKICBtaW4td2lkdGg6MDsKICBib3gtc2hhZG93OjAgNXB4IDI1cHggIzAwMDU7CiAgYmFja2Ryb3AtZmlsdGVyOmJsdXIoMTRweCk7Cn0KCm1haW4gewogIHdpZHRoOmNhbGMoMTAwJSAtIDI1MHB4KTsKICBtYXgtd2lkdGg6MTYwMHB4OwogIG1pbi13aWR0aDowOwogIG1hcmdpbi1sZWZ0OjI1MHB4OwogIHBhZGRpbmc6MjhweDsKICBkaXNwbGF5OmdyaWQ7CiAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgxMixtaW5tYXgoMCwxZnIpKTsKICBnYXA6MThweDsKICBhbGlnbi1pdGVtczpzdGFydDsKfQoKbWFpbiA+IC5wYW5lbCB7CiAgZ3JpZC1jb2x1bW46c3BhbiAxMjsKICB3aWR0aDoxMDAlOwogIG1pbi13aWR0aDowOwp9CgojdXBsb2FkLXBhbmVsLAojaW5mby1wYW5lbCwKI2V4cGxvcmVyLXBhbmVsLAojdG9vbHMtcGFuZWwgewogIGdyaWQtY29sdW1uOnNwYW4gMTI7Cn0KCiNzdW1tYXJ5LXBhbmVsIHsKICBncmlkLWNvbHVtbjpzcGFuIDEyOwp9CgoucGFuZWwgewogIG1pbi13aWR0aDowOwogIG92ZXJmbG93OmhpZGRlbjsKICBwYWRkaW5nOjIycHg7CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsKICBib3JkZXItcmFkaXVzOjE1cHg7CiAgYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTQ1ZGVnLCMxNzFhMjUsIzEwMTIxYSk7CiAgYm94LXNoYWRvdzowIDEycHggMzJweCAjMDAwMzsKICB0cmFuc2l0aW9uOmJvcmRlci1jb2xvciAuMnMgZWFzZSx0cmFuc2Zvcm0gLjJzIGVhc2U7Cn0KCi5wYW5lbCBoMiB7CiAgZGlzcGxheTpmbGV4OwogIGFsaWduLWl0ZW1zOmNlbnRlcjsKICBnYXA6MTBweDsKICBmb250LXNpemU6MTRweDsKICBsZXR0ZXItc3BhY2luZzoxLjJweDsKICBsaW5lLWhlaWdodDoxLjU7Cn0KCi5wYW5lbCBoMjpiZWZvcmUgewogIGNvbnRlbnQ6IiI7CiAgd2lkdGg6NHB4OwogIGhlaWdodDoxN3B4OwogIGZsZXgtc2hyaW5rOjA7CiAgYm9yZGVyLXJhZGl1czo1cHg7CiAgYmFja2dyb3VuZDp2YXIoLS1yZWQpOwogIGJveC1zaGFkb3c6MCAwIDEycHggI2ZmMzY1NzY2Owp9Cgouc3RhdHMgewogIGRpc3BsYXk6Z3JpZDsKICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsbWlubWF4KDAsMWZyKSk7CiAgZ2FwOjEycHg7Cn0KCi5zdGF0IHsKICBtaW4td2lkdGg6MDsKICBwYWRkaW5nOjE4cHg7CiAgYm9yZGVyOjFweCBzb2xpZCAjMzAzNTQ1OwogIGJvcmRlci1yYWRpdXM6MTJweDsKICBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxNDVkZWcsIzIwMjQzMiwjMTcxYTI0KTsKfQoKLnN0YXQgYiB7CiAgZm9udC1zaXplOjI2cHg7CiAgb3ZlcmZsb3ctd3JhcDphbnl3aGVyZTsKfQoKaW5wdXQ6bm90KFt0eXBlPWNoZWNrYm94XSksCnNlbGVjdCwKdGV4dGFyZWEgewogIHdpZHRoOjEwMCU7CiAgbWF4LXdpZHRoOjEwMCU7CiAgbWluLWhlaWdodDo0NHB4OwogIHBhZGRpbmc6MTJweCAxNHB4OwogIGNvbG9yOiNmNWY1Zjg7CiAgYmFja2dyb3VuZDojMGIwZDE0OwogIGJvcmRlcjoxcHggc29saWQgIzM0M2E0OTsKICBib3JkZXItcmFkaXVzOjlweDsKICBmb250OmluaGVyaXQ7Cn0KCmlucHV0OmZvY3VzLApzZWxlY3Q6Zm9jdXMsCnRleHRhcmVhOmZvY3VzIHsKICBvdXRsaW5lOm5vbmU7CiAgYm9yZGVyLWNvbG9yOnZhcigtLXJlZCk7CiAgYm94LXNoYWRvdzowIDAgMCAzcHggI2ZmMzY1NzFjOwp9CgpidXR0b24sCi5idG4gewogIG1pbi1oZWlnaHQ6NDJweDsKICBwYWRkaW5nOjExcHggMTZweDsKICBib3JkZXItcmFkaXVzOjlweDsKICBmb250LXNpemU6MTJweDsKICBmb250LXdlaWdodDo4MDA7CiAgbGV0dGVyLXNwYWNpbmc6LjRweDsKfQoKYnV0dG9uOmFjdGl2ZSwKLmJ0bjphY3RpdmUgewogIHRyYW5zZm9ybTpzY2FsZSguOTcpOwp9CgphIHsKICBvdmVyZmxvdy13cmFwOmFueXdoZXJlOwp9Cgouc2Nyb2xsIHsKICB3aWR0aDoxMDAlOwogIG1heC13aWR0aDoxMDAlOwogIG92ZXJmbG93OmF1dG87CiAgYm9yZGVyOjFweCBzb2xpZCB2YXIoLS1saW5lKTsKICBib3JkZXItcmFkaXVzOjEwcHg7CiAgLXdlYmtpdC1vdmVyZmxvdy1zY3JvbGxpbmc6dG91Y2g7Cn0KCnRhYmxlIHsKICB3aWR0aDoxMDAlOwogIG1pbi13aWR0aDo2NTBweDsKICBib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Cn0KCnRoIHsKICBiYWNrZ3JvdW5kOiMxYjFlMmE7Cn0KCnRoLHRkIHsKICBwYWRkaW5nOjEzcHggMTJweDsKICB2ZXJ0aWNhbC1hbGlnbjptaWRkbGU7Cn0KCnRib2R5IHRyOm50aC1jaGlsZChldmVuKSB7CiAgYmFja2dyb3VuZDojZmZmZmZmMDU7Cn0KCi5hc3NldC1jb250cm9scyB7CiAgZGlzcGxheTpmbGV4OwogIGFsaWduLWl0ZW1zOmNlbnRlcjsKICBmbGV4LXdyYXA6d3JhcDsKICBnYXA6MTBweDsKfQoKLm5hdGl2ZS1tZW51LWJ1dHRvbiB7CiAgbWluLWhlaWdodDo0NHB4OwogIGJvcmRlci1yYWRpdXM6OXB4Owp9CgouYXNzZXQtY291bnQgewogIG1hcmdpbi1sZWZ0OmF1dG87CiAgZm9udC13ZWlnaHQ6NzAwOwp9CgouYWN0aW9uLWNlbGwgewogIG1pbi13aWR0aDoyMDBweDsKfQoKLmFjdGlvbi1ncm91cCB7CiAgZGlzcGxheTpmbGV4OwogIGZsZXgtd3JhcDp3cmFwOwogIGFsaWduLWl0ZW1zOmNlbnRlcjsKICBnYXA6N3B4Owp9CgouYWN0aW9uLWdyb3VwIGEsCi5hY3Rpb24tZ3JvdXAgYnV0dG9uIHsKICBtaW4taGVpZ2h0OjM2cHg7CiAgcGFkZGluZzo4cHggMTFweDsKICBib3JkZXItcmFkaXVzOjdweDsKICBmb250LXNpemU6MTBweDsKfQoKLm5vdGljZSB7CiAgYm9yZGVyLXJhZGl1czoxMHB4OwogIHBhZGRpbmc6MTRweCAxNnB4Owp9CgouZGV2ZWxvcGVyLWNhcmQgewogIGJvcmRlci1yYWRpdXM6MTRweDsKfQoKLmRldmVsb3Blci1saW5rIHsKICBtaW4taGVpZ2h0OjQ2cHg7CiAgYm9yZGVyLXJhZGl1czoxMHB4Owp9CgpAbWVkaWEobWluLXdpZHRoOjExMDFweCkgewogICNpbmZvLXBhbmVsIHsKICAgIGdyaWQtY29sdW1uOnNwYW4gNTsKICB9CiAgI3N1bW1hcnktcGFuZWwgewogICAgZ3JpZC1jb2x1bW46c3BhbiA0OwogIH0KICAjdG9vbHMtcGFuZWwgewogICAgZ3JpZC1jb2x1bW46c3BhbiAzOwogIH0KfQoKQG1lZGlhKG1heC13aWR0aDoxMTAwcHgpIHsKICBtYWluIHsKICAgIHdpZHRoOjEwMCU7CiAgICBtYXJnaW4tbGVmdDowOwogICAgcGFkZGluZzoyMHB4OwogIH0KfQoKQG1lZGlhKG1heC13aWR0aDo3NjBweCkgewogIGhlYWRlciB7CiAgICBsZWZ0OjA7CiAgICByaWdodDowOwogICAgaGVpZ2h0OjcwcHg7CiAgICBwYWRkaW5nOjlweCAxMnB4OwogICAgZ2FwOjhweDsKICB9CgogIGhlYWRlciAubG9nbyB7CiAgICBmb250LXNpemU6MTVweDsKICAgIGxldHRlci1zcGFjaW5nOjFweDsKICB9CgogIGhlYWRlciAuc3ViIHsKICAgIGRpc3BsYXk6bm9uZTsKICB9CgogIC5tZW51LXRvZ2dsZSB7CiAgICBkaXNwbGF5OmJsb2NrOwogICAgbWluLXdpZHRoOjc4cHg7CiAgICBtaW4taGVpZ2h0OjQwcHg7CiAgICBwYWRkaW5nOjlweCAxMXB4OwogICAgZm9udC1zaXplOjExcHg7CiAgfQoKICAuc2lkZWJhciB7CiAgICB0b3A6NzBweDsKICAgIGJvdHRvbTowOwogICAgd2lkdGg6bWluKDI4NXB4LDg1dncpOwogICAgcGFkZGluZzoxN3B4IDEzcHggODVweDsKICAgIG92ZXJmbG93LXk6YXV0bzsKICAgIHRyYW5zZm9ybTp0cmFuc2xhdGVYKC0xMDUlKTsKICAgIHRyYW5zaXRpb246dHJhbnNmb3JtIC4yNXMgZWFzZTsKICAgIGJveC1zaGFkb3c6MTVweCAwIDQwcHggIzAwMDk7CiAgfQoKICBib2R5LnNpZGViYXItb3BlbiAuc2lkZWJhciB7CiAgICB0cmFuc2Zvcm06dHJhbnNsYXRlWCgwKTsKICB9CgogIG1haW4gewogICAgZGlzcGxheTpmbGV4OwogICAgZmxleC1kaXJlY3Rpb246Y29sdW1uOwogICAgd2lkdGg6MTAwJTsKICAgIG1pbi13aWR0aDowOwogICAgbWFyZ2luOjcwcHggMCAwOwogICAgcGFkZGluZzoxM3B4OwogICAgZ2FwOjEzcHg7CiAgfQoKICBtYWluID4gLnBhbmVsIHsKICAgIHdpZHRoOjEwMCU7CiAgICBtaW4td2lkdGg6MDsKICB9CgogIC5wYW5lbCB7CiAgICBwYWRkaW5nOjE1cHg7CiAgICBib3JkZXItcmFkaXVzOjEzcHg7CiAgfQoKICAucGFuZWwgaDIgewogICAgZm9udC1zaXplOjEzcHg7CiAgICBtYXJnaW4tYm90dG9tOjE1cHg7CiAgfQoKICAuc3RhdHMgewogICAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLG1pbm1heCgwLDFmcikpOwogICAgZ2FwOjlweDsKICB9CgogIC5zdGF0IHsKICAgIHBhZGRpbmc6MTNweDsKICB9CgogIC5zdGF0IGIgewogICAgZm9udC1zaXplOjIxcHg7CiAgfQoKICAuYXNzZXQtY29udHJvbHMgewogICAgZGlzcGxheTpncmlkOwogICAgZ3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLG1pbm1heCgwLDFmcikpOwogICAgZ2FwOjhweDsKICB9CgogIC5hc3NldC1jb250cm9scyAuZHJvcGRvd24td3JhcCwKICAuYXNzZXQtY29udHJvbHMgLm5hdGl2ZS1tZW51LWJ1dHRvbiB7CiAgICB3aWR0aDoxMDAlOwogIH0KCiAgLmFzc2V0LWNvdW50IHsKICAgIGdyaWQtY29sdW1uOjEvLTE7CiAgICBtYXJnaW46M3B4IDA7CiAgfQoKICAubmF0aXZlLWRyb3Bkb3duIHsKICAgIG1pbi13aWR0aDowOwogICAgd2lkdGg6bWluKDI0MHB4LGNhbGMoMTAwdncgLSA0NXB4KSk7CiAgfQoKICAuYWN0aW9uLWNlbGwgewogICAgbWluLXdpZHRoOjE4MHB4OwogIH0KCiAgLmFjdGlvbi1ncm91cCB7CiAgICBnYXA6NnB4OwogIH0KCiAgLmFjdGlvbi1ncm91cCBhLAogIC5hY3Rpb24tZ3JvdXAgYnV0dG9uIHsKICAgIG1pbi1oZWlnaHQ6MzhweDsKICAgIHBhZGRpbmc6OXB4OwogIH0KCiAgI3VwbG9hZC1wYW5lbCBmb3JtIHsKICAgIHdpZHRoOjEwMCU7CiAgfQoKICAjdXBsb2FkLXBhbmVsIGJ1dHRvbiwKICAjdXBsb2FkLXBhbmVsIGlucHV0W3R5cGU9ZmlsZV0gewogICAgd2lkdGg6MTAwJTsKICB9CgogIC5kZXZlbG9wZXItY2FyZCB7CiAgICBwYWRkaW5nOjE2cHggMTBweDsKICB9CgogIC5zaWRlLXN0YXR1cyB7CiAgICBwb3NpdGlvbjpzdGF0aWM7CiAgICBtYXJnaW4tdG9wOjIwcHg7CiAgfQoKICAuc2Nyb2xsIHsKICAgIG1heC1oZWlnaHQ6NjV2aDsKICB9Cn0KCkBtZWRpYShtYXgtd2lkdGg6MzgwcHgpIHsKICBtYWluIHsKICAgIHBhZGRpbmc6MTBweDsKICB9CgogIC5wYW5lbCB7CiAgICBwYWRkaW5nOjEycHg7CiAgfQoKICAuc3RhdHMgewogICAgZ2FwOjdweDsKICB9CgogIC5zdGF0IHsKICAgIHBhZGRpbmc6MTFweDsKICB9CgogIC5zdGF0IGIgewogICAgZm9udC1zaXplOjE5cHg7CiAgfQp9CgovKiBTaGFyZWQgbW9iaWxlIGxheW91dCBmb3Igc3RhbmRhbG9uZSBtYW5hZ2VyIHBhZ2VzICovCkBtZWRpYShtYXgtd2lkdGg6NzYwcHgpIHsKICBib2R5IHsKICAgIHBhZGRpbmc6MTJweCAhaW1wb3J0YW50OwogIH0KCiAgYm9keSA+IGgyIHsKICAgIGZvbnQtc2l6ZToxN3B4OwogIH0KCiAgYm9keSA+IC5wYW5lbCB7CiAgICB3aWR0aDoxMDAlOwogICAgcGFkZGluZzoxNHB4OwogICAgbWFyZ2luLWJvdHRvbToxM3B4OwogIH0KCiAgYm9keSA+IC5wYW5lbCAuYnRuLAogIGJvZHkgPiAucGFuZWwgYnV0dG9uIHsKICAgIG1hcmdpbjo0cHggMDsKICB9CgogIGJvZHkgPiBoZWFkZXIgewogICAgcGFkZGluZzowIDEycHg7CiAgfQoKICBib2R5ID4gbWFpbiB7CiAgICBtYXJnaW46MDsKICAgIHBhZGRpbmc6MTJweCAwOwogIH0KCiAgYm9keSA+IG1haW4gLnN0YXRzIHsKICAgIGdyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMixtaW5tYXgoMCwxZnIpKTsKICB9Cn0KCkBtZWRpYShwcmVmZXJzLXJlZHVjZWQtbW90aW9uOnJlZHVjZSkgewogICosKjo6YmVmb3JlLCo6OmFmdGVyIHsKICAgIGFuaW1hdGlvbjpub25lICFpbXBvcnRhbnQ7CiAgICB0cmFuc2l0aW9uOm5vbmUgIWltcG9ydGFudDsKICAgIHNjcm9sbC1iZWhhdmlvcjphdXRvICFpbXBvcnRhbnQ7CiAgfQp9CgoKLyogTUxCQiBNT0JJTEUgRklYIFYzICovCkBtZWRpYShtYXgtd2lkdGg6NzYwcHgpewoKICBodG1sLGJvZHl7CiAgICB3aWR0aDoxMDAlIWltcG9ydGFudDsKICAgIG1pbi13aWR0aDowIWltcG9ydGFudDsKICAgIG1heC13aWR0aDoxMDAlIWltcG9ydGFudDsKICAgIG92ZXJmbG93LXg6aGlkZGVuIWltcG9ydGFudDsKICB9CgogIGJvZHl7CiAgICBmb250LXNpemU6MTRweCFpbXBvcnRhbnQ7CiAgICBsaW5lLWhlaWdodDoxLjUhaW1wb3J0YW50OwogIH0KCiAgbWFpbnsKICAgIGJveC1zaXppbmc6Ym9yZGVyLWJveCFpbXBvcnRhbnQ7CiAgICB3aWR0aDoxMDAlIWltcG9ydGFudDsKICAgIG1pbi13aWR0aDowIWltcG9ydGFudDsKICAgIHBhZGRpbmc6MTJweCFpbXBvcnRhbnQ7CiAgICBnYXA6MTJweCFpbXBvcnRhbnQ7CiAgfQoKICBtYWluPi5wYW5lbCwucGFuZWx7CiAgICBib3gtc2l6aW5nOmJvcmRlci1ib3ghaW1wb3J0YW50OwogICAgd2lkdGg6MTAwJSFpbXBvcnRhbnQ7CiAgICBtaW4td2lkdGg6MCFpbXBvcnRhbnQ7CiAgICBwYWRkaW5nOjE0cHghaW1wb3J0YW50OwogICAgYm9yZGVyLXJhZGl1czoxNnB4IWltcG9ydGFudDsKICAgIG1hcmdpbjowIWltcG9ydGFudDsKICB9CgogIC5wYW5lbCBoMnsKICAgIGZvbnQtc2l6ZToxNnB4IWltcG9ydGFudDsKICAgIGxpbmUtaGVpZ2h0OjEuMzUhaW1wb3J0YW50OwogICAgbGV0dGVyLXNwYWNpbmc6MXB4IWltcG9ydGFudDsKICAgIG1hcmdpbjowIDAgMTRweCFpbXBvcnRhbnQ7CiAgfQoKICAucGFuZWwgcHsKICAgIGZvbnQtc2l6ZToxNHB4IWltcG9ydGFudDsKICAgIGxpbmUtaGVpZ2h0OjEuNTUhaW1wb3J0YW50OwogICAgb3ZlcmZsb3ctd3JhcDphbnl3aGVyZSFpbXBvcnRhbnQ7CiAgfQoKICAucGFuZWwgc21hbGwsLnBhbmVsIC5tdXRlZHsKICAgIGZvbnQtc2l6ZToxMnB4IWltcG9ydGFudDsKICB9CgogIGlucHV0W3R5cGU9ZmlsZV0saW5wdXRbdHlwZT1zZWFyY2hdewogICAgYm94LXNpemluZzpib3JkZXItYm94IWltcG9ydGFudDsKICAgIHdpZHRoOjEwMCUhaW1wb3J0YW50OwogICAgbWluLXdpZHRoOjAhaW1wb3J0YW50OwogICAgZm9udC1zaXplOjE0cHghaW1wb3J0YW50OwogICAgcGFkZGluZzoxMnB4IWltcG9ydGFudDsKICB9CgogICN1cGxvYWQtcGFuZWwgYnV0dG9uW3R5cGU9c3VibWl0XXsKICAgIHdpZHRoOjEwMCUhaW1wb3J0YW50OwogICAgbWluLWhlaWdodDo0OHB4IWltcG9ydGFudDsKICAgIGZvbnQtc2l6ZToxNHB4IWltcG9ydGFudDsKICB9CgogICNpbmZvLXBhbmVsIC5zdGF0c3sKICAgIGdyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMixtaW5tYXgoMCwxZnIpKSFpbXBvcnRhbnQ7CiAgICBnYXA6OXB4IWltcG9ydGFudDsKICB9CgogICNpbmZvLXBhbmVsIC5zdGF0ewogICAgbWluLXdpZHRoOjAhaW1wb3J0YW50OwogICAgcGFkZGluZzoxMnB4IWltcG9ydGFudDsKICB9CgogICNpbmZvLXBhbmVsIC5zdGF0IGJ7CiAgICBmb250LXNpemU6MjJweCFpbXBvcnRhbnQ7CiAgfQoKICAjaW5mby1wYW5lbCAuc3RhdCBzbWFsbHsKICAgIGZvbnQtc2l6ZToxMnB4IWltcG9ydGFudDsKICB9CgogICNpbmZvLXBhbmVsIGJyewogICAgZGlzcGxheTpub25lIWltcG9ydGFudDsKICB9CgogICNpbmZvLXBhbmVsIC5idG57CiAgICBkaXNwbGF5OmlubGluZS1mbGV4IWltcG9ydGFudDsKICAgIGJveC1zaXppbmc6Ym9yZGVyLWJveCFpbXBvcnRhbnQ7CiAgICB3aWR0aDphdXRvIWltcG9ydGFudDsKICAgIG1heC13aWR0aDoxMDAlIWltcG9ydGFudDsKICAgIG1pbi1oZWlnaHQ6NDNweCFpbXBvcnRhbnQ7CiAgICBhbGlnbi1pdGVtczpjZW50ZXIhaW1wb3J0YW50OwogICAganVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7CiAgICBtYXJnaW46MTBweCA2cHggMCAwIWltcG9ydGFudDsKICAgIHBhZGRpbmc6MTFweCAxNHB4IWltcG9ydGFudDsKICAgIGZvbnQtc2l6ZToxMnB4IWltcG9ydGFudDsKICAgIGxpbmUtaGVpZ2h0OjEuMyFpbXBvcnRhbnQ7CiAgICB3aGl0ZS1zcGFjZTpub3JtYWwhaW1wb3J0YW50OwogICAgdmVydGljYWwtYWxpZ246bWlkZGxlIWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCAjc2VhcmNoewogICAgbWFyZ2luOjRweCAwIDEycHghaW1wb3J0YW50OwogIH0KCiAgI2V4cGxvcmVyLXBhbmVsIC5hc3NldC1jb250cm9sc3sKICAgIGRpc3BsYXk6Z3JpZCFpbXBvcnRhbnQ7CiAgICBncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsbWlubWF4KDAsMWZyKSkhaW1wb3J0YW50OwogICAgZ2FwOjhweCFpbXBvcnRhbnQ7CiAgICBhbGlnbi1pdGVtczpzdHJldGNoIWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCAuZHJvcGRvd24td3JhcHsKICAgIG1pbi13aWR0aDowIWltcG9ydGFudDsKICAgIHdpZHRoOjEwMCUhaW1wb3J0YW50OwogIH0KCiAgI2V4cGxvcmVyLXBhbmVsIC5uYXRpdmUtbWVudS1idXR0b257CiAgICBib3gtc2l6aW5nOmJvcmRlci1ib3ghaW1wb3J0YW50OwogICAgd2lkdGg6MTAwJSFpbXBvcnRhbnQ7CiAgICBtaW4taGVpZ2h0OjQzcHghaW1wb3J0YW50OwogICAganVzdGlmeS1jb250ZW50OmNlbnRlciFpbXBvcnRhbnQ7CiAgICBnYXA6OHB4IWltcG9ydGFudDsKICAgIHBhZGRpbmc6OHB4IWltcG9ydGFudDsKICAgIGZvbnQtc2l6ZToxM3B4IWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCAuYXNzZXQtY291bnR7CiAgICBncmlkLWNvbHVtbjoxLy0xIWltcG9ydGFudDsKICAgIG1hcmdpbjowIWltcG9ydGFudDsKICAgIGZvbnQtc2l6ZToxMnB4IWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCAuc2Nyb2xsewogICAgd2lkdGg6MTAwJSFpbXBvcnRhbnQ7CiAgICBtYXgtd2lkdGg6MTAwJSFpbXBvcnRhbnQ7CiAgICBtYXgtaGVpZ2h0OjYwdmghaW1wb3J0YW50OwogICAgb3ZlcmZsb3c6YXV0byFpbXBvcnRhbnQ7CiAgICAtd2Via2l0LW92ZXJmbG93LXNjcm9sbGluZzp0b3VjaCFpbXBvcnRhbnQ7CiAgfQoKICAjZXhwbG9yZXItcGFuZWwgdGFibGV7CiAgICB3aWR0aDptYXgtY29udGVudCFpbXBvcnRhbnQ7CiAgICBtaW4td2lkdGg6NjUwcHghaW1wb3J0YW50OwogICAgZm9udC1zaXplOjEycHghaW1wb3J0YW50OwogICAgYm9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlIWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCB0aCwKICAjZXhwbG9yZXItcGFuZWwgdGR7CiAgICBib3gtc2l6aW5nOmJvcmRlci1ib3ghaW1wb3J0YW50OwogICAgaGVpZ2h0OmF1dG8haW1wb3J0YW50OwogICAgbWluLWhlaWdodDowIWltcG9ydGFudDsKICAgIHBhZGRpbmc6OXB4IDEwcHghaW1wb3J0YW50OwogICAgZm9udC1zaXplOjEycHghaW1wb3J0YW50OwogICAgbGluZS1oZWlnaHQ6MS40IWltcG9ydGFudDsKICAgIHZlcnRpY2FsLWFsaWduOm1pZGRsZSFpbXBvcnRhbnQ7CiAgICB3aGl0ZS1zcGFjZTpub3JtYWwhaW1wb3J0YW50OwogIH0KCiAgI2V4cGxvcmVyLXBhbmVsIHRib2R5IHRyewogICAgaGVpZ2h0OmF1dG8haW1wb3J0YW50OwogICAgbWluLWhlaWdodDowIWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCB0ZHsKICAgIG92ZXJmbG93LXdyYXA6YW55d2hlcmUhaW1wb3J0YW50OwogIH0KCiAgI2V4cGxvcmVyLXBhbmVsIC5hY3Rpb24tY2VsbHsKICAgIG1pbi13aWR0aDoxNjBweCFpbXBvcnRhbnQ7CiAgfQoKICAjZXhwbG9yZXItcGFuZWwgLmFjdGlvbi1ncm91cHsKICAgIGRpc3BsYXk6ZmxleCFpbXBvcnRhbnQ7CiAgICBmbGV4LXdyYXA6d3JhcCFpbXBvcnRhbnQ7CiAgICBnYXA6NXB4IWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCAuYWN0aW9uLWdyb3VwIGEsCiAgI2V4cGxvcmVyLXBhbmVsIC5hY3Rpb24tZ3JvdXAgYnV0dG9uewogICAgZm9udC1zaXplOjEwcHghaW1wb3J0YW50OwogICAgcGFkZGluZzo3cHggOHB4IWltcG9ydGFudDsKICB9CgogICNleHBsb3Jlci1wYW5lbCAubmF0aXZlLWRyb3Bkb3duewogICAgbWluLXdpZHRoOjAhaW1wb3J0YW50OwogICAgd2lkdGg6MTAwJSFpbXBvcnRhbnQ7CiAgICBtYXgtd2lkdGg6ODV2dyFpbXBvcnRhbnQ7CiAgfQoKICAjZXhwbG9yZXItcGFuZWwgLmRyb3Bkb3duLW9wdGlvbnsKICAgIGZvbnQtc2l6ZToxM3B4IWltcG9ydGFudDsKICAgIHBhZGRpbmc6MTBweCAxMnB4IWltcG9ydGFudDsKICB9Cn0KCgovKiBNTEJCIEhFQURFUiBTUEFDSU5HIEZJWCBWNCAqLwpAbWVkaWEobWF4LXdpZHRoOjc2MHB4KXsKICBoZWFkZXJ7CiAgICBoZWlnaHQ6NzZweCFpbXBvcnRhbnQ7CiAgICBtaW4taGVpZ2h0Ojc2cHghaW1wb3J0YW50OwogICAgdG9wOjAhaW1wb3J0YW50OwogICAgei1pbmRleDoxMDAhaW1wb3J0YW50OwogIH0KCiAgbWFpbnsKICAgIG1hcmdpbi10b3A6NzZweCFpbXBvcnRhbnQ7CiAgICBwYWRkaW5nLXRvcDoyMnB4IWltcG9ydGFudDsKICAgIHNjcm9sbC1tYXJnaW4tdG9wOjkwcHghaW1wb3J0YW50OwogIH0KCiAgYm9keXsKICAgIHNjcm9sbC1wYWRkaW5nLXRvcDo5MHB4IWltcG9ydGFudDsKICB9CgogIG1haW4+LnBhbmVsOmZpcnN0LWNoaWxkewogICAgbWFyZ2luLXRvcDowIWltcG9ydGFudDsKICB9CgogIC5zaWRlYmFyewogICAgdG9wOjc2cHghaW1wb3J0YW50OwogICAgaGVpZ2h0OmNhbGMoMTAwZHZoIC0gNzZweCkhaW1wb3J0YW50OwogIH0KfQoKCi8qID09PT09IEpBUEFORVNFIFBST0pFQ1QgU1RZTEUgPT09PT0gKi8KOnJvb3QgewogIC0tanAtYmc6ICMxMTExMTY7CiAgLS1qcC1wYW5lbDogIzE5MTgyMDsKICAtLWpwLWNhcmQ6ICMyMDIwMmE7CiAgLS1qcC1yZWQ6ICNiNTJiM2E7CiAgLS1qcC1waW5rOiAjZThhMGFkOwogIC0tanAtaXZvcnk6ICNlOGRjYzU7CiAgLS1qcC1pbmRpZ286ICMyNjNiNTk7CiAgLS1qcC1nb2xkOiAjYzVhMTViOwogIC0tanAtYm9yZGVyOiByZ2JhKDE5NywxNjEsOTEsLjI1KTsKfQoKaHRtbCwgYm9keSB7CiAgYmFja2dyb3VuZDoKICAgIHJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDkwJSA4JSwgcmdiYSgxODEsNDMsNTgsLjE3KSwgdHJhbnNwYXJlbnQgMzglKSwKICAgIHJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDUlIDY1JSwgcmdiYSgzOCw1OSw4OSwuMTgpLCB0cmFuc3BhcmVudCA0MCUpLAogICAgIzExMTExNiAhaW1wb3J0YW50OwogIGNvbG9yOiB2YXIoLS1qcC1pdm9yeSkgIWltcG9ydGFudDsKfQoKaGVhZGVyLCAuaGVhZGVyLCAudG9wYmFyLCBuYXYsIGFzaWRlLCAuc2lkZWJhciB7CiAgYmFja2dyb3VuZDogcmdiYSgxNywxNywyMiwuOTgpICFpbXBvcnRhbnQ7CiAgYm9yZGVyLWNvbG9yOiB2YXIoLS1qcC1ib3JkZXIpICFpbXBvcnRhbnQ7Cn0KCi5zaWRlLWJyYW5kLCAubG9nbywgLmJyYW5kIHsKICBjb2xvcjogdmFyKC0tanAtcGluaykgIWltcG9ydGFudDsKICBsZXR0ZXItc3BhY2luZzogMnB4Owp9Cgouc2lkZS1icmFuZDphZnRlciB7CiAgY29udGVudDogIuaXpeacrOOBrue+jiDigKIgU0FLVVJBIEVESVRJT04iOwogIGRpc3BsYXk6IGJsb2NrOwogIGNvbG9yOiB2YXIoLS1qcC1nb2xkKTsKICBmb250LXNpemU6IDlweDsKICBsZXR0ZXItc3BhY2luZzogMnB4OwogIG1hcmdpbi10b3A6IDdweDsKfQoKLnBhbmVsLCAuY2FyZCwgLnN0YXQtY2FyZCwgLnRvb2wtY2FyZCwKLnVwbG9hZC1ib3gsIC5pbmZvLWNhcmQsIC5leHBsb3Jlci1wYW5lbCB7CiAgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDE0NWRlZywjMjAyMDJhLCMxNzE2MWUpICFpbXBvcnRhbnQ7CiAgYm9yZGVyOiAxcHggc29saWQgdmFyKC0tanAtYm9yZGVyKSAhaW1wb3J0YW50OwogIGJvcmRlci1yYWRpdXM6IDE1cHggIWltcG9ydGFudDsKICBib3gtc2hhZG93OiAwIDlweCAyOHB4IHJnYmEoMCwwLDAsLjI4KTsKfQoKYnV0dG9uLCAuYnRuLCBpbnB1dFt0eXBlPSJzdWJtaXQiXSB7CiAgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KDEzNWRlZywjOGUyMDMyLCNiNTJiM2EpICFpbXBvcnRhbnQ7CiAgY29sb3I6IHZhcigtLWpwLWl2b3J5KSAhaW1wb3J0YW50OwogIGJvcmRlcjogMXB4IHNvbGlkIHJnYmEoMjMyLDE2MCwxNzMsLjM1KSAhaW1wb3J0YW50OwogIGJvcmRlci1yYWRpdXM6IDEwcHggIWltcG9ydGFudDsKICB0cmFuc2l0aW9uOiAuMnMgZWFzZTsKfQoKYnV0dG9uOmhvdmVyLCAuYnRuOmhvdmVyIHsKICBiYWNrZ3JvdW5kOiBsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCNiNTJiM2EsI2QzNGI1YykgIWltcG9ydGFudDsKICBib3gtc2hhZG93OiAwIDAgMTZweCByZ2JhKDE4MSw0Myw1OCwuMik7Cn0KCmlucHV0LCBzZWxlY3QsIHRleHRhcmVhIHsKICBiYWNrZ3JvdW5kOiAjMTExMTE2ICFpbXBvcnRhbnQ7CiAgY29sb3I6IHZhcigtLWpwLWl2b3J5KSAhaW1wb3J0YW50OwogIGJvcmRlcjogMXB4IHNvbGlkIHJnYmEoMTk3LDE2MSw5MSwuMjUpICFpbXBvcnRhbnQ7CiAgYm9yZGVyLXJhZGl1czogOXB4ICFpbXBvcnRhbnQ7Cn0KCmlucHV0OmZvY3VzLCBzZWxlY3Q6Zm9jdXMsIHRleHRhcmVhOmZvY3VzIHsKICBvdXRsaW5lOiBub25lOwogIGJvcmRlci1jb2xvcjogdmFyKC0tanAtcGluaykgIWltcG9ydGFudDsKICBib3gtc2hhZG93OiAwIDAgMCAycHggcmdiYSgyMzIsMTYwLDE3MywuMTIpOwp9CgpoMSwgaDIsIGgzLCBoNCB7CiAgY29sb3I6IHZhcigtLWpwLXBpbmspOwp9Cgp0aCB7CiAgY29sb3I6IHZhcigtLWpwLWdvbGQpICFpbXBvcnRhbnQ7CiAgYmFja2dyb3VuZDogIzI5MjEyYSAhaW1wb3J0YW50Owp9Cgp0ZCwgdGggewogIGJvcmRlci1jb2xvcjogcmdiYSgxOTcsMTYxLDkxLC4xNykgIWltcG9ydGFudDsKfQoKYSB7IGNvbG9yOiB2YXIoLS1qcC1waW5rKTsgfQoKOjpzZWxlY3Rpb24gewogIGJhY2tncm91bmQ6IHZhcigtLWpwLXJlZCk7CiAgY29sb3I6IHdoaXRlOwp9Cgo6Oi13ZWJraXQtc2Nyb2xsYmFyIHsgd2lkdGg6IDdweDsgaGVpZ2h0OiA3cHg7IH0KOjotd2Via2l0LXNjcm9sbGJhci10aHVtYiB7CiAgYmFja2dyb3VuZDogIzhlMzk0OTsKICBib3JkZXItcmFkaXVzOiAxMHB4Owp9Cjo6LXdlYmtpdC1zY3JvbGxiYXItdHJhY2sgeyBiYWNrZ3JvdW5kOiAjMTExMTE2OyB9Ci8qID09PT09IEVORCBKQVBBTkVTRSBQUk9KRUNUIFNUWUxFID09PT09ICovCgoKLyogPT09PT0gSkFQQU5FU0UgU0FLVVJBIFdPUktTUEFDRSBUSEVNRSA9PT09PSAqLwo6cm9vdHsKIC0tYmc6IzEwMGYxODstLXBhbmVsOiMxOTE4MjQ7LS1wYW5lbDI6IzIxMWQyYjsKIC0tcmVkOiNkOTRiNjM7LS1yZWQyOiM5ZjI5NDU7LS1saW5lOiM1MTQwNTI7LS1tdXRlZDojYjdhOWI3OwogLS1zYWt1cmE6I2YyYTdiODstLWl2b3J5OiNmNGU4ZDg7LS1pbmRpZ286IzI5MmI0OTstLWdvbGQ6I2M1YTU2YTsKfQpodG1sLGJvZHl7YmFja2dyb3VuZC1jb2xvcjp2YXIoLS1iZyl9CmJvZHl7CiBjb2xvcjp2YXIoLS1pdm9yeSk7CiBiYWNrZ3JvdW5kOgogIHJhZGlhbC1ncmFkaWVudChlbGxpcHNlIGF0IDEyJSAxOCUsIzcwMmI0OTMwLHRyYW5zcGFyZW50IDM4JSksCiAgcmFkaWFsLWdyYWRpZW50KGVsbGlwc2UgYXQgODglIDcyJSwjMjkyYjQ5NDAsdHJhbnNwYXJlbnQgNDIlKSwKICBsaW5lYXItZ3JhZGllbnQoMTM1ZGVnLCMxMDBmMTggMCUsIzE5MTUyMiA0OCUsIzExMTIxZCAxMDAlKTsKfQpib2R5OmJlZm9yZXsKIGNvbnRlbnQ6IvCfjLgiOwogcG9zaXRpb246Zml4ZWQ7ei1pbmRleDowO3BvaW50ZXItZXZlbnRzOm5vbmU7CiByaWdodDoxMnB4O3RvcDoxMDVweDtmb250LXNpemU6NDJweDtvcGFjaXR5Oi4yMDsKIGZpbHRlcjpzYXR1cmF0ZSguOCk7Cn0KYm9keTphZnRlcnsKIGNvbnRlbnQ6IuKcvyAg4p2AICDinL8iOwogcG9zaXRpb246Zml4ZWQ7ei1pbmRleDowO3BvaW50ZXItZXZlbnRzOm5vbmU7CiBsZWZ0OjEycHg7Ym90dG9tOjE2cHg7Y29sb3I6I2YyYTdiODsKIGZvbnQtc2l6ZToyMnB4O2xldHRlci1zcGFjaW5nOjEycHg7b3BhY2l0eTouMjI7Cn0KaGVhZGVyewogYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTA1ZGVnLCMyMTE3MjUsIzE3MTgyNyA2NSUsIzI5MjMzYSk7CiBib3JkZXItYm90dG9tOjFweCBzb2xpZCAjOGQ1YjY4OwogYm94LXNoYWRvdzowIDVweCAyNHB4ICMwMDA3Owp9Ci5sb2dve2NvbG9yOnZhcigtLXNha3VyYSk7dGV4dC1zaGFkb3c6MCAwIDE2cHggI2Q5NGI2MzQwfQouc3Vie2NvbG9yOiNkMGI4YzN9CmhlYWRlcjphZnRlcntjb250ZW50OiLmoZwg4oCiIOaXpeacrOOBruODr+ODvOOCr+OCueODmuODvOOCuSI7Y29sb3I6I2Q3YjljNH0KLnNpZGViYXJ7CiBiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxODBkZWcsIzE3MTUyMSwjMjAxOTI3IDU1JSwjMTUxNzI1KTsKIGJvcmRlci1yaWdodDoxcHggc29saWQgIzcwNTA2NDsKfQouc2lkZS1icmFuZCBzdHJvbmd7Y29sb3I6dmFyKC0tc2FrdXJhKX0KLnNpZGUtYnJhbmQgc21hbGwsLm5hdi1sYWJlbHtjb2xvcjojYjk5ZWFlfQouc2lkZWJhciBhe2NvbG9yOiNlMGQyZGN9Ci5zaWRlYmFyIGE6aG92ZXIsLmNhdGVnb3J5LWxpbms6aG92ZXJ7CiBiYWNrZ3JvdW5kOiM0OTI0Mzg7Ym9yZGVyLWNvbG9yOiNiNzViNzU7Y29sb3I6I2ZmZjFmNAp9Ci5zaWRlYmFyIGEgc3BhbiwuY2F0ZWdvcnktbGluayBzcGFue2NvbG9yOiNmMmE3Yjh9Ci5zaWRlLXN0YXR1c3tiYWNrZ3JvdW5kOiMxOTJhMmI7Ym9yZGVyLWNvbG9yOiM2MDdjNzA7Y29sb3I6I2M1ZTNjOX0KbWFpbiwuc2lkZWJhcixoZWFkZXJ7aXNvbGF0aW9uOmlzb2xhdGV9Cm1haW57cG9zaXRpb246cmVsYXRpdmV9Ci5wYW5lbHsKIHBvc2l0aW9uOnJlbGF0aXZlOwogYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTQ1ZGVnLCMyMTFkMmIsIzE3MTcyMiA3MiUsIzIwMTkyNyk7CiBib3JkZXI6MXB4IHNvbGlkICM2OTUwNjQ7CiBib3JkZXItcmFkaXVzOjE4cHg7CiBib3gtc2hhZG93OjAgMTBweCAzMnB4ICMwMDA2LCBpbnNldCAwIDFweCAjZmZmZmZmMGI7Cn0KLnBhbmVsOmJlZm9yZXsKIGNvbnRlbnQ6IiI7CiBwb3NpdGlvbjphYnNvbHV0ZTtsZWZ0OjA7dG9wOjE4cHg7Ym90dG9tOjE4cHg7d2lkdGg6NHB4OwogYm9yZGVyLXJhZGl1czowIDVweCA1cHggMDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCh2YXIoLS1zYWt1cmEpLHZhcigtLXJlZDIpKTsKIG9wYWNpdHk6Ljk7Cn0KLnBhbmVsIGgyewogY29sb3I6dmFyKC0tc2FrdXJhKTsKIGJvcmRlci1ib3R0b20tY29sb3I6IzU3NDM1NDsKIGxldHRlci1zcGFjaW5nOjJweDsKfQpidXR0b24sLmJ0bnsKIGJhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDEyMGRlZywjYzk0YjY2LCM4ZjI5NDgpOwogYm9yZGVyOjFweCBzb2xpZCAjZjA5YWFlO2NvbG9yOiNmZmYzZTk7CiBib3JkZXItcmFkaXVzOjEwcHg7CiBib3gtc2hhZG93OjAgNHB4IDE0cHggIzZlMWQzYjM1Owp9CmJ1dHRvbjpob3ZlciwuYnRuOmhvdmVye2ZpbHRlcjpicmlnaHRuZXNzKDEuMTMpO2JveC1zaGFkb3c6MCA2cHggMThweCAjZDk0YjYzNDB9CmlucHV0W3R5cGU9ZmlsZV0saW5wdXRbdHlwZT1zZWFyY2hdLGlucHV0Om5vdChbdHlwZV0pLHNlbGVjdCx0ZXh0YXJlYXsKIGJhY2tncm91bmQ6IzExMTIxYztib3JkZXItY29sb3I6IzY1NTM2Nztjb2xvcjojZjRlOGQ4O2JvcmRlci1yYWRpdXM6MTBweAp9CmlucHV0OmZvY3VzLHNlbGVjdDpmb2N1cyx0ZXh0YXJlYTpmb2N1c3tib3JkZXItY29sb3I6dmFyKC0tc2FrdXJhKX0KLnN0YXRzIC5zdGF0LC5zdGF0ewogYmFja2dyb3VuZDpsaW5lYXItZ3JhZGllbnQoMTQ1ZGVnLCMyOTI1M2EsIzFiMWMyYik7CiBib3JkZXItY29sb3I6IzY2NTM2YTtib3JkZXItcmFkaXVzOjEycHgKfQouc3RhdCBiLC50YWcsYXtjb2xvcjojZjJhN2I4fQp0aHtjb2xvcjojZjRiZGM5O2JhY2tncm91bmQ6IzMwMjYzYX0KdGgsdGR7Ym9yZGVyLWJvdHRvbS1jb2xvcjojNTE0MDUyfQp0Ym9keSB0cjpob3ZlcntiYWNrZ3JvdW5kOiMzYjI2Mzd9Ci5zY3JvbGx7Ym9yZGVyLWNvbG9yOiM1MTQwNTI7Ym9yZGVyLXJhZGl1czoxMHB4fQoubm90aWNle2JhY2tncm91bmQ6IzNhMjAyZDtib3JkZXItY29sb3I6I2E0NGI2Nztjb2xvcjojZmZlMmU4fQoubmF0aXZlLW1lbnUtYnV0dG9ue2JhY2tncm91bmQ6IzI5MjUzYTtib3JkZXItY29sb3I6IzgwNjU3YTtjb2xvcjojZjRlOGQ4fQoubmF0aXZlLWRyb3Bkb3due2JhY2tncm91bmQ6IzI4MjIzNjtib3JkZXItY29sb3I6Izc0NTc2ZX0KLmRyb3Bkb3duLW9wdGlvbntjb2xvcjojZjRlOGQ4fQouZHJvcGRvd24tb3B0aW9uOmhvdmVyLC5kcm9wZG93bi1vcHRpb24uYWN0aXZle2JhY2tncm91bmQ6IzU5MzI0ODtjb2xvcjojZmZmfQouZGV2ZWxvcGVyLWNhcmR7YmFja2dyb3VuZDojMjExZDJiO2JvcmRlci1jb2xvcjojNjk1MDY0fQouZGV2ZWxvcGVyLWF2YXRhcntiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxNDVkZWcsI2U5YTJiNiwjOGYyOTQ4KTtib3JkZXItY29sb3I6I2Y0YmRjOX0KLmRldmVsb3Blci1iYWRnZSwuZXh0ZXJuYWwtaWNvbntjb2xvcjojZjJhN2I4fQouZGV2ZWxvcGVyLWxpbmt7Ym9yZGVyLWNvbG9yOiM1MTQwNTI7Y29sb3I6I2YwZTJlOX0KLmRldmVsb3Blci1saW5rOmhvdmVye2JhY2tncm91bmQ6IzM5MjQzODtib3JkZXItY29sb3I6I2Q3Nzg5MX0KLmRldmVsb3Blci1mb290ZXJ7Ym9yZGVyLXRvcC1jb2xvcjojNTE0MDUyfQoubWVudS10b2dnbGV7YmFja2dyb3VuZDojYTkzNDUwfQojdXBsb2FkLXBhbmVsLCNpbmZvLXBhbmVsLCNleHBsb3Jlci1wYW5lbCwjdG9vbHMtcGFuZWx7b3ZlcmZsb3c6aGlkZGVufQpAbWVkaWEobWF4LXdpZHRoOjc2MHB4KXsKIC5zaWRlYmFye2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDE4MGRlZywjMjExNzI1LCMxNzE4MjcpfQogLnBhbmVse2JvcmRlci1yYWRpdXM6MTZweH0KfQoKCi5nYW1lLXBpY2tlci1ncmlke2dyaWQtdGVtcGxhdGUtY29sdW1uczpyZXBlYXQoMixtaW5tYXgoMCwxZnIpKSFpbXBvcnRhbnQ7YWxpZ24taXRlbXM6c3RyZXRjaH0KLmdhbWUtcGlja2VyLWdyaWQgbGFiZWx7bWluLXdpZHRoOjAhaW1wb3J0YW50O21heC13aWR0aDoxMDAlO30KLmdhbWUtcGlja2VyLWdyaWQgbGFiZWwgaW1ne3dpZHRoOjEwMCUhaW1wb3J0YW50O21heC13aWR0aDo2NHB4O2hlaWdodDphdXRvIWltcG9ydGFudDthc3BlY3QtcmF0aW86MS8xO29iamVjdC1maXQ6Y292ZXJ9Ci5nYW1lLXBpY2tlci1ncmlkIGxhYmVsIGlucHV0e21pbi13aWR0aDowO21hcmdpbjowfQpAbWVkaWEobWF4LXdpZHRoOjQyMHB4KXsuZ2FtZS1waWNrZXItZ3JpZHtnYXA6OHB4IWltcG9ydGFudH0uZ2FtZS1waWNrZXItZ3JpZCBsYWJlbHtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MTZweCBtaW5tYXgoMCw1MnB4KSBtaW5tYXgoMCwxZnIpIWltcG9ydGFudDtwYWRkaW5nOjhweCFpbXBvcnRhbnQ7Z2FwOjZweCFpbXBvcnRhbnQ7bWluLWhlaWdodDo4MnB4IWltcG9ydGFudH0uZ2FtZS1waWNrZXItZ3JpZCBsYWJlbCBpbWd7bWF4LXdpZHRoOjUycHh9LmdhbWUtcGlja2VyLWdyaWQgbGFiZWwgc3Bhbntmb250LXNpemU6MTBweCFpbXBvcnRhbnQ7bGV0dGVyLXNwYWNpbmc6MCFpbXBvcnRhbnR9fQo8L3N0eWxlPgoKPC9oZWFkPgo8Ym9keT4KPGhlYWRlcj4KIDxkaXYgY2xhc3M9ImxvZ28iPkhBTlpJSEFOIE1PQkE8L2Rpdj4KIDxkaXYgY2xhc3M9InN1YiI+TU9CQSBTQ1JJUFQgTUFLRVIgLyBVTklUWSBXT1JLQkVOQ0g8L2Rpdj4KIDxmb3JtIG1ldGhvZD0icG9zdCIgYWN0aW9uPSIvbG9nb3V0IiBzdHlsZT0ibWFyZ2luLWxlZnQ6YXV0byI+CiAgPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0iX2NzcmZfdG9rZW4iIHZhbHVlPSJ7e2NzcmZfdG9rZW4oKX19Ij4KICA8YnV0dG9uIHR5cGU9InN1Ym1pdCI+TE9HT1VUIMK3IHt7c2Vzc2lvbi5nZXQoJ3VzZXJuYW1lJywnVVNFUicpfX08L2J1dHRvbj4KIDwvZm9ybT4KCjxidXR0b24gY2xhc3M9Im1lbnUtdG9nZ2xlIiB0eXBlPSJidXR0b24iCiBvbmNsaWNrPSJkb2N1bWVudC5ib2R5LmNsYXNzTGlzdC50b2dnbGUoJ3NpZGViYXItb3BlbicpIj4KIOKYsCBNRU5VCjwvYnV0dG9uPgoKPC9oZWFkZXI+Cgo8YXNpZGUgY2xhc3M9InNpZGViYXIiPgogPGRpdiBjbGFzcz0ic2lkZS1icmFuZCI+CiAgPHN0cm9uZz5IQU5aSUhBTiBNT0JBPC9zdHJvbmc+CiAgPHNtYWxsPlNDUklQVCBNQUtFUiBWMTwvc21hbGw+CiA8L2Rpdj4KCiA8ZGl2IGNsYXNzPSJuYXYtbGFiZWwiPlRPT0xTPC9kaXY+CjxhIGhyZWY9Ii9hcHAtZHVtcGVyIj48c3Bhbj7ilqM8L3NwYW4+IEFQUCBEVU1QRVI8L2E+CjxkaXYgY2xhc3M9Im5hdi1sYWJlbCI+REVWRUxPUEVSIFBST0ZJTEU8L2Rpdj4KCiA8ZGl2IGNsYXNzPSJkZXZlbG9wZXItY2FyZCI+CiAgPGRpdiBjbGFzcz0iZGV2ZWxvcGVyLWF2YXRhciI+CiAgIDxpbWcgc3JjPSJkYXRhOmltYWdlL2pwZWc7YmFzZTY0LC85ai80QUFRU2taSlJnQUJBUUVBU0FCSUFBRC80UUIwUlhocFpnQUFUVTBBS2dBQUFBZ0FCUUVhQUFVQUFBQUJBQUFBU2dFYkFBVUFBQUFCQUFBQVVnRW9BQU1BQUFBQkFBSUFBQUlUQUFNQUFBQUJBQUVBQU1iK0FBSUFBQUFSQUFBQVdnQUFBQUFBQUFCSUFBQUFBUUFBQUVnQUFBQUJSMjl2WjJ4bElFbHVZeTRnTWpBeE5nQUEvK0lCMkVsRFExOVFVazlHU1V4RkFBRUJBQUFCeUFBQUFBQUVNQUFBYlc1MGNsSkhRaUJZV1ZvZ0IrQUFBUUFCQUFBQUFBQUFZV056Y0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFFQUFQYldBQUVBQUFBQTB5MEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBSlpHVnpZd0FBQVBBQUFBQWtjbGhaV2dBQUFSUUFBQUFVWjFoWldnQUFBU2dBQUFBVVlsaFpXZ0FBQVR3QUFBQVVkM1J3ZEFBQUFWQUFBQUFVY2xSU1F3QUFBV1FBQUFBb1oxUlNRd0FBQVdRQUFBQW9ZbFJTUXdBQUFXUUFBQUFvWTNCeWRBQUFBWXdBQUFBOGJXeDFZd0FBQUFBQUFBQUJBQUFBREdWdVZWTUFBQUFJQUFBQUhBQnpBRklBUndCQ1dGbGFJQUFBQUFBQUFHK2lBQUE0OVFBQUE1QllXVm9nQUFBQUFBQUFZcGtBQUxlRkFBQVkybGhaV2lBQUFBQUFBQUFrb0FBQUQ0UUFBTGJQV0ZsYUlBQUFBQUFBQVBiV0FBRUFBQUFBMHkxd1lYSmhBQUFBQUFBRUFBQUFBbVptQUFEeXB3QUFEVmtBQUJQUUFBQUtXd0FBQUFBQUFBQUFiV3gxWXdBQUFBQUFBQUFCQUFBQURHVnVWVk1BQUFBZ0FBQUFIQUJIQUc4QWJ3Qm5BR3dBWlFBZ0FFa0FiZ0JqQUM0QUlBQXlBREFBTVFBMi85c0FRd0FHQkFVR0JRUUdCZ1VHQndjR0NBb1FDZ29KQ1FvVURnOE1FQmNVR0JnWEZCWVdHaDBsSHhvYkl4d1dGaUFzSUNNbUp5a3FLUmtmTFRBdEtEQWxLQ2tvLzlzQVF3RUhCd2NLQ0FvVENnb1RLQm9XR2lnb0tDZ29LQ2dvS0Nnb0tDZ29LQ2dvS0Nnb0tDZ29LQ2dvS0Nnb0tDZ29LQ2dvS0Nnb0tDZ29LQ2dvS0Nnb0tDZ28vOElBRVFnQjZ3TGZBd0VpQUFJUkFRTVJBZi9FQUJzQUFBSURBUUVCQUFBQUFBQUFBQUFBQUFNRUFBSUZBUVlILzhRQUdRRUFBd0VCQVFBQUFBQUFBQUFBQUFBQUFBRUNBd1FGLzlvQURBTUJBQUlRQXhBQUFBSDZwSkFra0NTUUpKQWtrRG5aQWtrQ1NRSlcwQ3Rxd0xTUUpKQXFrK0VZbVZ5aEZteHBndW9ZdC9xckR5a1d1Ty9ja285U1VoRjFXS3FxTGNKR3VPMVY1NzR2b01pcWtXUDZGV1dhM2xmVnR1S1g0MWh2YVZVWlBhMGUrMUtaYXhNbVBpMWJJc0ZtelpDNmhtbEx0V2c2TXRVd0pvc290UXpVQm0yaUkzV1dXSmdSdXE4cVl5TWsxdWp5SHFoMTUwNjZ3STNIa2IySUpwUFpXM3g5NUpNc0pKQWtrQ1NRSkpBbGJRT2Q1MEpKQWtrQ3ZhOUMwa0NTUUlFMEJFbFFsdENzTk80K05CbDY2SzRkUHpwV2ZUdWtVeld2SGlqc0tzZ2gzUXo1MVVlVHVXWEsxcVNjNERxRi9OZWxXVmoxdkplaldqaHNseTh4Wmo0alpaNXNSbVhIMDhZeTFsbXNrZDI4UjJkUTlIb2xtVDNNWW03TnJ1Y2txWVRScTJlMnpaTGpGSURwNWV0YzRvdEJ2UFJMb0VITEs5M1hMeU50QlBBMkFsNk9JckNqZXVYcFpKelhKSUVrZ1NTQkpJRWtnVG5lQjJUZ2RrZ1N0cUJlVXVFa2djbGFoWlUxRmNLTUlDTlZrb0lDT0U0cFg4NHVYR2lWb3FhYUxqWXZuMk0za05CTlYwS29UUTJQdTQrZXZYazJoZ1pXY1ZJamN5MU8zek9lcWVDQ3d0U2hxazZlcTBTc2ZPYWFZWTIxRXpycVdDbVRZd01vb0Npcm9WT0tCclkwZm1oYml5MHhtMTlJTXpTR3cxeFJMUVFQSmNqbW1waWF6RnV0Y0pjalFyNWwwdFkxUDA4a2pHU1FKSkJUbmVEbmVkQ1NRSk9jQzBuQTdLd0xWdHdCbEYwQ0JOUUtWbGhobExMU3RYUmtxUHE4VG9MVnJVNEJHT1J1bzAzV1ZuSmF4dFl6ZXFHTmpOWkR4QlZkbTVtdm51NHkwcllMa2JvZW94R25CYThESmphSE1WTFgyOGJaUm5jMDBxMGF5TkdCVHpPNWxLZGJMWkttdTdtMnEybUVUVE9jZWpGbHQzeXJkUm9ocm5MU2lXeWdyWVF2Y09vdlpxaGxQUXBhb3daMFdhdm9JTzNqZWU5YmZKTm5PeU5jdmVTVEJTU0JKSUVrcUZ1VG9TVnFCT1NCSlhvZHJZUUY3V3djR1hnY2c3aEUybGxaMVNkWUp4R1M0V29GZG44WFdxQnhKbkd5S1dZdHNVWEplUUNITFN5TDZkU01UaEliMXlkenpzYWxiV0ROZWpXOCt5ODlwRlp1TDBQTGJFSlYwc0E2cmZhODYxUzJWODg0OGtMaDFwaHQ1T29vT054V3RUQjBsek9ndURkRHU0bUt0ZTlCdEFlaVYzUDliNWtrdWZvNWdKSHFPcFoyOFpWMzZQT09tMHI2YnpoWk5idWU4MzdpU1B6NUpBa2tDYzdBcE8xQzllV0NUc0NuZTlEbExjQ1NYQ1FQQXVOaE5NbGxPbFZEcHJqelhWa2xiOEcyeWpSUm1lYzVCem9HakEyTkRScTQxbU1mUWFQaTZ1TUNYcHZPTUxSekE5UXRGZWNaYlpldUMvcFl3M0dlYWF6ODF2cXBsc2VaOUhsek9uekE5S1hpcmFIQzg3U3BZenlTczRpajFpQUxQVWorZHBEVk9OQmgyeE9tYm1EbzRxR0IyNDFkVWk0M1BNNjJTOFdXUlBQV25IR1hwbloydW9zMU5SRVJXdFhKN1I5WmtqNFpKQWtrQ1NRSlcwQWZaQXR5bGc3MmtDNnhlZ0x2UmpiZ2lDR01xcFZoTjNRdUhRWFRvcmRSMkZrMTAyQldYemttWS96UjNvRG9YWkkxV1k0V1BNWTJLcWtiM01yVnk5aEJhUXBsQnFnS2RiVXEzbVF0QzlDWG1yUTFpdkpuZkpuWkw1QkJOME8yOU1YQTlObnFWWFdGQjdPaEt2UERUMk1SN3ZDSjB4NGcrY3BTMmF4VTlPVU5aNWkrNTVlSjFkS2p0NnRacU5KMWRRYVdNZUc2azZwVTBiK3JTUjhNa2dTU0JKSUVrZ1N0b0ErZDRFcGJvQk9Fb2RpeFE1TzhIU2RxVTJBNmhEcXJJd1hZNElwWmJTck5reWRSYVhqK2l3M2FicldlV3N5bXBZbnZhWEpnRGpHaTBpdEhScEtreVc5TmpPWWtYS0RQTkc5QlpWRDZSbm5HRTY1blRaREpNb2V5V0xDODFzbTgwUDBlUVRlUjVuMDNuUUMybmNzTkRlWG9nR0sxV0c2cjZDbzg4V21Cckxwc3F1VnNuVng1amRyU3RkQkNEczRwNkRFTHJ5dXFpZU5CYkp3YWMvcXBKZ1NTQkpJRWtnU1NCSklFcGVvY0ViZ0xtcndKZGVoWFJ1cm9wQnVPbU9yWElwYXdnR1lnRlhBTlZtMFRWUlY2R2Jjb0Jic3BSb1hyZDVrSWtramVSQUFDQ1FLdHpaKyttUWpvOVZuUVphSWx1S01HUm9LR2p5VXBtNjYyMGFEVU1hV3V3clE3YW9lWWRZeVpuMHZsdHhkdVZ3dEtzOWpoVTNxMDVtaURWRXUyekJMb1paT2xqYXVhNXp1bUtyMTIwYjdaRHhldFoydWUreHJpaHI1K3ZVZWJWMy9OemYxaVNSbEpPQjJTQkpJRWtnU1NCV2Q0RXJhb2Q1WHFkeENVWTZPNnBYSlc2cDhZTE9IWjBKSTYwNUcxN0FDVmZNMVZpczlzS3FyWll6ZXVIaytyRHU0RmVhSTRwS25yNE01THVoUmRXVlJUVFY2S1pGM2xGUmNuUUowZXZUVm1PTlRiUVVhTGVieGV1ZElCVllseFE2dEx5ZWxSWWxvTzk1b3k5RWZOMnExUkRwWnp0bDdPTzhiWkxDczZMa05Hc0xVeDljaDVNb2FHMEJYcE1iT2Exb2dVb2RYWHplMG5sbjlWa2xZeVNCV3BPQjJESUU1QkFXYzZIT2Q0RmFsRUVYYTRxejdFQ1hXeWQyTVVZRW1VYTVBMVZrZUNhTmtYblI2MU15VFN6aDBLYnBublZMZEV5M1FPaU9rS0JRbGVzRjRrZGMrOHJtN1VwZDdEeTJ2Yjk4TTZhZTVtZmMwVkh0b1R2WEo5RW1MT3JwTWs0T215a3JhVTV3TmdtVVFMS0RHTFV5dTBZc0RYekZ6elZ4bm10Y0xCcjFST1pXVktjZUx6OHRyS01pR1dlTHV0cDR6MGJPdUVLOGFZR3lZS0t5SURRM0cvUXlUVGlra0RuZWRDVXZVSUZpQUczZUJidElCSnlvV0F4VUFMYVFsV2ZtYk9hV0hrSVVUa2NnU1dkazBucVl6MUdya2gwQjV4UWtLVDRTeXJQYzRzSEhiRU0xY3JjeE00d0ZMcmE1VzJmTzBhMnNZSTJYTXFXalI5bDRGK2ErbEh6dHN2SldMU2VocTlEeWdZanI1cmx4OGRZSUx0MEJNdXZacno5anF5SEhSaElSbmNwVHA2R1RvdlZTbkxONkdSc1pWWXJTWjhVZDdOYmVqYWRhaWJRcTQ2MGg4ODdKemRRamw4bU1WdjZmdzNOT0d2YTBIYWN1SGJyMkF2T1FMY2l3SDRNb1c0S3d4R3R3T1VsMHg1V2owck9xZUdtVnByVmtjcDArS3crNklkYlRaT1lkUkxsRG1kdElwSmM0dWE3QlFZODhyL0FKay9uM044WXltc2tyWHRMc2x3NWZzQ3phckNmdFBYZk9mb2llYjEzTW5vMW1jK3RaRFJuWTZyYklDNmNwRlhjbEM5R0szQkFwVXkwOU5qdDhxZk5zYUNXV2huTTloM2V3eEVsWng5bHJLd2ZRZWRuVGFZSEhLMmlub0Y1QXVxbVRRazNDRGFpQVYwc1dvVFRYNlZKSzh1U1FKT2RDVGtEdExVSFlKVXc1Mm5YWnVoVlEreWp4QlJ5N0FoZlNWRnF6UVFpRnkzSlZtSU9sT2R4MVpQaTlkR1VhdTdyZFVrUWxUWEd4UHhYclBCbUJFU0J0S2lJTzEzczYxYS9MaHp2TE03ZWhaZS93Qzg4VDY3SG9SZno3R3F1aUJ0b1NURDFaWnQ5Sk5KMEFJNTJVTWhSbXRyZVBkalRTcm1RMzM4KzAwNFVOVHp6Y2JhT1Z0NTdZdHZHYVRWeDlYS2xhbHREeTcyWVlhRVNmemxqTG5MM1NSV2dWZE5XcElIcTcwK3dUazA0K2lJSmxlQVhCMnlMQlVNamNIOHBrRGRPdnhDVU9WVjFQUldTc2JQdlFUbE5GTGdhaVE2cW0rTlR0WG1LWmU3anhZVFZtZDlDQjY3UTFFVTBuS0ZHa2g1RDJYbGpQend6cmE1V0VTTXJibFdpMnBZWGUxNlBwUk1TL1RQZGV5N0VUOGRkUjFMS1VkWlcyRFBMWjZDZG5ES2E3eVVhc3luaXI2bUdxa2ZZZWliNHRYVG04N2ordjhBTHE5ZWxqVklzclR6aGx4Tk5LWTFWVEtIUnFaL1VsanlhYWdvNHRuUFRWVVhHalE1a051UHI4NU5lV1NRT2pYSVhTTUREZ21oUzg1NWFsdC9xZDBtMTVZT0RGWldZTE5IRlQxcU5lTTFsaUFKSTAwMjgwNU9rSk94SUNYVnp0UlBWeWpvNEloR3pMOXFoL0hjRE9mZzgvMC9uOU1FNWF1bWM1STFldzdDdktXR1hTei9BRnVldm9zNzBHYXR5RDdDU1pPZ1ZDczR5WHhkdXJ5bzZISm5YWExpTlRiVkwxRnFzcHk4NnBDcTgyeFBaUUppYlVUYzFmRTdWVHBOS2RuYk9RZndBcnJWRk9CS0NXZDdJTTh6Wmg5Ykx4MUp0bVgwTTJNenR6NjNjYnEwMk00cXczYlo3aUdGYmlCaEpncmhOaTNBNHdsQWVCU3lhM0dGM29UdGVKT2N5ckNlVjZJWk5Iejk0clJvQW8wMXRJS2FYTlhIQnV4c3RhWHAycXBNN3RSWkhuZmNKNXY1eXQ2QWZSeFlIQ2p1YTl0eHFGR3lteDc3eG4wREhwSnhEcFNiRGlTYkRDTERFTmpQYlZNNXpxRjRiaHFFeXJPenRQSGZSdEg4MHc0MUZsRDNsRFptODVTNFljVmRMbG5PTlVlK1BBcXhoZ3crcjZSQWd5MDJNUitUbG5GMEIyOHJyZDNTckZzOTM5SEczTDQ4OHpQWFNyYTdKZExMUE5CTHdoS1JqRFRLbFpOV2NvbFNuQVdDeTFtU09GNVhxcHhaaktTMHNwd0pRM0VYNXRONVNRYWtIU3N6aUwzTkNWZVV1dVpHOWd6YlJzWWsxelN5ZEp2SHpmY2VWcm04UXN5bHRsemxlVU9hR1Q2TE9xK2hXMmMrckw5TDUzUmxoV1hMVmtJeWlUcDVHam4wdEZhNVpXemNBNW02cDhtTEpuYU9Gb2EvZW1yS212a0VIcXJCSTNYUDFzMVBBSlppWXpFTjNFcVBRdllSVm8zelZ5RWpVZGNLOCs3bVhjYXFMdG5zaXR2NDlSOURyd0Y0dFo1Z0ZQVVFLTXJNc29WSUM5TXZNNjBseUtjZE81OU9xdWJlWTY4eTI1WVFsMzZKb2hZWFdyYWV0bnBTak1ETHZvTHpaYjlhY2pFVEtFMXpwTWJuTFl1cUd1MHV0S3NnMG1QNTU4dlR6OEh6dnBQSnNUN3l0UFJid3JTZXowdkI3a1g2NVpKblB0cHJaRVQ5RWtxWkt0T0swRkprc0xuOWNBWW8xWHQzcm9lYytzdzEwRDNrYXAzS2haVWk1THkvQnRJdm1WeTFiOGY2L3dBczVwdTRXNFF5ajZQTU5BT08rZGRuenRCSlpOd0p5MmMwckZWNjY1NXZ5aGxycW9POTFJbVJoYkR5K2NyYlhyclNadFc3QUR2YUVDMFZ0Q2dncXhXdlVuRlM1N2RLVXE2dkxxOWxMcTlvUzFhaldJcHlNN1h6blZvS2xDbExFNkIxakwraWJyRE5hTG5YaGJ5bXo1NXg1MWRwUjNTdmFzN0t3TGxCWlBjMC9KdHpmc0pqYXVmVjZmeng3clFEU0dpcFVic0tUV1JFZEJRVlJwREpMQ3NGdktVYWVuanNoeFk5Ym5RWExSUnhmUVNUc28zbkJoYkdVMVVldmR3OStkOGZBOUo1NnBYWkEwczlETE9LdWlyS1ZKeStteVRwNXV6blE0aytvbVdnS21sazJ4UlpHRkhwelhxRXJwZnJOWnpvVm8ycUFlNDQxclpVaTBYaEVDbVZ4b2w2T2MwTWdKVVR2UFVObkdCN28rTFc3QnJtSFJWVzB3S2lISUpjeHM5QWRzM3Ficmd1MWJuT2NDYzVBNzJrQXRnOUcyem1sUnZhdmtUeGZ0TmZ3dXhHL29sT2hub1ZNTXlpbkw1aG42UEx5TjUxbEgwNkpJNmFSaDZDM2V1UldIY2pZUUk2N3djZlh6MUdRYlF5cXo5UHMrYjJsdFRPMGNnbzZNY1dXV3g2UE1yVGxGVmgvVDRFdS9CM3NnNWFva3pVNVlBMlROTElJWlpjdm5uS04wQmpROWtSQ2Y0blJWWHJJblZ3Y3UwWmNxeEpSS2FZZ050SFFzaHFKQ3M1amtySFJWeU1oeDZCRHpDaU5IRFhVZEVEV2pkK0RqTFY1R1RrNGljN0E1SkFra0R0cWRBdGhXUTB4bW1UMk56eUI1djMwOHg2TEhwNndEdWRNNW04dmE0b1ZoVmthUzZ6TmxGbGNocENYcE5zcUViQmdhV1NRTkhidzNEM3R2QWUzSzE4eHJLblJSVFE0TUlGK09UQ2lDeCtxaWh1cm52MWRoRWtnNnF1QWw1MTgxNUM5T3BpMWg1ZTJyeWlCbWFzd285bm9jaGliWDFVYk5DNGpNRUFWMVEzbUcxa282V1hzeDFWNTdYODNyMXgraVc4WTYxdCtYQjVNR1VLMWJsWlZrcklGZVc0eXZMY0Rra1JPU0JKSUVuWUU3em9kazZFN1hpR0xES25iMUhrOVdOUFUwSGZMcTBTSUZLRm81M1Eyc2xIVm9CTzNtTnpNVjRMVlNQbjAzc3IwT00ydGplMjh3czhYY3d6dlAzK2ZuT0xYU3hYOEFBeFhTYzZXN25LWjM2ZzlMZG5ua3IzaVpaUzZjeE5wSlB6MTZVV1pReXJLRURSUHIrVmVUUk9yb1RxMFpEWmV1UjA2emhzRGNXdldGMDlzZHBIa3kzSG1hR2FQRTh2NkR6RmNyK2poQWFzTGxXNXprRHRMVWE1eWNaYVY2SE9XcUhKSWprNzBPZDdBck84Q2Q1ME85NTFIT2Q0eTdLNVU1eTRVL29CY1hmNSt3Qm5oS2x1V3UxMGZGUjZBMW0xbUxwdUFWM0VsTFp6WGFsdEpCNEx5ZE52R2VIcjlYeVhzRnVYRFlhZDQwYXlGSTE3ZGVQME1xaHVqa04ydGhpTU9JTGk3T2JPbVJTd25oY1hWd3VLNjh1NjVodDdiU2JpMkVkb2RLejJOYkxmV1NJSjBDTUNkbTRQcUQ1ajJBOC9NWStubFZ6Y3IydEZhOTR6a2tEdGJWRlN0dU01TzhEdkpBNTJSRTd6b1N2ZUJKeUIzc2dkN3pxT1Z0eGhETHRTNmM0WWZvL1M1SG8rZm9WTzRLZGNnOXhORXpHODFvNFNXTXl0SUZHMGd5a3p1eVRLYjBjYnRpczFSNUo4NXZhZUEybFhyOG9HZXR1OEQxclBFOHRXUDBTUyt2T3laTmxuZThNcXlrOXZOblRFa3N1Y0ZHYkZLck1yTW9UdWlxVGZkeFhYcXI1TEMyZkptTnhkVm1ZVm5NQVRMMjExMmxOY2pjenF6OFZpNjJWcHpWcGFqT1Z0Vm5KSUtWdHdLY2taSk9vNXpzQ2M3d2M3emdweVFKM25RNzJSSFpJSE9kNHl6aWJjc1JSMlQ5djdEQTBPZnFxc1RLSzNjNXBjYVN6QkhLMGxYRUpZNEt3WkJrNFhnTEFQeXJEazYyT1ljbkx2UGVFTUU3MzZLT2FBZDRSN3V5NU5jVFU3eG1qMUpoQzJkNkVzVjVpZWx2RmVSYTlCZlZZbWd3T2RNWGFMU1JJZzhrMTJjYldWTHltQTZJd3RDV0sxODZjQXA4clJVc1p2YXZINThpK2hwZ0toUjBxYzdVSk9kYTdXM0FIenZBN0pCem5ZSE9kZ2M1M2d1U2RDZDdBblpFU1NCeVNNNjBxMUxwWVpCL1I5cnpUT0hUcGVkMXM4cHBDUlU2RG83WEttcXNqak10SU81MDJpZFZzNnV1d0ppQ21ubnZJUmc2NmxlanE4dGMra29xcHc2Ylh0Q0I3cm00Vk1sUzNYbkFlTFFVZERORnpsak9PcVpLcHRnTmhTeWJDNUkxZW9PakdEVnhTakQ2c3JzSzV3VmFDRkxiekhjNTQrQ3oybE5PYm9HMW1DcmV0S25lZEMxYmNBVTd3T2RrSEpJRTUzZ2M1MkM1YVFKSkE3M25VY2tnY2tnV2FWY1RXT0JnZnVZcVRMZldWQ1dOcjFIR1RRem5ESUl1dWtkejlqSVNpenl0dFZMWUFOUnhjSWpaYkN6a1d6bE5DSU1rUXpNMjZva0Z4NSszN2FVb1NzYU8wam8wemRwSTZXeG9sUVd5dW81R0M2WWc2QzZLMXV5bkN4YXVWcEk3WHQzbWtCMnEwTG5FY1RSZkgxVFJLd2FqNTFSL1AwNVlJMUdBb1dqQTh0eHE5YjFBWE84SE9kZ1R2T2h6bHVDNUowSnp2QW5lZERza1JPU0J5ZGdkZVNmVFZkVzJFYktlMHBIUUYxQTg2YWJPWmVYUWRJODdXU3BXVGo0TklXZDJYVkc4L3RZcml6K1AxMHhsNktZeGxIWWh5MnI2UVBKNVB2c0lQTGpjM29XM1ExZEVHMGdNdjVMZE5zaGlqRHhrQ0Uya05ZMHpMTUtnSlIwMDZaMW5RR3F1blJJbHpnbXlGeTBFVmZoYUl5dTZLeTBFd2k1V0hoc2gxZStaV0VBMXl2YXNGeS9HWEdVQVU1MkQ1enNEa2tEdk93T2RrQ2NrQ1c1WVVyM2lKSkFrblF2b0lhVXNIbzhYMkNzZmJ0clFtWDlDOGFUNTE5c1VhcERPSWs5MFhoR1p6WEt6aWpIRTE4cC9QYUxJMEtkYVdWSWgwRnFodHNqV1RRQyttUE4yL08zcGZRT1dseU9oYWhIcys3cmNtZVV2UW5MS0JTZzFaS3JhRk9JNlNZZEF1R2RqanRyMWxtVzRwR3dybDBDbEdyWjZpM0JYZEkxcG91Zm1XWm81OThtbTVoZlJhajUrSFl5Mmd5MEhGamdIemtnNUpBNU93T1R2RXBPUnVTUU8yNUVwenZBa2taT3pxQzZpR25ETjdaZlZuWWNNbk42K09EZzg5ZlN5dzQ0bnFhY3dGMzgzTG82Vmd0UlhLMnNlOENaNTFwMXRwWjJnbHlvbWs4YnA3VkIyQm1rQ3E0c2xuemhiZi94QUF0RUFBQ0FnSUNBZ0VEQkFNQkFRRUJBUUFCQWdBREVSSUVFeUVpTVJBak1nVVVJRUF3TTBGQ0pFTVZOUC9hQUFnQkFRQUJCUUwrd2ZNWWVhL2tqTVllTlFvMnlLZmorRzQvaVdoT1pjMzIxZk1wZlpSNVlFYThzQmh4THp4ckZHWmdyR3hZTENGcktiVGpXYW01Z3ZJWGtGUWJObFJnSTdyaXdFS3hQWFl1MVZGUk5kcCs2M2lIREFnaVdlc3JJMjVXZHNEOXVMQmhIVXgxOGNZQW5sWUNGaTBNQnhZaW14ZVVNU2ovQUc4azZvbGZYeDNNcmM0L0l0WGhtc2NJdHV2OU13ZnlZQ0R3MjNuNURESy9oQTVFRm96bnh2NTNCak1Oa2VLY2dzQk1pRVF2aHlBeW9vRVdwTVBVd0JiTVlCNXllSjJRR3pqMkM4QmF5REJUdldhcTFWNkUwZW9pVlZNWUs2cVZ1eVVzUXdjZ0VXNjlYR1J6YjJPbDR0OW5sakRWTERMV0JXdkRQZWNUaU1TZVR1cHFyYXRycnlTamFDeHUxSFFKWHhtQnRmeGI4Q3R0aWdDMXU1Y205ZGFoVTRxUFdlUllpeXBHdWZrTWJWL2IySWY2WS9rNjVnWTdON1RPb1Y4dXcyajErdU1RZmphUEkrMkxURk1wL3dCZHk1SHNycitOcW5aVWJYUHNHOE1oZFVVcXlzR1N5b2djcmoxMlZveHFzVzBnb1JYV3JLYkRoN0wzQlZXOHNHMjQ5b1U2SjJjeXBUeU9HcW10N2RYdXRGaFhDMDhpeHRsY21VMW5Wa21DazVRMkNaV2Z1RzJlNHlvbDNOUWNpaXRKWUFySngxYVhnaGtWd09JZk5wQWE1aVl1d0dXV2xSdVgxZHVFaWwwQW5qUDlNZnpzOG54a1p6WW1Edm95dU1XbkU3bW1WZWNoY3pHVDBZaHRDeGJneGNES1poRXRlS3ZZWDJ6M0FWOWdLMS9OL3dBVjJxUmZ4QmV0RGFIVXVLMjBLNUU1Vld6Y2F2ZCtRcXJPUFRvM0tCM3NCeHdsRlM4bkpzQXlhaXdtdnRUVHRYVi9xc1ViVUtaeWppdFI0Y3h2Q3V3Vk8zRmZZUWYvQUV2Skd0cWJ0V3IvQUxkbDFVOHFWTzJXSDNtdEszZGFsTWFMeHZ1VGt0cks3RjAvczVtSllzcXpIK0xCcyt1QzllWWFtYzJKb3lPNGhzQ211OGs4bUo0bi9GR0l4d0hJWW91dGZZc3ZFc1loK081YXh2S2Fya1lWYk9HbGpWazFIajNWMlRsUHBMTGpxbG9Ya2NnQVNvN05jNHNjYmRLdVF3WUVWS3NmRW9RRXZaN2J5dGNsM3lWeTBzT1IrM08xMURJdG40YXNDeDJKYk1wVHRqRks1M1M5ck9xNUZ4eHJORDM3QURRdFl4bEZqdlh4TEFsRlpzYTI3WVAvQUZGL2d3ekZHSS9nQnN6Y0FsL1lueTNnSmI1MkVzMVlJTU55dklVNFloYlFHQWlYQWltMENINGNZRnJzRXFBZHdtUmJYN2NldmQ3Mjhoa0xObnJHODVlZXlvTTEzSmNhZ2J2VWcxdGZJNHhDV3BXcWxOTHBmVXl4Zlk4WUdQOEE3ZGwxMCsxV1JHYld4R0cvZXJTdzV0WlB0dUZEOGhRQWZsUXIyTlVkK1E1cmxsMlhYWGsxTDVMZXFrNWxBUnd3VmJXQ2sxVkRqVlZBVnJ1TDUwQS8xREI4L1J2RVY4eXpPTStESzB6TFVpb1NCOGRQbXhHU0tmYmtBN0xrbFZYWjdQWS9sU1BQa1R2S21tNFpLZGx2V1ZhdkdMUjdDelMyOSs1YWg3b3V0ZWd5eUkvR3FadVBkYTQ1QW9CZU1kRkttNDEwQ3VaMlM0TWhSOXducGJRNjc4Z0hQRWJMYkFTbnk5d0FZL2tzcDlYWXEwTmV6YXMwNUZIWEZiVmhkM0ZxMmZrUFI0SEgydHNyV2xmL0FORDdGUTYxUDVsZFpleTdraWNlaDdVVGlGQ01mMGg5Y1FIekdHUWd3TnN4MjhpWW5tTVFaVitXWXcyVnE4TFg3bFBtejhSUzJHbzhlUTcySEtwc2VoZ0thOUZZVHRBVzJ6MjZ4S2wxbHE0bkh0WnB5Q2RlSTIwNWRETksyMWZqSzJTeXM5V29heFNCeHR0V1VtR3dWVGxsUmJ4QU5MUWoxYXVoQ3RzRU9sekFpc0JqZU5EdGx0c0JlU3hXeTlubURaVnFnU3Frd05oM1YwZnp1YnQ2ZU1pdk9QWDJ2MUcydWxNc3haSEpMTnhIVkU1TGVpdDQvcXNJdjBNUDVKaGhjQ0NyRko4eXdlYXhnMkU3RDhFeGhRcERMck5vUGwzMGxsZTdDZ1p0cFRzYWxnR3RzU1ZjZ3FiU3RrZk03UWs0bDN2ZllFWGozMEEzT3Rob0txWHNSVzVMTFpkd3JoRXlhcXNpRDdxRHliczlWaU1YNUtGVTQ3RENNT21sMmxsckZsdE9qSHdxYUpjTWtyckJnd1ppSjJPUjlGc3hVUUNRNzV1ckVaZFJRY0JMM05ZNUlBejlxMWNKV29ma04xb1ZackxFcWV4djhlZjVHRCtHY2ZRbUVCcFg0VzRqR040aGNNUmczRWlWazdFK256QjRnczJlM1VUWmtIc3pMaFRrekRRcjR2Vkdlcmo3TnlHSURrNVZNcHNVUGFTYWFnV2RLaXk4ZFdyL0FHaW1VOElHY3FycXRwMktmL1FqamxsS2w1aUZtdFhSbjFkYTB1SDR2NERWMWJVNVhaSzZpTGNKQ1dLVnF6RzVwLzJ4V2kyZGE3TXpWY2RqWTdxcTJEV0hsdDE4aGxtTmk2KzluK3ZNMENyWS9paHlzdTJaK1BjOWJIa0wvanpNVEg4U1BvRytyZ1RlSXZrUjlvY21JK2pDMGFtN3d6N1JGS1I3UUY2OW9xUzFBSW13bHZzSzFDd1hwQWN5dzZwZGF4bGJIc3lCT1E5YkJobGxEc1NrV21Hc0dyaVU1TmlNRTFzcmRiQnJ5YVc1S3E1cXNwdUR5MWd3TmRieHE3VUwyV2E4Ym0rL0lPL0l4aHE3YTFqTkJhYzVteW1ldGRiT0duREdYWnZQTHJBZWhWcmxsdHRrN3JIV3l3c2NMMDJ0bHE1Z05OUnFnckZuS3NVcTM0MUt4VGRFVFphbzZKai9BQVkrZy9oajZHQTVnOFRFY2VWQmhocm5zSlY4eG15YktXV0FrVFlHWXJhQmNCbFIxcVhBdFpsaitRbVpjZk81WXFHUW9QYTByR1hCTmVEVmdsMVVCc01yS0MycU1IMXd5c2owbnFubnIvRmNPME43cWI2ZXljVjhXMkJRYnNJLzVMU1EwTkdwRmJ6YzcwTUJCdEVHMEt2MWhGTDIrSDR0YTYwMzFBM091dnR1Q01Wb0RPUWlyVDhpeTM3YW9YYkdnNDJwSjR6azJjVlZGWEZVaTFkS0Z5Rko4ZVNCNS94SC9CankwRGZWbXhNN0JSclB3amVVL0dWdExreTVVeWhUTjVxQ1N1a3lXY2VFN2dWZjJsV01lVE5acUpaV0hsZFFCTlNnbUtEMi9EV2hGc3VyMmE1ZFpUa3dzd2FnczV0TmdMSVhMRHBGaWVhK1F5Q3QwNUNQMVZ0VXdGMTdrMlYyaFM2NmtCdXVuOEZwWmx4NldZcXR6bHJTeG1oSXlRdWZhdGwwMER2eUYxalVPcThsZFg0N0Zic2RsbEZTQjN0OFhXN011RlBKYnhnS0tDcXRZK1NUL2pQMC93Qy9YYkVHREQ1aWZJYjZOaVlJSytSZ2ZUd1Rka0FiR1owQ1BNR0Z0QlRidVhxMWRXTlJkQ1RWWDQvZ2ZqTUhrUjJHU29jY2xHZDBadDNxTmpFS2xWTDlqa0hVMkRVVzdNYXhyVWRHL1o5c3M0MXRhOGZrcWtydzc0Q3B5a1dwbmNGck5kS1VZT0hDTGdXbmxLTFZHczE4RzR3bnVma0lxczYrZVA4QTcrZTA0bHMvVlNuVlUrSDQ2N0xZaWtiRklubVhQc05XdG5JSVdNdmoxRTYwYi9JZm9UOWYrK0ZBSU14RzhSWDhmbWYvQUhOL01aU0NNT0FnQVpQYXA5V0RxMHZXVm5ESWV3R3J5SS9naitETlBPYXZnRERYWTI0N2haWllGTDY3SSsxZXBzc1hRaTBzUmF1QnJyS3RyWmU0cm5HZG5ySk01bkZWb25aeHpUWW5JcXMxTktVSGV5elIzTlZsYThmTmxSU2Z1QUpydERiWXJVMTlsaFhXYkhheXRyR2F2VTJaRUI4YzIwUFdneTFkalVxMTNrKzhzUTF5dEh2ZGVPS3Fsb2o0TUhFTE1PQlhqL0kzMUJuL0FMSjh0OGxzUUVHSmpVRUFFYkVlQVVPMExZbmdSR0pObmtyNUhyTEY5V1hFUzdyVVg3SzdGUXAyR1ovMzZNQVphMll0akt6N2FkaG50TGwzTmlZcjlnbkcvd0JObVZuSFNiMXJMZXRrMkdyMUFtdXhVVzEvWkdYUEkxUkN1Sng3eTVaT3lubkx0T0kvdmFON2VNNVMwZ0lGWUlyc00wMU5ZUGV1NndGR1psalhLclgrMWRGZmRQMUtsNm1xL0lWK2xhYnRqUnVReHh4OWdlWGJ1MVRzWlhVYnBXQ29zNUlYK2cweG1LWmtiT01oRGlNNTJWY1NzNWI2T3hWdkRpd2tTc1lCYnk0YUlwajVDTGh3M3ZGWmtXdTdZVjV4dVdWU1NnWWZTeXpXTXk1VEpMY2h0VmNockxQRkRlbDd1RUdqcXVZeXRLdkNjZ2JuZkNJaWx6NGpLalRzd1F3U1dXR3hSVmhMZlN6aThrck1MMDJvMVQ4UzdNTDR1ek94U0txMDBydFVVbzFtOTFtMWJSVkR4cURxRXNGZk1aODhPa215dWl5VmNYcXM1MWkxeFF2VjJOVXRDc3k4ZmpGeUtqVFhkWTIzbitnUmtmaE1oZ29tZmJ4SEFhQ3c1d0FkOEVOSFhhQlBHb3hsZ3hYSmY1dDh3M3luMWkvZEpwSnIvYk9BZ1phN0cwcld3V0tUcWYzQWxnTHkxQ0J4QTJXZXBZOVllSnhraFVtM3h0YXBES1ZSY3JaRXNSWmE5ZGxkVzNhVWNFOGxBVzVLZ29CZllvd2VTT3NVN1BSeURzRUxjZTRNbHM1QzlpZzRLUXFXcVdzNlptdmhTVER4L1duajloYjdYSU5yMnp0TExXUzhScCs0ZFc1ZHJHaFhPMVljbmpKdmJaY0taKzhZbG1yeGl0V3Z0eTM5QStRRkV3QkdBYWZqRmJ6NE1XM1U0RGhWOW9maDJoemt2dEZ4aHJBWXlaQWJRcjV0Nzh4RGlXMkVHKzNldEVlREZxR2dCbHNVUng5MUt3cTIxNGFsZ3ROcjlhMS9kZlFMTDIwZExEWk1kYjNuZHVQWHM3NFExWGV1TXUvSHpBcTFybEVsb0ZvRmZyVWloT1dpV3BscXpYa1Y4MUJLejRwWTZuc213TmErVjlUTEZZaFdNNVJYdmJ4RnpYU2lrMmNieXRhTHFmdWNucVJoZllWbkRadCtSU2pJM1JvS2JUTCtPOWZIQ3MvK1UvVXdRbVBaQTNsckJxcjRqWXljWVZ6S21HMDNFdWFiZW5qWGNyRVZObVV5eXNpYk50K1lYN2NzWGVhQXlodnRWRmxhMGdNcUVTMXZUc09iTGMxOGp5b1FrY1RWSTkzdHlTR3JxZFJZN3J2YXpLV3RZS0xTd2R2TnEyeXRMZEUvSzlobGFnOWJPNGcrNGpNMVRja2JtbXpXZGRhOFg0bkVzV0c3Q1ZzcTE4alhzRm4yMVk5VG8yOXg4NkIxdUFYaG40NGJWcExUWnlXWnlrMjFpQzFMRWNNZWNVV3ZoMWdzMWxwczVkdDE3Vlg2ZnhNSDhCOVQ5REZNSmo1bXBKeXF4OHNLVVl6UTlwYVhNQ3RXRml0bVhyNFEvYmNncVBhckhwWWlxckViTS9ZRnJXTTdBL2tOOEFoMU5YazJNZHZXWDJzZ2JZcjBIVVBiVEY1TzVWeUg2aXhRMmhyM01zVTF5bzE3dmVyb1hNcDVCcGF4eTVON0UwV0VOY29zZFJvOTEyc3JaWEhYaDlXVm1kUXRuRzdoVHlIb05qWk5Kd2UwaDEyYzNWc2tGUnJRSEZWUUwyWFY2MlhNdFEySFFUaGFXME5tNGlUMWVXTzFkQ1diQW8wNDFaY0k5Yndvd2xsYUovTWZYNC9pSXl3RHdmTTZqTGs4WjhKWXdpWGdpNzNLMkJUWXdlZHVvWjNVcllkMmRrUGwxZTFwbG5saXNvN01xUFJDeE00N1lUYWlYMlpxUVN4c1N5MHo5MnhpY2wydmF3TERZZExic2hPVTJ0UE9kSnhlZUxZZkwzbG1xcnF3dDFhUFhmMWE4ZDFRVzFJYTByVXBaVlVTeVdNMXQyNlVKMlY5ZXFFK1MrczdQdDEydUd1cDdhMXFsYmVWOE5VY1dPWE11YlphcnMxc0NZYkJqbGpWRUJZTGp2SDU4aHMxNUt0Y3VpQXZaR1RWZUxvWC9VZVZXbFBFTmFyU2QyU3NhLzR2aUQrSmlyN1daaE9ZMVl3Y3pJd2x1ckJWWjdLeUNmWlh6S2lOeTZNMndsNllOUVlOeXZteEFvM1pnTTVMQnFsQldBOXM1QTFqRFk4Z2lLMHNkcXJlN1lyY0pZWUROcFMrRCtuOG9XUTl3TytrOUJFd1pacWoyVUhXeFdiaTZabFZkaUZyZXBVRlFyOTlhOXpMTU5BNkdLVGxqNkw0RnRQWEsvaXEzQnRiTVZtQ1ZBTVFIeFd1ejMrSHN3dFhEcis2TVBaLzRwclpaYWNVcm5LcWpSRFR4YUs4czVwYkQ4Z0pYeGVjdy93RWZVejRoZ1AwRGZUSDBLQXl4TUQxTVlhbEs5NVI0ZHRYQWJySnNBZ2IyRGdqWnR2WTFoR2VJMkk3N090bzBaZFYyTENnYkpUQ05uc09sWkc0Tm1EZTJ4M2hhRS9WVEsyOC9wbHpOVmRxVWNJcTFVSEZnZEc1R2NLeHk0cG5VcFowNjVaeE5GcHRWVkNuUHdlUlRveTFiVnZYWlZLTE5GSlJxUVNEVjdPN0VGdmRhRHJMTU5PUU90Z3pJR2ZFcWZZb0R0YmJZR0ZqWVp0NVQxNkRsVjFoODJ1VzBsdHR0aXFzdERDd3pNMm0weVBvRDlEL0FBTUgwSXpHeUltY0ZoTnZhMGJUcnlLemtXSVYrbkhJQzNMdEg4SWhBYXc1aXNjQy9BUzFVQ09GTnFDV0xFOHpWVmxPRUZaQ2dXem1XK0Y5RmMrZi9QMUgwRXIvQUMvUnJ0TGVUeHpiR3IxZWd1bzdDUTdmWVVoSnlBQzFDWTVOdkdyYUhqVnFwU25TdW02dVphdXprOG11eE9FSmRRanJkVXlzeVlzYmpzR3JHa3MwSnBPWmJVR2xOZ1ZIcEFheVA4OEFacUk5WFFCK29WTFl1b3FUdGJuT205VGVnY3oxNm5BMTRtcXRNVFdhbWY4QVNzMU9mSS9nejRPMEViT1FmRUxlWDFFeU1ETzdId1NJR0Nxd0JoOVQ4S3VMSzdmdVZvbTFWTlhrOGRKWlY3MUVZTEpvNjVtdVdVKzdEN2QxMnRYYmdYdkhiL0FJaHhPSWNQeDdqb3hEQ3V6c3Vma1Z2Rnk2WGtnMUhEcWhlVnNxeXl6QnZLeXUwS09WUVdia1UrUTE5Rnk4aTdzcnNDMmNsUVJ2QWN5b1lISTJDTDJGTmd3NDFnMDVZQzF0ODFWYXFTNHVTaXhpTEVTckZ0cldMMVRVNDR1dTExT0JVeHJqWEN4bVZNZjQzV012aGZoVzhsZ0R2aUR6TC9oQzJtZG1EYVBkaHd1bWJqNU5hbWNvd28zSFVsbUFndFZJN2dvRDcyTnRFNjhYa0dNaGFXSXVTODVWdVpTMnh2OEFMTi9BZnhFNHFtRk5vN3YyMlY0cE5HTFAyaUN0T1BTNWFzcXkzTlV0Vmx0MEhmbzFZRVcyczE4aTBQWHkzN0ovc284NUNxMFhpVkVXY1lJeDFEVWpLMkRzak9jQlIxdlNCWHpNZFBKK1V1d2JiQTg3MnJkTEhlVmpTcHZ2T3ZGOGRDS1RhWUxTRFcyNThwL2l6QWN4bjFodHlLakd3Wi8wbnpZU2tPSFNyeEdSUk1JNUhoYzd0WmhGTHNUUjVmazliSGpnb1cvSnh1eTVCZXNnVzFwMStvSGdnV0tpRkQyOGwvdDMvUEhQM0hJWm4rb2cvaW56eEQ1c3NDaklyZ3ZNb2JGdHF0cnh5MndxMnJvVlVxczRwWnYzTHJHNVNwSHZEUThpRzFoS3VicXA1Q05CeVVDam0xaW84bFdTNnhnZU0yeG5Wb2g5VkhOWnB6TTZIRHRaU3VyTTFkMktxMFpSV3RydlpLbFZWc0ttdkFhZFExMUMyRXpQajZzMkoyQ2RvaldlVmVNL2xXek1EQi9MeXBCaTVNT1FVeUpiNGF2QVVJTnJTMjFkWmlqd3VvWnhzdEM0bGxXTEg0MldaU3RTSE1VdFd3Y3Fibkx6WWhGZGhGY2RiZXBEZmM1WW5JeFBJK21Qb1A1cjg4UDFGcGF5WWpLZXZpOGdBWGNwSG9vNVBXLzc3RVBLOTYrWllRM2Z5UXZBcTEvYW9zdVd0UlNRWUd4WmNNMk5WcUs2cTdGWGpWdU9SVmhPSXVMQjVOM2lVdjVzT0g1UVljZWxkck5sVUxIcU5nL1VEV2tvYlZHYnNuWXBYOXhtSzRXTytaVnJoNi80TXVZMVpoR0RtVjVJWUhOY1N6YVkxdDFEakNBSTJJcHkwc1RKczlTdGh3bVM3ZUFqYlM1WXRyQXJibFd2YVZQdXJXQUN4dzBSeHRkNnl0eUplVk5aUk5VTVZYMnZDcTNOR2VOeUtXVmJQZ3hURytUL0FDRVdjUk1jZWdvYmJLK3RrKy9MS0VxbGxpQ0t2Y280OVNWMkxtR3MxaWwyWjg2SzMzaXd6QlhxRXpVUWpFc2gwclhFbyszT1l1WmF0aUhqZWc1RUZSUWNwRzA1UU9sUjY3VXI3VzVOcEVxNVhYWFZTOWpXY0RWRnJsbFVhb0NOV1ZqMm5Cc1VGK1ljZnhaUTBGV0M0T1JIL0dvWlprQmlEQTFCZ0FFSmJaL3hSdFRaN1ExRUJBSVVNdzRJZkJlOENQWjJWdlNkT01OVnNyRHpxUlp5YUlBdklxdHFOWlkrcDJhS1RTL1liaXlhMll6VmVDZU5ZdnEzajZHSCtTVGpWNzJNaG9wQ3NSaXBxNmFtRm5JZDJuVGlDckZOTFRrMUZhK3dkTlRnVGxNdGljVDRhNEpiWS9ZOXk1VGplOWVWclc3QXNERXZhQXNUREx5TGRRdHhldW5rOVl0MXRXaW9NOTlWTE5hUlN4MHdQWmxBRTduTHJjRVorVDJLcHNMK0N6MXJsZ3VXd3AvZ3hZTitVSHdQWDZNTWhVSUN1UkdjNXJiejJ3c2NaWW53dGpNTUxhR2dBellZZ0NBbGNjZ2xvdnlGeks2TEJNMnJPMkhrcE93aHdEWUg4RXNTdFNBaENLNWEyWjNsa0ZUWjVsUVM1bC93Q0pQMDZuUVBwMHU5aTExcldxTitKYXhCMm02RWJDbnhUY3EvdHVIVDNWMmNiUkhWMUlFcUNodjIrQWxJTTQrRmZrTTRqMk9EVXhXWHN0aThZZmM1Q0lyTlR2QWV0cWJnOVBGdHExUElURjM0Mk1YS1ZOb0VMbDBBaFFTdHlzd3dGU0d5UGFsVmZ5LzdYamhhN1N4Tmd6bjZzTkRVKzAyOW9UZzdBalRKNjJsYTZ6ZFRCOFN4TmhpS3MvNE1ZQkRMaGNhNFdxdlZybDFaVzhYZktONTVTK3pjWjJXdTk2SllGY1ZWNjF2VjJWQ3NvT2h3eDlaeUtTczZ1NnEyclYzWHgvSkpXUHVWRFdXM0pyZGtwWHQyV3FXUEZiZVd2dW9HR29PVTVRLytiaFdtcXFodkRnRWNnS1VINXBib0xGMlJHeExQVjFBc1ZmQmQ1d20wbkwwSTQzK3JscVdzQzlVN0MwTDdPV25IcU9GWjBESThaZHk5QmxGSk5scldXRVdOVkUrNHFmbTF3Wmc4UnQyWnNQdkFTd09TQmxZRDRadkJHVnJ4ajRoekI0am9EQTJUMkNGOFFPc1ErOTAvL0ZDVUN2N00xcFBjY3QyT2Z1cWRMakFia0RjaHRWdEVzVHVYcGV1TnMxTkxTME1IU3cxbXo3MDZyQkZYcHM1bkgzVHIrMC9FMDR4SDhBSXF6akROMWRZcm81R0FxQnluY3V0dHM0K01xNmFPWlRicGJaZjJEaEhzdHU5SlpuVXRBUGF3a1N0MkNqODdLd3g0Ykt0K3VKZ3RGZkl2UDIzZGE2NzNKTlZkZGxINmdvVjV4YXR5aUZWQkNrbktJd1dOWm94SmF1bXMyVDlxWHM2Z3BDN3dnWjBFNjhGZzBQOEFyUjlJUHVEMkJJeFBJZzhqSG5EUnZ4RDVVVzRWUE12VVRiMStDTWs3TkFtMFdwVm1tamZFdEEzcjFzZTBaU3V4aVFBeDYwQUNnTG53eHpORWpVSW91OWEvaHVPd1FObEoyYk5TcG5Wb1AxQnZWNjhRNnpQak1VcktxY3pocjkwV1BoUFkxZmhmMXFmQVJVZFphZ0V0WUdteWNkU3RGRG5mWTdNZkxoSXFpWHFwVldNR0lDMDRsWUZkYmEyV1lTWTYxc3pVcmZlbksrYXJXRkpacklaK25XcHE5b1dXa0VqV3VGbGpuZGFiV3JQQnRJSGYxRjNheU1HUlI1bVBwaWFSMHpGOUs5c09EdFBaVGo2UE53cy9LTlhoZXdpZG9lYWUzU2MvQThDVmZMdmlNMFN6WU9RVFdTajJuSXFiUlRiZ0diWW1jaXpNSUVVNkd3YlZXSTJYZkE3eXlleXZWY2M5Q3RPWnh6dmVwREg2b01uaW5ybFZXWVBTam9iQ3BpcGpGeTBLblVIMjNQVzUzaU03Y1pDbmJiNWxWc3ZZZGRKSmZsMGxWUkhEOFdvV2dEMVVvenV4TFpzZGFIOE5oazVJSzFNMnFjVE8zT3A2YkRQMC93QnJYVDd1aTlQalhob0xpd1ZKVG1LNjAzYjdyU3lTMGhnYndEZ0NCME0rQjNITzJGMjdBdGNyQlZHZjJEa3pZVFlUSHNIRVhPclpTTDVhdkVkeUd5SGpLREZRbHVSOHBrUWs2STMzYkUxRmFsZ3haYmVrdmQxTXNLZ3dlSTdaaFl6UXVNczVhb2E4eFJQL0FNZHpyaHBTV1dya0tUT1RVaGwxR3NNQWlrQ1YyQ1UyQ0syR1JzQjNjbTFseDJmYTR6Sll0dE5lN2JCVWF0WlZacTNFckQzNUdiR1Zvd2FWa0JUdGNpN2JJU2pkdzBaQTZLWWM0MmJOZm11d2VXcTNhb0JUeTdhcmEzK2FITmRqV05EL0FLQ1p4MFlTemtpeFNLdE9wVmFvMWlNU1NYUitPMlZKd3dXb1pMRVBaUzBBWUNwOEVud0RzTVlLaU5sR1k1TFl3amhSdXlzek0wWENCVGdqTXpvQnEwZG8rU0t5UTdmalNrdjhoRWo1aWs3c3AwQUdPdjFyL0t2dzJ6Q2QvcHlDZXhRckpkbU9TMUhBUTYzY3Ftc3Z6R2FjbCtTNjJsZ2Y0VnVWUEg1Y1ZpaHF1OVdwd2xaWmxmSVpiSzJsMnpOdWEyNURFdlMrM0kxRzZsU0xEbGRSMSt1M2d5eVhWaEdycnhEVUNiOHdEWVpZSzVQWlpUb0RpTlUzWGFQTmI5Wm94eUdOWFdMTWJhZi9BQ3NRc1Q1YmJZWllIMWo3STNlczBJRmJtRzcyZXhnVllzdVBQc0dFdi9Qdjh2OEFjaUxrMlZtVjErdlVNTUlVaUgxQThhK1MrclY0YURLMmVTMXU2U2w4aXUzWm5ZNko3VlZGZFJoWTVtNmx0Zlo4Q1dPUXBwSWxuNGNxbnFldDIySEdZczFheDdBZzVkdkxlT3hNUDhsT0pSZnJGMks5ckJhVHVBcWhmaDFiRFBXV1N0R3dsK3JXTmlrV3NZUHVBdHF0cE0vS2E0bGJhVzErU3c5ZVFOWXA4dFZvN1lVOGhpQXI2eExNVDlSb1ZST0Uyc3F2RHMyZE52dFdmZXRZbFpXclBCWG9YRURHSllEOVNvTUF4RkxaK2hKQnVQMjVWOG92cS9yTmdxdVJEbVZxU2ZVUnRvQTJUVjVQcEtzeEdmTGpZQ294d2F3dGpCbEJZaXNRT3U5L2dWaUE0ajJGbTE3RnYyTE5XMWdUaTRnUkVMV1I3Slk1eHlHdEJzZmFIK09mb0RpSlpLK1daU1Z6WFprMnRseG5LS2I0TjFESnF2Ym1DMzIwYkp5WTMzR3Fick5yS3JOK2RhdGxpME94Q0xPM3dTdHJ1b2dVYlgxbXMyMkJxWlF4VnFOZzNZR1cvUFdnWUJ3Q2FHMVJpZ2pNSmFWYUprZnllM1VvK1VaOWtGdUEvdXlnUlBFY3VZUTd3emJ5dTJ5cjdaSlZkcDdCbmNSaThWd1pybGRzUTVJWWRiSmVFaXV6TlI3bDdjRVBoZkloWUsxS2VNQ0U0aGFXTkxMSmZ5TVMzbEdQZXhqTm4vQm1Bd05GZVY4Z2lMY3RwQWFmcC96YW1zcy8xazVETm1Fc3NaeVdyWmVqayt5MXF5dlpXZGFqdkI1WlY2NDdlYXF5NjFLenNQZEx4V2tmT0xQa2VXemh1Ty8zTFhIN2Q3Vk5XS2xRVjFQV0t5UXdNcHI3WmJRSzRsQ1AvSjZ0ajFrUWZQWENNRlU5N0RpYmtocldpc0xBZU1RS2wxR2dnWmNOWnJOdGdMSWJBMFpVU1dLUk1HWWVpTTZ0SDlwMVlOSFpTeXRVOTlpK09PYkdMVnFUR2FGcFpaTGI4Uy9sNGpYNUQ2dEdCSCtRR2JSWGxYSWRJbk56TzdaUUJFd0xPNUE1NVNnMk9YZ0xJT0U1emNmdjJlWUFvanMrYTNVb3FyaGxNT2RlTHFHNUNxdzVKOVJicExxZXB4bWNHeFZQN25OZGxieXhXc0t5aGxEOGlyanRXbEkxc05yT0NRZjRnUXpFL0psclFGaDJUT0lFQkdCVXExKzl1VktQNE9jaXhZOWl0SHpGM0FWOVZzQ3RFckxDeEVVZytIVU1xVWJxbzZvY0VYVStGcVV6T0lXaldpTmFKZGVBTCtUbVdYTkdmTXpNelkvNWN6TVZvR2lXWW42ZWFtdHNSWlZRdTdVZ1NsRjVBczRWU0p4MFl6a2tDdGRtaEhtdTNLMjhXdGxPSnNyZytaUmpGL3EvTVh0UTFrR3k0d040NHFpeTZ2aEtodUpBcFF1OW5HYnRkQ3JiVjdLdTY5dHlxTEs4YmlBNS9oWVd6OUxtMFlWa0tNcUJjclJTWHNkUEdBakxidkZ2QlBiZ09BcWJFeXZaUnlXSU5kb00yekdjNDVOb0lEbk5Pb1VPU1dJV1d1b1MyN3Jwb2EzVnUweXdXeTd0V0hrTkxPUmtQWm1FL3dCUUdCb3RrNDNJTWEzVlh0N1UzeFBVeFMyMXpseldUWk9SeHl0NitoYTFnZ3E3Vis3Ukdac1ZwcFhkbzhzZGNmTmx0RmJLVmlFcTFQSXQ2aHVBZVE0djVHeTNjbXBnTlRNK1c1QUFMRXh2ajhmNDRsekZaV1ExdGwyV2V6Mkw0RkxxbGZhWVh5UXdBMk1UeVBad3BaRjhUNUdwYXRzdENnSzlDaWNldXV1WGNnWXJjRUxaMlQ5U3VLemlWbGtMQVJuR0MyWnplUWt0dHpDZjY0K2dNNGJpMmtqSVV3WGJCcjJaRnY4QVhpZUZXL1lXcnFXeUJXZktPdld0ZVg1TGxWb1pFUEpLYXQ3QUQzdkd0a292MTR0VHZmVjF0MzhtdEdwNUR2VlR1VEZCc1BGNFBrOVdwK2ZtTDZuK0Q2dEdPR3BxRFYzS29ZbVp6T3FwQXc5dGN3SjVRQ1Z1UWhzTXRZR0JkRlpHaXFtcDFqb0hYcEMwYkNzVTJzRlp0VXRYdDVCL1VVRmYvd0RRWjJSMmVjN25lSGNrL3dCaGZyK21XNnZpR0VwTXRHd2dCRFJ4aVVrdUNQTEsyQVJyVzVyZHFtdHBxcUptRXJvUkZ0dkhEMWY5VFhyNUdaWHJPTHlYUk9WYTJPdnNuS3JDTW56U3lpVVhBaDdDanI4d2pZSWZyL3g4aUV3V0VBTVRETStUYTJBM21yVXd2bVZpVk43dXluNk94SXBabWw0WmJRSUZtRmdHUXd4VzNtcmwyaWJuSEcvMmNubDRxSnovQUdoOURLaml5azk5R3VJUU0vSXBYWXQ2czFhNlZsVmhWVEQyTDlLMU00ekZyMUhVMTV6T0h1eHY1S1RsVWZ1MXRYVmw4R3F5bGFxNmtzcXR4dGJRN1cyY05rbldqS2VNUXpDd2xmZ2VKOFJoRk9SOU9TRDEvd0FXK21jU3BmVlBqT1RXRlN1OWNOSzYyRVlacytRanZLem1XSEpjOVRmcUtGT1Arb0FKeG9IMUg5dFBuNGg4ajRiZ01SS0srMmFkc3VUMlZteHhpTnkyVEZKbXhSbjlpcHJhSEtXbHlXcDVXYjlDYkxhM2NWWHRUT2NGWjJuRThwVFd5MDJxKzcyalh0Y2kxanRYdFkxbXFxSjhnUWVJM3F3T1FmaTV5WmlFUXduNk1ZZm9vd3EvRURTdTFkdlY0ekFudFhMbHM1c2FyRmlJcnNEYTI0NWphVWN1dzJWLzREL2dQK1ZQbG9Jd242Y0FYQ3VscWw2N08zSUtBempCQTl4Q3V4RzIyRzJPd3Q4RUswSzlhM2U4cUJvdmJsN04zTUR5YnQ0NzdKS0d4WngrUVZxRGcxOHZ4WWprTmE0TXQvSXNXblpnZzVuelBtZitnQ0RtWG9wVW1aK24vZjhBaCtZQWR0c2dUeEEydGhVTTdtd1FOV3NldEJFMXhiWTZ0czF0YjlTUkFwbjZpZnNja1lvUCtBLzFWK1crZzh6OUZyMlRwY05kUW0vV0xJM0ZBZllWdFpiMmh4RjMwSGlMZ3N6TENmdHQrQ1ZJL0h0QVdMbFd1V3JWcTlVUGlaODhlOUN1aU0xZzYzdzB6NGRNekFoQmdzS3hUNE1YekRtWXNEY2h6dE1ScC8waU44NWcrS3ljOXM0ZURYWW91QW82NEVWWXVDL0k3R05kbjdjV0JyWTI3aGtVTHVLNStwKzNHNS80ZjNSRDhRVDlMWmw0ZmF4Uy9zTGRwbHI3QXFkbTNzYlV4ZmhQaGZlYTRaMkd6UUt3aE0rV1pmZmtraUdHQ2NhMDFyYzdNZDN4bk1zSk1WWldUTVpPVFB4QUdBRDRPczVCVWpFeENzd0paa0hWb0VsWEV0ZVc4SlZURTRhdVIyNnNuSU85cFV4bDNHR1ZHWU5HejJkYlZ2OEF1dDN0OHk5US9GNXJiR0grNElmaUNmcFNELzhBbC9LUHN0Q01iR3F3YXUwckhPWFloWmtaWVJWd0NmVmhtQVpDK3B2aCtUNWxwQkR6T1lQSlUrTERnNzVCVWc1d21jUkQ0VnZMbUZqQWZwYmtuNW1JZklZZUthQ1IrMkRXa1VxSDRvRnRIcldGTzdDb1IwM0JHcktZTFRGL0xCZHRCU1A5dHJNcmhVUUthbGV1eEJXbHZtcy8zaitBK242YTJ2QTFVUFlXVmJzQ0k2VkwyZTNRK250cmc1OG0yTjdRRHkwclNiVC9BSzVKTEJzSDZWWW1jUUtZd2RZdG1ZRG1OZ0NKNUxIM1BzUXhFUStBb3lGVEdxbUZWbnFZZFVoUGdBYk00QmFYYmxkTDlxdTZjbGNOb0dXa0pSU3JKTGtaTHJLbnlxbFhzcWZzcWZSZHIyUEpBVGluL1cwUDh6L1cvd0R6SDA0bVJ4ckdaR3NzOFBWWTlhMWtoOEFGeGxUZzIvalNkUW50TGlaZ0NXWmFLL2pZQWt3TExJWi8zamNmc3FzUkZnekFnMTBYYTZsUXRtdUlERk9XOFEvQ09abkVIazlnbXdNVnAvenN6SENxUlo3RDhOR0FydEtsN0doclc2R212czVpalBIS0xYeVNlL2tsd3RGcFNCOTdSZXFtMWlWNU9uN0Qvd0F0Q1BIOXdmaFArY1ppaXF1OW1pNXFjN2YrbUFZWUN5cWd1ZjFBYW1rSEJ5b2RZUkxCaUZkbEtFU3B2UGd5MGdxeG4vZU9mdDJaeXZpVldESkhtYW42aUR5V09xLzh3QWd4bHZ5V21XYWlBREF5V2F0aXZVYzFGakRhWmhRR3NETnVUT2tZYVYyaXN0Y3pXSldydmRTdGpnclFVODJXSDB0eDFBNHNNLzRmNUgrc240eXY1VzVJbHdzSTlXeHNDL3FxK0xQbmo4b1ZqemRPRldIcTVJd0djUEIrRDVtUFJ5dWlDT3JiYkVRL0krYXpnYXM4Q0lWYkdjdFBBY3QvSE8wVVpKOXAxZ0d2R3IzQVFBV1RxOE9WVlJadEN6OXVvajdUY0pXTmMxNkNOWmtxN05McTByZHVxTWNjZmk5aGloYlN6cFNMWFhYbFB0UmNOSHMvTlkzOFJEL1dyamZQRVhhN3BBU3hmTmJFcXRtc0FUZmRldkpsYUpIQlVWUG9DV3RaRUMxNnhhdHB5YSt1a1N2ODZsUzE3a3d4bUpUOGxvT0x5WUU1SVN3c1dNOHpIOGFGelBJbHZyRWRvNHd0VEdZOEZQVVZBUTRRWFhDVjNyakpaS2JDalljaGZCUWhBOXlOT3NxVUpKUnkwYXpyWEszUytuMkEzbzVTNVEvRVAwUDFFYitxSlZIK2YwenczcVE5VzBHMWNzeHJ4N0Jya3pmRVkxc3JXSE92dFVGMjE2NCtkZU5mcE9UYjMzVytyTDhrNE9TUTR4OUZuNk9vL2VzdkxoVGxGdjE0TCs0cEN0WiszcStoK3RRekVQcm9ZcWVRZ1dXc29GZG9MRmhnWDdGN0NKMTdtMnNkaDQycTBnb1VJVysxdlZLOXgxK2VtdEdmM2UrcXNyMSt2SjdGY2pVVmh0VUFVUDVqREV6L0FBUDBFYitxSlJMUjU0Q2E4Y3FwaTVFVGlOY0xxYlZDYks0N1hqVU1zUlYyY3plc3d0MTJ2ZnNXOEhyM3NJME5oaWpJS3lsRExLbWFDaTB5c1paY3FxMjJRdmNJL3VpRExVc3cvamlMNml0OXZyWlNIblNhM1VBcmFpaGYvS0I3VlBIVVJpeVZWZzJUcnhidHBaYTFyTHhnd1IxUnJXeFRPNzFTcG1qZ3E5MU1Ya2RidmJ0T1kzLzBiN3gwd2ZxZnEzOVVTaVdqTXByWHJjZTFYc3pLRVIzZVhabklzMGp1ZWhoc1BPd3dJN0ZXVUJvM28zaGxzczFEZTByK0VpWFpWcmRMQnlSMlZXYXN2SnhQM0VzNU9aZmRzZ3dIRmoveFdMcEs4WUxnUlRrTTNnbUI1dms2ZWRQQVYxYjhvLzRJU3Bhdjl3MjNRaWNqc0FKVTFoN2FxenRMTFFEMjdETDJJbEFZMko2MiswYnhPS3dlWGNVNkVRaitCL3FyS3BXbTlxVXNMTEt0a0ZkYUI3ZDZpY0I4czF1ZGF2enJYMXNVR3RSZ1BWbVZuVXY3RFh5VVZCWjhwa3hUNjE0bklXRVJWOXZ4Zk0vOHVwd1lCL0EvV244Ry93QnEvaTBlV2Y2VStGbi9BSGsvaGY4QWpYTFQ3andvL0xpLzdHbFArbFFJMzVXS0FMVDlqSjBxL3dEOHQzNVBPUDhBN3VIK1BLQUZ6ZlUvMWtpL0g2ZlRXT0dqSFRZNHRKWjJkdGE1WjRTVi9MZkFBL2IzZmxWL3BjREZuK3F6NVUrclN1RDZXZjZURS9Kb3Z3MGVOOHI4Zi8vRUFDa1JBQUlDQVFRQkJBTUJBUUVCQVFBQUFBQUJBaEVoRUJJeFFRTWdJakJSRTBCaE1rSnhVcEgvMmdBSUFRTUJBVDhCK1JhSmpSUlJzS0kvMFNyazhrNGsvZVlvVjhDd09TNkVrNDVJeHN1TVdPbWhSWXI3S2xZbmtVYlp0YWVDRWFsWktqamczTGhFb1NVa3prblBhaVZmTWpBN1hBN1l2b2JvcDNaTWpKeXdTU2VDTW1oeHA0RmNSMDBTaldTTzFRSlMzUXlLSFo0NDV5TlZ3WVFwV3ovb2FMc1VIOWttMDZKTzhGS0k1bHFqelNzcDgvTWlyRytpMnNFY29hdFd5TXZvY1dRZEVWZVdSTHpRMzBQQmpjUGFoSzRVYnF3T21xMGo5dlc4NUVUc290V05XVWgrUHMyL2tsWnVpbm41MUpqK3pjSjlrbmVCTlJPUnFQWitUYndlUEk2U3NsYzFhT1ZaZ1p1YmRDZXgwU1haQjVIcEVjZmRZcE9oU2RDV0NjU1JhNEc3Uk5QL0FKRkYrWDVZbkRLT2NFMTBiYU9NTWNSelkzWjdheWVOWUpwdkRIQ2tKNEtvaVNXY0NWTWs3UkNSeU41cEhCL1NJM1JHUXNjanl4Skc1ZEVFcUV2cjVFVUpuSTNSZGxzelJ0Wk9LUjQ2WjVJSGlib2xKSWk5eEtic2Z2d2JXc2tXckdrOG0yeHJheUdHTmlWRFp4d2Q2U2tRd1A2UlZSRXFSR2RmSWl4TVgyTVMraFBieWY4QXBLV2tYVEpObmpsV0NOTmw3ZVNMc2xETm90M2tkUkxMcDJPRzdLRmd2T1JTdFdKMlJWTWxGUjl4dTNaS1RJTlBCZTNnYmZHaVYvTXRMd1F3ZVNObTFqK3RJamk1SGpqWTRMY2JVME5ic0RiVG92ZGtkVWJleitvak9pN2VTUkZHRndJbkZVUXJnN0tKdWtQZFl2Wm1UUHlUbHg4aktFY2labG5CN1h5TS9IWkNHY2xZSU5HSllFaFNwa1c5dzhDaXgxd1hTd2NEamVUZjBJb3dTL2g0M1R5Ykx5ZWFVK0VRV1BjVGxVcWlTMzNrVS81OFZDS0tlaVJ0K2hPai9RNC9SRlJHckdyNU15UDlZWTZpaU5wNU5sY0hXQ2wyWDlEaFlsMEpKaWJnU3d5NzBjYmRzMlVUWGFJVDJqdDVGQ1Y4bmtnOTZvYWZSVnZQdzNxaXVoUnBtM0lrYmNDV05GZ1pWRFpadlpHRzUySnVpTEs5MlRJcGREUzRObzRxaWFaQ1ZINU0wWDJiMGh5c2dyVm5HV1k1UDZMTHdTeno4U1l0T3hEUWx0eVA3MDVKU1pZMzZJeW9YbHQwS1NvaEt6TWNFNTlDbW1zRVBLOG41TnczZURoa1NUSXUrUllJU1NSZGxubGxpaURvZWVmalJXbTVJVE55R2x5SmxrbmI5ZFAvQUVpTGJSdGFSSEdUeVJiZTQ4UDB5L2NWdGlRMzNiTnFGZ2JzOGVHZWF1aCtNalNKVHNqTEpDVk13L2hhT2hQUldWMEptMVBJMmhsNCtEeHJBb2JpYVhCT2UxMFhMa3V4ZUZjczJ4WEEycTBrOFlQSEg2STRrU3E4RGRJcnNiSDRsUWxJejZraXpnUi81cFhRMDBaV1NMYjBTb2tySW9sNjRmNUhMYndOeGx3T09jbGJzRDhkWUVxNTA1UkpkRktyRkp4WThjRWVSekp6M2NEVDRNb2JOLzNyUXRHVUkvZ3JLenBHS0h4a3BpVEZ4cHROaDVJYmZUNDQyeUxrMmJxOWlJeHBrb3lGT2xrZzAvY2hqZG9xNVV5U3BsMGQyUExGQkU2NFE0dE05eXliMDBST1NMWFpzRXFHa0k0T1JvVVd0ZG9tK2h4dFVkVWRFWFFuWmJMR2xKVU5lanhjSCtlQkxOazFrbmRXS1A4QTlFVlRJMVIvVWVXYXMzSnNhUnRkbk1zRW0wOGlULzBTVG1TYjRJUkZkMHk2ZWlZNlpXMHMzRVlsSm5SZG0wU0lLaDNZNG0xczdJMlF5YmNrby9ROGFwa1hVY0RYMFZ0RkxkbEhqd1I3WkdwWkVNYTNPa0tDR2NqV2NERS9hVzF3VmFzVXFMYkpUcm9wQ1ZGRGJNRzBTMG05RmZCMFIreThIV0J5cklxdXkvb3BvU0hMWWlUM08vUkNXMWllTFExWkNORXNDNXlLS3ZHbEZVeVRjU0dlUlhGaWRFdEZGaVZMUkNnYmpjTmwySWxnVFpMeU5FSk42WDBpN0xISGR3ZENxVEhFcXVTL3NuNVV1Q2ZrYytSZW1NcUlTVE9PQnh5VlJXbERLdkkwUjRLZWlJNUgvVHNqUjVHOVZRcU1JbElUM0tpWGphSXB3T1RhTDZPQ1U2NE4xSGpnbGtmRmt2TGpBNU42VjY3Rk5rUEltcVowUEJ2b1UwMVJ0c3FrTVNvNTFnVG8vSDJKVXh0YXBXVUtoeHZLSXBIQkwyaVM1TWp4a2xGekUrbnlPejhtMGxOeTBvcjQ0emFOMjhYdXdiQllMc29hRXFKY2trMXlRSG8vU2hOOURrK3lMYndoczhjZHp5WDBaaWVTNWNGdE9tUlNyQTR0TEk4L29lTjVLYVltWjBhOUhreVJla2wyaFpJcGVpeTlFMnVOSURncUl0eFp1WExJeGM4aVZZUEkvYitsQjJoRXBDbFJReE01SkllRHF6K0RSWG8yNDlNT0Q4MWpTRkZkaVJYUjVlSy9TOGVFWHJ5TCtqYUZnYnRESXlFK3pjTlBXSTVOOGFKRkZGTkhqOFNhTmxZRmcyMlpqd2VWKzM5S1BBMzFvMGNDVEdjR0dpZk9sMGl4cCtoSTJtd2pGSkNpTnJzOGI2TnpUeWlpS3JKTEI1TDIvcFhTSFFrMkpFbzVvdXNEWXFvNUpjNld5bWh5ckhvZ3NGSlpNTWFTYUdsMFZqM0czNklWSm4vUmZUS0pxby9wUG80TjFFcEMvb3hxaHBFWFEzWWlzbTRlcUY5STJLOGs4TVZVY21XVHRqWDBMR0djSWVjbmx4RDlKTk5ZRThDNHNrME5pdDUwWkdWRXRHeTc5RVZrY21pTHprbEtKK1NQMEthRS9iay8wWlNLL3dEMFRya1VqenJINktqZkIrUGJraTI4a2VESFExWnVjY0Zwb2VsdXRVekdzZVRia1FrZVNDUjQzMGJjV2ZrTnFhdGtwVWhMY3lxUlBqUi9QNDIwZndqR2p5T3NHNXA0TDdKUlRRbVBnamd1OUwxLy84UUFJeEVBQWdJQkJBTUJBUUVCQUFBQUFBQUFBQUVRRVFJU0lDRXhNRUJCWVZFaUUvL2FBQWdCQWdFQlB3SHpyYzdiRXBUTEZENUtHaERQazZ2aHF2aUZHTFRRblF1V1kzNTJLVnRacTFRMXEyUElidENpNVNQcDJvcUtNRlhxTFl5bzVPajRkQ1kwbnR4SE43RVBMU2MrZ25HVG93enRYdGNkYkVxS01oUlFpOWkyWTAyZGVkems3K0NRdGppNGJpL0ltVVZEZnBYRnd4TWZZa05VY0ZlZXg1OGlHNzgxVFpScEZERVVPNGVQTm1yNXVmQmk3VnFISFkxWEFocjdERVY2V08xTVlzbkNPS0dQWjNQY3NVNHBWWjMwVWw1M3RzVEc0eU9wYWpzdXZCWmxHRlZ5Tm1LdmtWR1hwTEtXS3kxRGNaTnd1SlpVS2JxTGhmbzJqRjBpL3JMODl4UnBteDUzczFTeXBWd29yaTkxbW90K2JKdjRhbWptTGx3a1VKUTBhUHNOUXNiSy9vOGFLcmExeHRYbHVHbXpUbVdXdGpFaExZeFpmR2NHcEYvREZtYlBnK1h5WlZWS2VoLzZWYlh3WWk4N2F1aEZDVlF0N1Z1TEZqYXN0ZEZLeDVseHc0eWUxczdFVnZ2d1ZYSmJ1Rng0SENSUnFwQ2Q4bVQrbVZSMkpiR1VOK25ZOHFGc3d5MjVzcWo5aTBKZndmQmNMaEZ5bkxGc2ZsdVhObDArQlpTekpsMmZCQ1ZuWFJuL0FLUW9Tc3FsR3FYd2RqeWRpNUxpeXk5eW16S01tMTBNcHZnYTRLbzAyN1pRaFF4ai9KYk1pdFBCK1JlazFTMkljVk9OUHdyWTl2OEExNXBUVmlVME5GVU5XS00raTJWY1dKV01mUXhHVXB4VysyTFk1L0JZNWM2aEZMNUN4RXEzUEVhaWhpVlNoTVJsMlZETVhZcHkydGxuWlJkajJLSGxjWTRWNDlKcFk1ZkF1Um9vWjJLRVB3dkVTcUxpajhFNXF4S3ZNMFpjR0Z0RHNYQStTLzZVSXFHUG1WKytEa3p6L2hpblVhcUt2MDgxeEZ5eGNjZUJLKzk3akxHa0xNZklodW9YcE1RMlhEaTZHeEZiNzJZR2Y4TkZGVkZ3dlFjWmQ3V2hiSFl1WVcyeE81VkRaOTJZK2c0eTdsUTR2eFpHa3g0SHlOc1Y3c2UvUWNOY3dvY0pGVGs2TlJyVEZsZXpMeE1TNUY1Mk9LMkxIa3JZNDBsYmI4V1Bmb09Hb3FldHlSUTg2MnVLSzUzNCtoa0ptcTJNWWl4S3hpMk5uWTF0Y1dWRkNoWGNJWG55SHNYUXVSZGpVTWNQQVVmL3hBQTRFQUFDQWdFQ0JRSUVCZ0VFQVFVQkFRQUFBUUlSSVJJeEVDSkJVV0VETWhNZ2NZRWpNRUJDa2FGU1VHS3h3WElFTTRLUzBVT1QvOW9BQ0FFQkFBWS9BdjFWOGJaZzMrYlB5NDRPdHgzMk9aUHdMSTR4Vy9WampQMnNlbVdIekloSlpvd2gzMUdPSHFYekVsdmloS0luRCtEVjZsWkpkcFlFa2ltMDZQY3RpTGNzTXBQZkJYVXBFVlpwRjM3Y0VvZTZ4UW1ueWpwQ250WFFkYmozRmUvQzU3RlJGM1dCYVVKUmZQMkV2NUc3S2luWlhnd1JrNDFHT3hsL2I5VmtwY2FNYmw5T044TWJjZCtQZ1p6MVpjUlpNYzMxSVJ6NEp5azB1d3N0VUxOcWpIVTNOSzNPZkxKWWVkanQwTHZLTnVWaVVYYUkrbjY4ZmJqQXZoWG5xUlgvQUNPRll2WW5qbXNqekNwODNiaG1YTVE3anovSnY5QjQzTlRwaVZaUE1pck1QbU5QcSswZW5tajBZbkhFaXZVVGVTL1NpdFROTlJOTVV5OUpKNmxaSFIxM0p0VmpKSFN2dWFxWDZ2bU1mSjNGd3daZVdZNEkyTTN3d2IwY3lXa1dsVWpCbmMweXIrQmZpV3V6SCszMURSUENJcU1zRWJOUmF6UTQ1TzMwTGJ3YWF1eGFlbzZsU2U1cGc3MDlXUEgzN0ZiaTlUZVBROXRNczFJc1RqdVg0TnptOXZrdDRiTlc5R3E2THpKbExjaktobXFYdDZIcVRlNWgxTCtqSys1eTdpUzNva3hJOVI5RUtWWVd4VGpLVC9XOTBZT2JoUy9qaHFYOENheWFhTVlLWlNNbWVGSmNQQ0xIV0pITmtwMlY2aTFWc09VSmJiSWFrUnZtZ2JXYXRPbFYwRXpOVVV2NEZMcUtVUjkweVVwUG1ZOTZQb1AwK2hsbHNsRVhTem02R09NYkZXNG95YjdsK0RXMlIxZFN2U3kvSm9hc3BZemJNNVo3cmZZaS9VaS9UOG8wN3g2ajBTVkhSMFRYcFlUeTJVcnRITC9mNjNQQlVLeTBkak9Qb1Y3a1k5eFRFWGtWbS9Ec3kwT05YMUZ0Umd5em1kK0RVbmdlZHhPRDA5eHFFc3gzWGNTcXBIS3ZJbkRlek8zVTMzRno3RloxSEw2ZjNOelRON2pUU1ZGN3RQWWIvd0Q2Ujc4TURrVnV6VHBiTkNWSXd4YXBXSmw5QnY4QWFsMDRhcjVVY3R1UXQ3NmxTZkt4UDB5NjJPWm1wTXVlL1FhMHFTU3J5TkwzV2JYL0FPUnZxZmo5WnNWd1Q2V1djejQzc0x1TFZzUlVmYjNIQjVSV3hVbVpNWkVtOGxTWSt0SExzWHRYY1dyQmoya1pSaWFsTDdDOVRheFNoU2xWbk9xbWI0M0pZZWVwUnFleHI2a283TkhoRXRNdGtON2llK2VvMTZhdHZkbGtZN1VaVlh3cU9CS0l2MnM1OGlVU21SU2VOTk10ZTFtbU9JbTJEbHFHbnVQNGs5VllJK1NpRWErcEpSekhzTk4xNEhMd1BhKzRvcWt1NXlyOVhUTUdlRlBqWXVQTDAzczVWb0hxL29hWldNbks4SE5nNXg0MkcvNUUwekxFMHRoRmRDUTA4OE9iR0JhVlhjcm9hVVc5K3hhM05heDlEUzgyalUxaXh4L3oyS3Zsc3A0d1NSbG9WL3p4dVpWcXkxMEo2cSs0ckxZbzdMc2FZN2R6VDFJK20zWFZtbFcvTFFoK0Q0MzJTN2xvU3MwU3ZUczZMbEo2SDBMdkg2ZlB5MEl3WjRWMjRaNFpXRWZRcUl0dHg2ZC9reWJtUnhVY3JvVXpGMktvaWxIQnBHU1hVVGpuc0pUeWp3bVpKUmlZN2trMGMvOEFCZ2VuWm54SEpLalhHeFVyWnptcnR4b1dUeU9GV2FXWDJNYjl4ejRjeXMxd2UzY2pHWFRKS2MyUFZqMDQ1Yk5VY0xvaHB0Nlk3bG9pcEdXZFRkMyt0enR4YjRaR1ZIQ0tpVnc2R0ZreWhicEhMNnNqTWpPUnpndExXNW43RzdHK2c3VnRtK2wrVFRHVVMzVjl6WHJRNXhKUTlWNzdNZFVZcEdjRFhROG1CZHlha09OM1JkN2JjR24xNGN5MzRiSFd4dll3dGlTU0xGQ1VNZHpCWHVUTDRkTzdzMGJRdS9xVWxrZlExSVNicERMaGtmVDlUajVMVEtleHFid2VER1dLelRFcGRDcGJNMnRuTWREejROamRITkpseFk4dWpUUlJROVM0WDZ2cUpSUHdWS2FMMDZXdXRudUhyUlNlRFQ2Y3FaWHVGQ1VHdktMSExvejI1SDM3Y01LbEpXV0pWc2FwZnh3OERGcGpSNTRZWE53ZzVZaklyN1pHMXN5TVVxK2gxb2pGRHFXQlBHUlVROVQxSHk5aVhub09rcjdsdk41T1ZXaktlcncvMCtTaStQWGc4RlVWV0MrajZtVFZFM3lWZWZJbnY5VFM2VE43bDVNY0w0WUxiK28rL2dkUmtLUG5ZZGp5UnhrM1pKZE80aE9lREZKTFk4b2kwc2pQOFdVbS9vTFV0aXUrK0I2SXM5TnQxZjhBUjhKUFd1dkcyTlVWdElXbm9PZlkyeStyRW9mYytKNnRZMmozRTVOMFNUZGtYUENYWTFHUzJZRWhXOENVWmF1T2x4NW5peXZUeW51V3ZVaitxZkRTV3M4SXVRbXNEUlRHaTBmNU04TGhFcXFNUEpVeXBKMFgwR3BaYk1KSmlQY2lEMmZVVU5uM0s3aVdjalc3RzFGSE5INkdpT3hPY1h6TGNqcTJLMDduS3NjUGh2RDhqa2lVb2Z0TXV5NnlZZHBpeGt6aEc0MVpyOVhFTC9rbkhhTExUdEc1VmM0OVRTSEwwNWZZVXA3ZjhqaWx1VXR5bWhwdWh1UHRGcTdYWnFsTWZsOE1sN0l1djFPUm9WRjlSOWpCc2JmZmhieU54S0czbG8ySXhyK0RQVHdiZnlaTmpQRFZGR1RBb05mUmliTFhVM3RtWGxudVZJMU5xeTFWRDVmNFkyb05XdHk0WlJURkZyaDNYMEcwU3RTNWxYRDRnaXlNWnZKSmRPRWRkVXRvbktoV1NrUFhKYWlsSlYzR2tzSHA5ZUNhS2ljeHA5S3FNTmpVbmloSytReXpOZjhBeS9TNCtYSHljdEdNY0tmdUszSGV3LzZOTDJML0FHc2E2TVhMc1hKWitiSEJtRlJGOVVZeWJseDI4bE4wTFhzdG1ZVlVkMmFiU2tmaWN6SGNlVjdyc2F0b21wSjZWMVJYcVIrNDlMVkdtbFJIVGt0SVM5UGFzc1M2TWpkS2pWRjRSclc2M0s2bk5saVdCZVRQQ0VIOXlvL3QzTDlWK0NEZzFmRDhLT2VzbVA0YnVTM056VTNrUy9jUTFScUNJeGhISmsyeWRmMGxscmhqaGpqYU5NaWtQT2VoekxnMld5OXZ5S1BIQjZoNHlWVDRYbTJKWFZGejlwVkpEV0tNUzJNSjJmaTlOa2gxdVdMU2FsajZGcjIvOG1tUEt6Um5IVXB4WWs0N0NkMUZuTTZqMXNYcCttOGRTYWpIN2x4UnpVZjJPa2N4ZnBySnI2b2xteElnbXFrakJ5dmZjdmdyTk1kK3BmcXkyNkh4SExmWklhbzVUTi9vcW93WktSa2JpWDh0MGVPRDFJd2pIQ21qbEwrZlRFcm9XelpzamV5RkplMHYraDBxenVQVTdzV0hUOGx5WE1aVkYvOEFCcVRySmM1UDZvMHA3YmxWeWR5cnMwdU8vUWN2VGJRb3o2Q2NYc2ZGUzN3eEtid2NycFVUWFZva24xTkpmUWJpNmZRMHZtK2hxY1hSRndscDdpcFdXb2ZWaWNuV094VXNycHd0Sy9KUlRJUnRObUxaWGJoWmg3STkzNkxQSGJobjVQQllxNFZKRlpvZWNubEdwZllrM1pkWUtkV1h0UmhIa3JqYUxhdEhzRzlpM253VkphVlhVU3JDWW5QREg2ZXEvd0RFaUtxWjROTzRyMkkwaDRUWmpwKzFueFBoelJwY2NkeTZVa1g2WThXbnVpcTVabFNIOFI3TEJhRnFWb2VQb09YcVNwQ1VXc2YyYXBVb21Wa1ZrRTluSWxDc1BDSXZvS0Q2RjZiOE1hMlROVTJocExWZXczcXYxRGx4WTN3ZVRsWnpmb2I0WHhmY3lYSGM1dU9Yd3FzY09VdFlmQjZYanlPS3d4UmxTYU1aSzZua2RibUhSekZ4NWtZSDI4bW1qa1dIMTdHWFpwYndqVG16ZjZITTNxK2duR1N2cWtTdFV6U25rNWY0RktRa3pHSDlCV2thVi9EUHFQbVcvVTBROU5aNm81bzAxMEhvZkt0eGN5dUs0S1hTeEw3amt6U1doS1E4L1E1OWtXczF3V2xaaWh0NVpnemt6UzhkVFZYMFEybGdxV1VKUWl2NEYwRW5tMGNpNXZKditrODhIYUdrWnlXWTIrUzdNRnBuU3k0cmhoNld5cFlrSjN5c3dyNEtTMk03b1dmcWFZYmRVZU83R3JHbmp5TFpXWEhZUzI3bW90OVIxUmNVc2JsclpuYWtQVFJKVGYwczBpMHMweDl4cWs5eGFreVdyRWY4VG1WZGg2YmxNWkgxVXlQcXc5c2lTN25lMFlqY2FPbW9ycWJ2VjJPWGxacDFYSjdzdFpSV3FySFZObTlkeWNvUlI4VDErV0MvczFyVlhTekY0M1o4TDAzanFKR3JXYUlabjNLb2w2a25uc1lWL3BMWER1SnhFMmovQUcvSmFMa2h1SXFXQ3pSQnBNenVVWnBVZTdCWlVKazRaMUlwcmNxVnBpbnYyTDZsTzZGVVJXdHR4eHMzVm1tU01tcEVxWjJPVXB4dGxQOEFnaTBxbzE2K2hjN1pxVHRDdmNlc1VaZTVEVDNIS3FrVkxZck8zMkV4eGtlM2ZvWG9yUFV3WTNQdVg3Yk1mMGZFOVN6MDlLM3l4cEYrcW0zMGl1b242aXBMYUs2RGlqRE5XN1pubFFsQTF1VlVjaG4yOWtWVmZvSzRWd1pxV3haaEdVS3RpNWNMUmtzN0NTTGJMai9KMm8xV2FiTnlyTDJQZm84a2E5UVRuNjBXL0tNVHRmUXpQVFk1Um1wTHFLNUdqMVQzVWY4QXVYOWpTOUxYbEZhWU8rek13ZVRuYlNIR1hUWXBiR3FQTjRIcTlOb1Z2YnVSenltNlJYWVZiZURvTFRJVXBKeU1lbXJITDBvdXpSSld1ekc0Q1pXNWEzUXJ6WnJhK3czM05ONE0vd0JEWHAreDl6VGRsUkxpcmtYTENaZTU1UW95V2U0MVJiRktDcnBJOVQwRnYwWlNPWmMzNkRCa3h3dmpuRExSN1JNU1hIUHljeUtlNCt6UjNKYWpDeVZSYkw2R1JRRjE4Q25EMlBGSEsvRk1WNGtqUThsV1UvY1l4WFUyczFUaTZld3AwSjZGWStWR3R0cDlpL1ZpbDlTNHlVWDRQdzUvRXdKVnBvbGJYME5UYkZwbDl6VHc1RzB6NGt0K3BMbTVWMTQyeXRGcnVPdGtod2RZRTRJelRsdFpIMDA3YTNLU0ZGUGw2czVYUkZNcUxJeWgrNUhPN0hVYjhvajhTV2Y4VWZDOUgzZFJ6cXArVFUzcFNNcjcxK2twajRlVFlXZCtGYjhGcTJGUzJOeTMxNmxLaXVnbWxabm1pWUpkSmxtMWR4UlI0aUloNU44bzZhZHljWmVUNjhVMDhsZXE2bjBZbEIzWXRVV3U1Tk9WM3N5bTdYUTA4dGVDMDBzYkNhcEZDMHRaSlE5VDBzdnFlM203cm9OTDFNTE5NZjRibDlEVmxmVkZGcFVoWnd1NWVMN0NsK3lRL29WMXNhSlhzV3R4cHlTb3hLaVVJWjdzVVlkVWFuV081ekV1UnVqNG1HbVJUd1oyTkVQdXlmcU9uNnIyWFljMnJJeWRScm9QQ05OWS9TN21kandOeExleDRLbnVQSEM5cElzOXErZzZWVVZJdGpUV094cTFjR3BsRTIraFAvY3grS0llQy95TTh5Uno0Tk4veUtkM0VpMmtsNExybDZHYm9VSzNJeFZ5UTFwVXY5ek5VUFVYME5NbzU3bHdkUmZib2FaYmovNUZWNm04ZVQ4U09EVDZrTVByUkpSbEg2TWo0SEtYdU1ibHRNVHVqbGQyTGEreUdxVnkzT1k1cjdZSG9IRFduSHdZd1paYzdIb2pUTFNiUm9qQ1duNm1tTWFpdC9Jc2MzZHMwM0Q5RGd6OGpyb2FaN0g0YjRYMU1HbHg2R1MrSGsrdlFha3R6bDRWSjRFNHV5cGRUeVM4bHJZcDd2OEFLY1hzemxlU3BSNSs3MktsL1p0VFd4YmFNdzN5Y2hEWGF0R056TWJKd1dGSXIwcEtVWmRHTDRzVFI2Zk02UGgxemI2am1Ldlg2Zm5vTlAyM3VpclZkeHlsblNKbzA3ci9BSUV2VDc1SllWb1VwWnRjWlpYM0ZCSnFVOTdOTWRoWGxNYlNwZVNLMVJXVDRmcFppdXBwMWZZb1dEbExsOHRQOHJIemVEQmxHTnpLb1NXdzNIZnNhalpjcFdMNkV0YXgwRThsUUttaXJNOFUzdnVmME8zbXJGZjVhOG5OMkc1WlJ6ckNORXR1NW8xZlEwdkpYcXJESXl2WWU3ZG0rUjF1UnJWTHdoVG5pRjdXY3EwQzVYOXlwZW1TMXpqemIyTitrMXA2bWVoSmRHeGZ1THJUZlltK2oza0tNT3ZVbjZmckozSHFMVDE0UVVlWnRiRXJwOXZBL0dSZkZ0dm9jMng3ay9vV3ptcnhaYWttWFZtMUl1TC9BRExMdXVHZm1hc3BseEV0SXJpMks3UWxHU0Y2aWw5alZBN2NMUmRqYVlqQnlxeUtTcVJLOWxnKzVLK3A0L0xnY3JwcmNjWVBVMS9pY2pxVDNNK3BxWGcxdWM4YjVIVXBtRzNIeU9yeWN0ZVhzZnRTRTN6MFJld29MZXhSdllpMXNTelZHVXBDNVhueWJYSHRaNEhIK3lzNDZJMFo4bktxb1VtNWVWM0lxUFFpNWRZa1pPTmVCeVMreCtIdWMwcm45QityNjc1ZTNjazlqbms0OWk4MFVxUms1VlIzL05lQjJZNFZRdUZXTjhNYkM3bHRXV3pMWEJ1RDVTNUk1SFpUVFA4QXRrWEZQSnlOOE1ZYkl6bTFaWERjOGZseHMweHd0TzVwZzl6VHVqcDlSdXBWNUhvbFRGcWxxYk5FdmNYRjZmOEFnVWZXdUhub09uQ1Jnd3NtcW1LTW95K3hidFBxUERJeFdwY05pcFBJNFEva3Zkc3hrUzlTUDNMV3lQVFY5YUc3OEVsSEpWYzh1NHBiR2JhTXVtVTJ5b3BqNXMvUWIzUmpZeitSbjVLK2JjeVdpaDJWd2FIYU1iRm9hUTR5L2s1ZXBxM0ZLTmp1MGpHeGl0V3pNaXY4KytEemtVaFJjZGlVZmEvcWMrMVVJMUpTTks5UFY5VFQ2bW1FUy9jeFhHc21mVC9vbEgxRlhZazJrK3pMbzJWbTFTUlNqa2NXYzJ4eWZ5SXFzczhqWHFiNmtKZVRuZVYyTGEzSWFuelB1TDB2U3QxN21QWjBYOE4vWVNVS2FLaXFhT2QxZTUrR3VYeWMwa2IzOHVNbWVGZE9Gb3l6R3huaGpoWEJmSnNhb21TNk9uRG1OalNPSnVaYU42UHcxazBUTjdOU3gvOEFnc2ZtNjc4bWNGK3AvUW9RdU1UTmxSU09kNlk5RVJuRmNOVzUxdmd0TWlwWk4xUSszY3RlMUZyWVR2Y2RsNnZzWWlSMUdkelVoVGV6UFRVbmVMRkl1THN3eVQ5UmFwdkN2b0pwcm1JMDlVdW80NWozT1RKN3FZcHpkbzB3azJLazM5VGw5T0MrbnpaTnpsTW5Md3dWeHdlZUd4WnU3UGV6Rk16Qm50ZjNNVWhac2Q4ZFhwOURWVlNGa292b1haVXA0NzBYZjBIamMwTGZ0K1pGTHFiWUhwMjdsZGZMUDlzY3RsUXZRLzNHVnBYL0FDU24wckIvdGE2aWFlNUZPOWRsNDFMWTNMZGk3SXd6WERLNm8wK3BTWlJ0djFFdWk3R3VXNDFkczA3dnVpcFphS2xrV3IyeDNGNnZxN3llRVFiVlZqQTQrbGFpT1VyMWx5ZUJPRGFaVG5nazdQdzRqNVlXT01scS93Q2hhRGUzOCsveXQ4TWNNb3RaTXJIQ3ltV1kyNFdXdGgwVW56SHVvM2pJNTRTWEIxaUZEYy90dzA5RG4yS3B1emJIWTAwYW0xYTZFa3ZheC9sTDFHWjUvcUwvQUJvMWVxL3NhdlYvL3dBeU9xUEwwTlBxS29qMHM1cWxpcUxpcU5UWlN5WnVqTjBKSmJsYVIzandQc2JyU05QMjBSY2xtK3BiV1NXbU9QOEFqaHlLdWhuM0lycU5UNVpkemxudjFOZjhGQzBKZmNweU51Rkd0NGJMakxTYUsrNTFWbWZYYWY4QTQvTmFmQ3VIamhqaGtveHc4bEk5dVRKZDB1RkR3V1JmREJWTXZUU0xzMGVxc0Z3WSt6SUxWVkdIY3BZTjBJV20zcUh0Y1J4bDlTL3lLOGluUDJyb2hPQytwcXZsNjJha240UnFiNWpSTi9RY2RxNFZLSklwcnFmL0FLWkswN01vMzFDbkhaOURTc2puSm5OTG1zclZnY3BGdkxaTEhRcDllb2pGT3l0aU1WbU1lRG5LMGhWMTRKSW81c1JXNDY5bXlISG9POXpiQ0x4d3JobXpsWlJoRnlNRGZIYzdzdFlLdXVIZzNFakJrM0xqa3dWcTBzejZnbHJ5WjlSZndaVVpITjZRbW95OG5QR2piQnk1VkZNcm8rQ3hub1ZOM2ZZNXRoempuU2gxbWhUZTcrZUpxdkVqRHdhcWJyYXhQWnN1a2h0OWptOXhpT0RtYTJKeGpHMVJUVG9XbU5teFVxamZVM1I0T1Y0TS93QUR2K0NXcDQyUnJTdGRqVXNlQzFpalQxbDFLanVLeE5aTVliM1hDMnVVNXNyd1lrelZZclc1eW1tT05XK0JyVW90R1hucVU4RlN3a2I4TGlkeVBEYXZKV0h4eWNxRmZDdXBUUmFOU0s0Y2laMHN6TGhSZzVoWVpxT290eWpDS2U1R05ibElTVm1OeTJ5VnU1ZERWNFBKT01vKzVVYUVyUGhyNkhOOGxNOFVPelRFMU4vWXl4eFpYUVVuN1JDMUxKc1NsM0VsM01uTGxGVEwwcWh1Ry9ZV25QZzFiZFNVMzlqOFd1Ym9hTDVPaVl6RWJzMVhndDhvNHhPUzAwUFZuencwempzVkdkMmVPRjlPaHRZNXBydFJOVC9kMUhxanFMUmNrZTM1TnVDTFhEdngzSzM0VzhzcUprcUpkbGJNdG1CM3cwdFlGLzJKUFkweEpSV1dSYUYxTEZYREpVblZtTWw4RkdmdU1yWTN2dU5qMEdmbHdOeDNLaEdwei80TUZ5a3pPVEt4WTRuWVVaRXY5dUJKKzBVdlRXVFZWdEdock5IazZuazdrOVl0ZFNTd0w0YTAwUEZTNkRpLzJqak1xdHhSNWZzTlVzaXRjcHllMThOTjBxeVZDN00rN3Jxd1BzTzlsM0c1SmNxRzRycVdzcy9FU0hGVW1YZTJ4V2t6d2RjTEd1RExQSERKblljWUtpWFh3S3pCdWpCemNNWUZSekxsTGg3UjJpNDdzZk1ZN2o3R3JVS1d4MEhSVFFucEVvM1d4dlphTFZmOWliemVHbVlLbDl1SE5qN0Z4ZC9OcXN6dXg5aGFFS281UEpwdWpUUFpEME42bnVpY0tIZjdjbktLOGVSMWxYdWY3bHNhcjI0Y3RaSlIwYzE3aW1uOWh3V1JPUDNzM090MkpONE1ZRm5KeldtdUNjZHhyYXk0YWJlNVRpdnNhcTl2VXIxSVY5QnhmcXRmWXo2bEw2RHFVbkk1bGp3YUt5WWRmVGhkMlZSY1RxWk9VeWN6R2ozY1BJOEdEbUV0aXpPeGd1akhRbzB2bUtvZDl4ZGpsVE5xT1Q3bnU0WlpVaW12b045REJxalpmcU81TTJFbWxhNm10N0hOTlgyUitELzZmMUplZGpNZlNndk1qM0ovVDVjU0s5UXRaaVMxZGh5VXJ3TEp5VmpzSnY4QWtkU1RTMkZ5MmZFaW1pTXVaUjYwT2Y3UjZpb0tqVS9jc0dWcGlYQnY2Q2NXMEtNWlhlNHJrc20wY2RSd1VyWGtvMHhlV2VuQ2pmbUxKU2p2WFhoYVNiOGtlajJaeXE2RmNXY3JydUxVeVM5eG14UndpcXljeDdFbWNyTmpZeHNiSHRObFhHdW5IQkt6end5Skl5WVkwaDRNSjBha3Nsamx2SWQ4SHFPWnJKRThIWEJkRHpSVVdKeDNGR1ZXY2xsU00rMWYyZml5Yy84QWJzajhMMDRvZmJ3Wi9JLzI5ajhPU2FaejRJMHNtbUw1aHJZd09SaGZZNVVqb3oybCszd1ZJM0Y4Tk01OEgrV0JXYzJLL3NZdkpIVDFYVVZLcE1VWmF2c1BRLzZJeXExMU5mcCsxOEhTeVZLVlZzVzRxWFVjNnJ3ZTByWmllcnJSbXRkY2VpK1Y5dmtXcFpHdmsyc1Zibmt5emw0NE1STGtlM0J6T2kvVFkxS1AzTVpISlQ1ZXhhZVMrR3BsVVhXeGxVaUtnVjFMbXkxRlgzK1JtZnlkNlorSnpJdjBXYWRudU8wazY0UG9rTnhlVjFJK3Erb28wbWMwZGg5YkhleU9XTkdyK2pEVHZobDFaVjdIK1M0UmZxTGxOTVNwYm1HZmgvYzA4RlhVVDNwN0M4azU0cUpyTEZVbWlvdHU5MnhaUEpuNXFMNm5rcHF5eWtaTGpWSHQ0MnFPZkNPUmNPNWt6aEh1eU5hdGpUcTBtbVRPVm1UREhacFdUVEhkZHk2T1kxWGErZkROL3dBM09mcWI2WDVKZGh4ZlVsdGtVVmtVVHlKdXgrUllWcDVNYitCWG53YTl1Nk9aaTE3RitubUJ0Uks1WWlXWEtOb3ZLWjFIUlhVeDBJK3BtKzNjMmFLMWJycVZOTmZRYjlLN1grVEhuaDBOa3pmNXJNR1N6Q0xzZEZHSHNQVXNtR0xseVc5akczQzBiR2xvdzJZYmQ4RThNYmJwOXFNSVdpN29VNVIxWDBMbHkvVXVUK2gzU0xsbXZ5TVkvUVlZdFdDOTJ5MjZyc2N6M0s5SjIrNStMQ3k0UjB3TFV0enVYTWRYUmhHclRoR2x5YThIdUhUSXBMWTVpbXNDYnRYc2FXbEtMN2twYVg0NGZpMzROSHFSK2hqMFZwM3M1WTdIa1Q5VlhFdjJycFJmcFRVbjJLbmNhUGMveWEyUnI5eGNWVE1seWRXY3F1elZGcEd1ekwzTTdHRFRNdGJEM1IrS245UzQ3ZGhQYUp1eHYzL1hvYTVWWmxhVVZGWjdpY29aN2wzcUZyelhRcjV0L3dCTTQrcExTbWNtYTZqZWxNMVVpVVpEYnR5bzA3U3NVSG4xRjFNL3diaWdmRTlQRFFoL0UzWGJnMVA3TVdtbW41RkhHRE1xK3AvN2tuMEdSaTNTYkU0dVRvdXJIS1ZJbG96UnprYXhYUWRWWTAzZjFPZjAzZmgvTXRQSGw2N285OVBzT1RlVG4zUGhwOHB5enNqa2xiNVVlMmp1Si92M09mN0djK0JhdGpTMWcwNmFPYkJIVFJoamM0MnhWN1diRnllQnVIdU14eWRqM0c1bjlWb2N0K29rMXQxUi90RW9ZWFZsSnkyL2tUbEVrOVBLV2todlM5UGZpNXVWQzZwOWVHdVg4Q2xIQTlNbXlMa3JYWWJncWZiZ210MGZFY2xMd2FweHJzWjVZa0pMMUZ6WUxuS3pLTUdFcjQzMCtiQnpteXh4Y3YzajhsR0RmaHAzSzAzRVR1bU9NdWJzYmFXanNoY0hON2xGK20vL0FJbTJVUlJEWC81TXBjRzNzVVkvVjgyNkw4RFZyQW5WTmJEMTJPUFJrcDNzdGh4bDF3VTl4dHV6dFk5ZGFUVHVjc1JPV1d6YjZVaFN4WWg4SEcrYXowcFg5U2E5WlNVWHMraDhKdFJTMmRDVXFkOW4wTURZcCt0V2s1WXIrT05kUGx5T3RqWE9XRGt5dUdUbmJiWSt4dXVOUjNGajZscTBhc1dhbUt5bzlPRFRHa2s3SzAwV25IYTJlanEyYnY3Rng2anJxVjBSbzlQK2Yxc29QOXhYQ0k0cDdtRlpoYWE3SHZaejZjRkhLaEt5OXoxTkR0OUJ4ZkxKZEJLVmVSS096T2YxT1hvT3VHVDRjV3RLNmtPYTBYNmtyZ2NsNlR3YkRqSjVONitTbnY4QUkrR0daNDdtUzVtMkRCcFp5NHJnc2lSWFRodndrbEZKajZ5SlN2RHdUbEhhTU5LS0VmRDlQN3Y5Y2hTVDV1cGsyTTdvNXNJbEZLMkxVK2JxZHpIN2pEdndiVXpMUktDZUd1Zzc1dkpQbHdrWDZkV0p1cjdNVTF2UlhCTFFuWjZjbEhablFsWmptUnpxbWprbWN6djZjSzRXdC9rZGZrcDhPNkY1TFczQlNMTWJqMUk2NmpTbzVLdHBzaWx2SmtZcnhmREgrZ09LZTZIY3RqQ3d0ejhKUEJlS2U1SnZaR2RobHBiY1ZxMzhtcjBzTTUyeVVPK3c1TDhKK0RVOWhXdVJtdVBEdlhRYmgxV3pJNjhtbVVlWXhuL29iWTZkRzh0WEdud3grWXVHQmFoVVoyTUZNZEdGOXhVWFdXYmN3M1BkRnk2eS93QkM5TzlqOFA4QWdiWDhFbE4weDg2dnNPN2ZrU21xUlMyNGJsTkZiRzlvd1FtK1pDMHgvazhGcEM0MU40NkdXby9VeFQrZzZkR0RHREw0V3ZreHNVTnhlM1Q4bXVObktpa3JFbm1SY3J6c2ZoKzdxZjRuV3hYdU9icndMNm5wK1cvOUNjNXE0eEU0cDc3bXZWazFLaHR5VlBzUDRhNVdOelQxcC8wV3VnbS9iMzRlQ0t1bWJjSXplOUc1WTNlVE8vSFQ2bnVzcHliZ2NyKzViVzVzWk1QaFJaYUxLWENxWDVQamc1U3BsUVNUT1YyeDI3WTdNZTNvTy9jeUdxcXZCN2txN0NuNnR5a0xsMHRpa2xYTWVqSHN2OUMyNU5ZbkZZTWRlcEdMRnk2VjBPUzY0VUtJNzNNQ2M5amxNbmdwb29qcXlVdlo4aXhhTnNHWTh2Q2tiR2ZrWERKS09sZlg1RjNLNHJsTDEwMHVEcjJtR21XSjcyV3BWNEtsVmlqSlhJMCswVXArM3VLTUVmaXBmeWFJdFpQL0FKUDlldU52L0ptbVBRWE5sZENtUDAzTzVWZzB4eFg5bDlXTHJMd2JtSGJmUVZvYWtzOU9DTjhDem5oZmJoajVPV1FsZGR4NUsrUlVWZkYvTFl0V3hwY2NNZGUzZ3RXdzZnaGFGU0pKb3RDWFE1Sk1yMVpQd09tdGI3bHovb1MxMTROU2psQ1hWanJPZ1gvay93RFF2U3BsS1N6dWZEMDdaczFMRWhOZTVyOXhqcVAxT1JVZnROa0oxa3lMT09MYmRIZmh5anp4eWNyeHd2aDU0K1JKY0tNOE14UmlDTmtZaXVGbzZHRWNwVWR4WWxacG5FWGNlY25QVXBkaGNoVWZzUjVzbUk1NFY2ZjRqZmJvZFlMd2VzbHZXUi9YL1F2UlhnN201YWp5OUI2OXhFWXB2aFkzaXpKVkxJMG53eVlmRHo4bXJVa2U0cEdlaDJFNFBIeVh4UzZjYU4rRnNwN0NOTmNPbGxTS1NMa3pHM1V1SWsxbXpWRlhSR1VxczV0am56RHNMNFNSVlZIdVRoRnJZbXZIK2hMU3FkVVpaSlJLTExZbWpVMHFFbDJ1alVqVFF0UnlsWFpobURtTnpIR1VlbkRMS2J4d3h2OEFPakplcWtjcU04R25LMmJEdkphd1B4dzFTUW4xRW9seUhwVkljZlUva2Z3OXZJL2pTZGtZUXhYVWNkTnk3bHZCVXR1aDZsS3VVWDY5OEkvVXpGb3pqalg5bWNHelhZU2wwUFVuNmxXSjNTVHlYcTVScEk1Vm5oc0t0enlYOGpaNE15cG5JWk44R1BsWEJES0tzYkVXWTM0UFRWczJTRmIzUmh0dnBSZHV6R3ByNkdFb3A5eFl0K1IwbnFOVlpvYnJsTG1tcUZTSTBUbDQ0Ti9mL1FJbC91TExmMEZrenNPTmpzYm0zZlFTa3ZxTmFqVGYzS1I5VGxUTFhESldvZDdkK05DMG4vc2VwLzhBVTByL0FOTlAvd0NoejRmYjhqSXEzRTJZTGF5T2x3ZlU2czZhdkpoR3hLTVNsRldjem9TdTJQcXhYazFOUmlocWVJalNwVVlWdDVMbGd1K1FsRmJVejAzNEkvU3Y5QWxKcStuQzB5cUh5NTdpWDdoajZvVFVxUi8yWkZHSTR2ZzlRdlRoN1NTNGNwbjVGS1N3bGgrU1crWDBMakwxRWxxOTNVaTE3dFBNSlMyUFo4dVJpZDdqVXNyend5VlJacE1HcHM1Qzd5TzhHMlJ0WkZKTFExL1orSFZpVGZNUlY4cGF0TWpwZE1TWkhWZ2V0L2htTmlYcHZvMk5kdjhBUUw2dkoxVE80bnRIdVBHTzVjZHlsVm5NeFhzWTJObmdVb3F4SjRaNEtUVVVTOFl2aEhoSlZsRktEdGI0SFVIaDBZSEd5dmlTL2t2WE9sdmtWamE2SHR2OHZ3YkZwVU1TYXBISzhpeGJPYmcyM2tVb2JlRE9DN0wwL2M1MVZqZXFvbiszdUtVcFlPVDIrUzNXeEpvejd2OEFreHQrdmlvOU9DTk1PWEJXNUJZK3d2aC95UnZkbHBZT3RHRmtpM3c4RDB5eUtMZDhmNlBVM3FmYjZucU9PMHU2SlhEbGJ2eWJYY2RPUnJSbitoeTB0LzhBWlBrZVYvQkRTcXBHVEQrYm1PVTVpK0dlSGNvcEhNWEljWW5NaTBtdkpVYzBVMFQzc3l0alRKZTBvZGJJMnJ5U3lQT3labmZoVWo0a014L1d4WGtVbEhsM05Xakl0VGFlNWE2YjJQVDd1ZzI5eWl1aVhITkYzamp1S2pIREkrSzQrZnkxeFhCZkl2b01pS2oxZUQ0djZtTy9DUjZqNHgrdkNhWGY5WS9XMC9pZHhJM01sWGg4TEpmS3hIMytWY0k4VnhseC84UUFLUkFCQUFJQ0FnSUJCQU1CQVFFQkFRQUFBUUFSSVRGQlVXRnhFQ0NCa2FFd3NjSFI0Zkh3UVAvYUFBZ0JBUUFCUHlIK0ZoOWRUVUcvcE5LakVCOFVDTTNtWGRsekNvSnpCWElQSFh5eTZMZ3BoZ3UwQjhzVWFTWVcwb3NYWThSRUw4c1J5NSswdGdGNXdsQ2VFb3U3Y1gybG52UDQ4eEVUVnQ3SUpGZFpxSUhCd3dGR2REcWFCcERVR2tLVmJEd0twWWg1WFVaMEtGc0JXVzBJSGdESU5UQWtkT2lKSVhveGFiTHNIVTVnRzFMalVJTnd1SFBjQW16VnZpVk5qcXlYMlo0WUxLOW9zenJQalVzUHpFWmFWck80ZWFIcUxnS1ZNT2kzekFwZzZQTXNXckZUQllQNkpOb0JsRzRVWUVLMk9KWVJaNGR6RUdUS2xnUDJFM0JPZkV2SnBHbGh6TXpSaFNRME83Z1pMNmYvQU1nMTlTbUxqbzh4T0hNc3dTMmh1bVZ0a3pFcFltR1lqTGlVMlROcmlHUmZPRWp6UmdaUWVvdFNMaGl6dUc1cTRiRCtFcUt6bTRnN3QvZVl3TmZhVkpjdkIxTkN4Q2t3SmRpYzdFekdPa3ZMUWZhSkp4Q1FSenlVZTRHVG5ONDFXb2NpcDFuTU5SVmdyaU5CMmRIbU03OVM5c2JEUEs0MTZqUEMvY1dPankySVN0NXlST0lIVUdIZXBhek1OenZ1U3VhTDVqR3lOMG1qV2pGd0liR1lzMHVmakV4S0N1a0NZRFd4RUJZN1FNeUZPSmdndHFQVUY1bjFHTEExcWJDUGNLWWFiWVNveVF5cmZHN2lKWENxYmxSUExucU5YeDNpb1N5WnB0amdLOWVvVHJQQmVBUFVIZEZHUTZsRGpzNWlEUTBIbDZKeVQvUDhsd2IvQUpXMGJnQWNKVEplNE5ieUV4bkVyMTUzS0hsRmNTNDh0TU5FZXBSMVhVQTRVQXIvQUJHckYzR3RtNXI3TUtXcnpOVXdPWE11cW92VE1LdTA5eThpZ2g1VHBOc3E0RTlDTXhyczh2M2lZbEJkUkFybzlReHlDbjNPVUt3b1BjTi9Ca1ZHRldzOFMyOSswYnV0M3hBa3BCUlM2cUpoYkI3bVhDOUc1b3E3dEJEY043c2FwZzREWU9VaTcwdTQ1Z0JaMW00dFgrSmIwVmx0U2pUMU05TVlYMnhJYUhpTklvaTZZczNHQVlsbzVSV1JTVkJlQjRhbFRuUE54STJGVzNDK3FISjZqWXRQeWlZaXdmYVhOV2NWRnUxK0dSbEZmTEV3eWR5VHg2WnVYSTVHdFZERVZVQnhFREl3SHQ3bHRETzAxL0pVMUIraGlOVFg2OVIxQjNyQmhnSXVFdFJDY0dINU1WTjI0aFMwWG1GcVBTQzU5WVpyMk5TaEo4czR1ZVlCWnVjRXdZQWNRSGNja2JESzdOQWNhZ1p5NW1VaFNQZGx0RW9DNG5LeFZYYldWUXE1UDZ1QmlBZnVEekp6alpEcVVPQ0FxQ3kzL3FKYTRjNm5YbHdRREUwVkZ1NTRCek1FUkdpb216TUhWZ1NCME9WajBuM0VOZGJaQmwwbEM3bXNhMVVkV05HSWhNOG5NcldpbFZQTXdpdThWMFJId081bHBCVGlVYnl6TWdMYWJnc2s4aGh2U1laaWptcW1UZEthSVpKYitFdkRWTWppbVhCdGZZaklpcGpiNVdnV1hLU2hVTlh2c0dhbTdDVkFyWEpFTXkxb3R0R3ZCTG1jRy9FcFUvbC9PZlRmWDByVzRCaUZ2bUNXaEtyakpodUxjWlpqY3ZVTmIrYW1zMW1DdDVSc2QvUEpBYm55bHNSdDJUSytTOXcySzB2Y3NXNVlsZXJQdVpLb2x5bDN6T3l0dHl4VVlhU2hZZGRSSUZzNm1qZGQ3bkUxRkJvZEk3QVZPMUloeGc5Y0o4ZFNrRTdrU0dBZHlJN2xQTXFva0JxeHZEdUZDTGxjV2dFV3BUTGx3R21QTlJ4T0xMRGlER1ZpZUo3eG51VUhBOHNNTnJTWFhTR0FWdmJVNEw4RE9DS3llNHdaSVcxR2VFQ0tkRThTd1VubWNLRDhRS28wVVJJV2ZLWCs0VGhVb25XN0pXb1BMekhtbXdPcW5DSnZ5bFVBVEZZYWc3eDd4RHRhT0o5a1ZrallhYjF1VUZsOWpRUVFhSVlqWWdXNEphTDdJR0QyT0ovS2tQaS9vck10OUZDTEZyTXptNFRFWUJxNS9VL1pDQ3dNMUtJMEdkeENHbTlNb0xJdkF6S2xVMms1WnZsTnh3RjJwRHdVdUpSZkNBTkxOREt0TkdYeVJ1c1NzcnlLalAwWFZ3Q0dIQm02SDBqV0tndlVVWER3a29CZis0S0FUanhNN2FiMk1zMXc4Y3hxNWc0aHQrNTRyeERCSzlIVXBGbHN2cU1uQWl3TWlnSmRZK0VZMDBPNVEzNG5zbEQ2Unp6QWpZRVFjbGtDT1BJc09JQmZKYVpZQXBtVDNBQU1zSE52VXNac1pmSlExY05zcmtxVlZaK2NUT2dCbGxyWWJNNWwzSnpXdU42cldKVytMcVcwRlo0OXRsbEdNUlR4NGc2Z01RZVE3alF0YkwxUEZIaFNKdGxibkZSQmdxaXhITHR1T0FYOEovSFhtQ3R2bHF1V0tZdEVjV21HMmxYVDNMTjdFVmI2Z0xBYmlLbmlLeU1sNmhGbGVJMngzQWVLUUhLL1BNTmdGMWFNT3JZNXJtYmwwdTdFN0JURVJWZS94S3pLWFRtWGhTM2NWQmVvNlU4T0lpeHdGVUp1a2VJdTF4dUFnZHFaamk2aHBhbmtnS09NUUVFR3BTNkwxYkduQWt6aTRGV05DbitvZHFqUmx0eXFqOTF4ekFRWVFncy9ML3FZRHJobURqcXAxRThMZzRaZGk0VlZGdXpRZVlhVUhWN21UUWRlSWttalZJMGZJTUM1Y1FGRmVkWExVaHZtYXFFWHJjcVlGNklhekpjelBXblVYVXBnZjdEOStXMGMwS2FMWStYK1E0bGhRdmdUaUptSEdtRGNkcDV0UUZESTFNVVhtVnVDczVRRitjSDNsaGI4UkF3bjhGem42RW1UNXVMUHdseTk1aTRmS0VXeUF3akZnVkNtMkpRTEdaZExOeGNOTWQzNTdSQkNRV0lXd3Q1STFFcXFoczJGUld3VmU2aXlOTnF6Q042bW1mZmFnZ05WNEppVG1GQ016VHUyRTZsOThSNE1LQmRMMUxqQmNKUXNMV1NXejRMWVNzem9MenpMaFd0d0hwQlpIZGh3SlhHakNNSlhDemZNcnF4V2JsQ0tLd2tRSnQ3VFFEM0Z4d0x4YmN6RzE0UXdFUjNZNU9tTjdBOWh6R3pkQU5RYzNHTVE2b25obGMzQ3FaSGdERlFTYlZxYk45b2RNT0lkQ3pkeG9XMWg2bGFvVkMrNnhGbGhTK2NGTXBURnhOT3JnaTJweXpyR1JsRXZWNXN3K3NyUjNLSml2Q2wwRnQrdU9XUXZwY3grS2dvYzVlNWs3bG9HYWxEeks2by96SDZFRE1HejRTV0UwekYvRUY2aUN1MG1SMndqV291YnFWZzNpQldzWmhkeE9RczRtWEJqbVBJZFk3aU5HRFVmZTdqUnNCYldKMGJxTms1U21TN1ROTzQxQlZESlJQV1JtTVMvTTJrT1lhcGlKMHlxdVBLRGRubVVjbCsyVlJkRTFMQUt5Q2F5WmN6U1FkbVhTMVlxOVFQS0g5emtqdGNRTDJyaFQzQW90YXFxeExvZ284UzlRZ3dQY2VFeUdyZ28yZFppbzU1NWpFbkp3eWpFbldlb1RpTXJRYXZjTWZacExyMWZpR3JiNE9wU2ppeU9UWjdpRzdvOFRPR0hiTEl4WktRS1Nxc25tVWN6TVpFd3NwQjJmbGlXMUhud1RNd0ltN2k0MUlVQ0NnYVN5b1AzVVU5UkdTbDczTHpLWG1WS0RiTDZiY0M4VEpwQlRjdldrYlgrQVpjdU53eWwzOExDVmM2TTErV1YzbThqTVhhWEY0WXRYZWJuUTRnNkVIcU1Cc2NRN1IwblcybUNKREpZV1FhWDV2TERrbHNPRFpPWU1PUWN3T3d2Uk1CRHl1Qmp6OXBacC9lV2JEMFFyTkgzVUVXem1Bd0VRWU1UbUt4aDdtczVYcTRVVksxMUZxMm51YzJPOXh4Z3ZxbVl5STJzdjJqMGlGc3FLT2NJeStROFdNVEUzRUhjWEV5SVhNQkZuQnFHSm5kZmNBbW1IUE02dW1SRXZBNTVpa3hIOTBOTG04blZTcXhpd0dlT0VHcTN6MUtzTUZWWFVIT2k5NWhiUU1wWXFuSEUvYVNjM2xsZ2p0eEFPdEU3QXNTZ0ZCUzlKZ1hSekdHKzRJUUoybk1GV2ZBUVdVSGlpTG1XVXBTMGxnWW5ZMUhaYmFEaWJoT3hsSEY3VS93TVo1aGFPVTBoZytERVhFc3orWlY1SmMxRkRtQ09vaUFlQkVzbkRLV20ySHBqcURoOElyZmlveWhMS0E2ZTRidGtMeENRQitSTUY3amlycnh1WGwyWkF5bTFSWWF6ZGRQekNNbTBSOXZDdEZxVU1IOFM5alZTMEc0ZG5BOFFJVm5pVnFkMWxxVzgyY2M0OTRKMlMybE9nbE9RQjJNdldncmp1SDJzdXpMRWJCWEZZbEErMGZzR0dZQU9ybHgyRERMTHZyQk1tQTIrSTQxaS93QXkwWFIrWWl4MmJTMjBpdXdqTm5zMmg3dTFSekxWc05WREdZY09ZQmVOUDNKUnE1TzVUVGRtYjFMb1lPbzVyQkNhTTdlWTJTcnZBYTFCanM2Uy9hWnlYM2lqM0lBRGlOMENvSHRHZzRSZWx1N3hMSzF4cUQrcFlmMmlHeDNQYUJJaVZHaXRFNjd1S2E1YmdlYWp5RXBHQ2JROUp2aDMvQy9BWmxJL1N3Z2lVNTRaUzdxS3dKZ0V6QUxWb2xXVXNTbCs1Z013eUNIbVhGQWR4RHFYaFhXR1p0dy9xRnNUZFNvR3AraXJnZ25OZVlRVnNPM1Vhemw0WXpoZGNSQ0FHSzFNZ3JRQjhESWYzS1ppdlV5QVd1KzR5L29sRVFsQ3pTemNFenhwMnBMNFhYYkZGOEh1QVZLTzJKbXpIUmo1S1ZMc0VnVzBHOEZSWG04TlZLS0ZOckFGbGxwekFNcWJ2cWZqek9vd1pkN3FDdGQybTQ4SlJtaHVWa0xldUpnN1BsQkJtY1BVRlRRR3ZNTmgzRE10Q0lnbkJWZHlxVTZ4QUlXZ1cyaDVnRURuQ3lrSHNEbUlueWw2citlbzQzalpLb2x0WnlyQXZRaGdnV2xSN1RnbCtCUUVLQnVVTzRLTERnUkI2RlFuNHVnbGVEeEV5RmtHeHhhZTVnMmUvd0NJUzZZTGNHNDZseTQ1STZCbU1kbytlcmlPRVJoVktabW9EZk1IK3pLTkl2WkxOVEtGaEJHVldIaUhGS1U3VFN1ZExFSEE4UnhlY2N6T21sZHhZenFWR3VzUmwxZTRLR3lLcUhpQkdiYXo0eE0ra3FJb0RrZUp2YzZKZXlqbUl4MFhHc3FzVUZ5RWNYRTBKZzBxZnhCY28rRFVaUHNTRU9GVThRRlplS3ZYbWQ5RE1BS1BvTXZRTWM5MnVYWkhtV2NrdzZtRHVhY3NmaEdGcWpqbWZvZkNJNGxSUUdlR0ROeGRLNkxsZlp2WEVXNWdNMUdjTDB6S0RaY3VWUWRFdG56dVk0SVBFdWthdGxncE9PNW5nWmtUWWl2TU9xbzljekZKVjVtOE1qYkJXVmxGY3N5WFVHNGhlV0NpUzZhZ3FsbGdpVm1Vc3FYd1pIcE9idk9qaUFZcCs3L0dlWU9NZkJzOWZGeEhsRmxyTXhZWmcyZUliQnZVc0tac3hVQm16TVd2aXJHU1lQRmVaNUxBS2FSZHMzaG5JT2tQT3QvU0NpZ2ptVm1UdWlSRHA1bFFPeG5wZ1ZFeUZmSk4wTHQvZkZBeTIxNWhMWVRUUHdySU1LME5TdE5ock1vZGtVK1VPWFZiSG1ZbFdBRFNyYzVIRk1IUTVPSUpXdHlSRzNOVkdZNENabnRnQlNCaUlGYUhQbVpPSzhUTzdydVo3QXkzektzS3ZFcUV3KzZtU1YrUE10d0dGZUpqQTVwVTEwZ2lGcXppd1RmUzJ6UnNlWlUzRnN6T0ZsWXFYTi9VUlpJM2gxQWI0bHdZRjBxbDhSYmhUN3k0dlU0NkRTSVljTFJBcFIxTWppQ3lVYmRpMVp0TEdQTWFGVWNFMmRMcW9VYW45b2d0bytQNUIxTmIrRGlPSDRyWUNlTVpXOG9BSVFUSW5JcWhpcWxRcW9Nd3Z3aW04b3VOOURHS3RPM01lK0ZvQ01xZkplR1VuNklIR2RHNGJlOGVkekFxSnRKcG5jdlB6UStVQXQwNWE5OTRpN01kUlZzRnp4TXBLMjduMnJheXZLc3hVcEZJWnVIRTNML3lFcEFNQU5OYmwraVlZTnNHYnNOWXFPczI2aWJMc1JLQWMxRENHTHBHV0lZYmVVWnl6NzFGS3FjdHVwajF1UFppU3VhT0loUGRMbm9mRzVSdUF1emNCa1d2Mnh3MkhsMUx6YUxvS21QNERDT3RxOFJMazk4UVl4V0dvOVo5bmNBWEhkSXVaZ0lia2RXR3lWUGNnSEs2WWxLWjhNZE9KNTBJNEZwbGRUVElPV3B6cTl4eExBNWtEbkxQcUZGay93QW9oa21vRnh1QnlXaHFOQUJDWHBtUlhKdVZRM0tRWWVZY0V6SG40TjB4RHJsTHFGd0RvVG1FSUdQM0tBcFJEeTdtTTgzcVUyVEZKR2J5UWszSFVFV05LOHhldnlaa2xLeVhGWnhnd21mZXBjdGRpb0lXSG9keGJCaGJLNmxEb01QdmtJTFZzNmlTaFJHd1FLTnUxWnlSd3ZVQ2J1MGN4U2JZb0E1Z1JhOUJjTDMzVXl2Snd5T0dNRkxlNDc3dDNiVXJvQkxBRTZHZnZBQWJ5eEtKNGc3aFlwNVJCMmh3NElxZUpqVUY0djdvQ0RoM0dNVzE1NGh0d2hBSkJMMVFTSi9waVh0RGR2TEs1WGhiS3pGRkpkbmFFVm9NdkVldDFjWnc0M0QvQUtrYlF0Y2U1VzNRbkVLZ3F4akpqZk4zSzRIWEZ5Mk5DOXNJQUJRMnpzUG8vbXFKQlJMWm00QVZnd0hhNWl5TzZ5bmlCd3ltMlp1L2t4Q0FVVkdSM1B2RXo4Q0FzYWR4YWJnbWNPeXU1MG9IMlRRQTNjQVpCbUR0R0FQUnd1V200N2xoY2QyS2NoU09wOXZIQ2pPTXk4NndIRTJ0cXhtQ3pmTlFhSStDVzlYb0ZneGI3OVM5TnBkWHFIYVdGOUkxRjIzaTRYMkJtWkVzRU1kc1RVMmwxNWxYUVRsbU9VV2JqZ1VEQ0hMQmpCZFR3OEZaaW1HdUdXelFET0ZuWGxoZ2dGUXJxSUFmSG1XNkkwK1VxVkZxcFF1d3ltTHFxdEhZVjQ4d3lmVk9ZcE9rZHhPMFdaaU5GVFJaSHVBUW03Si9jZUhEQmNWYXIyemN0bkI0Sld0OVRFSUtMajNNaVMvZ1E5a25GUUJ1MGJnbkY5OXhUc0RtcFZaVHFXVm1jVVFwZVgzL0FKbjR3RW9FS0hERjRYTEFUOFJYU1N3Nk9vZ293ekZHY0ZSaEJVNlpVbE5NVTBJZm5kQXl1STBQTHFOUTFCK1pxeGx3M0dzWm1ZWjdtVGhJQk9aa0txK0dEblU1K0hCdE1SdnZ3N21FdG0rNHU1bnFVUmVLY1M3Vmh6RDF2SkNXTk80RU84SDhROWdmZHhDTGVKSlZyZUZiZ0dnTWxhTVFXY2N6TUxGRnNsRHBXNmxsaGFZaHhqZHRjUjNCczQ0bWR2OEFGSHd5YmdNdk95Q3ZGOGhEVjBGS2hyQVZoTElIZVlMcUVDa3JzWklMaGxZM2lNTEJaYVlMZ2dDNnlqa09jRWFVc2ptSFhGd05DRjdZSzJUVjBuWGVEbVh6bGxseTdEQnVnMUFVbEErNUFLOXZQRVlhUmF5aU5NTlZKa28rbDhoR2xWMm1pQVBZMmtwMFY5a2RJN1ZMaVBsU2dMQUtQQ015NWZ5dVBsc2NRbFVGRHdZdHVEQ2tnOFQ2bTJWVFpHck1VajZnMFZoSGNGMGxkY1p6S2psOFFMR25jV0JMekxPcUNPNkczY2Z1WlVFUWRUb2c3MHkzUWVqaGdZRDd0eDZhcE9KV0RXMHZnZVppcmR0d2hKWlJya2xsRlRhaWQxZDNFVW91eW5NTHJYYTUwZ3dKeXpNTDVlVTU2cFJaZ2RTelpqR29VN3o3bFJORWtkVmZJTnd1NXV4ekFhSGpadU5HbUwzTHRYUERLc3RkdHlsVXZBalRSNHFzd0QxQVA5d21XTHZPVTg0UGR6RXJPeVpRcy84QTY1aHZIeHd5aHBwWkI1dmFZQVZZVzlSZlVBNDVaVzIxSmVGbG91YjRDR3NoVmtmcUF5V0t1Qnc2R1pxUUxMRUFidjFLWWFPTDNVZmFYWTgraVZRS05Pa29VMjlEMFFoUmJJQ015YU5ZbVZIa21DYXNYTzA1ZUpUWDR4ZnIvUXFMQnY4QWlYKzB3dHZFSXBaVlpVU2lOekY4c3k3MmwrOVpWN1I1bVFPS1JtTnlzM04wQUFMV2FLbFFwbHAzRzNMZzR2dmlQVm96aVY5QlhKUE1KakU2bUJIbzFYRllqZ3VWNGRUTHlIaGpaUS9WSDF4blEyOFJmaWIxdjNGU2pQOEFVZjhBNVpoN0oxRzRvWUxCQ3o2WE9aMlZteXE0U0FDK0N5WDhyNzRpTmpjTVlSeGlHOHFjd0lyMFppVkJGd0lsQmFpN1dFdHM4T29neWczYkhIZ0lERTVWV3ltT0VBT0tJanhTbEpKWFFjUzZPMGR5dm1UZGVJbTJOMzd0TGFUcVVndU1rZHNxL0pPV0RDbVl4Zlh4R0VncnpGWjVFYzZsVmVubEsxdW5NR3hDWGlWc1lxUnVZenVGVmVTUFdSZmpJTVpmUEoxM0x6QUZzem9XWm5LSWJPWjNxSlhNNlk1Z3NPR3RNTENCMzlWZkxGY1lmSzlZajJxVzRTVU5MU0lJNSs4c2o5UW9FRlBTZTVsTkx1b04wMW01Y0Q3SlpHcTlTMGlmaVdyZ2huaGRWS0JwcmlaQWtMc2ZiUHlwY3pQTFhIS01nSmc5elQzWGNmSkFPcG15RjhGd1MwQnRtTDlwMmgydXp0NG1HQzNCR2FWT2lFUzdZUnJDZnVKbjAzeHZIY1BramxOUXE4WHVXMUZYOXNBMFRtcVZ4dndwcjl6N0x6QUY1QmlMQVlRWVdNb0ZEeWxiTzRPb1lQd1BDUG1TS3E0YTRQSlVxdTdhWWdCQVhwaDBJTDdqUVd0Tk1BZERjbzNuT1pSd1BIREh5Z3gxd05BV1hFWXVtVTRTamlXMWxseHhTYXN1MEVDNXdKeHZNMG1yZGRKbE82V21GK3BQUFhpR096dnVObU5qSk9lOERVSXFoRWRnZEZRdkM4K2t3Q0ZsSEpVRWNkakx4amZadVBGMWpRRXd1WHZ4OVZCTFg4T281UWJQbGdlWWwycFRhSzdpNVEzY29xYmlqQ2N2OXBrR2lZQWxkekpCaC9NTW9vNmd5RkVRMjczUE5zVVpXOFRCemlvQnA0bEd5Nk1YSGJnNHBscWplV3gwMUl6eW9RS0oxLzdGQzEvNmxFQmptY1pZbW9BUnB6QUdVQlVXZVdZR3Z4Mm5NZnQ0TUZhbW4wSmp6U3M1aTJ0RFVTM2hxK0lmWG5oTy9VeGJLZTBWR3JURHVUSlJsZTFWcm1ZWWROMUhMOFJMQ2ptamNUWk5oeW1aVThLRDdUREFsbThUY1hoVXZTYTFiTXd6TDFFLzRTT3JXdDl6SlhzYzVtVk1lNW1HZ1gyU1o4VlYyaWlEVGlLcDZSbVZ0OVJBWXF3dUlaZWtlMlZwdnBjdU5LNWxPWFRqNFdZa0paNllXempiQzdyYUZFbEdGY2xEY0NuWjNMVE5mc2xZVUw1Z0lzWHV3UnBXMnhDamVUcnhMUWE2dk8vVTJ2V0R6TS9jdWRsL1R6OFZMVGN0VEVkNTNOSXIrRDUwZ1pSbldvaDRHQ1l4akVxYmdtZCtVN29RUSs3MUtNcFdyaFFzSTRpMGJsanc3UzdETGM0NjZzbDhwMGkwbVhGeG1BVVlRamNNTStKV3BwNDZoTGdDb0RGZHdJZUI3bDJxSU11NWQyT2FsWUppdGhQQnRXTUxlVmY1QWlVNkdZaU5GOUlnVGpUN3lxbk5DS2N5MUVSZ0JrWW1zVDdzVktQS3NNVFJ5NGRTem9Cd1RWbmFpTlJMaFpncUkwdG01ZW9IQkxDMlZsRDQwWEF5bkpPSG90ZWJQc2dXWHJaTG1zQTVqTzFNSmtKbUdLL2NMaml3V09XWTEwcGlPekxQR05XeUZuaUxBOHpraVNybXVqSG1hb0NPTEdtZkVWUXJyaU4zSGZCRHlrV09WN1lhVkM2emFlWXhpSFRoTXNxYjRKYmY1SC9aa3Raa3ZVcGVjb0VkWnBqNHVDWTRYa2krRFBubG1FaGs5Zk1DeExjUXdTUHBPNWZ4ZHFHdmczQ283UytYMUFmaWwzSHpBdFFjN3hBWGNoYkQ3b3Q0RlpwaEIwbzhHL1R1S0FmK0psTnN5eXdjeWtzeS9jb3gyM0FVaStUaU5lUjFFSFRteWJRQ0JJQzBJRFpyMEVNQlJuRURJNzE3bWVtUnl6bERTdmN6cGIvVVJ0cEYrVXdTcVYvdVUzZGY3Z3h3NElscjNMcWhEWHdVQUdWeXVCNmk1dzRIbVVma3RlRXhpc3dSWWMzVE5TNnJYQUNZT3lLS0J0YzdnbWx5U3hlWFNjVEZpcGVXR1lnRzVVRlVPKzVHbVlOTXcrYU9RRVpCeEJJdzFpS0xsdFV6V3lqK1Z0bXdqcGk0RkFwWk9JYnh3eTl5KzJJUTlwY1dFK2F1KzVRd3U1SVdLWkZ6VXpST3F4MUhUSmdCQlEzTjNCdGdMNE1JMmxvakJLT0lXMnM0cVVNMVZkYklNOHpOUTdaTUpla3ZRN0MyRFgrczRGR2paQlhNRVE3YWlKY3hhZHkxcjR0eEMrZmhta05UQkFnRHMvRVdxdWNWWWxJdlFSYi9BTFU1Q2cxVVRtcHhCbXlaWnpQVVdHRVVQSVpvaWd4QkU0bVBxUFN2S1l3ZXpOMFljM01PcVlmRzhYRzZOc2FsQ25ZN2lIR1Z0eW5zWlN4WlhvN2xNRGx2T3BiaG9sN1g0Zy9JK1JzVERtWk4xQ0NUbTJFakVNelowbHAyQVpiaG5NS0tGZjRUSFZIVUV0YnNxSmpiTGQ3aVNrYnh4Q0FHOHpDVkZVaTZvYXBYTnhCNUxvSU5yeFllRVYyZW9MWEV2YWZEZzRDSDcyeHdTWkpvcXhNK0N5N2pwY1NUOGNqTmpsV1luaXJsL3dDVFRPYnNqdFFVT3pYS0VaZ3E2UUxXZG1MQW5JNVlxR3JpRzk2SDl3QVEvTnNURXd2U0hGVlVNQURqTlNyeVBERzRTNGc3bEtxR0NRc2hpaEJaVGhPeUxjSDRhbmlIZUlZSU41aEtRUklMdUNYTXk1dWh3emtaVzFEdUwzSllqQmFJVks4NFhrVzl1WTFIakFlWlpCTzJVTXhYVCs0ZTRiYzBqWEFja3ZlNHdIY3RGM3FWZUtPc3JncVQrNWdnNEhuaUkwQUMzaU94ZE9rdmRISVR6TE1pMXFac0xrekZsNHFFSUVENVdNYm1CbDlKUlVzUHVoajViTTZqdm5DV1FPT215WkNXdVdMSlM4Qmc4U3V1YVhxS1U4NnZrZ2FGRVVCYTNqQkRnT0djUnBiY3lKa2NZMmxLUkR3YWlRSmpIQkl3RHJsNmdjQTlpNWNoUHNaWXFoWGxLbU11WDVsa1JCeEtuYWJ3Z3ZkRmk4Y0VCRm5CamNGUVdmdEdUSWpIS0UxeWxJUVdncE9hUVJ4eVd6bCtLRXJtM1FjUy9oa0pIbjFNOTR2dVQ4RkdjTEhaTWc2a296L3hId1Q2UmMrQ1c1Wm5MWTFQSEpUd2lCY3JUdUVzR3BVUlZGNHk0TjI5RVlBcjdxV0dCTG1xalVDdlZpSE1TOHhUZ1IzVW9sWVhMQ0UzeE1WVllZdHV5QUVydm1XSTVlcFNHTllsV3VqcVhOWUI5d3NnNm1PcG5jaGFvNC9KRXBaVU5XMzRJZkN2a204c0xTcFV2bUEwcnd5OFVsUENMakIwMy9JOUhrUDZTbm9ORVZCczk3SWlML3d6RVI0OTFkd0JUaHlVbVpmblZiRWx2a2xBVFBKVlZIcThuM21MWWR5cmh6Q21aV3Q1YmVJR1pxOHU0RE5tV0l0WkVLaUdmNmxRVWp3Nmp1MWo3QmgwRlcwRGlWVm5ieXNPUnN1emFYbUpibUhIV2c0aTRwR20yRGpuWmxvWEsxNmpITFFlT0RoN1VacEhFdEdSTENiaWpveXRTSFVjOEpZdmlMa25aZjhBQU5mR0dXQ2NNZEpzZ0dpcTJCTGlxTjR4MFpNVnFJbS94RW5EY3ZTUTlMOW8yS0k4c2JicklkTUlzZ0p4NC9xRVBRNHJjeGQwbUdvOUI1ZFFDU0Irb3lVMjRtVy9nRHVBVE5tWEJLUlhQbU5Td0dHem1YUkZhNXFNdFJGcVl6UVFjYjNydVhzY1JWclRGL1lpbDF0VVZ0dytvUGlnYjFNMzJ1T0t2WVdzTkVWMzNBb3ZLTXA5QlBMTXJEdE9CQzBuSFpkeTRJRmFGM0ZURnRsWi9NU0xQQXYrSWoyaWhGb21LbzFxYUJYK1FjanZhQlViUE1PdHhlMVd3KzFtbFFKdGU2aGtwMzFLRi9tWmM2Wm1aSXRnNmplU21PVW9vcEZPWmJnRGdsVTNVMk5zb1M3bjVQY1dBS2NKeXhLTVFvbGc0VXk2TmlLclFmcUFsRjNCZGdIZTVVRjF3am43d0hnTnhqK3ZTekZXSW5OYjZEY2FzUXN6aVVDcVNKV0dKeDJGamR5cFlvaGNUZlVlSlRLTHVXYUlLdE9PNExGY1BFT0hLSFc1Z29Cb09GeEx6ZUhpQVh0eW5yZmZ4b2dGWjVtUU5iVE4ySFpOZVU1RU4yNGx3QW1sRUdOdzNPWWpDUlBEKzFNWnU1WVJlb2NrdXUwcEp0RHU0cFNWVy95NWhzMWt0STJ0WWx4c1NxeEZVYTRoOUpzMFhIM0hWUlRUZm4va09VVm5UNnBpWHREUjZqZDhGd2wrU1ZxZzhhb0ZJbTRhc2hNcGJoVXlhVFlHWWRXZmRHOUcyUXlsK0FTRUVRRjRZZ3NEMFpqbFNyM3pFM3l6VUszZlZVeEZkN2dnVXJJbmMzTk8wdnlrZndnb3MzZXU0YXdhTXNPdk5uRXEwRUFIZ2xETUxhL1h5anBxV3R3QVRnZ1ppYm5jRkNFdFMvd0lGSzVGN21HbDFKV0pqaXpMbE1jdThBVzlpam1Eb0M4ZlIzNllYb2lRVVN1WmRXcURxeHFCcERVMG9PWXI4b2d1L2lZQ2had1Z4bUhKRjlUdVUxTUxtUzhGbFZ6RmExRWJkSG1IeVhCeUZuRG51T3NRUTdneVJCUkhxQTlCeEt5bmd2aVZPRFBNNWo0TzQ0QlZtWk8yR2F6QTB6L2FJSmdPZlVGQUJjUmd3MmRxWFFzYzFMWU9oK2dHQjVsNWg5SEtiVVJ4eEpTS2pCMGFZelVSWU5Ic1hDK0NENVAxek5TZmd6TVdJNkRLektJZUl3elgybVhLZUpWaklmbWM2NmQzQVVnckpORHlLdnpGUyt3TXRqbHRXZ3JGMmFqZDFja2ZFQ0s5UkdBZTREcDkrVmo3NU1NdDc4dzRLMHRQVXNpMVhVb013Q3hwWm5sbHhXRTVvTnJNTmtHcXFQU1g4Sk1pcTl5ek16Z1RtcXRMbGppZ014aHZ3bm1hZVd5b1lkc3N6RWJ2Q0VFL1p2cUlxQnN0S0NMVjJoUmFISkthR3Q4eWpVdlh6T016RDBFZDVRYURjQWRyNGltMzJtdWh6bFdDeitDeitvMlp3QStFd0NvY2tIZ09PQ0E4d3ZBYmxhQm5Lb1ZGREQ3bkdIK3BSWm00UUtKcGZFcld0Y2tNRXQxYVEyUWVVTWJSRjQ1MEVmWkJsVHNkTUp1YnZNRUdHV2E4UjNVSVMvaTV0RTNKYW12MGxPZUl6R255NWlOaGQzY3pZd1RwRXZ2V216eEtiTlBNQWxUd0hKT1lhc1JZdTdrYVJvbytTV2ovQUxVZ0NqcUF2a2NCcGxNTjdLekV4OWRNb2hHYWJoalVJZWFIaUlOOTZ1Q29VY3ovQUJNN1VzOW9tbmlhNUp0NFpHY0JIWEJMODZGdTQyS040dWE5TWdPK29VVitBa2ZHdEJ1Y1pzcU0rSmIxQVl4SGxYTnlsV1dsMEtlZVlBRG5icUVxbmRMcWJjYTI2OUlwS0QrS2xwL3dRNFgwc04xRnFCUjVnU2pBZDI0b0V0dW1hRVJXTUhDSWMyTlVFdVlrTGRRYnMreU9NNm1OT0Q0NFZKRnJLTEVybUFtcFE0eXlBdUV6TUYzZUlrc2FTV09yek1kb0c5eXdaZGRTdUFKTmFuQTcrazBzSnhVS2hYeGk1MWR4WnpET2RrdTRJSW96a1lpckV0V2VPWVRIT1RQN1JNc2ZrWmN1WlEzY1VIYldEL1lyM0VhSU1YQ3dBaWlzMWdjeXVWUTRCd2NYMnkyN0NFQURGbVZzM05Vc3loOHdtWVlPbVdQSjVJMmRUeUJjRkNsZ3lLNHZjeVNjRmVHTmlsYnVFTjIzd3hHcVlXRXFhQ3hxcHFwYVArUkJBVmhHSUVvSnIwelpuQ294V3M4OVM0T2RzYW1TeTBFdFRBNzdoQS83TXRqTmlSZFRwdnR1Q1JOalo3VFpMenhGYy9sS3pXSndWQnhOczRQMmhRMTNXT29pUnZ3anpaVVR2SElxaUVFQXpLSnVZaVdWRzBDVXN4ZVF4OE5zaDJ0c3VuR1pLakZaY2dEQUhSOEFpSHRGNnJmTXV1NEJXYkhKTmxCaWJaQ3k4M0FEN1ZGZUs3dTd6VXVGMWJEc2M4emFveDJ4VVlsS1Z4Z1hjNjY4U2pBdlpNU1dqTjRsQ2prWWQ5YVlDYnBoSVhUVjh4cG9jRjZZa2psMVhpVll5Um9ocnVKSDVQamFZVUdWQXFneEVYOWtzS0VuUitJR0V1ZUVsZ0QybDl4ak5tWUVCaVptd3UwNGgwU3gzL3NxcE44RVM0VEYyYTdoUWYxZ1FnNkl6TlI2bkdGeDVoWGh5RnN3R3FYeWpLSVBRTFlNUUgzRGlCUllNa3Bka05HTXl5N0RaTEpuVnZjYllFTWp2QXZGVkZvcWpycVdxaDJlb09HbWppL002ZnhLZGRpQ1J4eW5KRHZFb0ZiMnhUa1gwU3Q4d21jQUg0SlRDTnVTWkJtVXJYYlpjb2c5V0JmSktDZ3ZjWmdzcUR3cUdNY3BOVG1FZWxFMk01d0JVNERtVndtT0ZUTUVjcS9VWWNDQnIvczJuSzZsS2phY3BTVngweEt0R0hURUxwSEVGcHBVOFJTN3pxbUl2QnNtYkRwaUZtbEdRRWVaaW16NW40aFJBUTBzTHNqYnUzV0JOS2RKVTVIT1pnUmVpSXVMY3dWZVBSR3k0TFBTQU5CN2tLZzJWVHFaMUtmMlphYndlZmlxVjhXSk9hQmE0ekw1c0FWMUVRcVhpV3BTM3BJTUZkcFltZ0Y0NW1MNmpENTIvTTRrTGJnNlpoWnpMa2JtWVNyQWlxcVVlaXc5UTI2bmtqNXVEbUxMUjZzcUMrRnhJYmM1RXNGV1lKTEhrWmdlZ1FFMU94SHdxd3h6TGFXa3o0Uzg5Z3E5UnNnWVRVRzZibG1kblRWUzh4TXVIZXJqbFhDeGZLSEl6SE11S2N4VVAyZTQxb3g1bWVYS3l4Q20wSEc0cWl2SXpBYmhqRzR6YXVkVXZncEZKdENQaVdGU0wzSktGRWZJZ0YwZWlMU0RvR2NOTERoLzBKdDVvbUc0WGNhWXNnOFRTSHlRdUJxZUZmRXAwRXNYUWR6VlpYamlDTkJtVUFHR09lRkxpRXVrNTFMUTFHNWpockJVb0dZT1U0bHZibVdLS3lwdTQxVXNsZ2hkTGlMQW51Z2VtR1QyYWhManRWd0xMQW1IY1g2REtsOXplM2NFbTd1Q1piRGtTdVF1dk05US9MdVlHQjRpRDRpY0ttdzhrWmVHSW1xVmE0am9JVEd6VzNtTXFtSEhhT3ovQUdRNGl6WW5FdTZiN0p6QUc1NHNZaXh1NWhpOElEWWdlR0VkNlpnRGM5SW9TcExVWW00REpXT1lkdllNZVkyVmRrckFZWmpKbW03RUJadjJsTVZsZk80aHI4aElFVk9ja1ZYUjJlcGQxT0d5TVZJRjFFVkd0UW1QTVBVTjNkd0tad0N0azV2dUlwUjMxQ2RnZENWTWM4dzE1SEJDdTBUV2FVM2dXRGE4czNEb3B1VStZTTExRHJ4U3duSTBmWHdyNEtTTEdNTXRnWjV1TGsxS2Q5a2VDUllJVVIzMFlOeVlCTGh1K09KWTN3UkZvY3pFT1BFVTVIM21Ga3hMSFE2TXpLamR4V2JaSUZ5endSZHF6T3J5bUtFWEY4STlXK1lWdFRkMU5vRzJvTklQSFV6ZXd1eVh2K1pBcys3ekJVVHVOc3dhKzBKY1V3OXdhdk1NSnhrd0dEcVp2QUtIc2pWZTVrbVJ6clk2ajNEWkhvd294NGlzeVlQbXJoY0htRXFyVzRyMWpxN3V1VW91cnp4TTJnUkx2UkYzekRFVVhTM05aYmFHV2dVRHVMY1d3Rnp5U1YrQXhUS0h3QWxDMEJoNWxTL2wxTXVzY0JMTGVYVU5LMjhNeklVeDVJeVlzS080TTNEbS93RElWTnh6dlVId1laT1k1MXZVTzBtMHFRS1l2aE8vTVdpZE81WVpBWm5HQlhLMnBDMmRzWERRWFRnQk1lVHRPQ3JZUXMrRWVwZnpINFRMendkeGQzdm00VVpZdGU1WjY0VzFHZHluV1p1dUkwU2xWYjRuSnVKQ2d5dklSS3B5OTlSRWR5b25mVUh6UjJoUnUySGdSSStEcUZMbDNOQWlTTXBqY0pZRk9vOTJ6cWRTZFFBVTFLRXZCM01HSUhaTVNHaU05ZzNHZ2FIaVg1THl5NWFtNjFEYTJPVXpPZUVwZzNDcVdiWm1rUldLT29oY0ppQ08wZXBDbkVwdGhxTnBBOFBFb1FCbC9zdUVzdlY3SVhCaC9VTE1JOGRwbXUrWVorMEw3R0xyRTVtZjBtUXEvTlJ0TS9jUGNKOFFVeTV6cURjUSsyTzB4V0NiS0hyeE9TRFgyUTRwUnVBU3RjK3BqVkhPT3JaSFpjNll4MEdDeURoYTBoTHJ1WFpISm9ka1h3VTFxTWdXNEVKUjhpSEdHQzV3OHJaVFlvZTRjd0p1NG1wVnlNcllaMW0xbDNGekxOS1lRS25EekUxTG9YSzhuY2tQZUJ3eWs4RVplZ0dKa3ExUEFjZ3U0dHh1QzdDVEJMcVdsZDI0U3p1SFMyUFRMTFB6WEZJTnpUUUptK3NlVUVIQXJLSUd5L3NpUEdHeGJ4QVNJTmpIY0w5cWo1WWNSUlpjcERoTUNnR1VXVXRTQU1XUW15OGtORjAxS2FQbVlkcUwzQzRXWmxmU3FpU05uTVRBdUIySyt6RUJTNzVqcTRJZWJlVlIwUUx4M0tLSTZseGdlb3Ezd0JXYVBFcXZBZk1EcFRUbUpZc096QjAyL01ZYjZyTXFWeFZxSzBtWEdJTFdPTWpSQWREU0JEcW04UzFxSEhFWkVaenhNNEZNYUlSSjBNeTh0UFBtVnhYc00xdzlpa2RYcm91VVo5aGNWZHpNejNEMnorMkVyVEZmUEV2UVBrSlZtYlZVdUFlMWNRdzBNVE0zSXl3MTdQaEtMc0pGOG1LUWkvekxId3YvQURtSmNMM3VDaHMyUWNQWExUZ1RTR1RReHVhRFVaV0I1bGcvdS95WEQzUkFTQjFZanZjTytrSkxKV1kwUlV0cU11UHYzREpQTnpBTXkyK0l6RFBJNVNxMVZjZEtNd2k2bEpxeWw0ajBVTUVneUI1U3BXMUtUYUFBQTFoaUIxM01WcUhRVll6RG1CNmpQSzR6aWFGKzRQOEFyQ09XWlR6bWRTdzRGZHpFZzhKWVd6MGNRNkZlWXVCNkVVRldVTGdjNWp6S2hwcm9ZZ25FUTNuTWdiZUNDbFd1a2ZGT2UyYVc2OXdPbjNGY3VPb0hrRHhDWTVpeWtQTWR0M1NCWkErWnRjOXNRc29ncXg4TUJqaDhSV2N1b3RWa2FpckpzMUJzZ2JGdHBLYUZoK0praEpxa2xiSHJ1WHFlZE10ZG4rMGFoOXBVV040OVNvVjNGeFZ4Um9ZZnNSRGVuaXBjR3duS0ladCtZb3NXWExmaDFIeHUxdnA2bXp5MWVwYkJvbFloQ3NHRW5Qd3k4K3BrNFJmTVlkbnpPcmgrWlpDb1pYL2NVaWc0U3B2R3g0Wmw5UTFVZWtlU014WXZETS9LcjFQSkp3V0NaQXVEMXNNd3RoNUtsOUwxWXFMT0NuRnhVTldsMm9sU2FYRnhxRjJSVDljOElKek1jd3dYaVZ5VkI2RG1QaGxrUEJGNkFjbmxtZlVEWXBJdmxUOTBUWlVvNGlGR3JxYnRYZzVnUG1HV2RSN2FaaFhtdTQxcjdFTVRFemlYQ2dCWDYvRlhLOVhxZVp1STFTWW11L3hLWGltTjUzM1UxVnozTDFlVzQ2WWpWWWxvWVdjd3JUZnFVR2xKWXRwaXBCaExsenJ4Qm9mWkRSSVN0UU1WVUFGdkJseFhwRkJpY21FRlZNcEtoZFJKbWFyN3lzYkc5VElDUXl0eTdnQXdlWmxhekNTMStqY1prdnN4MFczb2xGbnhabjNwZDZtZ1p5QVN3MHpGSDV1RVhIV0lnaWVRU3lIK2lLQTFNMDRmVVhqanQvMk1UR3hVSUNtb1V2RDh4WG9EYnFCV2x5U0NLT1g4UUFHUENybFNhYVpsaW53UlphV3Q3bFRlazNGd055ZitUbHNzWVpsT0V0cjBnRm53UmFScDVxWlh3dkVvcFF1TE5UQXVwcStZYkgzVWRMejBZblFydTNpUHd2YUdXeEdxSVBCTGkxTEVHcmpNSmR4d0xlNFRMQjNXby95RnNUU0dhQmdhUjhWODFjWENsNEVpNGkraVZ3S1ZsM0JkWjdneXVwQ0FLWUhkc2N4MGwzaUhHeFpDMHNLbWpobUtYUExBTVluQ1NBRkF2Z25hRkdVT2k1ZGtOcmpxVmZtSklVZnl6SVdDYWpUU3I3bGlQdU5KeDZnTXJiR2VKK0FBUVd1ai9ZOUJRT01TNUs2NEk4QkFGRXd5bm1VTzVrNXo4YzJQd0MvVmNQZ1BQeVJNd2tGM044SlFzVU8rZlVkS1l5enFOV1k2WmhyQU9NekIyU1lGWTVWRndnMlhCQXFLMWRVY0JpdEhFYUxqbkdvR01BUVBMWkxqY1FOZTYzaVgycGJxVlBuRzh4WVU5cnFZZ0N4anVHdlcxTUJwTmFqZUVkUXBuWnFDdDVJMUFmSVF3RHo5U3dWeWVYcUNHTjhNeWxhWHNoMEhHYWdET2ZNVkFVOXhKRXhpZFFldnBNUThpcGQ1RXNZbW9aYVY1bVJ5ZjFFcWhsbEtpK3A0Nk4rb0VyQ053YXpPU05HNTZsQ29jNytBYjFXa3E1aXI5OVFHdG53UzJmbVpXNTVqNmljaUlMbTd4VW9lZzhRU2pQdVJadzdhNkdXWVFGckRraWkveHd6RndOOGlEUkhrTUZtUFM1WUdJWk8yQm5KK1lYS0lxSWRUVEF0dTNUTnBINVpmMGpCK0Vqc2xicjZja3FnQ09TVVBBRkZNYlowTFhLVnoyb3ZYbHIwbE1vY0l6UFhSZmM5bUlqelpsekxEUThOU3Vjc2NTMEFLZVlvdEpVVks4SnpUbVdWNWRNYzQzWjNGZ3RHYTVqU05DckRoWllzbk9JWUFHRGpDMkhDSXBWVnlWZUpaeThhOXdBSHZRRzZJUWJIQW1saWU1YmdyUkozTTBnZCtkeWhxQjhzU281aXJxWUFIMUs2SUV3eDVSdHcwYm1RSXd3Y2t0aGhNRmpwTVA1Wmx5elRCRlhXSEVLbVovU0liTFRyU3VPNVlBMUJTeE9Fc2dvbk1kSEl4QWR6MlVzcDRHR1ZCMlZEZHBVQ1pjRmFqM3AvZENDOS9KTGpQQmlOd0s0b3pQc2dYZ1JRb0o1NGMzTEZyaU1NM0VzVFlMM0hlWE1YSHpua2x5L2gvZ0dIMEZ1aUtoSHBhekJyN1NiWlJLYXZxbzgwRGdZRVNEbkdpY2NDVmd1R1k2R1pWalN4TnhiZWFvcHVBZjBTL1dreGZGVFNKNURUS0NtK0paUEJlVTRERlIyOE5abzZLRHBHQ1d5ZkRpVmdDY1FJYWNsczhTckp1WUI0WEg4anRlNGlEOGJncTI2SGlGSmd5M0Rib3l5M1RaYVl0Z09KZFRDRzZGeDJRN1E4RCtJQXg5R2FxSUs3ZmhjdTlJWVpZekJldlNvUTE2WExFRzlpOFIvdFNRQmJjckFMSjRZektXTnhYTmFKd1JZU3FweldrcjE1YWxNdzZRVnlFYXJDbk5UZXFYanpNaTJPSWI5QUpjYUdySlM3L0FBbTAyak9vZW93dzZIbG0xMTdaU2FxS1RDQzNHV2NrSnpFYmxMWXNmaTVmeGY4QUNmSTAvRFhPQmdtMEduVDNNRWpndHVJQU5ESDNtcGxYc2xyampCN2VJQmVJNVVua2lEVWJDcXhEbFlQU0xSdURLd0d5RmNNZnhCSzRveFN5T1RqUGNTaEt4cG1BMFUyaEtJWjBrTHRJZG9qamRGVHFZOFVzajgzSVlWSGtEd3U3amlnbUxTQkp2SkJ4andrY2VRalduRGR3RjdWek1tRVVJc0h0QnN2NlBDTmtYSjBUSUJhUkZYaStJdEJ6TVFIbzlSMFFocm1wVTJqL0FIQ3h1UlZtTGNXSXhrVWNsREJGU0NwUWQzV09ZZVpHWGVYaUpCdXZ2TEJXTUY1cUxhUHhNVmxjcFhicVdvSUx0eVJNM0Q3anFINEp5aFVMUUdHc1AyaHJBbHNXUHd4L2xyNkJtWHdnUzdaNEdIYlRPRlJXa2xja1ZOVlFFVXdLTUp4S1dxOFVJU0Z3UnZDQ2tES0Z0UjJ3U3cwd1VXY1ZVQjFRN0pSOVJWeE8rWFhFVGI3bUNITVV1S2psMTV4Y3JQbVhURDdjL2FZbnJzR3JsVEVxQmdMa3FrTXRmcTdvU1dyUE1XU0REekRyektzbldMaE5EY0dtWW16NmZRdzQ1cmEyanhCYXFJUnVwK3ZqRzZVVFFRMzFNQmhEdlU0UUlsN2NFUGtiaUNndHp6S2JBSER1TkEwZHl2YnladUphR25xWUViZHQ2bHJkbmFWcHhCR0tyWXdVeEhQOVIwRDVWTWNEb1R5cm5wbGhkUHNqUUZPa055YWNzRXY2aGtyRml4akwrbCtIWDhiQml6RWk0Z2FRUDNHeGdoTUM2ei9jcEswZWVwaG82d1ZBcDN6S29Ic3dqZG5xVzVvRkVUaDNVdUtBOVRZaVlFK3lOQUxtemtsdCswNWhRd1ZvUXdrVFp4TFRRMDVnVTFrY3ZFVmtMblVGaEpkalhpYlJibnFPQmRXQTNLNHowWlkzcUtDOHU0QkNtU21NTlR3UmJzcW15Qkczb2ZLV3BmMm41WlEwOVMxbDA0bmdoTUlzdXN6THVvMVV5RDE5dytXUE80RmNKM0QybGxIS3JPakdFaVF0R3FsVHVXU0hZODl6QVlGOXc0RVVuSUpjeGJWN2NFRFNUSmlIQWY4QWNhbFR0aGwxcnF1WUlZZjJTOWNYNkg2WDVmbXY0dDRaSnBMQk5SREh0TG9HYTRqQVlIY3JENEhxYjl3V25QVXdGVEFrZFFCME9JeFZIRExDS1k5SGlERFhyWmw0YnNITUtDRG5MRnJGeUNKc3phWGJESUd0eFltR1dhVEhjTEFGTFYyZUk3czFGUTZsMkdjcWN3cUJrdnFQSGc2clUzOThyaXBVYlJZaEhCQUFLeEV5R003bXNvZ0RMVmFYZnhMcTFwbHZpNHhPRWFpVGlKaWJZcW9nUE00TGwzY21PVUhTMURGQi9hZGdvYzJNQi9WQnN1STJrQTF5SGZjcWlBNWRTc2IzN2pZMFB4R0N1dzFONm4vVDRSVFo1aTN1WEYraC9nZGZCOHY4R21PVTJJWUdMVkV1QUsyeXVOTk5wZnArYkJaRllDdFFXbnI4eHFCMkhWd3hsVitJeTFaeG84Rjk2SllyQy9IVUdGelNvRjZRMHc0cTd1R1FYU0FtVUdJUzZHZFJUMXlWRXE0YWNUYk1sbFJVN3pRVlFzMVhVZm9Sc2prNTV3Z21waUI3VERJOHVwM056SGttVU1sTWViUjJRcmlCdENxWmE1VXlocVYyUlJtWTZtZXB0cWZhOG9UemRpSTdLT3BRcVVQTWNDZy90SzNiR2p1WGFWTUhjYThSVEZzY3hZM3ZMY0hrT3lwUkVrb0sySmZiUCtQd3NmNW1rUGwrdGpOY09ZL2dRZDI0TmZXM016MDN1R2xpYUNEVTdVTlR3YWFJc1JTQjVxT0djbVlLc3FxWW1LUmNRVzh6OVZMMUZTelY0bUZJMlM3VTlSaWdIZkV1WU1XMW12aWdPR0l3VUtnVlRYaUhzY0pIaFR5dnBmY1NCL0JOME0wQXVOQnBadURTbmN1ME03V1NvOW9TWWNudE1QbU1LVm1ERlhlNko1STZtMUlBSTR3Z2VWVTFYWGdpT0FyamlHOUVSbjRxRXdHalR5aDZ3RHhOaVpNZVlLM0xvZ3JnaFFHYzdZb2w3NzM5VFQ0Zmgva09vZkQ5QjlXaURIeGdxQ3E0T08yWUdEYndoTTYzQXhKZ1p6YzNOQlV0Nm1scmtsV3pBNmdFY0RBWkpaaWdMTDhrMlhEY3BZUWN3Vk8zUkxnS2U1Ui83STBVTWRTZ3VJOXhGZ2NXQlFxZ0dGekNBOW1DbmlvWFlXcVowQ2FoSUFWeTdoVWxMSmN0L2lQR1hGNlluakdBdE1FSzI3UzJ5c2VicXBjNjNodUNlUnpVY3VabGVaczVnWEhWRlVOdmM1SUlxeDRKR3VKZGVwbElHK2lEUjR5MkdtNDdnVU4xak1OQllFVllYbkZoU1pYSkxTbDVWQUVJalFPd0xnS09DdVlmL1E3L0FOakhVWS9TL3dBRHI1Zm9xSDA3elZPWTQ3eXNyL0JLakx5amE4eWtDYkZ1K3BqRHBzMUdZRlRPTk1kQmRaYml2ZTQwUmVESkVGaHBxV0RhcWhSWDJ3QkhSZUlVTGkrTTRZTGxBWnNYcVMzVUhGekF1V1F1Nm1iQWptV2wvd0FHWlU0ekVLaEtjb3hreHpNMjhkaU5tY2Q0WmVOMUxFU3oybVpuMDBoRjRpNWg4eWpBaStVNXF3OHlyMnhzV0I1ZFRzcWw2V0hsTkludFl1N3VFZ00xblU5N2pUQ05WcE1USG5NYnFYR0NXSkxSb09vVzBlWVlJMnJRTUIwSlk5cGRBLzFNeWFwUDE4bVAwdjhBQTYvbDIramF5eHZBUlJScWt3RlhmWktFbFh1NGEyQWJjRUhGZzJpb3RXeU1BZk1wa0ZnaG5NSU84RnpQbWlLWUY4VW1ibExYY2J1Y0xsTHQ3SWk1Qmd0eHJPcFM0RnN6VXVWQzhFYllIVUVMUkZIV0lhQUwyOHhybGZuQ0tScWppdGJqQm5VMWsxUEZJeHhLM21DMWlVb2xpNDZnUEY3UmlCOEVRUFQ0aHdsdUt6RHR6WkdJL2tpSldLdTZtMEUzQnV3UGM0b2pFYlZ1SG1CVFZPbk1iVk5FV09ZSTFGOENNS054U1BuU1pDL2t4THpDU3Y0bVcvOEF4Uk1ZeGo4bnd4K3QxL0tUUjhUREdibnlwV3N4dWg0bzNBUnZrSnoyemlFQTdEMDhSTnFxckViTFpoVjJzRkVUM3JNRGUxTzV3WWVPbzRzMWw2TkdjeHpta2ZJVjRnT1pIRHpNbXFQYUpTamd3ZVpsdUhtYlorQlo0eHZwam96TVdvQVZ3NmhiZFpJQllXeG1jU3VUNEpYVjZuWW8zaVl5ekJYd1BFRkZDOTJReG5CNGhrUlBraVBCbGpWNVAxQ2txMG9tU1cwTXVacmtwY0twUjZ1RW5Xd3lqWG1adVhnb2RYekxVV3d0d1UvcUMxVzhpWHhzelRpQ0N4L2lLZU44OEVwenA1dENialF3bXFseVRWNkxONE1SajhueWZyZGZRZndudzNqQ1J6dFZhSVR0S2FEaVhsczQwWllDTFoyY3M0WWpCMU1VeFVSbEFyTXdDUTQ2Unh5MTJ6QkFpM2tRS2haeXhoWTZteVhxNVZ0a3RiNVp0V0RpWnpjYUlMbHBRZUlWN0luRG5veXhoUTVpSUZkd2dVTndVbVFUY3lEY1VWNWxSc1QySmMxdUxJT0pSZ2t6YnltU2x4VzROWGJOeEZLTGNSZ0NsNWx2QmQxS0pERHFEamdOU25OK1pnb3Z1QUREc2dSZkRSank1VlZVeUcyMG9tY01aUzQwT1pobGRiQ1o4dFY5WVFVUDhsTkJzZjhBbURKUVNrYys0L0UybUxHSkg0UGgvZ2RmV2ZVVGJPWnN3U3FjbmNFaGp3eEZGY2FjU2l6YndaMUZ1NXp6Q2ZCaTVoWDNjQjRqYm1YOTdPa3JLSEZIbUZORytka3JRNkx5dzB1ekxLQnlaeGhmRTlRbEhPU3dVd0lEY3FuVkNlR1pRRENxaXRmNG9uQnhkYXNjTXUycmRybDduNElwWHFteGpwck1yOUw1bDJWYitZVVRnY2pMUVhDcWFkQkFYQ01FQlJwV0p1S01rS2hXcjhSek8rMG9BdjNoZGEzcVdVVGhCZzhqVThnck1MdHJ1NVh4UnFEbzFmaExCQTJUWGlaaEVSQTAvd0JoeE5rc0VGSGxaVHhCYWhwcDRobVJtTVl3aC9DZGZCL0dUUWp1WkZIUER4ektWbTZqYk01aG1BVitKVmhJdVJhM2k0QytJRmVFdHFhSmlEWmFDL2NadGlJSVVEYmVad1JjeTl4Kzdjc29TOHlvb1hSbXk2ODVlVzMxTWtmZ0c4WURjV05ZcGRUTEllSlZ1ZmM4d0pWRXF1WXcxQkNHR2JqUUhaQUI2bUc1WnpDMEJYRUpKNGlWYWR4Mm9UaGxNd0Nadm1GRWJsWkhwWkZEQ2QzQUJZTFY3aXVoaGR4dUVrcnU0S0pvakdXeUplZ2RiUWpPTlgveEtwWFB0T05QYWErUjBtWUxscUdmN0VoY2VUbVdhaUdmVXFibDFYcU92NUpueG5EN3pTSE1TTVlmeExyNmo2eUhEQkZFNnpLZkxMaWNSWCt5akdJdVdIcUsxOHdnYk45VVNqQkhVZ1pQREsvaS9oQzFsNGxxMkRCd0plYTJVRlcvdXFJc25QRExIWmROOXhITVo0WTlST3JnZ3o0Q2JWRGw0bHJlRVZlVFJSRXEvdHo3ekZVVWdSeFlxb04zUEtZd2xRK0tkcWlVK0YycVh0YWF5RUpaa3VwWWRwTVVFY0Z3R3hiY1hxYVE2TXpQMzJ4YU54RlVUbmNwbGQrZFJYeG1HQjF6T285dXBrK2p2aVlsOER1YW1uVld4TWkzVHpMSWorOG9mMGxLSTFZbzFlMklPMHFmeEtYNXI5eVpYZjhBd2dZK0RCSCtQZGZVZkQ5UXdSV3ZBUmZod3NCaUtvN2NzM1E2RGlVcm9aWlZTcUx5VkRlMjZqd0NvU0xWQzN5NWw5VjI2aUFGZEpOUTR4R0MySWNRblpXUkdVb3M2VFZ3SFdOUkpwRTRFY0d0ZGVJcXpPTVRGbTRvbkFRd3pGR25yWGp1RnIwSzJ5S1B4TU82VXAzTjRLRmxmQWZCQlVVaVZxQW9QZ3JMVU9tRk1UbmZ4TFVCQkt6RXFDTng4cGt4RW1qdk16S0czTjZtM2xjUWszY3N0dVZveVJiWUc1eEphNHRjdGUzcVpRam00Z2pCdk04SEFrYWw1WHVGQ2ZGU3RNRG1tUHVidDQzREFIRnE1VWIzOTZPRk1xNFFzWS95RjEvTTJsRWtDTWtCWUlRcGVENGh0cGJuWUFjQ0dvL2hBMURwdUNPWEZ0VFJQdHpDMlFmSEU5aUdMNGwyeU5ZMlNqSFl3VTh6U3dqbGpzTHpvSlk1N2pVSlF0eEx2bEoxQU1ENGJFY0Z1d1lNOVJ2RUxmVU5vRjA1amRuNzRhaCt3eGN2Z0htYTJHZTRMc083K0VpUWowbGNxM0FxQXNUUC9zQ3pNR2VHVkY1MnVBUkZNcFNScW80WXl5cHQ4d2c0dkx1V0wySmRod2FnYktHdVkyWWZLQU04SVVibkxpS01tSTZMc21qTWlFTk1jUkZGZmpFRE9YUy9FUVVFdk81V0RVdW9SWVJiVW93YXR5dW5BNDRUTVp2VEVwK0wrQVExTnY0SCthWmhWdFlScTBCVW9zUWxqbHFlb2hVTGFYeUlNNUdNOUlIamxNS3MyMTBkVE82ZUNzc1pOWFN5SWp1WUp5cGN3Z3Q2U3Q1TXBHcHRXS2o1VENrd0ZyWlpxNkprcFlTOWdzLzdIRjdYQmRzdXBHbE9uK3hyY2k0aWkvSFVEWTRsWXRnTS9qRS8yU3UySHhuOVFDTUZTdFg2ZXY4QXNDOTREYkZZMXFJdzU5NVVTSkttME5GWDJ1STNjWUxaWU5EVVRPWXNMc2xKa3FwcE5DRnF0VEc1WG1aQ3V1WllISndFUlM3NU9JOGFRTWVaN2lFRHlYSmlNdVFuRTlZVlJEcTF1WFMxeGdIdVlDTDlFREM3ZHUybVdRTDc0aTAxUVJYcVBUVHozRXJwbUVzbkV2aGVZNVBqbytBamdtMzhEOUovQnRNU09jWFlnSU1LZFREaDBJZVVPTDB1aWpZRDBkektqSzFsbFJUdFNiVm1oQUhlTGJtTVYzam1CazA5NmpZclFwamRWVnNvTHIzRUNwWEtnaTgzbVV6RkRDRFc0QXdUS3F4Sy93Q3lMZVk2SG1VbkFWanFaVmJBTW16eEtxWGlWWjQrbzZpeWdqcWhLK0xGSnY1RmM0MHg1WWt5dzI4bzFGNGhBWUUvdC9CL1l6VjZsYTZ6VndoNHNKWXhTbU5Vdm1CRU5aaEZtNmMvYWJQZ2twaktycUNyUVlmUTFqditCK2doOUo4RUl3aGhDVWF0RzlRaG5GUVcwQ0IyRUJXdVk3aWNabVFOOXczRzU1Z3BUS1ZtaUFEVXp1bG9ycVptNElWTlJPWHgwK0RsbWJ1NXdtaVpMNXViSnBGVkQ1SC8yZ0FNQXdFQUFnQURBQUFBRVBQUFBMTlBQRUxQUExNL1FiYUdlbXViRXVubkpzd3h1eGtVWnZaQ29qaGlwSXNQUFBQUE9NT0NMUFBQRlNmR2tmOEFYRXBlUUdpVUVHWnFyc2R4UlEwSDY0UVBZd3J6enp6endCVFRqVHluNjFRZWhST1BJZ2t0ZHN2SzR4WmVsSUhqRmsyOWk1d0xYenpIenp6Z1JDenZsMlIwZUgrSGZEUzgzQXdNSW9HalNhZzRrSEhicGh3bU1lenp6eXpoU2p4VHkxVngyUDVreEJQd3RFRlZYYUM5Z1FhVUV6eUJXeFk0eEI5L0x6enp3WkFqQlFxN2VHMmJBNGJiZDZrck5xN1Z5SXlGNHNTNFkzb09kVXV6cWg3enp6enlKSTdKOVJuNTdBL01jMFUwVFMzZ2M1UllNb25MNzhQY0tvVTY2aUd5Ynp6enp5eDV0ZCtlaGNrQlkzT1F5Tm1DU2UxVEdXZWlNODl3bXJTMmZML1NuZ2J6enp6emhDZXM0UGF5RVJJVE9oM1lPbStaZ1l2UWpSdHBEbkZRem9HeWxPT3U3enpEenpTRDJKWTNJWFZmeGcwQ0ZJUFpoSWRlME82RHFGUG1uZ0RlL3dCeHV1TUY4OGdVTTRweER3cUVRZncrWDAycVVzZ2NhQ0c2RklSQVByRDd3aDl3bVZhcGltMDh3WVUzbHdGMm5iRkpSZyttRERGeG1td2pPSm1qb285RzVFR3ZlM21lTisyckRLekdCSmZFb3FFWVc5eUJBZUJuUVo5d0dXSk94dWdZRTVzVENMS0d5QnM0Y3BCQ0pOWW5lQm00Y1QzOWZvNElQZnVPVTY4Nkd2QWV0cEh4QUtRY2c2TXNhL1ljT0luV1VrRzlsQWRUZXhxRFZ2ejFkNEZqcS9uTGVidzVDM2tZR0VsWFREMEhpRE8vU3hIVGYwdWVJZjVHTnRGc0NZbHFneGF0d0sxeGhOQTFBeWdaVjFROTNQTGJEMVVyc1BWbGJrekRGdk0xWkdOdGhKdmpWeC9yTGJ3ZmtaRjhMRE5JcVhFaUdzTFZwWU9mNmptZG15OVJWRWUyNlVNNXJFR1BjZGkwNiszbWpPa2JTd244aStUSGtnby9VeVZIbDlCcHk0ZjBwSkVYZzVxd2ZqOG9laS84N0U1bEsvUSt2MXgwK05ab3JJSDM5b21mUGVqakJadTBTanFaQytibThiNTl1azFaZlhWV1p6emlTaThiRUkzb0FpY0tOSE9md0xpSEJuWmJVOHlPN3ZRNVBlbjluWnlSRXFwNGx2Qmp5dFp3Mk1iVlg1Mjd2MWxOd1g2SjdYN0xadlREVEJUYTF1T0kycTc4bzJJWmRxS0t3SlVIeEVBSDRqZlJndzhUUVpKSmpOUnJUSEJFWmZDL01GeU1rWkRDa21KZzJQMUFLZTdBcXNwam54QUJGU0xZK3RaQjl2OEE0ZGVLNmRPcklvUlo0MVJvOHd3Z2ptM0lUOVVXQkUxUzBDaWZYeUhNQWxjVllYV1JJYStYcUkvbXZTeDIvRWZkUU1JRi9GRFVRY1VHV2hmazU4UlRFRGVuYTIxTGViSnovVXJqQXprZXZHRnR0dVVpRzY4R2tORGI3anFoWVJGSVR0TGwybndFdUdmY1o2L1loQVdPcEVaOS9OTGZiNGhhRVNRUmVOZzM4UWFsTmRKY3JXMG80RkhJWmJhNi93Qkl6TllYa0ttQkExQ1ZSanhFRkNCZVkrUGsrUVJCNzZaQUJ0WlpCakYxVzA4dmV6TlR1RUljMTdLSEE1YWhLR3hEMVZEcDlwU0cwRW9NaFZtQTVwenhEaHpsc05NZVRMdzJ0WlVheEI4bTVyVkVDenRIM2NFbzNzSXdnVGdnMUpoaVRDY3pTY01YOWR4am5xbW80Z2FDc0NDeDcvL0VBQ0lSQVFFQkFRRUJBQUlEQVFFQkFRQUFBQUVBRVNFeFFSQlJJREJoY1lHUlFQL2FBQWdCQXdFQlB4RCt6MUlyeXk0M1Brbzlsa3JObERrZ2NGdkVjZ2NTQ0NONFhzZ2NiWTVYQW0vOVdCOHdEQjVKQ1hRSGt0M2Q1QVo5VGt6eXltZ0wvc3FQbHRYY0VRbzBjbEFEOFdFRG5zUFdRTU0xL3RISWIyRFdOL3dJQ2JMVVVmdUV4bHVKR2huRDZpa1NFU2V0aWRmL0FHMi84WVMxRENqeGNjdDNSV0VFVFpsMlZSa1c3QzVsbjZRZ1JnRWcySk1id0QyZjNJaC9iQ0tkSVMyUXlKcDl4RGdYTElVMWovNnU1clBrbk1UQmZZUHJwSEFleEZEN0t2MUhESENmUW54TjJYR3MzY3Rjd0l4L3JQTUN5ekxTNXRuaHMzc3RyZElGQjVEUnkvMkVIZExNTnRFVk5XdEY4aDhmai9Ha3hyNVk4aHNuaTI5dTgrV1Q4SkhVL3E0dUh2a05Gd3REMVpPREx3eDNlM2Rsak80dHBTeVBzWEVLbmJoRDViT25Ka0lvNmp0L1g5SitEbG40R3c3NmUzakY0US9aRzhuYjZNckFaWWZOTWFnSTR3eUJQazVkdEprcUdZYTNmdkF1UHlUZ245SjRRTERzSlExT1R3c1psWS9Oam9EazdUMngwSDltWGpjeVBoQVVCeXd4U1U0Uy93RFdjZ2d1TU9UN2JHbnlFTXNGbWY2aC91U0hyMHM4eGxMbFBMdm55SXNaS2ZxTGhHdHZZTFRoUWpYak04WWcyV2tLN1gyT3lIQjMrb0xJbWZqODRkaWM1RDBpcFBWcHV4MXdzazBJcnEvZ0hqWC9BTE93TGhCdElHM0VMbHQ5N0hiOHNaTy9oZ2N5bmZFWDdWMGhERERxOFBtVVo4bWNrNDhkbkd1MjV3dlEvd0JMQXorbU84K1RKK1NLY2pIY3RjbEdrdmd6MDRra0QySXRHM2Vmc2NDMEk1a0RCd3VHanMxZzZ4Zy9TRFpRNSs1ZlZhU1Eremg4U0dSNm44UEl4TThhRXVHUzVqRERSZm5uL1A2c0h5OTdrdmt1eG13NHdpMEQ4SVBiRDZMQzhOMjNxTWx3MDhoZk1KZVQ1RW1ia1NrRGVjL2RuWWVzMzVNY2Nmc1lIeFBYK1RIRUxJaDlqZnNKYysyOXoxYjlCZXdma3VGYXpZV3N3TTZmcXlVTWYwNDJpR25TQ21XQkF2bGdEZG1RRmhZQ3hNakFmMUp2L0l3S3N3QnlPRGpCV2V4Q2ZkbE1kNW1oaTdOYU0yMk1QbG9hOWxNZkc5RVpDRUtrNHBCZklUL1NSYTNmQTk2SURQMjhIZVN2NkNXTjVhTmljSXU0My94bjBMdlJJdklSMDlzUFV2T0V2Z21Ia0phcyt3OTJOdCt4YmJSMzJUQkNVTmc0VE5sT3BCajJTdWw3a1kvWklzbkd4R3NSeUUvc25BUVE0Q0RUVHVvbXkyMFBuOUk1WWtqTGVYU0NWNytHUGNNQW5ZNjViTVpyUDUyWHczVkVST3lNQnZpN3M2aTlrTDZrUFhrczU2VzBYa2hETkVJQVVsVDhNQmRzSU5wYzhqVGtyaklIbTJ6dkorZWZnUHhsbC9rWm01Rk9Gd1NieHZGT25TZk5KUWo3WVFBMmRtWExiZnlRVXVkUFpJK1pENjdzMEhzakdEQ0g3ZUE5aitobVB1U2pTejM2UzBGSUJuMWJad3VOMlhOTkpQSCtRZHZDQWUzd3ZNUXAva2FtZkxUeTlBa3pzZHoyM2tqMjl0a2NtZjRCTXJsZ0xXQ0xONWNVY2hEdnNCMG5CcVRuYkV4R0JwRXp4RGt6V1BOMHAyYnRtSnNqSmtnZXR0c1FTY21QWStMc3p1czlZdUdGdmRNSmt1Y0E2U2MvMndISlQveTBjWUFvVCtIOGxuaXdqSGR1aFI3Y3RNcXpOeEUrM01tRVVXd1RZdzhuMnp3MkkvMHRHUk9Jamp0Kzh5eDhmZ3ZsMjRZNjlrYnlkZHRIc0Jrd1ozeGMreWpzMVE0THhrNWQ0MkRQZkxRODh2WGJSK0g4SDQ1MEhrN3FTRWh5UnJzUCtOL0FnMTFrQVBrUFl5RnhqeHlGL3dDTWMwNU01SUdWM0V2VjI5ajJKbXB5YzFlU1lmc2E3YXRMQjdJcTd4WmhkQ042dHJ5Y0QyZUo5U0V2YmY4QXRDOFBKL1V3MzdhSEozN00xNmVTYkpaQkRFL3VjSTExSWtBa3ViNWE5LzZ5NnA0dzFQMVpqckI1bXRUc0J4NVlOcnRsSm16STV2SS92bHA3QUR3anFzbEhzaHRqbDJRMkE5bnkzVHFGOVNNWjh5Mnd4WkY1QVBZY2l4b3l4L3NZMSsvWk1qQjIzOEFQWXZvMjVoNmhuMlRxOHZmYlRyN1llZWtOTGc1QTBGNUlBVDJCZVNHWVhlem5Qa2UxWi9ma1lrTTFPTUN3Z1hzSFRaeFQyUWRrVWc4aXlOblFJUGgrQUJ4ZUZXL1VhYWlqcWErbDErakN1OHRHSm41UHFqOFpaRDhnWktaU2xvYVhldnFCcWN5eGxqVTVIYmFHUmV6MzhCNmJDNWw2cnhHd1h0ck1KTWpqdllQT1hiU1BDSW5aNEMyZ2t5aEQ2bkk0YnQvNklZVE9rRE93b2ZpVEVzUkE5c3ZJd0dZUVZldjFrSW8vaDUzeVZNYkQwbEIyZDlMOXBEWUJNSGs1NnNmTDdQdHQ3Sm5HNGtqSXE1TUpnZHRYSDgvdWkvTFM5Z1lDK3JpTTlvM1ZtZGxIVWtQWElRZGJMczJuSDIxVllJUGoxZWhac1FQNUNQSUgyMUZQZFhEbnMvVDIzbzdCNEplRVhPd2NSb3lUbVNaZGRtemthT29BM3lYNGZuWm16anlDTmZTSDRJSnViS29mM2ZSbFFTNXVsbnFZd2hqYkQ1SUI4N2ZvOWtPMkwrQk1zcy9tTWplYS9JQ2NYSG5zTmRsZDM2V2h5WVorSlNmb1NBQmpEbG5yR24yUHlqN2VJOW11Zmh5NjlrMDh4bGRjbFRoUGo0Z1plU3RkUDd0bWUvdWZxeUQrMHNNdms2QmNQTlpGMjAzQXl5U1hIa3Z5UTlaWTBrSGx6RGJJSTE3aGRJNStUQmtJZEpWNnptcTFlc1ZSMjdXZGJ1ZXhzeHF2eVBreUM3N0huOTVIdGpYRGFjc0dQYkMyVE1aRDJVOFhMRHlHdVhFdzZDOGdKMTBzaURZUm92c214K0ZtcnFBWk1OOTIrQnlONWhIMEJpR1h4LzhBd0VkbEhUcFBaZWJhdm5rNFRoZlFtVzF2YkRqTmo4V3A2dDdaTEdEWmpmdGpma1RCbjd1RDloc3FGMlNQOWd3MXlOMy9BQWY3Q0lpWUVnWWR0dGx4czdOdS9sZ05oeFdOWitIaExXNmRKalpsa2NsVGJIa3Bjc2czVGYzSVJQOEE4dFJIL2x5SWR2NllCcDdEUEhZakd6L1Evd0F5SkFkdERUMkEvVWpvdXdJRFAzWERSdE9vOEJISU9PMm1iZkJJTkVsa0VEb2tlcHcwanpaUnI4akhIZHRnSXhsbzN5OFRrNDVUdC95MVA1SDlSSHN2QThnZlJkTDlOaFlCZ21Mclk5emJiczhleUhpSG1KYVg4WkEzc05STXNNcll1UTJYWHM3bk9TQjN3Z21MaGZMeE1KNldMUmZEbG5YZS93QUg4SDlSYmxqL0FGTDU5SmJDdklCM0w0RW9jWkwyeFlraGRJVWR0bTF4YitkQVRTYmNTN2NaSmVSNExhcDhTakU5bFE3L0FPUVhPc1E0OFA4QTdDWVhYbjQwdC90SmFTRlBrYzZobTFuYk51NWtFUjVkcjdNVGx6T1hoU1dQSXoyZFkvd01QVURjZ2VONEVnLzd1WTN1NTJFQTZURW5zSFQ1SUREc25XczNxSDhIOVp5MU0rM1h2eURZWG1YUmpnM2FBdmpNUmhKNkxsa3NjOGtSWU52L3hBQWdFUUVCQVFFQkFRRUFBd0VCQVFBQUFBQUJBQkVoTVJCQk1GRmhJSEZBLzlvQUNBRUNBUUUvRVA1bjZQcmVSNU1HMi8xSWp0K2t6ZnNLT2tkZElYN043WUdmZUZwcm5ZZjdMOHVpYkI0azVNbDVzbzJieEJ3TExtZi9BQURoMjM4K0ZsaVRJVUxFQWMvTE04dUloNUhXREhaMFIrRmcrUEd3OGpZTjIvOEFGa0k1a2FQYk1JeWN1VGZiVHorYlpmaDJlVy9KNWNraCtTOTFnUTBrVEdyYnJxR0NzWnUyNWNiWU43YVhZWWN0L1BwNUhsdkpieVJCSXZQUDVWK1BMU0lCcmNKZS9EYk45aGtHdVg5RzVFQTlzSExHN0Qrcmd5OU0rQmxsTXk1cys4Z2M3YS9mbVA1Y0dXaGxCbjhyN1pZZVhqeThObko2MkhPWDlQZzNXY09PMi8yZXN3ZVFRUEcwbmZ5TFdNZjNzY24zNkp2YlpEeVYrendyN0Rua08vd2I5ejRzTXdUSTI0UFlENUZ3WDVTNkxTQ1A5UFpRYkorMkRlV2YxODM4Zy9xMWIyMWVNbVFScTVCajJPKzJ5QWpqMkJjL2x5Wm5NbmhhMDMyTmRML1VNNWJlTHpKOXNJeE1oSUVkV21TUXZqYloyUjB3bDRXZ3h4MjUrUThGcXhOR2FCTFdGeC9LZkcvWjFaY3QrdmtJK1R5UlBQYmh0LzhBUzFtYkRDT0daZVNzWjZoejRyNmd4bHp5T2RmMzRIYklHaEhlRC80b2U4Skh3dStRRzE5UGdJc05NalJOakRtbHVlMmc1NUtCY0NGZnlCSDUvd0NXeC9kalp1RVhzbWp1V2JYa2ZSRkRkL2gzNGx2eG0zTC9BR0I4aWRHU0hMbDBzSHlmZVdIdG05Skg3R2tQMWFlRTU3YWhaMzR4MGpMSXl6THNpUDhBYkc3NGxHWkYxc0JCcDMrSEpmejUrMi8zUG53cStmRC9BRTVHSHR4a2xnd0lQbWYzS09GczlaY3lPSU5uVHlRTWJOK05oUml2eHo4dGg1RVNFSnplVG41L0ZoZGtoT1FadzM0NU9DT3hJRGsrM0w1eHMrQ0VtWTNEeTlsRzN2SW9KVHgrSDlNUnY1Qi82UGhlMmZBd1B6bHlmNEc3QWM1SzV0ZzZzNlpQbng1TGJSc0xQbWZBa0xyYlJ6KzU0MFIrUWFTR0VnYzNJMDRrSEpIMUwraDhGSmYyOXRoY2x1eS82TEg5a2l5ejcvc25IMkdYaTdqZGtXSFlPeDhKbTZsdVBZeGNaZGlZSkxqaGJmV09XNmJIdDVEN1paMndnc0owZS9Pbno0V0U1OE9URnY4QXl4ejV0dHV5ZUIyVkhPUXkwekhzUjhMSlplc0NvemgxbHZyd2c0V2FZVzJkOExDSHlYNk51V0NiZC9mSmE3SzlnUGJSN2UzN2QrK1MyNDNmK1B5WDROdjlUa2pDeWM3TWVUcjB0Q08vZHNPRWdFazNldG9kTEZ3Y240ZmpkNUUwbEp5UzJYTW4yM1lzTzNMTGM5aCsvV3lHWGtPMjdGeklKUDdqRGFiclBXd1R5MWJKeHQ2K1BnTy9GbDJJUTdLK0xveThqTDVtd3NCQ1NRVUdqQWJiMldOc1lEQk42Ymh5d1hmalUvMGwzMlNaMkc5U3k0YVFtWDRSMHNERjR5N0U4TGJCK3pzWkwvclBKSmtWZm92NWV1eVgxYkNoMjB6SkRoSzlPU1BwdmJRRnRRbTlnenNtOGxzM3dnU3o2Mjl5N0Q5TE9XSHpOOW5NNUNzbi9CWWN1STg1ZGZZUmMvcTg5bmlXa0FhN3V4N2ZnUUJrZkg0ZW0yYUZ0cmVlMkpyMlkxMjBtTUN5QnZKSGlUdVh1R2RqZjI5UGdLemk5c2drbmhiK2tZZG5yaXpoNC9EUFdHUFBnWXdhNGdpSFB3aS90ZzhRZjBTc0hqNGZVMjJsRHRuNU1HK3dEQ3dUTGNrOVpodjlSL0hscGRZTTZRMHYwZkdFR1drKzluNWNrSU1sN3R2MFNEbHZPWFo3QS9ZRGRuWHZJZDh2MFFCNWI4Q1ArVWtNZ3d2OGd1V2hKVjJJeDFzZXh4c003RHBjT1pLeGYyR1FmcTU4UTJKZ21rZ2dzUnE0c04wa3pzRUdENGwrQkJCLzNrbHJGNHZTTVlEYlE3RkczQkFXSXhHSEpCN0lHUm81K1NjNUZqejY3SCsvTWsxN1ljOVdBdHAreDVCT09rSGUzRjVITGZnZkQrSnRkUnlGKzJRbmtlNlcrakRwMjhJOTJTNE5vdVNjNUpMOWZnYkxMTjhqaGpCbWRFTmJ3RXErM3Y1a0g4cmUzTEwrNytpTDNkaHZZTm45TGx5V2tZV2V6MTR4dS84QURxNWtPRTVrdnk3VFU1cmFWL3N1M2IzSC9CYjhmNFBYeitqL0FJd1lCK0RySWV4a2RhVHd0L3BkRWN0bVRKbW5DVE9OL3dDV2lNMiszNlpPekIvY2hlUi9QNm40bW52ay93Q1FYdGw2aUlQNUh6emhaamJEdnpiYnlISU9FdGJBSjZTZm1zem43SUFCREgvRC9HWkhpNTFZRitRYzVEdkw5Q0lXd2pXTkdsNEdJUXdqOHc4WVA2a0Z5ZW1RWjdIK1M5MmRKZE8vQmV6NEkvaGYrUEh4bnJDZmJ5NnlieWJxTVJ5M3NHUUU3R1prQTgraGgwblBaNGpNa2JQeVM4dlp2SU82Mm1Id1kvZ2YrUE42U25rVDFyWkFFcHhDdnpJWjhneldRZExSbjBlV0VOZ1liYjZaL3FlY3VYK1Qxd2tsMzVrSDhxNUNld3NMSTViOHZIWnhDdC9ZWkMvWkJibGsrMkkzWlZINlROemtidXc1MTJXYm9pUVErWHR4OEhQNXd1L2pLN3Qrd0hxOUplTHQ4ZU1NWTdGdHdjdnkvOFFBS0JBQkFBSUNBZ0lCQkFNQkFRRUJBQUFBQVFBUklURkJVV0Z4Z1JDUm9jRWdzZEhoOEREeC85b0FDQUVCQUFFL0VQOEE0NmZ5UDBTOHpOZVNBTWZ4dlZLVThSSVFZVmNBejk0Q0NJclIzTnF3ckViUWtVR0cyd3hTQURYMEE3TWtTcXZFQk55OGN5N1ltajY2UXEwQnkrSVlKQzdwMUw0QlpDTTRYbHA5MlZqa1dYYjRoQ1VTanBlL01LQTRXNG5IWmxwWWY3U281Z0p6NEJ6L0FKSEVySzJJRjE2WWhGSUhMMUZLMUdNU0xNNFlvZVJ1QmFkNHJueENXV2dXUjR1ZFdDNHVuY1IrOSt2dkNDMkUza2c4bWhJMnBFaGIwV0xYbkhtQThHdHNnKzRnb3prUGlKTUE4Z0dTQ3kwU3MrSWcweXlHcURjUFNiTGNJSWxRd1ZibUJNTGNEQVBNTm91c3J5Y3hqYnhrd1hlL01xaDQ3ckJCclBtYklTcXN0Y3k0bVhkdHhMcGdOSTU0Q09DVE1od3dLampFdVB6Und2SHVONG9iTlFvdHQ1dlV5eVc1TnZpRkNFWWIxY0oyVE9Rb2pYUU4wYk14cnZOUm9kbmlPTUhOOVh5UlNEZGJraDJ3MlgrRVNvY1FLM2JBRmFmaW5walJWaTF5TVd0L1pmOEE4a3VVSDhYNnBDZzNLSDhYVVN0TFNGZ2Nidy9xR1d0dVlCT2pBdGthdytZd2ZhV3BWNEpXTlJGNnMxY0k3bUYzRXpsRXljSG1WemJETmtZdXl5WG1OcTJ1N2NkQ1VvV0pCQnN2TVJvSElIREcxV0pWUTVFb0ZIVDVnTWdxaHB6S01VQmQxWHpBRzV4eGxFcUd5OHBYM0RvU29ZeWNqL3NhUVVLcUd0bDZZeTVmbGc0QklobXRSZGx0MFF3RlpwdnRZMk1XdGRDcFZqR3lOOHk0eGxHbHZjYnBpVStBRGNxNkFzakk2U2RiZk1Oa05CZ1djaGRWQm1HakdYc21WS29QbHUvbVhJT05RRlZVR1BRZFBRUXFHYnlaOFJFaHM0WUxOZGx3UjlnRnVyS3VPOW10dXRFdUFoV0JqaXBRd0w0cVlBcXVtTzRXTGxBVGd4VVhBZmd5S2NFMnNrRm0rSlMrb2JHM1dKZ01Jcisrb3dLcnNONzU4eDF6dE9RY1I3QWt0cmlScnVBWUQzQ3hzWHU0anplWkpnSWh6empFZXgzS2huRXNISkJ0djdJNWY1VXRtc0NoWTh3VVVSbFI3eExMeG04THdjeXo0cm55VDJoOVgwOElxNlRXdGlHd3Z6QUMyRVVDNi9aTk5IaS8vblpjL2dINnEyakxWbC9raFZxRVFvd3R4QlJTVEVOblZZL3VMa1VyeDVoRmVtM3BIckRaVW1qS1pscGxvcjVSQUE4aUpNaGplcFJXTERDcmxEczhCSHpIU1ZiUXV4cHFKNjQ3TTZKc2pzdU9ZV1hLb3hTMmlRWTBoNng1SE1aaEdHM1I2bHBnWml5UHJJbDRTdTA2aWpVdXJVejJabG5BbE1BZUNtVDh6RE5vbk5mczlSUGx6YitDZUlYNGFEWUpkd2d6YTFkOXNRckRxcHM0bE5qQVpaNnVQb3FTMktYd3gzQlk0YWg4c3RNZ0VNT05sVVl5TXYydW5oTVhmNGlaK29lZ1oxdVgxTk9HVzZPbzVBV2NseTNFTkVFNkhCMUtYQ1VhcjZYd3lvU3NxVWo5UkFLNFdYZHl5a0Q2K1lUYUhFdkJ1TFlPSXQyNU03eE41d0Fma2YxTXpDMHFrbHpoRVBMT05BSnNNdzFVQ0pRRVE1NlNZTzRlc3pIOGlCVVdueDhWR0pWcldvY1VwUVRLbHdrN0Mya3FnZ0hPRXRiak5XeXhCN09waWd1QjJGM0ZmUUMxR1Vucmttb1psQWRNdkVJTkRNNEQrNVk5QXIwM1VWSTZ2RGM2ZjFEWDBpdzhELzhBU2tUWWxoOUg2REdJeUZnZGZ5WlFhTzNpT1lLc0R3elZMQXU0V1NMdkJxVXVTelBxYWNIbUwyamE4TVg0NlpuS0NwSzBkTUpkZE5UcGpUM0FwQ21EZ21wZVdGTDN4RkdLWU13TUIwS2E3UmlGWW84OXloQUFLSFhtRTRXbW9BS1ZYVmxVeENNRUx0elhpT2sxcStTR1hSRERmeEJRd0tFdkJ4TEdoMENrWHFGY3ltclhVRkRvRzE4UUZaNTNmc3lmTWZ2elhZWVM2SnlWaTNGNGxZSnUrM3VvakhMQzJObFVlWStUWUo2VnpMd0FJMFpUa2grbVc4NWRQeEVYZ0dvNSs0Sm9MZ1hmVGNvMVNKbTgzblVDVzZWMEgvWVE2bXlxS1pUUmFZNUlGaVBtTDh3dTJsSkxZd2NtTFUzM0J2VjBtcWlrdW9aZHVvd01NT0ZIaURZOUpmWUQ5ekFSMzN1K0l4UUdodFN4RGEzUzN4cUVWSVdWTXZjWUt0YUdINGozT2JONG1leG9PZlVxUUlnVUoxRVJscHRRb3ZIVitLaDZqc2xnSENERk1Ga3ZDbDU5OVNsMlc4NE5sY1M4ZEhLTlBiQmlVVEovWWdodXBVMGhBeENqS3lOMnI5b213b3k1L29sV1pZWGc4QUlFWUZBNEcvOEE2ckU1SXJQNE9vQVhTRFovQXhsVUl3ekRZd1lMWHZVd0FhVER4Q3NUQ0dWb0JUeEFoR20zaEtGWHV3d3JNd1NHVi9jb2N6azFQbVVBR3VDR05vRXhxajVsMEFGUVE5VW9oekhVREdFeDh5MlJoWjh3bkFYT1Z3MWFRM1VSUUZpaFVXQTJ6Z2U1eHlJaXg4UG1GYUk1RCt5S3VjeS95RDY2S3JGUFVhVjFYV2tPNVZRQ1UyTXJtcW5rWXI2MUFsMEhJZHgrVExJOWdjcGN5RGxHTDFpNVZRY2tBcG9YSVBGU3VaZ016aGNvQkZhOXA3bTdFQmMwU3JZRW94ZWZNQlFQT1NsTzRTREZBYzJNQ1pDMXFzc2o4eWlPSkV0dFk5TFVEVkhGZjFMQkVnQ2tjQkdxQVdEQXZVZDdiYUJ1V0ZkNnJuR09vZWRaOEVKV1VwU3dqOEZVSnN3SkF0VXU2alNXTW9MNVk5eXNDaUNZV0UrNEhrTmNTZ0syNGlQNjh3UVVwN0ZlNHRPMFdXOW9VQnJLMFV6RUlyTFI4d2x3cHlMbnlZamszbERreTNsYWdQUG1MRFRkbWp4SFNqYVhhM1dKVkVzV0s2T09mY1FsRmFBOCtZT2dCS3E5VWN4V0VyVGd2akVUV2lvWC93QUMvd0NOa0NibDE5QS9SMUVpdGlDaTJjZlc0OVkxTEpVOVJCVGh1bUhoOHA0bHNPdEJEMmJrclVYMDZGRFJ6RVRLQ3lzelB3bURHSDNCSTRDL2p1QmRUVzdjZlMzd0Q1bGFTeDdCL3dBbUVxTUJoREtHMVZqR3BaK0ZSMzVsQkZZTFZreHRGaC9UTFZPRDNCR0JvTm40bGZFcTJpRHFJaUVMQitDV1Q0Z212VUt3SElWMitva3lFVUcvdG1LcHVIQU4wd25XOWkydmFYQ3F6Qy9mM0dOWURXQU4xTExsQTJVcE1NTnd3Y2xOTi9NZHRXQjVBNWUzcmNyNkRlMmE4MTNHMjNjREdWLy9BTE1RSE5oS1RvWlp3UmtNdmNaQlAyd3hWcTRyQUxqbEpUb3BzejdpRmdjUnY0bGpWV3k4MDc4eTBld3dEWGs2Z1NWQUdVOFFSaWR4QlBQVURxQWg1cnVBNHdEWUs5OVNwMTBHUUZjM2N6Y0JmR0xyaU01RmRGVXNSVlFLQzh4TXdDZ3pEVzVSV0F1K0poQ2xuUVBVeG1vWDhRaENJUlNvekFyQUJpMTRqV0tWcTYzNWczSEtSdmpkOWdDOGRXaHVzdXFJci9rY1FodkNvNlpYSUVRbUtzQW5OKzVmNlhmY2VIM0FsbkhmZFlxS3J4VExGTFNHVER4bDlFd0NWeVlQNDM5V0wrQ3pjUzRURXY2REh0QklNSWZTbW5FU2tBN2hxaHBjSkhUS2UxaUtCMWdNRHFFelBSQVoyS1NKRndBMlJLVXZCR1BxVzhsVVI0VlRPOEIxSGcwQW91cWp4YlFBSDl4SjBhb0ExWDNNYkt0UDJPcWxDVERiTTl5RkNza3hzenpIaW0vTEJFVnJiWFE0OFNpOGdmcFZ3dlJCVzE4eTdrNWE4bkVyS3V0Mis2RThvdGlYc2pVSlhGUEhMS0YwaGFCZ3F6M2hYWVM1QlcyT3lNY3JzTmw4UnU2akJ1a2VXTDBHbGl4N0lyczBxbUtlWTNQQ0xncHNqbzR3SGk5UGJLdUF3R012TUFFTlhRWXFLd0cwUE9UbkVTN0pRZjFNWENVeFdYaU1TbmFLYnE0enl6SGE5U3Bkb1h6cTNmVWJSRFdZczIvTU1EQkpWWWRzUEdwaHN0Vm44eDJxRmUybDFIYVdDeUN4Tkd4QVhaY1lzZkNZcDZBd1g1Z21CUUhoOFR2aEFRSTZ1TE5BUXdMSGdpZUFNQndGNmhnb0tnYmg4cXdKbjNDYWtVdG9PNHF5dXVTejlNSkVpN1EvdHhCUi9aUlo2alp4SWI0aU1QMUg3TUlpWFhQbTEwUmh2cllZODNVdEVTM1oyRzZnQ3dGa3lQRndqVnNiTTRZbzVyeVorWWNCbmgvaWtQb2k2WUQ2Znd1eWJsd0d5L3BZYWc0TG5yNkdhZmlBUFk0WUN0WDBkQTJUQ3NyanpOQU1jTEV0MTE0aTZ1K1dwWUFPeEUzWWpvT1BNTks2QnVwWTBIT25NUUN3dnRsZFJtVWx3c2E2T0NPZlZIdVdISXFhMUNiU3dlZFJlaVdXcUR5eXhhOWFiR1p5TkhrUUk4SmMxdlM3SU8zMUJ0ZGhSdkhNRUJtUlhKOW5VcThKZ3JsNFlNNVcxZ3ZwOHdvQ2hySFM3STJMQWN6QTNHRFNpRGRubnFXd0lBc25QMm1IMGhOT1hFUVVHU05mYjRsVUswdS92TUFxMU1oZVVmbUk2cTZPUEFoeUxISUQ0ekJsUkdnNHVzc0YrZXlNcnpVQTY2S0NOZTRnVWZrNVlEZ3RsdDhvMGtEcHNCcURxdnliOWtCR0cwUEFUNzRqa0pqTFVJQzFHbGI4UlF5Ymc1Wm0zeFJocUhrTkJacnk5eTVWVU9LYjVnZ2hoeVc2bUNXNWpxTm5jS096b2dTUnZUa2VaUlF1eXNXOU1kV3VhZ3JHYmlERjFMY3VjWWdzcG91OXg5a2J5ZDRpVm10VUtQRDZqWmdRQXNYMFFIcU9VSXZmY0VhSHV5dUpXM0JEQUR2eXd1b0Zyamo5OXlnaGtjK0NwVlRJQ2h4Y01oYmdPUnpFbEl2WEpMMlFKZ2N2cmN4dG15djUzS0wrbWI4UXg5R1pGVFJuNk5jek5NTUlFK2lQTWF4MmFxSlRZc2pDMzlrWW5EenhNeTdTM000RFEyYWlBM2lGNlljVzgyNmxyd3RuREtYVzFMWGpxSXVnd3ZWVE43bUp1VlBNTkcxUUszT2Q1RXRFRGszQ2dmTXhVU3RRTzFqbmZpVXJ4YUswd0M1S2hNeXFjczUvYUJKM0J3Yzl6d0hZTFQ0bGxVTlRHTVhUQWg5RG13dTdpSjZLaWg4Yyt5SUFLR1ViTjhmOWgvSStVZGd5MEdyT0NMRldYa0FHc1JaZ2hWcUI0SU9HcU1CUGZjdHhSRk5LdXNGNGxFR3haQWVBbHByM1YxYnV1SUMrTWljT3ErOEhiSUJhdmFCSnF5bFZ5UmFETXU3alMxRHVxZ3l1cWRCNWxDOXUxSmdoR21odnllSlJDMmhRRHI1aGszL0IyQ0pwYUx0VjBtWU9DNXZhdzFHWUhqekRJWGNxS20ybWpwRUcxdnZqSE9JTUN0dWhsaTNnQ05DVnV0bFdVSktsVk9XUzQydHdXYkFjaEtNa2NzZHhlOE1heWR2cnVJSUN0cTRKZmdTUVdpTkRYNFFwaldxalJ5dnVJMmVnOGFxSVJ4RVV1K1hrOFFrbVJ0TDZJQlF4RjUvQ1cvUUFYT2ZCTDdXRnRnd0xRMTlaTis1ZEdrakt2dkV5OXZCUXY0L216c2dXQVhHNVVyVmtvc3dBc2pneEVRaXNpQm1MdXh6RUJESHY2NnNRM1p0MUd5VnJpNHF3NURjeUNoYllaWlJMVFRnWThaU3JwNW1FQzREWVJTaEtSL1l3TmRzMnlqSEV6RVJQM01jdG5WNElTVlRJVmdZQ3FGVkhjUVVUMUNnTlJjRThRQUpvdkFsZFU4bkZFY1hCVDBlSlZzWHlKdzlUKzlrRWZ1eHNmekNJQk0xUitJeDBhQ3R1T3JpMUVFVXBaei9oWmxybU9LUzhnaldLMlFvTThuSkNOMUlndXhFcFJNY0Q0bDJLdDVwSFJFTXdEa2Rsd1RWZ2JjVFhBK1ljdGdhVWQvMUV3QU9BRWwzd3l4eEhKTmZBR0ZrMHd1N0l3ZnlCVmQ0ZVlyeFVBZCtTWHVHb2NGb0NVc1hnOS9IajRtMGhLWlVkMmVKZG8xNHVaV0hieG5veEU3Z3JoZHVvdmkyeVZ0ZHh3Y3J0aExGYVN4b3d5c0RnWUlVamVIZmlGQUFhU3I2WTh0TGVDWEt3YVZpdmlVb21XUThkTXJiUWx0TllnQzc2eGY4QWsxVUN0UXAwZUlTS0N4N01jRVpYL1pTOUpjT3g1Mzh3QmNyTTlJNW9neVNuRXNZd1lUSjhSMnhaVjhrMW9CZHl2OGhwRVkwQm5pTGxWV3cwOHpEOGFQWjVRZ0Q0R1h1WWZsRko5djhBNENpNHMzQytFTDJpdUdtSXd0Z2FGdVdMVXRiRVV3aWt4T1l1QkQ0bXU1N20wQjdtMURBQjRkUy9TQnJ6cXovY2RWZ3pucUJPMVVIRU5MZDB1R0VXVTJpd3g0bzJSR0NqWlRVb2hNZ3R3TjhSd3NlSmZVb3VFM0h0QW5rbHBhMndyT0lDTHJ4YmZEQTRaQUYvSkdURUZGV0lZMVVyUTg4Zk1zS2RHYWc4Vzhsa2ZSbXVZdkZRcEdCZ3RNelM4cktjb2dWdzgxT0FMSEw3eENyYWpSZnVJL2VBcHZxNGJHVUxSVE5HM2JabzlScDVBTFk5VjFGTk5SRlMzTitvOUVqVno0bTFGNHRZSjVoVzE3SEh1R2lEUU1udGVDRkEyMUNmZVk0UDhEYkRZQW83RExlMDRJVmJnS25jQ0pqM1VRQnJlKys1aGttVEFIcEkzdFVVeVBiNWxhU0NlMWRObkhjQWlTMk9GWEhtTFZBb0F0ME9vUzI1QUZ5aFhBdmdSeC9BY0NaNGFsNTI5d0FYZFpzL3hLU014b1l2cU1ROVhVVTlYSG8zQWJQU0ZKek83d3ZpQUU5R0M5Vk1QREZVQzA2alJLYzZweSs1ZWloUlZZbk1kMUlhS1k0MUJDdUtybVlKcXM0VFZVdHA0am1KZklYVWZoTkpXRkFtWWl2QkhhdzJsMVdvb2pkWFFYbnpEYnFrdG42aFJMa3Avd0RBem15elpRc1BtdzJpa1k1bExzdVZHMWF1TnhvTlFOUitoRENDKzViaHhNeUVSbU5CbUVNNVlaclhxbkNSN09hekRUdUY5d21jL3dEbFF4bTNHeVZTMEcwampCcldzK29HS3NHaDNhQmt5NU9ucU1LWU1jSVNyaXFiU3RxRGJMRHhnVksrVlYyWWNRU3djSVRDK2JoOHlkbTdIcS9FcTZRUVV1OFplWXFTbGxEY1hHUUxWWDZRU05ncXVqM1BZa2tCQ1VYZkhTWm4xT3RONDNGQUlxdjVvbktUeUtjdm1BZE5GTm1Oa1AxQkRMaTR0UGNyaFUwZ2ZLTUF3Y083TVFPd2syZTRPek5waXJQVU9BUkptLzdGZG5PUnA4ZVlaRzh5K1lUaDZCMTVTTjJHdTIzK01KQ3poU05EYkxmY0tWTFpTdTN5N014aTExWUE4Uy96Z0xsWDRZUnRRdmh4QTVnd2pkcnYrNEk1YTFpM2pYamNQUllvQmJXNGxodTBPcmxNV3NUZmd5MHF3MldxZFJnU3ZheFNvVVZ0clFkUnlsVUdiNmhyakNoZVJHWXlvNGRYQXJRdWc4SWxNVEtsM3YxTEpNMW1jYzJTaGVER0pYVUQ5WkUzZlVMSnJnMnNLZlcwcStlWmZwQ3kvd0NpYWxMVkVNeTJMVWoxWEpBbEEzLzBsK2tGRGlvd2lGTU9ZY2tzMEYweG1DN3llQVFoSkozZi93Q1NMZ3hIYWxvaFpBMGN4VW1EM1UwR3NRRkR6Q3R6OU1lSU40ejRpTldTYjNLanVscTVJQzZFNDJTL0M4OFZDRFdFSG5RVnNqNWxKTkFMOEhtSUZnYmJ6SzRBbWE3aXFTdkF1b0ZNNUF5SFVxQVhVc0ZoSFR1TUN6Y2FNTUU0blVBOU1GZUo4MmpLOXl5N0hBWVgzQTdSOEJLS0FGZGxwd3l4WnZEL0FJalh4bXF4UmdqdFhLemRlT3VaUmk4cXRIVVpKT2VwOGtLQXB6ZUpSUVhiWUV5eG9EQUoyWEtNbUlQSkt5SXBRcVFWSFZLTzBJbldSZlY0S2xUZzdoeEtLRSszek9NNUNncjJ4cVdoekNlY3pHUllIMlhtTnRrT0txNGFyZ2hsRHE0eTR3RDlHYnZNSlhjYUZxdkgzaXRLU3pVcDJzQm9RQUdCOFFFNW5VV3ZMRXBwYkxKUWxSdzRyelVaU3RMSmw1UUFJeXJ2QU9TTGpvRlFCNFh1Y2N5aHFueEFJYmMwTmZIdVlBV0RkSUloanNVUzlCRkZqamNYcFdCcWdsTHBBRVpIdVZBa09JNTRpa0xBdkJhaE9yeHl1bFd4NzhCVEdQaVlsQVJhdWl0eExvMjNrN2hBNWxJMEZRaEtzbEZzcFFXSDlOY1JjZDBJbS9tSU9Hd0ZXOXlwS3JFTkhHb29kc2NxSHJ0aE8xUlFIQW1mSTkvL0FEdU5DYTdRTU0xTDJjemRrMHk0Z0dJMFpTRzRvMFdLTU1pNFB1b0l0WEFwZHptVkwzbVVTNkNtNEVDcUhaRUFjWWlZd3BXWmVkQ2hoWUVFTXRXdUNWbWx4MXd5dW15dXd6RmpVKytYZU5vTTI4ekxLeGJLKzRRbWdCbE9wWmdHRm5LUEJncGMvWWhXZDdOSFVBVUZCb0pxWE5NN2lwT2lNQUNuSjFGdXF1SlllWjRVRkxGQng0aWdRVzBWMHhIUXU3RVVaNUU0UFVTMHJ3cUFjeW9OcXN4QkVDcVVBVmZtWHBVVnZ0ZFk2aGdGbWxHUy9VWXE0TDArUE1GN0lxdUd1QW5OQ29Bdm5xTHE3bXpackVHaktXMXZsTnhKZTZPVTIyR1p3dGw2VktrYWpscjVsYmFKbFpCQUU0TnBmdmlWU0lRR2kzQ1NnTytjRWMvaUp5aFFPVDBqWVFMSXF2TlN1STNTSEQ1bG5WUGtHQVU0WGs4ZFNxSUpxaFYxeDUrWW9BSWc0SS9NQUFkVnhVQm5EZURzOXkwaytNdU04eHRKblFwRmRRZkZLKzJQSFJBNGdGRHBFWnVFdnFVb2hHVlo2SnZKRFJSV2FpbGdIREVRaW1Bdk56SVhZYTc2SW1hRmFpWDVibEc5U1pBN21aZ0ZGSytJQ2hwR3k0dUw2T3EvK2JtVUZqN1J0Q0pZZUpWMG1BV3dERGRzSUFMeEx5cTVJczdBU0RxU3FhN2pXNFJ6V3B2V2paR1hKM0ljbEFkVktnbG5qbVhaRGRFckhpR3NDMm93UXFDbVdQR0paQTZtcTRVVUttYWNMYWk0Wkdoc0FnRkZCR3RvYnRRN01QYkttc20xeSs2QUFaREVDaXJRWUpldlJtSUFPM1gwY0VHd0hETXI1b0wxNWpBbERrNmxwQk9WOFJiR0REY3E3bVp6bUc3WlNpaTZ6Y3JtbTBzTHpCc0loRkttM3pHSlhWUTBlRjdnd3lJSFBwNmlqaVN4Mk1kYUFETUQ2aFFGVVdUMlN4Q0tDTXE1ZTVqb0FFZUh0N2ppQnNWcFNOU1hidGVhaWJqeS9yQ1BXTGIyTHA2aXV6VWJDenNlWnhVRERYM05FVlM3UzZMV005UVdobGhzSC9rQ2dJSmVyR3E2U1dMRGN0UnczQXNvQmVodC9vZzRDYS9DR1dtd1dGOERBUkxMQUhFckcwaGVIaVhtMEhsRmJkR25hTUZiRHQ1Zzk5QU5jY2Z2RzVwMGF0OVFJazNMOXdIbTFRZUpaWGJyYSsrWUYzclp2b2pVTTVtQlBNelpoWmc0bEhCUklEdS8zRGJBc1k5SWRUWmIzdDRnZ3FZczRlVVE0R3kzMU0yZ0MvRm9UVVhMZlA4QTlHSTFYRUpSekhPSnlDeVVYMW0vRVFxQ0NhbEx0T295b1dadWIzT0RLanNWTEU5RUF3RUpnb09pVmd5R3Bia3M2UTBSd1A4QTJJUkZMb2liSU10NWxtUjB0S1lBRlc3eFhuSytZR2c1OHcrNFdLWXBJdFlMcFRyeG1JcnJWYTdsQVUwUWxDdEpoQ2pTTUpod3FpTUJiaHArcmxKck9abjBJNU5DUXNhTkx1L2xoUXpGUllGQUVzc3RDTFZVclRGK0M4Tk5kUUs4SGVOUGJFb1RBT1ZEb2xzcG9WZkNTb1ZVckhFSkdXTklFWUtrYXdRZTRGV0ZzUnVPeFVCbno5b0w1d1ViNFRpQ2VGaDA1Y3NvRXBCc0pyNGlGVVlPVmErWTFzTXZ2bTRPYmRJTW9MYlVrTDlpSEFwVlZnMXJFYzhQSUFNUW9pN1NvSUhVYUc0THhaMUR0RlJya1BNYnJySGdsYTl4Z2Fsa00rcFpVS0NLVjVxREZRS1hiNGlZcmd0Y3ZjSThweVNYejVpRk1Dd05oOWN3VUpMY280MTdxR25Ncml5emR5c3dTMUxHS0FsVnZEcDRES3owRjZpTlNjbmZYbVBRQXZMdVdVU1ZRL0tVeTB5dHJkWmlDakxTOGQzRUNVQThDaTJuV0tsMXhMRnI1YUtodDFKWmNFVFExLzhBUVlsN2dCYWdPeU1qVmVaUnR3NFpTTUhjeU5XY1kxTGtCZDdqYXkzSVd3VEY2Tm43UmtBSElITXdUZDFWMHdLb05mVEV1VVV5dXFnTjRVOXVtZStGc0trWGFzWmFpeWdOa2VJc3NUZlh4TXcwZVROT29xaFlLSmVsd0NEOUZHQ0o4R29QRjhzYnZhNUxQVTJSamhZWVBUczMrc0JLbGhDbzNCSXV0UlVtV0JzdTBtNmxyQndXb1BiR2hVRVFNVTk1YmJUeExnSFJWc2YrUlJQVnlVSHFQWXNGS2hYVERSM1pyVitrdEVzV2djWWwya1VqQWp2L0FDTGxKUzVFcmNxOEcxbCtZd2tIbk1hclRkc3Urb2x0Y0s5T2NxWHpNRHVLRzBLQVZJZytsa25oMlFhalFpa1g1c2pqTlpEQmpPbzFVNnBCNWp2VGxLV3g1akZGUUozMkloVnJBVmViOHdtaHZQcDJRVDNSMFJ5MDFBVHBwTUZ5MWVRYjFFNVdaQmh2T2Vaa0thdTFRNENWSlZtazVJSTNNVWxMR2lWbTVKU3hYT0laUUE0RGNQc2dVREFvZzlPVFVyRmtVSW1QWmMxcjh5a0RCSEo3UWljS3U1M0ZsNTRiUS91eklLUENFQjJUVEpxL01jU2d6ZXZENGwvelVneXNBUjlqQ3R3WFROTFFYMUFzS2NLUjdoeUJ5Ry9pSFdtOG4vMFAwMitsMTJqVUZlRTdpNGdCaGxJd1RORzVmQkM4L3dDcGdlbzhTeUtSYVBFQkFzRlRkREpUdW9xcXd1R3czZ1Bjb1JkYWpwdUxLaG9SSHVZQ0E0Y2tPT1kzVDNGbFhxMjBkeFpDVjFpazBteFhjUFVmdGtYNlRRZ05YLzhBWWlrWWhHQjNNQkc3WHpFQ3Vic01abVdZQm1qZmNvcWdwNzVybUNMV3BVOEhtS1VvS3FhUTVGVjUxanF1NGxWVjBXd1JBQTBpaWZCNWxHU3VDdXZjSnZtc3FweVZHYXBHWWxDN0kwb2NoUUZZMU5nUndRN3VJR25LV0F2NFkrNFgxd2FCNmVZN2RlRTVPS2dhZ0NEdDV4eDZpaFFXVE9JekVWUkNpeFdScUErejFEaFROLzNRMlhEYXRyOW9BWTI5NyswQ3J0ZXgvd0FsdE5LOENnSTZDb0MySGFhbUZtbG92SmNZUW1qN1c0eUdnS0VjMGR5dHhWVlFORDVZS0Yza2x5QUFTNUw4UVFRMEJicnBKVlNMK1NBRXFoWHVKUnJFSGNDOGFHV05KaDNpUmxzWVJhdmFDMjQ3NmNRVERDOURUZHdjUTQ3dXkvdkx5aWpMSWpLa0xTWEdqRkJhcUQ0aUt3V203Qno0amhWbVJTZk1WNEJEQWp1QzgwWkJIMUtzMVhWajRNby9JaDI5c3RFN25wS3BVWUFVNzh3enkzTkdQNFgvQURQcDFjd3pNeXM0UlJoN2hOSUs0ekFHcURIeFFQVzVZMTF3OExCVllqS1F0VzRpK2Vwb1FGUkhpRFl2RUVDc3ptVVFQRUhNcUxVSXlrRWVoejJoSTBCbDhNVWhIbHo0aFpRU1U3K0p4SVU2L3dEWEJ1SzBDOHdXaUtwUXZ4RWpMbE9aNUQvSldvcWxrYm9MaTlQaUYwbVc2WDZncndsQzZXUGpmMVV5ckR4U0ZlRHRuYndLcThQbU41a2kvTHFCVnQxRXJMMDh4L1lXUUgyaWRJYzFEMy8ySTE1UXNwNXZFb2FaYmg3WEdtZDEzdnhCV25sZ2RKTlM0czN1dDB3anFDa0tYS083Y0ZqUHFZY1lidXBFbjBLSVZQVWRtbDAyYmVmdEhjcHBGNXQ1aXZBZ1hFK1lOWU1UcGY4QTRsWVlsaVp3Y1FBdnNENFd4ZkZaV2g4MDJzTjZkRFlkM0tlUVpCby9VTGNVYXNxQ2tCZUJ6VzJuVXJGaEZCZzlrdEIxZ1pzNmw5dEE3cm1TTkcwYWJpYUVOTDlFUXE0M1Y3TDRqYnNFRVlibEh4QTE3ejlpRnNvb2hSREY3RTh2SGlPSzdSc1l2bUZKVkpXTHltNVZPclJZN1hFbVZsTjJsazJXMGFmeURCU0xtelZlWDlRdndOZzRlQ1hZZGdLRWZUWHJVSHVXSHF6STE0SXJyQXBscTlSRE5yVmZoVUlDU1dOcjVpZ3liVFg4SEtBYmdhZnhXdnB3K2c0bGpoY2MxTjZxZHk3VG5YbVVuRFVCYy9ENG1VWkNrak1CdTVkUXJsS2lFckJ2c1JobFdoUnIxS2xpUk10NWxDQ29oMDVJRmhtOXh0NkdOUzUrVGRMUStJanlVdkczMURVRkxSc285a0tHQSs1WG5zREJtVVUyeTIxU2tFU2dHOHZ1SzZhVnZaZE1zSkF2SGg2ZVlWeHFhUG5xNFYyUTVlbUtZeXo4am1QS1JZMURxWDB3V0tEd2lyd0Y0eVpVbHhkcE9sTERzVWJobUMzTmIrOExrV09venFpNWQzdktlSzhTZzRJcFZQZ2dsT3RnM2ZXSlZnNURKNFNaV3JXTUhpc2t1OXZjYXduSStJTEFqZDhNOGt4eGIyazhIanhLMVJzVGY3NmoyU1VKdnBIVXR3QVFycnhVS3NOQUM5OURLNko2SmVlWVZKS3BsWTRKaThON1I4Vnd4MktBRXRyVVUrNmhISnhjVEFnQUdlMXdzTGhWcnpoMFlpSnR2Nm1jOFd0MmVPcjlTcGJMdTdsMEFkR3dGaUpaWlVGRzMwdEJIMXE4NFZVTXBvMEZTdnhCK2dnZkkzSEhDVFBBbXlNY0Nycm1YK0xVSEJYTXVHTmE1TFprbUVOVGRRdFFKem5hbWlhVXl4UzgrWXZ4MWgwTUxMYW1PeGllMHpzU3VvelZnNlZLVmx5TmovcUxpQU5pMWVwamNUU3FvUXpsaGRueU1IUG1JS0xuK0lZdUlPSU4vUlVMRUdaZXNSNHpOejZJY3pBWkdzM0ZMVXZtRE1EazhSelJQRVlMTHV4YWdZSU9ZcGFzc2NHRm9RV2h4QkFwSzVRRnZwQnc1cnZ6TmlIRGtKRHhaR1E1bHVDdUxZa2FnSXp3aUROM2cxY3gzUEovVUdyeTVFQ0dMQW1Bd29SWUs3RzRxMFhsRFZlNVlGcFJ4N2dMWVV4VjVZRXVRM1FJUG1Ca1dCZFBtRFpkSml5cnFtUEw2b050NGlMV3BWNS91Y0svNkVKYTJucXo5WWlOV3dLWUhOL2FYbWlXb3B4dDg3amRBRlNsMkxlUjc3Z0NDYVdBTGZETHFkUTFROEtoZzBvTlRqdThTNWtLRksrRmtXR3ZoWU5OUlNCR3lrSGkwbCtmZHcxMUdvOG1haGtzRUlzYjVpbVMyQnV4QTFvR0ZDV3ZOV21pODJRcGNEbkl6ejNOUEpsc0k5U2pqSWlycnNpSHdOQXllWXhTcUM4MXFOa0xmT1BIK1JBU0Rjc1hzZmliMTNyVkZmM0ZyR29NMzNpQm9sd0sxRnR4NFBKNWlZUVFxdkhpQm9GZ1hrOUVxL0F1bmR5cVJYdEJsUFlwVjRzOWU0SnVPNnZNVU1URDFOeDdHMlhkWHdQVUVBUU5GZzB4UnlET0hNRGxQbGNFSnBtRFZwOXVab2VDamNZcWQ2d3BOWEtXUjBITGlMVzRzZk1Sa2h5dHlzOEZJQXJlSWhtd1NyM1BNS2NzQXBtWWptZkhoWDhHSU81VWFKZGMxOUNxRERHMVhtSDV1b1lJNWdtNUEzdU9vSTJMdGh1dlVwOVJzZ0M5OGtvc2c1dmR4Nk54c3ZFQkViYnN3NE1yZ3d4VWhHRWN3N3lKcGlsWThkeU9DOHVMaHRVakRaVVlMWFFFT3JrNDRpR0RFR2dxbUdjZHFhWDd4Y3BOa2NIK1MyTThySGNvQ1ZSZGJKVVFTdFVLOWx5d3RBcHhCMVR0bTM4aVlDN0xSZy9hYkt5cVlhZ0Fpd3djd2FhUnljc2JyalZvdUI2aEFzMWxISHFWTzJmRFF5RDZJaWNzK0d1RU5kZk1yRkxOS3RlZWYzTG1aclB3dy9GWmhZN2JmaDFoNmx4TEphdDhMNWw4S1ZEWXJsei9BSExhdkZjaDB6SjhyaXduTGZER0FtT3c4a2YrQlZBQU1WRytZMXFQMjVob3EwRzY5UUlKcTVCNEs0anljR090YzFFVkRNNExGdHJwQzFIRVJBSnkvd0N3MUJzY2wzQW9EY0cwbWNpM1ZNcjVtTld0bHFQK1JDRTZwZHQ4VktUUzdGQjl4eUJiVGpXczdpUE1MaTlGZHdBS0MxOVJzT3Z4a1N6RFp3K3g1WWQ0aHdtN3VLVm5aTDRsbDRJS0p4MTk1ZFRreDFkN1gzSFp3UTdEWXI1Z3JTeURMZDFEVjVPaXIzRnFjUjNSbXBzQzhLVG5KQjVscDNwRFI0aEN5MDF3SEl4OUdrV3ErSVRzUUFQS2VaZnBGdFc4TExDTDdwRnllNVZVckdYK2lPajc1TlBIM0tEYXBabmY4VEgwVUxvcGl2U29JY28xWUZpbTVKWCtnaDlLWEhUQ0l1dUlDWHkrMEhtS0YzZ2hNZ1VwWXhCV3RNcFJRMFA2bVJjQ3FZb1E3bHQrb1NxRFMzNW1nTWlsSWVJRTRuRnd5SlpubEx3U0NNL1RMQVkyRVlpTTZIOXlyOElWV0dLUmtwR3I4UjAwQnUzOG9VcUdyR0w2Z0pwMFFOdlFVcXZjNFdXSy9zaUJTdkovWGppTmRIbEJyb2xjZEkwd3ZCOTQ0bFY4eGwvOXhBK016UG1uOXNURXJld0N0L2VCYWlpN1o0VDNCd2dVM2hTaEVSS3VDOTh4Q0JFWFJGaUxRYVJscjBERFh0NS91Y0ExR2dkU3pNQ251bXJJSG05dGg0Z0RFUUxRcDFjTGhNUVNGMlMzWXB0VzJNOHhGTUk1VmZMQXhOQzNWUWRDVlhZT0dLcHdVb2oyblVDVjZhOVU1RG1HQWh6WVhROXhlS01hZXlac2d4SU5XYWhhNnNtM2hxV3BZUW5QekRoRjZ3UnJSMjN4RzIvUU5DNWZNbzI1WTJ1bUMweWJrL3FOZWxSMnBSSEdiUUVjVS83QktvYXlVdHc1T2lZLzFCUkxBSCtuTEs2Q3pIc09RN2czZDBzZzVJUUpnbXZ0Tld5K3FHaTlOMUhTTjlDaS9QaUhKbmFhcnRjc2liQzBiYWxaNktBdHUvTTJjRXE5RXByVDNlT0lOR20vZ3V2ajNHWjVxWlpPTDdoN1lMVFlIbE1HNUtZZnRBc0kzZHYyWlozL0FBeEZiaURiOUVyQnFqS0x1bzJKS0djUko0UXZoSEY1UkJIQ1N4T0lZUXo0Z0VRV1BESEFnOVJCZE5PcWlFeUdhNGd5MXRaVERFV1lXTEtlSWpJQ3VlNFFzbFlKdFl3Z0hJYTRUTHNObE0xOHpBS2l3Zk1KOGtGdzRIczNMVElrYytqYnFJSG1GNmZubUpybFZEelp3elVPRXMxNmU0ZGFLQldlN2o5S1FZV3pNRFhxMkdmVVEyelUxb2NRZ283VlRlRFJLQldGdGFRNmlnejlnMEZYL2NSeEJzNlZkL2dtWUFFdkluTHhkekRRVWNleisveEdGNmpUclRpS3VOcTJNYnJSeDFGbUxDTW9YVWQ2d1hBYTZJcUs5NmlJTkROc1hHRkIyQ2xiczhTaWtzbm40ZzNnRUhhMnZkVHF3cnBFOFRJMUt2WnEyVkxkbTk5eHRsTW4xZGxjZm1DdTQyQVBoOVJXb0tEQTZPNHJxZHhFT1BtTmNVcWxPaFRobDZTVk9kdTc5Uk9ySFZnTUdyYW5qazQ4ZHlvRThKd0x5ZVk2TXltYTR4OW9Mb29UNWZFRVFMaXFzZjhBWmJVQUxTdkVabldXak9HMitZSGhsclJzczVsVzlXdUZIRW9tZ3RZQWNXZXZFTmVEUnBMeXNXK0s3Z2QwK1l5dTRCeEtZaUNjQWxZaThjSzREM0xGYlQ0cG9ZRmdMTkU0cHo0RWRkdUlkVno3bElLeTdmOEFTV25rV0gzcDFGQ3VFbG9QRW9Ld3dGRGxmMUxIU24vZ1EzVlUydFJKSVdzUXlNdVlQVnNMTlVad0pJUFlnd0lMZ3g2MWptQVNtRmFrR3k3Z0psM0Q3MDlrYVdDRVhzTEFwWkRWUldGaTBzclNMamZOeTZad2U3QkI3VWJlT3BTdCtUeUh4eEMwVzY3ZHdtV21aMGR3N01oYzlqN2g1NEpIWmNZVUJweFdlc3gxakNoNGxpR2paV0xqc3JhMHVHSWM1TlJvMXVOUWJxS1dtV2VqdE1kVE50QnBndE9XcXdwOFNwQlZEUnhtWmVRNmNGeDlwaUpadzhHZmlOYWloUStkSHgrNWM2a2gwS3ptdmxmdEZhR0NiYTI3VDhTaU5DdjNHelZrYUh4UE41aTM3anFKdUdXVzBSc2pWUVhHZ3E2ZUlRSlV3dENTejR0emJHS1lnRzE2SW5MTVcwYzc5ZU9vRlMwR3hxWDlNdGRLdmMwRVdrWlR5eXgrZFpaY1psSDJpN1g1UVFGdEtPWHE0S0s2eDJ2ak9LWUtVNUFGZSs0WFlMTmc3ejFIZUF5YjdHZHZpYkE0di9ZU3hxMVMycWI0bE9Jd2EvWjRsc01MTTRlNEtGS3MyaUpRaUs1Y1FWZzNCa3FzQkFpYXJ2cDVZVTFLT0ppOGVHRjVsZDBxOXpBbWdjT05qaUFEa1VsbFVFSmdiYVBSQWZjbmt3NGduK1VLSzhubUV3TXBiQjVad2N5bGg0NElrVU5nV3kreTJGbzVqRmhCQUhkOFFKQTdIWkVaYlREeDh6ZFNvcUxYN2dFTDFYTEZ0MkpidUc0UmZGSzJOanFCUlZIY29XUncxTEJGR1BJRHVGb2hmbUtCQkNXR00vVENtSEVOQ200TFl3bG10Wnp4TGloYjFDYjNDckdscWVnbUJ1R2lMYXJtSzhsZ1VocWFHc1VWOTRab2lwVmxZYlA1QWlJNGJzS3NsK3hhai9jTFJYbGpCMk1MdFh6QkJ6OVRaRHFBUEhOdnNRZVZHMW1yNXFLNllGM2ZNQlE0L1FYQmhwczN4N2pEcEdESFBjVVpWVUwxQUpObDdCY08wdHNQdVRtRUdlbEhvbC9CMk9Nbk4vOEF1NDJzOXdwRkdQZ3FYZ2M3VjFsLzkrSXhrblkzbWNrRTlIMGkvb2dFQ0RKY1lHRHFkNGVVdEFZbml4c1lmY3FEUlhFTnVrR2pHbUFJUmpnVHBtOUdBWnRvM3BlSW1zRGt6Ymk0amFTbmVIVUxTcnJZYTB3QnFLRnZCekFzNGJBdUVLVU1DbXgzWEV1V0dncmJXYzZnV2tGaXZ5LzVDTmFvd2pQYzFLUStLT1liTU0yWVZUSnZJWURoWFpMNTRCalZmanVLRVJRMlJsTUZXQXcwMWN1dFMwT3V2aVBBREJnZXE1aXNybFNsQm8vY29FMXF5dFRLb3JKWWUzRlJIR3did2F2NWdLc1hlZk1wQnNscWxqNEIyM3NBZHgyQ284bDY3aHU2QXpLYTFYN2xVQVRnUTdZYmpuREdIWU5xNEVpVlJaZzdRK05GanNtVWRhYUpYd3haY0hVekFOTjVmNDBYZjhFRXFWdWdpWmk0cTl1WTFpMUFjc1pBM0hVdXdYZ2RqTVFDbTBJT1ZVT2hoY1U4eS9OUjFCTjQ4ZU9XRndKU1VWN2l4UnlPYmcrdzFWSTB4WTg1eUNNTGVWTVlKWmlWQ05FRXlITkVVQXltNHQvdUJjb3R6blpVNzlVY3BUcVVnZEtMaWp6SG1CVHhVUzZLR1RubVZmRHdadVVSb1FjdCtwd1pjQXhMaUt5SGp0ajN5YllsclpuZTVVdkI4cTIxemN2cXJaRnE4NUlsRnBkZndSQ0NvcWpHdGU0b3lMaWIxQlJOb0lRUW1FU1libFZOTzdCZTVUcVV3RURXaUlMUFZ3NG5nRVJLME9HM2N0U3VMVGJGS1JMdDJGNUE3Z3MwSlM2OEc0bDgwVzRKeVBFbzNuQmdJeGFiUGNjR0ZrQVAvdW9YY0FZMVhpK0lvVG8xaUhPUWlZcW95bkNXTmRlMUJ5ODFGYnRoWllwTkRVS0dVUXFCdGZRR3hWcHFNcU9haXZUL0FPNmxPdEN0bzl4amQ3dGFTMjhiVnhoR0NDVmxyOHdZZDlRS0Z4Y0pEVUZySG1aaGdkeEdId0RBTG8yK1lIdUhkczJtZmlBTVN3VlVtTS9hRnFSaWxDSGZFMEdDelZYajVuWTBHOXlWUUxTRk1lbW9NK3lmYkRvbktlVS9xRmNqVGoyZUp4QWRYbk1RVEJiSElUQ0JlRU9vaGFxd3hKa1ZNdXJ4L05hRml2S1hoaG1Db2hhQXd6RVM2eDNpWFoxczV6TXdpNXZraE5YbTVSbGF2QjNNVEJBWFNIQ3hXb2ZydzRicW1NRVBvTC9Nck5MbHRsalFITEhVeEtNREcyRndUbWNpVmw0WUxUUEdPRURzemhSUjdyZWdMMTdsRnQvSisyTmVRNXpiTy9jVmlGWENPdGd5bXUzbVVGVmhGRTZJRURVMXc4NDFVYWJGUzl2YVUxQU5oNzh3d1lJVlYwOTNLb0YySHdlNThEQWFjMjJFSVZ6YUhlWW9CQ1ZPREkvRkRCQ1pLUE5Ed1JHcUZ0MGFnemNyRUhNRkVKekNjeXlOTEcyWWkrM1JoMGFJL29LTk9XeDFWc3YyVlZCWHpKWGlXTWtUdS9jUUJidEtVMVIzR1gxYkVadnpLSEFZVkJ6MEZSRXFLRUhCb2xjWUtaVmJxMEdIczNpcmg0UzdSUHVEbTRBdExtbGh1TEtoY29QNURDS01ETXE2NmxraW9XejlwVFVGaXdtcm1LRmpJcXRWNGdDSkJLajNqOXlpMjZWeS9jVjJ0ZVhaQ1Z6ZlVRS3F0UlRxTUNnb1hRQ3Q5c1UxWVd4YncxRHVuS3BkTVR0V0FGQ3EybkxHcE1tRHUwWmNNUzUwQnRmNWlPRE1scjVXRnJuU3l0OEVTdElXd1YzdlVPOTNrSEk5UlBzR0E0aE1oVUxxb3d2Z28wbDIwRVE5SVROSExHQjRZQ1BFQTVNelJVQzRjRXowM3Y4QWdLTjl3dHJMNmxrWXVHZWV3MU1sa0ZpY1FFTlFPYVpsZ3QzS1lCTndUb1hidUdnMUl0aTJRQXV6QkM4d1Y5b1lvVW5Ldk1yVWk2dHVwanF5NWJnSnFPcDRjMFJsQUNtS0hLR1lTWGJzRi9VQkF0VEI1bldWRWJpSGxwNFNrRnNUajFDaG9XNGpVNk9DNmRTa0FhZjVCZ0xpNkMzdjl5bk54U1drOWNSYW1jWGRla01hbEMwbHBpOXF6Z1lpS1ZhWGoyUkdCaVdVSkZUVXRLelZGbnhtQ04yQWFpV2FHeXpraFJ0aE5UbnJ1TGR2aGlZSmpxWkRoRVZSQ2tnVVM0TVQ0d2xRcTZoWDNqN1RCYjFCb1VhQVI3Qks3eHYweTBTM0ZNUHVHK1pSQll1Mk1oWUl5RjgzeEhOVkdyRGVtTUUzOFdlb0kvbFZlZjBSZGVjWmhZQ2NzUmdxQ09CcVgxUkVTS3AyUW1PUUJFYWl0SzBXN2ZETmdyVWFka3EyTzZCL1NVVUI1S1VIaURWUU1hYjVxUENCM091STZwYUYwZ3V1UGVJYnVYTXBzdnpBUVFsbVd4bXV4WmdPU29adThBNExYbWV4Y09GL1pFcHdjVjRnQ2R4c3gwd01lQkdaV08wbFdtamltYlVhakx6bGdGbGkyMk5mQVBCVDd5bEM0cWxQVEdqeEJRWEgxQ2FaSHpPWTM3UExNTnNXQnhVelYwNE92NEc3dEJIQlRyaVVBSjRoaEQ1UzNrSFpIV2thdW9rKzB6YnFHc1pXakVSVkE3RkI0aGdIUlVjSGdvdkxMWUtYeHFFS1dZeEMyTE5KbUtpMW5NTUd4V1BjTHZoaGU0ckM4cmJobXBRMFJ5cE1lUkRBb093ZGVvV0FDbXpjSnJsbzBGbGxxT29vVlFEN2xkODZTeFlvOHFsL0Z2T3F0eXhWbENGQnVvbTBDT216S1dMelFMVVhqcUhGQUZJc1h6TWpnT3Z3ekFTUnM0dHhmWk1jcktOL01jV2lJT01SSC9Ja05LS2NNbUlDR3lrT2xxLzZKWUxKUTArMkFTanpxVkNDdzZtc01FdGpEWmx4RGlsalF4TUVWZ3VuL3dBUmFLQlZMTGRYRHQzdnl2VU9TeERuSWRuNW01em5vT3NmZVlMUm92OEFreHVEQUgrSWhzNmkwM210eWhYZzBKcVB4UmNXcGc5TVZYUGhDelk3MVJzNElQb2dzYnBJSkVtczNYaEcwbEdoc3BDNW1vTW50QjN2WkVFQTd6K0hpRHlxWFRtK2ZjdXhRU3R2dy9jcEZScXJGeXRwVlEyWHFVdUk2M2ZNR01xWWQvQkJXVEpzK3ozRVZZTGV6SFdvTk5WZ2pMQUZiT0RMOFVUSFFybE5pYnpCd3dsQTE4ell6allmUk0xalJZOFVFaVVLY2oyVEJrSnRBOFZLOHVkQ3Q5UUJvcmE3RDd5NEU2YU52Y1dEV3FvTHJhYXlPdzhTb1daeFMrcFQ5ZWIybHgrakNhQ2RKdUhiQWNWQ2s2SGRRc21mTEV2cUZhUnVXSElEZUlrS0g1djNGVTVPNDJiVHFZVUZPWUNHODQ2bExxSER4SHBRNHdYVUUyU2NzYmlCTm1hUVlNT2cxVVpnUWRoRmVvN3NJTjFuam1aUmx5WktLWm5nVXBpL01UY2hhbUsvNUtBUnZobFJ4emRrcXlGODVyMUZYSFA0WW5HYlVZLzFERWFDMFFnR3FzeThlb2JIaTlLKytVRXF3TGQzeEM3MXFrM09wUXZLUllPMGVZU2VDZzJoZVY1YzhSeGhEa0dKOENWOW8rMUVDcXJxV2tjL1FMS2MwbDlhckV3aUlRTXBVb1djbk16VGhQYVdtajd3WFduSExlWTdOOWdaUFJBR2F4bytXK0lGMnlIRHczNWxLTlM1RHFQWGxpZys4VEtPS1phS0Rxb0ZJTGdjYS83MUt4akpmQXVjZUk4anZISGNzU1JvNEZyMzVqUFdvaDArWmNCR3hWQWRzZHF4aXFYK3Jpb08zWlFFR2llRmdQNkdHNXF4bWxwOGVvbGN0Z3ZuTW9QTGc0Q3ZoY3FXNmVVWHAvRXE0MU0vUTE0bDFhQWRUU3VvekRXM3NuVGlwbUNkaTZmOGp5aXptTnFTN3JGb0pIZmVNZUlZTjJuRlBEMEhjVVcwaExmcFdGY2xsakFqOVk1dzc4UTlUbHVoaGMzamRoWG1DUkpkN2ZKaG56R0hKbElBWG5ENDRsSWhQSVBBbGZNQVVLZTBLRm1NNG9TMmtYb3ovR3dObUsxRUdBeURjSXEzM2NFdHlLdVhodXZFWllZTERtNEVqU3p4TWRiTHpjZE1LV1ZMVXFKb3piQnZNNXFnZ0VBR0VaZ01oTkp3bGJaYW5CcURKN0w5eGFpbCt6SDE3cHBZVFM4cWh4Y1VxYjUxS3RLTHJHWWNjRzI2aVlGdFhGUGx3RWVudVpCNXBXN2daK29QaEIzY2dpQVB0TEExRnNyTEN3SXpkbHVWNUZDeGRPL3pCY3FtT0FlNFV4T2VzUFJzcXhqeExydlNZY0I2aHB6Mk0vTndzYUFCcFJ4THBacWduQStFaEtFV25tOGpjYnNBbGtxd2FtMkkvU2hnRTNQYVpHV2pWNDFMRTVhOEd0YmZpTUtSdFRCZS9tTXJuaHFEaU0rRzNjNnJ6SFhXdVVQQVFvb05DRzc2SGlGWWxzSlR1V3dpZWFpcWFLRHlGNlBNcW5UZkdmRWRaQllBT29selF2NXh1TkM4UnhtTUlFT1V0TGZJM2wyWStaaGRxRjNYdnFZOXNFcVBsekw2cXJCVm1rdkpGM1piQXpiSzBhT3ZIa2R3SGtxMGc0czQ3SmlrQWF0L3dqSnBDME5uWml3Q1d0T1hUSEhRUkpRZVZlSXJyYVJjZzl2Y1JJdHRUZCtFRTVrYnJYaTlWQUZHeWc1clpjZEtoTElXbU1RNzJ4cXJ1WTJpUlJiM0xqVU9GVkRxNVQ4eHlyK1loc0MwM3pNOGFZRWw4Q0tBVUNNYlhsTVBKaSttaUxLOXdqS0xtTVVzVDNJS0hCaStjcGlvWlhsNGdZMHo1bDJxeUV5eU9JV1V0MlN3SGRHR0JmZzJXVlRFd09qM1l3TUFRNGlDenRkOVFDZzRsQU51azRqTGxITUtBRGdFYUd1WWNGclIwaGkyYmRDQWltV0tjV1FxbEdxbmlFV2k4TXA0Qmk0dXAxb0c0dDJEWVBCSzZDb2dFVEltbEVwN29hY1hIRFQ2Qy9tTWkwVmJNTU9vTktGVStZaERnc0dFaEtLQk1oNGVTV1MxMm1nK1lqR0F3MEZNZTVsMlMraWJDQXNIbU1VVk5yVFNWNHpHWFp2UnEyOFhCTDlaeDNFWkREQnQydXVyL3VNa0YxdThZWlFNb3BYTDRtK0RpSzM5TERCZTRSVnRGbWZtTGEyMHg3andnVWNXakI4WWkrcG1SUS9WeXFLMjRSMVRjWThDc0dudHVMOXFDNjZPcFpUVlZ5SEJFRHpVMmZVTExXUS9obUdxZVdpdDZnYVZYZ1Z4R21XYWVZNkdCVTVOeDZyeTVRMUJlTkFtcys1N3lGRmdzSG1XdkFmMUJ5Qm9DeThmRXBJZ0JwSFRuaVZJNy9EQWwyTEpUaDhvL0cwZFJCTllnSWhyR0I1SGNDclhoRCtIVW9FTzVXQWQzMlJLVVhqVTJSK0hGZFdlWWtiTFlWUVBNV3I3NlJ5c0xrUkY5cXZiSEZ0VnEwYkNBMG9VTFQ0aUYzT0F5KytwWnNTK3lvZ2xUU3RUVDBFNjJzTUhFa3VxQVBNVXkxaXBydERSaFlQeVNpRVY2ZEhxS3lETWVBSGhqNW9NQndvb1hzMUNzZGZDSURid1hxV0tVY3BMbWMvZUU3eGEzeWtzQ1JyTnhpRkhRUndqYTZsKzJza3VQV3Izd3dGalpibERTaDZqMFpCZHVDb2xxZVY1UXRPak44emc5TUtwaFZod3hvZ21xZHdFalpRZE1EYk5ySGNWWTdGdHpIbGJxTng4M0lMcVd3VjVRM2N1VVJwZlBxb0dQVVNpOGFhaVlIbzhQM2l5UXZCbGJGYUVVRmhmTU5SQWJBakQwT2loYUR3RXUrTU5zNHFvK3FSVkdiTzJKdEtMaHZkRXN3SndYUlh1RTdJTERlT2hsOTJBTGJEdUZ1TlhkZW9pTEVHU0RvT1lyTHJBQWFUbUgrbWFqaHBJNEFPMVdncit3RDh5OUpNcm9zL1lLK1dBRFJ0bnBMMWROYWxOMVRjUVhDeGkrRGc3UEVwNDhud1JwZm9wY0kzd0ZLSDJtTi9NNGE1cmxoWGdIV3h4WFVLQ0ZLNUVZQlowSGZtWDJNb0x3ZERDTHdTRVNwVm9lVERUQUJoWmZYVVpnQzcwc1U0QkN5RkdKVzRXTVFLVTFvRU1mZUlKWnBmQ1FFMVhlYS9IWkNtZHR2UjdqU21vblh2L0FDRVZoWnpVM0V6WEE4UGg2WXRtM0RoUEpBSmxpdHpKc2hJU0xKc0hWUUZ5bFljY2hDQmtBWDNiSFVVOUN1R0QxeFM0SlJPYy9lS0hvSWtQMStvb2ZQRTJCRUYwdUVwMGVaV01YQU5RZWcxQ3h4TkRLK0k2QTVLUVdLcCtVQ2tMVWNBelV0bytYUzExaWJrQmZSNklIc0d6VlhrUThCSERCaFN3R3JxN2xnSk1ZVDVVeTdOM3pMaTY2b3hYdVhCSmUwaWdxRFE1bVpneGE0aGdNM3FaQ3gxV0lyNmFlSlNBSGpPb0l2YzJHSUZhRmpVWmMydXhpcFRyaitvSHBkRHNQY29iWjZMOVFrYmxZT3lXRXIzTkkwTEdkYWppU2xKazMzTTVhV05TRHUyYXRJWDVja2RObTBPV0o2ZmVGclpaNVh2VDFjSUdaK0Fkd21Ga2h3SmRDeVdzRWh3Q3lQWFVjVUs5NFdwbVZzbkI3bDBJRnRtYTUrSWtDZ1UyQXhFbFd6TEpBZFFDMHlkcEIyejBZZUc0VXd1SFlYMFJJYVZJblI1OE1vNHBidEhpVTJ3cW1GUlF2N3dRSldJakZuODl3UTNyVUphME12di9BRXdjeWs1UjNXeHdTOHN5NFpWRVZBOWkxd3BxWFRydzVwREVSUmRaVGlWcVlFdEN1YWxCUUlYTnU2bVpqalRZVHFLV2xlZHk0anZZVzVCNGVJUU5IWVllSHBqUUhWU3RRQlNpbExSVVVEaEVha081UzVkR0JYbUc5WGtZV2NrVFlXaWwvd0RYRUtWRm83OVE0ekxjYnRod2F3QnRIZGNTa3NOSWE5UktVS3p3MzJRakJBbzJxZHpEYkJzaTdlSytZZFV1N0N6d05hbHlZTk5IRHErVHFWVW0xT011eDhlWlMxU3Fad1hUWXVEa01hbVphUUVBTzRDd2p0amJYbWFVT0psWE1NQzVidGg3Nm1IZGNUTzNBcnYwUEVKOURpbERyM1BoWVloNVloVTluVVlVRURSemVTT1ErSURjRVVTeEZOZGRRRmtoSXAwcUtPbVVMRndSRjJsYmZHWGtWSXEvTXNBM0pVQWpXV2VMWms2UmloU2dxam1CTFBnVVVBTm11QmpCYzdKNllDV0hoSFAyaFpKUTVycVhMQXVBNjYzaVdyWkczaVVNWXFNSE1BS1VmelVDUXBma3dSUnJnTTNGSTBHK0RGMWNKTlExSUVpbzJvWVFxUDNRcDZoUkRUYkxkaGJ5dVBVUzRxV2NpcHpZWVcvcWR0Vkg3bDFZMkI0WldwdUZjNC81RXlTODN5bmRrYTFxdWc2aWxVQmFCd2ZFVjRwd0VwWGlhRklIcDlQaVdvZXE0UUJ3eXVhUE1ab1VCV21wZ3JEZGUvRXFRNEt3eSsyV3RvbDF3UkFFRlYyTXdRS0lFeWFvWEVNVUZaTDEvd0N1R1dxTGZvRVFXbmxtUmlabUNJUnRIRXh3UWxEdVhXaGdXc2NrQko2SGpkdkY5UzJ4QU1wYUdCQXVxZW9CQUJXRHl4bzBxbWhVVDlyazRhNDhSOHNkOUJnRHlHSll3c05kQ21xMWNHOGd5OGlPa2dxbG1zcnl5eUlEVmxXdk11UGF0cTNoaDBOb3JBVlMva3c4QVlXc01sckYxcUtmREpzMXFXTUdTMzZJUnlVckFubVZvTVhqU2NkbGpSUUxmek1NdzJQRDN6S0pFYlpzaEtKd1N0RFYxQkNRREs2c3NpODM3WWVJaFF0RG5TWFBOUXZ2ZzdqUkhFdDJVd3JRNnZtV2hqelYvTUtrbElraldmY3NBMzBqTmVvWUliS1d2dnhEa0dFS1dtQUlYTW9pMHdGamlsMlZta05HMnNCVnZLUUVTdUdqNVIzZzFncFBWc0ZPMUpwS2RLcGlqWnd4VDFoRmQ2cmRQRU9JWGFTbHhLV1BVZjUwUUVOU3VPRWxEY05pTm1vM0JMQVo0ZHhkMk1xUmwvNzdGWERnOUN0bjl4Tm5aeXd4SUZOMms0bVUyWUJxZjdFQ0pWTkRGSmJ4eUtqOUJEQmdzMURaeVFaZXdQYStXTmJtQ0V1RW54QWN2aVZLemtwdW1MbmdzV3AyUjlKY1FuL2hLU3FVRkNPdzZpbm43SDlJVlhKeU1mQ1A0QmFPMktab3lMTDJocERyRzREeEFPRTZ1UFVGWGM5UG1LR3lKVkhnK1piOE5oV1NkRUtCbFdMcFJ1eURFZTAxVUlrRllVUU40ZWhNb3hvRVdRYktCMmVYNWdxQ2k4djJKdVhxcmJQdmYzaEZqcUFJeEVFcDZoWndRWExGZE1TQVIvdUtCYm5WeDZUWU9ITkl4bEFIU0ZRWkNyb2NSTFdxVzdUSzBNVU5qaUZvSVZ0YThPSWp6czVOOFJidENzcGU1WDBGTkVlWXhjVzBIdXBuVmJEYm9sVVRrTlFVQjljSXFXU2R3NGxvMGpsZ1dyUGlONmNpT1NaTVJuQ0NWeElYZU1aaTdDVXRsTGQrSWJrM2NCUjM3amdRWjR0TWR3QXVTWWxWem56TThRZHRmOWlaS2hXb0NYNUtMdU1jUnBiNUNsZk5vZzZLamxwS1czOThTaUJWc0VwaW80UE40cUQybEN3ZmQxRVF5M0pIUWRSVVlMYWZ3SnlhM2NIUWYzTUMzaGREM0ZmYlR3eGRRT0tEZHBSMkVkSERVOTB2NEJCdFdNVUR5Z0lhQVZVdEk2VVlhWnFaOEJ5S3FaelRGRDh4d1dtVTB5amRaYUpxTS9NQ3RTbnY1TEtpQVhPTnc2aWJvZHdGWUdWdXFQTXcyYkkwdzBWU2hiZTJXdEJmSnhYY01GUFhCSmpWZVdteUhiWFRrSTd4OFZoZW1FUHpIZ0ZMNklmRHpkb1Ivd0FDSTZTN0thajlNUVYyRHYzRnQ4VXJmekVqdU5XVk5LRkJhVTVKaWhwSW80UW11SHJjMGN2dkhObUhnUGN4RnM1YXRVZXlxdnU5eG9DMlZUTURCa2dXVDNLc0ZHMFBuM0tpRE5WcCtaaHprbmxMYkpMd1FQN3pBSlZRdGZhNGx4Y0F3RXBYY0d4NzZoMnN1clVkL2p6SDNxdHZnajZhS1dUNVlXNysvd0JtS0ZsdGxhNDFsSHlaN0k2NG9PYzNXRUFEWER1OXplR0NiK0l0TGdEMGI0WmVrQWcwSjRZMGhSWWNhak1kdlBTbFp1T3htOWxxNnpHNE1zT1I0OHlvOWdWV3ZJd0lnMFhpRnhBQ3BRTzBzU1JZTUtlSXhrR3gwWHhCck9OKzJYTlFjK3dpcE5mdnk5WEZUSXkzYTdqc1dLTXJxOFNzR0JzeXRaVVY0bUlHb1hwVlUyY2FLbFdXcEFOTTJNUHJxbGRGZHpUTWtiSFVUdEFWU3FrOHNZbzdnYUI1Wm5BZDhzSjFNcTVZMUh4OFJoWUJHaU9SbE1nOW5tUEpuQi9Lb3BJNUR6NTh6WnF3V1QxOW9XQzFEbEgyTkxWZk0xUmVXTlBiRzBjVk5xOFRlMG9VQmZiS0RXQW44VE4vb0kwWWZlSDFUYmJMaVpXVms3bENWQnZaZ1hOUTYvYVdCRG1tWmx2WFJGbDh4dktvZEFNdW9GcXltVkpEUjVKUUNjR0dXTkVLbVFjUXVxODJvVUJ3cEZuQ3dvWE4rVHFYbWZnYWxvSFFvQ1hXdUtNa3RJam9kc3M1bS9wTGc1TW5VdFdYcXF4R0JTRzExZmlVWU53ODNHWUJ1aGlwZldyZGhzK0kzQk5IcnVIWTBiNENPRVhvMjdsbjJ5MzlRVm9BakNReGhic0xUM0VMV2VrMlBNdWxDd3VZNTFrQWdCYnZ1QnloR09YeVFxK09EbGFOWDhGblRNNFVCdk5zVkx2V0NsM24vSXE3MWc3U3gwQ3F0VUxydW9vbUFHMCt1YjVXSE9HQkQrVlJxNXhTb3FOYkFqUDlEUlVYeEJPU0YxdVdlN09SMUR4OHNOKzNTYTdCZXoyTmsycUhlZGFhalphbGlyaGdGMk1hQm55alFsTEF5WmxvS2JBRmxNdUtiMHVoWG1vUmhnRGRkaUVOb0lJN3hEUURzTUNQVlJnSmRaUysyNHVtaHJhdit6YThrS3UvY1pTODJwekN3UU15RHpMaklGM0RoKzhRSWlNNzJ2UGlVMWp6ZGVJRFZ3S2ViY3hiVlJhVnI3Z1ExaGV4NGlYdFJWamJuVXpnTlFEUERuVUZwS1ZBVzQ5a3JiRFJibjdSa1p2SkZ1emhKaldram82KzhYRmtZYjhDdUI3ZlVvQ0lEZ3RqNWpwLzhBR0RNY1MraWpiMmhLeTBHaDhwQjdjZHRobGNXMFFPVlgrWVQ2Q25QKzRheVM5WHFCcnZZT1I2aUZ0OVRaRWFkRVhBS0tEUStITVRCRnFtWUZUZ3E0dVdEMGlySmFpTlJzRWU3OHdVU0c5YlF0eUY1ZVpWRHU3S21adGRXSWF6TkM4UXpDbzRNeFhjVkwzQUxRRGs1aXRFdGl0UlRsQlRUVnhtZ1R1ODU1bWU3bUc3dGlVTGhCV0l2VkhWcXhGT2pWT0VpVmlCQncrR0JhWFlHQmVHS2pBUlEyRWU2cGZySCt3K2F0SmZQY1VpdDF0MmVKVkJnTFhhT1lCMWJibk1kbnR6aWRRRXJndVJ0QlVxanJOd1ZVTWxyKzh2WW1Xd1JNYmpFeU1hejVZZ1VkMEsrWWViYmF1NDJ6UWF4ekZMUDg0aXMrY0F4NzZsek1EdG9mOEFzeU1aR0xMUkNGK1psU01tQjJWSzZWMEtZcCs1YTN5bFFQSS9aQUFkVndiNk9rTm5PUXV1MkowVE1ZSURHTW1rN2haMXVTN2FsaC80UFBtWUx0TEFvK1lxeXQ0aDV4RVY1Vk5EaUhGYWdodUFsRktEd0dZQ2lUbDVOWS8yT0txb1pwaFVBMW5IVEFvbXJZM244UTRqQnR3SWFxT0NGME0wdkVNUlEwdFNWbUpTaFdsblBNUnNJMXFCdVVFSU1Ia1N1YXdGM3VHWmFaVVozUXc4UjhsZUlLVnJYRTVuWTA4M01IaUZ4QVJGUkV3QW1hWlZ3UXBLTGxPb3pZVTVieEVTTmJUeEdBRDJidm5VV0oxUTBtRURhSE5ocjNLcHRyVjFVUXBROHJCYXBwOVFFUG82S3VKYkFNV3c2b09HQmRjSEJLM1NhdU9oeklSL0ZRd0ovY0lMZkNpOVI4WmFxakxCRkJGdW54RnB3N3pNU3ZtTEhMYmptZ1M2R0Y3NVRKQ0JJckRqTUxhU3VhMGVJcXNIc3VLRXNPRmFoZEFsRTRmaVh0aVlGNGpCdzRwcko4enJQRVdQY3dtelEvcUdTb1ZTcFBJd0dFbVdka1JpcjZoS0FhT2FqRlNsSVdGcUt3VGJzVVcyL3dBaHhjOGRyaldDUzNVR0lJT0h6RkFVUXJHbnVjYkw3UWJjSHhLamFCb3hxS0N6dURvMmJ6TEx3TGZsK2dzV0w5TDh3cHpMT29vNGdLekhFYm9hVERIQ3FObkkrWjA0WVZmQm10cEVWay8yakdGTmJnTzhQUDhBa3dtWDJiTlhDQk5HQkFxVldsNStaZFdaZ1cxekcwVkVEa2hBb2VHc1N6N3hDVy9NdEdJVXJvNnJtWDNjeEdyZ09HVVREWnpBZ1hXT3FscFlZZG10bnhPUFEzejRzb2dLeThwVDVRbTU3Q1dBTnRhdzFVSStSanlFR3h5MHFsNmxka0xKTm5mdUdLMU5ZWmhhVlFYQmFWaUU4UWJ1bUZlWHVKdU5OQy9jVHIwRGRsdkRjZmxsRE12T1luanBRNlBvNWdpRG04TzV6SzR0RGdRUW8xZnpLbVlKR3J2bUd1cHczRnI2RUlyWEU0YmRsV1JxN3dwZk1sYWw2ekRLUVQzQTJLM0JkckRUcUlTalZZZm1BbUJtT0lZRG9OT1lQR3lrTTNDck5rWmxKcFc3WnZFU1Z5aGFCSEJDNmgyd2tSa01XZnVVeUFicGhXRmxydERZa0R1aVJVL001UE8xcUIyRVd3c21Wb2RMWnVMaGZ0V3FJc1QweGRYTU9JSmxTYnpXVm5IMTFHU1ZDZ1k3TzQxYkxlZUd4Q3VqWFZ2TXdVSWNaWHVCcEt1QStPWVVGQU5BVkJFdlVKTFZlSUFCVVlqR0F2Ym1NYjNOTDEveVlmN2xVeVIwUHRvN2h1Qk54aXhSVVdYTGcvUXBkL1RZY056alZSSzdWc1Q4RXlRT2dXUDdnTk5BTUExdGx3Z3ZzQUFoOCtoM1hxQTZZYVB3aW1oRlo0cml1b0o3b3Z1WVdYYXNNbGR3SkFOd0FSbGVNT0JWd21FQ09BKzVzbmk4dCtZY3VvZUhVdjZ4cmJSRklqSUY1NmdKYlRCWmJoZ2psUzFRdTRocjVkeU5wM0x5NTRNUEMzRlh0dkJYdWJ3NVpFOGpHSlV3Uzh2T09DWWxTc3ZFWEpTcHlIZ09jUXN4cFFuQUtadUlWVXk2Zi9lSTNwdUV3WDRaV1pNOW5jSGxkWGcvY01qQWFpUFhNZE4yOXh2cnRnN09NWlYrNHF4ZUxGek1QMU5TNEhlQ0kwVXdsb0YrZVlEQUhQZ2ltMmhwTURFeThvTHBTVzFsbUd6VXFGeHdGTEtZVm1TdXlHWVZFZFBjdmlSWXpBdWVNUlJncmVjQkxOWmFyWXR4VVFMQ25WRDh4b3RIRUdvY1lnSXd4Q3pHZzRqa1lIWnJ1TVpVYjZseUkyWjFCUFk3SEk3SUdJTDdEeDdndE4ybEw2ZUp5NkU2VkE1bGV3Uk5DTXBhTGRmOWdOelRzVWUvOGxjZUlBVUVGZEF1TWl0YTNITDBVcHA4UEJCYkx0eW5FcldMay84QVhFamQ2VFd2bUphNE80b1Zlb3RqbEZpYmpINjM5QnI2REVNeHVXdGN4aEtZNkRZTjB4Q2huK3d4L3JvMGgrSS9ZNHBRK0EzN2hsRWJ3Qk50dmZpQkVXaGlvWWc0VTREK0JLYWJVR0ZlV0dmVUUrRlp1Q09kZ21ZT1NKd3lHdkNNVkl1U3gwVG1VQXBzb1BzTzRuQlJ3SzM3bERhUEUrSks5cTIzcVpiaEdBdmVJUkdEZVBuaUxBYUdRSHpObTU0Y0hoNWhaVVUwZUJNQTZkNmk2aWwxaERScFNqK3BZNEhCMngxR1hoYUdhUTg4WjUzNnZjMjZsMFlmc3dhTVYyY0hURXNlcWtFNUJNL2pWelBQK1Y3K0lYWkgzRnlkbjhNZ2gzbkVyMjU3Z2pCQ3FHQmlvUnh5dW53c05VdlJ5UG1DNGxJcExTQ2FROUdOMldxOVM1NUJiS0prcUNFM1VvVDB5NGFqZWxlYS93QkVwMUNKbzl5MnRlVFFZSzFCeE5TcUlTZ08ySWJUb3ZobHJZdFZ3WVkxdGxNeGZrekoyOUpCSUdkN0hpTkJJSXNBOGRSeHc5VmdnMHJWVU5RRVliZHI4SG1FSWdBREJvQ0JwbGhubUt1WHZkeW1MUEFSbDRnY1FUVEdOOFJtQWYzTEs3c1lWOUpOeTJNZG9zWVZzZ1JqL0FtREJnek0zRTd1SXR4TzBoRnZoZnQxNFJURXVUMThrSk1TMk5kb0Exa0diWGF3QnREVGtJd0JtdTF3ckRuTUJXSk9JT1BWeTBwQ2loRzVDYjJQL01WbGphZ1RjR1RSR2pjS2tvMFg4dkVkTlBjbm0rSXFTeTNzekpNT1MxYjRJMUVNRGFTeEhGYmNJVDVocjFCV3NSZXp6VVRFdmtqbjFDSENRZUFWV0N6dnVGWEFXMkU5OVErVWIzYTgrSmZISmZENTlTc0dNeGE4U3ZRUnd1R0dZbzRsNWZVc0RFUjJKY2d5MjBTaEZGc3lKclRxRVF5T3ZxbGxNVWIxNGdJRE9YTWVCUEptaFRpQWJoYU4zRjFvZHRzRWRJWDM0STYwelYxSHBLMVBUTmNRYWpRcTczRXRFMHR3OWthMWpjdEZ4NjZtQXBBMWJVc21OdTZ6TWtwakVvUndMMlRYbUVZTGZwU0FIR01tVmxJYU1JeUZiUENVN01wV1R1RmFjbU1MSWF1WFZWdCtJK1hwVDFCTGdOTGhwRi9NemkwbDUxUGdyN3pjbHpEQjhqTlFOWnNYaVVudEduNmpJRVZpdit4RTVaYzh4UnlRUVJ1MlBpWDlFcGpGL2dTb1FFNWpxWnR4VzNHeGlqTXFrQXZYZGFmY2NJQVdkV21NMUg2Z2FabkhmbUY5cEFJaDBTZ0NCWlJMMTVpTVpXNkgvd0NSUTJMRytmN2xIaEcxb0xkdDh4YUtOWEZ5aElZcXRubVB4c1V1aDl4THNKSlI3SXZZTk5nK1pUWHNVMGQzT1p5MlIzVTZodFpuRWUySWFtUGphdlhjYTNpcFRHZUdNbmhIWk9SQmhabWowSWJ3QUc0QXFJNkRVdm90WnhFRndZQmpTdlVKcWFFMDE2dUQwaGtJUkdLMGN4aTVGTi9SZTRUSTZvQlQ4UkZ4UXdIQlpWSkxHNWIvQUsraDlGV1lCYU5jOVJiRXNMVEtRb0FxTEw4eDNNYnAzVGlZZ1MwMUNtQmVNUUVIYkdCcHVIVVVBTkVoekVydG1kc2JnMHhtcGlXdFFHTXhmQjFGZ244cUpJVlNMUHhMbXB3dmtPb2dLVzhzRVJtTjBwemNUMjVsbzFHazRsTTJBM0xTUUxGcDNsekRJUTcwWXIzWUhhcWoyMUl0d0FXZlltQ0Vsb2YreFVxQ0ZXZG82dXBkZ1hHTVhVUTNYQ0VSSzVWbUNKY3lqMzlGM0dKRWcrbWlQMXFWSytoeEQ2YVRNekF1WWhpRHFWczFnWGdhL3dBbEdrTkZKTUZBRzJvSGR2QlRCdmNWckd2TlZFVFFoYXNIS3k1QUZDV2ZiTDZrdmRteTVTZmhBcENzcmN2QTB6Qm02TzVYYVRnYU5TOVVxeWNEMUMxZ1d2Q0pJMmhLT2lHNFhGbUY3SmNrc2FaZWN6QkF5bFU3aGpaZXdyRHRsUmkxbDU4d0tZMnVXZGdVaHBIaGxWbEMwMjRSOXhVVHdPYU81U1ZCRjVIbnFQZnRzLzhBSVZwVU1GWVlRaUcyMncrSlkwbEg0SStWZ3M2L01VUHp5c0xYSTlNYStMRytmTXI2RDJheENtMXExdUNyUTVSSVlieXhMd3VHRmNieHk4em1LVElqWExjUkhXeXJLYWF4UjAzQ3FORGt1c2NnbVYxZ1A5Z1RhY3FhK0laWVFjNzlTK1lQbUVZZzJHRTdsNGwyUEVITHZvSEJMWnlTR3VlRXRLbzJQSEpNdGpkdzFRaXhpM3djeFMwb0RoZC9ZanoyaHVzbFkrTGdWTGRVZUFtVm5VM2dMcWF0SFZLdm1YUldNNG1zV0RMajlENStta3FWOUZSeDlUVVBvelVhNHg0bmNOSWlrS044VEFNVlZhR241M0xQaUJwV014d0RoYytLbDNvQ3lkUEJpWU4xMG1GZ1phRDRyQ0E4Z1hFUU84S2NFcUlobmsrSU1Ld3Nrcnd6WFRJT0VwVlh3cFRKcHRwZ3RXeVlxWlNhNmFrdWFvbHV3YUhRRHI1Z0xsR2lhdmt1TXBMaWxlSlJkb3JuZFJrbXczY1gxOFdGUm1NR3d5L3lOdFhPQ2t2RE5GU2dHK3hHUURCQ1R4VW9ZRUdkOXlvazhsQ0NLTVMxS1p2RU01ZW51VzdIdnhIMEdUMlFxbTlKOUVCSzJjTFMrSVVyeXl0bEkwdW9na0lHQXdHN2pBQno5cGF5YVlWS1ZPYUdJVXVGMXNJTHFlbmRSb05qRm1UMHdFQjJWcFRMWUgzY3c0eWRZeEtnbFhlZE1yU3RvZjZqdTlVUXJ1WGl1cTJQQ1dNMW9wajh5L2dteGVuY0dFbkRGZ3VZa1hXQVkzS3NRbmt0dEZtRTc1RlI4bGI1akdTTDlMeE40eGd3WXhnWHFHb016U0VadDlTSDBZd2o1b3Z1d2dENWllaWJsUW5ZWHF6TVcwalljcjFMS3QxRnRyeDhUTUFQR2U2aWV0a3hsV3pwNlptZG9LcHQySFdwbHhXUWZjbVNyTmZnUU5zQXZXNE54TUVJMlI1M1N5Mnd4d1ZGQ3F2VDdpeTNJR2FKUmJxc3ByU3pvMGMvRWVuU0UwTmVPWU00N2hTL2lGeHBZWDJ4MUVBZ2JUdUNhckV1SVVQZ3A0bFhQYTFYNGkwNDF5OUxJaXFWbGNlTXk4dXBvNUJ3eXpyQ3luaVc0Z01DcTRNb0xTb0xWTmRJQ2poK0dPanMxN2pkbU9tVUJZTUg5d1E5akVNVmd2TVFjTm1HWGUwV3BxSThoNklyR3M3SmtFeHA4eGxzZUVxY1FyTi9xWnZtU0JiVXhBWWhsWXFXM0ZGMlhVb2wyWVRkZkVjbXFBNWZNQjM4dFRkT0k2b2FJVVFsaXBpcXI4d09ZR3ltYW1XTHZkMFRKeWlsWVkwNGFlVGlPaUVPQ3JUNWg1TEFyZG1KdU9sQm9EL3VMUmJMbVBHWXNZT1pjNG0wWWtOZlM0c0dmMndRSXhkZndJZlZ0RlVxcjl5dHAweXRFMHdkdUhMd2tIY0x6eUllWVhGaHF4OGtTZ05VMVhZeGxIZkE0d1p2enFKS2swR0I4YzlUY25XRnJuRmRSN21WcDVZRFgxdWxqS09iQWlZUTRtZ0xXWmxzUkZyUVR1K0lscW4yYkk5eHhNUHpSQTluUTUzOHdBMDVzN3J6aUFsd3J0L3NOYkYxYlZIcVlrSlZidjFjYWJ2SkxyVXd1YWkrUnJOcGVDQWJKdW0zM0JPa1NoWDd3UVR6TFIvcERiZkNrdDNCazB6S2pFZVpXNGp1bzRsVmJPNGxlQWFoYXdiaFpJMFVSM1c5M2htQklyRXZUa2poeXdoMnBiUkhMcjd6U05YQVV1T1RNcWpQNUl5d3d3dVplRFVxY1ExQ0FXbUxab2Fod3NJU0lBWk80VGI3WndTbzBMRHhkc0pWU3JBK2FaWTN4MCtIdVcwb3djdlZ4TU0ya1pZY0dlaTFUeEZVTnNrY1MzVWtJajZpcEY0SHVzL3VNeGdEUFZMaWhqekg2R0U0K2gvbHpVMysvcXBINjZUYkQ2TWRUaVJrdGNRd3dXcUxBcFBaajlmM0J1MmF0SkhWK3BRRkpia3FkbkpBSjRHQ2dDWm9OUTJMdW5xWmtrSzNSeGZ1TlNrUWxDbXZMTGdNKzZ4S2ZJQmhZeXFubTRNaCs0S1NSMEtjdzRYUU8xSitvT003bHZHSWdBSXZwTHpTMzBXczNMWXhzdTZZdWJHTWhQVUFpeDRyNnFaeHFtM1RHY0xmVWNJY2pobFNjSmJRRy9tTTdrcnB0cmZxUFJaZ0xVcnNCQ3RSbm5KS1Q4d2FDNXdhRWZnWTRXRU5YcUNTYjVaNW93NmlLWW4reUZXTXBJU3BUY2dxaXRud3VCckJxekF4STMrYmduU2tLazJyR0pRNHhSS0tGWkExTitvalV0Nk1hTjI1cjVsQnpiUE1IdzY2bFBFS1VZUXdkVkUwOGx6ZUsyMkhvakVONjJEL0FKRGJESWpDR3FZQXlnanI1akJRQVN3UGNKZVJSbDNuM01FQ29PV3VKbW4zUVVlREV2RW9iQUhFR0pRcGt0TnhoUlExKzFLQmN4WDFHTUNYOUw5YStwUDdvVlVYTVVZUUlZUVFKVWR4SUtNWDJvbFJRUy9FY1hGNkhtQkJjRnJRWTNYVUdydEZnTmNRQkVTblZqaUtvSGlGTjkxTWdWZEhzRUs0enBWTnhaSXZHZ3l4ektVQzRZTEd0c1pvNmhScFpaNmhNU25odVhRUFpzaEJuTzFkellLaHNVWDRtTFhuWnFBRzkwOFJBV1djQWw1bHNVZTVZdFlldkVRdEVJVlJleUVOM251TFpFcTNMVTFLK04rWXNtVGhERXhFRzgxc2pDeHpERnRsWGJ1TnFYNWdhdFliV1lMMVNncUNWTHBoajduVnAzQ3c2MmhHQWNIajFEZ2xDc3lQZHhGYTI3ZzlEVVd5dUdaYlFLTWhxT3NSVEUwSkpYOTB3aHRnUXNtMUQzSE5LU0FQUUdWRzNxbWFMSzhHMDFVSFZPallQRlMxU3V0UWd5SUZSZ2l1bXdJMm5FeHV5aTcxeE1TQWJGK0l2L3lWUlMzaFUzRmZFUXZ0MmZueE1hbjlEUE01NEhZSlZpQnhmeEFVUDZpWWp2NmpHSDBPbzdxVktsU3BVUHBEaUxtTVlRTWN3aDlMaktibWlMTjRtNHNrZVNydzg3Qy94RVhoYVZxbVdsaXNjMDl6RVlxbmxmcVh5d1NmSUVaOGxidGlkTUswYUc2RzlNQllIbVhDdElWWXVSNXpEakhnQXpVUXRFeEJ1UENNQnlTNURzd3liV0RMZ2pvUURZWnp4Y05vSENxYmowVTVLZW1LTWhNbHhlMkw1enhVb2FzTUFGbE80RENlNHdiVVZUcVplRjhJdWhreWpvVG02cVVBVTdxdUhPbTc2aEphRllqVjBsd3BCdGQ5U3htd0VZQ0ZmQmkzNTJ3bUVEVFVKZkdEY1NwRENselNRQmJHSmlWS040bThMZzh4elIybXNOY1REWGhEeWhncnRYZmhGdDBLTFpXQmhUYlFROFF1MmJlWDFONFEzZ3JxaU50QTl2TXUwalk5ZmlKc3p3UTBSK2tJdkFYZFhCb2xGaGFnTWdpSzM4VkVFZVdlY2R6TUdPRnE4ZW80T1hOYzVXL1VYb3pzdlRoNmxqb3JvZjhBMnBhenB6RjlwRG1UTDZOb3hmb1ljUVpsL3dBT2ZwdWc0amorSEVJZlYrbTVGbjZZcm1EQVpMZUFWbFBaekwwTGV4bGg2VEZOK3dsRU54QmRGVm1pV1VYSFhTck1JZldocStybDFWYnYzQnhXWmF5Y04yU01qaW9GYmdsalRzdDBpVGNHNThNdmpWckhNbVVQUllkbVNLOElSdk1ORm5RQW9wa2pPd3QzcmNSRzB0OEV0U3B5bXpjS1UySllHc3NhNVN0WUlQUmtGLzNEajFtbkVKWVhRSmNJR3ltUWFZZkZDNTE4UXhqNnNVY01yekcvWCs1SzFyNVdVSUJBd0FBWnRoUTV0eHhIbENWZ2d5NVRRQzVRa09FSWhPRk14WkhGV0ZzVVUrakVUVnJnQVVRb1dPWE9WWlNXcHE2d2U1VWFJcW1pRlhJaGJmWHViWUEyRDh4VW9IQlRFQ3VxT2pVdjJQZ0x2MUxIckYzUVlQQVdqZVd6L2NzQUN3MjVsYXBSc0hmMmpvcXh5cDdXWVVCazJ5ZExHREVFVURybGNKQmh5aXhYOHNibXdxYkt1TXZjSWtPZVRPUlAwVGVTZ1FmUTZqOVduaWJUdUVadVZPWnVocUxPWUpVSUVyNlAxMmxXdkRGUWh3TXN6VFdFbXhWUGM1Q1d2SG5jSk50YWFpOTVPSWF3b0dnOFEwRHV5dnBCU0hoQWpxaHRMOW5pTXlVcklzM0FWQ0JzaXFHOFcwNHFXcEFoa0t6WkNCU3FxWkM0NU5tT1NPR0M2ZUphelV5TVQ0RFZwbk1GaVdsQjVaUWJhN3FZdm5VTy9KTHNFcnhDdEIxYjNOTkRBTTJ3Z2RSaXdrOG1CamJCVW9ib2dCbTBRZnRCTlZjNW1zY1JCS2hxQTFXRkpGbllLekdIemlGSTF3ZUkwTjRPNHFwYTVzbGt0QnE0VU9IYVhMaWdTT1dZYkNzUmNZVlUwY1FucmxHNVhxVVdlNHV0WHhLQkpOQjNFcUFyVE1wRmU2dm5xRVZTUkExaVhrQU1KbWJGRHExNDh4NDRCSElIRUExeXVWZS9VRVlCU0RGMUJ2a2RBeFVTeVFadmlPOW8zZWhYTDNDNUZzU3R1SU55eld5aWJoaW9NbTB5YmxCSExRZVVQK3pNcHlTeE9pQ2JJUHFKckV6L0FEMlJ3ZlFHQjlEK2JLR3orWVl3Z2RoY1JiMW1UWUtMRTgxSHJxdkJmZ2grNG9yWVR1WDN0YVF1cGNVZ0lOb2twb094L2NMZUY1d09lenhCSlFxS08vOEF4QWRTeGRITFVyR2RBZDVaWWdBcklGSW5ETTJaZ04xRVRBR0hrbFFTZ21jc0JMQ00xc2dhdXhVOXlnRjBQVEsyUHNNUTRXMWJnWFdrdi9TSUVGc3ptNVJBQVlkUWIzNGpMYVlCSVZRdEVBcTRaVHdXVFd6RUh6RlRpRnMyUmhMdHZNSzJtY1IzWllHcHkxWXJkU3ZiTkt2OHBucUdCY1RlOU9DQkJyS3JsV0lJeUR4Nmdpck56VXhrd203K0p3Q0NscUFMTVd4a0U4d3hBWEpUSHpGOVVxN1NqUVVaWUNOM0dJNFNWaWhHQWF1VzIwMGplK3BhMTQ2MjR1VkxHSzMxRU4zT0F0NkpaNkwxYks0SlduQkJtRWhNWmJzd2xMMUNUa0pRcS9CTjc3R3FGcHpuMUVCZTE5T1AzRXBLVWo4U3Nxa1FNR0poRjlWL2xVM1RpQ0I5U0dJL1IrdThDbTZocFEzNXNScTNUSnVycjFHcGdLQzRpMXZBNXZFRTZrN1ZYL1lnaXN3V3BxSzVSMk53a3V5QjJQRGNQUmhxM1k1TitaV3NSbTV0bytDcGU0NHJ4dXlEaGlBMmVwY2ltZ3pqek1vK3hXdjRsWnN1eVZTOFNvOEhOUXFZTmlwQnFZQm9waVlJWHdXMzFCOWJKU01PQ1MwTFptWmhnalhjQVhiVGEvY3RxQkFNMGhvcEhJSm1pLzZpR2tCZGRQVVhLcDJ3ZVladVMrRDVsZDhtZko5RUE0WmFnZjhBSmxBaTdPRDRtV0NNUUFTeWFPbzFWTjJ5Q3FnQ3RsWG1ZMFFzWlNRN0YzS25IWlRWOXhXOTRLRUZjcGtNTldqeGFHUDZoVVpnQ04rSmpCL0xINHFMS1lvb2k2SXE1VUJmS2NJelVvWHNPenFiRENtaEo1WmJuR3laUHVMVEMyY0Y4UnVyWUVhRXVTT1J0RjV2eXdlSEJycndscnl1U0dGQTRiQkg3SEl3QUZGSUdxRi91TnZiaVVYNGZvQ0dDQ0hFU1Y5T1lTc1JQcEJpVi9BU282K2o5ZHlXQjJTbU1hMkJmd1MyclpMNGVJdGFLRGJlZktXR1VLTjVmWkR6NDgzTnN4cmFYQzdmRlFFUmhnWUJ3ZTRFek5pQnhHaWJyaHA1ODNENE10WGJiaGxRVnViSk9ZTko1UHpNbVMyb1ZiTU10dUdIeEQ2a0Fxd1B2THc2cXUxMW1LVlppOXc0eXQ1Z25zdkpWUEdZWFJaVHVZS2RNbUpkWThKbVJnc3dLQ3ZCbWVqRzV1RXQ1dGZ4QVZpYmFmdlVaNkZyQkhGY1JCME81dFljeTBETXBNSEVNK0dPdGNPWmpsVjJQNWlaWkZhd01xWXQyNGxlUUtwd3NlakJjcTQrSWhkVnJnSlZoYTZvMGFEVHNabHljUUc3ZmlZb0dWWEZNb1RBWFBNcDJyS3Y3Sk1JMXpjdDlFS1c2a0cyT3VDSmZkRHFNQ1dXVzA2SXhrRm9UUGhEaWxITWVZeDRibVZ3ZUNKTnRWSmlNWmJROEJ0aU5RbVN5MGdTRjBQRUlSQ1NPSElqQ01pazlDZmlOYUtTejVmNGtxd2hzWUpnaG1vTG1EL0VneCtrUWovQWZVL1FnekxsOVNwM2pNRk1jcFYxYmY2bUhzVm1oMUhCaERaektWS1dkREVIWXdxVTE2aTZ0U1dacDRxWFREVTVVeFowaE5JZUlqMjlnaGVXb1hFSUhNRGlGZHUzQXhFWUF3OGpGRUNsTjNOUW44MGNRb01ObXJUcUFjUHErSlpWdmJXSVFIWkZpVTNoaHJaemJ1VWtpMlJwVUswM3RKakZJY1J1MnpUNGpYS3d0bXF2elYxQlc2R3dhcTNyc0tNTmxLcUxxekdjQjRSWTdEcHNiWXQ3RDlRaGxhdm1GcUdPYldWaUlaSVFWTEl0UU1lRmgzY2ZCclE2eHhIYktEQm1BMmlQaUcybDNGTHRnbklNTlZVd2ppL3YxQ3cxMHhVdmFGczdJQ2FYWkcvRVlNUktiREtDMUtweEVRSlRyRTRLWGZtRXdRRmE5b3F0bUZtbk1DU1J6Rmg3OXk4YmtIL3FuTWpRV1d1WW5zVFhPZk1yOUV5VzErWWxSZVNyS2lrQ0lmWjVoRll5QmE4RHdRKzIzeW93TUtHSGcwVDV1VVdqVzdIRm40aitJU015Z0VZYVdCYkRVV2ZwWDhMeEJ4SCtSQ2FpL1EzQ01mcHpHRU53ZGVKYVhlV0hiVm83TkUrT25ibVdXQXBrZkV6YnNFS0NlTnpOTzhPeFV2cHdRdFZURjdwWnZWRUNTMEdRUXBBWHROS2ZxRHlpRkorRWI3U3NWVExhTXRvYTA3SGNMUGMySGZGOVJ4R2kvRVM3SzRsQjZseEk3RWF5M0dXeWJQbWNyTlBtY2lOL3VYOFBhU3VxKytJdDFFRWg1cVc5QVpacTRMbHlhN0poOVJYQzZCbGZVZUdnTEdFc2Z0bUpOaFZBbDlzeWx2QmJOVFhQTk1iQ1c3dDIxNWdnaDRtZ0JMcGJFNng5RExaRU5FWk1raEltdlljZk1vS0F1Nm9sWXlYMUFVQ0tTdEdFNGdvZUNuYnd4U1FiU3BZd1hSTFlYQ25sZ2FOeTJWZzFZTFZaR1RFR2pzOHpleGxnMHhNbC9DTll4RnVLNU1MK09vWFlOTWs5a2JtTlZjbjNMK2RqZDc4OVN2Z00xZ3ZrcUxEZnZKR2FKQndYeWRFRmhTSzk1YzNLVmlnTjAvVTRCRlptVzBZeGZRa1Ircy9MbVhoRVVKcHluczNNdzFMcTJScVc3SXh5aFhNeVRGUi9SVXFKSyt1a0NNZm9mUmpLK3BEZFNsVk1WTEFHZ0VFdzhXei9BT3VYR0N1NEJaVTRlV0lqQUxTWnFDNWlvNWZpWnJMWkRYZWUyV0FvV290TWNrWHplb1ZSZWZjR3BnZzA2OVMxWlZ3SzJSZWZvdE1FbGpWRG9qeUtjcnlWQW9sNXRzOVJxOWRZeFFTc2pXdHN0eWo1SWxHZzN4SGdPUjJ4TitwaDJNbG9YbG9UMHNxZW5BV0JHMDFiM2RYVVZxV1Y4cGZrb2hlSFZWcUNZb3l5NHc2eE1xQjBRM1NsVTZZTzFRWVVveGxZcTZEdjdtRndSUzk3QndtbEtyUDlGSlltc205d3JiRjkrRkV3ak1TdDFyd1orK3BVRFo1dU1CYzZSR0xKVnhHcmlJb01VMld3cFNPQ0pWWjBTdDBTeEprUTJyT0pnMkhXSmlYTEhlZFNyeGhVVzVGeUZSZVo4K0lyVXhqeWx4b2NVYTFMWWFKVThMcFNwVzNWQXphUGdPMCtUSEZSb2E3TXE4dlVwSHNDbTRXSmlRakMrV0hhS1o4dkVhcHpBQno3Z0RGTE1oWWJWRXZjYTVmbUphVW90WHV1UFZGZUdqM0hXSVdjcGJmV1pXdHJGYmhBdEtEY09DSzMwUjNYOXdWekZnWWYyUlRGVkVXVE1UUDBFS3gzL0F4bFNwdy9nZlE2akdhSWZRM0RkSWJKaU1GWGhjL2dZNmo5NGNlWUZRc0FTcnp5ZFNsSzRlMGxFdUk1cXpmL0FMdVhvZ3FoeWRueEFncDloY2JDcGtOR3N5cXRnRjhoRlpaREJ4NG1BRFZ0Y1Z2bWFjb0FFQWIzVXFBZ0Fzc05KcUNYaXI0bVZsYXU2bFZKTjJYYkFLTGdkTU1SWTVaV2hhclc1dkk1aHpFVk5acGV5WVVaWVhzWWMxRkFGdFp1TUlHdVZjeFFnRjJjU3hKMnhxQzIyb2RDRDJUTTVqcU1FR3RUSlgxRXF0cXhnTjVlT1liRjFIVVFxTkZEa3VweEF1WnQ4cG1KS3FKVmVBdUMxb2dOY3dURUNIOHd6V3psaTBLeVloREdEQk1qY2lmMGdLSEFZSXJXNy9kTUtNWk1OVVJCSnl4UkROQzZKVldBVWhTS3VNWEdHbUlMbzFyYm8raVpvdlVWMGxnYWdDeks3SU9sOEJ3WE5tTzRmVXVQb2ZSbkVQb0p6Q2JUbEdPL28vVWN4d3N1Q3FWaVhtcVdxRFpnY0dIZFNqQWExUkxRU2hpUE5OZ1loS1JTNmF1V3NtUldIUVc1RzQxWmJlMkMwYkZYNGdDQUNwb0t1U0dBckJDYkRITXdGc3NNSUFDVklLQ3FHSnpUSm1jL1VhS21yQlprTnl3VXE1dVBmUXBiMUNWOEpnM05USU1yYUFFckl3Q3NjeExTZ05mRXlJNmhDaHFmLzlrPSIgYWx0PSJIYW5aaWhhbiBNb2R6Ij4KICA8L2Rpdj4KICA8c3Ryb25nPkhhblppaGFuIE1vZHo8L3N0cm9uZz4KICA8c21hbGw+RGV2ZWxvcGVyICZhbXA7IENyZWF0b3I8L3NtYWxsPgogIDxzcGFuIGNsYXNzPSJkZXZlbG9wZXItYmFkZ2UiPuKXjyBPRkZJQ0lBTCBERVZFTE9QRVI8L3NwYW4+CiA8L2Rpdj4KCiA8ZGl2IGNsYXNzPSJuYXYtbGFiZWwiPk9GRklDSUFMIENIQU5ORUxTPC9kaXY+CgogPGEgY2xhc3M9ImRldmVsb3Blci1saW5rIgogICAgaHJlZj0iaHR0cHM6Ly95b3V0dWJlLmNvbS9AaGFuemloYW5tb2JhP3NpPTFHNnVNd3ZtLXVnMEJkdEMiCiAgICB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciBub3JlZmVycmVyIj4KICA8c3BhbiBjbGFzcz0iZGV2ZWxvcGVyLWljb24geW91dHViZS1pY29uIj4KICAgPHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIGFyaWEtaGlkZGVuPSJ0cnVlIj4KICAgIDxwYXRoIGZpbGw9IndoaXRlIiBkPSJNMjMuNSA2LjJhMyAzIDAgMCAwLTIuMS0yLjFDMTkuNSAzLjYgMTIgMy42IDEyIDMuNnMtNy41IDAtOS40LjVBMyAzIDAgMCAwIC41IDYuMiAzMSAzMSAwIDAgMCAwIDEyYTMxIDMxIDAgMCAwIC41IDUuOCAzIDMgMCAwIDAgMi4xIDIuMWMxLjkuNSA5LjQuNSA5LjQuNXM3LjUgMCA5LjQtLjVhMyAzIDAgMCAwIDIuMS0yLjFBMzEgMzEgMCAwIDAgMjQgMTJhMzEgMzEgMCAwIDAtLjUtNS44Wk05LjYgMTUuNlY4LjRsNi4yIDMuNi02LjIgMy42WiIvPgogICA8L3N2Zz4KICA8L3NwYW4+CiAgWW91VHViZSBDaGFubmVsCiAgPHNwYW4gY2xhc3M9ImV4dGVybmFsLWljb24iPuKGlzwvc3Bhbj4KIDwvYT4KCiA8YSBjbGFzcz0iZGV2ZWxvcGVyLWxpbmsiCiAgICBocmVmPSJodHRwczovL3doYXRzYXBwLmNvbS9jaGFubmVsLzAwMjlWYkQzRE1mNWEyNDJ6cDYyb0cxWCIKICAgIHRhcmdldD0iX2JsYW5rIiByZWw9Im5vb3BlbmVyIG5vcmVmZXJyZXIiPgogIDxzcGFuIGNsYXNzPSJkZXZlbG9wZXItaWNvbiB3aGF0c2FwcC1pY29uIj4KICAgPHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIGFyaWEtaGlkZGVuPSJ0cnVlIj4KICAgIDxwYXRoIGZpbGw9IndoaXRlIiBkPSJNMTIgMmE5LjggOS44IDAgMCAwLTguNCAxNC44TDIuMyAyMmw1LjQtMS40QTEwIDEwIDAgMSAwIDEyIDJabTAgMThhOCA4IDAgMCAxLTQuMS0xLjFsLS4zLS4yLTMuMi44LjktMy4xLS4yLS4zQTggOCAwIDEgMSAxMiAyMFptNC40LTZjLS4yLS4xLTEuNS0uOC0xLjctLjktLjItLjEtLjQtLjEtLjUuMS0uMi4yLS42LjgtLjggMS0uMS4yLS4zLjItLjUuMWE2LjYgNi42IDAgMCAxLTItMS4yIDcuNSA3LjUgMCAwIDEtMS40LTEuOGMtLjItLjIgMC0uNC4xLS41bC40LS41LjItLjRjLjEtLjIgMC0uMyAwLS41bC0uOC0xLjhjLS4yLS41LS40LS40LS42LS40aC0uNWMtLjIgMC0uNS4xLS43LjMtLjIuMi0uOS45LS45IDIuMXMuOSAyLjQgMSAyLjZjLjEuMiAxLjggMi44IDQuNCAzLjkgMi42IDEgMi42LjcgMy4xLjcuNS0uMSAxLjUtLjYgMS43LTEuMi4yLS42LjItMS4xLjEtMS4yLS4xLS4yLS4zLS4zLS41LS40WiIvPgogICA8L3N2Zz4KICA8L3NwYW4+CiAgV2hhdHNBcHAgQ2hhbm5lbAogIDxzcGFuIGNsYXNzPSJleHRlcm5hbC1pY29uIj7ihpc8L3NwYW4+CiA8L2E+CgogPGEgY2xhc3M9ImRldmVsb3Blci1saW5rIgogICAgaHJlZj0iaHR0cHM6Ly9jaGF0LndoYXRzYXBwLmNvbS9KMTJwcDFhUGlWZUZRVVl1V2gxWFBoP3M9Y2wmYW1wO3A9YSZhbXA7aWFtPTIiCiAgICB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub29wZW5lciBub3JlZmVycmVyIgogICAgYXJpYS1sYWJlbD0iSm9pbiBXaGF0c0FwcCBEZXZlbG9wZXIgR3JvdXAiPgogIDxzcGFuIGNsYXNzPSJkZXZlbG9wZXItaWNvbiB3aGF0c2FwcC1pY29uIj4KICAgPHN2ZyB2aWV3Qm94PSIwIDAgMjQgMjQiIGFyaWEtaGlkZGVuPSJ0cnVlIj4KICAgIDxwYXRoIGZpbGw9IndoaXRlIiBkPSJNMTYgMTFhNCA0IDAgMSAwLTMuOS00LjlBNSA1IDAgMCAxIDE2IDExWk04IDEyYTQgNCAwIDEgMCAwLTggNCA0IDAgMCAwIDAgOFptOCAxYy0xLjMgMC0yLjUuMy0zLjUuOUE1LjggNS44IDAgMCAxIDE0IDE4djJoOHYtMmMwLTIuOC0yLjctNS02LTVaTTggMTRjLTMuMyAwLTYgMS44LTYgNHYyaDEwdi0yYzAtMi4yLTEuNy00LTQtNFoiLz4KICAgPC9zdmc+CiAgPC9zcGFuPgogIDxzcGFuPldoYXRzQXBwIEdyb3VwPC9zcGFuPgogIDxzcGFuIGNsYXNzPSJleHRlcm5hbC1pY29uIj7ihpc8L3NwYW4+CiA8L2E+CgogPGRpdiBjbGFzcz0iZGV2ZWxvcGVyLWZvb3RlciI+CiAgPHNwYW4+SEFOWklIQU4gTU9CQSBTQ1JJUFQgTUFLRVI8L3NwYW4+CiAgPHNtYWxsPsKpIDIwMjYgSGFuWmloYW4gTW9kejwvc21hbGw+CiA8L2Rpdj4KCiA8ZGl2IGNsYXNzPSJzaWRlLXN0YXR1cyI+4pePIERFVkVMT1BFUiBQUk9GSUxFPC9kaXY+CjwvYXNpZGU+Cgo8bWFpbj4KeyUgd2l0aCBtZXNzYWdlcyA9IGdldF9mbGFzaGVkX21lc3NhZ2VzKCkgJX0KIHslIGZvciBtc2cgaW4gbWVzc2FnZXMgJX0KIDxkaXYgY2xhc3M9Im5vdGljZSI+e3ttc2d9fTwvZGl2PgogeyUgZW5kZm9yICV9CnslIGVuZHdpdGggJX0KCjxkaXYgY2xhc3M9InBhbmVsIiBpZD0idXBsb2FkLXBhbmVsIj4KPGgyPlVQTE9BRCBHQU1FIEFTU0VUPC9oMj4KPHAgY2xhc3M9Im11dGVkIj5QaWxpaCBnYW1lIHlhbmcgaW5naW4ga2FtdSBndW5ha2FuLjwvcD4KPGZvcm0gYWN0aW9uPSIvdXBsb2FkIiBtZXRob2Q9InBvc3QiIGVuY3R5cGU9Im11bHRpcGFydC9mb3JtLWRhdGEiPgo8bGFiZWw+R0FNRTwvbGFiZWw+CjxkaXYgY2xhc3M9ImdhbWUtcGlja2VyLWdyaWQiIHN0eWxlPSJkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOnJlcGVhdCgyLG1pbm1heCgwLDFmcikpO2dhcDoxMnB4O21hcmdpbjoxMnB4IDAgMTZweDt3aWR0aDoxMDAlO21pbi13aWR0aDowIj4KPGxhYmVsIHN0eWxlPSJkaXNwbGF5OmdyaWQ7Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjE4cHggbWlubWF4KDAsNjRweCkgbWlubWF4KDAsMWZyKTthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjhweDtwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDojMTExMzFjO2JvcmRlcjoxcHggc29saWQgIzM0Mzk0YTtib3JkZXItcmFkaXVzOjE0cHg7Y3Vyc29yOnBvaW50ZXI7bWluLWhlaWdodDo5MnB4O21pbi13aWR0aDowO3dpZHRoOjEwMCU7b3ZlcmZsb3c6aGlkZGVuO2JveC1zaXppbmc6Ym9yZGVyLWJveDt0cmFuc2l0aW9uOmJvcmRlci1jb2xvciAuMThzLGJhY2tncm91bmQgLjE4cyI+CjxpbnB1dCB0eXBlPSJyYWRpbyIgbmFtZT0iZ2FtZV9tb2RlIiB2YWx1ZT0iZnJlZWZpcmUiIGNoZWNrZWQgcmVxdWlyZWQgc3R5bGU9ImFjY2VudC1jb2xvcjojZmY1MTQ4O3dpZHRoOjE4cHg7aGVpZ2h0OjE4cHg7ZmxleC1zaHJpbms6MCI+CjxpbWcgc3JjPSJkYXRhOmltYWdlL3dlYnA7YmFzZTY0LFVrbEdSZ3hKQUFCWFJVSlFWbEE0SUFCSkFBQlEzd0NkQVNvQUFRQUJQa2tjaTBPaW9hRVhXcjcwS0FTRXNnQmpBU3FzZjBJL2UrYXpZbjgzL2J2OGYvMXZhQjJrOWhlWWIwaC80ZnUxK1hmL0c5WFA2NzlnbjlmLzJTOWQzMXdmdWg2ai8zRC9jSDNodis1K3pudlovdVhxSi8xSC9RLy8vc1lQUUkvZGIwNnYzYStIUCt2Lzg3OTB2YXQvOVBaMzZjN3hrL04rRHY0NzlJL2x2NzMrNVgrSitQWDhQeVorci8yWC9ROUJ2NVgrRGYzUCtIL2VYMjUvNlhpWCtaZnYvL2s5UXY4ai9vZitqL3dIN3ErOG45MzNpKzVmNi8vdy81LzJEdmRyN1AveHY4ditTdnFINnZYaVAyQXY2VC9YZit2eUlQc0hzRGYxai9SK3JGL2hmL0QvYmZtdjdyZjBiL1VmL0QvWGZBVi9PLzd2LzFQOFZ3d0xvOGpScC8vQ0c4UzZWYitEZjZNeXpCVFU1WU1xaGdWUUdjWXMvWmFlY1FpbThVNzVET01SNmZhbktyYnlJQ3NsU2IyZ1F6OFh5d3k1ZitLOUlmbjZMMzRyWTk2MlM0S2UzSkM3MCtJTzJvZGRWOVJoQ3JsSnVlRE41bVpxRVljWVF6QldwOGFPWDI3cGYrRCt2V05ZYUw4eTVSd3lidWYveU5tWUJoTVdVV1pGaTZidkdPSzRsbnRwc21FNnZCUTc4dU40Vm85YVI4K1JhQ0NDYitpZENNZHhrWk1KRU9mdGtyQ3kyS2RFTmdMMlNYYjk2cXdIMldzVVZsVlo4SHpEWVUrak1SalEyWktyTzFtUk14OS96bzBrZFN1bGlLZDZhaXdWY1FWNUFUcVBlVEJ5R0dia0NUakVqcmJ6Y1ZDUll2cklkeXFjd3FJL04ycXFScUJzMDAyVEVBRmYrbUpFS21OaW4ramJYTEl5WVVEWWM1WGNpNWFmU1dBa0x5WStObWpNVzkrT0gwOWNJZStES3d1VEVUdy90OXF4amhPZGVPSVNTYVFNenFXQ1dzY3lJendwOGNHSW1DZ29oYVhhVnpSTDJMYWZMaWZzZnh5blNhQjJac1lhNmlYUmJMUlJhTkVrSVhDZkhvSXhjZkFyM0NhN09FQm0xSDRCYmVYZWVkQk1rMzdKSkJ0cFd0WWQ2VmQyM1NrVmJtT1dObDFaWnY3VjIzMnAxQ01lMjZHbmZuZDVydzc5V042Tlo0Qk5ZZ3dvbitYZCtBM1FabkNQcE1ZcStDMjE2YklSVHJzTkhkM2ZUWGxjdXd4NlYvNFhPVWJMNWsyWm1mNUFnV05zVnRCTG9TSjBpVkhWVGh0V1crb2lMMmViWVFBWTBaSS82ZUo1WGFWci9NRFpudXliSFhJTDBEZjlpMHQwbjVFUGJJTm9iL2hsTTUyQzNmT3Vrdm9CcVhOL3dFT0JUQ3V5cXRaRnA5QlJNckg5cnVCTHQ3S3JlYVFwR0RGdTJLVGw1MkdUTUMvd1BkTTNUQU5QaUxONmx4SmFwZUNxOWJHOGJNYUs3Y1Q3c0p3MXpSZzU2VkRFbU01L3MrdkhldTJUNE93am1lNjM2T3Y3ZkRQM3lkRjlMTWRXdWxMOFN4Z0Y4dUxrcFFmM3ErN1V1UnFxWTcyUFJLTW5rYXVQa1lvRGVvMGZzMWdQSmdZUEdtN2xZam0ySXVOT1Ztc01ZcXJjSTRtNjBuS0tPbW5QaFhuRWYraDVvWTJ2R01HNmVvdFQ1N1BCaldoMWN1U1gzOC9HYkVkalIrZ05EWFZ6dmZVNHBRN0h0TnMvaUJQeWJwWkVVdWtQL3VLWWxrWk1qMTZjcmM2NmNteks0NlNRaFlma1FzMnFiMkp6emtYcHVBaGNUUzFsV3hVZHBSS1pTUlVUMVdGMUh4SU1zbUEwQVg0VnFXRGhGSFNRM3pFdjNCWVpMZ084NVZoMnhRM245ZVlmZlZ0TnZyaGNaQ2s3UkVkMDJ6bkNidWRKTloxTGlCUStoUVFMUkYvSTlQTVVlcUNzWVBDazNSWTBxL0lpSWM3WU8vWDg4UVJUM2VTOEtqOHNGaHErLzN6L014Q2gxOWRxQmFwS0VuVmoyYjJNL2JRakZwTnRSdEFvU0dUcXZqWjJrY09qN3pwWUg5ZTlOWlBxWFAxMEhGbzN0SU1LWmxLL2F5MzE1Q3p6QzBBTndwZ0RLVWd3UXM2b21aUXJja1JWSFlXSW5teHcwaGVzSWkvMmg4bEtpNDFJZi84SGdNMGZvT3lqZ2NjbVpMcWgydGE0S09MQXRpUGtkOVNPVjJ5ZnRBeWxHY2ZSajVDTmdzekdGMk53bmlXY3F3Mzh3VENhRDE1VnUxU3ZoOVRqZVJtVmp4OE1hTVRHUlYyWUEzQ1hCMmpQT3Fxc0VsRTVNdkZ5OFQzZFpTWjFWYVlvVmNMQXV1Rm9zNXEybytuVVlBTmR4cmJ2akVrd0NHUkhTRTJsMDZlQXVkOXFtVE94NDUrVDJTUWJEeWJabmQ4NVAybmxzL1p2VlFmQUxFM1JPZlVGM2VuZmp4L2RkbTRGWFZUWVdEaWRlODZya04vUGVoR1RTNkhFQ043R0pqYWIwVC9CMlkrOTR6RWJjOXh6eDlYS1lTMmtJUUwvcytpYUZSL0Y5b1hVNmlCdHFOQjZqUnRXSFdMQVZ4V2ZWM1FTRnQ1WG93RjNFc1gyRERTdjMvc1ZobGM3dzBpdHFQWFFydTlOSEo0ZzV4WCtoOHl5UGdpeFhGcWxVa3c3SCtuMmhSaHFseXhOeFFuN3l2dzNQcG1yZzNEN040QTBMZ2lIdE90elBMRWpCS0pYeG8vbEJJQ01kK21lbWdUMEVKL040cmYrMGJCbEJ3b2czbmtBYTVOY01OUkFuMXRqNlovczJyMHNHUDcwbDBRL29Yc1lqWXlqYzVRYVZQdEY5UEkzbTgyelRDWHllK2QzV3lxK0FNMTZIVlRRN1lzOTB5bTVuM1dBOElVK2ZNc0x0OXkreldhbFMrVyswcHpyK2t0am5Wd1FTR0I0Z2I1MW5zTHUxdVZhcUxmTHAzUWkvSEpRSWI1dklFWUNHcmZNWFd2L21KOGZwcnJDTXhoWGJrZVZaY1p2Tlc5OWU2Z2JXZVlBeEVSUEpDY2NSbllXZFl2Vmc2dFNjU25XcGp6Y1hZNEFFbDArZk9rSWFKQ1VzUUFBQVA3L1BWakhzSGxZNXJ0amZLd0hYd0c5N0luQzh2dldVbWFuRlE5TldKWnlMRnI0cU9hcjBCRVErUG9UR2xkVHpnNzY4Ukp3eFVJakJBcG1BUlM0VStBemxBYjNYbVU0VE8zc3pwTTRIVEZsUDAvbkpBOGJXTGkySitNZ3ppTDNXVkhpUkZrVnJwTlNnbjh5Mjc1UDBBeit1MTEwK2pCdVZycGE1bGFyZy9idjZ4ZE12SlZYdGdjd3BHcFg2UEFITHRiTG5GOEZzVkM0WDdrYzdnTERUMExUZ1Q5WEwvYzJ3TllnYlpMN2NrR0l1Y2FGYXg2OEFYNm5kUmtsWW5ZakVreVRyZUFmRGsvQmo2MVAzY2pDVmdOT1AzYml4UVhrZEk1SXg4a0FxR2FnaS9XbTNCb1VNY2tGZWRDWGcrWkFmVGR5bGo5MWU1eVczWW43QlRUVHhqV05jRXYrYTllYXl2WDJsdmt3SC9SN2ZPYUpCdUxBNS9KL0o0YUxvZ1l6NE05RDdGbVg3Uzh5TTlUUW4wdXZUZHpJQ2IzZVJwcXZoemUzSnlMVEh4M0N5bVlHNTdNelRZUG40Yy9ieHhwRmJXdXh5QlI3M3NycENHOHRWTTBDSlhyOHZoTFdCc2RJdnBpL2Z6OXRSM0NMV09XRzQ3N3ZCQlo1ejRkSFBzQndzNTlkZ1F4cmxQTWU4aEwrZ0dyK21sTGhVN3FNSUM0eFlLcStuZ3ZPeHkvWnNmamtrOUF1d2Vqc0hBMzdLY1VRRE5vU1pNQ3E2M1NVclNjdWt5dTQxczViL1RscWsvM2lBSENkRStVa3B5cUNDb1lpYUpwcUN3MGVveVAveE5qOUh5UVR0VWJvQmdUeHRVdmdrZXZINFVGOU1YcmlUcFBGOStxb0tIOEVEU1Z3MDBBU1NCaC9pTTJheFFMSTJsRlFMeWF4VGJrSHRUVHpraCtJQWt0THB0SWZzYTlnWERpTUZmUnBQNnZNM1VrejAxOFMxY2pwdUwwNnRSVndsK0s0Z0h0OVV1eU80ZmpIeFJORlgvNExtcER2WlFEN2k4T3JKNit2blJmYUJCY0JEVDFZb1BEc3o5alA5c210RTUyd2k2Y1hpc1dGM2o5ejhwQlBTKzVLSnovRkFTUGtJUDk0RFNMUUdNNFNEaVNJN1lGaHdFWXJlR3JrLzBCUmpoYWNhTXdWOSt1cEdMSGxBekdmQjlOYlhKNHZlMklKZW9RcW5aSVRwUTBIU08vRkN2SG9KRnoyTVRxMkJkKzJ5Q0tqSnQ3Q3R6Wklnb3NiN2pmSHdPWUszeTZGSksvWEZ4UXVSOGZrNGsvVmJsVVREZS9HNXRnZ1FmamJZTjlBMDdySnF3V2RVSGdBOGNFVGtDbDJ5QXBVOFY1OHhxMDVqbjhNSDZzU3pvZnZLMG4yTjVjYm96ZVpjbWxVbEZsTHFUK2txTWtINk5nSWRsMCswS1VZbUJnY2kxWWxIRkdaZ0RJclJEdFl4eVdDenBpSTRnSmdDMWt5eWJ6UG42RE1wMkdBUFIxdHdvSE9HaWRqLzJxOHZjN0Z5cStrdWRjaFlFaWxmYWVKZWQ5dDl0OTdVdkFQWWdNVGxpTEloOVZaQlIvTnVTOGYzd2RwcGVHRmtTZDZldTlPNG9VSCtoOGh0Zmg0RHk4SmJFRDFLc0U4bVZ5OTRyZ0JvZXh4NzA1OWRlc2hmam1qTWtLTUdHUlljQ2NVamNZTGhYbWsrMXBudkw5Ylh1NW1sRmVHT2pjNU1DTVl5OEc1TEk3clNKZEQ1Y25SM2ZlS0FEdXFscTVqbUxUUERRU1g5U0xwaTRBUHhkWXQxYkZlTjlYQ2NMZFl5alR2WlpGQjk4dUx4SkNuREcvcnBDSkVyTlBZS0xJOXBsRGx2OWI5Wk9LdEtrUzZ3SVRZWDFWbnhja0F5aytXZDV0a1VkVDVpL1YrUHRpUE40K0hDR3JkdmVhR09ma1dNUmVqcTQ5dGhuMVZBNEd6TlZDKy91WWhpbm5nRmZ4Y3NhZEE2c1FiY3F5dUlONUN4cS9PWmxFTU5CMHlDK1ViYzJzZUxSQzlETVNHazZYd2xzbmMyR29YbHdOek84N1k2SWEvV3lLd0VHMEZhcFh0bnNsZm0xdjNoZkRhLy9sRnF1TFQ3Wm1UZmxVL2NtMlE3YWFXY3ZvQUV1MEhiR2Evdmk0bnk1R2hoTFh4RGFqaXhaYzNESDlIMk1JM0IydCtST2xGNHIrM0U5T2owUXdRbE1sazY1V1dhbzRqRTcyL2h2NS83WjhaYzBFZXBQMS9DYUtuL3F5elk2MDJGc3Vnb3d0TThjc3Zxc3F5Y2cvWUxkbE82MEg5Q1NOZitqRFFoa3dmZ1p2Wko5elN3Qm01S015NHd1SVo4WXJFdE1IOFFDM1c0OGVkMnZFVFJ0azh3WHdNZzVYZm1ocFdSRFZscjhrOTB0MENzTS9vY1lSTkZZU2lqT0diSEsrK3FZeFM4dy8vM3dBYWtHZWlnVFJEOGM4UFEyeFptTHJudmdEcWdoQzFOSnBaRU9rRnE1L2pQcVJHTU5vdzNhcStKbUYyMGpTV2lXTW5xL3FUNTV3aTZwUnhZOUpYaWVDL3QxTTdVa2dXL1ArRTllLzZVS0VlK0FYbkZwVkVXMlZWQU40ZndWSzBJVnJTVEJYNmNkbnpGUllXUUgzUVN0RmFHNGNtdDNFL3h4cHdIcTY5VHlRVXdmZ09KQnBmbS9NSDdiY0Z4TEczN21aMWtuRkFvUFRGQTdwNWlHb2tydkY1QmxpTWl1SDZxWFFrdzJxbE5nbUkvMFJXQy8vYTFsS3k2cWd3SU8vWkdsKzlwVE45bzdTMlY0VTJlSDJYcUx4Rk1Bems4VEUza3BkU0J1UTlhaFJFajhtVEdSRnVxM1J5Wm5XWThtKzk1QzN0anF0RnEzeGp2RkZSSEIzZGgyZXhCMGlpSjJ1L2JsR082cUFOTm9ISmRpdHVjUUlkdWh5Sm5LcVY1TkJ0dVJIOHJDb0ljU2hodW9mRHpmaXd4SW15SGlFd2U4cTdvYUVZcVpYZG5Hem1IZGRsTmFRTktKOXJhY2dhSUx1NmJibWtNNDJEMXQ0cFhZKzdqTm1qaDhBRUpkK3VHSlptbXhJcW1vWE9GWnFsSVRhTkVqOEp2VmpNcFVONVBrNm1LMVlUVUhrR3Z5eFdzcVFGTzI5c3gzTThVOXh3L3UwRnhsc0xnWGFxUm9ENHUzRTRjcW81T1Rodng3ZlZ5dk5nY2NVUUt0WmlveFF0UjFEc3N3WER0VGJ2eW56T25qNzFTd2pMWE8xR2d1MnUycTIranhxRDRIYTNSQjg4WHp1MHMyd2V6N2k2UC9Mdk83bDV3a0kwdUo0aWIreTZUV0U3Z3paOUdMZitLeXNqV21pZ3gwSnp0UVhHSmwvUFBsalFoK0VVOFJGa0x1L1FOVmV2dDJhS3lBSmZDMGtLQXU1VmZiRVV5eFdBWGRUZDFDd2hweWk4SHYxV2hMazlKRGRzZVh5WjdyRGhObjcvMXovaFlLSDVEeGlvcnFoZXQ5anZscHZQVkRrK3ZWUFcwMTVzYXJUMmp5UUowbis0eENrVlZWeWNSbXRFMzMxdDFPSDcwN3VyT2U2NXR2a214Rm9PVzlXV2gxRzJIWEdvR2Z4d21HQWZJUHFKeHVFeW1JeUVsbi9PME1GekRsazdNKzBteWNMWVFCb2NaTnFBWFVCZjM2NU96cHpvYnlsQ2xGTDRocVEwOU5nd2JiTDdEUHJwSkpJcC91bXNDM2h0Y1BHNnlKNWNKVDhTUnMvb2NzOVhEc1pPNHZWV3kyM1Z0S0pvYkpYdHB2ZzBkTzZMUmRDTTRWRUpHNnFuckZhakx3Skk3MGYvOWxnTERnN0hWd3AxVmR3anROamkwaG9peW1xQ296VEpTTm56NkR5YmVTK29mbm9BWmgvTFJRQlZUNUxpbVBvSS9zaGNBSHo2NUQySFJiNnZjNS9QakRBVVBhVUczOTFPSm91Uk5XNXJvbDRWNStVUVJObWowMFVOT0lPSkNZdGhqdVdhN2lwRi9sWC9MM0R4cDdOM0NheEtYNDdKNTFuVU9CNFVlSHFzY0tZUHpTYnVGM084UmQwK2Roa3d6Z0xWQWp6dDdOSUlsb2xGcU9HT01xa2pTclhMT1pqY0lWYlpRbzFEaFZCcENCSnFuV0ZzeVdiS1NCb2RoR04zSVhpbHBUdS8rUEdrL0ZEYXNlV2IxaTV4Q1pCdjROR1Zrd0tCWE96TUlBWWNtMGZVNnlJZXZHMzFCRUtWcE1JMG4yTnN2UzNXTzV2Qzd5UHh1ek9FOHBIa0VDbENFT3Y5Q1MvTHBUeGtaWXc0WnBQMXE5Q21HTmpnTC8zTEhxaGRvQ3BpM29OMGMxdHI2VjBMV0hpYXNpMHFKRlA3UFE1dmg0VzhaQzJHcmZ1NmFHT0hWUlJ4Z01ZY2I0QnNDWVNGWTFKSnVLOXFCQnBDa0xjTEdzckowUjZ4MHRpS3J0QVNiMnVueUFMT0lsUW1Ic2N2bXMxSTJZdUVuVDFXbTBrZUk3cHVQcDNySmJucjc5NERrVkZOMzAxQ055Ly9PdkJ3azZvMW5vSjJ0WXF2cHVlODF3UDhKSU43bXg5S2lINWthVzlxZEpqMDNFeldtNnZpV3QrRm9YWDgzQzc0c0dqM1BRT3NkRXE3OWtpTXVPUHdoN0RyV0F0MS9UaEYzd3NJMEtKZnZXOEJFYXFFSm9WWjg3RHc4STA0K3MrdXhDZDF3cXg5bjFPZCtUMkN0Z3kxMXIyNzY0ZUVuT01ZeDVhV3hZTTk1cjhZVGs5WW5Temx2bW9ydUxKVlkwc1laeTBKdnpxcEhndTRySExOWlhWTlRYU2ZsV0gxMVJBZlkwTUx4aTJ0YnhLSHRTVEhPd3VmdjFmdzIyL1hJelQ1eFBBZ2VSQXNsdFQxTkNnSTlIVSswb1JZNzNnY01rV0VnSzdjNVllRVR5NXlhTlJXQlBnVmRsT05HdUxIcXpYWUgrRnVlTzJjYWZIM3FBL0FLdUl0ZGpSN0paemp4SjcxNXNKNFRrOExPRS9BTVNXL0oxSUtOcEoxOTgzNzg1U1FEbTVQS1F6RDRPNlFTTUo2a2JGUGM0ZHRTZHBqZkVhaVd5S0FhOFJpdm80b3Y4OEZQaFhWVmxKejZ2ZlRzUzZGbzRHZVl6Vjd1YmhTWUk0YTJhVkF3ZDBrdVV1UXljajVTTEEvNE1vclJMLzVPMHd3UXh6UndNYzdVdFYzRUtEeFZXbU9IZnZ4M01QVitOWllFVDlhLzBsKzNHV0tiWS83ZXI4V0tEc3BhRjk1ZmlyZDJBZzRHVFUzQ2ZrUVYrREdISitUYjlJeFdlYmlPM29pMlBNNGlReDdSQVQyc3Q3NTNyRUFYN1FnS2tuZk5iOFN5bDEvY29kN3RLTUE5RmZmbVUweVNyTHBmVWJ1QldZL3dTUFprUHlqY2lDb0VnSHZQYytrWFpxS3R1dlcyU0pKUGpXdmJJQ0hiYnBDSitMQ09yTmhVU3Z0YjdMeGovaEpOMThlcXQvdVFaOVdsQXkxbUU0MFMxeitIZUFqVkZZbjRoczQ1d2lIL1hrczc0VHRvSUtnb3FUM0k0NWx0akdmdjJxMDB0R29FbnBJcUhCNUdSOG1NVXRqMnh3S3EwdFk2dDNwUm12TTAvaGZ3NGt1dzFvR054U0hPVkwvcjJ0VGQ4YnF3L1l1N2x3VXpDYzU3UzByb2RXOUdVTUY1RHNFaDNXeHU5QUFrUGRiRkFmRDFzSzhtczEyRnFXVnd6enowRDRhdXpRSjV3MjFLU09IajFvb2FucWNPOTRwbE9oTUIxUVN5Rk1WdzUvYXg3aHNaQjR0QVJOTnZZV1pkSFp0Mis0Q1dndXUxdmt4UXp5bzJ6NnE0bE5kU2NPSkl6dTl5eUZGQmxqS2gwOWV2VTBJeWYxYk1qOGZFSzhEUWwzVHo5ek1OTGNiYWRVU2FFL2Vwd0xvaW51YVJvNHVCSUo0aFZ1MWg1cTVnSXM0WFFpV000RTNkanVITGF1SXVLekJsLzBydkNrWUZWeVc5WlRpd0JTekJseEdkQ3QvVzY5WEZya0RrM0lhUnlBVlVIRVg4YklTTTlpMU16U0F3cWNCYVpTMExWY2hob2h5eDEyTEhzYmpXdmdDbGs4V1BlRnoyeCt0aTZwdTRxcE9zQ0dmMFdIeUlwaXV1OEZKSmlBYjl5MzB0SnVEMC8xMkd6bEo1bjQxWGtnTkNzQmMwZ3AwMUpDTS9rSFc1YnJwSFl6d0JtQ0JhTWRUcXgyK05JR2Y1aVFYaEJnLzdqaFFCYkRxdUdxSlEzb0VZM2NYdkVuUmlOeTVRU0pIZEpPTVZQcnRoQnNhbUxDaExkVlVMb0VwcmR0bUh2WnpvV0svQ0RrZmhFQ2RYNUthMjBQRkQwNFpRUk45UnNQcEdUelNOQng5YUx3c09wbmk3WGdNRVJBYUUwakJXY0ViYlBkdUVTZFE3TTlDU2o5R1hiS05pcWhUaFo4SE9nUGpjSmZBVmxYQ3hNL2JLanZrTllwSUdCck5hWnkyN0JDNGRpRkRUaFpBNC93bUFqbWJDcXMvZ1pET3Q3eWZoSW5ZM043Zks3N2VoTllvU3RjOEI4aFJhQ250VWJVNGJwWitFWnRXVkxYOHIvaFU2OVZ1ZFVaL0NLODFjd01CNkVpSFBScnVRc0FERGQzU1pBY3NtZGpHNlBWNVdoK0wzZTNiUHpHVW0wclJSUlRRbW1aTUhQTkNweWswWmhtQ3hoVWxURzBOanNoVUFDUXNVbDVYS1JhMXdGdlJabHQ0V2lDUzE3dDE4M0d2d1F1bS9DMXNnV0VYSG9mbnZhV0VJcFU3TG9Yc3NuTUUwcXJ3TWt3UStnTWFYK25iMGVXK0RjSVpFS21wT1kzL2MxZDZoUE1CM0VWYVkvR2xwQjMvOGkzVEJwMksvVmRRMVRheEw2SmdVM2sxTkdBQXhGQVIvampsOTJZUjhVajF0Ry9CeGlYQk5QbWFDMjJTVHkrSk5xNkRjV3pLajJYTDFtdXpwY1BMMjlPNC9EKzRzWG9pSSt6eCtOTlBhcko1N1JjR2ZOUW5reFRzWTA4MWtybXhwc09pOFEzQVNNRmNxeEdhSnRZQmppK20zS2M5QngyMWdkR2wxY1h5TWFBaEZwM1Uwb0RjaXA3a0krWmZEZUtNVExpdG1NcG1jSUxVVGhOOEgyWGVhSjJON1JBd3IzUzFSNUhJSTdDRU1DUllDRlpVeE9PRUhGSTV3ZnNXYjc0Y293ZHBVR0wxdXNQOVlES3RYTzFwN29raGhLbXYxWVJINERjZzc1UGFQbkQyN0ZVTXpPRUMxMS9NUmRmejVRQ2IwczdSNkE5eXZHL0wxVHBncStSbkU3eUxyU3FNVjVid1VPbUNlMWZLUHhsdEpvOUVmUlBxS05aWUhublZZQjIwR29VdXBJNGdEemlTNXBQaWExWWZhWFplNCtSUGRWOFVId0pXSUZ1MVQreWhHMmV6eTZIS3d6dHIwNEhnaGZHcFg3bWkzQ2lMcTlrTE5FTTdOcTBEaWg0TDRGamVXeFZqZUJaL0NYODgrMWdLOG02MWFvZXRvVVltVjhodjhCOWFHdWhabzBIMEtrOFF3UjJNMkpqMDJadVVISThORCtwTGJVLzd6VmVjWEcwRHBBM0hObmdrZHc1RHlRSTdDVUs4Z1dlUHdNQUd0YWlLaFFrOUY2b1o0dW1QTkJRbnY3OEZ0cVZhRTdXMUhCdVJFZUgzRENHd2xwTjEveWtRL1VFbE9yTmd6S1VUaXlvZ2dtbDYvV1ArVHZXMTF6ZzNITDJueFNxK3JBV0wxZENSa3o1VllUbWRGSWM1bHZhcStJcHdnOEhZRVVkakxsYk9jdzZCRFRQcWVGZGloWWJLajJ6V3IvL0NuN2g3SG1QUWFTSkZRQ1VsYWpxK2pJR01yVFZ6RkdMME9UUEtkZWlhY3lzakNlOHR5QmF1eEFHV0NWTzh6OE5WcVo5TUxxY3YyR2RLZGErVkdDM0xzYmNQZW84MUM1ZFhuS3I4ZFZtd21uTmE2RFRPaXBLSGROQmIrNG1Jdm5MVnBYS1BleU92dzlNR2ZSdlVVeTEzS3NoemZMTS9UZXpuVitNa2k2UWhlcTc0aUt3QWZpY2RldXZONWtqWnU3V0FCalFhTHlzdmtwSTZaemRyN1ZkVElHUHZadVJCaHI3clpPTEhZdFVEUEpBYmkzRUpmelRSSDFXaVdhUWhIbjBvWHYxaVQrRDlwU1U5bnBpVWZLZjBXQmRCOWk0SkZwSWl2M1RzcTYrdXZySmlOeWV6NGI4NERhUk1uK0d3UTJkekh1UXhOMk1CdFNOLytEODhFaGt5R0FPa01ud0tId2R1clhLcXp4V3BGdWtWVkorbmZkOGZ1OS92ZkQ0aXlJamI4aUhRQnFDYmRVTk9veEttOTY5WFBTL281RGpjZlFoL1loU1QyUmdHMElUTmgwN1Q2YngxY3JBYW12aHlKNnJWRkJOT1BKN2w2L29wMTVnZmR5a1FKS3ZqUDRtcEo2QmV3amV1Q1kzOGhYTDcyVmxDT1hmNVh2R3AraDhNalB2aTlQVVk2aDBpTk5Ka2VuelNvTGpBWjFEQTR2UWRxdmFjd0lyQlUvT095dTRCNXEyeVRGK3RzUElYVWlNQ0g5QitmWHg1d0UyVEhscDkzWXFMSGMwMWNUWkttTVNRd2huSVJJMlZMN1RlUlIvMm9zcUNnZDRBMnFyYjBUNVk5WWVnK0J4STFXdzgwTE95aEUwdHd1ZjJneWVQYXlFUVQ5VTJlMlB6amlUeTlnaHpWWUVhNzdrR05uRWQyUEt1VHJ6NyszRVoxeUZwU0N4TFhwWDVMUlRseUUvTm92YklKMkh6NTZ6d05RVW41QmJJcnFRbDRraW9aOTdPYXNwUWRSdktWbnZYcHVucFMzdmNOZklsSlBNN2lsSGFUMExSVVhEWHpiR2JOU3VrRXh3b3lJT1J6VlRob3lHemFHUTcvVWVoRlRvNmZqd2NZN1FTMnR3K3kyMENST1ZWMFdOY0kvR2xjR2xGRnBTd1NSaTdhdHFoQ1Q3T1ZrQnhvekFvVlllYk5kV2VqRVlHVCtmd3cwQzFMSDJCSVJwRzZZbjZoelVlQjFnV255dGhidjRTOVY3U3A5aWIyYXUva2duTmFsQWx6K2NjM0NiS3NISWs2Q0dZN25JR2IxVjNuUlJhREM3dWs4eXlBSzAvV0ZEV2hhSndmL2hpVmpvWDJoR0g1UStzLytKVGI2dzE2SzN5QXYyU2Ntd2RSSWdHQ2YwZy9uM003cDRHL0QrTzhzaVUzWWc4K09xR3R0YWkvdVFHN1lHa2tGTEFwWnNINWhyc1JsNm1ycUQ1cVZzOWNJdDZYNTVWeGFFTlVjR0JRcERvNWJSVW1IVkVqVEdEbUdPTWIvQjMwZmJHZUJ2bFJmNnJrTUdncThoZW4wTVZHVUkxb25NS2xzZHpHWXlSZzZjZ1pZdjlFZnJQRHY5U1VwcHBPMFQzME9Ud2VnMEU0TklrcDZDdnh3NjRXNk50b25kMVp4eW1RamNNeXg1THlEU0RhS0xabG1LNW5QcEFrV0pGWG5hOE1wN3VMcXk4TTkybHdudHIxeFhXc3hwZnE0UUZnaHUzdFI1RzBnQ0NkK1hLbGdxMjNZN2RlUER6YkRhWGdMc3hDQ09qSDdXSmRiVmkxeUNBVDZpMjZRSG1mbFZxazhIWjI4VDhGeEQ2aWMzU21wcDd3TnQ5NDJJUDBtbDd2clR0NEpmL3JFL1EreDBnb1FIY3JjOGRvd1JxY040R1dzbWJseS93ZzNoWHhZc1ZIOFBBS3VwMXgrdWgxVWl0akJRY0JtZFFEcmI1MGcrdlNtUGk3WWZTbmhKWXd1eWI4MWZKV2lEZmdTLzFyb0J4WXBWeUFuRnpEL0U3U3Z5QzZFakR1ek9rV1Rad2lpam1LVFdlczVsNVRZKzgwbFY1bFZUQWVKV0JLa1V0cHZYMXNKOGdsUEt3emdsYXVWQU5wVnhCQnVuUE1HdGRZay9KL0M0OUQwTEVGanR5clJmM0Jwa3ZUd0FtVWtVTi83dmdTU3ltVUZtd1cyT1AveXQzMTU4Um9TdWVaME9JY0xmZnRyeFRidngwVE5aZHRQSVFPVU9rTVJUaHoxV1Rid1ZXdTl3V3NGb0hpNXMvNnoxRVdMY3Q1TnlvVE5tdVNHbFRmVzQ1WGduTGlGcGNqQmNMcXlneUt2c3VqVjNqUGdUWmF2WXdIOUtkLy91ODRkRFh3b3o3aFY3UUU4OTkwd29oaUJEbTdLaGNhZnpZVHZGWXNENnIrU0IwZGR3enJyOTRmODJtekV1UnRwVy9UaWNTQXJiUTZvSlozR0UyakdzRDV3aWtpaDJxS00zK0pwQVJtZkt6RWE5Y1V0UTdmS3llRHl4aStlLzhnVm4vQmwydURtVUMveSs5SjBjQWhRN01GNG45MGMyWFpHeHQ3Ujl4T1c5TFFHdjBOdm9iaXhUMGtFREhqL0FOL0lWd21OeHdVdXl1aGZESmdJei9saFVzVGZDQVlaU1podU80VHhtMjRLN2Y0N2FDcEYzNFJUWEc5c2NxRjJ3K0pYNkZ3YSsxSXdDVCthUGZhMm02Z3NLa2xVVm52c1VhZytGS2JTUGpsSmFWRitrN3ZiczJ6ZFZwbUVseSt4VjFaZ2UvRlpSbDZxYmlvQVdaL1ZJN0ZYMGxKYW96aHVuSVRRNVZDZ29Cb0RBdzZ4dzVGM1VYTHJWb3V0aWo1V3FwT2FQb2ZsREFTT0hUTVljcWZGWHUrNnpRcmNkQlV4UHFiTzBrMEluUEluU1ZaeU5aNktCdFl5VWpBOW9HZ2NXSHlzcHVpV0k0eUQvUTllaHVnRDJxUHpVZjEvMDFseVR0UkV1Tll1L3V4aGZUWFhhSW9COU9mTlltYkhkNnloNFI3d1RkVXQ4a1pQSFhManhUME9EM0huZkVieG1HOGx0ME9yYk5lUWNkVVB2SHp6UGxHMHpjdnhhbm5XTkYwOFVBajVpUUhkUDkwOGxFUjlQaXk0R0ZjOU5aVktFOEVROFJmbWhHWkJ1bXg2WXdmeXA0eTNydWtOMUVWUEV3bGwrR2txVlJvVWlxTm82YSt2SitFOStqMXNGaVN4L0lZMXdkQ2ZnVm1IOXQ4akhGRmtRS1JseGlrSkU1ZDJPR1Q4ci8rc2FVM3dYVmY4bTlhK1dxUGxkK3BUZGw5dUxTZzRWVGhaOVpUazNoMG5WTTlCaFVoODRFTEdyWXBpM2N3alZpRlNKWDhlYVg1QTNreXhYU3BabWRiNE95N1NuUlQxTUw4L3RqZ2R2Y2dvMEdxZjRXUXdnZVJRQ0lMMFpqZE54RlJHb3UrcjhWRzBaQUl5NEx6RmFmRUFZU29jU3FJbFNKbzZFV1dsWGZjSk0yWXNmelV4R0R0cEM5N21NK0FXWVptMGRQMkh5Y2tWS1hoS0IrU2xlWGlrVzZBSHA0enZtUkYweTJYMUxRM0svZHBEbjBBL1lGYit2T0lMQ2Zpb1RaRldzUTBCNko0ZGpWQ0lUbDkzRFI0dXBES01mdVFsaGpUcm5kWlozdWhYR0EvalFlSVFpZTU0UEV4YnBaRkl1dXJJcXZuMnhaNmlZcENZZTcyeGR6KzhhekN1ZWppSW9XTVorSHM0eExSVmxmT0s4VmhlZm9VS0VaOVhBai91eVJKT0ZDc05vWHcwMkUrem44N1lhWGxaQUtaK2RQa29hOXRuTDRIVUVlc1k0ZVhNV3Y0OVgzYVVHSVFiZ25nbUI4N1dZaGVpYWlIbUdqbDU3VWVnTytYT0pXLzVCV0NRalpXMTdjSmh0d2VyaHVkTkRuR2tHQjYvQUJLTkN2RGFwYngrWDFRL1BSTGNPRzk0dTkwRkZOdzNMQ2dqWkVKTFFCUVZ3QUd5TWJRa1drZUVXMndyNExZMEVRaGFsN2hXR2VybG9nMEVZOGlaNDRJZGlOVWNIRUVDemdzaDFDS2sxTmNhOUpQalN3bU81YTBnNTgrM1ZmS2F6L20wa1drNlUySW1zUEJxNVp4SHF2S2dra0JYb0REb1VVNVBvd2pVUTN6N28zUlovM3ZFdUZkVlZSUUM1ekQ2ZjFxTDZqanZFd2tlYmw2TWQ3MnRTcFgrNGR4VmN0WmRSYThRdFVQVWtHZVhCRzhCNEEzUWZFZ3hmWEY2bHYzcFExTWpKUk1WU2ZLZjJhenNpYVF2ZHhZWmVobXc4L0tXTkZZajJoZUk0TlNlVlExdnB1TW1CK1ovdEZidnc4dUVKS2V6QW1uVThZejlTb1lLZE1ITmFZemJFZmNkcWRiODVDUk9hZE5NOCsyeiswVHJEV2ZsT21PS0c1OStpNUw4OXFWbXBDaEVSTnhHK01CSDJCcXJFdHUzSDd3U09SeEVmSUpQU1hOTW8zdXdZSmFmQjAzSStHYlZ5alRkVmMwd2NMbmZWZm1vY3JIV1lvWDhJeWdpZzI2eHVkZllzd2l4bVl0MlBBMXdQeUduSWVXVlJaQnUvaER3eEpBbXVvYnZ3Tkk0Znh4eGJEa1FFbXFyK2ZSeHFhajJ4TkVPNFZaU2N5N0kwMmIxSG1UQ3plOE9LQlAyV003YzhLaU1iQ0xOTFJlbGlJM1h5dEd1SlhKM1Zzak5kMGpiZ2NzQUYyWDlQYTc4TlVhZjgxc2lqMnRFQ1ZpQkZSWlpVUlcvYlY3aVNLckpianJOZTNDWUhqMkMyN3QrMXhFQk9IRFNJSFhKM3pLakNzUnZWQ203a2ZGZUJhSmZ3TENKUlRuSTdaNEhhRnN1cW9PSWd1My9RQkJjT2ZjdlNkaU52cXhyd1JTellaSC8xT0FmZGxSMnZUQjBUaGM0ZXJEWjRuVjh5a2JaQlRKSXBCZUVKRnJLeERTZjQyZm1DQ1VvZjNvWmdrZVVMamZqNGVlNS8ySU84TTFYa1BmNDBPaUVpWWhkYzBzNWNzSTEvVVlpMzkzSm9mN3I2UWh1SU51MjEvWm5pWVNNcGNBbW54Vi9QUmRXT0xONnZleTd2cktaNmhNUGJMelNwWE1nT2NPcGxWMGFxOE9wYndVV1pvTHB1TEtqWFpzTUMvdVdzYmFqVEUvVG8veWI5VEJManZOWlZRYzNlbGt5Z0NhK1JrWHBRaHIzdGErOEY4S0xVMWVuT3dxZExDVkpwNXJXTVZMM2NjQ3JOTUVhR0w0ejhsUmtLeTQyM3liTWRjN2d1em14QkwvbXc3ZjdFUkVtcGRvaFRkMllLdlhLQjZYOEYxWis2Z21nQjBBNjBDbkN0N2wzN1pWYTMwNWVidCs1bGR3TWR5ZndkUFI5WGNFc0k2azdRK01rV0o4eU5WQ3B1RkZYT3RSN1F3RC8vYU4zZk56Ky95L2dGUEszZi91WmZ6Qk1PZzlpdGU5emk4WklhR0txanBYRzBvdGV5SVdUSVMyaUYyRjM4WE9nekZENWVkN2U0aGhwMlRhNEJpVWRnQjlVL0ZSSnU4REVRYndPVHNlQTNMWWdLYzB5OGNtY1phQk0rVHpuWEptNVpaZjMzbnovcnprTUFUTUFES2F4Qzg4ZDhjL3c1K1d1YS9TQUNsOEt5NUlwMCtvUGVrWTJOMmFaSVVkYTR1b3RRNFA4b0xtSGFnUktSRGZNQ2RLeklQYklwa2FiMFVXV2ZMODVmZWtiQmp5UmlNNC85QSs5WERpQk1mVkViSjZmV1NIZ2dhaFZ2NW1RTXllQ3ZyQlhoWEoyekkwM2w4RVA0eUtPSXd6SW5OSHQ2SVpqYi80YlBVM2EwblR2Z2VsRmRlY1V1d1JDQmRZeDFVOHU5OWhzbnd4cmpIRnJUbXhidFVaSmVFdnZNNmttdXZObE5QUHdOb25hYmZ4MWxCWHBhMFQ4UnU0dG82UTQxUzh6N2lmSFZlSEZ3bjgxa1Z6S2lTWGU2bFh4b01uTnM4WDNZODZFQlN4c2FWbnpOeFpJaWgzbDJ6TVJIdkJIMDNvaWJDaytBa0k1N0wwWGRsbW5IVU5PamhHQ0hjY0pTdFRhdW5qOWo4NExQbHpxY3V2THJybzAzbTJodTRiTmlCV2JuT0pqY0ppQUdaK2ExTnQvY21YNXpWT1Y5MzFFc0lUOEprRFVQSTJ3aVZRMnUrSXBJNHJBNXpxOXoyQmp6M3NEL0hsek4zak5VdDZTOVJadGNHNGVGdStONENJVkZER1RUOHdrd01SaCtiMFpUd3dXU1VzNnhhRDYrOEpqRkVoQ2RIKzBJQTk1czdDL1BDTGFVa3d1TUpBVTdWQ1FRTlVGdkNiOC9sWEc5NFI5c2lmRFRCMGk5QXNaY2k0VG81eXZVb2FrbFBkRWlDK0xQTkd1S2lIdWlCUXRscTVTc01QekZaNGpNZWRBUEx3M2drZWY5MlExNm4rQlpldjhnOEpWNThPZ29kNk9JM2tDUkRHTzAvaXpjTnFpWUgrV1ozdDN5RWl2QnpXWTgrZ1IrT045TER4bWo3eTNTcUN2dEJVMm5nSFRuaFhZNHpUTkR0ajN0ZHVtL0xVUXVtVnBQWXJhTkVsZDRabDVaQTViZ1pWeHN1VERkeGZYb3RXN1lzdFJrWjFZVm0vSm9ZVitWZzBRRE9tN0QzODNqNGVSejJEU3hYb1E3VkdBMkc1UDJncnhsNzJsdy9iNktFQjdSdWI5aDkzUDFROEdZVzdWT0NRcUkyZWdOR1lYQjdaUWVuWTkrVU5kMVN1MGNVUENDaGdRa3FtTXZOa3k1SGFiVUN4SDlyMVM2STNhaFRxQlhjTTBZT1Fhak03ZGc5eWczZ0hLdGQ2L0sxVDNGWHlqbzc3TXJGWFl0ZGhiZlBJQ2RROWZtaVF3SlVQbXRQQlJ1NlVJQThTUmxqZjdGSGZVbEFONURTRkJUSmJRSndLaVJCTUdKWjhzRUJnSmtZWWRBZWxjc1VKRFIyYlJqSUhMV0ViTHYwZ05zVGthTHRoaHkyZ0FESkhSaGpDS2FHYkk2QWVzalJDTS9zSjBlS1VEQ0c2N2F1d1JjcWRqcmxSZHVWdG80NzV6T21aVkcrYURva2xYRm1mQm5RQ1pBUnBDWUJMY1MyZDBqdjJDMzRKdVdwM2RJRjY5YUJNWnQwSnA0UnJBRUFXWmZJNVloMGNEazUyaDltVzVLRElQVGlBMk5zdXQ4ZXkyWGJKcTdzVEJTRUtoU3NIV0pQZzM1SnRwY202SkZWUXMzWm92S2d5YmpmM20vR1Q0ejVvOUNsNkNMMUxidWxjcGNDV2ZvekdKdEQ3WjgwUE5CUlEvWk1meU1YU2t6d0NWMUd1ZmdGVFd6azNGbGtoeUxGeFFSY3d0Rmt1QVFvbTVubWxOUU9vSkZhK3JSNTNaa1d1MVpnQ1AxNldIRFA1TnJicFc1RGRVTEpEY3BLekhIRkxSeHViekp4MG9uTEZRQ2hKbllCdzdkZGMyYkdGNlNiYTlUQlFlQUtlVnVJaXdsSEkyL0M1K1lVK0RwcWJ0NkJuWjZERXRKZHAvTmh3Tm1pandpL2VZRWl6a0YxVzJGbWlvS2xGQzFoekVpS1pUZnJJUmpoUDRLMFJhZ2VyeDZ6ek9QNzFUUi9NUHo4RWw0VzNvUWhhQWt6YitadHBMSEt2MHppY2F0OFlFRjRUbGFwRXNSa0VNUE9IRVZYaW16bEt5emdOak9mc3hmSVpkTEFxeWRWeUxMN1R4QTBzaktMbFgya3RSYnJlK1psUllpR0NxcXVrVmVvWnMzYWgzT3VIakM1UFROci9VZnUxc2x0WFpTWnZFL3FEY096RlRNNnA4SXNSUm1GRWhKVU00MXd5TEZIb3gwNmQxaXNNUmx5Y0l3TXlNU1FVMm5UcnRQQUx3ckpnZXJ3MkdQVWpZWXlPVzJjcGtkNWhGV2lQSDh1ZGMyT3k2YU9DTGlpeWJMMFo1S25aTWpuYnhicjVHMVF4U0VnVjZ1ckVUSnNLT09mODZHSDBVN1BETTgyQk14OGkwbWVhSXZJTWVBakxsTktXamRNQy9YbTRKUlNrRy9WT0VrazdWSUpLaVNEdkN5YlkyaDI3eWM3ZUZ1Mi9WNVlTYVlPZjVyb0xwaG9YdjQ3ZTNIUDZUZC9ZclZZc0hrYmdMMWFyMVhhTWxEVVFzTlpWdHZXNHIzWWtCZ05wTnIwRGp5WkxXR3ZXZ05HeU1FekhYUmhnRHBiR1hldTVnZTZRLzZsRG1IclNmUzB1bVFGbmRKdW5wTW9VUCtWVzRoRGdHcnBOblhXcGpYbDlBSDBHWjRwZDBPNVVDNXFYTjhVdXd5elBhcmNBcWdHeXBFM3VJMjk5VnowenNzZUx0Vm9CcXAyMldUOXJmWnFZZXZIUTJSeTBwQUZFQjJ2TFltZDVhbVZGb3FRMnQ1MXAyeTNQek1JMzBXdE1Pb1J3RVFUeEVSVExpRFhTbnlzRUd3Tmg5bnppcGgxSGlteUNhQ0RCUFZYTFNkUVZMSVA2YitaVi9UWGF0aHdRKzVEdGNkNk9nYnJUS0taRHBYU3hPd01pRDR5d3kyYkwwUnZFR0hWRld1MnpPMXNMNTRqcHgzeGVZbUNKNks1WDVEMFU5K3kyMkRLQy9hTzF4dlkwZEZ4MGxOMHNvUkZoV2cybnlqNmw0WmJZSW9lSDJwQ1BpZGw0dWYybW83RGF2c2hjOWFQNXIrUnJkMUpUUzJ4OHlZaWlobEgvelMwR0ZvejdIUVgzOEdIY2hHUXN3UktHbDlZYllhRzVOcTUxSEc2cGtVYitvM2Q3aTNhSGZBckd0UWNEbTJnSFRiTDAwL1d2eHZXNFRiSDF4NytubmlZV1lRc0l2ZWtYdExzSnhSdEgzZGxGV2pHL3JKcDlNcVU5Nks0ck1lNHlhY1RTRy9ZeEVhRU5LaUJnK0JVbmlqellaVjdsdVh3UHJWaGdhQTY5TG1qNHpmTjRZb1hxaFhRK1hIb2V4Q3ZnL2M3QjhlcTJZb2dMK01XeXBPRGVuVElpbmFNYUNhYkZLZ2xNd0tseG1lWGo5dkttZUovTnhhSkRiQW9lZmROMHpGS294TUwxOStZeFhqTnp4UXp5L20yMnlGei9pU2U3dnhIc2Q5M3hCRzJ4M2NQN3B0Uzl6UEI5REphekhRa3JpbHlXWVVjWVBtSm43NUx5MXJnMFNsVG1MeWV4OGkra2Q0VE1YZmVIdmVJZG10NFIrdzZkdmJTMG5nK2EvVzF3TTFRRHJBNFRQeDROUkpFY1R6RUl4bkFRSlNINmVLOEptaG40L3NyRnhydEt6TXVKblBiWm1YbitrSm8xaDV6dFc1TFRYYitIdEVrdzF6RWNMRkgvNFNZM3B5QUVXUmk1YVMvczh6OVYxcEgvcWI0c3dnUkQ5MFVlRVBtaTBNTWVIdGNZdzYzTVEyOEJFM21udVJRUzRkcml3aUkraWtlL1hVOG50djErbDY3TWVXcUxlWXFtWGp4YzY0ZWxQeFZEdFBuK3M4K05OU2hHM2FqNzZjSllzajZ6Mk5uQUNXOFpLbkZlTElROVF1SVYwdi9KdlNqcXdtVlE0UzFjR244R21vcm1KYStIUGZXOFJPdE80VThsL2FEZXNxNlJlUklXWFBzSndYaFk2RDMyemlabUk0QzA0REt3M2JWUmtRSndRc0xxR0FYS2FRZTBmaEVmci9jaElzekNMdHlXSU81Sk5hMGNGMG4veEZzN0JsYmI3dnRXK0IraEh1eW5WS25GS1ZOREtFa3A1UDNQcndIWUxmT29jNVhLMXZVaGFsdHRrZEk0RkhmeEdZV3ViMTJSRDU0eFBXL2U5NjlDS0ZzajRPNzdpbld4MXRDVUVRQ0NXcnM5VmxPTHpQR25kMlIwdnhDcExrNlI0VVJweXVGZ3NEN05oRFliVTJNUnh6c1NXWGRSUTNRQWVsc01mZ1hYS3VRRWRUM1VQSGFzaDlDd0JGei83cTc3b3NwQVJMTnBPdjg0VmdBNDNWaG5VZmhMenhIV29NdUJ2cGhWUmtEN0w0Wk5iTXRVYTVTcW4yQ3EwekxRMjdKdzZmWE5SWnN2OExqRStySjZscjBqVndNc29kZyt3d2JSNzNYNGtxZ2xEcHBVU3FEci8yYUJSKzVtcGtTaitpYzdiQkNueVRNQUNaYXljbEduVEpUb1pSMVluUjM5OTFXNVA3VWI2c1pQaXlOcG43SmtnL1BZOXphcTVWdG00K2p6ZkZYcWFqNXE2T1hxVVJlR1JmKzl0U3JRMGw4SEg4R3VtYTc1NllDZXFkcjlJNVNsNG1zVnd0ejlrRFpUTUtZcDdoTXNKMkx4eDY4YXJRYU9CTGNSdExneWVDbTU5WnBjUHZJNFVYWmRqUTJRcXpObEVTNXhGWUFZY3NuZWRvNmdWVVU1NER4WVdteG5IbThSaHVwTGVhT2h5OFA1MVlJc0lWa0pLVlp0bE8wcjNxRFhGU0IxTDVjZ3F6VTZaOUprcTZCRE1ZakIwNHlMbjdScjRZTHBlVDR4eHZPeGVHMUpIM3BvMDRKSzRKYkdmY01TTnkxbEg0SEN1OGJZb2FMZ1FIdEl2cUk1cDBtckVQeUZ4aXZ5Z3YvdEs2djY5blYrdEJxQ1BobkllTEt0bVIwaDY5MFdhd3YrUk16bGFydDA0TFNDUVR0d0ZFbFNNR2RHWjlaYU16TTZVa1pZZmxzQzBTYXF5YWJPakVrdmF1YXkxUHdaMFBNZUVOQ2lmUmc3ZHZRdVFNNGpETG1JMllmM3J1K3JsVnozUFhzdVpmTWdETUM1Zzl4bVRUQjM1dTNpVWRlNFVlRk9XZFVnWlZtTWU3TzdVcmExTDZmSzVWelZnc2hEZmJmRE80V25xQnFKbWdtSzNPd3EzMEJmdUljRittYXZMclJpTUc5eDMvYTRNV2xjblR0MXA3WFhRbHpidEtVZmZpOUdHd3V3WC9NSDBhNUlpMmFCeHU4SmY2MDIvZUtTcnRxK0pmZ0lmTnplbW9tQTVTVVMyUUpWM2FmdDVhZ0Mzd1ZsT2ZqTDBvbDAwd0llaUloa2M3ZmJQWVJhZ0dSZ0YzZml5ek1VclhhL1M4RGZ3cDlqVTBSc3RJak5uNzgycUV6dDI1SHdVenhiNFpaQUsyRWJMRXk5YUxucWJzam03ejh1SVZWSHo1aSswV08wTXllVG9EZnNCYXUyc1RrUFl3OFNRTE9qemZOM2JYbmljR3U4clJjUWMwelZMcEo1QkpPcFVBYytRanhNL1djbEhTYjFNcmxXalZxbWVMbjZJSHZac0RYR0ZKdXA5QmRhOTB4T01QVEhGWXZFOU50WXE0V0JaVUNDVzM0QlZGT21xcU1keFN6bmZ5SHZFTmtwWVE0VTdlYWZtdm4yVFNmNmFtVnRyK1lxT3ZsMVpoV1hkZ3hQUHJKZHpDYU9BREZkUHVxRHRLRkU0bGJFREp3aXV4eHZSaTdVamxCdUZLWG9JQjBpZW80OHo0YWhVQUZaNWxtS25VRjZEQXBuTy83R0ZOa2VIV0E0ZXkvUnFDZkk4Sm5hRzRnakM0MU5BNHpkdlpUTGwvcUxzaTl4QzhQZG9VWm1jWXkxSDBmSkg3NkZNZHVOZUhZMTZTUjNtdkRiTFZOekp1bkNmd3UrKzFyQ1BqM1hoZnNlUkF2a2p2YUtGZ2FTVlhMdlUraGdIei9NOGJDbjN2azZ2RGZOQUJ5R0FNUGZtMXBXdnJwWnFHZVZsaWlmVnFSZ0thQTN2U3dhSHphTDFYYXVZci9idjVQK2hQQXNGTUZCd3dWb1hjUjZkUEp0cnpNaFdKUVVyRWpmczdSRk1hVDlXS1FhOVNTQ1JRMHpzaTM5SlMyWm5rMDMzekhCRGp0V1hFZm4ramdEVS9HcXJqOXZSODRrZytzWmJLQ1NJS2lTR3ByMVplb3ppdlpRVjhKdEt1MnV2WG1uazBodzd6NzZWcDJOSFdkN2JUUThVNDVJc1o1SWZBZkZMSU9mMHJhd0lUa0E2Q280eUMyQ00rTnRCNUJ0UHZXOEp5ZEwwSjVYK0xSMk40bWZkcWp3QVFraFlwODRJaXMrQXNJY2hHVkpiTlhMQ3BNOVFaT1Y1NHdUWFNTOWhxVDFWc0RnaXV6TGx6QjlZU2FCcDlGd3VTNGx4S3U3NXJjYjBGU0JJak5idTMySDMyU1RwUnVqaG92RE9zYUxZYnFJR2t4dHNHNzJzL21EQ1BycGtPdnlQbGwyT0x0Ym5Fc2c0bjBieFJNWmFab0pYeHMrbkgzOGJPdDh4MjFqVGliUTlsRjJCdjFseUNKSUpvZ0IxQURIUlR5SVZOaWp1bWtmZ3F3K3dXY1NmTExJRis3SmRsWUtoYXgyZ2lyVXVWR1VoY2NpRFd6cXlVcGN5YjdVSlg3ZWZYTVVFcVJZcnVERk05SmZSdlhXb1VlcjJTNitURUJWV0t6VUI4cDIwWkQreTZiN1hkeGVPNGNhMy9VdzRGUmd1S0U5T2xDQzhGbWhmZWpUUWtlM1NUYTRDU0pLZWl6MGltdUhObVoxSFBqWldnNGxMNWJlRmJCdDFxd05BUEwzY1hYYmNBaVlrbW91YVlXaFBMOEtWeCsyUTB1b0Z0RW9qVy93M0swR0lmMG1rdUEvaWs2RWVDcHZBNmtSajBQRlFzdmowTUwwdVNTV0N6S0JHZ3Bpb0l0YUJHY0hhRzVzd3BqdllBdnVEb1NCS1dMT01Sbzh2a01CYm85bEFtR0l5NkRtUW9FMDdqQ2QramlZSkQvK3IzNXl6SGhsSlVvRlJ4YzRwNEcwQ3ZkK2V6dEJVczRaMktEKzlxK0hlWjg3SUxOcXBtSVN0NkdkbDNrZnYwNnRYWGtONXZVZ1hUaDRzUHJDOVM4NGpFaGhkZnhkTkI4dEF6ZGVBNzM3VGlhMXZGcnU0K0pmVTRCOE9PRFJUWUVCbG9yNkNUVk5mak9pWERBK2VIZGF6Q0EwQnl5VEpUaDZlako3RTRtRHVmK1A1ZW5LRTNtK2hBMEhGSjRWQmJ6YklINFhLSmUzQUFqSTBOeWZGMXczNWcwU0NqSThrODdYdXFyTTB1UXhuZklXb0J1MEM4dml5dk1RMEVIS2FQbklHZ1BJVWRiNld0S3VUdU1kN0FOUUI5Mk90ZTN0emE0R3FYQ1NKTzlFdHJuOGY5OHRGM20vcmx6Y1BaZ3J1SjIrd3FYMUx3YWdTWHJrUm00UjJReEt0TlovS3E0U1ZESjludHlYQVZBVGsrblBDSGZCTFY1VUtNMk1MTEhraDJHT3ZNTGI2TS9kVHNaUG5hQnNJdkFndHdsYkN5RFhNc1BRZjg1c0dkZ2FlNkpEV3RRS2FxWWJXdHdXWEtIN3d0MTI4MHNqTVZFV1JhZ0plTmdkcjNTTnRCem5yWmVwSUtKeFErTi8vd2k4dVZraHhRVUs5QmNiR0U2dWZzbmtvNldjcDA0bE5yZU5kTlBiUW1GSHBHVEZHZkZmN2pibE5kV29QaVd1VlluRzhKMENsejN0R3E3WUZ0aWFWNUx3ZWNzRHFqV0QwRng2aFRUKzg5REswbHQ0L3Z6cDZsM0poanV6R3dqQWZsMkE2QVdFTFgzWnZjck4rTnBUYTFhSkM0N2tlSDdYZG8rMFFLZk9vdDZHTE10TUlMczdGa3BCN1RqWDYwL2FjRXpFT01lU00raXFkTm0rNVVpVXl2L3A2cEVFdTdxckFpME16ejlQT3VxZzhCN255NFpYR2FtSGhDbFZIT1FFZTVKSnViR2xFUGhCQkZ3aDJpWGVVTnM2d2pLZ05GeEUzbWNPaThHUlpyd0JDNzVESWk0KzVHWjZOTFdYVlIreEhVV0RHQ0RSRWw4R3FlU0l3SC9POHR1T2tHZjdpdXBBK2gwTlVQekRHMXYrc2pScFV6T0EwMGU4dEhKYnJNRHdXYlpHSGdkZ2VQL3U3YnEzVitsczh3VGljeTNidTdTNEF0dDNZZzRhakZyakZYQlNMQlk2TzE5SlNQVGFRK01LUHBkRWlmU0NYSW0ra0ljdlRxY3lDM0JFTkRwN0ZhN05JQXYwbWtjNWdvQkFiODNsVXdtcUpMN2tUNnhtWHJtM21ZdkVWc20rd1plQXNiWk8zSjRDZmFIQXhRd1FNcUQxalJSc2N4UktQK0Jyd0RrU0V1eXFsNElUMVA4VmtEZXZoZVBHY21GR01UTlRjS2dRS21sQXp6UDNHalJkSUVnR0cwZ0h4UHhLK1VTMkd4R05RbFBmNXNrb0hZT2Mwd2JQYm8wa2wraHluUHdtNWdLekg5dWo0T2UyVWkxQVU1cW9LWUYvQ0RwMnpESGMxMVJmYnNBOCtudVI3YlcrMm1vVVlLTWUxTDZxaGNJNVFqVlBpRWpRaUFRSURScEZFNjJaWTVsaTF4TXk2SkNxeUpIdmNOKzQ0MzVLT05RZ1c1R01JUGZoTjE4aWFQZUhEenNwNnUvcjExQkM5Y0dBZW5sNFBYR2hjaDRDZFY1MEorSENaQ1JBL25PTjU5UGt4ZkxwczlnUTdqWUlmdXBtNjQwTUIreXY3bThtQzU2cGJGUUhLWjR5bktvUTRzamRkdzVOSlRzWVlVaDgzZXN5NVNGQXhTa2NJbVc0RUpsTndSQlFPYUkrWWhpR2dFTEVKL0gyYURJRFJwWjRpR3kyaXFjblJaSUF1Y0NpVUtTN1dCSUxqMUZDNUdKODg2SklTQ3ovTnVvVXNJY2pTc1VQQklBSGY1VHlFVDlCb2l0K09saE13dUwwSTlXbTdDYktCYVEvNVcyaTNPajBoS0ZySmNzVkVBbStrdWk2N3l0Nm1NRWlzN3ZmZWZnN3VJaklTMTVlajcyYVF1RndDZUs0dTM5RFV1MC92ZG9FNGZFdFJQTDk2WVVTOTczWThMOEVMUVBEalpocThDOEhEQStOVVNxUkszU0pRTi9wMXRyeWZ4b2hpbllxTTFFTHNjYUpzWEExeXJlUC9FSVIwNmtJcjRZTldVMThGTVVTWmc5WHpEQ0lJV3dkZ08wOThlMmVhQ0h4ZWhUelFiN3Q4ZXcraUNRY01OTEhYYTNiQmNkeHgwc2NVbklleEVsWmtSbmF0ZWdYQ0FuQzFYS3pFWlRJbTJzUklPNnRHTVc4V2Q2d3JQVThIaVZ3aDhZSGNOQUFWUFNOUG1lSDR5ZEIrUWNjL1VJcHdDMXdLc3B2K2NlN3NEY2NoSkFSb1FweFJ5c3RqNTlZWjBlVjFDV1VTRzM5NDhTdGtTV1BZNEZWckV2VW9WWk9MU2xHUG5CYkVRQlZoTE0wcmJYbHJwYnRJRXNKRHEyOVBWNkg3MUFuamhLRlRUUjhwaWh5MHIzWVBnNzN0TC9rVG5RRHpLUzlIaVRJcXcwWmxFQ1pKdUFEaE5JWGVtaTdYelEwVVFWdW0wREVvSDdzUlJFM2lSQ2g4NHNqb3BTcEFKUWcvRTcyQi94cndRdTFHOExNa04xTEVQZ3NUdzlCTjVxQlhlOXhKOUlxNmdubmpZR3o0K2RXOHluTHk5Y0NEdEtJRXY3T2VJU2xKVFZoWmM3eVdsZjg4eGJKK2R6dE1rMWF2dWtRZnVnWlh6TzVMWU84VW5wWUZ3VC85L3p0WUFYUGFibUJGS1h5Y1dyOW5LekJsVWhVdFNTb2ZucXNCbnpYeENYU2p3ZXozWi8xajZqMDdXYUtPTGFQRDRKMVVtTmlHUGZKWVpqKzBCMHpEbzl5OWJRdUlIb0VhVWRPVFBTcmtaTnFHRXcwZHE2enF0TExhbWV4dzdEZXRMNllFaDRNSEx0TFNveVRFTFlnaTJYM01KenROY1lSdG5PMkFyalZQeWdMaWptWFQvTnU2dkllSXJRTzN3N2tkeFY3T0d4NnBRY0U5cUhFbkw4ME1yclNyNmFtYS9aNHdmeVV6WDFvOUJSb3Z5QTBWdGtlZmpyLzRjTUlDSWdmNGNZVDZUNXNTYWJ4VzRqbGJYUVhrZUJRTitpVTkyb1pMcjBPMzJaM2xjWDVtT3d3WEpoazZHSVhBdTBYNmQ3MkpJbmpybnl0TW1SRjRGNzFhOStRdFNGMmlCeFZvb29lYytMbXkydkJjL21WM2dYTkNONlo3Ui8wTTlFNTJscnhINnFmOHh6anAySng2OFMva0REQ2RaZXlscEJwNWtwQzBCcndJNkozakhqMUJvVXZpSGRWVVJHcWhBK0hIbzJ0dFRqSmZJbE54WWhreEpRMU5QSGpsZnFFRk52d1o1V2RIUHNZVHdMUDV3bG4zSEY0RFZqaWZDTC9wWDV1eURDcWZnd1VnTTZWajVuUjFTVThIcm5ZNEYyanVHM0ovalBnNng0UUZ0QytlMHIrYjZrdGdDS3VySG5EZCtuN09rQTV0VmF0dVZYYUtPWVZXY0hRMFFmb2lzcWZaeGJTUWZ2STJLdFFjYjlMajJaZTJuNld6SGYxR3RWcUlQR09wU0VLMDlyVUhmUXpHWE1oeFZ4R0U4Yy9xYmFTS2wyKy84Q1hCYSsyVzNiTjRFandwUEF2ckZQTmxJVGtFdjJYTGZUME1UM0puOGx1QjhoRUVCZmNxY3VTSzdpN29sTlNuZzJIYmhqNXZoeVpIZ1ljdGp5Qm5hTjl6WFZEUzhiYmpJSVJrc3AzZjBOM0dPRzFqeldZK3E0ejgvS25GdEJBUitETndGeDFaSVZxa29JZS9taUFvTjA3RnFHWDZSU3hYdUFrSFdNelhjemZyV0lJeUFwMjM4dXZnV05NOXF6Q3IvWS9nL2Y4dXB5V2R4VjZVMFZ0cEtONVRHVXo3c3RyZ2JNOUdMTEZES3RMMG9kM1VaSVBaL1RlbmhoUTdoc0J2clc2NlZOOUtaczFuZEY3TEVHZW14UHJqVHM3SEFFVWtxMGdOVzJ4eXY3MXJZNEtVTEtrMW43cU9TWnRNQVhYR0U2Y2VUSVlUcUMraFR6ZCt2aWZMaHhScnJoUmErVkxCd0kzRjZvaE9NbTNOTDVaKzM2MUc4NDRuTEhBVGloMjlrSGhKdWJxMTZXM1FWT0NQbyttbERublVvR1o2dnZVU3lnU25iV3lzZGIxeGRma1ZSMzlidzFCRGlITEozZkRRRWxLYS9NVVlTL2QrTXlGZnp2NURVQmk5ZCtLN1RadXliTkVsc1JSRjR3T0grc3R2K21hVXpMak5pTWUvMVVUdk9FL3VpOElYaE9tMUwwbFdEK2FSNXRHZlFnWVhicW5KR0RRNjZwRVd3Y1dHMzB1VkVaMTFzd2NrS3R0REdlbGtEUDRmRWJ3MjFuYndxMURJV05PeEd5M3kvTHJmckFlU1N4YlVic1lRMnloNUg3d0gzZDl5M0RXZFJ4K0ozRlVTeGE3Mk5WdEU2dVZQcVF5WVhDK3JwdE5YMFNtZ3dwZHpyQ2Z0dllGZDJrTFVVYndxS21yY2F2NzJmUU9jMFg2bXIrNEJaNHpyUlRzY24vbGxkajJzc1BJWXk5T3NKRG0wR3R0SkRzMWRNQk5tSk9RdEpSalpqNVpUb05WcThNcER0a2RTVXRBdngzMG52ZTRqM3hWc0dsYW1IYkExbE5yUEhzTmZPdzM0NzFGbjhLcnhwV0xWTVRIRXBQbllMYVo1ZEdwZ2FmYk1Ta29VVWYvalJhSkljY3hERk90K0R6bVV2NmpaakpXSmc4S1FDT25EanZ0OGRpWG9ZdVVvVFQraE5abWFLRzhDYXoyZ3lWQnBZak4xYXdtdVg3RVp6UlVWUnI5dzliTEsvWkdONlRsWHoxWEFTc3hpWE5MVi9QcFlMa0JCaVdNL0pnRzk3ZmFlUWZkckFSOXltYW5PUDF6RHVPMlZGa1g4TnRKVENtc1dnZGxSZVA2S05QVlF3MENDdkQ5RHFnVW5lNy9ZNGIrU3M0MVFxaUFuU2NDc3ZTVlVKWGVEL3JIZzFVY2l4eFhNOG1mSnUvbG1lWVAzWk5WbjhaQzR3dTVOc05rTkZGdENVVXNCOWs4UExZRWVEZXlNSS9kQnpzUXVCTlJ6c1ZQSHFlck5VTW9IamZkdHZKcXhueVpMTkp4cTAzOFd0NHlzRTlndDBXZ3FUZGJ3b1cyYWRGeDRDeC9Tb0l6MFlmaS9uTXRzeHJGTlI2S1ppTlhFdEcwTzUvQnBVYW5sM3pDb2VZOXptVTBBajRsaitEdnhxc1ZHeEFFSjd6L2hMYUE3ejhsb3BURXdjTkNUQkd3a20zODNMMGpsZ28yeXErL0wxandkVy9RbFpVYkl4aitlNUd1TzZoellhQzc3UGpkY2pSNEFJaEZjU3RnQkhKelVvc3QzMlp0eTI2anpSdWMramkyNnRXSVN2WW5qUlkrY25zd1V5Rm1pRCsvMEk3NjMrUlQrS3NkdFZhdDNjWENDcjBXZEZ0czlCRXNQandxOWZFTjdsNEJ3aU1KWmJPeUY3ZUJoRW9NaWw2U2M5YitWTGprbjNEUGt3bFFEelB4eXkrUnNMZmQ4VTZzMS9aT3ZibHBWcmR3cXlzOGN6R3I4cTdvUzdnaXhCMkdlYldIOGNzV1IyMy9tTy9zT0lxbXAxTTZuU21XbEVkWlAwdlh2aU5ENlN3MmxDL0JzYjZzQnVOTVRDcTFXK0hQOWNYMjhjMmxBaG5uWW56R21aaE85dEFuVkpiTy9hZVg5NnlUS2pyL1pVZFExMzF6Wi9qK05SSmxETWdUWllCQ3IxbWErNUlxQjlxZTJITVpJZFRuazJTb3NZZ1Aycy9iRGtXaEd0cW9QbFZITWJKMjRlMnpaTDgxQjNZWkV4RlUyREkvMkdZNnN1Q2gwbURzRDB6VjBKRm1PSkFCU2wwZTloQ2lTVHdyL0FoR0FUVjVlbUdIckZReEkvbldGYWdSUnk2RlE3RElPcmhRbDdXUHNlQmdHYm1lbXBTOUlIcmIxQjBCZGpkNWFvbUtQcHQ4QzgrZVpoV0ZSa3ZlNFRZVlh6cFJBcjBrdFlnWStIZUw1STlHRWhKVWVSNkFzOW9iWnhoT21JYlJwOHZFR1FkeU5BMytJSEFKS3F3SnpUTkFuWnlDSFdCWnRRT0sveURDLzhlenorQkRSUUlJSWtONERNcjQ3RVVqekk1RjJMYWw1TXh3RENvYmtQUlpXWDNMSzNZb3NISWtVSGJ1UHhjVU9Gek9KbURWNkR2MEk5akZoOGJ4VE1pcjltcDJTRFRGUUJuTUNSbExXN3lLeWlDOERYcG16Rzc0STk2a1RZQXlNaDBDb2c3MFQ0Q3Ywa2g1S0FGNGxjVlgyRWtISHJiYThXWG1ZZG10WkdialN3cm51WDg4M0xSWVcvRUE3L1NhZ2xrekk2ZGtaZ3BRMHhYYitPaExyQnhKdEVERFU2TVVoY0REdEJRc3ZnZVNwa0NaUFVoL1djekhvWWxycWRiYlVSQXZyemVzUWFnL05yaVNqK2EvcGtEdTBReXRFdklndUtSaTAyUjcwQ3daS2ZoZXkyV1V1OERJZWt1SEZiME43OVhCcUgxNTRkVDA1TEkyWmNOS3d0WEZHUU9XRm5zcGpOcldRUnZhalZyN1VURFNQSEdNRkREVGhGR2Jjd3pxQUNkeDY5SXFub0p1WHZHYzZLRENWSzZyZmlKZFBWWnM1clB1ZWdUTWhLNnhVUVh6b1dZVElOZnNURTUrVzM1VFRRQlBUVzRSZXZYMUljUVU5VEFDNlROWW1EQlo4bS9oQlh2aUFsdlZaeHMvTythZk5wRHlKSFdoUFlqOHh2Vksrd2I0cHpQTTIrVXZubC9kTmFIQjA2TlRDRzRRSkh0UG8yejBWOWZMdXdtcStrcGdjWVU3NG81Wm1FNXArMHJja3hFaE9GNC83RFE0Ymd3d0tQRVlHMVppK3NXSGxXcU9XZ0NjYTkyZmZUb0w3aVAyNVRVRTExVUJFcjJTREVyVi9zY2ZqYUIyOFl1NWJmYVZWRzdwUnFUSXF3azRoQm9uU0pWOXBOTVdGTU45dkJUS05lNjE3Njh0UzNRQ1BROWwyeWpVWG9SMGVNNjhnS1NaNi9qUVNweUNINWRUMEZrNzFoaG1JKy92SXdjSC9FMEdkd2ROeUNuYlMwWDZ4NkRYQkY1ZUgvM2htemlmbTJ5cVppaTNZakl4TWcvU2F3SzdDczFRYTZhOEkvNGlpazNBZmI4SDVyMjNOM2dEQi84ai9iTW9taXlZUXY1TnpiTm1Qa090ZTIxcms0YUlWbnRGNFoxRzgrL2xvL2JQZFVsMjVkMlBWREJzSUV1b0ZydjY4VE5KbWd6c1ZwRjV1OGkzb0ZiRGtXZktqTmpLQjlZMTAyZTV0ZDM4ZDZDVkRDMW4vTytyVU9idEt1LzNWWWJ6TzBQTGhsejNsbzlWd1JyaDlvMDVPZGNVeWFpQXRwUmprd0NVb2FxaDNCMHZmNVk4WGo2aElCY3l3YW9wclYwdjU0dncvUGV5TC93RXhSVGJZWVZpTU84TDg0S1lTaTJKODdBVjV3QUxpQ25INFEyODM5YnJhQlZQMmkya3N1c21pdzByalVLbG5NNlVyVGxvUkoza3lwQjZUTlZJK2lXaERVMHNmYXZwNWlYWjhIVXVUalhzNmphejA5cWg2TnR6ekI3N25KcVhaY2N4MStSSHJmNExCRjFCVlBIV0wvSTl5WWNscENORy9PZSsxQ0F2R3ZpWHFQekUrV205eHpHMTRSYnk1cWVIa1JNSmVmbldMVWZKQTVNbHdodHZ3WDNOTjQ4YmVtcWpidXRuMXdIMFpBUkt4MHVtbTYwTEVWcnpJaXZoUmJHd1plcFlPUjhFa3hXbXNpanZ2Y3pHc3N3WisvOXNBQVN4RlF5SS9TbzBraC9LYzU3VnIyTkJiYVljc1cwYlY5MjA0MzQwSUcwYWcwOGJLY0h4Qm5nNUpsaWN0NU14dkJ3Rys5OXp1VjFJRUx5bmJEZDNET0VkZktUdGcrUkprcm05cURnVTVuSno5NDQvRXZQcEZVMTM5RVM3RWIySVMzTmE3QklIUlVRSjV3VFhjOFhBdlNodnkyTHA3dUlnNFludDNkNTF2V2oxbEd3WklmMkRIWjNNMUZYK012bkZvb2NjVzFDbnhrSzFDUnppZzFaME5KaFlnLzhoeEpPNWhzZWNGY0FnVmVheGFOMG1Wcjg1bFZDdnM1cTNMVUFyc3RGc1VhcFBEMjhUZko0aVpnTG5wVXU0RWo4M2VGaXZNWUFjcjhEN0VsdGM0Q0Y1eDNwYnF0TXpsdll3NmtSNFozVU1NZFFkVXEyYmlyM3B5bEVCWFhQOVJsNTNvZ2JlR0dXdE8vUnZoRDVzVWxkOWNsNmJjYlhtOVE3aTIzSTBZek5TTkViYzVEUUdOeTg3STQ5Tm4xZ2NRRTFkWnpNTHlYcVJqc05UbEhCLzdpbTFYRTZ4elpGeGtXanlmNEk3QkhWcWt1REtQcDFsdWIzTndlR2ZySXpkQ3lKcHNGTjFla2M5WHRWdTlLRHZNV3htTE91SGk4bjg4Q2tNbWdzVE15d09wdlRMdUVFQWJZNUhWeDVWd2dEUVpaVU5pMHZOZVdjUmEvWEpVb2dNS3hlb2I4UkRTSkxITE8xQmNWZ2wzbFpaUnlrZ2syUFpyZnhZb0xEdGlnVXR0WmNrcTRGbFJBTFc2cnFHODIvbDNLdlp3YmZNRUZYT0V4V2Q3ZEVyZFU0TXhZQzhwMm1CcGQ3MmxDb0s5aUJoQWxyOVBVSE1wVCs4SGgrTzFMYndpR1V1Nkx1K20vaVBzL3h1eFFMME9idUFkL0VVcjdWcnc0Z1JYbkdkRGVoM1VVYWNFYkNDYUpiRWhFZzgzL3dZallNbmdwM1JhMzdlWW0xVkwybVpHcjlNUEpNOHgrdXNkMSt1QUM5Nkw2T01yMjdTWW44THVVaEplQkNDRnVaSTVSV0NSQ2QzdHNNL2RxWC9NczdvVFk2WnhFMzcyNjVBZHAvbEJSZnU0QlNWTU91R0s4S1cvSmRWQ1pFS1lCK0x4d0FBQUFBIiBhbHQ9IkZyZWUgRmlyZSIgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiBzdHlsZT0id2lkdGg6NjRweDtoZWlnaHQ6NjRweDtvYmplY3QtZml0OmNvdmVyO2JvcmRlci1yYWRpdXM6MTNweDtmbGV4LXNocmluazowIj4KPHNwYW4gc3R5bGU9ImRpc3BsYXk6YmxvY2s7bWluLXdpZHRoOjA7bWF4LXdpZHRoOjEwMCU7Zm9udC13ZWlnaHQ6ODAwO2xldHRlci1zcGFjaW5nOi4zcHg7Zm9udC1zaXplOmNsYW1wKDEwcHgsMi43dncsMTRweCk7bGluZS1oZWlnaHQ6MS4yNTt3aGl0ZS1zcGFjZTpub3JtYWw7b3ZlcmZsb3ctd3JhcDphbnl3aGVyZSI+RlJFRSBGSVJFPC9zcGFuPgo8L2xhYmVsPgo8bGFiZWwgc3R5bGU9ImRpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6MThweCBtaW5tYXgoMCw2NHB4KSBtaW5tYXgoMCwxZnIpO2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O3BhZGRpbmc6MTBweDtiYWNrZ3JvdW5kOiMxMTEzMWM7Ym9yZGVyOjFweCBzb2xpZCAjMzQzOTRhO2JvcmRlci1yYWRpdXM6MTRweDtjdXJzb3I6cG9pbnRlcjttaW4taGVpZ2h0OjkycHg7bWluLXdpZHRoOjA7d2lkdGg6MTAwJTtvdmVyZmxvdzpoaWRkZW47Ym94LXNpemluZzpib3JkZXItYm94O3RyYW5zaXRpb246Ym9yZGVyLWNvbG9yIC4xOHMsYmFja2dyb3VuZCAuMThzIj4KPGlucHV0IHR5cGU9InJhZGlvIiBuYW1lPSJnYW1lX21vZGUiIHZhbHVlPSJtbGJiIiByZXF1aXJlZCBzdHlsZT0iYWNjZW50LWNvbG9yOiNmZjUxNDg7d2lkdGg6MThweDtoZWlnaHQ6MThweDtmbGV4LXNocmluazowIj4KPGltZyBzcmM9ImRhdGE6aW1hZ2Uvd2VicDtiYXNlNjQsVWtsR1JzZzlBQUJYUlVKUVZsQTRJTHc5QUFEdzBRQ2RBU29BQVFBQlBra2NqRVFpb2FFVytJZE1LQVNFc3dCY2k4QWpDL0Evd3ZvaTExKysvM1A5WGY0RDl3L21CMW85ZitXMzBYLzV2dkYrV2YvQy9adjNpZnAvL3Nmbi85Qi82cS85VCsvK3UzN0FQM1Q5VHY3U2Z0cDd0SHAwL3UvcVVmMjMvaDljNTZJM201Zis3MmdmM1IvY24yamYvL2hNWEdmOXo0Ty9qLzAzK3IvdmY3dC80NzQ5ZnpQSXYyRGFpL3pMOFYveHY4aDZUZjkzL08rVHY1ci9KZitMMUVmeVQrbmY3Nys4ZnU1eDQ5d2ZRbStBZnduL1QrNlQxVWRibklHL1gzL3djb0xRSi9YbnEwZjUvbUsvUVA5djdDdjg1L3ZuL2Jadit1UWVmOTdoMVordUg4RUpMMFlsTnZIN2hmSTF3WTA3VHFpTEdyTTNuSVA2OFJuVVJZZmhMeHcxTm9sV0J0WUx6RDZpTVRJZlBHUlRaVWliMjV6aXRsbW1nZGZwQUcvY0J0UjgzM1k0SFQxcndaR0xxanoxSjV0dWgzNFVhbkpZWFhpQUNyRUJEb2UvTExiVURhT1JaMFY2Q3o2QnkyVCs5c1UvbnNjcHJjNVVnbWx0S2FnUGM0bFBwTFh4NysrM1ZDcGZGV2ZrdFhFeUljTVFKSWhzY0ZCZ2l2YW1Id3paaVFaZTEzRDBZMEtveE5CZTlTZUlmQWtJZSszNDYwblBvRExLUk1iVGZubWRoNDNFL2VvRG5KaW45YTFybzFFMFpqeG1Kb2xVNExkRVUvSXpub05rMDI5Z04zVDIwZnowWWxmZGhGWDNOT0xkb0ZTWTYxenZzbkFjOHJFd2grQ2V0Mk5xZnFYNllITThPb2R0bkpOMFMzamdvTmZLOFRwNHdHaGtrWWMrcmRNT005dVhtOFY1SnlhRlh1ejFXa3d5dlJqUkNSbXBVYTFQOHlBMHB6T2x4dDcvVFJubmN1Y3hpVXpmbDBMVnF3bUd2L2FNbit3QnZqdm5ueXFxdmM4OTVpUnR0d2ZZZWM0RWJWMUMzazQzNk1pcDAxU0hhM1dlZUg3UDIyVWdseElNMHlRazdWVk9Ub1NYR1M0SEpzM3lOLzhPT3hmTnlnY29BUTdwbG1IekpnMnlyY0RYWDlMQjNnbDhrb3dOYzdCdkYwL1RZcE51MUdCQzgwRVZMaU1zYVF2TEVZbFIzVDAvNEJjOHhlNFJoMXhXWmtWZHNta00yUzNSUTUrWnNXLzZvNFJxUDMyQ1AwZ3d2NGF6OG5HUkRUcUVXWGxid28zRXUwQjNOZWY3VXNqdUxtcG1DWmtvd1dadWlxcnY4Y1dSMnMvUCs3cXJILzdRU0J3R2QvNFA0TXlXK0x4bnNwZmttZGluTXBENytNeTcybTExUnU2Myt0VFEvUXV0aHN0eC9tRWYvYUFNekYvNTFBV1JoR2gvK0FuN1hRbW1zNVV5TUNvU1k4S3h6dWx3bnYxWkp5Vjl0Vi9FTEQxbWxSS2hDLzJlUjZRMzNsazkzaGhkWE1JajJBUGprUC8vL1JuOHQ0ZXlUVWhCeWN0Uy9pbzUwMFhJWXdZNWNUbEFvdTRORmtxZzJNQ0JLa3hHK3JlbDNqZk95U2JsVCsrcy9US1hKbnZLSE9XUkNiU0M0QytoeEgrMXV0VzBDM2xUQnlIeUFmL2ZFYVFHUzgrSW9aTTZJQk5rdWVjSHdUSFVONFl1bTRQVGJkTU5kZmdWb3AzVHp5d0lWMEI3eTdNb1JaK1d2Rk5pU29obVNDQWtVSTBlSUJCR3pTcXJ5Zi8vNVVjL2hFOWxYaWFnM1pya2Y2RitqdjRNQXAwM2tLYjBCczhsYUllaFhRdzQrOEs2SjA3T213UzZrTHYvdG12UXJzcTNGNVBHSllxOERZR2JLL0wvNUliWWF5LzN6WHB6TzBGa2J4Lzg2UDM3dXBtc2t6YnN6UmpEaU01ME81R1JtOVBtTkFDaVNxR1V1S1Fxc1lUazBTajhoZHBaUHI3OXRyMEpEeld2T1lmT2Flb0xqNVhMeVB2dGpOam9HcGZFdW1Ic0RlOWE0cmJ0M2JCa2w3R3d2LzY3Q3pVU09xa2h4ZTRUME53SS95UTZDL2ZrK1Y2ZXVqZm1KS2IzZWpLbkV4c2dLNTJWNWJaUmFKaGJKYnJJMlNKWDYvWWxqNzhKV1J5Y2VQU01PNlhrK0hZM3o1OUdtaXRsN0dZZXB4T2E2RXkyRjBsTFFIazNienNDdS82VXMwUG1BbHI3a0EyNTJXclVwTEJNV3J6dUdoTjhaWTdNcDdNSlRDcFJoNEYyZjFlNmpqYmE5UFBNd1RiRlpvVU43T0VzUzRYb1RwU2xTSUdnbExubWpjYmZxelJMYnNMaDM2cE5wb2ZWalhaVGFyOGVjUlZrTlRoTGdvYUUwMUFwY1AzbHBHSHBTZDB2Z1p5MU5nL1l5S0JXRnp5VzJOeGVsN0JVRHlBeThlWEl1TzRYTWdlZ3JwcTMvRm1yWkMzL1BoMS8wb2pWMkFjT2t5QXMvUVdHRDEvdjNoMmNFT05UVlZRNWRiY0pHOGhhN09EQ1BsK2JQNVZjaTA0TFFLWGFTSFdyQkRNVnFERE0ydUVCZXFoZDBzOUlJell3S1NGd0s4aHRQbVpXcitpaG5YUGEwbktyalZXZnNGT3RtaUJBaDFWMlVyU0J1RU9xeWJTaHUrMklaeUkwZjJBRXY1c3M2S3VqVkozakpJcllzTkxTYlY4K0dsNThMMkVmVFNJd2xlWHVwK25nTE1xNGx1a1NmbWN2ek1KN1FRdEFPWDV6STN6ZDlFVnpkZ29jbGU3eTg2SE15bGpIU0oyQ2RaNWJIbGxMOFFmU3gyQWc5UmY1b2dSWDRQRlRhSUpFQ0RHandWYXAzRVdXc3lKMWtuZTc5MW1Uc3ZhVG53VENhSk9aYzhLdkJLM29mMlUvUHJxWjJHYWFtMFJYOGs5YTl3SDZBQUQrL3ZmdUVSaE5NUWZKUXZNTUcwUUJYbnllMDVUWHFQem9NZTFWbzhMbjdOanJnNHdieEZzT0laNGFQbEllUmg3eHpDL3RnMGtlcktmSyszRHI3bWxwUm02aHhPamJCMGc3ZnZPRUIzWWZoUk9wRnRVODJjUlQwM3FlYmQ0ZDV1emR4aHE2eDNXdmx6dk53RmMxMkxMWWtwT25yMGpocG5PeVJGK3RWcmZxbUpvRXFwbHVFclg5WDZ5UlJwQlhSSHBGNVg5em40UHBNNE9iNUUwaC9TRERvaWZEVW9MTjlDZlBPLzFUQkpqQS9Kc1BmR3UxVFZPYnVtTGViQ1dVMXZTWWR2YXpyTUpaQ2VqclpvYi9UQ0Y2V3kzVzJwRFFld0F5VkpKM2l2cW4ycmhObnkvM04zWXBQajFteStCT3lsZlg4MUo2dEw3QUQ3Zko0UGduSFRvVHloTEpGRnl2T2lHaTJZTVJVU2RjeUVXSFlsOFV1NVBPdDY4QXN1WlRhQWt4MGg1aFA3dTZFZ0VBV1IrOWx0M1NhNWxaeTIvczhDdk1iUktua0gxeVpnVVF6SlBiOUtDOGxQekcxR0tKelNpRTNLdWt0Zm1idEwrVm9lVTNTMStsR2FvOVpOVldsdVRiQVNwVzFoODZZelNzblhCZW0zMjExZExDbVYzWGl4V01OeGlTalZZejBDLzFFVmlrTSsxZXFMOUNFUit5cStpUHdCVkZpeTZHMTlsbVVpQ0ZTTEw5NnpLeTF5NWpPQlR2dWh3UXE4TDg5VTlTb3BiSjAwSmpMWktWRU5OV1FJc3NrRnBMWmtLemptdkIzendYZ1kwUGJmUXQyNnpKNnlkQkM2NTFIeWwrcS82R1hDbWh1N0IzSUQ3NEM5Zlg3Ti9sYWlueVgzbi8wdTJicHdjelN1dWNiZDF5N2RpVmVzRC9iVnNtK2xLU285M2N6NVJQRnpzM1ZOaE5NUTNnVmk4aWhyRWVMeVRCWnZ1K08weTNFR1VKL0JVZlRVWlRCVlVJdkxIMzBaLzFPbVYyMUFoQm9DSVFxd003by9jL2tzanh6REpHOFdyVFZHUzdmK1R6NVVmc2N2ci9pRTd4MTZuWU9oV3dZSmJXUGhuLzJJeHA2Yjd4TExmaGhwTm9jNzM3ZlhBaXk5NU4zMTFJZkkrR3diS1RNMkhrR0pKNXg1UGNwZnBUeGM3L2d2eG1sbmY5dTVKZlZyV05xNThDWUplOTB0dmdPdUxQS0xSNDYxNVlQdHV0R1JRbmtsTEVzU1dpeStoQ2NJUzd3c216WjZzNlRWS0N2Y1lpd2ZKVkRBQk9hbXpsY2cxVzdBSnFvZjVpcTB4N2ZZclp1VGJWeDdtWjE3bCtEU0NuZldzS3REYmhMT1EwNE8vQitxRXl1ZlA5MWVHVjlHa3BUcEpKUW5WM3VvSGFLT2FZTzBSSGxQeE43cDkvWGJFc0k1Yk1ZdzY4Y2UyOUMyK0hVR3VCZktYVjluMExKYUVoODh3YytFUXhNNTB5UmJaUlB4UndoV1U3VXBVNmdLdjR4enNGa0JIVnJuSm5FWGE4K0xUaTB3ZGp4cXZ2YmhlUWR0Z0dMQlk4emFWekoyZldXYlRNNzZNTXJDVFF3aVZiTnVtNWhUVnp5dm9mMjlXN0NBNGM5Y3hjVjh1QUpWUWxuQk9FdW81K1lJWEVNaGRsVDluekgyNGdzbURpRVY0YzNCV3JLdWZLWHh2aElmWnZ3Nk44MkZHVjVNUG1zeUFFOUFVa08xL3kwZFZmWnoraUVBbmxCUXdQNzBuWnJNZkRic3BKWnpheDA0L1E1Rm1XN29hektCdFEva1RrZEJybVVQdm44ZzB2U2tZYnFMcWNCYTJMa2Y3YVRpSTNwUWJJRktFcVMvNHErM2xGbUVEVmlPVjdGcDlwbW9kazZiVEhmRVNqSWRhNkozQjZNbUR5OWxDbEtLck9QNHRUQ01PT2FpQXJrRVpsaU53a0NDazFacWYzNUxCd01zQ1lPMjlOT3kvcTRSUFpjcnZkd1JvMzlTRTFTdHhpNHVHVVpNQ1F2MHZ4eWlOT2lwNzF4WVh5MW4xbjQrVVVOYllaWVBnQ0hHRUFNYTNTNUkwampwRm5VSzZZUm1CTEZYVWRPVGxvZ2FuemlBWXRRVkFib3VuWWhDb1NhMUprNUttdHVqRzlRRmVVSzRzYnE3VzRFOEw5VnZSTkpXQWlrWTkyZWlnNmR6MXpwcWsvU29pL3o5Tm56WFZRUFF1RlRKSXBnM1VvT00yRFpOOUxERWR3WVpCNlJtVm1RMGRzY1pkejdwYnJ6VC9UYm4xSUswNXFndDhER2JFYy8vMEJrbCtMTlBDbTBVbW5Oa2Vqbkk3UkxhUk8yand4YzVaVXNteXR3RHEyeHZuVzB6YnpIajBBVTYrbUtjU0wvU2RlRWpzS1NuQVBZcjQ2aC9TSjVNTU5WNGRqbUxMa2VmNnZtL2I3d3V1RGNUWTZDVXRYK3U4KzhIYXlvQVZxYkgxR0dWRURFWXRONUhwRXJjTGtvNGcvem5IenNBQ01pb2MzeUY4dGdDM2YzTlBZSFdUYndoVFJkL3FhYi9iL2ZhRUFTN1YrcEJXZ0tMQ3FKeWNZZGovYWhGb1ZFbmYyb1V2ODRNbmRteG1ZeGY3Sk9wVXM5UHdpTk5sZ21nRVRIRFhmOEdpZ29rYVdWR2VIdFJFRmFuNjBkV0FBZ1pjNHU4ZnBZOEthWnRIcTB0VGh2YlljaGU2dmQrbTlVSTM5UUF5WjQ5NXpPejJaYXloSm51K29lZ2dCT0VIZmQzZEVQMGhIMHRGUml4VzgvUWVqYkMzR05VSGJXMnlqamx4dXU4VDllaEZ3akJYdGpuRml3dnlZeVdER1lwaklNYjVlOW02UStLOEw1RnA4UEpwbU1sYjhaK0hISHNNdXJPWVBuM2VVRnlSUC9OazkxQWYzL0g0dDhnUlBLeWU3aTg5d2duc1pTTWZRazNuY0ZFa253ZmJjMW5JZ1JldnYyakIvbTViNEh1TnlxeHVmc21TeS9seU9MWXdMYS9qUzFKTDY5SzhUNFJXU3VEWHNMSTgrcEdUZWdyYTJTNS91TTNIeGtTT3NFV1NsQkFTa1RWUG03SHhWdndkRlFucFFXbUJsbVdLc3NSeE41VCs1Z3N0bHBMamxMTWhvWWF1RzFYR0o5M1paYmdZQnBKMVlSM2FtTHozRlduQmRmbExYVjd2TmEvZjIySlBxNlFnc0tldVhKVzE3VEoxMCtUL0N6OVVQdjdvc3JKNmpicG5lTnBJNWdXejlLamZzUXF5ZmhWQ1lZbHM1c290UStBdE9wMHowWlRoQVZLVjhUQ0lLZitkai9DclRhWFZWanJLaG1BaVpLbXcyY2hxVEVjVVg5QjJWTlFpTlpoOFQvdkhkSjM2dGNEQWJFUUsxOEp6a2dSa0RBejg3NC9ZMHE0STI1UVM5dmR2b0lTaG5oeFYzaW52NUNZR3kyVGQxZ3FSNHVSNlZya0hGTENWMkw4YzVDdk5FWFdJbUVTWjJmY1V3bG5YSVRmM3psellLYXRmK0pxZXR5VGxrajlNQ1YyTlFiUi9YbHFqMUpLMjN2amhyVzhDb3EwZWswa3QvOVZEOEdsdmJiNmhXdkJnUXFJWE1xbU5IcTMyc0o0clhOUlNlc1cxWmVZbWFvck9RcEJoUWp4dHlqL2VnODFYM0xKTW5NdTFpczFkNEF1UXVpVldZRjNnQWtuYVUwUEk4U0lTU0xUbHY1Mk9KVlpxdzg1bC82SE8xeGlKZ1BFVmd0aTRiV0VueXZVN1ZXZXZ1RUpoZW1nZUpIbFFheVNYMi9rOVRvNHpDWVVEMHpWMU1JZDNweHJZTGo3SzdEVWpjY0ZFM0tydW1VRFB1ZElFN1gvVlNJdi9pSEh0SXhWUXgzMGpNNG9wUXpFL1hsUXg2K2ZKdllpQk9kMEcxU0ZoSzlZTWtuSFBrc1cva2MrLy9vQmJjK0NmYjhZNkNWTWdVWXJhRW5uVFBxTGREWC9sYzFUeVJkMGJiVVd1bkRkYlBxODJBeTdheForbGxRbjBMMk8rcHFPejhoQWJLdlFwdHVkK2UvckJKWnR2NS85RlNaV2h5Z0lveFdVSlRvSWpnUnZqdGFoNFV3OGxnT2UxNzN3NGFiOW92Uk1QM2NhSE5ITzJoSTRHTjA0Y2hGZ1FnMW5zZzRPUXNYdGptTlRUUnNGTlBKQVMyS1poVGMzZGRUSlM0WWkxQnFSQU9vQnluU2lBNU5VTTdjSGdVK3lYd09rSCt3Q056M29GdDlRbkFXMkhCS3Bjb2VLbGlCWW5xdXFMenFmbjlRN2hreDZMeVNNM01uaUV2MkdpV3M2b3VsU2RoOXFQTDdHNHpUd1RudFpvRlR0RjVSUUY0SUJ6SHVqWUVPSkZXa3Rma05USjRUNEZuVC9mczBJcXJLWlFNYUkrREpQaEJPMER6bVd5cC9xTXV1OGJzdHF1WFdUaTRjUjBvVXJsMTlhUURKK293RFAzTjM0bGRqRWRRTTlZUlBmQkZIQXc5cWx5L2x5Qm5VclJxWUhnWFpTNzNjTDcrN3FsaTE4ZTJZOHNIVHYzNnBFRmF1ZTNVU1gycmhiWjdwdmk5ZEN1bmwvK2tQaUdlQzB5aWZSbE1QYzFLaWZwWUdFeW1rZm1kU1VqZmVmU0d4VmU4YjJyOStmb0trYVZuSjZuNlYxWWN0WFg4QnBpVjhYQitLS1ZoNVhZNzRNNWNHeFdOeEdpL0xHd2sxN1NGL2Q3TEo1c3YwLzgrdFpOWFdsWXFoR0FEa2d4NDkwcUs1K0ZEcWlZT0h0bmdMSzN0cmRQZnB2dG1VTzM3U2dtTG9WY0ZRV29PMm5yREh1KzJJcnlFRlAySUlIcTRwbEdXQXNJcFV5Y1BtckMvZDZFdW8rNE10bWlpTFptb0g5ZkZhVEI0emNzY3piVUhoZzIwdjZEK1lUR1MwYnZIWStZRWZtWjJtRVBFMUNtMnkybXJzczZHRUtoci9Sc3NxOThXU3UrTE5xQjVRMWNjOXY4eVRVWUFLck1iWHptR0xLRElBZElPMU10Q2hqWnVDWVFtLy9BQ2tqbHJqcDR0OHE3djQvdDhwTmkwU3BXaElUTzVnS1FMYzhybFZJSTZENDZMQklSbENRSVdTWnEwbUNqV0Izc01uYnlJcGVjQ3ZSbE14M0hlOW5hc3hYQ05MbUF4QkFlcUxSTG1wcTlua0FWRXNqSDBMMWpFM3Izay9QTnBKL3VGazJGb1ZMWjFVVUJDb2lic1NmZ0JPdmY5dVFodjVPUmVLc3dLZ3V1UmNnWk1WNTdPQ0pQWWM4VkVrM0R5N0NWVndlNE1zc2toMnZvWGNqUmVLUTR2Z2FLbHp6Mkh0WjNXZW5LaXlTc2JMWHZ1MWxOY1ZneVlwOWFXVzBFT1RRTXJGdHptZGgyR2I1S1NjalA5bXdCdHdVd0kzdkhQc3BwY0RXbEtIVHZocVM1Qm9SNm83bU05ZjM0QTRZSGlRM2tycjBTc3Z4b1JCckR4eVNabHVSNnR5WlhuWFYrdG5hUE9TN3ZIclhZUGtUcmpZTE9laHZmT3F6WnRnNGZNaFl6eUpXcVJ3K0lPTDVINWtEaG5MdW1yWDhhbVRkTVFKUmxDMDZkVzBzWXRrTitIYWEveEs3ZkFHSkI4eTJWRk9YWjdLVzBHNThEaTNSNlFQcU1hTVdBTy9wVFZwZjNzUXNPZ0dKTmtLV3hCUXYxQzRZY2NwUVVHWThmaEZqaVpNUG1yb2R2cDZaMExMNHRFbjdOK3FacXZxbSt1ZWwxN2dxNW8vekd4ZlFqcUFDWVEwcWE4eGRvMWRrZXlzanF2ZkNlL0NPWnpYWStxRzdpbnBuWUVoc0VTRlNsRllXQm12cmRENnhCWjkwZDlENWZvbEhTTVVFM2Y1V2p5djcvNFhlQjhQOWExS0hDYjQyS2tLVGtHWmd1bXAvSEdzVFFVWDJxQzFaWm1rVFB2M2pNYjFqUkR1eSsrcXdPNFRZekZKRTB4bXQ4TldmRFpRaEYxRm1KOTZTeTk2SUo3NUZKTjVIajVDa09WRTdjQzFSeml5M0FPY3g1Szh0cEsra2dFc1NTVGE5d3JpKzVjKzhqemw3V1ZRczJleXQ0Ylp0a3N5bXMxMXJvelFiWEpSME10UjNyZE9tSEl1c1EvSS9WcUR4RTN0M2g1Zkh5d0taVHpXNzRGaldLemdzY0JvSmx6blptR2JDOHZEd1hpa2dDYksyL3dsaWN1bWhBMUxMMWIybzZqcGZlMjBNS05SUnZ3T3pNL1BsVkdFR0NjbGNoRmtrdXJsaG50R2pkWXNqRDJlMkpmQkZQK2h0YkIxeUdyL3Bka3lHY0pBMUFBRTd0MjU5eWlvVmUxTzJmL0pKNUNpT0lDSHZmWWFobGp0a0xpK3VWYnlSckNJcEFMY3RWaVg0YXl0eUZ3ZjVzQ2g3NS9DWlNBMzVHTmxzZjgvYXVHR25weVA0bnkxYnZhZlAwa3pkZm0yZmFSVUx1bTVUcU0rUkhoMmVTRDI5VnVqS0ZuSGJOemhUTTVoUU9WM0I3bW5yd2hYN254MTRGVHM4VkNzdWNJUElGUS9udFdlVHNoUEtpWVdIaWNtcS80cEJkWWVNdWFsWVF6V0NjWlpYMnZmMlNraHpjZFVMcGdOczVvaU9hSWdnZE1vbHZRK3BhR0FoSDh4NU1sTUlVUkJVLzBLMkZIcllXZDNaVGJaRVU1NEo5TjJlaHBMcEZUZnhCQVpuNkVWWmhXdGxVS1RzWmd3bXNiNHJaY3JMY01VN2pPbEp0UXQ2Z21aSVFqUFlqaUFOdWQ5TU5jTkswdFZkUnVLZ0s1NG9vVkdzbm5uNHFLWW1GOHRtT003NmxDVWczOTEzRFkvOXpNc3VlYkdnc3AweXpkU0RKanZzWktSL2dYaUZGVlkwMkxncENBanZHbDAzOVh2SktqV3hURVplaWg0aVIybkZiWkMvRXlwOGZGN0NVbFgrVkdaekRPdDd5YSt2MFFmOVlnYWloRUp5Q0s0bkhzMUFub1Y5MmoyeWRLMFErazVvUXhqMFlNb0RueHNGYlgvRk1OS2M1SlFaUGl6bVdZRm1manZGK1JHdWs1UlJka1NSZy92UmRaODBoVHBjbUpzMzdhMHk3QTdRUzQ3RW40cGhxTTRuelF5MERUbHBvV0Vnb1NIWVg1ZDVuRVBPaDB1Q2VDbktxaUJ4VTRQQkRONGNPdEErRm55TVhuclhhdC9DbHZRUEJTSVJnazVXcGhvdU1qenlnOHordGp6Y2MzejRXQTIzam9xL0pZaDJ2SlNxVDRKYldLLzh4eGZZcnlkdEZZQmdFMFNKb2RFMkFjeUIyRTRZSm1QSkliZWZHS3gxUDJXY3FZS2x5cFhkT2hiM05TSmcrUzlsU2tEVWF4c3FSc3pHZnZKWkRKWC9mUjFwdlZLMXZSR29uWnd3VkNqd1FpdnlMMERhNnBRR3pEakxPMW1lcFF4TWJUVHRWck82Y2hoSmlCZGhXdU0wMERSZnlHK1crVmd2aDZCbWhjMUZzdnFwdmVYOWVqNStxa1NYTU13S0tBOHNTMkF4YUxicEtRTXhPcldNekUvV0orQ2ZORHViWjQ3ejFIWGt1YWpEcXVobi9MV2VKWGQzSjlJdzdrUmlENGRkYWlWaTRJbnBvQzZhYUs4TndmZ0YyRGFPMmkrRElRcmpsWjZXak4zbUpzVlBxbUJwWkpQNUY0WnFNWUxFdWNHVmpXekt2dUt5NHRvVSt4WitUbUVlaGJwenIyVktmMHhYb2k0Tm94VC8xeTB5OUlKRlY2cmpqNmpXWmNsVFl6Y2JQOFBnVXA5czFQUHdRdEwyWkU5bkRQZ0MwWGxlTVRnUy9ydWJuRWo1K3E4RDF1K2JUdGNhMjhreXMzL3FiemN2VEJ2RVlMRFhjdCtJa04vWXpaWlJLdjJBUzVyakJpWXM2K2g5dGxJamxKeWpRMXNmVDgxdXpxUnc5a1RUemcvUVYrOFhkYWtWMjlQZkhmRyt4dDRKeW5IYnU3amczTTFTM05IYjU1Ylh6azc4VFRmODNPMlhDcXBLN2hYbExzOXJIUXNjRFA3MVhRRktsOEVlYTNWSHZoOUtBVFQ3cnRkTjFHMjBIVFVpQmpjVGRLUFIwai9BQmxPOEVTMW9tV0M5QXF2Yi83dUhBQTMvNEV5TWFXY0lWK3hxTkliNFhDaEF2UmNlR3BreXZDYUtzbVhLLzZ3WGFsSmIrdHBhVjZxajFzN1dCU1M5YWpVNGZ2NUkvaFMxeTFqUlVEVlR4TXlocGhraFR0bVRSZjFpRXRyNHZOTWdyTjNsbmlRM0U1ZEVXRVNia3IzUDNXL043c0hrc1NOWklYcmJBM3V2ZCtiRUlmUkk1VEVmMEZUWGhSVnJpNm44cjYwK1VNWEtYbzl0UitJMGtJT3RzUzlzdWxpZDdjUERsU0NKL0ZmYUVxcHZZcmdwUkp6WnhFakNYRUFJZklUZC9iZi9JVytUM1JHMTc4bEd4cFJBRXU3U2RhNTN0MzgrczdLRDkwalpiaVUrWitzRE15TXlJVmxBd1N0NEZQOUQ4MlJHT1JRSnE2anArVWlSL0g4dEYvRmJOUFBGSHhUaDQySk11OW43TTVucHVCUW56cnpPRnF2VHpXejdwclVBUTA1NDJkdzFyeUphVjErbzh4SGJPWmV5TkhZOU82Vk9BZnF1Mytxc2cxRHl1ZE1zMkJxSWF3TnZnSnNOM1JZcVNIMnV2TzdKMEV5U2R6cnBCRlNFNjlBYUpUeFN2VEVXaCtaUlNJVTFxWmhheDhuc1FDbHNLaCs0VlAzYVpWSlFqNDFhOEhxUk90N3pPZE42aXlsVEVlSnhRNGtxVGtmbnBraURGYVorZVZwTC9lSmVIek9QNDBqRGFiZ1BIcjA2QlNqd29wazI2NXdZNy9jU1pBNkYvNVZEMjdudWNaUGtvTnZzeFhVNVhLNVhKYy9sS0hGZllyQThFbXY3WjgxZHpwMExiY0tqU290MXMyTWZrVzErSzBHTm82UzNZeVhLVUV3VlkrY255NUQyVGpCdGtNeTZFNlI2OWNrdjhqNE1pamgrQ3gwUzI2SnJ6L2UyL0V0aWdON1NUK01YMFFGZXRmZmY3d2VKeTEvZzlLMUJHQVhvMkl3VHBmSlY1dlR4SExyc0taVmt3ZVRqeW1QUzFpRDFsU1NDM2x3eTZBVFJrVnJqQ25YUExyR0wxcnRTRmg3dm1keGJzcG5HOGJ4QTNtUXhMRk9WWTNMQXY3cVRHbENYY1ZiNXViUmM4TzBURTdDNHJ2eXo3YjhoUW10R1FldURDdEI0WDJYcTliM2YrZ1ZETG9UY2I3V1E3V243U3U5UlZkU2JYb1h2YTAyYVR3a0tZMGZOUEwxMHI2SmxxMHlRa1dqQXNXRE1UdlZrR2FTTEdMSGZuWkllSDNDc2oyMXNzUElyTmdPN09JeDMwbkRpUFJlbkk0bmQ2c0JFYVJQUmFlZFN6M1JvZ3JkckhqSzdPZDBXK3VzUTV1Y0xJeklaZUIvS0FuazliTDhIYjI1RWV0UzlXRGh3R1l2YWhpT25FVy9DekU0L2x4WlhGb0FEZ0dQeHVSaVNvSzh5ZTNObUgrUEJNc3NHdExRVUxOazlhbjJaMEtpTDVmd0xTNnJmRFk3b1JRTEZMdmxkL2ppd29yOVNxWjVIY09mTmhPTnltZmNoL2g0UUllS3ZCMWMzWlZob2o4bDlvTU10bWgvZEVPczY1TXFBRkJkT2xxdXp0MTlpMFllYytmcWxOYTlwNlp0ZzNJUGhwZDgxL0grc0tlbHZkb0JlN2tXbXA5RFZXSy9HYkh0ZzQ0REJKT2NqblpVTC9HalpXd0E5bmY4U1JhdWVxUUtCTlRzWEFVbTM4WXFYWHMxRk1VV3ZHMFZpUDhpdTVJU01kVms3TjVzWTJTQ0FtMTRYT3hnUVd0ZEdrbG1CdG5VdnVjalpUQkJXWm5qUE9jalNyaTE4Y0Vzd2Y2RkRDWDJoNHB5QXJxQVVPbVZWZzVLVDRLd0wzRHExS2wxUUpiWExBK0dpMmp3aFk0TmxDK254dmhSaU5OcE9Nd3NENXM5eiswTlFBOFdpRWJybXh6YS9Mb2lFNXlzSmVaQ20vU08vSGNtV243ZzhhdjlONXd3cis2MFBoTU5mdWkwTTF6TUhXRE12dzZGSy9nMDhtUUlsck1MbElKY0crQmFNV3BVTzcreG1UeWd2M21BTGZBU2NHbUNRendyc3dtM05aWmR3Tk1DSUI2ditQKy9FQ0lkb0pxMnZmK2czdlZuanhrbkIzUStkcGFSTjJwMUNQMmg3QkFBU1d3ekRFWkpvM3RxRDFjdXUxa0svNXlXTmNkZ3RGQVpYcEI2N2hGR3pqd0pNc0FFMzlkU0ZKU1hmYTZ2c2VsWFI0S0F2S2c2Si9oTExQZzBoMWUzalBVVFBuR1Z4YkdLL1lZS1ZjRmFtanp5U01mWjYrVWpEMmdkSmIrSVlVTVIwRGVQSzAvNG9FUnZ4STkyU2FSbmRuWnRoNEhiRDJ0Q2JNYnBVQlZGeW5LR1E0UVdDWTJETjJoRGhSRG9LTGFKVS9uOWJvRUxwNGZSenE2aXpnYXEwajRIRVlBa0J4V1hFUkRuUlRVSDM0TDE0MDZaU0JuZHFra0crdmgyMk1WRm1NNXFnbmdaVUY3YkVzSnduUk1rTkN5NUVLVjhKZ09BMmhlRkZtc3YybXdrcFpTTFJkRjdUZi93WFMzM0RFS1hpS2VnSUFjWUhSTWlXRXdQSjQyL2FrM0RKRm1VTWZpUDlkZWZhTUlualRDUGlPZUwzMlVOdEw1c2p5aW9uaEN6dEYxNVpweG5jL21HRE9XWUtHOFhjN29yT20wbHU2Vkp6WTFaOFYxWGVrL25DaVRyVUI0Q05aN2NyQmIzU2xCbjZ2SWV1VnJFOW9vMVlsV1lUdXhKUm4rd0NKWHJIcE51UUcyRHZ6dXRrRWhXcVpjNmVZU005MjJ5WlltZ0hDVVdXOTdDcktvZDJ5MVczT3I5NkN5eEJnOWhYaGZDRmZuSDlYVWNNSllZQkpLaTBOTXllTllpL1RyTU9qbURydzYzRVJHQ1dXbGswZW05RXlCc1YxeWh5UngySDh3TzdpakE3cHBNelJST0RMRU9tTUZ5eGdUV2ZGNTdWRnNMWGJjQjlWaGVudS9yRUpMNysvci9IenFrVVRsVzkwZWUxNEVGU0doK3RjcGZmeEd3K00xTnlzUS95U1dhVTlxQllhVlNoTHljM2dVSXJ6U3cxOGgxTXo4dEwvSzR1cDdaMVpqZ1l0cE0yYzVQQ0lCQzEyZ01JNG03K3M3N3g5WTN4R1krNTNGeTNKWkZGVitqMlhaTlNLRlVySmxHMWtaMzZCMWxaOVpZcWxGajgydzliSWU1clBUUjZ5QTdDREpxVjQxNkFFS1JiSDBhcllqYnJKVEE0dGJUeTJpN0dYZTUwdVJsMU51RXVmN0taaHZmNmJMM1dlUGI5WDY4bEpaSDJ4SlFHY1RoNHVUS2IyUTFqOWlWMEhxUDZja2xWN1pvWjdudXNNbk96dXNrdnEyVnAzaFN5bkprN2xteGU5dU9ZR2dUYk1ZbUdyL01pRHY4elJHaXRkUFhOWitGWm9Oa3NLWEU1STBBNXBoSHdnZkxRc1FJblNwMFZjd25RakxCMVc3NmxpeDZjeUl0YlBtWWhEM0xSdkpiK2JIcXBKSVdVWVFCRXNGa1BSOTFLTkFJVVkvR3VLcHU3ZmRtcEkwbVVsM09LUTRYL3ZpTVdmL1ZmdmVIUjh6a2tIOEEwRDdoWWpVV2hBODlzSnhvRjhFWWtLZCtBd2RrajZtL2NwOEh0TEtWeEg3SHJPZmY1T0ZXcktNblZESmNxL0cxbmJ4dCt5cEx0UjJQMVBscUJ2NFdIbHAvbWlRVjNqR0NpeGdiTkdGSHJ6YkFoLzNjTXNUZDVwQ1NQWTRJbGtacUx4SUpBQWpvSEtyR3ZESE41SXJYb0o1eWZ3WHpTTVN2NEMyQjBrWnl1UkllQTdESTZvU1hnc2hrTXVtQWo5Zld5T3N6TE16dXNqQ0FKTmprbDBTcXZyMG5ub05HNzdzRGVIT3BxV0p6ZmhPWlBhN0dySndXMzViNmFycnlma3d0dlFKaHBWaFhhNCtPNmZHQ0xFeFIwTTdlTW5YYnNqZWNXU3FDWEFsejVyU1BvU0NlUm0wMS9JTWlCeURKRXJ6enpYd2FjV2NlazN1cmVuVWoxYzBxTEc4WWFqWWdNYTZ2WlVpZ2ZZRjBabHNXUjZleEpoUnAweUNMMlJlYTNBcHNjYkVPTE9CRmZHTE1tU09aTkV0QXN3QUhlamdvYnAxczFMNGQyY3VHMFJTWDdTNFdWc1pzZXpYOGgzMG05cGJBRSt4L1FaeFBGYk44VlVxQWNrMnlMSlR2VmJ6ZlA1V2tMT0ZPMEpMdWpFdTRXY2pCOFlGN0tCVlZTbWQyTkV6a3FmL0VkU3Fma2xHMVFFclpDcFhkRjJQK3pXeGZOUDJvRGdmN2ZGekxUM0RLNG9BSUFxN0JnRTVzYUlQczRwZFJwOWZrOWJPVDRrMi94bVkvcUlZbkNaMEhTS2xsamc1R0NHNlhRMUdtV085cTBEa29sajRaeXZiL2QzN1AzWFYwNEU2dCs0QTlGUm5rU0QwT29NaFFGd3Zveko4Nmw2MHZKdURpQ2hXZGdoZzNSelpiQVcyNktxN1dBVi93VzNzTlM3YS9DNEhZbUxsSWlMM3UrN0FNNEY2N0FPR2J1dDdwUzE3MUVGN3pYT1B5WWl3VTR0YWJveWFFWXZxMS9rQ2cvaG5aM0crTnNVUGhyUEFaa2VUUUpZZDRnMUljZVV6VnlaY0NxYzRkYWgranBxQzBuR1lBYWQ2TGxUaE1hTnczRjBSMjNTUk9OKzFjMzFJOXBUcHd6UVhZVFdLUVpmSnRlT3JqUkNaU0J4dWs4ZEFveTNyMUdmUEJrZDZacUtCMWliOEJQdkZIeVNhMjFFdjFMSFBVSHIrdHVHa0xDOFhreHd1dlFoa1NZU1U1Ym1nblNPNU1valZDMGNuMGhGSHZPc1BXeDM2N0kvL252elNBZ1FNUG5VcjI3Tm5RYnFLUFJDZE5UMXlJcFJjTEFQNVRFU0RjWnJ4RWU1UzhETlFCTGtGWjdCWmRuUkZwTC9IejBnL3lrSEVQb0VGQ3FJYjBwV1lwTXp3dWtuaG5sRE0zZ2FSdWo0LzlYTXV1SU5FSHI0VFo1UGl2QzNqVTh2czdVZVo1NC90RWxyY3cwSmZpYy83c2gvVStKZU9ZcS9zNmhEM0kzcUF0YmNHTnhDK0ttVWdTVDEwZTg3MEV4ZnFsdGJQbHBPcHVoV1RVRTBrU0NoZnhackQ3T0VmN3NXRTRYZ3ZKMWdLQldaYkpmdzVrVTNuVnBWVnVMMS9wblRwVkxMSzhEVWlpZ0FRUmlCQmJlUGdNUy9hYVM0eGZCYkt1L0c0QzFsN2Ixci9nUmNWZEtWS2YwcFd1TFA2OEphcUQwdjJXT1FrVjJrTlVmQ1h0V0VzRkRsbGw1RjFzTjl6ZTRvQmg5Y2prMVZKOVk4U2VlTlBWTEIyUEcwQjB5SVVySVFPOVdsK0t6QVA1cTl6QWlzMG9Yc0F1Zk4wLzlGZFMwSXJoSS9vQVNUZldQaDRxRHVYNmVwZU45SDIrbXIvS2xrYStaVnhWbE5OcE1oZjUrdTZzeXU4Q01TazdKczV6MGhtQ0lHUStGWkJOSzZJTFQwczN0VVdTNmVjNEI5ZlA5a0NYZGpicnBSOGFOM0RlN1BMcjhSQm9zYW9WSlFJL011eW9vOGZsNVM2ZFh4VzNXSFA3dDhtYXd5SVBKSzdZcmk5REFCR09ZeWwxU3lTbUNhMy8wK0lRTDV5eG1kbDFObVlTQmZDbGtOcUFVQVMvREVkQkdzdDFRUkZ1WmxCUUdhai9BRld4QW9vaGUxaFhFOHZDU3hZejl5VUF0U29xY3BibWVycFhRaHBLeWFqWFY3b2tWUko5bGw3SE0xbXk2QW9STkg4RHhxTktxL1hGVmdaOHhuZVpRM1Y3NERIQWVSMC9JYW5RODI2Y0oxQ0pNeEcvQis3VGtqU1ZSeVE1SStkOVlSU2t1a3Nyek1JTDVLQnpUU2V3NGo3SGZWVTRvejFtamFLbmdoTkU4L0RtN2JMellyaTN0dDNTSnNNN1Z4Y1FCbUc0QmVnWFB0LzBFRHBJQTBiOGkzb1FDTFVJZEZnbjIzSWUrK3hyaFNpc1NUZ0FmRC9qWXI3YUd3RnhTOWowbytuSHZud1ZKNzBibDJ0b2pVV0NhaXZUL3R2MW9EQVpENzhiL1QzMXpyN1RHRTd4eVcyKzFFZlFoRHRNSStxdGJlWUw3QXkxdk9NUjFHYnpNeXVJL1crSmdRM3dHLzczYlc2RGZQbmZTK241cFdIcHdtaDFkMzIyelc1VWNwMWo4eGVMYUU3b2ZXS2Eva0ZJNlhOKzRmM0VMM3VaK3RPbWZOWkxmLzVKRVpWb2wyQmp3KzhBM3ZlcU5xeENUNVNIWXgrQlc0OWJYL2Y4cndVMlhkRklQelJVQm5GT1NRb2RmaVZEeDZwZW56Umg0L1lHNi9SZGp1MVdORWhEUytxaVYxUlliN2xERmZ5NmlGbSs2NUh5NStBTERjQWV5c1laWlZKaUlRZnIrbXZORUg5d2JGdEE1cnFUT1U4aXdOeUJudzRyYkg3MDB4VEJWdWFibFlTWG9UMXVsZ2F4eXJ2NExDTXp1U3V4cE9YZG03MENWdndwZkMrOCttWHBQc2ZHU1FsMzErOUx0N0ppMXdpUmhEYXdZREtMMzlnaDFITkppZWFxclpiZ1FQNmFhbXRhdGFiQU91V3NlWXF0cmRFSmNRWGpMWjlVVW1sZFZQSXA1alRFbmVrb0l4TmJmNCtSem9qQXhaRS9Jc09nSEJMU29GbjV1bm91WXRGbnY3VTArTklEK0xKRnYyWUxUV3JSeHA5NFppSGxoZWFpY1AxMHc1V2ZlVGJDZVNDVnFLbEMvY1pIZmtlNlBGWHAyYWxoNGVaYy9ybWY2QkJBeGd2V2FGdTVmUlAzSi9HRnZTejlNOVIzS1p6Y0dQRklTWXZrUHZzUHZjcGo3MGZGbEtCK01wQnJPdWRackRyREdUSzk5eXVYTEJiNEQ1Q1ExOFByeXcyME1XMHNBMkp1SFVSMkpiMGkrTSs5bWQwMVAydHV5TGhCclJVcUM2RHcxZ1hiVC9pQkVSTDhsTUZKT3dLOFdua1pTOENpSlhYd1ZmV2lhUUlwMnNyZGhwNHM4MVpsdjZ4ZFQ5SFdSMUU1S04vYVVDSFlSWlZRR1F2NmlmZ3NsK3kzNDdGVm5STmIwODZsc3BiYnZWSkxnQ1VUNFpnMVo2SEZvSjdxdVhrRGMzVGxFRnVOQ1poWEwzMjZTdFdnYmZ0cW85NHJWT1dERUYzTjlCeGZENTU5d3FBeGNOSEI4SUpMaGwrTTFtMVdja014YVlzYk1DM0JIMzYyNkVZYWVmK0F5dTlraFN6ZVg5SGlFNkRnOVVSZWFwSHp0RUtuUVk5WW1VZnRsRjVWODE4YkVwSit6Yy82T3EvdWt3aDJmd0pLaUVBYVcxYkhTcVJDTGVqS2pDK3JDc3N2bytScUpHTXFpQU4xRlVscWphbXVYUGZqdktGZ0NXMDJ4S1cybVYrRFllK1dJN3FYWHFRdXN1RUZDSHJ0STI3VTBCQVdsL3RacHRpZjlWckNneHVqRVJHWllMWURCMWdJQ3ZyZ00wWDAwa05NRTdtVFdud2VWakNUbnNXd2hhZ0FXcHo2TXpHQS85N1BVOTMwK3pqRHpiZWIzM1Nib05VM2ozQStlNVNscXVGamF6Vkl5YXRuY0FnNkp6Y3lLTnNuKzRSRjdJVTRHUnZybHpiWHNvYTZXZDcvdEkxNDV3NGtPUWhLNzJ3dWRHNzlRRGh3anhNaW05K0hhSHFJU2dXNWx4bUhybGRjWlJwZThaK1daOUFhVlZ6NGJMQTFrNDNYVGt2TnFzVkdCOWdsdWpmdHB6UjNPbE5TOUZjSnpDUWx6ZmRmYlRjQWtmck9wY0VNeHVka3Y5alJHWFNYV05hS0wvV05PZUpza1lsVUlLa2t4TnZ3TUYrd1YrMm42dE9qd04wR2svczBBNmR0VGJlVDM3UlJablBPY2RtdXNaVTJaWTdkQmRUekZUS0NRWFFCU2o2amNJemg5c2RKL3dTQmxURUJFejVUSlZpVVRkWWxSTmh3QTY3Y2h0UkRML3Y2bytDRTNETHNvN2p5UFVzVEFmazdIV0phcmdRVEcvR2Q1LzBLZG5ScmE1N01BaFVjVHlmU2lCYjNnUGxnc0tGZTFGR2o2cU9hcnZscHp6YzZQMTc3N0EzOUJzZFQxZnU5TFUwbG9KcmI2azN4SzFmTmVIQmVFT3AwUWdZQ1ZTZGFhTUNPaE52eUJ1eWRBNlkzOTM2ZmlrVzFYTG0vRSticzEzMnNUeFFVcC9MQzhieEpIZ2NZSkxBMnl2Tkl6bWt5QTB5ZU1OTXJlWU1yYUFLQjN4TjloejdWQTJkUVFwVWhrL0ZuTDcyVzE4OGlqNDhxQ3ZsY1JNK1ZaU0t6ejBCYm84aHdEdXBQbWZBbXhJSEpTb2x6NDVNakZTVitncTN2SjhKUXhzbmtHa29KRmhzM1VDeDR5YlpuT202bnNqNE5HL3Jtd29YZ25uUDV0TXBrTW01QTAvc2NrREpTdlZQSVcvaitNeGs1bWNhcER0OXJOUEdSVkJrazdMaDhUT0d2Q1RFSXdYNVYzK2ZlTVZ2MVNsTkpCMkM3L3ZJWThmekhOcG5qZFRWWE1nbXZ2ZXF0M213QmxTYjcrZ25jYzNSbGhSMXhUQWFMVEJBZE5nd2k1c01OOWpsL1g4UGpiUG9qOEtUbkxweVk2c2JwWXMzV1J1U2t6UzNRYVYxSHZPajN3cmpSYkRvRm5SZ1RYcDg2c21iQmt5NS9nT25CSElUREhncGkvR1JESGtMVVgwQTRnZ0hrdTRzYy9DcFpxWTJzMFFxVjAzVnVaZ3VmekQvMWVXUjc5UmRsTWlubVlkSGlLWFBMMDlMWE83dlhGazArdGJ4bjBLYXgwejB2VkxwYmd0MUVuMy9zeC9HUnV5S2VoUDF6NkJiNGJsa05ybHFYTEI2cDErbjJPcmtNbmJhNlhjRGlyMnEwdUJXTU12OEZMVnE1QUR1SDNSU1RNdkNxSGtNTGFkRWg3UjB3bjBya2dMNXhMczFqNThaazRCeTh3dlRML0ZrdW5jcFJPZ1FST0lDeFpnMS80THZxbDNteUZaZ251aml5SDdubC8yaFl6VTZxZ0RQd0RKU3BvZXRYQkoyY2NxLzMydVVVUUFjdnB1Tk14ZCtpY2JML29wNnhnU0VjMS9nN002ZWN6V29SbFoxSXRoWnNRcG9RVjAybVoyb25tMXQ0U1FqS3dHYjBuYThQMVg3NU9CSWhUSnVsMjF6RjVhVGNQVHVDeFA2a2RJR25iK2JEdmt1emJjNDUxeXhWQ3ZZT3B6QU95MExPQW1FeElsTFVZaWxwVXlBbDBVSHZwUmU2dFd6MXRxS2dGOGVFRHAxU3B1QWlyRXVEMklhN1NDaWpoSGJhQVhFdUczT1JRWGVLUFlndjltN3lMMzFBcEVJdDBKenhlVU80YlVqTkEyVzlpQmQ0SW4vc3p4dXJSMmppcWQ0K3lnUlh0M0k4RDJSYk5LTGpCRUVGK1Q4dG9lbmZFSXYyOTZrZERCVkRmejB0VmxSakMzaWxONEVDajZTNnI2VDlVbzAzYjJ1Ny9FZ2liRUozeU1CZkZmZlZXRWhYSVFUNllmREhYYlZMYWlDcHRDUU1XaGgrQnVYbmE5aUNqTU81WnFrVm9BY1c5TGorKzBkWmJUR1hhenZNcm8ramljbit2ekJSbE54ekhkL1I4VXp2Q2w2b0I1Zkx1eUk4b0dPaTgyUy9OM0NxZSthREpPRVdDYldhbHl4T292c2NxUHhBOUNBa3B1OUpBakNGUmdXcldjRlJCbmFDZjF1Z2JGcC9QTWhXdnlnQjU1UitBY2J6cVAwVWdhMVUzakI1a2U5YnRIM09kNUpLdWRhb2hubkN4RzAvOXJyd0FHVVlGM2ZTQjcwTVkxMXcxUTcrNmxhVXBDak9NWHNrcHMvR1BqQkJNOHRLRTIxd29ndVNwT2t1eU12Z215dVZBNG5zWWtPZDJYSUFMZEFDY3NXYmNkRjJSdHU0SDRIdW5QTHJxZE14amVqa0lXRTkzbnlhalYxQWZYRlMveDVxV1ZDSStKb2ZXUmZWR3dsdWFFM1VVTGRObThsNmVMUDVEcGhuN2NHNVFUQ2FRWkxkMCtkMFpvT2wvam40dWYyN09EUEZPM2VwTzhWNU82U1FTcHpMM0FYWERBN0ZNWkxkWjcyYkVqVTBEaTB5bmVlWGd5WGFFa3pCbTNHUXdKK0xRTFRCdmdjbG9vdENVbjhLMlBld3JMcUVIdFhxdkZXcjdIR0V0R3FXekZIOStjWXhJbGpxM3MrRUZSRUM1TEozTkRWUk1SMHF2OTczWDM0eHlPRU5TSm1aMmFlVm9oeDVCdFpFTFNmL3N2SGVBcTFsbzJ3cTZHbXo1RUh3QisyRGFZSDAyWWlac0pZS1VpaXFFcCsrcFJBSnM0KzZ6a1NTMlRtdHMrMnNjdVZMSjFzcFh2WWdkM2s3V2VNSG16MU4za1l6M01JMlVPVXVTYTNCeWdmcm80bUJlWExIRytpTktXWUJNRGRRRkpTb1hPWjV0RTRSZzlxZkpOaExiNmw2QmxGODNieVZoWnZNTE10SkRUemhPSDBqVTlzdGM5T2x4Rm5lcDM5SC8vbW4vYjBIRnpXb0IxUkV0Z3d3ZmFOU0ZLVERGWTJYS1hpYzBRL3g4Zk05eURLdW5BcXRGNGdMQnJ2MlArOW5xTmdXa0JBTFFFRHM1OFhaL0VmYkxMd2pOWUlzQjNhbytxRitOSTF3MUpNdUQzUTQvU01DUkZENVV3WXROOXlNQnFGdHg3N1QxaERqRDBpUkVqTDRtZFZUOUQ3bzJCTHM5aGM1aDBpMU1CTG1OL1dGc0RhU2F1b2tpelc0b3NsM1JOYWtBMDNxUGdYelRZOUxRNk9kOCtUQi9xUW5nOWttcG9nS1UxNVM0OGJoZ1Brdm1XZ1hHdXByWjJWbi9IMGovNkFQMWg3dVNGY2ZMbVhEQmR0cTFSZzBjcEZjenRNK3luc29WNVRzZlhKMjlBMlZmVHJtNWE5dVFKVllzRk1Fa3hQTVFnYlpRMFdIWGlWNWQ4VytYWnR4Z0JrbnhvUU5PSVhocmhhWGJndTFORTBQSS80NEtjMmlzcGVyR1RSSHdLRnd1MVVvZHF0U0pVUHVUU2R1MnhxQlV1T3FEU0VSNE9TaERTTzcwTldwdVU3RXVoVmJIWmVIVllsUWw5czhCbWtubjJ4QmFaYTczZkt1K0twb1NyTlRjM2JsRkk5OVRPUnpXY2Y2OU1xYlFFeUNKT2U1dFplellqZ0RkOTJXK2U1QVByWGhSQzNTQXFBZjRYaDFwM05RMS81am42NDh4aTFpdzEzYkc3eksvMDRNOGNwTDlIUEtFbUFrTWR5elpuV1g2ZVZKK25XL00rRG81VzRoU0ZGSzVGMTdrVkpFanBFeWgzN1dGL1VZUW1kc2Jpck01YWxJcGFuMk42aHpLMzRNajJsZ3hibmpNeHZ2WnlzeUZpTUh1NTNZb1hraDRjVTcwNEV5T09STHAvanEvR3VIUFJqK2MxVFZ3Vk1MdVFSNHRGaFpnSlpKR0p4SGM3cEkycnhRMGMxcG85aU1DYU1aQllObkQ5bU55dVU3NFExWXErNmhPTHhlNmJuVkxvTFlKclY3eXZrcTN3a2Z0NjFycGF6M2FYenpKRDNFMFF5VXFRUmV6SDFieXBBM2F0TzcwNFhvWUFrVUV1aXB4UWovclM2S25aQWNpZXBkRFpFd0tFQUV1c2k0QUt5OU9lS2w5cVFIUGNBZTNibVIzR0pyUEpjN2NOQ0pFSDhZbzhmSUNUVUMyWGl0RTUybUxoSHZiTXZlczQ1QUZHZjZXaXQ1cGRBaWdvdkdvR2VSMW1UYXhJYzdQenFiOFdTYWQxZHU0Wms2b1Bpd0x5WVcwMGw2a0M3MDl3YUkrVGtQcmpsdFBIZkNVREZoRkNhOTNDcHdzd3U3S1l5dWQ2T2gxVmZFVWFwN1NmU2NOWmkzakpIeGxYWmhyT0FTMnY5WWN2OEhXYzdoRThjMWw3MHRQcFVLemdnRTBGS1RHZDJOMjhSaENyWG1jbmY5ZW9Dd3hGRWZpUFZlckhGbVc5NnQyOGNqcW4zTk9Jd3ZSOWpKUWI0bSt2TXlpb1dmSktYWG9xeVZTWnUzZ2FCUGJFbTZITFNuY0VkSlJJbEFucWx0anVwOThwOTlGRmhQNkIyNmVDcmIrSnM3SWIvUnpjKzZvM3pOVlBJVnpDKzM1ZmdnZXl2N1JTQVlXMkRCdkd4c3Qzb2dBMTdXcFdoQTUrL0NyUTVOK3F0WVVITUFQc0tRdlhxVWQ0U1RwRUNNdkJEZ09aVytNQzlmd3A5K3d6V3U5YXFBemRCYkRLRlZsMmNLYmtPNExuRlZDZzQxNUorQyt6enY1L2pOZ1FjWHpHRk9zRDFZeGZDRlNYNkRhZy9RUmpqRloyRG0zR2RmZVg0RVJmTUJVY3Q5eWtTME5OdisxczY3UVNzUGRQY1hvS3h3aHJOaGNFOGVaT3N6RS9MSEdLOFY2d0s1TXlKYUdjWkx6ZHJoSk96eUNSbTZaaUc1VDBONU0zNFRYL0MwaGlMTkoxNFNkbGI4VmR2eGJBNnM4ZjYrejFIUm9ERmJuVGtpT2JNUEk3Y05iK0lmcFpjQzdSVW1xYUZ3cEhCeU0rZEd3MVNjV3Fsdko4KzdTZ1lCUDJrZGdSWWhoMTd5VVdndFliOU9IR1hNZUwyMTQ4cVE3N0lWSGU4K0piL2RYVS9qWVRtRjFGM04vQ200WGE4LzJrYzdjWXpjVkFGaG5MTnMzVTBsUTc1YUMzYno5MWV2amlFWXYvaUdySUVUdXlOdFBsams0cjNGUTdHbEc0ak1ha3pWZkZiclBPMllDUWZkU1VJdDVvdEF4dmlUUFJSdU9ESnZnN296bVZScUlzZE1vN0xIVzNGWk5Fd2w1OXduMGpxOGpEMzZ5VFRPdVJBRjVPRWRSMHNqcGZlRTZUTG9XQStGRnprWkZWM3J2aGhiZlFPT3NHV1REcEdEWkJxOCtnc0p2KzFld0JmdDZGTHFaM3Q5UUVRNWFWUkVWMkNxRXlvbVJINm9ZaExyYU1IV1RJY2RCOGtjcEtNTGt1Ly82UVoxd2hZaEVNMUFEZTFzcmtyRGRmRDErdUdhT0RscmhlS3l3TEVDLytsejkrK3JtWmVwYXlFQzQ2NkRraGRqZWxmMWI1aEg0OGRnSGIyV2drYnB2YWJ5ZG1VaWZMSU0wNjZFTFZKQjBCUklUbnEyNEdYM1pyUFVPSXlDMTYvRzEybWlqd0hrd0ZENWdRZEpnb2lLQTNEQnhJQlo2eHhCQ0hyT0NxWFIxMUIvV1dlWnczcVZsbFB0UFJFdGpGa3dDK283LzBuOTNLSWxOY0Z2VFVOVG5vVUw4TXBPS3U5ckYxenkxZmFCSE42MzRYdzJlVWdFUzZESlZHNVB6Tko2T0dqeHNtVk8rV3FJYkNVWG0rZStCMTJFRHlOYkQ0OHE5cjhyQ0RTdytmK01JZnVzZFliNUtKc28wQ0thUGVsYkI3cHVPRnl2bXR0MTRIK1krZFRjdUQ3VC9CUWdKRVRZM0Y5UVljWU9hREhib2xwdzgwMUp2NC9zRkVUTWg3RzFiZTJQd1JPSjJoZllqREpRZ29LOFZmOVUvdCtCbUtNYUZ2SHFmbEh5a2k4UmQ2WDNMSVJ0QW9xWDgwaFE5bU5GbXo1SDJ5ZlF3eG9TcjcwUzR6dGQxRmQzODc3Nk4rWGZEemhtWUtCdGRLaENnSnN1TFBGdnlkOXhPZldNemJVZmF0TStTZDFlSUg1MVI5TFVzMHJpcEF5WWFpaFM5Z1JFL3pMbFlERWpyRmRxRmZGYy9FOFY0M3dHSmhDb01VajNMNlV3UUo5UTlvTCsyZERRK29USDJGNXV2bHp0a09uODhINHNobFNiRUFudmN3bTZIc2h5OTdRS3FCZWQ2eldCTDJGQ1J2QWxnMFgrem5nK0tVNEdSbzVqKzVrTXRidVZFMDhtV3B2RFlLcS9KL243UVh5THNTSE4xMlhBNUQxNkxjWkJnaUZ2dkw5WmxUdThaRzlwbVJIMUVqcUp4OXdRQ1Qwd1FsVTEra3BKSlVkd2U5NUczOUtZMEN5Y0k2TFkyRFRlaU82aC8wb1ZFVXF3SHlHbHNwdlF6UzNsWnZVdFBxVTFhaUdVSnV4MnFLNGlVUlJ0ZzJvZUowdVJXVk1YTWUzN0hwS1Z4RzdFU2g3TG1sMno3YUFYZFZWcXVMeXpNWjRlQ24venhBYktXODJnOGFnQ1JYYUg3MUNCUWpmK01VdVhxZ0JvZHFQZWpKTGJmcHVXNDlHNG5LWlZ5THpMZDdmS0Z0RFpEeVlBeHJCTFdQa05MS2pXTGFHYzdHelRCREZEZE9UWW5DQlh4RTJ5ZzhGVzM3WkVtR2VtWitjWmErK1VmTmdNUDc2MlVSVjJFVlI4eWtjbTZ1NU16Sm5RM2xYSG9MeDdhYlo5L1dxQTBrN2FnM2xaM3lTTEhaV3gzemVxbG9wQmpjNVcvRGc0ZHhERSsvSHkva3NnT0FOTlZkUHZVaHEyOWhVQkNEaHJFUFk0UVErUVNKc2FXZWY0M1FuUW1nZjQ3OUpMZ0NSblJiTFhha1dBY0hoeHZKem02cFRaR2RaVU1kNUszWHRPQTVGcFFyTXZIbkU5R2JQblJCT2xSVFF0TlRYOUtFZFdxNVVwR2tzMktRUHJCK1hKMEh4bEt0Qnlxb2JCMGNIWnNVZVVhL1NNK1pZUzBNUEN2aUVQSVcrZmR2dXd4bC85bHQxbXZuWXMzZ0NxVEVEOEYwNmFnaGxvc1dGeDJGcFdyZFpoOGF1Q0NXUjYzdlhaMloySlQyZ1M1S2pNOC9HUHZQUmpMWmJrMUo2ODF5SDc1VUIrZCtvSDh5RXRMTDdyLzJLRm13U2VZeGtjY0V2b3FDa2w2MWtBaGo0OG9tN2dsOG9ZSFJYOE9IQUZyak1oaUt1RUhSUHZIajk0L0djSVJoeURxaHlOcTc0cTk3UWh6Nk5UeTRlTzVSa2t4YmUrZHNtdkFxd2hXcjJMZ0JvRXhxOUdndGs4RTc3RGZKZ1RPbENuYVJlV3N4QlZjbTJHWm0xV3g0KzBTSDA5THNwNXd1Ym4yNG5SNjNYQW9wTDBjcXhkZmkycGFpZU5kdk5WWW05WmtXZVZhUHB6WFhXbkpEbExVL1ZUczhzSHFBU0F3c3NjdzFaQjhxOGpvM0ZoM1lPRWpQWldUaFhWT2l2RnZUVkIyNG9KSDArWDZjUWRiWEdaOVN4SzhUWlVrS2tjMC83NkxpU1BtaXVKeStOUHVBS0p1UHZ1Nkp3K3RHQjIrN1F5dXd3WjJmWDdINmU2NlRya1UwcklYVkJRNlVtZWdlMWtoanNOTW0vcVBiWXRFTHFsY3VRVmpqbWtveXljQTQyUjhNaHFoTE5NRWorMFQ4YkNNRHoxWkl0bUZlLzdNQmdjNXNtNUNGMVBDLzNOOW1Oa1RZMXQzbSswdUlkV09nbk9HajRYeW95bmM5K1dxRS80eUh0bXdPOEVqUXROODYxbHYyZkFHNUpIR0hlVXltaVRTQkhLczViZFFYa3AyUmpERlpGSnVJTTVaeWZydDlVTkZDZjdCaS9mc3BQUjNhWk5qV05BMUZlTkpGR2VmQVJ6bzc1K2tmM1JuVU9WbGt5a01JTzdSVVVMbkRWMjJ1MjFwUVBWRUhzRG9FMUY0UTcrSFdoQzlSRzJHVWFscDZqL2VKc21lOWROMGwrRTNWNmZSd3hiVHlZS1EwdGoyTzNrR3NVZGduMnF1NHU4a0lNQmhlM0dINzRqYnVpbU5vWHpDRHZFbzVjTzdvOWl6VUdCNFhPTDNHY2JINWFvd0EreXE5em5XRGZud2dBRllQSmdIQUJZeERlM0pGb0w1S3dFSXFCSXFHcWhmK2poQ2E5cnRyQmRqVFZiZWJNeVJ1akFEUGhaZ2hENnJwM2x2U243SENxN053elJ3SE1WQ0RsNmNLMnZLSDZuS2Z1K1dIR3VCeU5rZ0h0WnZ0eFpJVU1KTEJOUVBjdERUN3FpRlEyUkRkNW55eUxSb2JKMllNWGpuQnNic1lROG1KQk1jbnlEaXBnK3pINXNLRHQwWUtSWEZIbVZFby9VMERNWm9wRVp5ZFluQTdOelZ2M1k4a215VjA4anVMMUdQWFNXazhLaFJrYWJLc0VXb2pIR1pXUXlmNG0yaWZxR2RtMnpOVVpKSXp2OHM2bEp2NzU3dElQYm43ZUFDUkZOL00wQk9ZSVBIaG1tY0kvdkhSU0tzSmhGTmxERXNUQnBFRzlZM3ZGYXBDclp4dEdHdldDNVdDSFJmTFZwV1UwVXhvRkRlZklNMWdTWVFjU0d1YUlMZ1ozSVlOTHlqZnpONDBOQUNHWkxWajQvcE10Zm1Ec0pxMDNNdTZOSVZuekdrT3RPMTd0NWtDU0JmYSs5akxvWGJicUJLWi9Ray9PYkp2RzU2eXFsNGYxSHp0YVU4aUcrejN6L3ZjbUlMNzlBUklVUEtPN0R1TG9tTFZWUERXMUp1RnUxbVl4OUJkb1B1bGxRQVdhN09nMENTN3Nva0VZOWdJV1lQd0dlUk00bGZ6UHdUUmdDSEdKdXArejdsT1o0NStYN0U0QVNrVFY0aWZyTTVEVEtla2NMczJOUHRvMFVBQjVGU0FBQUFBPSIgYWx0PSJNb2JpbGUgTGVnZW5kcyIgd2lkdGg9IjY0IiBoZWlnaHQ9IjY0IiBzdHlsZT0id2lkdGg6NjRweDtoZWlnaHQ6NjRweDtvYmplY3QtZml0OmNvdmVyO2JvcmRlci1yYWRpdXM6MTNweDtmbGV4LXNocmluazowIj4KPHNwYW4gc3R5bGU9ImRpc3BsYXk6YmxvY2s7bWluLXdpZHRoOjA7bWF4LXdpZHRoOjEwMCU7Zm9udC13ZWlnaHQ6ODAwO2xldHRlci1zcGFjaW5nOi4ycHg7Zm9udC1zaXplOmNsYW1wKDEwcHgsMi41dncsMTNweCk7bGluZS1oZWlnaHQ6MS4yNTt3aGl0ZS1zcGFjZTpub3JtYWw7b3ZlcmZsb3ctd3JhcDphbnl3aGVyZSI+TU9CSUxFIExFR0VORFM8L3NwYW4+CjwvbGFiZWw+CjxsYWJlbCBzdHlsZT0iZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczoxOHB4IDY0cHggbWlubWF4KDAsMWZyKTthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7cGFkZGluZzoxMHB4O2JhY2tncm91bmQ6IzExMTMxYztib3JkZXI6MXB4IHNvbGlkICMzNDM5NGE7Ym9yZGVyLXJhZGl1czoxNHB4O2N1cnNvcjpwb2ludGVyO21pbi1oZWlnaHQ6OTJweDttaW4td2lkdGg6MDt3aWR0aDoxMDAlO292ZXJmbG93OmhpZGRlbjtib3gtc2l6aW5nOmJvcmRlci1ib3giPgo8aW5wdXQgdHlwZT0icmFkaW8iIG5hbWU9ImdhbWVfbW9kZSIgdmFsdWU9ImFvdiIgcmVxdWlyZWQgc3R5bGU9ImFjY2VudC1jb2xvcjojZmY1MTQ4O3dpZHRoOjE4cHg7aGVpZ2h0OjE4cHg7ZmxleC1zaHJpbms6MCI+CjxpbWcgc3JjPSJkYXRhOmltYWdlL2pwZWc7YmFzZTY0LC85ai80QUFRU2taSlJnQUJBUUFBQVFBQkFBRC80Z0lvU1VORFgxQlNUMFpKVEVVQUFRRUFBQUlZQUFBQUFBUXdBQUJ0Ym5SeVVrZENJRmhaV2lBQUFBQUFBQUFBQUFBQUFBQmhZM053QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQVFBQTl0WUFBUUFBQUFEVExRQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFsa1pYTmpBQUFBOEFBQUFIUnlXRmxhQUFBQlpBQUFBQlJuV0ZsYUFBQUJlQUFBQUJSaVdGbGFBQUFCakFBQUFCUnlWRkpEQUFBQm9BQUFBQ2huVkZKREFBQUJvQUFBQUNoaVZGSkRBQUFCb0FBQUFDaDNkSEIwQUFBQnlBQUFBQlJqY0hKMEFBQUIzQUFBQUR4dGJIVmpBQUFBQUFBQUFBRUFBQUFNWlc1VlV3QUFBRmdBQUFBY0FITUFVZ0JIQUVJQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUZoWldpQUFBQUFBQUFCdm9nQUFPUFVBQUFPUVdGbGFJQUFBQUFBQUFHS1pBQUMzaFFBQUdOcFlXVm9nQUFBQUFBQUFKS0FBQUErRUFBQzJ6M0JoY21FQUFBQUFBQVFBQUFBQ1ptWUFBUEtuQUFBTldRQUFFOUFBQUFwYkFBQUFBQUFBQUFCWVdWb2dBQUFBQUFBQTl0WUFBUUFBQUFEVExXMXNkV01BQUFBQUFBQUFBUUFBQUF4bGJsVlRBQUFBSUFBQUFCd0FSd0J2QUc4QVp3QnNBR1VBSUFCSkFHNEFZd0F1QUNBQU1nQXdBREVBTnYvYkFFTUFBd0lDQXdJQ0F3TURBd1FEQXdRRkNBVUZCQVFGQ2djSEJnZ01DZ3dNQ3dvTEN3ME9FaEFORGhFT0N3c1FGaEFSRXhRVkZSVU1EeGNZRmhRWUVoUVZGUC9iQUVNQkF3UUVCUVFGQ1FVRkNSUU5DdzBVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZQL0FBQkVJQmdBR0FBTUJJZ0FDRVFFREVRSC94QUFlQUFBQ0FnTUJBUUVCQUFBQUFBQUFBQUFEQkFJRkFRWUhBQWdKQ3YvRUFGY1FBQUVEQWdVQkJRVUVCUWNJQ0FRRkJRRUFBZ01FRVFVR0VpRXhRUWNUSWxGaENCUXljWkZDZ2FIUkZTTlNzY0VKTTJLUzB1SHdGaGNrUTFSVmNxSWxORFZFUlZPQzhSaHp3dUlaSmpaR1k1T3lkRlprLzhRQUhBRUFBZ01CQVFFQkFBQUFBQUFBQUFBQUFnTUFCQVVCQmdjSS84UUFReEVBQWdJQkF3SURCUVlFQlFJRkJBTUJBQUVDRVFNRUVpRUZNUk5CVVFZVUlwR2hGVEpTWVhHeFFsT0IwUllqTThId1EySUhKS0xoOFRSeWdwSWxWR095LzlvQURBTUJBQUlSQXhFQVB3RDlVMTVlWGxDR0R3bzJVMTVjc2hCWU93TitGTWk2aVc3RlN5QzBjekh0Y0l6cU4xNFBMUVJMNFFlRkZyV21UdytBMzQ4MHZpbUwwV0ZSZDVYMURLYU51K3VUaEVvblhKQkhSdXAvMWtBMUUrYWc2ck1FRHBxdjlXMGRWODM5dW50czVYN01hV2VLaG5wOFVtRjJnUk9OOTlyOGhmbm4ydyszRm16T2s4N01McmF2RFluRndBWVcyL2lueHh0aUpUUitvbWZQYWp5WGtKN284U3hSa0JhYmI2ZnpYenAybGZ5bFdYOEppbGJsMnVwcTEyNEFlVzcvQUwxK1grUDlvZVljeE9KeExFNTZ0enYvQURMZmt0ZmFiRFZKNHZtclVjUzlDczVuMkxtLytVTnpUam9tWjdqUjZIRTJJSTQvcXJpT1pmYUp4M004enpOU3dOMUg3TnZ5WEtSTHIrenNpTjArWUMwQ3NiQlU1cnJLMXhkSkcwWDh2L1pKSEczMzRDUUVlcmZ2VkxTMzVvMFFkL1RqL0lMMzZjZjVCSmFXK1M5cGI1SXlEd3h4M2tGTDlPUDhncS9TM3lDa0F6eUNoMGZHT09BNENtTWRkYmdLdXMzeUM4QTN5Q2dETEg5T3U4Z3ZmcHgva0ZYK0h5V0xOOGxBYkxIOVB6OUdoU0dQVGo3SVZicE4xblNUMFRRYkxMOVBUbjdJV0k4WW52OEFDRlg2U3N4dGQ1RlFsbG03R0ovMlFzTnhpZSs3UWtuTmRiZ3JEV3V0d1ZDV1dINlpmNUJaL1RUL0FFVmZwSGt2YVI1QkNMTEQ5TlA5Rkg5TnY4Z2tkSThsTU1aNUJHa0F4MXVOdjhnbWFiSEg5L0hzUGlINzFWTmF5L0FUTksxcG5qMkh4RDk2T2dUNis3Q25IRS9kNy8wUnN0cTdjUzZod1pvQSt5ZWZ2V29lejdWc2dscG1YRnlXcnF2YlpnQnFzdU1tTGR1N0p2OEFWWk9Yc1g0aXZzT1hxOFdhVHQrcVAvOEFhVjk0Tmp0RzBlZ1h3bDdGVXJLWEhCRzBnRVJIL3dEdEsrN29ydmpZZlFMRXpGL0dZRVNJSWJqbFlEQ0NpaDJrTE9mY3ZSS2ZHbWlLbGVWejNFYXd2YkswYnJmTXp5aGxJL2ZvdVExV0xDS3RlMTNCY3E4bndITGtxRGlVbUhZbzF6bWdEVU9mbXVyZS9mcGpBN3MzOElHM3lYRnM1MW9qdEpHMzdRNCthM2ZzdHpJeXNvREJJUmN1QXNmdlZkdmtXbHlhRjJuUnZGTEsyM0FYeTFtYXNmU3ZMYmNGZlduYXk5a2JaU0dpeHV2azdOald6VmtnMG8weXpFMTV1TUZ6YmJKU1RFeUg5RUY3REU0N2RVcE82eHZaS0xzdXd6VTF6cEJzQXErZkVIdEhBV1JMNklGU1drY0tDUE1GK2xYWDRDOGNVY2ZKSXlPYTBuWkJkTzBIaFFmRXVJcTUza0VHb3JuWDRRSVpta2NJYzd3VHdrczRpem9xOTFoc0ZhTnFOUkNvcUVna0N5dTJNQXNreUd4Tmh3bVUyQ3QzekVFS253blNBTjFhdmMzVUQ2cFhtT1JuRjVIUjA5N2RGckZOWHVGU2RoeXIvSHE1cHA3Vyt5dFRwMzNuSnQxVHZJNFd1SzFEcFdjZFZzWFpuVk5wc1lodWV2OEFGYWpYVlBodGJxalpheEkwdUtST0JzZ1lTTi96OU9IenRlUE82MEFUaVRFSEZiVG1PcTk2cFdPdmMyV29VREM2ckxqNUlHR2JYU1ZOcUp3V240aFhhS3QzelcweE9heWpkd3RKeFFhcXA5ajFYQ0ZoRmlHdTFrWjlXNXp3YkJWbEEwRTdsV2JHZ2k5bEFHUDRYaWJvc1JwU2JmRXZxdksySkdyeXBUZ1dPOS93QytSTlhkVmNEZ0xXY3ZwM3NzeEJ0WGw2Smg2QS91VUFya3ZLNnMxTUkrNWE1VVZSYThsV3RRZkUrL21WUlYzeEZVV01SV1lyVmEydVdxVDFqbXk4TFlxNGdBZ3JXNjFsaVNBa3NzeEw3Q3NTUGRnYmNLMEZZNTNSYW5obFJaMWxzY1VnMDhKYkxDQ3RuOFNmcHFuaFZ3YUxYVEZLNGE3S3F1NTJYS0xodFhvYVQ2TFdjUnJlK3hCcmgwVjNVdURJeXRhbXN5VXZQUW8wTFNOZnpQaUlNakczNnJHWHBDNmVPM21GUlk5VWQ3WFdCdlp5djhweGlTcWpIcUVhTE1leDJiREhIdUl2K0VmdVU2dXAwRUJNVUVUV1UwZDdmQ1AzS3J4T1FHUUFlYXJaZVNyUHNYT0V6R1F0c3QydzRlRWZjdE95eFQ5NEdsYnZTeGhqUXIybGRGS1NJMWtsbGlobHU0SkhFNmtNZGE2TGc3dTlMU25aNVd6aVJ1VkpKM0VRS3BzVnE5YnlySnAxUlc5RnIySnlCanp1dFdFcVJWeUt3SnJ6Q0NObFM0N2pQdStIeWcyRjkwNUpJMSsreTBUUE9LQm9NYlBKWXVzZTVsN1RjRkRUMUQ2akVKSEFiRnkzRERJNUhPR3kxYks5TVpwZFJieXVsVU5QSFR4RnptZ2JGWitIZ0xVTGN4R3Z4VTRmVE9EckRaY2x6SmpIZjFibkMzSzJyUHVPTlpyYXc4QThMbWRSVmQvcWNRa00wTU1LRFM0bVhpMnlhb2FraUVqcVNxU0U5NUphMnl1NktMeE5iNW9XYVhhSmVZTTRzYzRucXR6d0FPbXFBVnJORlRoakdpd3VWdk9WNlpzVFE5M2toTTdMTGsyQ1NUUXhyZlFLMHdhTTMxS2pjVE5NQU9GdEdIc2JEU1hPeHNtNG5Sa1RXNEhqTllBd2hhVmlPSTl3MXp0bGM0MVdlTisvUmFKaVZXNlNRczNzVld6OGw3VDhJSlQ0cEppRlVJd0FSZm90N3dscnNPZzFPMjJzdGJ5emhrY2Y2NXdGK1ZmWWhXZDZORVlzTDlFV25WQ2RUeXdOVS8zK2JWOXlkWmk3YUtuN3NrY1dWWk80VUxRU2VSZFZkWk02Y2FnVWVTVmtTc2JxOFNEM3VJSTNDcnFlck1OemJyZERwMmw5OVI2WDNWZlhWN1lRUnRzcWlqYkhZNGNrOFd4b2hwNFdpNDNtQU4xYmhNNDNqRFdzZHV1WjQvam1xUndHNjBNY1RVaERnaGptWlhTdWNSYmE2TGdFRDZxOVNSc3p4S2pvNlk0bFZ0ajA3T1c0MVRtWUJoV213dTl0bGRpTWlVZWFzeUd0ZDdvMngwdXVzWUZWdmZJd0FEWmF5NmNTVnBtZHVIYkxhY0hZMmtjMXpoenVwSmpyNE44bzhVa2dnQUlIQ05EWHVxbmIyVk96RVlwSWcwQVhzbWNQY1RJTERxcWt4VW1iUFFSRjVDMmFnb3JnSGRVdUh3bHVrK2dXMTRiR2JEWmRqRXlwdXl5b29DeG9Uem5HbkYwT0lhVzM0U2xaVkYrd0NzSXBOQnBhOHYyQ1h2STV3MjZyMUhDWHV1UXJpT25hQVBDbHRoSmthZUV1MC9jcm1rYjNiUmRTcEtJQURaTXlRYVFMS3pHQWlVN0l2ZHFLSExKWUlySTlrR1pvSUtkVkNrN0VKNTdYU2NrMXlVelVSamZkS3ZEUnlRa1NZK0lFWDZyQmZwUXFpc1l3R3hDcm4xeGtkWUpWQVdXTHNSN3U0UTIxQmxLREZUbWF4S2RpaGJHQnd1TmhXVGpPa2JyejVoWXFNbTQyUVRHVDFRdVFRT1NwMEE2ZDBHT29hNGt1TmxDVXNwd2U4Y1B2V3Q0eGpMWXdlN2Q5RlRXTmpJNDJXbU5ZMHlsQjBrSDVyVkt6TUQ2dTRJRmxXell1SmlUSS93Q3Exekc4MVUxR3gya3R1UEpXWVFMY0kwV3VJWXMybGE1eElXbDR4bjRRbDdRV3JYTVl6bWFvdWEwbXkxR3VxblR2dVNWYWpFdHJndThTelc2ZHgrSGRJZnBoenhld1ZYSTBHMnlMSEdiRFpXNzRPME90eEoxK2lZaXJueTdXQ1ZwcU12ZHdyYW1wV3hrR3dRTWxBdzJSMWpwVEVSa2FQaFRQZU1ZTGFRdkNabHZoQ1dROUcxMHV6eFlKK0dsZ1lBN1dicXY3NHk3TmJwUkdVOGw3bDVzaERaYnR4RjhHMFlCSHFpc3hPU25HcVFBZFZWaW9iQTA2aHFJQ3FxaXVsckxqZGc0Um9GbDdYWjNtaWFXUk5hN3B1dGJyTVdueEY1ZEt3TitTVWxEb1hYUGpRdzUwM0EwSXFBWVdTcU5rdTZwS200Qlk3c0hvbW9GbVcxSnNvbXJlT2lrR0FMeGFQMlFpUUpEM3gva3ZlK3ZIUlpJQTZJWnNQc28wQ0ZkWHV0d0xvQnJuNnVBc09jRDBRM1d2OEs2Z2d6YTkza0ZQMzV5VEx3UHNvUmw5RVlMTEQ5SU84bGc0Z2ZSVnJwajVLQm5Qa2lBTElZaVZrNGc0amdLcTczMFdlLzhBUkdBUHVyM0lKcW5lU1ROUlk4S0Rxb1c0Um9FY05VNGRGQjFZN3lTTDZ3VzRRblZndHdpQlk2K3VkNUJLeTFydkpMbXRhZkpDZlZOS0pJVXdqcXg5K0VZWTVVMHBEbzJOTnZOSU9uYVFkaDgwcDNadWJ6WEhrbXJnRm0vNWM3YjhieTFLMTBOTEU2MzdYL3N1eVpYOXV2Tk9DOTB3VU5KcEIzdVIvWlh5NldnRGtGUWM4ZzJBNTZwcW1BMGZwTGtqMis2R3Q3bHVQVDA5SUNCZlRwL3VYZnNsKzBmazNPWVl5aXhSc3NqdWcwL212eGNrcHBtU05JbkxnZDFzV0VacXhqTCtpV2d4T1dCemQ3TXQrU3R4eW1hOFA1SDdxVWxURlZRaVNGMnBwNEtLSDNhZGV5L0p2c3M5cy9NV1Vud3hZazZwcjJOSUJMeVB6QysyT3lYMnVzdjU3RlBIV3l3NGRJNE5CRWp0L3dCNVdoanlvcHp3dEgwVmZVZkR1b3pTc2lJMUd4dWs2UEdhUEY0R3lVTTdKNDNDK3BoUnkwUkFhdjFwdndyaXlKbFI0aHhwdUFzcnpSc09pa1JkUTZSVWh3c2FWbmhjYU8yWlhsNWVRMlF4ZFpVQnlwbzJRd1NvM1hqMVFKWnpFMHVkczBJTzV5eGdFZFN2T2MwQStJQ3c2bEl3eXVkcWZKNFdjZ2pxdmwvMnFQYkV3anNhcHF1aHc2c2lseHNBc2ZCSVI0UWRyOWZYb25SZzVkZ0hJNloyeWUwRmx6c2hvSnFqRWFsa2t6RzZnSXBBVHhmZ1hYNW0rMEo3ZW1ZOC9WVlRSWUpYdmlvUTR0RFpHdStHM3pDK2YrMXZ0cXhqdGV4eWFhcXJKbXhQYzRhV1RPSXNUNUxubFlSVHRpalk0dmR3U2VWb3h4SkZWekdNVHhLc3pCV3VueEI0bGxPNWNnR1RSSTBNMkFSSHRMYU5oY0xPdWhnYkJQakFUS1JPVnJaQTBqNGxoOFR4R05aQkYxNVNKdnNtcUlxMmVZQVFvdmEyL0NtQnV2V1JuUXRQSEdSd2lkMkY2QWJMeENKRVBkMkZudTE0QkZhTGhHUUQzWVdSRUNwNmZSVEFzb0RZUHUxSFFqNmRsQ3lnTmc5QzlvUmczMFdRMVFHd1FFbm1zZ1MrYUtHMldRRTBFRU85ODBlSVNlYTliMFJZd29RdzRTVzVDdzBQODBWN1ZFTlBDaENGZ3ZXSGtpdGkzNFJCQ3VwQ3JGZzBlU2wzU01ZcktXaXlOSUZzQUloNUptbGlCbmpIbTRmdlVkQ25DMjAwWjhuRDk2S2dMUG9Uc3Z4TjJENDFRdER0aTBIYjdsOWs1M3dkdU5kbDdhZ051NzNZbjhTdmlMczlqZlUxOUxJTGtOQUYvb3Z2N0JJQmlIWm4zUjhSRk5hMzNyRnl2ZzBvbnpsN0t0WS9DTThtRnhMZjFkcmZjVitodUh5NjZhRjNOMk5QNEw4OU96cUIyQmRxOGpiYUJab3R4MUsvUVRBSk84dytsUG5Hejl5dzh6TCtNdEhFQnQwalVWR2syQ2JrRndxK3MyQldjMlhvbXU1b2tjWVhiM0Zsd2JOT0ppanhBWFAybDJ2TWRZSWFHVUU3K3ErY08wT3FMWlhTWDROMVVreHlWbHBpbUp3MXVIM081M0tvTW01ek9GNWlpZzFhR0YzWDVyV2NOekNIVTRhWDMyODFybVBWenFlc0U4Wkl0dmNiS3UyR29uZmUwT1J1SjRkSEswaDJwdDdqZnpYekRteWtFVmErd1hXTXQ1OFppT0dtbGxlSE9EZE81dXREenJoL2MxRWtyUmNIYmRIR1FkVWN4eFFCbkFLcld0YkkwM1YzVnMrSzQ2cWlrMmtLNk9Uc1hsWUdPT3lWbTNWaE0yN1VxNXR3b1NpcHFXQUFsVk5SSnBjcnF0ajJLbzV6cGNWQ1hRNVRWTGJCRmRLQ2VGVXh5ZU1icTBnTjJoTGFDUmFZZTRFdFYrOXVsclQ2TFhxSGR3K2EyR1E2b3g4a3FTSFJIOE9sSUkzVnNYa2tYODFydUh1dEp5cjYrcG8rYVRRMUNXUHYweC9jcWFoZTB2TjFkWTZSN203NUxXb1hibmV5WjVIQzJxb212YmRMWWV6VFVoMStFeEdiMGc2OHBTbnUyUW0vVkF3a2JYV3k2NkZnNThLcGFZaU5vSTVWakUvWFNIZS9oVlhTTzAxTGdlTElHR09TMVJaVHVGMXJraE1zcmlmTlhreEJhVlRUQzBoWENFNmY5VzlXMEQybUlxbnR1UG1yaW5oOExTb1F4VWdEUTYzQzdwMk5ZaGZEbU12OWsvdVhFSzF0b1J0MFhTK3hpdTdtVU5jZVdrYi9BQ1VPYlRyRlUyMm8rWlZIVWdPY2R3dGhraTNGK3U2MXV1bzN0cUhQdWJYVlJvNGloeGI5VzYzcWtLdUZwanVmSkZ4Mm8vMHJUZnFQM3JGVkdURVBrRlhtV1lsZFF0YTJiNzFzYkMwUml5MTZHSTk0cnlqak5oZFYyeXdoc0R3TE5KL1BmZXN5TnM1cWt3V2UxSVIxY2pPSUVpUFphcmprNXAySGUyeTIrcC82dUxyUTg0eWh6ckR5Um9KUk5QY0RVVmIzSHpXOFpEcFRKaUFGcmkxMXBiVzN0YmxkTTdOSUx2WVNON2VTTU5jSFIzdU1VRGVsZ1AzS2dua00xU0JmcXRreFFobEw1YkxXS0NFellnT1Q0a2lLM01weU4veXBBUkUwa2RGczdwQ3lNOUVsZ2RKb3AyN1dSOFpxaFR3SGdiSjZld3J0V3pWOFlyRDM5cjlWZVpYZVpBMjYwdXJyZTlxcmM3cmRjcm03RzdJWFBjd2xFMjJXWVJSYkhleTFqRVNacEQ4MWQxUjdzZ2s5RlFWcjd6QWp6NkxWblBhaXNvN2l1ckdtbmhlU1FOanl1V1lyVmZwREVpejRoY2paYjFuYkV4SFJsb2RwTitpMHZMR0h1cmE0U1d1TlhYNXJNeVBleXhGYlRkc3FZT3hrVEhGdHRsWjVxcm00YlJPTFhBYzlVL1RzRkhRZzJBczN5WExlMFRIeEtYeEIvWHpWZjdwWVVkNXBPWU1aTmRQSUNTUmNxcWJJTkZ2UlNjNE91ZWJsTHhEOWI5NlMwYXNJcER0Q3dhNzJLdjhBREl0YzdWV3d0R2tXQVYvaGNPaUxqcWxNS1Q0THFtWmVXTm8zM1c2d2Y2TFJOSTJOMXF1QXczbEpJdjhBTlgxWk5ad2JmYS9DVlpsWmJiTmp5L0g3dzdVZk5YZGZWZTdRRm9QUlZHWEJhRzZEaitJQ0tONEpURzlxSzBJN21hN2ptSzJrZDRsVDBaRmRPRFk4cEdzcVRWVlJBTndyekJLZnVuTnVFcjc1YnJZalpjUFlHUUJvSFJGSVpBUzV5TFR0RFk5UkZ0bFZZdFdBYWdDbXhXeEZTZnhNWHhPc05VRFk4YkpPbmxKdTBnb0ZOSWFweCthOVdWcmFSaEJzQ3F5ZTVsdU1BV0pWd29yMlBvdFF4dkV3MXJpSGV2S0xpK0pDWXZKY3VjNWh4NFJzZXdQMythdVk4WmRoRklCbUhIajRnSFhXcHNsOStuQXNUY3BhZkVIVHpFWHZxSzIzSitYTy9jSm50TnJYNFYyS1NMaWFTTGJBc0ZaUlJOcVhBQXRzZVZydWNjZEZZN3Vtblpoc3RyeG1zRk5TT2FEWUFXMlhMYXFRMW1JT0FOeHFUR3FGb2R3YWpGY1d0SXRwOFc2MktTY1NBTVp2cEZsVGwzdU1JQTJKMlZwZ0ZLNE5KZnZjMzNTcE1Oc3RjTXAzT0l1dHp3ZW5hMW9MaHVxbkJzUHU4dUkyV3hNaEdzTkczeVNxc3J5a1gyR1AxdWFBRHN0end5SWQyRGJvcUxMbExxaUYyajZMWm9IZTd0T3dUcU10eXNEV1ZaZ3VOMHBEVk5rZHVDcFZkU1o1SEN3WHNNcHRUdHgxWEdKa1c5Q1dtMWdWZVUxT0pBRFpWMUZUV0kyVi9DNFJzR3k1dGJFdDBFSkViUUF2TmZydmRlMGwvUkRta2JUdEpKc3RKMGtKMnRtWlpBd0hkVmMxVmE5eWs4UXgyTmpqNDFyT01acmFBUTBoSWNrTVVDN3I4U0VZUGpBKzlhOVY0OWE0RDcvSXFra3Jac1RObWs3K1JSNkhMRXNyMnVjWDgrWlNIeU1YQTFTMUVsWkp3U0NmSlg5Rmcrb0J4c0U1UjRQSFNSdDIzc09pYmpnYzUxbWpaY0ZKQUJUaUFXUXBpUnduNmlBeHR1NVUySVlwRlNNY1hPQXQ1cGJWalZFWURnMXBKTnZtcVRGOHdNbzlYNnhvdDZyVXN5OW9yYVZybVJ1YjVMbHVOWndreEI3bkdVajVPUzlySEtETi93QWV6d2FndWExL290T3hETmhpWTR1a0gzRmFOWFpsTHdSci9GYTVXWW8rZHg4YnZxcmF4bWtvSTJYRnM4eUdSd1k0N3JXYXpFcGEzVmQxN3BUNCtkMUtPbmM4OEkxRklQYWdiSXJHNTNVM3g2enNFOURoeElCSUtkWlJCdlQ4RVoyaEdDaDFsdHdySnVITVpIZXc0ODBkb0RCc0I5RVJsTzZmaTZIY0ZRdEJwaVBCUldTYWp3VTAyajdya0x4WTJIY0Q4RkxPMEJNR3Zvc3NnYTNtMzFXWFZianNBRkR1WHpHKzQrU2hLQ3RsamFkdGxKMVU0RFoyeUg3blljbERmVGtkU3BSeGtKYWtHNWR1bEpwbnpDMFhoK2FZTU51Vm51d09pSUZsZUk1V245WVE3NUtaZ2trL216YjVwdnV3U3BobGtkQU1SYlJucWlOb3RrZTkxbXhzaVFMQUdpVXpSdHR4K0tKcklXYmxFZ1JWOUlQSkJkU0R5VHhCS2dXRy9DTkFpSHVZdWRsNDBUUjBWZzRBTjRTc3JySWtFSlBwRzM0VURTTnQvZWp1a3NTZ3ZuSG1pQllGOU0xQmZUc1U1WmZWTE9sdjFSQUdDeG9LRS9TRjV4dWdQS01BaTl3UW5FQlNLRTlxTkFncENFRnpnaU9qK2FpWWVxSUZpNWI2TEdrRkh2MHNvbVBVbldEUUhTMVlESXowUnZkcithSWFZTkYwTmd0QzNkRG9GalFqbnc5RjY5K2k1WUZFSStMSGxZYlR2WS9YcUdsVElzTG9FcytrV3VvcE1Od1ZFNnlvRG0yYnlGR2l4dWFobWJOU3VMSm1jT0tTa211ZVZDUnhiR2U3RjFZaGthSzhzYVBxZnNJOXNyTWVUS3FHanhXdUw2RUVOMHREdmgrcFg2R2RsbmJyZ0hhWlRSeVVVN1dTUEY3U1NBSGoxc3Z4UGdMWkluQjd5eDF0ckxkK3pMdGR4WHMyeFdDV25xcFRHeHcyZktiS3pIT3lyUEFtZnVreDRMV2tFRzR2eXMzSG12bC8yYi9heHd2dFRncEtDdnFvNDhUczJOa1RDRHF0dDZlaStrSktoeDBtRHh0ZHlTdGlPVk15SlkyaDdVTDJ1cERoSnRqY3c5NExseDJzbW0zMlQwMDBJN0V1cTh2ZFZnOHBjZzBZVWdicU4xa0VEcW1zNnpEdXFTcXBHc2FaSDdNSDJUMVRqaUEwbTRBODE4cGUyUjdVOUoyUFpick1NbzZxMk9TUmw4TXNidFRXN2RiZk1kVVdPTnNUSm1yKzJKN1p0QjJWWVEvQ01IZTJ1cnFwcGljNkYzaXB6dWI3a2VYNHI4bjg2NTJ4alAySlNZcGl0ZExWeXkvRVpiWE85K256V001WnRxODc1a3JzVnhLVHYzMU1uZUZ3K1ZsUnlOZENTNi8raS9aYjFXM2h3cWhEWkYyZ3N2RXdNUG1GS0NKcEJjOXdjNGRDb3NxWXo0R05JSldCQkpHL1c0Z3RQa3UwVmlZbE04aFlSWm8zV2ROL3VVcFMwdHV3V0s4T0YwRm93QlpTMHJJQ3lpc0dqQUM5WlNhdkVCUTdRZUViTHhGbG1Ld0N6ZEdpR0FFVURaUUZpVVZvUnJraEVCU0RWTUJaQVVGV1JzRkhRakJxenBDZ0xZSU0yV2RDS0dyT2tLQTJEMEwyaEdBV2RLYUNEMElzYk4xa0JGakNoQWIyTEFadWp2YW90YW9RdzBXc2lBS2JZMFFSaE1Rb1hMZDFuUjZJNWlVdENOQXRpM2QraXl4bG50TnVxWTAyVW9vOWNqQlk3a0JFQWZSL3M3NWVPWUlHdkRia1BEZnhYMjlsZW1ORGdMNlIvV1BUWS9OZlBuc1o1WGF6RFErUnV4bEIvRXJ2T000djdqalVWTXkrbHo5TzN5WG5zdm1hc1RqdUs0R2NMN1J6VUJ0Z1hzRi8vVVY5blpTZjNtR1VuL3ltZnVDNEhtN0xJbnhDS3JETGt5dDMrOWQ4eVkzL0FFQ21iNU1hUHdXSm03bC9HWHNnc1ZUNHJLSTdxNm5GaXRYekxOM1RYYjJXZEx1WG9tbFo2cW14MHJ3RDAvZ3ZuN3RCOGRGSThIZXk2dG5uR0M2R1FGMXRseGZPZUlkNWg3eGUvaFZLVExNVlp5aW14TjBFbW5VVTFVNGhIUEFROGkvcXRSeEd0TU0reDZxUm5mT3dXY09GWDVMS1hCWjBXSXlVVmRlTjUwNnVpMmV1eE51STBoRHpjN25kYytGUVlKQmZkVzlMV0dWbXhSUllMS3JGYk1ML0FKbGExUEo0eXRoeHQ5ZzVhcFBKWngzVHlSRzJPMWhCZUxLTkhKcU81VXFud2hRc1Z3STFUZFRTdGR4QmxuRXJZWHUxQXFveEdPNEtnaVhjcFkzK01LNHBYK0FLbEcwbjNxMHAzV1lQa2hhRFJkMEQ3T0MyQmgxc0MxV2hrT29MWnFOMTJEZEtZNkllQjJpUlh0TzdVd0xYaWJTaFhsQTRGZzNTbU5Rdmp6LzlFZDhsclVMOTFzR1BIL1JYam5aYXpFYk9OMTFuS0x5Ri93RG9yVkFONUlVSVhmNk0zNW84QTFNTjBEQ1JZVWsxb0hBbm9rbU8vd0JKZFpTRDlESEJCcHpxbU4vSkF3eGg3dkNWVnlpOGlzSHVGaXE5eHZKeXVIRUUwN0MzbXJpa0JMQXF4bzJIelZwUlRBc3NvR2dzemRjWnV0bTdQc1JiUVZrWUp0d0Zyd0dwcnY0cjJHeU9wNjFoQnRad1VHSkgweWExc3Bnc2VXRDl3U1dKdWJvSjJ1cVhMTmFheDBGemV6UUZZWTQ0c2JzcTdLNXBWZkgzK0luNWo5NnNhdU1DRm8vb2hWcjV2OU9KdXJLc2NURUQ2QlZKbG1KV3h0QWtWMVMyRFFxTnJ6M2l0cVo1TWYzS25MdVdFTnlTaHp3cHRGM3RWYkhNWFRENXEwaUdyVFpBanNSaXRkcHBpdWI1a243MlZ3K2E2RGlyaXlsZDA1WE04VWRxbWQ4eWpSWlM0RktlTzVDNjEyYTBvRFdtMzJmNExsdEkyN21yc1BaMDBOaWJmYndubjVJL0lYSXVzZnFkRVpiZm9oWlZwZmVLdlZhKzZCbU0zZVF0bHlCUWg3cmxxVHArU2xJM2ltakZOVGk2MWZObUl0RWJnRDBXM1lzQkJBN2NENzF5ekhxaDAwamhlKzVSYWg3VUw4eXVwWk85cXJuelhUY3JCdmRONFhPY09wck9CNnJvZVdHTzBnZWlxNFpOc2NrWGxjZFlWRFh1RWNUbkU4YnJZNm1MVENTZGxwT1pxenVhYVFYNkxVMU1xUlh4S3pubWJLNTFaVTkyMGsrSWZ2VzM1SHdnVTlNMTcyaTVzZDFxR0MwdjZWeFh4RFVOaXVwdGliaDlNeG8yR2tmdVZURTkzYzdrNEt2TWVMdHBhYVJsN2JMaE9ZYXAxYlh2Sk95M3JQbUxGankxcnIzUFJjMnFwamJXZVN1WmxSZTBxdENza21uWlRwL0U2NlNxWkxPVEZBNHVJUzJ1Qzlac05GRVg2Zm10bWdZR01hUFJVdUR4YTJnMlZ3MTEzZ0t0SUdSczJEdEVjYm5laU4zcHFLcXczM1N0TS91Nk1uZzZVYkx2K2tWbTZyc3BUaWI1aHBiUzBWenRzRnBHYXNUMXl2YUQxNkxaY1hyUGRhRWdHMjM4RnpTc3JEVTFUNzc3cG1kMGhHbVZ2a0poakRMVVhLM2pDS1VQTFN0Und5UFRLTnJyZk1PYjNFQWR4d2h3ZkVQMUhDRDE5UzJtZzBnNzJXclN5dXFKRGZxbXErc005UVdYMnZaQnFJMjAwZXE0SDNxemxWRkxIeXdRMDRmR1NTUE5hdmpXSmlVdU43QUkyTzR3WGd0RHZSYUxqK01lN1FPT3NYdDVxdGlqYk5lTVN2ekxqNHBROEIxeXVjVnVJT3E1bkVrMnVzNHZqRHErb2NMM0NUaWpNc2dhMGFqNmJyV2pHa043RnBnV0dHdXJveGE0MUxxMDBMY0V3NW1nQzk3YktweVpseHNWS2FoNERTQnEzVXNmeGdUdWtoSjJhQ1VFblRFUEkweldjNFltUTB0YWVRdFdvNHJPTXA1TzZMWDFacjUzWFBCSTNVNE4yaGdIb255N0Z4ZGg2bmpPSU9hUEkzVzJZZEFHdGFBT0ZyK0ZSKzZrSHoyVzU0SFI5NnpVUjFWU1J5WFl2TUxab2hQblpQWWRFK2FxSE5rbEcvdVBDcnpBSkdtUUYyeTZpbk5tNlllRzBjTGIyNENkZFdzZEU0M0hDb1o2b3ZhQUQwVVhQSXAzZUljZWFqWm1vYmpyNDNWSkd4dXRpdytrSXNSMTNXa1lOUlNWTmFDZU9WMDZoamFJMkR5QUNLUExPc1pvb0NTRmFPaWExdHlRTEpBenRweGU0SDNxanhuTklwMnVBa0hIbXIwSXBvcVN1eTd4SEc0YU5oOFEyOVZvMllNNkFod1k1YWptSE04c3JuQnI3ODhMV24xcjZuZHhTWlpDL0hFalpQMDFMV1BObkZFZ28zVmovRVQ5NnFjSE5uRFlyY3NJcHk0aXdLcjdyWjF3U0hjR3dlT0t4SUYxdGNGRXhyTmdBbGFDaXNMbXcrYUpYNHJGaHpkNUdpM3FteDVLYytHR0VUbUh4bXc5VkdweGVtb0l5WE9iZXkwZk1uYVF5QmpteHlIWWRDdWQ0dm5tYXVEZ0huNzExY2psQTZQai9hQkMzV0d1SEhRcmttYWM5enlpUU1jNjIvQzF2RXNWbGU1eEx3dFR4REhtalVDYm4wVFl4VExNSUQ5WG1KMDczR1YzMVd1WXBpMTNFUjc3OUZYMWRXYXA1MC9pZ3NacCtMZE9XSkZsUVFZeW1UcXBNcHk4b2tWRWRpbllvUXdCUWlrQ2hvK05sWU1oWTIyd1EydnR0WXBtS0Z6eU5rdHNZbVNZQndBanNwM1A2Sm1tb0R5UXJHS0ZyQnVMSlRrR2tJeDRmcXNqaUp0T0VlV1VRdE52d1NUcFhUdXRZb0V3ajBrbmVYQVMwY0xuT0lkd25ZNmZUdVVRMk93NVJvZ0JsTkdCYzJVWHVhemdCRWZBNXlFYWNqbE1SQWI1VUo3cnFUZ0VKNzlLNkN6RG1YVUMzWmVkVVdRWFZTTkFzSnBVZzNaTCs5RlNGVnNpQVlac1F1aWFBRzhwSTFSRys2ZzZ0ZGJxb2dXTXlBQW9QdkRSc2x6VmwyeUM2L21pUUxIeFVOOHdzbW9aNktzTG5EcW9HUSthTkFqOGs0QUtSbm5DQkpVSHpTc3MxMFNDQ1NUODdwWjBwUFZDZElWbTF3aUJaNTd5aFh1aWx0MWd0MktJQUNUZFFjcGxSZHlqQUJ1Q0E1aFRTeTRDeU5BaVdncndZVWR6aGRZMUMxa1FMQTZHK2lpV1c0UlRFUnVvT09sQXBuU0drckF1NDJLbWFnQzZWbHFneTV1bXJrQmpEb20yM3NnUGtZenlTY3VJazdYUzVrZElicGlRTkRNdFI1Sk9SNWNVWFRzaHZhRzdybTFCWHdEMDNDZ3liM2QxbkRVRjU4dW02bERHS3VuYzkyNUJzdTBMYkJ6dE14RG1PMGpxQWlHUnJJdzB4OTQ3aTZ4aDhENXBIc0d3QzJUQ2NHaU0vd0RwRGJydklydVR5TmkyTjVVeEtLdnd5cG1wNVdHN2U3dGZ6WDZnZXl6N1IxUG0vQm9zT3hpUVFWa01ZWUh6SGVSMXg1Zk5mblJoallhYVZwRzdSNUZiamdHSzFHRDRsVFloaDVNY2tMdGVvaE53NW0ySXk0VlIrd3RQK3NmM3JYNm1IaHFiSFJmTy9zM2R1emMrNFRUNGRXMUgvU2pRWFBrZWJBaTNyOGl2b1lQR2xwMUErdDF2WXBXakV5UjJzbDFXQ0Y3VU50d3Nsd0hKQ2N4YUZaSGtuVVBoSEpYcDlUbXNMZU9wVVk0REV3eE9mcWNlcVh4ZkZZOEhvSktpV3dpaWJkN2p3QXV3VE9TZkJ6ajJnZTJDaTdJY2oxR0l6enRqTDJ2amFYMjVJc1AzcjhSdTJydFhyKzF2Tk5aUFZWRDN4ZDdJMXBFaFBoMWJmZ0Y5RiszL0FPMExKbnpPbGRsYkRhbDN1Tk84U2lSaDhKOFIyLzVWOGFTeXRrQjd0dWwzVnc2bGEyR0tSbjVIWUtza2JTc2lpak9vOEc2TEpmM0ptcnpXSUtacmdYUGNIT0hGMUVQTXI5Qkdsb1Y1Q0RMV2l3MlJPbm12QWRGa05Ra1BBTE5sbXk4alNJZWFwV1dHOHFTTkx5SVljREgwWG10RHR5c3p5TkZnSEJ4c3JDaXdDdXhPTC9SNmQ4bTMyUWs2ekRnMC93QWU1bHJSWmMydFhndUt0aU53ZG1sZXVyaUxKMk8wcHU3Q3AzRDVEODFQL0pMR2VmMFpOdjZmM3FnK3FhUngyT1pvcm8ydXdUdFkrSmZtaW1hanN0d3JOdVVjWi8zWk45RXpIay9HQ0wvbzJiNkpXTHF1ajB6dmVYTXZzOXJYSHhZdzcvbWlzYTF1MjZJMXJmTld6Y25Zei91NmI2S1l5ZGpQKzdadm9FRDZubysrL3dEY1ZIMloxYS9nZnpSVUJyZk5lN3R2bXJzWk94bTMvWnMzMFdmOGpzWi8zYk45RTZIV2RGSHZQNk1YUDJhMWY0SDgwVVlZM3pVaEcyL0t1eGszR1A4QWRzMzBVaGs3R1A4QWRzMzBTOG5WOUZMdFA2TUtIUWRYRCtENm9wZERmTlpFYlQxVjUva2RqSCs3WnZvc2pKdU0vd0M3WmZvaisyTkYrUDZNVi9oN1YvZytxS1FNYjVvb2phT3F1UDhBSTdHUDkyemZSRU9UOFlzUCtqWmZvdS9iR2kvSDlHVC9BQTlxL3dBSDFSU0JyZk5aMHQ4MWNuS0dNMi83Tm0raWova2hqTi8renB2b3A5c2FMOGYwWlA4QUQyci9BQWZWRlUyTVg1UjJ4amJkVzdNcFl1YmY5R3kvUkhibExGN2Y5bXkvUk8rMXRMK1A5d0oreldyL0FBUDVvcE82YVZtU0Y4WTFCdHdyMDVUeGUzL1owdys1Wmp5Ymk1cDNhcVNYbnFFeGRXMHY0L295ci9odlYzOXgvTkd2aW5mVUM5dVBKUDRIUTFGVmlGUEZISHF2STM5NmVpeWJqR21TMUpMeDVMZmV5WEtOV3pHSVhWZEs0TkJCSmVPRVgydHBhKy85R1dvZXpXci9BQVA1bysxT3dITDV5NWxXT1F0MEVoamliVzZMYUpHUTRoaStvT3U1cjdwWEFNWnduRHNwaUg5SVFzazBOMnViamI1TFZjc1k3U2Y1UXp2ZmlUTzdENzduNWVpOGxQcTJHL3ZmdWFzZWhhcjhIMVIzWVlPY1F3dUpoWmN0ZGU5dCtpM2JLVk8ybGlhQ1R0WUxuMURuL0JJZ0l2MGpDU09seXJxaDdUOEFwQnZYd2MrWldkazZsaWY4UXhkSTFFZThXZERuZXd1NVdrWjJramF4L2lJc29TZHJlWDNnMnI0TC9NclRNMTUrd2F2YThzeEdINUFsWjA5Zmk5U3hEcE9vbHdvczVqMmdZcTc5WjBBdXVPNWd4WmswTDJGKzlyTGVzOFpqcDZ5T1VSdWFlUUNGeFRGZS9ucUg2ZFdtNnoxcnNTZjNqUmgwblZTL2cvWTFqRllnS2h6cjdJTk5LR0g0aW5jU3cyZHpTYkVsVlRLQ3RhZitydnNySzZsaDdXTWwwWFZmaCtxR1o1Z1Q1cG1qa0pHeVNiUjFaSXZUUFZyUTBzN1FMMDdrTDEyR1htQXVpYWwvdy9WQ0dLYWpHZXV5MDZ0TnBEMDNYUXEra25rWVI3dTdoYXJpR0MxVDNHMU03Nkt6cDlWcE1TcHpCbDBIV3psdVVQcWlvcDV3MjI2c1M0MUVkZ0VxTUNyVzhVejFaVUZEVnRidlN2U1o1OUx2Mzd5NjlIck1jUEQyZmtVZFJHWVhtK3lyNnlZT2FWc09KWVhXeW53MHIxVlNaZnJpMGwxTThDM2tyUzFPbHpLbE1wUTZMckc5MG9mVkdwdkE3dzc5VTlCYlFOMHZpRkMrbmViN0VkRUtubGNOaXJGR1JWT2krbzVMRmJGaHo5Z3RYb1hnMlYvUlM2U0FseUd4TFFtN3dWWTB6dGhZMlZWcXZZcCtpZnFza3NhZ3VNbnU0ZlBicXRWRDljeDZDL1JiTmlaN3hsajVMV3FrQ0oyM0s1REY3ejhTRmUvNW9QdzlxTG1sRWVnWEpUVWNma3FqREtPZXNzV2F2UFpiQkJTMUlzUGQzZVNETDFHT21YaFA5RFgwL1J0WHF2OEFPakQ4KzZGSmhwQ0FLZ05OdXFzNXNQcVhOLzZzNUlTWVZWazM5M2VzbVhVWVFkMmJVZW02eGZBNGZzQ25jQzNZcE1BYTczS3NIWVRXbHY4QTFaNmczQnE2L3dEMVo2ZDd6aVhObWJxZWk2cHpUVWZxZ2tHblNuTVBjTmYzb0VXRlZvSC9BRlo2ZW84TnEyT0grak9RKy9ZbDVsNlBTdFRIRjkzeS9JY2t0b0Zrc3doc2pUNUZXQW9xb3MvNnM1QWZoOVZxL3dDcnUrYTU3N2k5UmVsMEdwakozRTZwMmZWWW5qWUE2OWlBdG16RElZcVluMFhQOGdHVER5REpjZUsrNjNUR3NTanFxUXRGcjJTSHI4WHFHK2xhbjhQN0dqUjFna3JnQ2VTRnVWWlR0aHdvdi9vZy9ndWVPcHBmMGkwdHZiVU9QbXVweFVEcXpBN0huU0IrQ3J5MXVKK1pJOUsxUDRmMk5PcEoyelNPYnNyeUJ6YVduRjdlVzZvSktKMUJVdk4rcVBQVm1XbmFBZXFyUFZZbjVseVBTOVRYM2YyTFNuMGpVNGIzTjFZWWZJVEx4MVZCUVN1MjFjTFlLR2VKZzZYWEk1TWZxYyt5OVQrRURtYVVDQjFqWXJsdGRVemg3N3NGcm5kYjltcVY4elhDUDhGeitmRDZ1UjV1MTFycXo0K0t1NVBzdlUvaEdNRGNacWxvZnR1dTY1TXcrQTBtcldRZEo0K1M0NWx6RFRETzB5QzIvVmRveTVpMUhSMFphNTdBZEpINEpjdFJpOVNmWmVwL0NJNG1ETFdocmQraTZia25EWHRwV3UwMjJYTDZPcnBuNG5xZlVOdHFQUHpYVThMelhoMUJRTmFLaU1IVDVwR2wxV0pQdVZjblM5VCtFSG5iRWZjNG5OTHJGY3ppcVh6eXV2dmR4VnJuakg2ZkUzRXgxTGJYNmZOYTlUMWRPd0Q5ZTFKMW1xeFB6RHhkSzFQNGYyTDJqaS9XTnVUeXVtNVRZTzZhYlgyWEk2WEU2ZHN6U2Fob0YxMHJLK2FjTnBZVzY2cVBqcVVyU2FyRjZoWmVsNmxjN1RhcStuTlRHWHV1MW8yMlhKODZWN1hTZTdzZGMzc3Q4eHZPK0hQb25zaXFZd1Q1RmNtZFUwMVhqQmxrcW1sdXUrNnZ6MW1MMUtxNlZxWHlvbXhaRXdSMVBhWjdPaDNJOUZaWm94SDNlbWVMMk5rM0JqMkdVdEZwanFZZ1FEd1N1ZTV0ekl5b0wyc2NDTitGV2VxeDMzR1I2VnFmdy9zYVZqbFUrZXNjU2JpL1Vxa3IzaDdMRFpXOVNCTUhPNnFqblk0dklURnFjZGR5N0RwbXBYYUlpVzk0Nnl0TU1vM0Y0MlNkUEFkZS9tdGl3MTBjUUY3THVMWFEyTldIOW5hNS93RFQvWXZjT2lNY1hGdGltS0ovNjdmelM4T0tRc1phNFdLV3FwaEpxOTRhTGxZcjFLOGE3OHh2MmRySktuQTJHb250QUFQSk41ZnJtd20rM0MxK294Q21NWUh2TFVLanhXbmhKLzBsdkMwczJ1aHNTRS9ZMnFiNWo5VWJEaitQUG1CYUR0YXkxeUl1bGt2WkJyc2JwM0g0bWxTb3NSaWZ4WlZ2ZUZxT0VLejlJbnBGYlJzdUZXWVczQzJTVEVReUVDNEd3V29VbFdMaXhWbytUV0FkWFJhMm5YaHEyZVp6WW5PVkJYU0F5Ri9yZFVlWU1iREd1YUhLZUs0bTJtaU5uYjJXZ1lwaTNmU3VKZDZydWRlTDJEeGFaNCs1T3V4blJHOHZkYmRjcnpYbU16VE9ZeDl4ZnpUK2M4eXRBTWNMdDdkRnBJQm1Ka2tONzc3cXpwc1d6dWFXN2dQVHU3em5rN0xkc2paZmQzelh2YnFCTjl4ZGF4Z3VHUHhDWmdqRzF3ZGwyWEFLRmxEVHhsd0FJQVR0UksxUURrRnI2Z1lmU0JvT25iZ2JMbmVONGwzMHJ0SjU4bHNXYjhXYTI3UTVjL2txaEk0a2xWY1dOc0M3QXp4V2t2ZTExWTBoYUdBZGJLbGxxUzV5Znc5c2tqbThxNDF3V054dFdEMGhtYzA4cmQ2SWR4R05yTFhjdXdkMndGM2tydGsrcDFncTBvZ05qN0g2NUFydWs4REFSdDhsVDBrTjdPVm15UzFnRldjZVJiWmQwRS92QjBrK2lmZGgycXgxTytxcHFjR25zUjgxYjB0UzV6ZHlVNmlrNGw5Z3RNMkVEYmRYYjhSanBXWEx1RnBjbVBzb2dmRnd0WnhmT2JuaHdhNHJ0RWpIazNETUdkV1JBdGErMzNyUXE3TUVsYTgyZVNENnJYNm5FWks2UWt1TmxtSzBZNTNVb3VRaVBNZmNrdWNYWFBWRWEwdmNMQkFnaWM1d1Y1UTByV0FGMWtwVEhTalk5ZzhaWTF0MmhibmhlSXcwTFE1eEgzaGFjN0VJYVZoc1JjQmF2aXVhbnNEZzF4UnAyVlhqT200NzJoUlU3QzFqMmcrbXk1dGoyY1pLNXpyU25meWN0VXFNUmxyWEV1ZWZ2U2trell6NG5JMG1SWVI5OVUrY25VOXh2NW02cXNTcm1VekQ0a3BpZU94VThaMGtYOUZwZUo0M0pWUElEalpYVkFkYUdzVHg0dmM0QjNvcVoxM2tra20rNmlHNnQzSDZxWTJSSlVUdVpqalRMSWJxTUxMcDJLSzlreE1MYTJZamJzbUdRbHhDTkhTMnRzbnFlbHZiWlUyeXdScEtTOXJqNnF6anBlTnZ3V1lJdEZ0azZMQzJ5QnNnTmt2Y2kxZ3ZPQnFEdHQ4a3d5azcvb2p0cFJDZ3M2SmpEbWpja241cVFwMk02RDZKclE1MnluSFNGeDNLYnVJSkVEaXlGSkdSMFY0ekRXa1h1RUtvcG1nV0ZsemNRb2pjSldhNUt1SktjWFM4bE9QSmNzaFVPaHNneU5UOHNSTjlrdVlIRXBxWXF4RjBWK2loM1lLdEcwdXlpMmxZRHlFU1pMSzhVMTE0MHlzekV4bzVDQkpwRjl3alRKWlhOcGQxTjFMWUlwbUFRbjFJUm9UdEZaS2V4UzhqQ21YekFsRGtJc2lRTGlMYVNoU01OMHpjSWNqZ2pRdmFMeXdFalpCOTBQcW5DOFdXTzhiWk1RM3lFSDA5dWlEb1RzN3gwU3hjRWFCQWtGUklLbTV3Q0U2UUlnVEJZUW9sdGxoMDRDQytvUUNncmdoRWVwUW5WR3lBWm5ibzBBeHJaWUpBQ1NkTTdvb0daM3FqQUdYMU81Q1dsbkpXYkFyQmpCWFVHTFBsSlFYRXZUeGdGa05sUFlvMEN4SVV4dWpNaTBwcHpXdEI0U2tzb2FTalFESXZlZ09OMTV6dGxIVWhvWFJqUmZheWtIZTVqU091NnlPUFZESUxuWGQwODExY0Vvc2NQRFkzZDY3YnFyR2JHVFVFUndnWEp0Y0tsaVpMV09iRkUwK1d5NmJrUHM5ZE1HUzFBOWZFRVc0NVFYS2VWWjZ1RVNTQjI1QlcrUlVjV0hVRWdkWUVONmhXaklZTUpvN0FOYUdnTG0yZHM1c2laSkhFL3dBUjIyUzB1UjJEanVPWUgyNzFQWjFtbW5OTktHTTcxalhIVmJiVllyOVR1eFB0U29lMVBLZE5WMDg0a2UyT05qdEpIT25mOXkvRUNvYzZ2cTNTekM1UEJQbXZyVDJIdTJxZkkrWnFUQ01RcW5Ha2xsRGlYbndnYXY3MXA0SlVVdGRGU1hCK3FMMnlkMjdtN1BoOVZtbmMrc3BtOTc0Sk9vQ0RoT0pSNHZoMFZiRVE2R1Z1cHBIQkNaallkWGVONFBSYmVOMmp6dFV5YllqcTF2SUpIVUw1cDl0anR6cGV5dklOVFFDVzFYaWtCamkwRzlqY25lMy9BQXI2T2RWKzU3U216ZXBLL0dIMjdPMldUUFBhRlY0UXljdlpoMVNXQUIvSGgvOEF1VnJISGtUT1I4djRoWDFXS1Z6NnlxZUpLOTRzOTQ0SS93QVhRR1BqSGhhQ0hIa29ieDNKMUVuVWRySWdGN0d5MU1jU2pKa2RFa0w5UklMVDBDbkk1c2dCWUNEZFovRlNEVllBUmtIWUxJc1ZCU0FVbzRUSjJVVjVlUklobHZLeXNOV2VVUkR6WUlqNHdOd3Q0eUgyaGpBNnRzVHRUUmUzQldqVHQ3dDdTMDlGT1I0ZEcwL0NRT1FzL05vc3Vzd3krSm1ocHRaajAyb2psakZVajdFeS9tVnVZYVJybzVXbSsvS3NEemJxdm1Mczd6KzNMMDBiSkp5UVRwczV5K2xjQ3hPREZhQnRiRTdYWUQ1Y0w0SDF6VGF6UWFodFRsVnYxUitvZlovVTlPNnRwRW5DTzVSWG8zYkdtMnVtV05zTjlrdEZDSkhQbXVmRHZaRnBwL2ZwaVRzTFgyWGtjMnIxV1JmZmZ6UFhhWFI2V00zanlZMVM5VU5nRzNJVTJ0Y2QwT1NtZlVVN24wNDFPYnRaUFVVY2dnRWNqYk9jTEZkeDZ2VjVPRk4vTVhxRjAzRjNVUG9BQU5yMzJXQmZ6Ukh4ZDI4MHB2WnU5K3F4b1kzN1JVeVpOY3UwNWZVcHd5OUttNnFIMElqVjVxWGlVbXRaNXFRRVk2bE13NU5iTCtPWDFIU2gwci9zK2hIeGVha05YbXNFSG9zYVhlUlMvRjF2NDVmVVhYU3ZTSDBKNythanJkNXFQZHU5VjRzY0J3dWVMcmZ4eStwSzZWNlEraE1GM21zK0x6UWcxM2tpTkJHNTRVOFhXL2psOVNWMHIwaDlDYld1dnlBbUdNZlpDaU1GUTRXZWI4Ykp6OVkwTlpHME92dHVsKzk5UzlaL1VDYytsVjJoOUFPbDNtRkV3dGw4SUhLNkJrL3N4cXN5Umg1amZ1TDdYOGtITitSUmxVaytMVUJlemtYdmZVNnU1L05sRHh1azc5dFEraG83b20wekxXNVE0SFNRT0w0enBCRmt6TDNsUncwV0NpYWViUnN6WUxudnZVdldmMUwwSjlLOUlmUVdaRzJwazBIWUhtNldpZ2dwS2g3V3NJY1R5bTlUR25teFEzbU1tOTkwWGo2My91K294VDZWL3dCbjBJeHNkRld2ZVR0WlJrZjNoSUM4NXpML0FCRzZ4WjNrbHZMckgrTDZqb3o2Vi8yZlFpSWkzZFpZV1BObkEzV2ZINUwxbmVTVzU2di9BTHZxTjhUcFgvWjlDTDJTazJMZ1dyeGdqWTI1RzZreHJiN3VOMTU3R25hNVhYNzIvd0FYMUF4VDZXdWZnK2dBVTBkUWVQVkhGTy9UczBrRHlDTFQwcmRRM0s3UDJaZG5VR2FjSGtsa2FkSWNCY0Q1cGRheS93Q0w2bWZyZW9kTHdLNmovU2poY3NMMmMrSDVxTFhTTTNCKzlicm4zS3I4SHhTU0NvYVlvUSswUkErSUxUMk1MYWwxTzRmcUdpNGYxSlhGbTFVZTdZN1I1dW41MG5GUitnSXZrZHlWZ3hrN2xHY0xHeUc0aEt5Nm5VS1hFMmVtOTMwcWgvcHI1QWl5MTBMK2FkNUlqanVoeXdTVEVQQThRMkFUMW0xRTQvZllqRDAzUzVKT1VvTDVCRzZUdVFxYkhzVmpvNFpCZTJ4NnF4cUhTUjA3blN0MEJvMnN1VFoxeHlXZWQwTVp1d0c5N3IwSFN0UHFzazdjblI0ejJtMTJqNmJGeGhDTjNYRkx5Tld4NnZiTFBLUmMzY1ZVUkVPTjA1V3VnY0x0ZnFkMSthU2hjMlIyazdmSmZXRXVEODdOM0pzc2FaNWE0V0t2NlYrN1ZyYlEybklJSk8vVlhkQkpjdFMyaHNTL2FmMVlUK0duZmRWc0k4SVRzRW1ram9sTkRVTTRrVGI3bHJWY2RKdXRwckdoOFlQb3RYeEdMeEhjcG1LWHU2MnNiTEppbExmdFhCYlpYeDlsTEl4cnI3N0xxVkc0elJOZTF3Y0NBZGpkY0ppcm0wcmdMMlhSc2o1bDdpSDNkN3RXc2crSTNLOGIxckRra25saGZtejZoN09kYjB0ckJPQzhsM041SmZ4ZGVhMHUzdXN2aWtNQWtJczE0dUNobjlSU3NlVHVUWmZQUGVjc250azJmYk1PbTBlV0Ntb1I1L0pCdzdjQWxHYUw5VW82SHZaR3NKSTFDK3lZcDJ0a0pZMGttUGxSNnpQUHMyRGwwMmdTdHhqOUF3UFM2TDNUbTJJSVFOUmRLUTRXVERYTUEzY1Z4UFZ5NVc0eGNtbzZaRjdIcytoZ09lT3E4UTRqbFM3NlB6VWU4WVR5bXIzdXZQNmd4bDB4Yy9COUNjTFJIR1MzWXFEREk4dUIzQ203UiswandTUnRIS3FWcS84QXUrb0wxUFRGK0Q2SHFLallaTlRoWXE4Zm1FME5BOWpYYkR5VkJWVHNCMmRiNUpaK2x3c1hrajVvbEhWL21KZW82WTNkdythQzFPSWl1TGliMzlVczAyWUZIdVdEaHhSR05ZT3E3czFmNWx1T3I2Wlg4SHpRZUNYVU50a1pzcjJ1NVEyNkJiZEVhWS9OV0g3MHZVSDN2cG4vQUdmUUs1M2ZmRWh5QzRVMnVqdjhTSU82ODBEbHF2UmcrOWRNOVlmTkM3SWhmY0xMaVdtdzRURjR2TlMvVlc1UzM3Mi94ZlU3NzEweSs4UG9LZDB4c3JTQnVpMU1qaXhvQjJYaTZPL3hJYjlCKzBWM0hpMWNmVVZQVTlNUy9nK2hGcldGbmpGMEp6bzJjQXFSYTAvYUtqM2FYbHhhcVhxSGkxUFRIK0Q1bzgzUS9nTER4TXo0SEFCWjdzck9nMlNZWXRWSHlsOVE1Nm5wbi9aOUNMWkpXL0c2NnlHOTRkdVZpNUNrQ1VmaDZ0L2krcEhxZW1mOW4wTWtTeERuNktEeStiNGlpYWoxVVpEcllkUEtZc09xL1A2aS9lZW1YL0I5Q0dzc2JhNkE1Z2NTVkpvZWJ0SVVHTmRTeUZ6aHR3YnBxeDZwZW8rT3A2Wi8yZlFWa0paZTNLRjczSmV3UENhcTNSeHVGUkdkVVRmaVBrVXUrQm9hSm9Eckw5eUQwUStOUEh3elkwMHREblh3eGo5RHdxSkhEY3JMV01idlpaWVFXWGs4TC9JS0RKd3hqbW5rOEpMelN1emp3YWFVNlVFUmtld25qWlFibzZEZFJCQmNiOEZRY1RTdUxtK0lFVzNSK0pQSndnTlhwc09LTjdGOGpMeEk5OXRRVjloY2NrVFFYRzEvTlZPRDBBckg5NWNrMzRWeTd2SjJQRGhvRUEyMDlmOEFGMTZQcG1ubXBMY2ZMdmFMUGljSHNyc3YzTCtscWpHUmNxem14VHU0Q2RWdGxwbUc0dXlZbGt6dE5oZlpLNG5qeGpZNEIyM1Jlcm5Db3FqNVJqbGVSMzZoOGN4eDByM04xYkxRc3dZNGFZUDB2NTIyUThhekFYRjI0V2s0bFd5VHZKSkorOU4wK08rNWV5elNYQU9jdm5rZEk4ZzczUktaeHFudGlIeVNENnJUNFZkNWVwREpLSGtiY3JReUpSWEJWdG5RTW1ZY3pEbU5lKzE3ZWZvcnpGc2NGTEM2enJmZXRmaXFoQkVCZTFsUzVqeFFUTUlEdW5SWjdUa3lDR000eTZ0bmQ0cmk2cTNPSUZ3UjlVbTU0MUVseFFuU2FqOFJWckhGUVhKMml6Z2FIdUc0VzI0SFNNTmliZlZhUlNBc2NEY3Evb3NRZEcwQUg4VURZNmpvREtodEswQUVmVk5Va2pYU0E2aHY2clJoaWNqaU55ZnZWbFMxTW14QlAxU3BVVGF6bzhNN1d4Q3poeDVwcWtjSkhYSkgxV2h3VjB3QTNKKzlXbE5pTTdSZTM0cExSTnB2RHExckc3dUczcWs2dk03S1ZoQWQrSzA2b3hpcmtCQWIrS3BxcWFya2NTUWZxdTJqbmgyYkZpV1pIMVRqWnlyV1RPcURjbFZFVWt6VHUzNnBzVlRnUEpTd2xpTEpydTdJc3JTamg5NEFKSTg5eXRjWldHKzZjaXhFTjRjUXBZZTJqYTRwR3gydWJXOVVPcXhnUk1JRGg5VnJFMk9DVWFRNjN5VmZMVWczY1huNnJpeElyNzJXMWJqVWtqallraFZGVFU5NGJraEp6WTFEQUNDNGZldGJ4RE1JZHFzNVdvWWtGWnNGWmlqYVNNa09ISFFyV0t2TWI1WE9BY1ZUMU9LT2xjZkVUOTZVYzR1TjFhV0pIZDlERXRYSlVFM054ZEEyYWQxS05uQ24zZHlpZElXa3pMR21STnNndmE2akJDckNLbkp0c2tTa2g4VVJwNEFyT0dtRzJ5OVMwSmVRcjZpd2d1dHlrT1E5SVRaVDN0c1ZaVWRIcXQ0VmF3NGFHMjhQNEp1T2lJMkRmd1NiQXNROXhGdGdpeFlacjZLNWd3dDc3ZUZXbFBnenR2Q2hiSlpyOFZGM1E0UmZjVE4wSzIyREFTKzNoL0JXTU9YUUJjdC9CQlpMTkRHR092OEFDVklVRG05RnZrbUR4TkhINEpPZkQ0bWc5UHVYTFpMTk9kQzlvS1VraUpXeTFkTEVDZkZaVTlXWW9RU0RkR2lXVmJxYm5aS1R3V3VqejRyWWtOQVNFMVErYTZLaVdDZUcrYVVsa0RVU1NMazNLVWxBRjkweEppN0lQcmJYNVNycFpMM1JqcEhLdzZZVzRDTklsaXo1SkQxUTNCNXZ1cHl5anlDWGRMdVVkRXNHKzRRWElqNUFTZ1BlRXhIVE9uYmxCa2tJV1M3MVF6SUVhQk1kNFVLU1ZTZklDZ1BGMGFBZEVwWGtEWW9KbktpNTd6MFF5MTd1aTdaeGtudnYxU3pwU2ltSisreFFYTkpIQ05NRUMrWW9EcDdwbDFNWDlDaEdnY2VoUjJDTEY1S2lTU25HVUpjYldSbTRhQUxtNjREUlYyS2tSNWhXVHFWckVHWnplTEQ2STBBMEpGbCtpd1l3bUFvU2hHQlFIUXZCdGxLOWxGMG9DNmpyTTJLSEpLR2psUWZVOGhKdkp1ZDBTQVptYW9KdUVzUVhySk8rNjlxc0V4QU1nN1lLTjdyMjh4V0NlNVI4QTBUMVdUTkZUSEVKQXhvdmRMeFJPcVNBMGMrUzNmSmVYM1Vzekh5TjJ2ZmNKY2lVYkxraklyR0ZzMHJQVmRFcUs2SENZQzFqZzIzcXFLZk1FT0dVUWFDMXBEZkpjN3gvTjc2cVJ3WS9ZN2JGTDVKUmU1eHo2UTEwVWJ5U1IwM1hMNnVHb3JhZ3p5RUZwTjAyV09sZVhPSmNTYjc3b3pHNmVpYzFRU2UwV0ZKRk5FQUdFT0crNkxBYXJDNmx0UlR2RFoyL0NVeUpBM2dENklNb2RNNzNqcTNhM1JOeHpwaWNrZDZQMWU5anZ0aGk3UWNrUVlaSkxlb3c2bkRaTlJ0YzZ1bC8rSmZSTUQvR1dqWnEvSnYyUmUxbVRKT2RZS0IwdWhtSVRDTWd1dDVma3YxZnA2Z1RTRjdOMkhncmJ4VDRNTE5qMk01TDdVZWZ6MmY5bE9MNHRHNHNuaGJjVzUrRW4rQy9ERFBtTXV6Sm5YRXNXa2NYR3BtN3czK1FIOEYrblA4QUtVZHA3TU95L1U1Y0VsaFZVK3JTRHo0Zi91WDVWU3RMOVI4MXU0NG1QSms1cWZYTVpqL05uanlXQXBDVXkwamFiN1RUZS9SZUd3dGRhTUVWV1lEVklDNjhMRlN1bUhVUXNzMnVzZ0JaVW9FOWJaWTBxZXdCV0J1alJEd0M5cDJQbXBCWkF0eWlJUXAya254K2ZWTDFyWFBCRWY0Snh6aE1MTjIrYXd4b2crTGY1THVIUFBDOWxpY3NZWVY0YlhjMDZ2OEFlYWFZUEQzTnNRVjNYc0o3VFh2bWl3dXBlZkc0Qzd2bi9ldVpWbEV5dkJJRnV1NnBNTXFaY3VaaWdxNHJzYkgxKzhMeVh0QjAxYXZESiticzlyN0w5WG4wL1VSVjBtMGZmQU5vb3l3M1pJT2lPME5wbWpRQVhlaTAvczB6UTNNMkF3blhyZkhIYzJQcXR0Z2FRL1dkMSthOVhHZW16U3h2eVAxZm9zc05mZ1dhUGRuWCt3MnV3eXJ4cW5vOFFvR0ZqM2JtUzl1Zm12cVBET3k3TDFTOFRERFlDeDI0NS9OZkRXQll4VlVsV3lxaGZvTWV3djhBNDlGOXQ5aU9iM1prd1ZqSlpRNThNZSsvci9ldGpvdUY1cGJYNm55cjJvMGVvMC8rYkY4Vno4elpuZGtHV0hqV2NLcGk4ODgvbWd1N0hzdEcvd0QwUlQvUS9tdDhwR3NlZGJ4c2VFM284aUxmTmU3bjB5NHA4SHlIM3pQR2JXNDVyL21jeTMvdWluK2gvTlovek9aY1AvaEZQOUQrYTZRVzI2aFk4UUhJK3FIRDA5cjBIdlhaNis4YzUvekxaYy8zYlQvaXBEc1d5My91Mm4vRmRCSUhrc1hhT2lUOW12OEFJTDMzUCtJMEgvTXRsdjhBM2JUL0FFS2dleGJMbis3YWY2RmRBMXRYdFRWUHMxL2tUMzNQK0k1OE94ZkxaLzhBRGFmNkZFSFl2bHUzL1p0T2ZxdDlEbTlGTnBBNktMcHIvSW52dWY4QUVjOS96UTVhamNOT0MwNDliSDgwM0gyTlpka0FQNk5wMkg1RmIxRzh1S21SSjBLMC9kc0huRVU5WG5YOFJxOUJrT2d3VnRxZUZqQUJ3MjZYeERJR0ZZOC8vU2FHSjNUeFhXNGFpMzR0ME43M05rQWJ0ZExlbTAvNFJIdk9keXZjYUhVZGtHWFlRME53Mm51ZlFxRGV5VEFHdHVjTWcvRmI1SkJJOGh4STJVM2pVMEJEN3RndjdwWWpxOC80am4vK1ozTFozL1JGUDlEK2FqL21jeTMvQUxucC9vZnpYUlFUWWJySUpLRjZIRjZBZStaL3hITnoyTTViSi83SXAvb2Z6VXgySzVhdC93Qm0wLzRyb3B2WkNMRzM0UVBSWS9RSmEzUCtJMEQvQURLNWEvM2RUL2l2ZjVsY3REL3cybi9GYjlwYjVmaXZhVytYNHBmdVdQMEM5K3ovQUlqbnA3SE10ai93ZW4rZGorYWxIMk5aYmNmK3lLZjZIODEwRWFqc0RkR2p1QnlGYXc2TEhKOWdZNjdQWDNqUm91eURMTVRiL29pbkpIb2Z6VnBobVZjTm9JSFIwZERIU012dTF0OTFzVXIzRGdwR3JxdmRtRU9lMWpqdnFKc0FuWituWVZCdWlrOVJueVpGOFJvK2FzbjRGTEcrYXN3K0dZTTNMMzM4SytTZTJYTldYUmlVdURZVlF3TWxpSWQzOFY5eGY1K2kzcjJwUGFNankzUXV3bkI2aTFYTURISVdIVUw3bnA4Z3ZrbkpjVlhpRlNjVXhVOTVMSTJ4SUZ2OGNydyt1eFlzZHBJK3lleXZTOCtlc3MzK25mMU50Y0xpNkM4SmgxcmJjSUQxNE9FWlpiYlB2VU1NWlVtQ0lBTzZpQU8vYk4zd2JDM1oza3BrQjF3Vm9uYWZuaWp5amdWUlR0SmJNOGFoWStuOTYwOUJpeVpjeXhybmxHZDFmV1E2YnAzSmVqK2h6M3Q1N1RKS0owZE5oMVNRNEhTN3V6ODF3S2JOR0xWVFd1ZFZ5bDVOdWlqam1KeVlyaVZSVXl1dTF6dFRicG5MR0N6WXhYTmNCYU1iM2N2dS9UK25MQmhTUithT3NhOTlYek8vMU5veXNLeVZnTlE1NUJOL0VyOXpkTWcwdVZqN3N5T25ZeGdzUTBEOEZXVHNkQTY1S2pSNWlxSENidEZ6MVZ0aDFSWnpkMXI4VDNWSEIrcWZvcGRMd2t5UTZKdTlKTHFZRVp6eTE0K2Fyc0xsMU5HNmZtMjNTZk1haTFlOHZpSFhaYS9pQk9vaFhHSFZBbVpZbnJaVm1LdDB5Y0ljaThWMmNoR0ZiYU5UeGFHUXNlV1h2WTJzdWJ1elJqbVg4VkdzemhvSkk0NHV1czFVZ0JCOVZydWE4R2t4bG9tWnZwYmI4RmN4NEk1bzdaSWJneHJTNVZsajYyZHc3TGM3ak4rRVF4dWYrc2daNHI4OC93QjYzZCtsMVM1anJhQnVGOGtka3VhS3ZKMlpuMGtzbWxsVElHRDhQeVgxeUdSejBiWldrUEpQTFRkZkp2YUhwcTZma2M0cmhzL1Juc3IxTmF6RXNiOUgrNUprQWprRTNlQndiMFhSZXlKMkdUWXdZNnluamtFamdQSGYwWE1DN3VXbGgzQjZCVzJFNG4raUt5bHFHWEJZNjY4N29aUjhSS1JzZFcwT1gzYVcxOXo3dXc3c3R5elYwckpXNFZUUHVlZC96Vms3c2Z5MDVvdGc5UDhBUS9tcXZzUnpmRGorVUtTVnp3NlYxN3R2dndPaTZsRTh1dFlyNm5vOUxpeXczVWZsWHFtZlVhWFV2RTVQaHM1eS9zYXk2VC8yVFRqN2orYTh6c2J5NS91bW4raC9OZEtjMG5xb2FpRFlGV3Nta3hyaWlzK29aMUg3ek9mZjVvTXRuL3dlbitoL05FWjJQNWJIL2hGUDlEK2E2QUE0YjdMSUx2TkY3aGk3MEM5WG0vRWMrZjJPNWJkLzRQVG43aithd094N0xmOEF1ZW4raC9OZEZhZk1oZUlJSEs0OURpOUFQZTgvNGpuWCtaekxYKzU2ZjZIODFFOWptVytmMFJUL0FFUDVyb2V0d1BLbUxrTG51ZVAwQ1dzei9pT2Rqc2Z5MlA4QXdlbitoL05TSFpCbHNmOEFnOVA5RCthNkpwZDVyMmx5YzlCaTlBZmZNLzRqbmY4QW1oeTUvdWVuK2gvTlIvelI1ZHYvQU5rVS93QkQrYTZOWSthOVlwYTZmamI3RTk4ei9pT2Qvd0NhTEx2KzZJUG9melVoMlI1ZFAvaEZQOUQrYTZIWXFWaXJNZW1ZdTlFOTh6ZmlPZERzZ3k1L3VpbitoL05TL3dBME9XdXVFVS8wUDVyb0IxWDVYaUhkVk1taHhSOGprdFhuL0VjL1BZL2xvZy85RVU0KzQvbWd1N0c4dWY3dHB4OXhYUmJHeDNRaXh2VUZKV2h4UHlEeDZ6TXY0am53N0c4dWY3dXAvb1ZJZGptVzdmOEFadFA5Q3QvREcrUldReHZrbFpORGlUN0JTMXVmOFJ6di9NeGx5LzhBMmJUL0FFS2wvbVh5NS91Mm4raFhRdzFpejRQOEZISFE0dlE1NzlxUHhIUFIyTDVjSS83TnAvb1VQL00xbHlPUU5PSFUrL29WMGpTeEwxTVlNZ2NtKzQ0dnduWTYzUDIzSE82dnNkeTVIcExjTXB6ZnlCUzgvWS9seHRPNldURHFkcldndU53VjBXU1dOdGk4MkE2bGNBOXBUMmdLVHM4d2lvcDRacnpPdkhaaHZ6dDBWZWVreEx5THVMVTZtYlVVMmNlN2NjM1pWd09yZmdXRzRYVHZra2FmSEhmWWpiejlWeG1vbGRDeHIyeEVOZHVHam90VHdldW56Uml0UmpOYmQ4dmZPTENSYllrbjhsdE1zOVUyTWQ0OEdNandnZEY4dTZwZ1VKOWo5TSt6T2dlUEF0M1BQK3hMdTJ6Uk5tYy9RU2ZoS1dyV1htWVdud2diMldZOU10OWU3ZWk5Y05pZGZ6MldPbzB1RDFPMk9ITGJYbUFsSmtEV3M1VlhqZU14WUhRU3VxSERVR20ycnpzckF6aWhpbG5jUlpvdXZuN3RnejQvRnFxU25wNWJnRy80cjBmUjlGN3prU284MzdSOVp4NlhGU3Z2L3NVR1llMXpHalVWREtLYWFCb2U0QXR0NXJHVmN4WnJ6QmljQVppMVQzWmQrc0czSDBXaVFUVk10WTJBWGVYNzdDNitpdXluSlRzRG9YVmRRQmVkdXB2MS91WDFUTnBZNlBIVUVqODl2cUU5YkpxVE9qNFRJY0d3MWhubDcrWGdrOHF2eFBHUklEMHVsY1V4QnJYdVk4M0hvdFlyY1I1NVdUamp2ZE02OFcza2xpTmJxY1ZUVDFRdndzVFZvZVRkTHVzODNWcHdXUHNWM2NtRnBvRFVUQTlGdW1IYUtPbkhGN0xVOFBjSXpmeUtkZmliajRicXJsblkxSTJCMks5NFhDKzFsUjRoVTZ5ZkVsWDFKWUxncFI0bGxmc0NiK2laaGdueU1VUWh1L2dwcWlvWFNsT1laZ3I1bWd1YmI1clpLTEJCRllrZ1c5VlcxTTlqcEJxSlMwMkV5dUk4SlYzU1lLNnd1RlpDcWdoQTh4NnFKeDJPUFlYU2R6WTFSSlI0U0cydUFuWW9HTnRheXJYWmhCdmE2aEJpaExybSs2R3hpaVhnT2podDB4RlVQRzNkbFZzR0xSaTJvRXF5cDhZcHRydEtHdzFBZmprRzE0VVVOams1aUFVb2NTcFhnV0JDYmlkVHluYTMxU3R4SXhRQ1BEWXBCOEFDd2NDalBrcmltaGpzTE9IMVRZb3I4UGI5UXB1SGJGUnE3c3Zqb29ITHg2RmJhYVhRT1I5VUp6Q09OMU54WGtqVG41YWRHU2JxdnJNRmtEU0JkYjg2NzlpRkg5SHRrQkp0OVUxWlFscDBjYXhQTHRVOG14Y3RjcXN2MVlKOExsMytmREk3N2hMMUdBMDBqZmcvRk1XZWpyd0pJK2QzWVRVeG5kamxFd1RNNVlWM2liSjlQTVQ0UHhTTStRWUhnMllQcUVmdkxLc3NSeHhySEFiaEhqYnV1a3pkbk5yMmFMZk1KQ2JJajQzYk1SdklEdG8xbWtpYVFPRmJVVklYT0cyeXRLYktFakNQQ3JkbURHbmFQQ2RrdHpzNzJGcUREQTYyeTJHa3cwdEFzRlgwMHZjdUFzUjl5MlBENnlNdEYzQWZNcGRuYkowdUZPZVJjSzVwY0RhTEVnS05QWFJ0dFlqNnBvNHFBTmlWR2NIS2ZEb294dlpHL1ZNUEFWVTdGU2RycGFXdU43Nmg5VURJYkhIVXNZTnJLRTJMQ01HeTE4WWdRMzRsWFYySzJKc1VKQzdxc1VOajRsUzFtTE8zczVVdFRpN3lEdVZWejRrOXhQS05JZy9XWW5JYitJcW9tclhPdmQ2WG5xM3U4MGpQSElSc25SaWNHWmFwZ0IzQktyNmpGU3crRVhRSFF2dWJxRDJ0R3hCS2Nvb2g1K0p1Y0VzK3VKS2crSzE5aWdPRnVoUjdSZkliM2tsWU5VZ2dtM3dsUU1MaWIyUktKQWpwd1VKMHZLOTNCUFJlOTFQa2oya3NWYzV4S3dRNCthYjdxM1FxYlk3L0FHU2hSemNWNVk1Q2N4eXR4Q0QwS0t6RHdlaUpBdVJRaUp4Nkl6S2N1NVY2TU9iNUQ2ckpvMk04dnFqUUZsTjdsdDhLZzZuMC9aVnc5N0JzbEpudFhCbmtWem1pM0NXTk1BYjdKNlJ6ZDBrK1lib2tDUjd0clY2N0I1SUVzKzNLVmZPZk5HQ09QbVpIeFpLVDE5dGdnUGVYZFVFeDNLSWhsOVErUTlWNEF1VTJBRGF4VFVjSFVoR2dHSXVHbEJlOU9WYlEwS3JrZnVqQkpHUkRlYmpsWUpzRUNXWURxdW9Gbm5oQmM4V1E1S2pmWW9MbmtvMEF3ampjcUpVUVNVUnJibzBBeUxEM1o0VGRMUXVySGpaWWdwKytlQXRsd3lrYlR0RGlRUHZRYmp0RGVENEF5SnJYT0EyMzNWOVU0cERSUkFNc0NCYlpVTlJqbnU3UzFwVkhWMXo1Q1NYY29seVNpd3hQR0phdHhBY2JLc2JHQnU4NytxREhVMktsSUROdUNqVVNVSGJJRkxYZEtOTmphNkpyc2p5ZGhlWGdNZDFGa3Y4QXBEUUIrcjYrU0U2Y0FIZEJiVnRaVFBhYjZpZGlxMFh5SGpWcmt2OEFLK0wvQUtKelJRVnpIYVRUUzZ4YjVMOWgvWnd6c004OW1XSDRqSS9YTklUZS9QQUsvRmlGam5BU0RwdXYwZjhBNVByUGhyOElwc0RkSnRERzUray84UDhBY3RyRExneTlaRStTZjVSSE40ekQyaVllNk9VdVo3cVFRRHR3eGZJclpBWTNEMFhVUGFBekcvTk9aNmFkenk3VEZwdWZrRnl4ck5KWHVqeUJLRWFJZ2Vxd3N5Yk1BQ3lCc0YwaDRCWlhyWFVyV1VJZUFzdkxLeUJaTkYyZXRzVml5blpZUkFNeFpTQVhnRklDNkpBdDBlQXNwYzlGNEM2a0JaZHdyd2RURnNYTDQ4VHllaDRBV095ck1XdzczeU1zYTN4SHFCdXJVTnNwRFMyVnJpQllLdE9IaTVKdGVvL3hWaldOblJQWmR4dzBkUmkxSEs4dXNBMEJ4dmI0VjlHUnM3bDVrUEhrdmx2c2VvMzBPWkh5TXZwbWtGN2ZkK1MrcEpIM3FERjBDL09YdFpoV0xxMlNTODB2MlIrc3ZZaVR5OUt4WlAxL2NicDV1L1lSOEo5RjJMc0Q3Ukc1YnhvVXMwdWxrN2czYy9MOGx4aWEwVm5zNEhObGlxcVpxQjlOVjA3aTE3UEY0VjVmcCthcG85VjE3U1BYZFB5UWl1OWZ1ZnFCUlY3Y1NZREVRWU9qaDFUc1RpSEM1Tmx3djJhKzA1bWFNbDBkRk03Vlh0dTUrbytLMWgrUlhiMlBOZ3ZwK2t6WEZjbjVhMWVuOTN5enhTOG0wTVBmNnFJY1QxUTlWMU52QlZtY3lqRDRmZ0NCNjhUZExOZjRySXpTU0VhZTRMWnM1TU9QSlVYT2dld3ZMeUxlU21XbXhOcnFGTk1KU1dPcDlBdnlVZTJ1UmJ5K1NKdERHNk83ZHF1ajMxT0xEdGJkQ2RJSWdmMWRyY0lMSmU4ZVpITzBYNkpFc3FpNkpVcEt4d1RORzM4RklUQkoyTjczVTJ1UlhEMUQ4TkRtdHBXT3ZDQUhiTEhla0lrNGVvSGgyTTMyUW5vSm1JVVRJWEk5MEg1blBDRHVlQjFRKy8wb1phNVFEVGZkQmJPN2NmbXcvdlNsM3dmc2d0anVpTW9TM2ZXdXFVam16Ry9NdzdaWUVwRjFDYUp6VGJVb3h4N2J1WGR6T2VIajlROU05N0NTNGVEekt4TlVSdWQ0SDhjcEtwcVcwTFNUSnJIa3RGemgyajRabGVCOVJKVnhoNEYrNkozUG9rNm5YNGRPdmhaYzAraWxtYWpqNXMzWEVNZWpvbzM2WEFsZ0pkZm9GOHIrMFg3VWxKZ2RKVVliaEZTeVdVdE56Y0Fod0c0K3E1MTJ4KzB4aU9hSlo2SENhZVdoYWY4QVh4a1dJOHVTdm5LdmRVelJUellpSFZVem5GMTM4N3JIKzBWcWx0VFBxUFNQWkRMaGExR1pQeWE1UU9xeEU0NWlzbUs0alVTUDF1N3l6M0Z3SFRxdGxvczk1Zlkxa1B2UVk4bXdBQTUrcTVKaWVMVkxqSkN5QjdHbllCWC9BR2FaU2RpTllKYXh0bWdYR3Z6V05xc1dPS2NwTStvYWFlcWdsajA4RTZPd01xV1ZMMlJBL3E1QUNEMXNwU05ZellHNWJ3bDNRaW5qR240bWl3c3NUdjdtRVR2ZFpyQmQxMTRlTS9IbjRhOHoyYzQrSER4Y25GQ1dPNHhEZ0dIeTFzN2d3NlRZSGpoZkhuYWxucCtkTVFtbGJKNFl5NWxtbmJ5L2d0OTdmdTB4MWJOSlEwVHpvRHZzZVYxd2xyeThtSnJkVDVEcVB6WDEvd0JudWllN1E5NGZkcE0rRCsxUHRONDgzcEUxNXJ6RzhQd3grT3l3eE1COEJzYkxybURZRXpDY0xqaWMzUTlwNXR1cWpzMnl6N28vdjVtN08zOFM2SGpXSGlwWVhSRVc5RjY3VVRqa1d4TStUMDlJL0ZYbndVVFczQ3E4UmlOMVlIVkVTRDBRS2h2ZU5WUmJmVUJaV1ZVRW5kSG15ZnBKckZWMDhaYTdaRWlrTFNOMFRVYUdMS3piOEtuOFEzVjlJQzlpMURDNXlDTGxiZFJTQ1ZtNnJTVVExbVpLbWs3azgyUkttVnNyT0FTazZzbGw3SWNFcGNMRkppNHZJdVN6cDhyeVRTS3l1Wlo1MldLT1JvbWJHNnh2MElUT0lSM3ZaVThMWHRuN3drN0ZQbGlVcFJwaU1tT1NtNUd2NXp5N0pRMVVXSXh0TFF4MnU0MlhmdXhiTTR4N0oxS1hQN3lRM0p1YjlBdENxS1dMSHNIbXB5QnIwV0YwVHNKZkpnbVpwY0ZrSjBReGtpL0hCL0pZdlg5RDR1bi9BRVo5QjlqdXFQVGF4eGRmZC8zUjNTS0RWV3NKRndtSFJqdkR0d3N0SWJJSEx3ZnFjNWZEOVJGcWRvL1JqZStTa2RwOW5yT0l3akhXVThzeEVaYnBEQzdiZTQ0WDJoU3pORkRISzAzRG1oMzFDL012QjhXbXdiRjQ2aU54QURnZHZtdnVmc1R6NjNPV1gyeHVOM3QwczNQcFpmUnVnNjlPSGhYNUkvT250eDBlV0xPdFVvOTJ6cVlmM2VsMS9pUkhXYjQvTlIwQ1FOYVBzS1RpSE83dnkzWHRISCtJK1VPU1NzSS80VkNNRTNSWER3QlJhTFhUc2FLdVQ3eUFUQTZ0bEJ6Nmx1N0dYQ085bDdxTk81MGJIQnd1YjdYVnJaWmJjcXhubU9Md0RKNFNQSkdiSTE0MGc4SWNiQnFKY2JCQnFLa1F2dEd6VjZoU01hSytGT2JHKzlzdmF5VXUxOXdEYXlLeC9vdSs3elhORDVRc2xaeUlMZ0tIZUR5VVRMNkxseXhpdkREZDRSMFdEVUhpeUFhaTNJVVRPTDhLZTlOREZqRDk3Y3JPdTZHSE50d3ZkNFBSSmM1TW13SVZEeGVTajMyNnk2YlNsT1VqbXd3WHZIMlF2YVM4YjdMQWZyOUZGK3B2QlN2aWZjbXp5TVhhM2ErNlhuRG8vRUNTcFRQWlB5OFJXODBHYW8wTkFZTy90NUowZEppank1TVhrbmx4dW9JWWdxUkpHUTQyY0JkQ2pyeFBUeUdid0Zwc0xlU284U3paUzRSSElhblRCcEJKMUw1bDdjUGFjTkREUGhtRVJGN25nLzZURWZoUDE5Vld6ZFh4YUpiYk4zcG5SOVgxVElvcU5kdjBONjdkL2FOd2pJK0hTMGtGV3ozNXpTMXJDUVBFdmdETW1hcS90S3pESldZM0srS25ObldhOGtYQnZ4c3A1bXJzUnpMWG1xcnBaS2pVN1VDLzdLMS9HNmh0TFM5M0dRQ0Q4UVhtcy9VdmZYOExQdC9TL1o1ZE1nbkpjK2ZZM09QTkdCNFhHMktPZG8wZ0MxaCthc3FiR3FYRldqdVpOWVhGcUhENU1VcWdCSjFYVzhxNWVOSFRnbDl6WmVWMStCT082K1Q2SDAvVjdIc0xPV0p6YkJvNnJ3aGZMTTJtYnVYN3F3OTJKY2QxUloyekpUWlF3S2V1ZTVwbmpGMnQ2OExLMGNaWnNxeEplYVJlNmptaGl3dkkzNU5uUCsyUFBVV1ZxSnRGVHlCMGt3TEpMOGpuOGw4elZNNW1xblRPZTV3ZHNDVGRYZWE4eHk1bXhTb3FaM2t4dWRxYUhkRURLdVhwY3dZa3lKZ0ppQkR0UTRYMmpwdWhXanhJL09uWGRmNzdsY1UvTmZzYnQyVVpPT0pWY2RUUEhkb2QxRitxN0ppV0tERDRJNmFPelEwYWR0bFZVRkZIbC9EbzIwNEFjR2krbnpzbFphcHRTSHVrUGk1M1ZLY25PVGJNZEpKSHF5dEJqMWFybFZGUldhaGJaQ01qcEtselNUcHNsNmx3c2JMaU9rSE9EM0k4TWQ3QkpRaHozN0srb01QZEpwVExJQ0VKakcxMU9LbGtuZFlCYkN6QjdCcGQ1SjJDbWdweGM2YnFvR2lwb3N1bVMydTlsZHc0VlMwWUJ2Y2p6Q1hxY1ViRGNNL0JJTm5rbGRjeUcxMXl3MFhNdU14MDQwc0Rmb0VsTGk4a3hOdndRbVFNZHU1d0tkZ2doRnZoS0d3MEl4dmtjZVR1Zk5IYkM5L21yT0dHRTlBbklhYU1rV0FYSE5IU3Nnb1NRTGk2ZWhwWkxqd0JXOVBSdHNOZ3JDbnBXdUlHaFZwU1F4TW8yVUQzZlpUVU9HT1BRclk0c01Md0xScCtEQTVITjJZVldjZzB6V1k2Rnc0SlV1N2xqNEx2cXR1anl6Tit5VmlYTFU0SDgyU3VXU3pXWXF1b1pZYi9BRlREc1lucHlEYy9WV3h5NVZYc0lIZlJaR1NNUXFQKzd2dDhsTEpZakhtYVlzdFlGSGd6UkxFZDJOdDZva3VTcTZtRzhEL29xK2ZBYXhoSU1Ed3BaTExadVlvcGVyUVV6RFhSeXR2cVdveTRWUFQ3bTRRUldTd0cxeWlHMmJzK1dJL2JVZFkyc2JyUzNZbk1mdEZNUlkyNFd1b0EyYmVIZVNsYytTb0tiR20yOFJWbEZqRVJ0ZXlndGpta2c3aFNCWWVXTitpRUs2T1FiRUlqZEw5d1FtV0RRUVFzZjlrZlJla29XT0h3ajZMdzhQVllNeHNwWk5wVzFlRWg5N04rZ1ZUUGdjZ09wcm5pMjlnVnN4a0o1WHR1b1VzbTAxU09vcWFjMk43RGJjbzR6QytJV2RaYkErbGdsQkdsdDBwSmwrS2Jpd1hkeUlVa3VaZFY5d0VqL2xFOXAzZCtLMkoyVUdPdWRRU1V1VUwzc3B1SVZ6YzBYRmk0SWpjWGJOeTVSbnloSXpjWFNqc0NualBWVGNpRmc3dVpQdEZaRkV4NDIzKzVLc3cyVmxydUtaWnJoYnVicnRoZzVjTkhsK0NHL0MzdUZnMVpueEp6RDhKVTI0MDBXdTFHcEMyaENUQkpISDRTaG5BWC9zSDZLMS9UY1kreUY3OU9SY2FRalVnS0tPVEIzQWZCK0NVZmhENy9BQWZndG9PSlFPSERWajN1blBScVp1QjJtc053cDM3SDRMeHdjamZUK0Mya1ZGUGI3S1hscktleDNhalVnYU5jL1JPKzRLbU1MYU9uNEorZXVpQk5pRW5KWHQzc1FpM0FVQmtvR3Q2ZmdnbUJqZW40TDArSTZnVWhMVXZmZXlNR2hpVVJ0LzhBWkFkV3Rid1VqTTZWeDZxQWhjZVNpUjJoeDliZmdvRDV5N3FodVlHRGxLUzFyWTdqWmRPME1PbHQxU3M5V0FFbExpQUpLVGxxdFYwZEhHeGlXczhXeFNjOVZZR3hRblB2ZENaNGlicnRpbnlZNzUwaDNYaTREa3IwandEWm9ScVhDNXF3Z2dGZDNDdHJCR01rYmJvMVBSU1NIaGJIaDJYQ05KazQ5VTlVdzAxREg5bTZGSWNhOHlnN3V4Y0ZHb25hRzJGaFpTcmNTWTV4MDJWSE5XRjE5K3FaRkFNOVdTNmlkMVhPTnlwelMzUzdpbkpBc3pMTjRka2hLOGs4bzUzUSs3QktzVVZ3STNSQXpjS1lpc3Npd1hhSWViSGZvaXRqMldHdUE2cWZlQURvcFJBOU0vdXp3bUpjUXMyd05sVlBxd09FSVQ2eXVVUWRmVmw3dWJyR29ucWhSdENJTEkwUXlEWkZiVVdGa0I3Z0V0TExhOWltSWc4NllEZTZHYXMyVmEyZHpqdWl0ZUxoU3dhRHZlNTZKREM1N0NpMDdROGNYV3dZRmd4cUhBRnZKWE4xRW9ScGFKeis3Rmw5UWV4WG1ML0pudEZxSFBrTEdlN2tBWDIrRnk0dERnUWhMZkN0djdOS2lUQXN6VFZEQ1czanRjZklxTExSeXJQbGJOZFdhbW9iSTQzSUNvZ2RRQlZuai84QU9qNUt1ZC9OdFgwK2o1M1pGZzF5SHlVdE5sNW53cklGbEtKWm0xMUlDeWdwcVVTekZsTUJSVWdFWXF6S3dzcklGa1FMWmdDNVVsNnluWkdoYlo1WmFGN3lVMmhNMXZ3VFVsNkhNRXIwazR2dlpGUmNOY1o4MFQ3bGlTRTIyU3NUVU1PVEpMMHNYc2xtbmpoSDFPbzlpMUg3OVV5dkxTZTUzdjhBUmZRSGRYSGZqbDJ5NXAyTzRWK2k4S2ZJNWdIdkROaVI2ajhsMG1FOTFHSXowMzNYNWs5cU02ejlUeU5QMC9ZL1pmc1pnZW02SGhqTHZ6KzdEeHN0Q1kzYmwyNm5BQStPUmovaEFRV1ZHc2ZKTTBVWnFhbU9BY3ltMnk4Wm83V1JIdThVb2VCTHhPMStaOUIreVJsaW9wTXh1eE1DMUpKQ1d0K2RqK2ErdS9oWmZxdVRlejFsNzlDNUxvMlBZR3lDOXlSdndGMVNSM2hObDlMMFVtb3F6OG5kZnA5VHk3TzI1L3VIaE9xOXlqdEFBS1JpazAzdXBkNWNYdXRPY3JaZzdYNHpKc0IxbjVwdUllYVNqbkFjbVd6M1Q4VXVSbVhzTmhvQVFxaVZ3WVh0Y0JiektFWmRpYnFpeGZFWFU5NUNiUmprcTdPYTJpZFBnZVNkR205ci9icmhQWmYranhXdWRJYWcySWpOejE4Z2ZKY3hxZmJZeWxKTVloSFVBamZlL3dEWlh4dDdTZmF6WFptejVYMFRYNjQ2R2ZTMGEvVCs5Y2ZHS1ZNODVxQzV3Yzdhd2N2T2FqSzAzUjlLNmY3UFJ6d2k1ZnNmcE4vOGJPV2dQaG4vQUIvSllQdHQ1YUgyS2o2SDhsK2I0eEtySFYzMVUyNHJWK3YxVlR4TXg2RC9BQXJwL3dBWDBQMGRIdHVaYi9ZcVBvZnlVbmUzRmxrRCticWIvSS8yVitjZ3hlcS93VlA5S3ordjFSTEptQmZzcnAveGZRL1JQLzQ1Y3MzM2pxZm83K3lwajI0OHNmOEFsMVAwUDlsZm5UK2xKLzhBQlh2MHBQOEE0S0x4TXdQK0Z0UCtMNkg2TGY4QXh6WlpQK3FxZm83K3l2Tjl1RExMdUk2bjZPL3NyODV2MHBPUFA2b2tlTHpEcitLbnZ1WmZ3Z3IyVjBiL0FJMThqOUdXKzIxbHM4UjFIMFA1SjJsOXN6QktnZ0FUajVnL2t2emhqeHVZZGZ4VDlObVNkdlg4VXQ2L012NFIwZlpQUnY4QWpYeVAwcWc5cVhCS2lMVmVUN3lmeVZSaTN0V1lQVGh6V0NVdUlzTFhPLzBYNS9RNXVxbWdBU09BL3dDSXAyTE4wenZpT3I1bExmVWN6WDNXTmg3SWFOTzk2K1I5VzVsOXBURXFtT1FVbFNXdU83Ymc3TGtXTzVwcjgzVE9maWs0bEY3dDZmdks1aE5tOXRNTHlQQStaVlZXNTZrbWFSQVFma1Y1eUdEVmFpWCtZMmU4eGRKNmRvRXA0MUdWZmtqZjY1c1ZBMDZKR0JnNEdvTFVNYnhiM2xybkI0SWJ0YTYwYkVjeVZNc2xwWkhOSjJ0cUt1TXQ0RFg0dkt5UXRjV0UrWjNXaHM5MGhiWnE0dFJEVmY1VVk3VXVDNHk5bGlYSHArOElBWXczMzJYUXFTZ2d3MW9nWTJ6bTlVREM2YVhDNmNNTVlhYldPeWI3Mk51cVNVNlFCY3J6V295YWpWU3FGMGFQaDQrblIzTjM5QXJtdDd3UGNSb0hOMXlqdGU3U1k4QW9aS1NHWWFwaHBzMDMvd0FjSUhhajIwVW1YYVdhbG81bXZrSTYydmRmTDJZc3cxR1AxajZxZVZ4Qk9vRFVTRjdMb1hzN09XU09iSjVma2ZML0FHazlxV292Rmc5UEovbUxZaGlENWF0MDA1MWwrMnkySEp1V20xczdLbVJtd1BWVVdENGE3RzZoZ2FDNXR3VjJuQk1KaW9hZU1XMGtOSFJmVDU1MWdoNFVmMFBqT1dMMVVubWwzN2pGTEkxa1RJWXdXNlJiZFgrR3NkM2VseHZzVlNUQmpIZ2cyVnJodFExNEF1c3VwSjcyeWw4VW50bXVCTEU4TzdzdWNCNnFtZEh5RnU5VkVLdU93SFR5V3VZaFJDQWtvRW42anZCZm9hM1Z4QUU3Sk5vczVXMDhMWmJxdWRESTF4MlR0c211NVBDZm9XVkU3U0F0bndtb05nQ1ZwMUtaR3VBSVYvUlNQR2xLY0g2azhOK2hmVmJkWVMwWTBFb2drMU5DOFI2Skt3eWprVHNiQlBETk9nRTQxaFU5Uk1JcXhrWFIyNnZUOEpWSFh4QjBtcmcrYU9VcFJuSGtCWm5rbEpiU3l3U3BOTlZnWDhMajBXNFpZd1lSWnhteFJnL25HNmIvQUYvTmFEUWxySHQ4VzY2dGtlNzJ0TnRXM1g1TE42NXFKeHdVbjNaNi93Qm1kTHYxcmRlWCs2TjhhYnNiOGdzVG51MkFqZjVJYkhrdDBubFNvaHBFNGR2Y2JYWHgzTlcxbjZXeDJvb2pHN3ZtWEozSytnL1pXeHlmRDh3VTJIalU2S1dTNUxRU09mUDcxODlSVXhmcGFMK0kyWDFuN0xPVkg0VlE5OUxGZHhrRGc5d3VSdWVxMXVoNDV5MUMyOXJSOCs5dVo0c2VoVGROMHo2WnBYV2trUG1wU2VHVFg1b2tVVjQzZkpSYkVTd0MzVmZiM2d2Q2o4c1RmK1dtSGJ1MWV0dWlobmdHeXlHZWlMd2RwMlhMQWhvdWhTNi9lV0M0MDJUTG1jcUxhZTdTZDlTdXd3L0NGSi9DTDFEUzh0QTJIVmMwN1crMkhDdXlpaUZSV0Z4R3ZUWmgzNUE4dlZkSG1rRHI2ellOOGwrYlh0emRwc2xWbnF2eTdCSmRzRGcrd2R2OFIvSlptcWw0UEp0OUgwaTFVNmZvZlFoOXVMTEEreFVmai9aUW5lM1JsaG4yS2o2SCt5dnpYYmpOUVBpY1I5NmtNWEx1WkRmNXJ6OHVyWmUyMCtweDlsdE8xOTc2SDZSSDI2OHRmK1hVbjduZjJWTnZ0ejVhY2Y1dXAranY3Sy9PQm1OdWo0ZGY1bE1NekF6YThsajgxVG4xSExMK0ZqVjdKNmY4WDBQMGNiN2JtV3BQOVhVZlEvMlVVZTJobHM3Nkovb2Z5WDV6eFpoWi93Q2FmcW1XWmlaLzVwK3FyUFdabi9Dd2w3SjZmOGYwUDBOSHRxNWVQK3JxUG83OGtSdnRvWmVkL3E2ajZIOGwrZkxNd3k3Y0k3TXdTbnlTdnRMTXY0U3ovZzdUUCtQNkg2QnQ5c3ZMenZzVkgwUDVLd3czMnRNRHhBZ2ZyUi94WEg4RitkMzZmbUgvQUxxY2VhcXBud3VMZmtWMzdUeS9oQy93WnBuL0FCL1EvUnlwOXFMQktWbXE4aCtSUDVLb2w5c1RCR09MZE01KzQva3Z6LzhBOHJxeDNMM0g1dUs4TTBWQjZBb3Z0TEwrRTcvZ3JUVjkvd0NoOTZWUHRmWmFhMGllR3BlVDVBLzJWUllyN1hFRG9pTUdkTEFTUHRnL2tGOFZETTFRNC9yR2dCTnhabWpqYnU0QXJIeWEzV1JWY2xycC9zaG8xazM1MnY2bzdobS90bnpObkI4Z2xyV3VqZnlDQ052cXVielJnU09mTEkzdUhHNzI2aGNuL0YxcUZWblBSZlE0RXFoeExNVTJJQWx6eXdjZUVyUGVsMUdxZTZUWjd1T0hwL1Q0MWhVYi9LbDJOMHh2SHFPT0h1cVlGb3RZclNhMmxOZTRBRUZoUENxdjBqUFZQRVVYakoydVN0N3lobFo3MnRscXRUZGsxUVdpWHhNQlRscW53aHJLMlZhYWxESkRIWjJ4NVc0c3FHUVdZemJvbFk0KzRqdUI4T3lHUnFhK2FRNldzM3VGalBVU3p5Mkx6TmpKcFlhYUhpTjlpZUw0ME1OcHBKWFNOWnBhVHVmUmZMbmFsMmhUNXJxNWFkc2w2Y1hZNGZndHI3Wjgvd0FiM3lVVlBPUWIvWmRicXVJU09jMHVhQ1hTUE9vWFgwUG9uUjQ0bDd4TmVqN0h4ejJoOW9uYjA4SDZydVN3NkIxZlVDa2EwdUx6cEZod3U2ZG4yWEk4cTBUR1N0LzBnQWdrZkphNTJkWkxPSHhpdmxqMUdRYWhxRjEwYWVJQ1Azemd2MnQwWG90UnJGRmVIRStiUWpLY3ZFbDVrS2lyN3Q1YTgzRHQ5bFI0aTRod0xEc1UzV091Q2Jxb2xuT3EzS3pxTHBpV2J1NDlRK0lvRU1icDNiOVV6SFR1cUNOdGxiVTlDeUd4UDdsM3NRRmgrR0M0SkMyT2tZeUJvNldTVWRYSEMyd3RkQ2x4Q1J4c3dBMzJYTElYTlJpalN5d1BDbzZ1dmVYZUUzK1NQQmc5VFdrWGFSZnlWM2grVXd3Z3ZCUHpTV2RzMWlJU1RIZHJqZjBWclE0TlV6a2VFZ0h6QzNXandTbmpBdTBYSDlGWE1MNEl3QUdNMi9vaEtrd2t6VUtYSjlSSTBFZ0t6Z3liTUxEU0Z0MVBXUnR0czM2S3dpeEJnK3kzNkpMa0hacTlMa09RMkpEVmIwbVJYTnQ4UDFWNVQxZ0pGckt4aXFqMFZaekNLMmt5UllDK242aFdsTmxHTmhCSWI5UW1vcXA5a2VCODVQR3lVNVdkc25CZ2NVTnJnZlVLeWdwcWVNY0Q2cFBUTThjTEh1TTcraENTMmMzbHhCSlRBN2tmVldNSHVUN1h0OVZxSXdtY0c0TC9BS2xlOTFxNGp0cVAzbEZ5RHZPaDBsSmhwMGt0QjM4d3RtbzYzQjRtQUdNN1c2LzNMa0VFbGUwMkFQMUtmaWl4aVMxb2piNWxUa204NmRVSEI2dmJSOVNGUzRuZ3VFdWE3UzBYSXQ4UVdzUTRYaThscnNjUHZLYUdBNG03bHIvcVZPU2J6VjhjeWhINHkzVFlrMjNDMFBFc3JhSG13WFdxM0x1SXRiY3NjZm1TcUNyd0tydVE2Sk5zZXBuTVg0Rm9CRmttL0JOTjlsMGFmTFU3eVQzWlZmUGdVakwrRDhGMnlXYUUvRFhzdllJUmdsWVZ1VXVFeUQ3SDRKS2JEWGcvQitDbGtLQ09ybGp0enQ2S3hwOFljMndKUDBUYjhPMitEZjVKYVREVDBhcHVEdERzV0w2dVhKcGxZSFczVkNjUGVQTlRpTWpEWWdxYmp0bXdlOEMxMUIxVDVKQ0dVMnNVY0hVcHVKWTB4MWpkTVJ6SG9Va0hGRVlVcmN4WllzZEliYnB5SndOZ1ZWTWNSMVIyVmVsVGNRdHU1WTl2Q1dsd3lOOS9DZ3R4S3dYbll0ZnlVM0VLK2ZCSEFuajZwQ2JDU0FiaFhKeEFPNnFMcXBydkw2THFtR2FyVTRPRGZ3bFZVK0ZhYitGYjArVmp1ZytpU3FLZUlnbitDTlRPVlpvTTFHV25ncGQxT2ZKYnBOU1JPSjQraVNtdytJOGZ1UmJ5YlRVdTZsdXZIdkc5VnNiNkFXMkg0SmFYRGI5RVN5SGRwUnVtbEFJdWxaR1RIN1FWNC9EUFFwU1NnazhpaldRQnhLZDBVdm1GSHVaTGNncXlkUnZiMFVEVFB0d2pXUURhVmNqUzFRRXdaemRXVHFHVDlsTHZ3NTd1aWVzZ08wVGtybU5IVkpTNHBvdnlyTitDRjU2b0UyWHBIRDRUWk5qTUZxaWtxTVZMOWhkVjhybnltKzYybUhMRHI3dEthR1dnUHMvZ25LU0FOSmJUUEo0UDBSRFJ1QXVRdHdsd2hrRnR2d1M4dEVKRzJEZndUTEUwelVYVTU2QkVpb0h5RUFOTy9vdG5wY3Z1ZThFdE52a3Rsdy9BR1JOQmN3ZlJjYkNvMURDOG9tcHM1emZxdG1wc0lod3RuaXNMZXFhcmE2RERHR3hBKzVhWGp1Yk84TG1zZitLSGtLaTR4Zk1FZE13aGp0eDZyUjhTeHFTc2VScTJTRTFZK1VrbHhOemZjcFY0THQwOUlSWVYwcGJlNVFOVnlWZ3RLZ1hXVG94QmJNdUtDOTI1M1hudlFIUDNUa2diUGF0MW5XaHVlT2lFWkxKMUNSZ3llcWlYN0lIZWhDTXU2bEVHSFMyNm9abk43SWJUZEVBMzRVb2hneGwyNllncDlycnpRQnlzUG4waEZSQXNoN3ZncURxaTNWSnlWRitxQ1hrOVZLb2cwK3FKNm9SbHVnQUVsR1lMQmNJVGFBUFJGcDRuVFNBQUVvY1RIMWp3MW85Tmx2T1ZjcnZjV3VjeS93QXdnY2p0RWNDeTg2bzBFc1BLMy9Ec0liUnl4K0hvRlpZYmhqS1dJRFNCYjBUMFRlOE5nQjlFbVVtU2hhU0JwQTJUZUhRZHhKM2dHNUZrZG1HdWVRYkZXOURobGh1UHdTSEprbytKY2Z2M28rU3JuWDd0cXNjZi9uUjhsWE8vbTJyN0dmTkxQTStGU0FKVVdmQ2lEaFFsbUFMS1dsWkFXVkNXWXNGbTExbXdDenlvTGJvOWF5eUJkU0d5OGlBWmdDeWxaWkFYZ0VhQTc5ak9uaFNEZDE0QlRBdnNOMTNLM2xqWXBQWmxXTHlaZ0N5ZHdlbE9JNHREVGdiTy91U21uelc3OWwyRWU5NC9UeWxwSUI1KzlaL1ZjdnUyZ20xK0Yvc2VqOW5kTXRWMUxIQnJqZEg5enUyWGFGdEpnMUUwQUF0WlkyK1pWMDQ2anI4MEtHTVF3c1owdFpTY1FIYUIwWDVRMUdaNm5WU25JL1orUEF0RnBZNFk5a3cxMnhSa3JadXozQnBNYnpOaDRZMDZXeWk2MUNjbHpEYmhmU1hzc1pRWmlrOVZVeXhuOVVBNXBPM2twcE1TVTB6STY3ckhvK241SlJmcCs1OVA1V3c4WVZoMGNEZUcrU3UzYml5QkNXeHlsbzJGbDR5K0xsZTYweTRQelZreVBOT1dTWGZ1VEFzVk1IWWhCTDFIdlRkYURRT0piL2pEdGpJUEtJSGFRZ3RtSVdUSmZxaXZhRE9GaEh6RU5LNDk3U0dkUDhqdXk3RnE2SjlxaU1YYUJ6d1YxcVFqU2R4eHpkZkNQdDVkb3MrR1Z2OEFrNDJjUGhxWUM0dGFiOUIrYUNXWjBhZlQ4YThSZjBQaS9IOGJreFhNVlZXdkJMcXFUVTRuNWYzS0xIR0tyY0NiTXRza2c0Q3pqejBWdGcrR1Q1aHFPNWlJMWM3cWhOYmo3VjB2TWxCSUYzcEpQaVUydUorMHR4WjJVNGdXdE91UGNlWS9ORUhaWGlBKzNIOVIrYW9lK1FYRmw1NHMva3pUZEp0OGFoNHYvTVc4ZjVyc1IvYmorby9OUS96VVlsLzVrZjFINW9sclllb0R4YWoxTkszL0FQTVh2Ri81aTNYL0FEVVlsLzVrZjFINXJCN0tjUy84eVA2ajgwYTFzUFVId2RSNm1sRUczODRoa3VCL25GdWIreTNFeC9ySS9xUHpRajJXWW4vNWtmMUg1cC92V25DV0Jtb2lSMy9tSTBjaC93RE1Xei81ck1UL0FHNC9xUHpVbWRsbUozL25JL3FQelNwYW5URnZIcHpYTytjUDlhaU1xWGdHMGhXek43S2NTUDhBckkvcVB6UjRleWZFZzRmckk3WDh4K2FTOVZwdlV1eDB6OURVWTZoNXVKcnUrYWg3bFZWa29GUEU2MStXcnFOTDJhdEduM3ByWGdEZXhDMlREY3MwV0dOL1V4NlNQVlowdXI0OFZxTmxqU2FiR250eXF6UWNyWkFOVUdQckJZamV6MTBxaHdxQ0dFTWkwMDVBQXVGaVdRZzI1Q3cxeGxlTDhMem1xMWt0Uzd2ZzMxMCtPSmVKcDFSVDQ5aXRaZ3pYR0tsZlhmOEFDdU41MXpUbW5HWHlSMG1GMVZLMC9zZ2Ztdm9jZDZXV1liZk5aaVkrTS9yQ0NmUmFYVHRmaDBpVytOc3l0UnB0WnE3aEtTbytHc1Z5SG1mRWFveVZORlV5M3VmRUFsbjluT09UR09NWVpNd0RZN0w3eGVXRmhlL2NCQkRxZVFFc2FRNGVhOWcvYTJHbStGSm5pcGV4ank4enI1cytWY3BkbjJJWUxUTWMvRFpDN2poYk0vTCtKWEZxV1FEeXN1L3h1bG1lV2x3MERkUkRXYjNIQ3pNblhubGZpVy9YeUpIMlBXTjFTcjlXY0dkbGZFSHg3MDBuMFRHR1pmcjRYK0ttaytpN2t5WnBkcDZMRTdBeXhiMVFMMmwzZkR6OGtObjdFd3lLNHBmTm5LNmZDNnR2Tk05SllybDZzcVcrR21mOUYyRnJEYTl4OVZQVnBHNnFyMm1hZmQvSkRIN0d4WGt2bXo1M2x5bmlFYmphbWsraXI1c3A0cWIvQU9pUy9SZlN6bU5mdVZrdEJDc0wybi9YNUlXL1kyUG92bXo1amp5cGl3ZC8xV1g2SzBwY3Q0czJ4OTFsdDhsOURDSUFvcmRoWmNmdE5mYS9rZ1A4SFI5RjgyY09od2V2c0FhVjZaR0VWdHYrcXZYWnU3WUNzT0RSNkpmK0oyNUoyL2tpUzlqWTVKcFV2bXppejhIcmY5bGY5RWhWWmJycFFiVXovb3U3YVFRb01HaDNpNFUveER2bkh2OEFKSGNYc0pHTW02WHpad1NueXppRWN6U2FhUzEvSmRheU5UeVVjTFJKVGtiZGZrdGtzeVRnajZyTjVJUjRUWUpQVmVxdlBpVVY2bTEwajJmam9kWkswdTNxL3dBak1qMmlvYllXUkF6a2pxZ1JSOTYvVVR1aXl5ZDBBdkdabTl5UjcxcmJrVVN4eTVoa3VLWTVUd1JndS9XTkpBK2EvUW5zN3lxekJzRXBDMEJwTWJDUVBPeStRL1pyeStNZnppVExDNHNhelVIRWJYQUpYM2ZoOElocDRZd0xCclFQd1gxejJhNlpGd1dXdkpINXM5dStzUEpxRnBFK3pZYUFYYTRlaWt5UGRZSGhmODBjTjVLK2xLQ3JhZklwYzhHQU9peVJaREQ5MUl1UlR4b0x6TUhsQmtMaFVOY0hXWU9WTnppU1VDV1lheEFSNG5kVTZFYWlHMGFyMnFZMjNMMlM4VnhDTTJkQkFYN2ZOZmpqMnBaMmRuWE9kWGprdDNPbUZ2Rjh5ZjRyOUZmYmc3VTI5bm1VSThPYzhqOUtSbU96ZnY4QUwvaFg1WkdScHBBU0N2RzlYblVxUjlTOWtkR3BOeWZtbis1NTBycG5IZlNFUmtBdGN5Z0tlQTRiTmpVNGpqTzVOdDF2VlAyTzRqVXh0ZUh4Z0VYM0kvTmVibG13UWROSDBXR0xQZkRORGMzVHcrNksxdy9ZdXQrWjJRVmtXem5SMytZL05FSFpMaVYvamp0OHgrYVE5YnAwWFk0ZFJYYzBOa2cvWVJteWo5aGIwM3NseEcveHgvVWZtaURzbXhIOXVQNmo4MHQ5UTB5OHpqdzZqMU5JYUg3SHZFd3pYYitjVzVEc294SWY2eVA2ajgxSWRsZUpBZnprZjFINXBEMWVuTGE5NDlUVHRUaC9yRjRGMy9tTGJ6MlhZbC81a2YxSDVySCtiVEVCOXVQNmo4MHQ2dlRyekdwYWoxTlREbkFmR3BCN3JmR3RyL3phNGgrMno2ajgxNy9OcmlIN2JQcVB6UWUrNmYxSHBaL1UxSXpTeWJheUZneHZHNWx1dHdIWnJpQkd6NHg5NC9OU2IyYVZ6WERXNWhIcGI4MTE2dkRrN0Q4OFo1bFVPRFRETHBGcmFpbThNd3lmRTNhUkc1Z0pXL1VQWjlGR0FabUFrZW9XejRmZ1ZKU0FHS094Q3A1ZXJ3MDZwV1U4WFNjMHBicHRHcTVieVV5Z2NKWm1CMTk5MXVVMFRIeEJrQURMZVNPK1JwQVpiMFE5UHUvaUIwanJjcnp1ZlZ5MXI0UFNZY01OTkVER3dnNlpOaDFKWE51MWJ0Q2d3R2hkVHdPSGVQQmI0U3JidEo3UTZiTDlISVk1bTZ3MzdMcjlGOHFad3pEUG1ldWZNNTkyTmRxM1hydWhkSThlYXlUWFpuenYyazlvNVlNY3NjVyt5OVBVUXJxdWJGTVFmVjFEeVE3Z09XMjludVVKTXdZdERVeU50QXc2VGZqbis1VWVXY0RsekxORlRSc0xnSEFrMjJYMFRnbUFSWlB3cGxLMEFTU05hNjdUdHgvZXZvR2ZVTFR3OEtQNkh4VGJMVzVYbWw2MmVmR3loaWlwMkFCck50a3JXVDZnV0QrYUc0OGxDcXF0YjNOSjNLU2xxUEIzSDJodmRZc2NEeVBlelVwSmJSU2VjdUpDOUJUTmVidXNwTWlEenVvU1NHSTJidjhBSlBxZ0JoOHpLWnRnQVNvUlN6VkxyTkJVNlRESDE1YVNPdlZiVlE0TkZTTmFYQURZZFV0a0thandpYVJ3THIyOVZzbEJnc0xRMHYwM0htbzFHSXhVN2JOTy9va2Ywczk1MkpzZ1pEWi9lYWVuYUF4amJnZEZsdFU2WTJhTExYNmVYdkNOU3VxT2RrWUZnaGZZRXNvV3lDMTNIZFdjTkNUWTZsWFJ6T2tBSS9GUFExcjdnYnF0TU5GclMwQUZydVZwRlFNNnVDcHFlcGtQbXJHS1dSM1VxczJHbVhOTlJSdDVJVnBEREV3QzVhcUtKOHBBVHNGUFBNUmI5eVRRVFplUkNBZFdwK0tzcHhZQnJWVzBlQjFFb0czNEs4bzhweU9JdXhDMEEyUlpWUkU3TUNmZ2thNGZ6YXRjUHlTWFd1MWJMUlpHYnBGMmhEUURacHNOT0hINEUyeWpZYlhpVzkwK1RHTnRjRDZoTmY1S1FzRzRIMUNLaFc1bWp3VXNJSVBjQlgxR1loWWU3QlhyY3ZVek9RUHFFU1BENEl6c1FQdkNsRTNNV2o3a00vbUFFQ2VvaVpmOVdFNVY2SW1IU1J0NnJXTVJxM0J4QWNwUjNjeWRmaThUd1IzWVd2MU1ySkhFNlF2Vk9zZ2tIbFZzalp5VFlvYkxDWVY0ajlFalV4UUVIWUxMNmVwY2VWR2FpZnA4eXBZYVpXeTBzTGlkZ2xwTUxpZURab1ZrM0QzazhKaG1IT1VzWWFzN0JiMzhLQkxndGg4SzNabEtPTExMOE9hNGNJYkIzSFBINFRZL0NveVlJd0Mra0xlNU1KYVRleVZrd3IwVXNtNDBWMkY2VHNGSm1ITzhsdGttR2hwNFVmZEd0SENsazNHc2pEVGJoZU5DV3JaVzB6U2VGSjFDMXc0WGFHR3FPaWMzb2hGMWxzMDJHZ2c3S3Rsd3F4UENsRUtsejFpMXduWDRjUVZIM0lpK3lsRUszeE5KVUhTT2FFK1lkenNVS1NtdU9GV3ZrNml1ZFV1SG1sWjU1Q09TckY5RnZ3VUo5RVQwUkpzWWlvNzJRbmNsUWRLOGRTclY5RFlIWlYxVENXbmhIdVl5Z1h2QnNvbVlsZU1kdWl3V2VTNXVDb2laTmpzbDN6Z240VXdXZ0FwZHpHaSt5SlNZRFFFdmFUOEt4b0JQd3FkbWpvVklQYTNuaEh1Qm93Mk1PdDRFVnRGR2R5QWh5VjhiQnRkS094Rnp6WnQxMVpHY2FIL2M0bTlXb1I3bzdhUWdzam5tRzEwYUtnZjFDc3dtSWtnRTBqR0RZQkpUVlIzc0ZheTRjU09GQnVGTkl1ZjNxekdZbG9vM1FTVkI0S2JwTUwwN3Z0OTZ1SVk0b21tOWhiMVZMakdPTXBiaHJoOVUxVFoxeEhIdmdwR20rblphN2pHYlcwN0hCaDNIa3RkeGpOTDNPY0E0N3JXS21yZE80bHh2ZFdJOGltcUc4V3grZXRlN3hPc3FvYXBkM0g2b2o1R3NaZnFnTWtMeWVuelZoUnNXNVVTMFc2cnpuQm9RSkttMTkwcEpWbnpUa2hWalVrNENVZEx5Z09tTGp5b2wvcW5KQU5rM3lvTHBWQ1I2QVhsTVNCRE9sUW5TM1F5Ni9WWXVtVUFURGlWTmpicUxXaXltMTFsS0lGYTBBS1JlR2hBZk5ZYy9pa3Bxc2duZFNpRHJxeTVRektYSGxJeGt1Y200MjdKMUVKYVNTczhLV3BaQXZ4dWxzaGhqU1UxRlRQZVFMY2xNVUZHWkhDN1Q5RnRPRzRLMlRTYmRVQkNlV2N1QjBqSE9hTjkxMUhES0NPbGhiWm9Cc3FqQmFFUWh0N0MxbGVseEdrTjMrU3JOaktHUTEwaEFhTnJxOW9jSnNHa2oxUWNFcEJLR2x3SVd5TUdob0FCWEtzbENacDJ4Tkd3V0dUYU9BalNoMGhzQVNqVXVHbVFYSStxbXl5VWZCZU9qOWNQa3E1dzhBVmpqMzg4MzVLdVB3QmZYVDVrWlo4Q0lBb00rRkVVQVpsdkt5c041V1R3b0RkRVZKb1dBTEtiVXVHV2I3b3A2di9Pa3BSTWdYV0w2RDVxWTRYbU9FaHRwc2llUmpvWnBQSDRkZVZIbU9lL2dJdmN5MitIWlJNWmFOalplYUpDZjV3MlZyRXNjMThUS21LV2ZUUzNLSVZvQmlOOWlzMHNuZHVkc0Q4MUZ6aTZNaHJick5QT0ltdTFSM1BxajArYkhwMDIyV05aZ2xxWktsNUJZd2Ftb3RhMS9KZHQ3SU1JTkpTNm5zRnk0RzVIelhGOEtobXI2K0x1b2pwTGh4ODE5TlpYdzl1SDRkQ0xBRXNhVDlGOG05cmVyeGtuQ0wvRWZhUFlicFhoVFU1TDhKYk5jZGJoZFloZnBuZmM5RkM5cEhIeldMMmt1dmhXN3hKdG42VXlaSVk4YVZqMURHNm9ZNk1DNzNIWmZkZllMZ1l3akxWTExvRERKRmNrQzE5MThjOWwyREhITStZZlI2YnhTYytYSVgzemxXaGJoMkR4MHpBQjNiTGJmTmEzVDhmeFdmSGZhN1ZicWpGOTEvdVg5UXdGeGxCTmlnYWlvTWxjK0lNOGxuU1Y3YkdxaWo1ZEJXbUVhNDNSMmxMTUNPeFdZb1R0K0xnSzZRZDJSMVEzeFhMTnlMclBkRjIvUkJlWHZlMEMvaFFUeE5uVXZob1h4Mm9aUjRaV2x6aTN1b1h2djhta3I4bGZhSXp1YzY1N21xQklaUlRQa2h1VGZoMXY0TDlFUGFwejRjaDluMGxXMSttU2N1aDJPKzloL0ZmbEZYVmhueEN0bGxkcWROTStTNTlYRS93QVZ6d25GSHR1aDRyaEovb0p5ekdNMzgxMHpzc3dvalJYRWJQRnZ3L3ZYTWFabjZScldSTi9hc3U5NUlvQlFZVkZURVdjM2Y4Rmo2dklvUlBvblJ0Ty9IYmZvYlFKTmh5c2lRK3FoZTNWU0MrZnZIa3MrZ3BZd25lSXBlbDcrcXlaRnp3OGgyc1pOejBNdjM1S0c2UkNkSXA0ZVFsWXdybkllbzNRM1NMQWt1bXhqTmR3WjRvWk93ZTkxTmgzUUd1MlJZM0pPU09TWFlkZzBzSXV4cGgyVXkrMXlPaUUwWENrVzNCTjF5R0RJelhTaEZVU0ZXK2RoMUFDMjJ5TEUwTVk2L3dCb0phS243OWhicjBHL0sraE1vK3pISm1uQXFLckdKaUx2R2F1UFg1SzlEcFd2emY2Y0wvcWp5SFV1cmRPNmRLOHVTdjZNNEFLT1JyZFFiY2VxbXlNZy9DdnB0M3NiVGtXL1R3QStYLzJxVFBZM2wvMzQzNmYvQUdxL0gyYzZxMWZoZlZmM00zL0d2U05tM3h2by93Q3g4ME5ZNERoRGV4MXl2cUp2c2JTa2Y5dU4rbi8yb2Nuc2JTLzc3SDAvKzFPajdPOVZYZkY5Vi9jcFkvYmJwTUpmNjMwZjlqNWVtdjd1NERjcFlVejJSM3Q4UVgwNVUreVkvRG8zUGRpelpBT2x2L3RYenRqVlBCZytQNGhRR3JiSWFkK2kzM0JJemRGeWFOYjVwL1EzT2tlMHVEcU12RGhKTi9veXNqa0piM1BCRzl3c1MvQ1FpUHFCSElaQkZxQjJ1RUY1MUE5THJGeVNYM1Vldmc5MHJCQTJSbW03Q09TZ2tXUll6WUJJVTloZHlSdUlMeHh2RVcvaTNURDI5MndBYmtyRWpnSGlROUZDR2J2WHZjZUc3b2xETGZDS01iMU1HNWNEQWFHMHpkWnNickdwd0Y3YkxZOGlaT3FjOTR3S1dFT2F3MjhRSEMrZ0l2WXdrbXBvM25HMnRMMmh4RnVMai9oV3RnNkpyOWJ6REhmOVVlUzFmdEwwbnA4M2gxR1duMjdQK3g4dG1ZdDVXTytKSEMrb25leFRJNC85dXQrbi93QnFDLzJNWHh2MGZweHArNC8yVmNmc3oxWEMrTVgxWDl6Tmw3YmV6ZURtV3Arai9zZk1WM0dJdXR1Rm03NW83VzRDK3BXZXhYSTJuTjhjYnY2Zi9haUQyTG5zZ2RiSEczSThqL1pUTWZzdDFHZk1zZjFSSDdjK3ptTlY3eDlIL1krV05XaW5hTGVLNlhxbVZaak1UbzlPcmdoZlRzL3NjbWxnZkxOajdHTlkwdUpJNHNQK0ZjSnpsbFdreTNqT2lreHFQRkJIZHBiSDVqcHdGUTFYVGRSMC9uSkdqUzZmN1Q5TjFlU3ROazNmMFpxVU5NWVFBU2RSNkt4Y3gvdXJHdkZ0K1ZpVm9xUzAyN29oWWpuN3FkekhuV0J3c0tXWHhYeWVweXo5N2o4SkI0Rk5LMXdPd0NpV09ubmp0dnFPeXhWa3ZCS3Q4cTBEc1d4L0M2ZGpiaDBnRHJmZXJzWVBXWllxSWpVWm82TFNTelM4ajdIOW1US29wY3JVbGM2RnJYdUJCZHAzNEhYNzEzMEN6UjhscWZadmdqY0F5dFRVYlFMc1BUNUJiY0c3QmZmdWdhWjZiVHBQMFIrTXV1NnBhenFPVExIczVQOEFjd0drK3FNd0VOM1VBTkttSGJMME0rWFJqTlZKeUlodS9DaEkwM1JnZDFGNk9CeFMyZHlEQnR4dWtwMzk0N3g3SHpDc0I4SlBvdWM5cmVkbVpIeWpXNDA4V2pwK2ZvVC9BQVZIVjVOcXN2NmZHODgwbDVuNTArMi8yc2Y1eHMyc3dZUGFSaEU1WWRKMzRQUDlaZkxsYk0xa1FoYndDdHI3VDhjYmorZU1jeE9JM0ZYTnJBSFRZRCtDMHhrWmxFYlhIeGx3QzhWbjFDY21mYk9oNmQ0TWNVL1E2UDJTNEwzOVpIVUVYYTEzbDZydURveEV4bHRnRm9mWmpoQncvQlhQY0xPdUNQeFc4UlBNckhnOUF2bld2elNuT1ZIMXZSNldNYWJJWDd5WXU2SXpTTmtGZ0ViUmZsRURsNS80MnpjZU9LVkJSOGxMVWdpUUx6cEFsemhrOUJHeUJJdlVTK3lDWmQxRXlJMUpockhqREZ5R1NobVM2bHJYZHgzYmpKYXJMSGVJVDNvWmZaZDNFMjR4dHR6dko0UjZMeG5MRCtyR3I1cWp4VEc2bWtZVEhTT210MEMwckdPMkxFY0h1MFpjbWtIN1czOXBiT2swUHZIQy9jeE5WcW9ZbGNqcWJYUGwvbkdodnlYbk9GS3c2Ti9tdm5MR08zNnVtZTRIRDVLVStSdCthMDdGTzFyRzhXSkVjMDFLRHQwVzVpOWxYcUpjMzgwZVQxUHRYZzBxY1ZKWCtqUHAvRnM3WVBnVEhTVnRTSW5qZTIzNXJrZWR2YURFcGtod2gwYzdTQ0wzSEM0cmlHWmErcUJGVlV2cUwvdEtuc0ppWEE5MHZXYUwyY2pvcXUzOGp3bXY5cDlYcTIvQWltdjYvd0J5eXhyR2FuTWtrazA4MG01TjJoNUlTV0UwTW1LMVRhV05wY0w2ZHVVdkhITFd6aUdtYVRma3RYY2V5M3M3RlBHMnJxR2pWYlY0Z3ZTNWNrWXFrZlAxdWsvaU5nN004bE15clNDZVdQeGFTTHZiNkt6eEhFTzllL2U5allLeHgzRW13Um1HUFlEeVdwenlFa20vcXNMTExjeTVDTkFhbHhjNjRRbXlXTy9LeVNYRkhpcE5lNlFobEF1N0x1TDdwNmtvTDJMaGY1cWROUzc3b2xST0tjV0M3UkIrS1psSzNvTGVpQlZZeDNvMHRQMFZTNm9mT2RycG1sb2k1d3VwMkNDUkNTWjE5eW5vNmR3dHNtcVdHT0p1NENaNzZNY0FLYmtHaU1GSnF0ZTRWdlIwalcydVNrYVZqNmh3REdsYkRodUExTXhIaGRaVm5MZ01sRTRNRmdySEQ0MnZjT3BWemgyVVhPYTB2SDFXejRmbDZuaExidGFxMDJEUnI5Tmhra3dHbGwxZTBPWHFsMXYxV3kyR0NtcFlHajRRbVJpY0ZQd1cyQ3JObktGYWJMTERhNE4va3Rod3pMc1VSQkkvQlZUODNVY1EyMGtoSno1K1pIOEEraFN4ZTFuU3FPaXA0bWpZZlJXTEpJWTdlRnUzb3VMeWRvazIrbHJrbWMvVjhwc0dTVys1QXcxRm5mV1kvVFV3M0xSYjBDSi9selJ4QzNlTkgwWHowL01lSTFQSGVENklEcWpFNVRmVkorQ0VKUVBvS1R0SnBvK0h0L0JKemRwMEIyRWpWd2Z1OFJmOXA2a0tPdTVMbm9PUm13N1MvdEVqZnhJUHFsS2pQZGdkRDcvZXVTTmdyRzlYS2JZNjhmWWU1VGttMDZhN1BVc2hzYlcrYUJMbVdPWStOd0I5RnozWFd0RzhMeDZvYmhWUDUxTktuSk5wMElZMUYrMWRZT1BRanExYUFQZXR0M0xKTlIxTGtQaUI3VGVuWmlpSFZ2MFFtWTlBVGZVRm83blRkU1ZqdTVnUGlLbmlFMnMzbVRIWU9oQzlIajhJSHhCYU4zVTd2dEZlRVV3KzBWUEVKdFp1d3pCRGZrS2Y2ZWlJMmNGcFRZSmYyaWpNamsyOFJRazJtMXV4cU8vSVVYNHUwK1Mxd1FQUDJsTWtqcXBSTnBieTRtMTNrbFgxd04rRld1Y1VKMGgzVW83dExBVmh1VmsxNWFxZjNoOStGNHl2UFFydThZV1Q4VDU0U1Q2azNKU3p0UjZGUWMxNUhCVTNrQ3ZycmRBaG5FZ09nUzhrVHowS1ZmVFNHK3hVM2tIemlFUjh2b29Pcm9mTWZSVlJ3eVlrK0lyQncyWWZhS204S3kwTmJDZW8raUg3ekVmTDZLdS9SOHY3Ulh2YzVHOVNwdk8yUFBkRzhjL2dsSmFaanJxSGN5RHFWN3VwTDlWTjVMRVpxWWI3ZmdnZTdlaXZ2MGU1emVGRTRXOGRGTnd6eGpYSnFVbnpRbTBqckhaYkljSmVlaUpEZzdqOWxUdVR4a2FnYUtWejltb2o4SHFYamFQbGJyVFlLUklMeHE4and0aldBR01LYlNlS2ptTU9WWlhrRWh5c3FiS1JhQVMwcmZwYVdDQnQvQ3F5cnhLR0VFQ3lLTVdKY1NuZ3dWc0FzVy9ndlNVc0xCZllmY2xxL01MSTlWaUZyR0k1b0RBNnoxZHh3WXQ4RjlXMUVFTFR1UG90VnhQSG9ZUzZ6d0xMVzhXelM2UzREeXRScjhVa21jVHJObGNqallHNUd5WW5tNGtPRFhXK1JXbzRoamtrN2pkeFAzcEdwcmRRS1FmTnFLMGxqSzdtZzh0UTU3cm5kQ2ZOc2wzVFdOcklVMHdUNHdFdVF4N3dCeWhTVklGN2JKTXo4N3BlYWYxVGxFUTVERDVMbmxCZSs2V00vcW9HYjFWZ0VPWG9abFFUTGRRRnlvUU02VzZnWExBRjFNTlhTR1d4NmxQdWcwS0w1QXdKU1d0NkpndmtiTXdac2d2bnVFbVpTOHFZYVN1bkRMbms5VkRSY296SXJwaGxPRkNVRGhpMDJUR3F3c3ZOYmZZSThOSTZSeVV4cUl4c0wraXRNUHcyejJraE1VT0ZYQXVGZXcwSWpMZGtMREowdEkxakI0Ung1SzF3K3pIajBRR3drTVU0R3VhNUF3alpHMWZlV0RUYjVMWmNCZ01oQk8veldtNFJFNlNVWDR1dWhZTzBReGcraTRDYlBTeHRZd1dGdmtGWVU3Mmx3YWJmUlVJclFHMkJSS09xY1p3Z1pEY0lLQnBicTBqNklocHc0MmFQb0VPQ3NEYVViNzJVOE5rTTBuM0lTSDUwNDZQMXpma3E1M3dCV1dPajlhUGtxOGp3TlgxOCtZMmVaOEtuZllMRGZnV0J5b0EyRWJ5c25oWWJ5cGdMb0ZtQUZObzNYaDAyVXdGM1U1TVdQaFVLVU5rcWtlQUN6SVkyZkMwZytaWHZrTitpM3pzODdOS3ZQNUZNMkp4bWU2elF3SGRhV2wwYTFXTnlYb0x6NXNlbXFUbzEzQk1zMUdOT0Fqa1lMOGFpRnRqT3hYR0pJOVRaWVFENWtmbXRleENrcjhrNWltbzVHRmpxYVRUWWsrUzdsbFBNTU9PNWNwM3ZlQlZsMTNNYjBHeStYKzAycDFQVEp0WTc3cnR4NUgxYjJQMCtoNnpVY3UyNmI1cCtaeStQc1Z4dW5CMVRRN256SDVxUjdGTVpsYVQzc1gxSDVydEVvZEs1dHJrV1V5OXNZQWVTRjRLWHRUa210dHY1bjFML0FBVnBvdmRhL3dEMU9aNVE3TmNRd2lvYVpYc0liNUVmbXVtaDVpYXhvNk5BVTJ1amthTkRrUjBMblJtS0VheTdxdkw2N1BQWFBkWnZhTFNhYnBuRzVMNmRnVDNiQXFRT3BvUE82eEZUOTVxaWt1SDhXUmNPb1pCaU1OS0FTQzlvMzlTc0phZWNIMk42V3QwMldQOEFxTDVuME43TDJVVzF0ZkZpMGtaMVF5V0JQei91WDFyRkVJQVMwZkV1Y2RobVQzWmF5eXpWRnA3d05rM0htQ2Y0cnFrTkVXeFNQSU80dUY3UFJhSnF1RDRCMXJYZVBrZlBiZ1dhTkJ1QVVRYnBta2JlQVhBUDNMRFlUcTRYcG82ZHBHSmprbEN3YldYUlEwaE14d2JEWlRNQkI0VElhZGlvelRrQVk3UlR1ZDF1c1U0R2w3ajEzVEVOTzE4Z2pPelR5cTdOR0l3WmZ3REVLd084VUVaY0w4Y2hHOGJYa0tsazJ6VVQ0SDl2cnRGZGlOUk5scGtsL2Q1UkpvLzlYLzJyNGVxWlRLQy9WYlR0dXV3ZTBSbW1yenAycVlwaTlnNktWbXdCOFBMai9GY1RyTDFvZTFwSU43V0NYT0hCOUM2ZHFZWWNhL05JMlRJZEdaOFppZGJVTmQ3aGZRY0xHMHRTNGppeTVsMlE0RjNVYjN1YnFOdGlSOGwwL3dCeXFEVnVMV1hGbDR2cU9MSktYQ1o3bnBuVWNXTjdyWHpDOS9kZUU2SDNMZ2JXTjE3dVhMekhnYWo4RCtSNjM3UzB2OHhmTkJ1K1VqSnNnOTA0OUZqdW4rcW5nYWo4RCtSMzdTMHY4eGZORW5QUTNQVXU2ZDZyQmhjcDRHby9BL2tjKzB0TC9NWHpBbDF6eXBOS3lLTjE5N296S1FwZVREcUYvQS9rQmc2dHByNW12bVlZVWFQZmhTYlMzUlhVN2FLTFdTVDEzUzRZTlQzY0g4allqMWZTY0pUajgwWllka1M5aHpkUWNDWTJ2WUx0ZHlmSlJjQkZHSHNPcS9tbFRubHhPcFJhTmZCbnc1MWNaSmg0U3lXTnhhTEVHMjYvUWJzZmQzZVNzR0huRDArWlg1OFVwOFE2TDlEZXhwbXJKR0Y3WHRCL0VyMy9BTFA1SlpwVTJmRFAvRW1zVW9iRjVmN25RSld4TnNTTDNSbzRZN0N3UzNkdUozQ2ZGZzBmSmZXNFlsR0NQZ09IUE9jcEptTzZhT0FvT2piYzdGRmE4TERuQTNYVmpUWTJlN3lLUEhhV04xREliYnI4bHMrenpRZHNHWW1FMlk2cnNQNnJWK3R1TVBheWxlNG5aZmtwMnBWYkorMlRHV3RzTFZtOXYrRUx4dnRKQ0hoTlJYa2ZUdllESmtlcitKK3Y3R3owOG9FZmRub2d2Nm9yMmlOZ3NvRjRLK0R5dnhIK3ArcDhWYll0QVNGTm5DemU1WGlkaWpuSHpSYmxLbHlTZXdTeG14SHl1aTRMUkhFSytPa1kwdU1qdEpBRjBsWXNkMzF6NGVuUmZSbnM1OWliOFhxSFl6VlJPMHR0TEdDTGc4QmVpNlBvTXVxeXE3cjlEeGZYZXJRNkxwcDg4MWZldk02ejJDZGw5TmxQQ3FmRUpJQ0pYK0UrZkg5Njc2OE5iQTB0OGdxL0NhSnNVWXV4ckhmc0FXQVRuZHVEdHhzdnRlangrNDQwdGgrU3VwNitldjFNczh1N2JZQXZOK3FJS2VPUnBlNGVKR1l6MFdIdURUYmhhY2RWNDMvVE12TkdPV1BZV2huNzJVTWNkdUxKaVZ6STlJNkpDb3A5RW9tQklJNkxRTzJMdGFvT3kvS3RYV1YwN1lxcDBSTk8xMXZFYi8zRmQxT3BqcDFlMEhUN3RibFdPR1BudDZuSnZhLzdlMmRtbUVWRlBUMUk3MlFtSXhzZGR3MWJjRDVyNGc3T0syV3VqcmNTcVRyZEpVT2tCSGtYRXJTdTFmdEx4SHRlemxVWXhVeU9jK2NpOExYa3NHNU93NDYrUzMzczN3MnFwOEpOTEZGcVpJUVM0OGpuODE4eTZ4cUk2dE5iUFUvVHZzdDA3VDZEVHFXWkpjSjg4R3h0bG1xWlh2THYxYlRleWpOSUpUZUlFTzYzVHpNTm1wZzlqRzNlN2F4UXhoTlRBd0V4L3JlQzFlQWxoV04vY1BvdVBxZWhUcU9TSy9xZ0xKTzlqSVBQQzdsN0x1Uldaa3hpcnFwV2FoU3VEaGY3dnpYRWhTdmpsRUpiWnp0MTl2OEFzMDVJZ3k1Z3Z2VGk1cnF5TUhjZW8vSmVvOW5PbHl5WlZPVWVFL1Q4ajVyN1VkZmd1bDVjVUpjdXZQOEFNN2RRc2JGR05Jc0U4M2RLUFk2RitsZ3UxT01OZ0Y5dmhCWTRSaWo4d1k1UEprbS96SXlrdElzcE1OMkwwZzFXc0xySUZtb3E4eXhrKzZpSWVRVmg3eXZIbGUwRTlMb28wVjgvUFk4SGZxM2ZJcjR5OXUzdE1qdzNJdUo1WkVoYlBWUmx3YmYraWY3Uyt4NjZjVWxEVVNuYnU0M1ArZ3V2eWY4QWJOem8vdEI3UzRuVTc5VWNESHd1YXc3WEJhT0I4bGc2KzlybzlOMFpSV1NNcGVWSHpROHVwMmEzblVUNUpyTGRDN0Y4VmpjQmNhZ2JmZWgxK0cxelhCakl0UTQzVzk5a3VVYTQ0b1o1SUxNTE9vMjRLOFZseFRhZEgxekRyY2NFcWErWjF6RHcyanA2ZW5hTEF4dHY5QW1oTUluMkhWWUdHVkFBOEhHeXdjTnFiL0FWODN6NGRTMi9nZnlQcTJEcW1rU1h4cjVvaStUWE9XMzJVdTl0dGRZT0cxUE9nL05SOXprSG1xMlBUNmkvdVA1RGNuVjlMWCtvdm1pUmtzb3VsUG1zR0J3MzNVU3cyTndtVHc1L3dNclE2cHBtL3ZyNW1kZTNLd1gzUXRMQWQzRmUxUkQ3UlIrNnk5QjB1cWFiOGErWVF2c3ZHVGJuWkQ3eUlmYVVYU1J5eE9icTM5RVB1MGhYMnBwMy9Hdm1GTDFrMjgwQTFVVDJCb2Q4Q0d5ZUtvbExTOGdEZlpCN3ZJZkhxR25mOGErWTg2WnpiV095QlZ3MGxkQzVrekM0a0tIZWV0d3M2d21UZVRUdStTempXRFZScVZITWM0ZGtjT0w5N0xUTWEwZ0VqVVF1QlpveTlpbUNUeU1kc3hwSTQ2TDdJYzRINUZhbm5ISk5KbUNsa0drQWtjdGF2WjlINjVLRDJ5L0x6UG5udEIwTERKT1dPdlBzajVKamdrZXk3Mmw3cmZaQ2R3dkx0VGkwb1l5SnpRZjJtcnVXRjlsRkJoa2tqNUhPUG80ZjNxNm9zSm9xT3B0Rkd6YitnRjdtZlVYbVh3SHh2TG84K25tMG16Vk96M3NtWlF5UnpWREczdUR5RjAydG1qd2ltRVVXd0F0c1ZtU1pzTVEwMmJ0MDJXdjRsVjk0VDRycWhMSzVkd1l4SzJ2clBlWkNTa3kvVnlzeXQxdXVGSXgzdHNrZHkzRkl4RkNDYjJUOFFEQnVvVThZWTI1UUt5dGJHQ0FtUlIxMEdxYThRRFlwRDNnMVR0MGsrb0VyK2JwdUY0MGJLTmlocGpSRllwMm5xYmtXVmZEREpLN1lYdXIzQ01IYzZRWEJOMG1UQ0N3UnZuc0FDcnFneTdKVUZwTGVTcjdCOHQ2bXRjNXY0TGJhS21wcUJnMTJ1UE1KTFlTSy9Bc3FNaExDNXZrdHZpYlRVRVE0QkE4MXJlSVpuaXBHa05jMFdXc1ZtYlRWT0xSSjlDa3V3a2RKT1pJWWRnN2I1cFdxemZUTkIwQjExemlPdjd6Y3lPK3FZYlhOaUlKTi9ta3RXR2xadGI4elRWTHJSRndIcUNpTWJpRlVMOTYwQStmL0FMcldZc3h4dzdBTStnVEF6YWJiV0h5U25GaDBiUkRnV3NndWMwazg3aFdFT0FVelJkK2svZUZvd3paTmYrOUVHWjZodzUvRkRRVzAzMXVHNGZHZDJqNmhPTVpoN0xiRCtzRnpiL0tDZDNVL1ZUWlh5bmN2ZDlVRFFhZ2ROYlYwTVkySDRxWnhpa1lOaitLNW9LK1FqNHo5VkY5YkowZTc2b0tEVVRwWXpCU3RQWDZvcmN3VXo5djRybFA2Um1KNVAxUllzUm1IVS9WZG83dE9yc3hDbWtJUDhWZllWWFljNXpSSVB4WEY0c1drYVBpUDFSMjQ1S3pjUGNQdlUyazJvN3ZVbkNaSWZDQmUzN1FXcTRoQkFaQ1l5TGZOYzJibVdZZjYxMzlaSGJtU1E4dk52bXB0SnRONzB3MnNMZlZEZkRHNy93QjFxTVdZR041azMrYW0vTXJkck9WTFl6dEd4dXBtRTdJajZSb2FOeDlWclVlWUw5UXZETUQ3OHFiR1NrYk5IU3Q4eDlWNlNrSFFqNnJYbVk0OXlLM0YzbnFwc1pLUmNPZ3NFUFFRcTBZdzQrU016RWk2M0M1eUR3UE5Cc29HSzZFMnJ1cGlzQlU1SndTOTMxTEJvZ1ZrVHRQVlM5NFlPU3B5VGd3MmhZT2lsN294dlJlOTVoSDIxZzFrQSsybStHeGRrWFU3QWVGZ3d4Z2NLUnI2ZXg4YVhkaWRNMC9HcDRiSlpKOGNZNkZDYzJQOWtxTW1NMHcrMkVzL0dvQ2ZpQ25oc2xqUmlGa0Y3UFFxQXhXTDlwVGJpa0o2aFR3MlN3SmJ2d1ZuM1F1NkZOQ3VnSXZjZlJZR014Tk50bFBEWkxBTXd3dlBDYWp3TzlqWmViajhEZVMwZlJFR1pxY0Rkdy9CVHcyU3gySERHMjNid3BQd3R2N0tycHM2MGNJL25HL2dxdXU3VDZlbmFRSHNQMFVqaWtCUnNzZUdSOEd3K1pSV1VOTkVMdWV3RC9pQzVSaXZhOVp6dExtZmNRdFF4THRObXF0UWJNUmZ5Y3JjY0xKUjNhdHhXam9iL3JHZmM0TFc4VTdRcVdtRGdIbS9vVndtcXpkVVRPSk16LzY1VlZVNDdKSWQ1SEg1bFdZNENVZFp4SHREZEpxdEliTFhLdk9icEFmMWk1N0pqUkkrTDhVaFVZcVhYczQvVk1qZ1l4elJ0Mkk1cWNiK0phOVY0ekpLRDR1VlNTMWhkeTc4VXI3MXZ5citQQ1ZwWkN3bnFudU55VWpOVkVYRjBDYXEyNVZkTlZEVnlyOGNLUlZsa0dueTdtNkU2cGEza3BLU3FCSEtTa251ZVZaMkZiZVdFOWMwRTJTc3RWZnFsQy9sQ0xrYWpRRGt4cjNqZmxEa212MVN4ZHVzWFIwZ2JDYXlWalVWRWNMMnBRYVp1Vk1Pc0ZBUEZsZ3Z1b1FLSkxMUGZXQ0FUZFl0ZFFoNlNjdnVnZDJYbEZNYXhwS001UktPTzFremF5QTBFSmp2TDJVSlI1cnJJN0pDaFh1cGpsUWxEOUpUNjNEWlgxSFF0QUJLcDZLY010ZFdzZFNIQVdLVXdrWHRMRTFvRzQrcWFkSUxoVWtGVHA1SlRJcm1qcWhZUmV4T0RtQkZpYU5TcDRNUmFiQUZXY0V3a3Nib0dFYkhnOFFEMmxiUkZOb1lBRnFlRVNpNDNXd3NOMml5WFpLTFNDUXY2cTR3OEM0Y1NGcjFOSUdIY296OFhiQnc1QTJTamFYWWhwY0dBK2kyZkw3dzVvY3ViVUZmNzFLTEc2M2pCNWU1WUxteUd5VWZuOWp2ODZQa3E5dzhEVlo0Ny9PajVLdWNQMWJWOWtvK1dNOHdlQllBVW1mQXNnV1hhQVo1clVRQzZpQXBoU2dMb2tHcVFDd0FwaEt5OVBsUDRuUXJKbThTVm93QmI1cmMrenZQZFZrdkZZYTZPUnhFVHI5Mk91NjA0QUxMSEJsUTE4ZzFRamxvNVdocDlhOUJIYUp6NkNXdGdvOEd5NXh4MW1QNGpVWWs4aHJwSGF5Q21lemZPTlBSWW9ETlZOWkU0YVJHVHdWcXRXMkIra0ZwTWNuQVdtNC9oNHczRUdUUXR0RTE0Tmg4MTUvcW1HSFZrMjEzUFFkQzhib2VST012eTQvVSsycWFwaG5nWStPVnJ0VFFSWlpKY3doNWlNclJ2WmMyN0o4d054L0M0bXh2R3RnYXl4UDNMb05OWFZNVDVJbnY4UEMvTSt2NmU5SkpuNjY2ZG16YXZHdmlPeWRrT2FNdXl6UTB1SVlUQVhHd0xwQ2V2M3I2b3d6c3l5dE5UUlZVR0dVMHdjME9zMi9VWDgxK2UwTmMzRHF3VEFIVTAzQkMrdVBaZDdZZjAySThQcjVDNGw0YTI5eHNEWk82YkxmTGEveVBHZTBtajFHTlBMR1hxZHNnN0Q4c1ZNWm4vUmxNeDFyMnNWNmw3RnN1eDFRcURobE8wZzNCSVBLNkZDMHo2WFFrZDBmM0oyUmtjNDdoclRkdTl5dmRRNlpISXJvK1QrL2FtTHB5S21pd3FPQ0ZzTVRRMWdBQUE4bGF2aTd1RnJMY2l4UnFhbkVKR3lQM0hldXVlbm10clRhVkpveU5SbWNwQ0lwR3hVNDJDeEhTZ3VDZGtqMXZMT2dVNDRyRWJMV2VCVU5XUnJHQmJTZ0x6NmJsUGFiS0xtWEIyVWhnUlV4NUh1S3lPbmJFNjJzRnlqaUZEVDE5SytsbmdiSkhNTkxnN3FwdmowUzk4V216VXpHOWppMGxwOFhDZGwwc1VyUUdvbTFtaXI4am1GZDdQdVNacGlaY0JvNVhFN2toMi80ckxmWnY3TzlIaHlwUUIzblozNXJwMHNMUkxjdEtOWU1BSVNGcFV5N2sxa29RanljMXArd25KMUN3aW53R2toQkgyUTc4MWhuWWxsdDB4ZCtqYWNEeXNWMHdPYS9ad0pVWHhOYWJnRkp5ZExoTjhvbVBxZVNFTFRab0E3Rk1yMkgvQUVOVEgxczc4MUlkaWVWLzl6VTMwZCthNk0yOWh1czcrYWQ3bHBsL0FjOTgxTC9qT2MvNWs4cmovd0FHcHZvNzgxai9BREo1WC8zTlRmUjM1cnBIM3JHL21wN25wZnduUGU5VCtNNXgvbVR5di91YW0ranZ6WHY4eWVWeC93Q0RVMzBkK2E2UHY1ckJ2YmxUM1BTL2hKNzNxZnhuT1QyTDVYSS83RnB2b2Z6V1A4eStXQi80TFRmUS9tdWc5ODRIY29rY2hmZTVReTBHbGZlQVh2T29YOFp6bzlqT1dCLzROVGZRL21rNnpzZnkwNWhZY0ZweUQxc2Z6WFVuVzMzVmRYdmZHYmx3MEkzb05Lb1A0UWNXdDFXOWZINW56SjI2WVpsUHM5d05qWFlmVFJUVkRDSXh2ZSsvRy9vdmtRMVRxNlF2YkgzY1I0SFJkVDl0Zk4wT2FjZndla2dlSEdpbUllTCtqdnpYSWFXcGZMU3RpZ09sbzMzWHlQMmc5M2psY1lyelg3SDZUOWo5Tm5sZ1UzTHVtK2YxTFNsbUdwZm9yMktHK1NNTDlZUDRsZm0zU3luWFluZTYvUnZzVGxkL2tQaFgvd0FqK0pXdDdOWW9idTNuL3NlUjl2dCtaeDNQeU9tNmQwWXR1MUx4dWNXM1BLTnFOZ3ZxazVLRUVmRG80OWpiUEJsbDR0c0N2RnhVbTd0UG1neFRVa2QzTzZLWEg1ZE9IeWZxN3I4ZCsyYkhoaEhhdmo4M3UrclRWWC81UXYySnpLOTdNS21OOWwrTFhiM1dPcU8wck16YjhWQi8vdEM4djFIQjd4QnFSOUY5bE1udStaVFgvT0M4eWYycERIOFRkVGU2bjRiL0FML1ZiMkhYR3JpKzlsOC9kaW90bXliVnVPNzZmSXJ2THBUcDJYeW5xMmd4NmZKY0VmcERwV3JsblNUL0FDR084RmtOMHB1bDJ5RWxXbURZYkppbGJCQkZHNlZ6M3RhUXdYNUt3TWEzTkk5RHJXc2VQZFp1blpGMmZ6Wjd6UFN3bHBGSzQ2WE9JMjVDKytjalpaanl2aGtOSkNBQkd6U1MzcnV0RjdEdXltTEplQVJ2ZEVHMVVvYksxd3R0Y1gvaXV4d3hOWkhjanhkVjlvNkowL0pwS2JhLzRqOGkrMVhYOG5WOHJqZkM0K3BrUjJQZURZZVNtODJhbDN6dUI4Tnd6eVdZcEM5NERqc3ZleWh2anllRldKcUZraEpZcUVoMUVuaE12aWFHZ3BDdW5aVHd5UExnMXJXazNKU0l5aGdYWVZnamxjNmJLck1XWktQSzJGVFZ1SVRNaXA0OTNQazRDL0xUMnFPM1NxN1ZjelRZZFN5UGhvcUtVdGJJQ05MeGIrOWRvOXM3dHlySzUwK1ZLQ3JhNm5xWXpyRFRjWEF0emUzVmZFdGNEUnNMWG54djJKWGxjK2VlcHVMWjljOW4rangwTFdmSXVSQ2xyWXNMcUJBV0J3ak9ydnYydlJmVGZzMGR1ZVd2OG9xTEFzWXd5Q0tDVncxVnN4T2xtOXVoOWZKZkp0VE15b205MElKYzNjbm9SL2dLNXdETExzZHhHR2xvVzZOV3hjN2k2ODlraGp4eitOSHM5YlBMcmNmaFluUit5K0RkbkdWY3gwa05YU1VGTkpDOGFteU52Wnc4MVl5ZGoyWDN2c2NOZzI2Mk82K2JmWmo3Ykt2TDJIMDJXOFhuNzBzWUlLZlJlelRlL3I2cjdKd3lwZFBUdGJLNE9rSExod3R6UmFEUWF5TzV3UGpuVmxyT201SEJ6TkRrN0djdXoxa2J2MFZUdHNMWHNWdU9CNFBGaDhSZ2hpRVVjUXMwRGhXTDV5MStodDdsRmdjNE8zNjhyMDJrME1OTEg0VWVieWRSbnFWNFVteGVXN3JOMWVJRk5CK3dTc3NibTF6M25kcENPZmhVOGR5eWJmeksrbmdsS1RDaVhUMFUydTF0dndrbnVjRXhDNDkzdXIyWDRZMkE1TjVuRHlKamMyVTdocUdDYmhZa2NSWlNJY0Z2N2tLcHJab25zZUxzY0NDRDFCWFBjUzdFTWxZZytTcm53R2trbUpKTDNCMXlUejFYUWo0aHVnVlRHTWdjMERsSXo0bEpGaDVuZzVSemVUMmVjalNNRC84QUoraXVkK0hmbXBSZGptVmNNWVBkc0JwbTlMdEIvTmRBa2UvdTRtc05ncHZMNEl4Y2dtL1JaOGRIRjl5MWkxK1NmRnMwYi9NL2w1d0IvUmxPTDc4RlFkMlBaZUgvQUliVC9RcmZYVkhoNTNTa3RZVzliS2ptd2FWZndsdUdwMVQvQUlqUy93RE5CbDcvQUhiVC9RckR1eUxMZy84QUNLZjZIODF0ajhRTGVxQS9FYWkyenhaVVBDMHEvaERlZlV0L2ZOT203Sk11L3dDNklQb2Z6U1VuWlBsMEgvc2lEOGZ6VzZTMTlRVDhZU1V0YlVhdmpDb1pscHZLSm9ZY21vYTVtYWk3c2x5NS91aW4raC9OQ2QyVFpjSC9BSVBUL1EvbXR4L1NEK3JsbjN4enVxeUhwa3l3OHVwL0VhU2V5ZkxuKzVvUG9melEzZGxlVzRtRS9vZW4raC9OYjBhaDM3U1hxSHZlMGk2UTlLZ29aZFJmTWpSMzlrMlc0MjZ2MFJUK0wwUDVyUXUyTEwrV01oNVJiWGZvbW5Fa2pqR0xYdUNiRHo5VjJTcnJaUEF5K3pWOGtlMS9uV2FzaUdDTm1CN3FacnROL3dDa1B5U3BhWkpHMXBmZUpUalVqajgxVTJXb2xld2FXT2NTQU9ndXZDZS9WVmRPODl6SGZuU1AzSmhzbGw1WExrV1o3V2ZmdFBnamdTYytSdDBvV0k1dzlwYWRycGZYOUY0eXh2a0FhQ0Nxc0Y0VTAwTjFjY0dYRTlxNW9vc2ZPaDNoa3RkVjJIQnJEcWVRVXhtT01pVmxqeVVtSHh3MHcxRHhMNkgwdktwd1Zud2pyMkhWNDhqOENTU3Rmc0V4R3UwdElCV3Z5em1WNVJLMnAxWHNVdlR0MXU0V2xSNWVMZm1NUlI2aHVFV1FOWUw3S1d6RzhwQ3BxcmdpNllvajdQVDE0WUNPRlQxZFVaWGNvZFpLYm5kS0NRdk52TkVBNUZsUnNiSVI0dDFkMG1IdmxjMEFFcFBMK0NTeXlOSjRKWFJzR3dka0FhNlFBVzlWVjNNNkxZTGwxemd6VXhidFM0SEJSdGE5eGJ3Rlh5NDFUWWV3Z0hjZVJXdllubkdXVU9hMTVYTzRadWRabUdudytNdGFXM0E2TFZNVHpUTFVQUGR2SUhvdFdkSlBpRWhKZHQ2cDZDaE1ROFcveVhLRFFjMTAxV2JPY1Zsc0RtNzN1VkpqV3g4SnVHenJib05wMUFHUlR1K0VteVkwVHVGamRPUjFVY0EzVERLK0VuZ29ObzJKWE1vcFhHNXVuSXFRdDVUOGRaRS9oR2FXUDh2cXVPQTVJV2pnQXQ0VXl5TWZzcGxnaTIzL0FCVERHUkVjajZxbzFSTEV3eG90NFV5R05zamlHTThmdlVtMDRQVWZWQTBFbUFEUUVRYVBSRU5KdHNSOVVGOERtbEJReXc0amo4Z3ZkeTNvQWd1ZG9DZ0szUWVxT2psaDNRSG9FQjhiaDBSVzRrMjNCWG0xckhsU2lXS0V1YjBXVzFGaFlweDdXU0RaTFNVclRlMWxLSlpLN1J2M2dVWFROYjlzRlZGZEJVd2drSGIwVkZVNG5Vd2tnaDMwS3NlQ2hlNDI4NG1Janlwakg0eDFDNTdQajd4enEraVVPTE9QMmwzd1VTenFMTXl4TjZoRS93QXE0UU9SOVZ5VjJLdVAybEE0by96VThGRTNIVmptK0lIa2ZWZS95MWpad1F1U210Ziswb211Y09xTDNSQ3Q1MXc1OGFCeWhEUDRCNVhKamlCODFBMXBIMmxQZEVUY2RiazdRQ0JzVDlVbE4yaFA2RXJsN3NUdDFRemlOMVBkRVRjZE1kbjJZL2JjbDVNK3ovdHVYT2YwbmZ6VVRpRitxZDRDSWRCT2ZhZzM4YmtOMmNweVA1eHkwTDMxWjk4SkhLNzRDSWIwTTNTdU84aFIyNXFkYmVRcm5UNnh3NEtBL0VaUWZpMlU4QkVPbFB6cTl2Mmo5VUgvQUM4a2FmalAxWFBEVmtqY29UcGllcW5nSUd6cDBmYUM4RDR6OVY1K2Y3L2IvRmN0TXp0OTBPNzcvRVBxcDRDSlowdWJQcjk3UFAxU1VtZXBpRFo3bG9HdHc1S3daaXA0Q0padGsrYkttUW45YTdkVjArWVozM3ZJNHFraWtjN2tyMDJ3VEZwMFYvR0gzWWs2VUc1dWx4VTJPNVNCbkRTVXBOV1c2cDhjS0o0NWJTMTRIQ0FhelZkVlRhaldoelZvajJCVmhZa1R4eXdmUHp1bHBLa0Rxa0gxaFBWS3kxQlBWUFdGRlR4bVdFbFlMSGRKT3JiWFNUcG5IcWwzU0ZOV05JQnpiSFphMGxKeVZKSlF0Uks5b0o4MDFLZ0c3TTk4U3NYSlhteG0vQ24zZm91a29HU29xYm1tL0NsbzJVSlFFaXl3akZvS3dXTGxuYUJuZ0tKNFJMTEFaZEdFQ1VnMG9valJSRnR3dWtGOUtscHNpbGxsalNvUUdWalNqOTBWTmtHcm9vRlF1MXBKUlJFVTJ5bUhrcE9ZQW9TaGRrZm1qdGpDZ1gyVVRPVkNVTWs2ZUVhR3BMVXJISnI1VVhteDJTbWNSWW11SUd4V0lLaVdWOXQwdFRRbVFpNEpXd1VPSGhwYWRLRmhCOE9wNUgySnV0aHBZM01hTG9WSEcyTm9UWnFHTUI4UStxQmhGcmhidTdjTGxYanNVamlqM2NGejJwekQ3c0RaM0NxcHMweVN1MDZqWkpET2p6Wm5aRmNBaER3MnRseEtXMjlpVm9WRytXdWxaYTV1UjBYV3NyNElLY1JPTGVRQ2daRFpNQnd3eE1EaXRuWk4zYmJYU0VUMnhRZ0R5VWZlQ1hjb0NIdzltRCtlSHlTQStBZkpXT1lCK3VIeVNBSGdiOGw5a1I4cE1hZkFzZ0xOcnRDeUFqUUxNdENuYXdXR2hUQXVqb0E5Wlo0V1FGblNtZHpzcVI0QlRBOHdzTmFpT0ZySUhHeXM1MFJqWnFLVXhhZzcyTjF4ZjVwK002ZDFON215aXk1czRvS09UbE1QMklZeS9ETXl3VVQza0I4bDdFK3Y5NitqSFRpU1RicXZtakxWQTZoenRSVkRObWpmYjVoZlIxSklEUnh5bm0xMThCOXJkSzhXdmcvKzMvZG42ZzlpTmI3M29KTC9BTHY5a1A4QWVBdTdrZ0VqelYxbFhPOC9aOWkwTlZFUTFqRHFOemIxV3ZVenhJQk5mbEF4M0R4aUZDOE5tQWNSeU9pOFhDSGg2akhKOXJQb0dyMC9pYVRJdisxL3NmcXQyUVpucDgzNU93MnJnazd5VjhPcVFEZTI2M2FWeklaTE8yMzVYd3AvSjg1NXJLU3J6Qmh1SzF6M3hzQVpUdGxQL0J4K0srN1laMnpTYUh4aTQ2bGZaZEpsV2JCR0tQekQxSFR5MGVva21PdDNhRGJwNUxQM2Znc2lNV0hpWHU3L0FLUzJGamg2bVR3WXR2eCtDbGYwL0JZN3Yra3ZkMy9TUnFFZlVuQm5WNmZnczZ2VDhGSHUvd0NrdmQzL0FFa2UxZXBPRE5ta2J0SDBYdkNPZytpam9IN1N6M1lQMmx6WXZVNWNTUkxUMC9CWTBOUC9BTExIZEQ5b0tIZGYvd0FnVTJ4WG1kcE1KWmcvOWxrbGhIUkJMTGZiQzhXaXg4YW53cnpKdGlaY0hENFJjcjJ0NEFEeFpMd3ZFYjlSbERnRHdtdThiT1FRUnNsK05HWFlYQ0RqM0lnT0J1TjBXMnlGUElXdEdnYXQraU0zZG8rU20yK1E1U3NqYjBXZGdDdk9kcEtHNlRsTVhBS2hZS2J4Tk5sQ0ZqaGZrTE1SN3gxdlZIWXl4NVI3dmhvWGt4dFpvejlERFdiYnJWTzBISEtYTEdWYXl2bmwwUng3bHg2YkZiYks0TWFWOHZlMmgyalUrQzltV0xZU0pXeFZrek5UTjkvaFA1ckwxZVZMSEtIbTBhdlQ4SGo2bVA2bytFODhZL0htTHRFeGVkMDdud09xTHRKZGNXc0VlTE1GSlRUbWxoa0RyZFR5dURadXpUVVVVMFppYzR5VEhkd1MrWGF6RTYvRW95SjVIdjFEVVBSZk04M1RuR2J6VGZCK2krazYyT0NzWG9qNlNvMzY2Mk1qZzdyOUpleFFXeVZoUC95ZjRsZm1oZ3J6M2xLSGZGb2JmNTJDL1RIc1RGOGw0Ui84bitKV243TjVMYlg1bmt2YnlWN2YwT243RHBaU3RZS0x2aUtuMFgwYXJvK0hSZkxJMjlGQndJY2lPY1FvRTNLN2ttb0t3b3lUWlJaemQzZUJUdVBRZndYNG1kdkUxKzBiTkJCNXFQOEE2UXYybzdSYWp1Y3ExYi9JZndLL0VidHZxZTg3UXN4bS9NLzhBdks2NWU4Nm1MajZIMFgyY2hzMHVUTCtmOWlIWWVRY1ZjZXBZZC91SzdnYWdRc01iZDNuY0FyaC9ZbkhhdnYvQUVEKzRydHI0MjNEaVJmelh6anJqY2MwWWZtejlBOUZ5S1dHTTVmd3BCNFhuVG9ZTHlQMnN2cXoyVit5RXh0aHg2c2c3eHNqYldrYnFhRGIxK2E1RjJIZGxzMmZjY2psTFN5Q21lSE9KR3poL2dyNzd5NWwySExtR1JVdEtHdGlZZGczaGFQUnVsU3pTV1JvK2ErM1BYbGtuTFNZcGNwcCtmb1gwRFd4UnNZMW9Ha0FDd1RBSXR3aFJzNFJkTmw5YjNMR3RwOENsRnhsd1ljRytRUXU3Ykx2d0I1SStrRUpTZDQwa05kcGIxUGttWXNTdmZaeWZ4Y0l4UE9ZNDNNUE52RDZyNXU5cHZ0OGo3T2N2VFVjRXJQMGc0bU56SEVDd08zNXJwdmEzMmwwZVJNdnoxTlRJMXN6WXlZbU9POGg5UHhYNWw5cC9hRFU5cHVacW5HS3d1amhsRzFNL3dDeWJrMy9BQlhsdXQ5UVdOYkl2elBmK3pQUko2MmU2YTRTczBmR01SbXhlc3FjVHFwbnl1Zkk1NEwzRjFya25hNjBER3NXT0lUbU52RER5RmJabnhvTUxxZUUrRStTMWxrUGl1TjN2WG05TzNpVnMrd2E3S3M5Umo2VUdvNk4xVkt5SmpidUxnTDlWMnpKK0F1eTVSc1lZeHJlQThPSTMrdjNyVU1pWllzV1ZNd3VPbDEwbDduU2FPbWtXQzgvMUxPOGoyeGZCNlRvK0haQjJ2SkZ2aEdOU1pheE9teEhVUjNUdGR5VitodllYMmkwK2VjaFVPSXRsRDZpVWtPQThyRDgxK2ExWEErc3Buc0xpQUJaZHE5alBPOWRnK2VYNExVU3ZkaDhjTjJBL0RlenZ5QzJPaWF4WUtqSm5nUGJIcGIxRzdKRmNxdjJQMFZaM1pBUFVqeVJBNW5SVnRQWHRmQ3h3R3hhQ2p0cW1ub3ZxZmlZMnU1OERlT21OT2ZIMXNTbzk0enpTNW5hZWlpWjIyNFFiOGE1czd0UTNyajgxRXZZRHlrWFZRSFJEZFdqeVhIbHgrcHp3ckxIM2tEeVVYVlk5RldlOXFEcW02cFMxeFpXbkxCMWFMb01sV0NGWHZxZHpzbDNWbS9DcFQxalpZanB4OTlYWkNkWE9PM0tRTlJxS3gzMWdUYmNLbkxVeVpZV0JVTVNWRDJURFhzRXJpRlE0NkN4S3k0ajd5Q2JXTGRraSt0ZTUrblNTQXFrdFVtZDAySEpGL0VoNldvWkpDQTl4YWI5RkhYc0xFMlNiM01lQUhQRFQ2cVlmdHNiaFU4bW9zdXl4WHdGa2xzT1VwSk9MMkozVXBIWFNramJ2Vko1VXgrSEJGTHVFZXc2YmkrNjlEZHZKUkNic0FRaVNDazJNZ3RxMnNPWFdCUTRuZDQwdGQ1b2ZlV0l1cDFUZE1lcG5sMFhFbUJDTGhKMzVsTGplSk13N0NNUnEzRUFVN05Wejl5L09UdGR6ZU00OW9GVldkNlRFK3hzRHR5U3Z0SDJpODV4NVB5ZFBDNXdFbGJFV2o2LzNMODFjWXhPU0tuRStzbDVOaVVUZ2V6NlJqY0plSSt6T21uRTZTTjBUUkp2cEd5Y2RPeDhiWE5jdUw0YmlsVFdWOGY2eHhDNnJockhlNU1MblhObDVyWDZiYk5TUjlYMEdwM1ltaXpiVUVzQVdXU2pXSCtTU2JMb0ZsS09ZQTJPd0twUnhPVTRVSG56cUdPZCtockdjY2RqbzhTb1l5NGZySDIzKzlLNG5WRDN4OWo0YmJMbkdmY2ZkVlpzcFltdXVJWnJmZ1Z1c2p6UEEyWHFUWmZSOU5wV3RQRlVmRitvYXBlOHlaNWw1SGVhc29BSW1Yc2xZNHhFMEVvVlJXV0ZnbTFSNTBsVzFOeVFDcXVjNmQ3bFNmSVhrbExTT2RJYkJHZ1Jhb2xNaDBoV2VCWUM2cmUxeEJLeFI0WjNqZ1NyNm5yV1lXeTFoZE1BTDZoaWp3dGpTZWx1UW9ZaG0wQWFHa0Rwc3RWcThja211TG14U2tXcW9mY2xMYUxDbFJlbXRmV092cmNiK3FMSFRrbnFVclN3NkxXVnJFQUxYU0hFZEdTR0tTSFRiYXlzMkVCaENUZ0lzRTBCY0hkS2NXT1VrQURmRWVVVm9JSFZDYzhSM3VnU1lreG5ObDJoZThiTGpkR0JEUU4xU1B4aGwraUc3RmlVYVJONXNiS2tOKzBqc3J2Nlg0clVmMGs0bnFwTnhKd0hLS2liemJoWEVmYVAxUm84VUxmdEg2clN2MDA2OXJGWi9UTGowS0RiWjMzaEc5dHhxM1ZHWmpWajhTNS8rbFgrcWszR0hrOVVQaGs5NFIwWnVZQTBjZ3FRekt3ZVM1Mk1VZWZOZU9JdlBWRDRMSjd3anBJeHlLVHFGSVYwRHhmVUZ6UjJLdWpGOWFYa3pISTNZUEs1NEJ4WnpxUnE2ZmpWK0NHRFQ4aVFybHB6Qk83aDdsNW1QVklPNzNJSGdHTE9qcVlsWTNoNVAzcklxQ0RzVnpTUE1zek9TNHBwbWE1QU9DVUh1N0RXZEhSSFZEV2pleCthVXFPNXFCWXRiOUF0UGp6TTUveGJJcnNkQkd6ckZjVUdEdlJiVk9YS2FwdWJrZklLbm55aU55MHVTc3VQU05PenpaRml6T1JiVmNwaWd4Ym1WdFhsdWFBa3REaXEyV21xNENmMWV5MitQTWtFZzhUUWZtcG5FcUtZYnhzM1RGRUJ5TkRmT0dIbmRBZldFOExlNXNQdzZjSFNZN241cXJyTXNzbEI3b2o3bFlTRW1xbVo3dUF2T2tIN1JWaFVaVnFta2xybldTTDhHblplOTlrU0lDZEw1RmVFcHNzbWlmSHl2YVd0RzlrZEVQZDR2ZDU2b0o1VVM2eURhRnZHZTlVSFRHeVhMN2RWQXpCTVVRSElZTXA4MWtPU3ZmdDh3cGlwYllsSHRBY2d4NVVRRDVwVTF6ZU5sbHRZMVNnckd3TGhSTUJCNm9iYXRwOGxNMUlLQm9sa1NDMVFMd0ZsOG1wRExDVU5Fc2swZ0hZcU1zb3R5bzkyZk5Da2lKSEtZbUkyQUpwVzNPNlRMeGRNdnBIT0tHYUNROUNtcVNSTmdzNlRiWW9EN2xXTE1La2VlQ21vOEVlN29tZUtpYkNnSWM1WTkzZTdvVnM4ZUFueVRVZUJnY2dJZmVVZDJtb0NnZjVMUDZMZTc3SzNRWVhHM215ZytHR01jQlR4N0NxalVCZ3podVFWTDlINk9pdjZpUmd1QUFrSkFYRXFlS0VtVlJnMzQvQlFkRjZLd2RHTG9EMkp0Q0tFaXowUW5SSHlUaFp1b215Tk9pVUpkMlZNTU51RWN0QjZLVFdpeUpUUk5vcjNSUFJTWkFtR3RCUENNMksvQVE3a1RhQWJUaTNDZzdmYXliN3AxN1dSUlNCYzNERkVybTA1ZWVFWm1IazcyVDdZUXp5VXhLR2pnTG00TlJFL2RkUFQ4RmdzRE9pTytjRkx5U1hVM0hUSmtEUVVtK1UzS0k2NUs4WWhaRXBFRnpJYnJ3ZVNqaUVIeVVtd0M2T3lFWTJGK3dUdFBocm51QklKUnFPbWFDTDJWc3dzaWFEc2czRUpVT0hCZ0YyL2dyUHZtUkRwc3F4MkpzWTBnS3BxY1JlZFZpVng4a0wrcHhkckc3RlU5VGpSTGpaeCtxcDVLcDd6dVNzTmJyNVEwRFF4VlZMNXpjT0orOU80UlR1clpHc0F1bGFHamRQSUdnWHV1bTVReW1HNlpYRDFRTmhSUmFaU3lvYWRqSHVZVDh3dWgwSUVZQXNCWkswVWJZWXd3RGhPaHVnWFNaTXRMc0dsbXNPVmlHcEFLVG1rMlM0bHQxU0dDejVGekFMeWo1SkFDekcvSlA0NlAxbytTUVB3TlgycWo0L1puN0lXUndzTitFS1lGa2RBTm1XanpVd0Zob1V3aW9DejNBQ3lOeXNEZlpUYTFGRW1SOEhncE8zSVdRRmtLeFNLRGJiSkZnMGNyRUxMdTNVMnhGMis2bDNkalpLbEpKRDhjSEtpK3lmUSsvWmhwbWtiZWZUb3V5MGtkbUdDK3dGbHp2cy9vakRaNWJ2cTU2cm9BZmE2K0ErMStwam0xMEhIOFA4QXV6OVRldzJnbG90RExkK0srMzVJUEYrcmxOTU9BbUhNWkJUdVpieEhkSndPdThucjVvemlaR0hkZUV5NVB1dGVSOUg4UzFLRDh6Y096ck9UTWdZelQ0bDR1NWpmcmxEZHlRdnBwdjhBS1ZkbjFDVEhWVVZlWmh5UTEzOWhmR2tjMnFOOFIzdUxicmxPZjhHZlIxTDVnMndKc3ZXZEU2akpUZU9Yb2ZPdXZlejBOVEZabDN2MFAwZi9BUHhQdXowY1VkZmIvaGYvQUdGNy93REUrN1BmOWpyL0FPcS8rd3Z5ckR6NUxOeWVuNEwxWHZXVThaL2gvRitMNkg2cC93RDRuM1o3L3NkZi9WZC9ZV2YvQU1UM3M5LzJPdjhBNnJ2N0MvS3l6dkpTczd5VTk2eS9tVC9EK0w4WDBQMVIvd0R4UGV6My9ZNi8rcTcrd3ZmL0FJbnZaNy9zZGY4QTFYZjJGK1YybDNrczZYRG91KytaZnpPZjRmeGZpK2grcW8vbE5lejRqL3FsZi9WZC9ZWHYvd0FUVHMvL0FOa3Ivd0NxNyt3dnlyYkk5RWJNNU05OHlBcjJmeC9pK2grcUgvNG1uWi8vQUxKWGYxWGYyRjRmeWxtUVhjVWxkL1ZkL1lYNVppZDNralIxVnJYU0phekwrWStQczlpL0Y5RDlUWS81U0RJVW4vZEszK3E3K3dtRy93QW9sa1I0dDdyVzcvMFhmMlYrV2tPSWFlcWNaakFiMVNIck12NWpQOE80ZnhINmZEK1VDeUd5TWtVbFp2djhMdjdLN2oyUjlzbUY5cUZHK2ZENmVlSm1uVURLMGkrNDh3RitQbloxUXV6OW1lbHkvQmQ5WFVteldONU80SDhWK3Z2WWprZVBKT1NNTHAyeGh0UTJEVEo0Ykc5eXJtbXp5aytUenZVZERqMHlwTTZUQTZadGE1cGNDd0RZS3dhYm15VGg4Ujd6N1JSMmxla2hrVzA4YksxSUk0QW9MN2JxYmlCMVFYdkJkWlY4bVpYd3hxbnQ3bUtSb0JKOVZON3lIZWk4NXVodWxvMk85MENWN3o0U0xEelZpVTR4a3JZT2VkeGJSN0Vxa1EwY2twT3pHbHhQeUMvTHYyNHM1ZjVVOW9FREthWnJxZGtUbzNqVmZjYVIvQXI5RHUxUE5WSmxES05kUFV6ZDJId3lNQlBucHQvRmZqRDJtNW1rcmNYeGFkMHpwTDFNcGFYT3ZZYWl2TDY3Sy9GaWwyczk3N002U00xTE5OZHFPWTVneEwzaXRkR0wzaGRzVjBQc2h3dXJrcVJpTXJnWW50c1BwL2V1YXNoTmJWaG9Gek1iTDZEN1BzTC9BRVpsbW5wWEN6MkVuamZnTEk2dHFWajB5VVZ5MmZUdW42YVdYTzVSN1VibGhwUHZzUy9UTHNSLy9ST0VmL0kvaVYrWldIUHRVc0hrdjAyN0U1Qi9rSGhIL3dBaitKVmIyWmhWdCtwNS93QnViYmd2eU9uTzNjcGtBQkFiSjRBdk9xQjVyNlA0a1ZTcytLcUR0aEhsQ2NUWXJJbUJVSkpRRFlLcHFzc1hIaGtqQnBtbTlxY3VuSk5lN3kvSXI4UmUyU1hWbi9IOStaLzRCZnRYMjExM3VXUTYvaTFyL2dWK0ozYXpBSk04NHhOcVBpbnYrQVhuczJSWWM2L1Erb2V6UHg2T1dOK2N2N0YzMk1NdFVYNE9nL3VYZU1wWmNxYzNZekJoTURTNmFjK0Y5cnRIMy9ldUtka3NMWkJBMkhlb2tJWnArZXkvUnIyWGV4TitHUXc0blh3RVAxTmUxem0zMk8vVmVIMU9HV3MxOGVPTjMrNTlCNm4xV1BTTkZGUmZNbyt0ZGtkYTdGdXplSEkyWG9XeHhpT2VTTzB4MjhSdi9jRjFHRnZkaS84QXFqd0VLSUJvN3BnQWF6YllLVDZodW94djhJSGt2cWVteDR0RmpTNFB6M3F0VG0xdWVXV2JiYkR1a3R1Q285K1R5VXN5ZHNnTGdiMk5sQ21tZEkrVHZScFkzZythYzhrY2trN0ttSnRLcDl4d3pHeDMyV3Nac3hsdUJVY2swa3pJNllDN3J1QVRsZGpySXBaV0FqdW1OTHRTK0xmYXY3ZVhTU1M1V3cyb3Y3eXczYzE5bkFnVzJ0ODFRNmwxT09teFZIdlQ4ejBIUStrWmRkcWttbnR0ZVhaSE1mYVM3WHF2dEN6Q3lpYlAzbE5RUzJITnJXUFg3MTgvWnF4V09taWQzWnM0N0sycmNROXdwcFRVT0pra0c3bkc1dXVXWTFpcjZxcWRER2RRRy9LOERwdC9Vc3JsUCs1OSt5WThQU3RQR0dGSyszSEF0VU9Na2pwWGJtNjJMS1dCSEZLZ1BjM3dzMzNWTmd0QkppVlMwV3VMMnN1dVlGaHphQ2tiNFEwNmZKZDF1Wlk0dFI3bG5SNlI1Skp5TGFrWTJtZ2JUczJMU21LbDB3YzB0Y0xXVmFKUDFsN3BneUVqa3J5Yms1UGs5YkNLd1JwQm5WVlFJM01EeGR3c3I3Sk9hWmNtMXNOYTE5cFd1QmVSMWFPZjRyVjllL0trSDNidWJvWGxsQi9DeWpuakRPbXBJK3g2TDI2c3JVbEpUd3l3VmZleHh0WTQ2WGNnV1AyVVkrM3ZsTmczcDZ2K3E3K3l2Zy9Ib3U3ZjNvMkFIUmE5TmpjVHlHRndCQzl6RFg1bWwzUGxXWDJVd3B0N3ZvZm9hZmI5eWtQKzcxZjlWMzlsUi84QWo5eWs3YjNlcy9xdS9zcjg4SFkxQkd3TkxoZFpiamtJdHVQb25lOTUzNmxQL0RXQk90eStSK2lBOXZUS2IrS2VzL3F1L3NxWTl1dktiaC8xZXMvcXUvc3I4OUk4eHdNNnRUVE0wMDdlUzIzeUNSTFY1MTZsaUhzeHAzL0Y5RDcvQVA4QTQzOHRuL1VWWDlWMzlsUy8rTnZMaEg4eFZmMVhmMlY4RU16aFFpMTVHMys1TXN6cGg0SDg0MzhGUzk5ei9oWlkvd0FPYWY4QUY5RDd0ZDdiR1hQL0FDS3YrcTcreWd2OXRUTFkvd0M3MVg5VjM5bGZEWXp4aHdIODQzNkJDa3o1aDUvMWpQb0YxYXZPL3dDRmsvdy9nWDhSOXhuMjJjdHQvd0JSVi8xWGYyVkIzdHU1YUFQNmlxL3F1L3NyNFZsenRRTysyMzZCTE96ZFF1ditzYjlBdSs4NXZ3czc5ZzZkZnhJKzVIZTJ2bHZTN1RCVkFYL1pkL1pXV2UyL2xhbFllOHA2c2tqYXpYZjJWOEp1elZUZDJRWE4wSGsyQ1p3eVZ1WWNTbzZLT3hkTTdTeTNWVzNLUWpVOVAwdUdQRFAwbjdNdTJyQ08xSjdYMGxQVU5hNGFnNlJwQTR2MUM2Z3gyd3RzRnl2MmVlemM1UnlGUk1saDBWTFNkUkxkK0F1ckVhUmJ5VmVkbmp0VHQzTlFKdEFkeXNPaEJ1VVBYcEtuM28wbmRKYU0yc2lmRmcyRFU2MTBjd0N5RlR1YTQ4OVZudm14eWJucWkzSXNUdFpVQWxacGVCNm8wbjZob2FUeUxvTmE0U0hVM29xSE9tWmhsekxWVGlrcERXd0Mxenh3ZnlWaU5jRnJZNTdhUGpIMnpNOFB4ckVxT2hpbERoVFNGcEYrTmorYStSTVJxVEpLYWM3Z2JyZWUxN05rbUs1MXhLbzFsN0pwcnR1NjQ0NkxRSllnYW52Q1RkeHNucGVaNzdUWXRtbmlsM0wzSnVGT2txMk9OclhYVEhQTlBGR3kvUmF0bE9nTURXdUk1c1ZzTXpydUM4N3JwcWJ0SHM5QmpjZUdNdmNPNkJWZmkxYjdwaDBzNWRwMDlTbU84c0xMUisxWEd4UllEVVUydlM5N2JpeHQwUWROeFBOazdkbWlyMWpNc09OcSs2Wnh5U3NkWDUxZVNkUWROc1I4bDJxbWJwQWhQQTNYRXNqMHJzUXhoMGx0V2wxeVYyK1d6WUF6aHc2cjZidVVQZ1BpZXJibk56TTFjdWx0Z2VGVy9HNDNVNUpTMzFYbVJHWTNXWTBDQ2VDRFlKNmxvV2tYTmg5Nnl5RHV1UjlRc1N2TnZDYmZKY0FaS1NwRk1iRDhFaFdTdXFkMU1nazc3cVFnTGh3cFlJdkIrdE5ySHlWcFRVcFlBVUNCcllEZnI4azdGSVpSWUJGYURHNFhhUXBQcnRIVmVpaURHK0lwQ29hWGsyUU1OT2g1bUxsdlVwMkRHQzRja3JYQzBuYnFyTERhZHpCYzMrOURRYWtXTlRXbHpkbFVUT2ZLNDJCVmtZQzg4Sitrd3N1RjlBUDNKVmcyYTlIUVBrc1U2eWhKdHN0aS9SSkErSDhFYUtnMDh0L0JFbVN6WGZjTkxlRUo5UFlyWkttbHMzaFZqNERxdFpIWkxLd1VnNXNwaWxhT2lzUlFPYllrRkNuYjNiZUVTUWpheFR1R0JSTVRXN3Blb3FTSEZCTlE0OEppU0pzWXpKSzJQaEt5WWdHN2Jyd1pMTWVFWm1Fdms1Q1p3VGF4TjBra25YbFlaUnZlYjJWOVI0SWJpNFAwVm1NSTd0b09uOEZXM29kc05haW9pT2lMN3JZSys5MjBiV1F6UXZKdnBYTnhOcktRd05ISVdPNllPaFYwY1A4QU1MM3VMQnlwZG5LWlJHNTRCQ3gzVXJ1Q3JxYUZzWTRIMFNVbFUxbDloOUVYaGc3MkppbmtQTGdwdXBDZW9VWnEwYmtXU2pzV3NUdUZOaDNjTkdrTGVvK3FscDBpMTFYT3hYVjFRamlSS20wbGx4REwzTHIzVDhXUE9nRmc1YW1LOXhLbUtndjZvYU8yYlk3TmNvMjE3Sk9mSEkzZzdtNm9yM0hLWGthZlZHa1N5d3FxOXNsN1hWZEk4dVBvdk1GdWQxbDdoWTdJNkpZRXlvYnBWaHdjQ2hPM1IwTHNrNmE0NVFYRStheTZPNEtDNW84eXVrNVpGenlEeW9tVnlrSXlVVmtEaWZoWExKUXRwY1NwTmE2NnNtWWE5OXRrM0RnYjMvWks0Mmh0RlV5TnlPMXBWN0ZnRHYyU200OENJdGRwK2lCeU8wYTh5TW5vVWRrSlAyU3RrandrTkc3ZndSaFJOYjlrZlJBMlNqWHhoVG5mZWlzd1Z6dWkyQnNJYjAvQkViYml3K2lEY08ybEN6QU9wc2pEQ1dqb3JvdEo0Q0hwZDFGbHpjZDJvcjI0YXhvNFUvZG1ONkptVjdJaHViS3VxTVZqanVMaER1Wk5vVnpHTjYyKzlKMUZRMWdOaUQ5NnJhaXZrbkpBNDlFTmxPK1EzSks0b01GeFI2cHhFZ2tDNlFmTTk1NTVWaEpBMWpUZjhWV3l5QUUyVDR3WXR4QlNEcVVCMG9ic3BTdTFKY3hPY25xQXFtUmMrNXZkUWNiaEcvUjhqcldCVE1HRXlPSXUwMlZoeUMybGFXMzRXVzBaTzlsc1VPQkEySkJUSncyT0lldnlTM0ltMDFadEE0OUVkbUhFamhYcis2ajh2b2hQbWpzYkZLY21UWVZzZUVBRzVzakNpYkdPbjFVSFZNcjNFQWJMQmpsZnVicnFrSHRQU05hMjlrbDd4YzI5VTBhZDNXNmkrRnJCL2NpVFoyZ0pmcUNDL3dDYWxJKzJ3UXU3TC9OSHlTMFJJdXNGcUpGU2tucW1tVW1rWElVRmxmb1Brc0ZwVDhoRWZRZlJBZEswbm9pUkJkclRkRWEwaGVNb1hoS0Vhc2dlT3BMVm1XdGNSYTZYZThXUzdwU2dvZ1I4em5FcUFsMW15ZzJVbm9FekJUNnJGMnk2bUVrUmJGZm9peHdFdUFBdnVwU09MU0dzRjF0dVZNdVB4QnpIdlo2OEl0eUNVU3p5ZmxrVkRtUGMyM0hLNmJReHRvbU5qQTlFaGgrSDl3MWpXdDAyQUd3VjNUMCsxeXFya04yMEhqQUExZFVTV2F6VkF4a0JMVHlrOEpiWkxJeVRjb0RwQ2VFT1l1SVdLVjVCODBKTzU4cjQ3L09qNUt2Y1BBMVdlTy96dytTcm5Ed05YMnlqNDJlWTN3cWR1RkZtN1ZNRGhFa0F5VFJaVHRZTERVUURaSFFKQUJUQVdBRk5xN0VYa2ZCa0JlY0xPQ21CWmU1Y0V5VHBGZUN0aEd2REdmY3AwclRQTXdBWHVRZ1RnaHJRRnNXVXNOOTVrWVhEMVdScU0yeUxON1NZdDBsUjBMTHRFS2FsWWJBYkFxMkQ5eWdSQVEwNEFQQUM5QS9WcXV2elZxTXIxZW8zUy9RL1hHZ2F3YWZaRVpnZlo1UmhOYVVOODBwR2JTSGRUSnVDL3dBbG15aGVUYWIvQUlOWTFNWmVPN2UxNCthcU0zVURjV29Ia0FhZ0NWWU1uNzlwSGtvc2JyN3lNL2FhUitDdTZYL0p6djhBUVJueUtXblNad0thRjBjOGpkWERpUHhYbXNJKzB1Z1ZIWnJVeXp5UERtV2M0bmtkVDgwUC9OblZEN1RQcVB6WHRGckkxM1BCdlFacjdvMGhyRGI0bExTZjJsdXc3Tkt2OXBuMUg1cVk3TmF2OXBuMUg1b1hySStvUDJmbjlVYU5wUDdTOXBQN1Mzci9BRGExWDdUUHFGNy9BRGFWZjdUUHFFSHZzZlVuMmZuOVVhS0l3ZnRMT2kzMmx2VE96Q3JQVm4xQ0kzc3VxL05uMUNGNjZQcVdmc3pQNm8wSFFUOXBTOTNQN2EzOGRsbFZibG4xQ2ovbXZyQ2JhbzcrVngrYUgzMkQ4d3ZzN092UTUrWW5EL1dJWlkvbzlkRy96VlZuVjBZKzhmbW5NSjdIYTJzeEtraUdod2ZLeHB0WThrZXFudlVQVTQ5RG1pcnRIMEYvSis5akxzY3hhRE84NHVLQ2NNN3B3K0x4SCt5djAyb21lN01qSUhoZnczeVhJL1pyN0tJK3lySWNkSDNZYkhVTmptY0cyM0pCUFQ1cnNXa3RhMG40UHNqeVd2QjdGd2ZHK3FheDVadjhodVIvZGdhUmZmaEVKSUFLVTcvUzBPZHdWS1dxOEd4VnIzbHBWWjUvRkh4SFljU1hLZzRGenIzU0lyRGZsVEZZQTA3N3F2TFVPKzVaeWFjYmxxdE5vdnRuaEM5N0R4bzZqWlZSckFYR3NlQ1JHYldIUCtOa25WNDFGVFUwMVdUb2F3YWpxTmxUMVBVNUpXbUg3dW05cDh0KzM1bjM5RzVNR0cwMVJvcVd6alVHbmUycHY5Ni9MM05GZDM4ajJhcnVrSkpLK212Yk16N1BtbnRPeFNDS2RyNlZvRG0yTng4VGw4ajRoTzZhcUxpYjZTUXJHbGIxVUhrZmtqNnJwOEM2Zm9ZdVA4VWY5aTV5UGh6c1F4aUcrNGpldm9hbmk5M2xMVzdOdHd1WGRsT0RCcGtuYzBpNHVEOUYxUjA0Yk1RdkhkU3pQUG1lSHlSOUo5bFllTHBvNVpMdW4rNDdoNS8wcHEvVFBzV2VCa0xDUC9rZnhLL01XZ2x0VXRYNlc5anMrbklHRWIvNmorSldsMGJONGNYK3A0SDIzVnlqK2gwODFRYXpsUkZSY3FpbXJ0SStKWmp4SCtrdEhMMUtTblZueWJIaHV5OU5TRzlVR1dzNVZOTmlOaHNVdU1RSjZyc3RlNUpjajQ2ZmsxUDJnTVRET3luRjVYYlBhTnZvNWZqTjJqeWwyWnErVngyTWwvd1g2MyswelhsdlpUaTJrMkduL3dDa3I4bThYdzUyWk04VTJHdEYzVlUraXg2N0lKNVhxTldsK1I3dnBNUGRlbVpNNjhwZjJQbzMySCt4aWZPR00wK01WRFQrajNOMU0xRHczQUovSmZxSGg5SEhoTkxUd1V6QXlOa2JXa3Q0MkFDNU43S3ZaaEYyZTlrT0dZZTZMdTZtSW5VZWx0TFIvQmRUeExGbVVGTStGdCs4UEJDdjVkTkRUdU9YK3A1VHFIVWNuVk1peHZsUjQrWTNXNG1JWXdZaHFkYmV5cjQ4VWRWQ3hHaDZwS1hGZmQzU09tT29PNHNvSEVXeVR1a2kyQlZITjFHV1diaW1KaG8xaitHaStaV2lNOTNxOFI2SmF2eHd2MHhNR2kyemlGU1ZNc3JaQlZCdzBzV2g5cVhhRkhrL0E1cW9UTmpsY3drWE81SzdqMThveGJzc1llbCs5WlZ0UnIzdENkdHRQa1hCcHFXbWVKcTAzWWRCOFcreStFSzNIbllnK3F4bkUzOTVVTmtjNWpaT2JFay93Q0puenRCcWM0Wm1xTVVycERMVHZHdzN2ZTVLNW5uTE1udnJ2MUx2MUxSWXRXWGwzZFF5VTMveG4xdnB1bHhkTHdiVXVXaFRNV1pKTVJxM2dYWXduWlVsUEdmZkxBYTNIWkx6MWJhdGpURUNITTV1dHd5Vmc3YWhqS3FkdTU4MWFuLy9BQmtiWEJiakdXc25jdVRZc3A0RTJrRFpIZ2I3N3JaWjZzTnN4dkEyU2paaEd3TmFkZ0VOdzFIVmRlVWxsZWQvRWV2eHlXUHNOOTVzQ2ltWFlLdjd5OWhkSDE3RGRWSngyOWk0cGVJZzVsV1JOWVdTam43ckxYYnJzTVhpTzJKbENpZUkwd3FjT2t2eXVTWWpFK21yWlFYV0dwZGRMeTRkMkRzVnEyT1pPZFZ5aDdiZUkzNVc1aDFVYnBtTnFkTm1TNGFORHQzcnlUSXA3RDdhMmc5bms3V0J3TE4vVUxIK2IrZTNMZnFGcnd6d2FQTTVNT29VdTVyRnIvNnhaMG5mOVl0bi93QWdwaDFiOVF2ZjVDVCtiZnFGeVdXQmF4WXRSNm1yOGRMcUxua0RoYmNNalZsdG5zK3Y5NjhjaFZoSHhNK3FKYWpURFhwdFI2bWx1bWNPaWhyUGt0eWRrQ3NKK0puMUg1clArYnV0QStKZys4STFxZE1JbHA5UjZtbUIvb3BDUUUvQ3R4SFozVy90TStvL05ZUFoxV0g3YlBxRVh2V21LN3dhajFOU2xqRDN0Z0VsdFF2ZnlYMGo3SDNaYkpuZk5RcVpSK3J3NlFQdTRmRngrYTVCUjltbFZOY2pTNllIYTI1WDZRZXloMlh0eVBsUnRZSXhITFZRZ3Y4QVhjZmtxOHBwcmc4OTFlTXNVSGI4anZvbzRxS243dUVCckI5a0t1a0hQelRZbkxnWkQ4SjZKWjlpU3FHVEtlRWhOeGRNV2Z1c0M2WTd0cFVoQzIxMVRsbm91ZU1rdXdzSSs3RjdxRFlESysrcGVrY1NTTGdmZWlRQnpSZTZHTTJkblRqdUl6d2FBZDE4NSsxdG45dUNaRHhEQzJIVE5LelVMYy9DZnpYMFRXeWtRU3lFMkRXbDMwQy9PdjJ3ZTBCdUxaMWlvbVAxeDkyNXJyYmphd1dqaWJhTlhwY1BIbmI3SStkSytxL1NrM2VPK0pwdVNVdFN3T3I4UWJFMzdKQlM0bDBWRDlPd2NWc1dVNlRSaVRwU05pM2xYcnBIdThDM1MyTHlONW9nMm5nakEySWFQM0lnazF1U2drdnNpYXJDNFhrNUp5aTJ6MkVHc2MwZzgwb2F3bnkzWENPMmZIVFU0dkhBeDNoMFdOdnVYWXNSclJGU1RPTGdBR09OeWZSZk5HTjF6OFp4cVJ4dTR0ZTVvK3E5ajdPYVZTYzVQOGo1NzdWYXh3MnBQMU4rN0o4SzBDZVo0NUZ4ZjdsdnRWUC9BS1M0RGhWbVZxUVVHRFU3Z0xGN04vcXJDVm10b2YxSzNOU3RtWnBIenVNL0V4S1RNUnhkNlUzR3dRaEFqUGMyS0pyN3hWd3d6cFJJZ3NaY202eC9OcnpwdElTMkF5VW1sZzZJYmFpK3dHNkUwT3FaTklCSzJYQjhyR28wdWMyM1hkQllKVTRmaGtzendYQTJKNnE2OXdiQkgwdXRta3crS2tqR2tDNEhtcW1wak1qckFiSlc0dGJTaG5iSTkxbTN0NkkwVkNTemNicTlwc1BiWVhhaXpVWVlRQVBvaTNBN1RXb2NPTHB4dHRkWDBlR2FXQ3dWaFM0Y0xhdEtzNEtVSFlqaFN5VlJXVW1FWElKQ3U2YkQyeHRGd0V6VFFnRkdtT2xxcTdnYUZYd01GOWdrWndJd2JKMXp5VWxPMHlYRmlqVWlVVjBzbXMyVVcwd085Z212ZGJYSkNCTkwzV3dSYmlVTFZzM2RzSURlRnJkWlZ5UGVRQVZzY3ptekN4Q0JIaGtjajdscXNXVGNqVzQ2T1NkdzhKM1Y3UlpkUGhMZ3Ira3d5SmdCMDhKNXoyMnNBUWgzMFRjaXZnd0tCak53MjY5SmhqR253Z0pwem5BOHFUWmJjb2ZFWk55QXNwbXgyMlUzTURoWlpkSUNvUG1heHBOeDlVZmhuZDRDV2xHNlRrbkRBZHJXUUsvR3hDVFozNHJYNnpNakNEWW02WXNZRHlGeFVZaXh2SkFWYk5pN0czT3NMV2EzRjN6T05ycXZjK2VYcWo4TVc4aGZWbVl3UVFDcXM0czZWeVVHR3ZrTnlFN1M0T1J1UW1nb0kyY3ZDQjNaMUt4Ymg1YmJaTXR3dSs5a0REU0toc0YxTVUzb3JwbUZueVJSaHUzQ1cyTVNLWVVqYmNCVEZOWld6cUFBZEVKOElZdUFDQWlzc1NSaXlhZklBQ3E2ZXAzTzZZaUdTMEJBbElCVVRVZXFDK1J6ellBbGRJRmxsWmJZQktQdTQ3QlBSWWE5NUczS3NhWEJMOHRYTE9xSlFDRjd0ckZIaHdlVjU0TzYydUhCV2kxMnExaW80MmdiSUhJWW9tclVlWHk2MXdyZURMalFOd0ZleHNqWVA3MU16dGFOaWw3ZzlwV1I0T3h0dGhzbW1VVWNZNENrNnEzVURNWElISWRzSmxqRzlBdkRTZWdVUTB1WGdSZmxBNUUyR1hOUW50UmRTZzZRRGxBNU1td0hwODFGMGpJK2JJRTlUcHZaVjgwN3BUWVhYTEpZOUppakk3OEpDYkdpOEVOYWcrNHVsTzZJS0dPUG0zMVRWeVN4R1dhYWM4a0JERkFYN3VmOVZZeVBqakZoeWtwNVpIWDBwaWlTekwyd3h0MjAzQ1Nucnd3RU5BVTRLR2FkMjRQUGttLzhtM09BY1FpM1VLc29wS2lTWW13TzZFS0tSNTN2dXRvaXdOc2ZJVElvSTQrYkQ3MTN4S0NTczFpRENYTzVDc1ljRUd4S3NwWHh3RFp3K3FTbHhqdTdnSDZMdmkwRnNSTnRKREY4VmxtU29namJZQnQxVk9yWktseEF2dXBNb0h2TnorS205c0dpYzljNGtoZytpVnRVeUhmVUFWWlIwY2NRdTR0MjM1UTVjWmhqMkFPMnk2blpLRXhoNzMvRTYzelJCaHpHOHlEWkwxT05sK3pTUXE2V3RxSkRzNUdrU2kyZkxUeGpodXlWbXJvd0xOQVZZTlQrVklRanF1cEMydzBsVVhjQkFPcDZucVpHRUY5YTFxZkZBTmt2ZDk3bEVEV044a2hKaWgzQXVnbXNjNU5TQXNzak0yUGZaQW14RURaSXVxQy9hNkE1cEp1dWJRaG1TcjEzM1FET2JvZkFLalpFb2tKOTZWSVNGQzVSV3RSMFF5NlFyTENDZDE0aS9DdzJPNVhIR2dVTnhobHVBcE9MNTNBUkEvY293MGozdUFBdmNyZWNyWlhBY3gwak9iRlY1T2g4UlhLdVdYVlR3Nlp2MVhUOE53dG1Hc2FHTkhsc3M0ZmhqSUEwTWJaWFVkTmNDNFZaeVk5SW5UeERZcDVwRFdvVWJMQUtUenBIS0N4MGx3WWxuQVZaTEtkUjIyUlpwUUR5bGFtcWpiMS9GUXF2dVlsbThIQ0RCT2RYQ1ZxTVJqQStMOFVPbHIyT2R6ZjcxMUJvK2Nzdy93QTZDUEpKUkR2V0FKL0ZXOTQ3ZnlWZkE3dXBXanBkZmJ6NHVabWlOTXk5dXE4M2NCWE0xSzJwcDdpeXFTM1M2M2tVU0JabHZLbU9Db3RidXAydUVZQjVxbTFZRFZOcmQwbHhxYWtVcytKM1JJY0xMRzczWGdEWmVEdkNydTM0ZC9vWE1WYlBEODN3Rll6djNobzNXLzVTb1BkMkFrZEZwbUIwcnBha0VqYTY2WFJzYlQwNHNBQ3ZsL3RScjQ1NCtGRjhwcjlqNjU3RTlKbmh5ZU5KY05QOXg3VXN0Y2xlOFVoSXZqTHhPejlDckJrUzRRMXJYdGR4NkpmdkF2ZDRwNFlYK2ZIaElaYTYzQ0t4KzZSYkpkR1pJaDhOOXptL1VmaFJZQThLUUtXYkpjSXJYWFM3WXh2R3cxOWxob3NWZ0JTVWxOcERJWVlTWk1GRWJFU294Umx4NFZqQlRrZ2JLcExLYU1OSkJnNmVMaE9kME5QQ0xEU0VkRVY4SmFMS3Q0OW1rOUZwY1g4VEVqRWxud1NQcVd5eGk0YnNSMFZrSXJsUWxiM0x3MXZCNnBrRzVNdWU2NEpZMjAvSVNxWXA2Z04wdHRwNXN1dit6Umt0dWJjNU5wNnhwRU1UUkkxd0Y5eGMvd0FGeWVHS1dTb2JGRmVSMGhzQUY5N2V6RGtDbXczSWRCaUVzVFljUmRjUEorSzJrZm1Wb1lzVnRObnh2Mm42aDdsdWhCMTVmUTd2UkNQRDhQcDRSYlRIRzFndVBJV1VYNGcwSHBaVitKVllZMEFIZ1dWUE5pWWEzbmRhOHRlbHhaOFV4NlY1T1diRFVZbUh0c0xJRHNSc0xYV3V3NHFDZDkxaDllTEZVNWE1UHpMaTBUajVGMUxpSTg3SmFURVFDZkVxV1N0QjZvRHF5L1ZjV3VYcVhNZWw0cG8yS1BGR2crSzJqcXVUOXVtZVdZRmszRnJ5ZDA1OEowV051cTJ5b3JuUk9FZlU3cjQ3OXREdERNY09IME5OSWZFU3lRTi85WEttUFA0K1JOR24wcnAwSlpsS1haSHhobmZIcHEwdnhHV1J6M3krSFU1MS93REhLMENpamRYVjdZaHU1NXZaWGViYTRHTDNZY05OMUxzK3czM3ZNVk05d3V3SGUvekM5ekhKNFduNDlEMUdUQzh1cXhLSE5NN1BsS2s5MHdtRnVrTk9qZXc5VmJXNjNTMFRoQXpRM1lBVzJVdS8yQVhnYzJKNXN6a2o2MWxucXZzK0dMRkJjTWRpbGNLcGxsK2xmWkJJNGRuZURuLy9BSi8vQUtpdnpMaHFQOU1qRmwrbHZaUk5wN044SU52KzdmOEExRldOUFBZbWZJdmFoTnlqZm9iTFUxYnRSRjBHT3FHcjRqOVZWeTFwZElSWlNqZHY4U3Jhbk9qeU9MR25FdG5WaEhCdW9Dc2ZZa0JJbVVONjNVbVZJMGtXVlRGbXJ6SXNhdnNjdjlwbXZsSFkxamJ3QVNCLzlMbDhLK3o5MloxSGFKMm8wR0lSUnVrYmgxU0pKTERiaTIvMVgzRjdUN3hCMko0NlR2Y1gvd0NWeTBmK1Q2N05wTU0vVHVJMWtkMjFUUStJdkhxemo2RmVoNmRsVUhiWmVubFdMUVpJUDEvc2ZhRk8vd0Iwb2pFMWpZMkFIWm9zdFB4R3VhNHllSzV1VmZab3FEU1VZalk3eDNzYkxUKzYxeWdGM082WDFUV0pxcjlUenVpeHI0cG1ZNmp2N3RSSW1lN3VMaVNnMVVZcFEwdDNKU3RUWGFLZDBqenBhMEZ4djZMRzBtVGM3Tm1NUEVpcUJZOW1PUENxS1NTcWNJNlVmRS95WHdCN1FmYlZQblRHNWNOaG10VFVzaGF3eHV0cUZ1dHZtdWtlMVYyN0FVcytCWVhKYVNSaEhleEhnZ1cvaXZrT1RFbVN4UG5uY0ROYTduTzVjVnV3YzgzRTBlbzZkcG5wbXBTQ1l0aS82UHc4TkpCSjIzV2pUMWJuRjNYVWI3bzFWaWI4U3I1QTYvY2dYQjZLV0ZVQnJxZ0MyMTdMY3g0c1dHRnQ4bTdsL3dBMmtpd3l6ZzdxdWNPTGJpL2t1bTA5SzJpcHcwQU45QUxLcXdlZ1poMEFOaGV5c0RVR2NyQjFzWjU1ZkJ5amE2ZW5oWEl4cjlWanZENXBmdkI1cjNlRHpXUmRHdjJHQS9kRkwvRHlrKzhDa1pWMnllTktQWVkxcVRYK3FTNzFUYk51cHlLZXB5K2hZc2ZleU5xdU45MVhzbDlVdzJUMVU4Smg3ckdOWHpXYnBmV3BoMTFOalIxSk1MZGVVQWQxTGRTbWd0b1Jwc2lCKzFrRThCWmJlNlZ0WTJMeng3UlFiamUyNFU0WCs4L3puaEkyMldHTjJSNFlST0w3TTlGT3c5WmRRK0hCQzc1UzEybTNnNHVzdmRIQzNWRzR1UHFwVE5HclFSOTZ4SGg3bnl4c1llOEwzQnRoNnJtNEdXSnpUY2tkQzdCc292emRuaWhjNlBYVEIybDIxeHlGK2dtQTBMYUNoZ3BHdERHUXQwZ0FXWEJ2Wm83T1A4bk11UHFwWS84QVNuUEQyRWpleHVmeVhmbzNsME4yL0dCNHJLeDR0SStFOVoxQ3pUYVhrTXk3ek9hUGhTY2dOeWlzbjF3ajl2cW95V3NsK0lqek9DTDNOZzI3RGxFTHJOc2hEbFJrZFlLUElqUW0waGFhbU1sUTBnbEVNdmRXYjFSR1A4UWNVdUc2NW5PSjJTNU8zd0U1Si9BelhPMGZOTU9XTXNWZFJLOE0xUlBhQ2ZQVC9ldnljN1FNeE94bk0xZE81L2VEdjVMRnh2dHFLKzV2Yld6MStpc3BlNlU4bW1UdmJFTjVzU0F2enpyNUFXVFN1TjNPY1hmVmVwMEhFZmtlcDBPRjRzVHZ6QmgxNWgvU0szN0wwUGQwVEFSNHZOYUxoVWZ2ZFJEYm9kMTBPRm9weHBHd0M1cjVJOWIwYUhoWkhrbDVvYWtkNGdGaHN0cnR2enNsek1IU0JZa2xESHNkZllGWXpqNGsxUnU1OGlqRno5RFUrMGpHZmNjS05PSGFYZzlEdXVTNVBvblYrWUkzNmRUUzgzMjlWc25hemlocWNYbGpZYnR1TEFmTk9kbDJGRFUyZHplSGNsZlFkSGo4UFRMOUQ0NTFqT3RScU9QSnM2SEZUZDFUd3Q0QUhDbDNHbVFub21Kd1hPYUdqaEY5MmM1Z05rbkhMYk4yWkdvL3pjU2d2Sml6ZmtFT1EvNENzelRORGVsMHJKQmQyd1FOazJpZ1lTTHFkUFRQcTM2Ykt3cHFGejdEVHl0a3d2QU5MMm5TbHRuWXg1Rk1CeTBROE9jMG41aGJjNW9vNHRJYUI5eWNvY05kREdQRDBVcWlrTW9JdHVsbHlDS0dWbXNuY2xSWlNrdTRWaERoMGhlYmcydXJTSERRMW9KQ2dEWlZRMHhEZUZobExaMTJqVWZWWExvV3NGcktNY0xZbmNCeE82V3dXeGFDSjVzQ3dBZkpPeDBPcy9OWEdHWUhOaUJHaUlnZVlXMjBXVHhUeGwweEFJQjVRQzdOR1poem9oY2dvTTlNWGNCYk5pTEdOYzVyUU50bFdzaURuRzRYS0pSUkNqYzNvb21FUmdrajhGZlRRdGIwU0ZWVEVqWUkwaVVhNVh6QnR3TmxVdmVYSGhiSy9CbjFEK0UxVFpTYzRpN2VxTklsR3F3MGI1aVBEeXJlandaMWdTQ3R1Wmx0a0xXblNPRjZlbUVFWkFhaVVSVm12ZTVpSUlFamdPZ1JjUmxlSEd3S3I1WlNRalVTV1FtbHRkS3VxYlhXSmk0MzJLVWN4enJpeFJLQkxJVFl0cHVMaFZkWmlicEJZSDhWWUhDWHlYTnVWQjJCdVBSV1NXYXZVdGtuSjNQMVMzNklsY2VDdHY4QTBOcE45S2JaUU5JQTBoY29FMHVMQTNPTzdWWVE1ZUoreitDMjJMQ3I4TVRjZUdPSDJGTnBEVVc0TVkvc2ZnbVlzS0RoWWkzM0xhRzRSSS9saEFRYWloTk9QSktIbENjS2pieis1WlpTdGIwL0JOeTdrK0t5Um1uMFgzUXVOblFzbWxqZUI5RWxOVkJ0N1dTbFhpWWJ0ZFZGUmlZTjdGRHNaQ3hrcWh2dXErb3F4MEtyUldQa2RiZE14VTdwMDRBREpWRTlVQXNrbk5nRmR4WU5xQUpWaEZoMFVWallLRU5kcGNFZklia0ZYbExnb1lCZHQvdVR3ZkhDTmdGQjlkYTlnb1FMRFJzanR0K0NhYStPSWRQb3FsMVk4bnFvaVNSNTZwVkRTM2ZXc0YrRU00bnEyRmtpMkI3dXBUTWRHQVJjb0dHaVptYy9lNng0ajVwbHNUR2prS0xuc0I2SVFnTGRkK0UzRGUzQ0VaV2pvRjV0WUc5RXZhU3d6OVhGbGw4QWFMM0tVbHI5K0ZobFE2VW9sd1N4bHB0c2dUeGw5N0l6RzI1S25xYURZb3JKWldta2M0OEZSZEYzSTNiK0N1WTNNOUVPZUprb3NMSkpLTmVxS3QzQUFDVjd1ZVU4RmJJekIyeUcreVpqcElvN1hhTmthT210MCtFU1NHN3Jxemd3UmpiYXIvUldVczBFTGZzaFZWVmpER0UyY0VSQjk4TWNMUnNCYjBTczJJUnhpMXd0ZXJNd0Yxd0NxZWJFNUpTZHlnVUdOYzBiTlU0d3dYc1FxaWZHblQzQXQ5eXFYU1BlZVNwdDB4N3AwWUNYTU01a2s1dmMyK2FKSFIyK0s2VWZpWWlHd1NjdU9PTndBVTVRRXVaZkdTQ2tiY0VYOVFxMnN6SUJkcmJLbGRMTktUcWViRlE5M3Z1VGRkVUJaWUN2bHFkd1RiNXFMbithVEZSM0d3YXN1bExrYWlRSytVQkROVUFoT3VlcUdXWDZwaWlRS2F2eVVEVUVxR2x2b3NFZ0poREplVDFRbnFSZVBSQWM4cnBDTGpZckd2WlJKdVZuU29Rd3ZMeXgxVFJhUjRyemQxNVpZRUxEU01GbTZQRTNaRExsSmhKNFF0aHBHZG1YdHVuYUREcEt5UVdCUk1Od2w4cndYOGVxM0hEcVdDaWpCT202U2RVUStCWlhEV3NMMjhlWVc5VUZMSEhwRmdMQWNCYWNjZWJEczAvUlQveXE3b1gxYnBiTEVlRHBjQmlqWUxsVGZpa01RTzRYS3A4OHVhTEJ4VlpQblNSOS9FVXVpeXBKSFhKOHh3eGcrSUtrcnM1eHhYczhMbGMrWlo1QWZHNVY4dUpTem5keFR5dkoyZEluejIyNUdvSk4yYmU5amQ0aHo1clFBSHY1Y25JQWU3UGlVRVZ5YkU3SEhTdVBpL0ZXMkExN255Yjc3TFVLZnJ1dG15NkJyKzVRZEU1TmpidTVsQUhrcTh0dTFybFlZNFAxd3VPaVNJOERWOW1QaXRqTlBpTG80OU82RVRjaythaTBlRWJLUUNKQU5tUUZPeXcwZWlJQlpHQlpnQ3dVd0ZDMTBXTm15YTQzQnNUS2UrYU0ydXNNajFTaG9VeXk2Zndxajc2ZHJtZUt5ejlYckk0Tk5OTjgwL00wZW42YWVmVlkwbHhhL2MyVEwrSEJrWWZwNkxZaEpZYVNlRXBRdkxZV3NjME4ydHdpVHNqWUxsNUMvUGVzMVVzMnFsSnZnL1ZuUzlMRFNhS0ZLbnorNGNQdWJCUzE2VHlnUnVqWkE1OFR0VXc0YWVxdjhvWkN4clBNejJVRk1aWm04TmJmbjZMTG5PSzdtekxVcUN0NWZxVk9yYTUyWGk3WmRTaTltRHRIcXBPN2Znam1nYjdhdjdLWmQ3Sy9hTU52MEk3L0FKdjdLcFN6eFQ3aVB0VEREdmxYek9TdGZaRmErL1ZkVmQ3S3ZhTTV1MkNPL3dDYit5cDAzc205cER6L0FOaVAvd0NiK3loOGVGZHhpNjFwUFBJdm1qbDBjaFRjTnl1cjB2c245bzdEdmdiditiK3lyRm5zcTlvbGgvMEc3Nk8vc3BmaVJPdzZsb1gvQU5lUHpSeVJrZCtoS1lqcDlSQVhYNmYyWE8wTmx0V0NPdDEyZC9aVEx2WmZ6c0ptbjlGUEcyNDhYNUpFOGthN216ZzZuMDVkODhmbWpsTk5SY2JLeWlwUTBMcVR2Wnh6dFR4TkF3bDNIa2Z5UW5lenBudVJuaHdsMy9OK1N6WjVGWnRZK3I5TVhmUEQvd0RaSE4ydXNnVkU0YjFYVHg3Tm5hQ2JmOURPL3dDYjhrNVIreXpuQ3BlUGU4TmtqSHBxL0pjY1VpM3FPczlJY2JqcUlQOEEvSkhHdmVMM3NzVTFMVzRsZU9uaGtlOG13TFdFcjZkd1AyUmlXTU5ZMmVOMTl4WS9tdXg5bnZZSmdtU25zZm9FNUJEajMwWVA3N29vNU5ubWVDNmg3YmFYU3B3eExkMzdNK2QreG5zRHhDdHE0TVJyNGgzYkNIMmNMRmZaT0UwMUxnbUd0WkV3c1lBYkJPdWJSVUVZRWNVY2JSMGF3QmExam1OdGYrcmlJc0R3RmNqcm9xTkpmVStMZFY2dm42cm1jL0RiWDVHYXJGek1YL05WVWxVNlIxcm9NdFlIanBkSnZsdWVWbHl6dHZ1YUdudzE1RDdudVp3NGZWWk03dHQxVnVrSTZsSHBwSFZFUmVSYlNiSlhpdGwyVUVrTnVsUFUyUTlaM0lQRzZUNzB6UGMxMndIa3BOa2JHNHNCdVBNcHNaU1p5T095dHpIajN1TksrdGU3UTJJVzFIYi9BQnd2emM3ZWM0dXpCbW12MXYxdGpsOEIrNWZXWHRVOXBSeS9oRStCVWJocXFJOWQ3MmNEYis5ZkEyZEsyNVpKSTQ5NUo4Uk82OWgwakJiVGw2bm85QnQ4Q1VvUTVzMFBFcERWWWc5cDNYUit6ZkRXeFljK3FJMHZZN2EvUFZjOGlwNXBxOWhwMmQ0UzREZjVydGVDWmVyYWVsaUxvZERTMEVnZkplZzZobThQRW9MekxYVGRCcTgyZVdUWktrNzdNc0lKUzhrbnFpbDFwYkplUmpxYzJjTEwycnZSeXZNWWN1MTJ6M3VMTm54eWVPY1h3UFFTQTEwZTExK21QWmE5bzdNOEgvOEE4Yi82aXZ6SHcrVXhWakxqNnI5TWV5NTVrN044SC84QThmOEErb3FwbG40YVo4eTlwVmVTSTJKR21WM3lVWTNTYXVka3RVbDBVaDJzc05xRHNzTEpxTnpQUDRNZndsaUhucVVWa29zZk5KUXpBOGxGZElFbU9kb25oL0VjOTdmc0Zxc3c5bHVMVWJDSG1RYk5IUERsMGpzQ3dZNEJrSERtTmJva1pUMmZmL2lWZlh4TnFxZDBiZ0h0UDJYQzRXNzVhTEtUQm50QURBR2JBQzNWYk1OWHNYRE03cUZyRTRyekVjZnFwNm1yZThQR2p5VkxITkkrb2I0Z0V4VTF6VFV1dWRra0FYMWpYdCtFY2xabWZOTE5MdVAwMkxiZzVYZEI2bW9jWE5EdHdGdzMyZysycURJdUYxRlBITmFad01lbHB1ZDl1QXVnZHAzYUpTNUR3T2VvbmUxa3BZVEdIVzNLL05qdFk3UXArMFhORlRpTDVuRnNuMkd1OEkzSjRXOTAzQktrelcwV25hZ3B5UlFZNWpjdU5WOVJVMUR3K2Q4am5NZDVBbTYxREhLcDB4YkhFYkhoeFVzVHhLT21kM01UOVR5T3FycEpLalNMc0hqNEs5emh4cnpWRzVseStVUThMR2ltanAyZ21ZTzNJOGx2bVdzRmJUdFk4aXgySzEvS3VBMUpjSnhGcnY1N3JlYVNsbUJhMHN0OGxsYS9Jb3JiQ1I2VHBlbWVibVg1QnBYM0liZllMSmVLY1g2K2llWmw2WjdOZGpibEtWRkdZU1E2KzNtc3JCckl3NGZKNnJKbzFCY0FDNis5OWxtKzEraUVBSkkzT3Y4QTZJRFo4blVIL0YxS21tRWpYdGJ2R0JzNzBYWllrbFpsWk1paDNKQjNxc2wreWZ5dGxyRU0yWW1hSEQ0VE5KYTRBWFFhZjJXKzBXVUJ6Y0ZlV3UzSHhjZjFWV2FTTTZYVThHTi9FMTh6bHV0U2E5ZFZmN0tuYVIwd04zL04vWldZL1pZN1NRUi8wRzcvQUp2N0tpY1IwZXM2T3VkdnpSekZqK0V3eDJ5Nm0zMlUrMFpvQi9Rai93RG0vc29yZlpYN1J2OEFjai8rYit5bVBORXFmYW1sL21yNW81WUNpTmN1cHQ5bHZ0RmIvd0NDTy81djdLbVBaYTdSZjl5dS93Q2IreWtTelJEWFZOSi9OWHpSeTFwVXh2MVhVeDdML2FJQi93QmlPLzV2eVdSN01YYUlPY0ZkL3dBMzVKRHpJYXVxNlQrYkg1bzVoR05TWVpFdWpPOW5EUFVBL3dDeVhYLzlYNUtMZXdIUFlOdjBRZngvSkM4eU5EVDlVMHQvRmxYelJvRFFBRmlvSkR3WWpwRnQ3cnBVUHM2NTVsSUxzSmNCMStMOGx0MlhmWmh4VEVITmJpRlBMRDBPa0ZJbG1SYTFQVmRHc2Z3NVkzWHFqaHNkUExYbGtVVVQzeUhhN1drcnZmWWwyQ1Q0NjZucXE2SU5ZMGg5bjJhZHQrcTZ0a24yZk1QeW04VFNNTWpodmFWbC93QjY2NVJ3d3dVNGpnalpGcC9ZYUcvdVNmRlNQbC9VZXM1WlNhd1pIOHhqRGFPSEJZSVdNYmFPSmpXa0QwRms0ei9SOVVuU2JoVnJLc2wxanVuV1RCNEYraXJlT3p3MDkyUjJ3b2hERzk1Y2I5RU9SOXh5dk9JSTVOa0Y3QWVxNnN3M0ZqMjl3akRjcU1uQ3d3aG9PNkZQSWVpUHhXeVpJdG5uU1dwM3U4aXF2RThVOXdvWkpTZElEYmtsTlQxSWloUGVuUzFjVjlwRHRNanlmbGYzU043UkpYUmxqQ1RZMzM0K2kwOENjNUl1WU5OTEptaTZQa1QycE05dnpQbnF2dzRTaVNGbG5BZzNISjYvY3ZuYXN2SnFqdnN0b3pKVXlBdXFKbnVmV08yZHJOemI1clRpNDFFK3g2cjEybWc0eFBheWlvcUVVYkpsR2kwOTY0aTJrWEMyaUtwN3h4djVLcHdSZ2hwdklrSjBHN2paVXRVOXpQUTQ2eDRJdGR4alhhTnp2SXBiRTZzUllaUElYQUZyYmhaNzhSZnEvUGRhbG5uRmZjYWRzWWRidmRyWFR0QnAvRW1uUm45VDFmaGFhU3ZrNXBpdGE3RmNURDNHNWM0RDhWMi9JZUFlNzRPSGFiRTJLNU5rSExNdVpzMDl3MXBjMXRuYmZmOEFrdnFla3k2ekJxS0VFVzBzYmNFZWk5bzJzY05wOGxqSjVNazVQMUtPbHdrRmpuT0ZyRHFoVlJiREVBUHdUbUpZZ0NTeU93NmJiS3Zob3BxcHcySkIyV1ZQaDJobW5XN0swL1FXYTh5SGE1VmpRNFc2ZHc4Qk4vUmJCZzJUSGEydWMwNzc3aGI5aE9XMlFNYmVNY2ZzcmxENk5Sd25Lb2VHa3MrcTIyaXk4eUhUc1BxcitLaFl3V0RRUHVSUGR6R2RsTm9hUlh5MFRHUldBNklGTGcvZnZ2cDJXeFV1RFNWUnZwTmxheFlkN2d3Nm04RHFGTnJDdWpWSjhGamdaZXlxSjJocExSWlgrSjFuZkZ6R2M4SU9FWlNxc1VxQTdRNnhQUlRhVjJ5amp3dDlTUlpoTi9JTGE4dGRua3RmSzEwak5yOVJaZEl5NWtKbEpDMTBzZkcrN1ZZNGpqZExnOFpaR0dCdzlBRlBEQWNpdXA4SG9zdFVvMUFhcmRDRnFlWU1mTlU1ellTUVBWZXhqRTZuRnBUb3VXMzZGUXcvSzFUWDJMbUZUd2dHelZqVHZxSG5hOXltWXNKY0JjdFAwVyswbVRqUzJKWVNmVUkwdUNPUGhFWStpTHdndHh6ZWZDM0Yzd2xTZmhJSUhoNkxwbE5sZ1BGM00vQkpWdVgyeFhPbjhFU3hFM28wdWh3UnBOeXdsWExNTWppYnVMRldrQWJTZ2pTUHZDU3hHZDBsOUlIM0kvQ0p1SzZxcG0yTzQrcXBLMmthUWR4OVZjR2lxcWcyTFNBZkpZL3lZa2szZHFUZkRLKzQwU3V3OE9jYkM2VE9DRjMyVjBZNWFETFhCKzhJcHkwR0MrbjhFYXhrM0hNLzhueVQ4S21NdGk5eTFkQ2ZoTG03Q01mUkNPQ1ZEenRFajhNbTQwZCtDdFlPRXUvRGQ3YVNWMHFQS0VrMXJ0S096Sm9oTnkwL2VGelkwVGNjc2JnaGtQd0hmMFZsUlpNYzhnbG5Qb3VuUVpiYUxmcXg5RmF4WWN4clJkZ0Z2UkRWQkpuUGFUSkxRMEVzUnBNcVJRaTdnQmJmY3JiY1J4aW53cGpybG90NWhjenpkMmdCNWUySnpSZmJaY3NOR01kcktYRDR5R25jRG9Wb1dJNDIyb2U0QXBhcHJLaXRjNHVKSUp2eXFtcmo3dTVKSUtxRGdWZldQWWJoeXFxekUvQ2QwU29kcnVBYnFyZFFTenZJSU5reEhSR29xblRQMnVWS0dpZkxiWXE2bzhCMDdrRldIdXdnNGFQb21xcUlWRk5oQWJhNFZwQlNOaUhUNm9yemZnSVBkT1BtcTlrb002Y1Jpd1FDOXp5aXRodHpkZU16V2VTNVpLQWlGemp1cGlrRnVSOVVLV3JJdllKV1NxbFBBMlVzbERoWTF2OEE3cUpuYkdWWHVsUG1VTXZjNHJ0SExMVVltRzdicVg2UlBtcXRzVDNEaFNaSExleGFnYURUTEIxZTQ5VkExUk85MEVReVczYWhTUXYzMktHZzdHbllrT0xyREswT1Zib04rRVNLTjEwVFNPV1dSa0RoZFpncmRKNEtCRkdmSk5SMC9vbHRFc0k3RVRicXNzcUhTRys2SXltYmJkRURJMkM5K0VwcGtzODE3Z1VkajdDNUkrcXJhakZXeDNHMnlwNnpIYmdnRzN5UnFER1diTE5pNHA3MmVQcXFtcXpRMnhzVGRheE5YU1NrMmNmcWx5NXg1dWlVR0M1Rm5XWmdrbUpBSlZaSlBOTWI2bEF1QU82d1pXZ2NwaWd4Ym1qRHJubFphUTBYS1hrcW1qcWxacTBEcXJheG9TOGc3Tlc5M3hkQWRpT29kVlh2cnQraFdXeWg5dlZFb0lCeUdIUzk0b2lOcElVUkh0ZFJMZzA4bzlvTmprbXpSWWpoUVpjOG5aSm1wMDlWRTFwNktiVU9IMzkyT1FnbXc2cE0xRG5yeEJIVXFWUkJoejdJVHFpM1ZCSkpIS3dJUzQ5VndobnZpVjRFdVJtUUUyMlJoQnBGN0xwQlR1M1hSWFFXRjBWMG9aMENXa3FMZ3FFQlNEVGRDN3l5aStTNVVRYnFFQzg5VjRMQmlzT1ZnYkk3Q1VTYTljMlhnOG5nSnlsb1RPNFhDQnNOSVZqakwzYlhLdDZMRHdiRWhNUlVMS1Z0eVBxRkdXdkRRUTJ3UTJGUlpTMTBkTXdhVHVCNXBPVEYzUzdhbFR1ZTV4SnVTb1hOMHNkU0g1OFNkR1R1VUYxYytRY2xMSGZsU3VQSlNyT015WE9lZVZrTVBWUjFCRUIyWE5vTnM4Rk50Z29BWFUyc0s2Y3V3b21zbVlaRG81U2pSdmRIQU9vS0VvZm93WEVyYzhyMEQ1SGJBbmJvdFd3eWxmVVNNQUM3ejJZWk5mVXhNYzZPK3g2ZWloTG8rVDhjRjVSOGtpUityYXJESFIrdEh5U0IrQnZ5WDJZK0tkekxQZ0NtQmRlaitBTEtKQU15MEtZRjFob1JBRVlEZG5tUmpsWkx0S2swckdqVzRKK0pwOE01cHNlOVdTaWFaQ0FPcTNITGRBMmlnN3lTenQ3N3Fud3ZEdGVrMld4dXVLZlQ2V3N2bEh0UHJaWXBlSEY5N1I5bjlrdWtSelM4U1M3YldNdG43NlE2VzJBUFJGdXg3dExuQzQ2SUZIS3lLRit4MUVMZHV5N3N0cmM5WXRHUkVURVNDZFE2TDVobFNVUEZrejdMbXJHdkNYa0h5RjJjMStmY1VoaXBxZDhWT1RwZE1Cc0N2dXJzaTdJYUhKMkdSZUdOMVJvOFQ5NzN1bU95bnM4dzdKV0ZSMDFQRDNXb05jL2NjOWYzcmNxekU0OElEdFJ1SGNXSzhqbjF0M1I0WFU2anhQaGdYMGRWRFNnTWVRQ0QvT0hxckQzNmtOdjFyT0Z5YkVNeHkxRXhMM1hwajhMZXQxR1BFcFpDTEc0V0JsMXNyTWFXbGVYc2RnRmRTQm8vV3NUTkppZEczL1dzWElSV1M2UGkzV0lxMllPK0pLanJaQS9ZMDVxN1IyWTRwUzMybGFpTXhHQS82MXE1UEJVeUVDN2dpdnhSOEkrSmRYVVpGWDdHbEh6UjFOMWRFVHRNMnl4TFdVd2tiNDJrMlhMb3NjbGR0Y243bFpZYTZwcTUya25iNUtTNmcyS24wNldQbXpvWmtpbURkd1Y2b3FJS1ZndUdqZFZ0RlRPWXhwY1VsbUtUVENlcXFTMXJNMldLVGRKbHcvRTZlMXhPMURPTlFzNWtCWE56VjZuT0RMZzM2cEtwbXJCdzhhVmVldXRHdkRwVVlJNmMvTkZJell1YmRWK0s1a2lpWVhzbER0dUF1ZE5rYTRmcld1THZrb2F1NkI3d0V0UEZrQ3p1WllYUm81SFpzMVJtMzNzR01DM1M2cDZtZVFTRjF5NjZyV2QwWGx6R2tIMVRYdnVnRU9CUHlUNDM2bXpnMHNkTEZLaHVPVXU1VW55V0NyV1ZSdWVpeWFoenoxS0I1UzA4Q2p5aDVqOVJDbFYxNHBIdGpZTm5DK3lGU3RMaHVDaVBvV3p4bVYzTGR1VjJHUzJWSEg0aGVldXNHNkJ1N3lXclp5emczTE9Henl5SHhGamdMK2R0bGJZeldRNFZUdm1mSTF1Z1h0cUYxODQ5cVdlaG15b2tvNDMrRmgxK0xqbis1YUdPVFBSNkRSck8wcTRPSzlvR09Zam5IRjU2cW9NajlEM05hSGVWL3dDNWN1R1FLM0hLcW9mTzkwY2NadTNVRjFYR3NhcDhQMUhXMnplYk9XaTR4Mm43T3A2TnptdU94NVh2ZERPY1lWRkgwaVhUK25kT2g5ejgrSC83bDUyZDltZEpTVmZmMVVqSkdCdC9GZnlXNjQxam1IMGtKampZendqVHQ2TG1lQjVseE9TaWF6dmJiYjNVS2d2bmVTOGdrOHBlUnl5NWRzbjVsdlI5VDBlRzFDTFgvUDFMT3RyMjFreExSWVg2S01iZ3h0eVVsRUd3czlVU0pwbjZqNzBPcDA2eHF4V2ZVUFBOemg1amxITnJyV2JMOU5PeW1iUjJiWVB0L3dCMi93RHFLL01pbWMyR3NaNXI5TXV5bDdYOW0yRGYvd0NOMS80aXNYWC9BQXdmNkh5ZjJoNW5FWnJwOWJ6c2c2bTdjS09JeXRqa0lHL3lTanBDQnl2SHFiY21aV25qY1N3Wko1TEplNDlVakRQWThwdHM0S2s1TkJPUHhCeEtBTEZYOGVLQ0hEeTNpN1Zxa2tvMTJ1UHFtWjVIR25ZQnZ0MFV4NW0rR1U4MkZaRnlUZktaQVhlYUZWNHhEbC9EcGFpcWUxclc3M2NneTFIdTlJSG5hMjVYeTk3VXZiWWFVdXdPaG51K1dMbHB1QWJEeSthOUZvc0R5eVZJZEdIRVlIS2ZhUTdaWjgyNDNMUlFTdWJCVHlhZGpzNFcvdlh6eFdUKzYzbWJ1RHRwQ2N4cXRkVTFCa2NieU9OM256V3UxTmQzdFM2RVhMRzdoZlE5RnBsQ0tQVFo4U3dhQ0VsM3NFOTdKbmw4clJHL29EeXVqZG0zWkpqV2M2dGo0NlNWOU0wMzFBYldXb1pYb2FUR2NlcC8waEdaSVJzYmVXeSs3TWs5cStWc2daTmlwc01ZK0NwTU9rblYxdjZCYzZsckk0bHRoYVpYMDJLV1NuR05zMDJrN0dZc0hvMnhTdWJGSTNrRUZJNGhreW1vMzNHallKWEhlMnFxcmNVbHFLcWZ2SW5Dd0F2eXRicmUwaDlhRCtzTmo4MTRTWHZXZWR0OEgxSFFZRmd4cHVybzJTdGJTMGRHUjRiMlhOOFdySTNUdUF0WkR4UE5VbFRkb2RjS2dtbU1ycmszSzFjT0NNRjhhNUhhalVvbStZTm03b0g5UzdkemVpMkhLdVRNUnpaaWNGSmg4TWo0bnUwdmV3Yk1IbVZMSlBaN1g1M3hTR2xvNG5EV2JhaTNiNnI3eDdIZXlmRGV6ekJvaXlEVFdTcy9YT0JHNXY4QTNCSGx6N1VmT05kcnVIVE05aWZZWmgyUzhHcHhOSEZOWE4rS2NnNmpzRjJjaGxLeG9Ed0EwV1ZVMnNiSEVOR3orcVZxY1NZOFdON3J6MmJXTlBobmhNNnk1cFdYWDZTakRyRjRURE1RaDAvR0ZwN3BHT053aHZuMG13NFZWYTJUOHl1dERtZm1qZFlNVmprTnRZNVJKTVFZT0hMU29wdTVJTmo1cXdwNWhQenQ4MHIzeGkzcGNTWnRFRldKQmZXcENwQisycVpra2NMVkdLcllXbjVybnZWaVhwOGFMVjFXTlZ1OFhuejdmR3FMM2xuZmI3QzZja21qTE5qZjcwUHZEQThQRW4yR3c5aitRQ3BkMUJ6WnFxeldEb0NFTjFXZk5EN3cyWHZCayt4WnZsYkdiTkFLR0h2bUYyeG1LM1ZWcHJySG5kUmZpOVF6YlhjZWk0OHI5U2U3VDdzdFk2alNTMlE2dm1oMVZReUkrRUFYMlNNTmJDVHFtQkpUUVpEaUg4MlEyMi9pS0h4V0prc2NIOFNDdFkwQUh6VXU4MDdCS3VrMGJhdU51VkVUSDVyaWt4MGNLN2pUcG5JWGV2UFVvUm5HNjhLa2VxYkZuSkpKMEc3OHQ2cUpudWs1YWhwTmdSOVV2VTRoRlJ3U1N5eXNZMWpTN3hPQTRDc1JzZERIdUZNeFpncHNJcG4xRlk5c1VUT1EvaGZBL2JsMmh5NW56SEt5VXVmVFFTL3FTZUxXNmZVcnFQYnoyclM1c25td3ZEcFMyRWdzZHF2YTQyWHl6bS9HbzRJM1FWQjF6dDJhUndDdlU2R0c2U1I3VHAraGlzTHl5N28wN05kZHF4U1YvTVoyQVZiZzBYZlRhcmJYU3RUVk94QTl5ODNsRzVkMFYzZ0VHZ0MvbXZYN05rS0tVWnVlZHIwWmZ3SHVvd09Oa1pzdW5kSk9mNHdGT2FUUzNZOVZrWlk3cEcvR2U3NEE1UGVBeWVTNXpubXI5OWthQWY1c3JkYTJ2Tk5UdWJmWTczWE9wdFZiaXBpK0x2SFcyWHB1a1lmaHQrcDQzMmd6dU0xalQ3ci9BSE9zOWdlRVIwYkc0ckt3RXZZUnY4djcxMHZGTVJtclM1akd1dHdMSlBzeHluTEhsaWxweEM0V1BsNkJkV3dUczlFcm1sMEp2dDBVMVdSeHliZnpQUFJ4cU1FL1U1amhPV0pxeVlPZTA3bnF0OHd6S0RJMk51d1hIb3VrNGZrTmtEVzJpSzJPaHlXSFdPaTN6UjdkMEV3VWxqVzVITzZETHoybHRtR3l2SU1Ea3NQQ1YwT0hMMFVRSGg0Ui93Qkd4eGo0VkZFV3BHZ1JaZmtjUnNWZDBlVld5QUYxbHRFZE93QzJrcHVLaGUwYmNGTVVCdDhHcnowY2VIUjJhMEVxa3FZWjY5OW1NZFlsYjlQZ0pxVGR3Q05TWWRUME96bTNQb1Vld1JLVkdrNFprQnJudGZMWTMzTjF1bEJoZEhoRU96R0Z3Q2NoRDVENGRoNnJFMkV5U2JtMWtTZ0JaU1lyalU1TG13TWNBZHRsVFJaWnFNVGZya2M2eFBWYnRUNGZCRVFIc0pLc2U1YlR0QWFPVWFnQzJhMWhlVkthbUFEMnNjZlZXejZLR2hiK3JqSGxzbmhoNzNuWGNlYWtZUS9ad3VqV05BTmxVSWRaM2Fqc29ZM051UUxxekZHSERZS0RxVXNUUERRbmVWVTFOb05tajZKU3B3cnZXN3E5MGpxRXZNOHRHeU5ZMFRlYXZKbHdPZHZaRmp5dENkM2FTcjF0NUNwdWhlQnlMSS9EUk41Unk0TkF3ZUdOdHg1SktURE43QnRncjh1QUp1Q29PczdnV1FLQnl5amJnYlg4MlRKd0JqZ053ckV4UFBCVWUrZTNxalVTV1ZveTlFRGNnSmlQQ2FlTWJ4dFRYdkJQSzhaQTRkVVNpU3hHb2hpaUhoYUwraVJkVG1YZTFnclo5SjFOdnFxN0VNUmlvWW5iZ0czbXV5Z2ppWXE5OGRJMDZpTmgxV241aXpaSFNSdkRIQzQ4a2xtWE5sM1BEWFhYTnNScnBhMlJ3TnpjcWprVkQ0Zzh3Wm1xSytWd0RuV3V0ZTkxTlNkVHpmcnVyNW1HTmN6VVJ2WkoxRUhkbHdDb3lrT1JXMUQ0NDIyYTBiS29ucG5WTHZJSzFkR0hrM0NnVDNZMkJTeHBWc3doak4zRUtMcU9NSHdnS3dkQkxVSGEvd0I2YnBjSElJTGd1T1ZIU2k3bDdkZ0NwQ2tMd2JoYk03RDJOSENEN21MbXdRNzJRMWdVanI4S1JwaTBjTFpSaHcyMldYWVlEMFVDTlVmRzdpeUEraWNWdHpzSGFSZXcrcUE3RDJzNWNQcXVrTlNOQS95S2szRDNrZkFWc3NoZ2c1SStxV2t4YW1qdU4vcW9RcDI0QzUyNTZxWDZHRVkzc21wOGZhd0d4S3Fhck1aY1NMbE5GRGZjUnhHMnlucmhBNENvM1lvWlR5dk9xamJsQ3drVzhrMFlHd0NXZkswbmhWaHJiSGRZRmNMOVVBWlpDbUR0OWtWdE8xdmtsVzFaQUN3K3VMUWdzNVpZaHJXRG9vaW9BNmhVOG1LRWJYU3I4U3R2cS9GZFhKTEx5ZXVMV214VlJVNHBJQ2R5cTJveGkzVlZzMks2aWVVZTBsbHJMWGQ1ZmRKdmthU1NTcXozcHhQVlFkTTkzbXJPd0J6TGR0UkUwSGhKeVY3ZDdKRXNlODhyTHFRZ1h1UHFqVUJNcGtwcXkvQ1VmVlBOK1ZPU01ONmo2b0pJQ05RRXViSWw3enlTb0VrOHJMcWdGQ2RJWGNKbEJvbVEzekN3Sk5CNVFIYWllQ3B4dGRKdFlvUXFEKzltMWtNek9jbVlxRFVOd2p0dzhDMzVybG5hRW13dWNkMGRsS09xYWN3TjRYbU5MellBcVdOQUNJTjZMTGFaMGg0VnBEaFprM052dlRYY01oSFRiMVMyeUZPM0RTZHlwZTdCaWNxSzFrWXNEK0txcWpFcmsyTjBGa0N2a2JIdnNsWmEzb2xwS2t5ZFVBdExpbWtEdm1MeWg4cnpScFJHN2xkSURFTnlwZDFaSEZnRkV1M1VJUURDU2pSVXVvN3JESlFVY1MyR3lqWStobUtqakFCTmtSOVV5bkhodHQ1S3ZmV09Hd3VvTWlkS2QrcUZocERjbGUrYzJGN0tOdHQxbU9NUkQ4bGx6ZTk0UUIwQ0lzRkE3SXhBR3lFOUNnTEJraGVLaWVVWURZSTBkN21HZ2xHYTByMGJicGhqQmJkTW9LZ1FBQlJHa0ZEbE9ucWd0bTM1U1JVUnkza25hT0kxRHcxcmJwU2xpZk1XaHJTNjU2QmRTN1A4aVByNW95Nkk3a2NoUWJYQS93Qm4rVFgxODhaTWY0TDZseVBsbG1FMHJMc0EydCtDcnV6cklFZEV5TW1PMnk2cFBoamFlRUJvVUV5UHljeDBmclI4a2dSNEcvSldXT050TVBra1Mzd05YMmJJdmVleDhhaS9kZTU2TVdZc2dLYkcrQUxJYWp3NC9kKzVVelpWcU9FWUFVd0ZsclZPMnlzVFhqbGVIK1R3UWM3dTA3UVV4bmNEWkFncGpVT0MyTERhVVFOQklYanV1YStPbmc0cCtYKzU5QTlsK2t6eVpVMnZOL3NPMFRQZFdDNFRXbVdaaGZHM1VSMFFYRHZTR3Q2bGRUN0p1eVd1elhpMU81NGRGU0VnT2VSNFJ1dmkrdDFUVXBaWCtiUDBKaWg3bmhTUzhnUFpKMlNZam43RVFXUU9kREU2OHBiZllmNEsrM3V6N3Mvb01oME1jVk5HMThyUlk2MkM5ckllVk1vME9WTU5naW9JNDQ1V3R0STZPOTMvQU9ObGQxTmRaZ2RxdEtUdXpxRjgzNm4xVE5xSk9NVXFNYkxlb2tXOVhpZnUwWklzMCtpMU92eGVXcm10ZTR2NXF5WTRWVGJPZjlVcytnaWpkZlVDVjUxNVcrNGlFWlJmWVZiQ1hNdTdoWEdDMDhmZG5lKy9WVms4UklzMTIzb3BVOVBMVE1QNjArYUR4S0xsU2Nhb2VxbkNPZlk3WFdaNUhkMENBcTBSeVNTM0w3N3B1VWxyTFh1Z2VSSGZpWGtTcDY1OGpySnhrYnBEY2txdHA2Y3NkZS9WUE5rY3djcHowK25ybVRFWlhpbDJaZDRmb2l0cUErOExaNkhGYU9tYURxYmY1QmM1TlhLRFlYVEFsa0xQaktyU3c2ZGZ4TXpKNmJIazQzSFFKczR3UnVzMTRLcU1VemNKaFp1azNLMDF4a0w3a2toRzFBMnVGVmVMQS80bUZEcHVCY290SmFrU0c0c0w3N0ppR2RqV2VMOFZXTUx0dkNuRzA3cEJhMWsxUmtNbExHbFZrbjFNTG4yRnZvdlZROEd6Ung1SjZoeThaOXk2eWVqeVMrVG1yMjh2OEJNakNiS2p6NG9QbG1wZ0V1NHNqWGEzbmY1cStxOHFDa2FTWndWUzFGT3lHNE1nTmdtcFNSY3g1OFUxd3hjTmJNYmNmSlNFd3BEd0NQVlZOVmlrY0JPcDRqQTZxbXhET21IMHNaMVZjYm5lVjFha3B6NFNOQmFmSk5wVWJ0SGpsSzFwRWpnMnczV281dTdVc055N1J5NktocGVON0d5NVhtdnRVTUQ1RzBzSmxCRnRUUDhBM1hMY1J4S2JIREpKVTFCWTBrK0Z5dmFYU1RsSk9qMXZUL1pyeHZqeTNYQmQ1MzdZS3pINVpHTWVHd2c4c2RiWmNYelJucjlIbVR1M2gwaEJhU1NySE1lTzA5STEwRWJXdWR4cUM1aGpEQk5JNlI3OVYraFh2ZERwdHFXNUhxSnJIMHVPeUg2Y212NHhqMDlZOTk1SGVJay9Fdlpmd3A5VFAzanJ1M3Z1anN3Y1ZVdzByYmNMd24zS0M5dWk5SFBJb3hxSjVlR2hsZTUyRmFCU3hCbzIzUkFkZ1VKeDF2TjFneUFMRm1yWm93eGVHZy9lQlo3N1Qxc2szeklMcWoxWEZCZ1R6SmNGbEhOSytwYktCY05YNlc5bVZhOGRtZUI3V3ZUYi93QllyOHhZWEdXbmNHU1dkZm92MG83S0lOWFpuZ2Q2Z0Z3cHR4LzZpc3pYeGZoTitaNHJxMGRQS1VYR1JkelZNVE4zdTM5VXMrcDFqWk93UVJ6dTBPQWNmTlRrd0VzRncvYmxlQm1zaWsrRE13U3d3YnBsYkZySjIzVGtja3pXL0RzdmU2T2dQTjBSbXExdEtUTEprWGtUVWFqSFhERklZM3pWVGR6cDZwNlhFNUtOekkydGE1cDJOMHpabFBUT3V3ZDRkd3RTemRqMGVEWWZMSklRSEZ0eGRYYW5sa3FRclRxZlVhaFg1Y0dvZHQzYTRjbDRQUDNXalc4R094c0xYMi9pdmdqTUdNeTR0V1ZOVFV5T2tlK1J6Z1h1dllFazdMcjNhVmkxUm5IR3B4TlVFVTQ4UUR1T1NWeDdOVk5ERVMySnpiQVcyWDBQbzJMYkZQejRQZTZYb2NkSkRkT3pRc1NyaTZjdCt6ZTEwdUloY0Z1NUpzcmVXZ2ltQnNSclZqZ09YQzl3TXA4STMzWHJzdVJRUm5hN1NlTzZnVHdLaE5PR3Z0WTgzVnZMVXpGd0hmU1c4dFJUYm9HUU1zTGJKQi94ckQ4WGRLMlhNV0RZU2tlOHRzWE9KOVN2T2xkQTNROGtTbmNOODFHWjEyN2NyMU00dWhkSEt6VThuYVU5RWJtcUxNcDdGM0pNZS9rOGxieDJlOW5XSTUxcm9ZNlNCMHJpNEZ3RjlnaTlsdlpoWDVzeFJyWFJ2RUFjUEdSdFpmYkdROGlVZVFhS09PR2taTE1OdStiZTVXZGxsM012UHFuRk9pdzdLK3l5aTdPTUhpSmhhNmR3YThtUmd1RGE1NVcvUVNtUXZlQU5QSXNxbDgwa29BZktRQ09DaGUrdmdjR2drdE8xMTg4bnFyaytUeVRqT1R0b2Q5OExxeDdYR3piTHpxcUoxeGZkSlZHbHpBOFBBY1NzTWx0L3EvdlMvSFRDU2w2RG9sWWVIRlRhOWx4dWt4VTZSL05xSnJOLzV0YzhaQmZHWG9kR0dqajZJVHFvTlBoU0RZM1BiY1Njb2NrVDJiNnJwanc0L1VSdFRMZGxROXc5RjZubjBFM1BWVThkVStQYmNvaHFyYjJRUEhqWG1Fc1NaWjFFZ2s0TzY5U3lhQ0M1eE52TXF1WlVsM0lXWFZCSFFvTm1QMUo3dWkva3hHQnpiWEYva2dkNUZKdzRxbzcrd3ZwVW1WYmh3eEczSXBiWEVzSkdSL3RGQ2EyR0g3WlB6VUd2ZklQZ0tNMm5razRpSlFQZDZISGxjU0xuTms0T3lpeVprTHJkNFFUdHNVeUk1WVJ2VEVoRGZDWnQrNjBsRGNrTDk1Q1BZOWhEaVRZN28wZFUxckNISkp6SlhiT0phQnNrcXlzZ3BHL3JKMnRQcXJQdkxud094dngrRVd3cUlpZDNmY2xhckU1R1AwUnREZ1ZwK0k1M3cyaEx3NnJqdUI1cm5HYWUybDBUWHcwY0JtSjRsWWVQeFZ2RkZ5YXMyTk4wWEpuZHdSMVBOR2NjTXl2VDkvV1ZQZFNrWERTZHIvVmZPZmFaMjBWbVpUSkRRU2Y2TVQ4Y2JySDhGcVdZOGR4SEdhZ3kxbFU5MFRqZlEvN0lYTzg0Wm9wOEVwM2U3bHN6anRwYjBXL2cwMHAwa2oxZW02UkxUL0ZKY2kyYXMwTXdtT1J4a0xwSFhjUzQ3M1hGTWZ4aDJLMWJwTlZ4ZS9LZXhyRXFqRm52ZEk1MWlUc1ZUKzVsMWczY3IzR2t4ckV1ZTVWMStUeEZ0aVpwWURPNXVrYjM1VzFVemRER2kxdGdxL0JjUDkzOFVnNmRWWXZPazdjS2FxZTVwSXpkTGdjWHVZVnhVQ2RqZEQxb00xUUdOSXYwUTZiRTVNczZuVVJ4b3JjZHhCcHBuMDdUNDNjS3g3R3NpUHpwbXltYTFybnRobEd1dy94NXJWNm01eEZzcmpkZzVCWDJGN0gvQUdjQ21peEhFNW1menJRK01rZXJlRjZ0UnBjSHpPZVRjM1ozWEJPenlEQjRHUU5oRm0rYkZ0Vkxnc2NRRm8yaTM5RldsTEU1MEFjOGVMMVJRd2pvaGNSVzZ3TVZNeU52d04raW00QWNOQStRUjJNdWp0cHdSdlpCdE9keXI3c2s4THdodjBWaTZsNXNGRHVOUFJNU0l4VnRNRDAvQk14RFJiWlRheTF0a2VLa0xyYkkwZ1dBa09zV0FTLzZOZEs2KzVWdXloMzNUOEZNMERoR2hiS21PajBBYmZnakNMYXlzNUlCYmhMdWgzVmdnbWFjSHArQ0ozSEcxL3VUTFk5K0V5SUJZS0hCRVJFS1lqSGwrQ2FNUThsRXhxRUFHTGJoQ2ZGZE5uaFFjMjZnSWs2Qzk5a3BOU0ZXcGFnU2xRaFd0ZzByejJuaE42YnFEb3dvUVNmUmkxN0phU0F0NEN0aEdYTHhwZ2VVZGtLSTZ4Y0FJZnVMd2I3N3E5ZFNSanlVSHVqQXRzaGJJVmJLVWdiaERsTFlnYjlFM1YxYklXSGhhWmpPT09Ebk5hZ3NnMWl1UHRoWTRBalpjOHgvR3BLb3VBY2JlaFZqVlBrbXVYWDNWRFh0RGI3YnFpN0dJMWlzRDNPSmNTbGhHRDlrZlJXczFLK2QzaGFVYUxCM2tDN1VtU0NScmRROHNGbFhTTWZJVFlMYzVzdk9rNktNV1hnejRoOVVsb05HbVI0YTk1M2J5bW00UllYTGZ3VzFUMGtVQTRHeXE1NUJxTFdoS1l5eXBOSzJMN0kraXk2TW5nVytTc1cwTDV6ZXhUcmNNQUF1RUREVEtPT2tMdVJkRTl6YmZjZmdybDFFSTI3QlYxVXh6TG9HSFl2UFMwOU8zVnFOMVVWbU5SMDRJYVFWNnVFa2x4M2hWRlVVTDNPTjNYVVNZQkd0eks0dUliWlZjMkt6U2cvbW1aYUJyZVFDbHcxZ050SVRraUZmTStTVGx6aDk2VmRHM3E5MTFhelJzdHRZS3NxSXR5UTVQUkJhYmJhNlJrNVRMM0UzQ2dJQzQ4THU0U0xhU2VFUnNGK3BUc2RJTEtiYVlEcUVQY2dvMmxCNmxURkkwYitYb21ITkRMN3BhV29EUVJkYzJuUWo2cU9NYzhLdXE4VTJJYlpCa2FYRStOTHlNYU9TQ25iUlc0V25yWm5uWUlmZHZmeVNqT3FJMmN0Q0g3MnkvUlRhVGNRTk1lcEs4S1pvRzZqTFdXR3lSbHJIMzJ1cHRKdUczT2JHZ3ZybXR1TEJLYW55ZWFrS1l1NVIxUnl3aHJyOFdRalVQUFZUOTNERmdhU2JiSTA2SlZnamQzSkt3SWdSeVV3YVp6dUZIM0tYVndVU21qdXhpeklTVGF5YmlvaWVpYmhvallYQ2NqZzBqaEM4aVlDeHNTWlFqcVB3VERhSnNPOXZ3Um5DdzJDakhySjhRTmtseXNiR05DMDBybW13YUZpS044cEd5dFlhV04vSUNiWlN4czMyMlNYeU9SVnhZVWRpYnA2T21qaGJ1UHdSS3F0aWpic1JjS2xxOFV2Y05jdXBER3g2cHJJNHIyZFpVdFRpWmt1QVVwVVNQbWQ4UlF4RnA1S2RGQzJ3Y3pudmNUY29RY1J6dW1yTkNpWVE0M1RrZ0xBNkxySVlqaU5TRExKZTBiWXVJaVZNUjJSdzBCWjhJVW9KTUNHRlRFZXltU0ZnUENsQjJSRExkRmtDeWtYQlFMZ2hvbGtyRHlSR0d5WDFLZXF5bEJKak9vV1VIUDVRSFRLSmx1cFFkaE5kMUVtNkZkWkRySmd1aVpVV3lPQjRXZFFJVVdQMUcxa0xJTlJUZ0RmWlRkSXdqNGlsWEJ0dVFGRU12OXE2QnNoSXZjVHVOa3hSNGUrc21hR2duZEV3NmlreEdVTVl3bnBzdTFkbTNaUFVZakxHOThadHp1RU5qcjRGK3p2czlrcXhFNTBPcmZxTHI2YnlKa0h1ZTZKZ0F0YjdLdDhrOW0wZUUwOGVxTnR3dWxRVXNPR1JOTFdqWURoUVcyTDBlRnRvSW1pMm5ieVREbnRjTnpkSTFPSU9tazB0VW80bmtYSlVGTm41UjQ0MzlhUGtrQ1BBMVdlT2Z6dytTUUo4TFY5cWYvbDJmRkpQM2hHR044Q2tCNUtUUGdVdzN1eGRXRktPVldVWGpsamxSQUJGYTB1UENpMjhqckJYR0gwVndDUXNMV2ErT2p2bjZucStuOUpucmFkZlFsaDlLR0VFaFdoMmJZTEFicEEydFpTQjlGOFkxZXV5YTF0dS9tZm9iUWRNaDArblgwb3hGSVkzQncySTNDMjNCTzNqT1dVb3ZkS0d2RVZNZHkyeC9OYXFHM0hDRE5UUlM5ZDFtd1VNajhPYS9JOURPSzFFYVIwVm50UjUrcGlYTnhSdDNjZUYzOXBBazlwZnRBbmtNLzZVWjN4NUpEdjdTNTRNTGk1TGpaQm5naWl2WnhUNWRIMGNWdWFqOGtaa3NhMDc1T2t4ZTA1Mmd4My9BT2xXMytUdjdTeVBhYTdRWkhiNHEzK3E3KzB1Uzk4OXBQaDI2S0VsWEkzb0VyM0hSL3lJL0pEbDRTOURzVC9hZHo5RTMvdE52M05kL2FXWS9hYzdRcHR2MHEzNk8vdExqSXhCOXR3RmdZcElEc0FoOXcwWDhpUHlRYW5pWG9kclB0TDUvaEZ6aWpUOXp2N1NKRDdUT2ZaenZpYmZvNyswdUpqRkpEeUFVUnVLU0FjQUlIb05IL0lqOGtHcFluNkhjejdUR2ZBQVAwbTMrcTcrMGlSZTBybnh4M3hOdjlWMzlwY09iamtndHNFWm1PeUQ3SVNKZEswNy93Q2t2a1dJNWRLKytOSGVvL2FOenk2MThUYjlEL2FUVVB0QzU1ZVIvd0JKTitoL05jQlpqOHR4c0xxeWd6SFVzSThBVk9mU01ELzZTK1JxWUhvcjV4UitoOUIwdmJybldVQytJdCtoL05QeGRzK2NuRUU0aXo2SDgxOC9RNXhxb3g4RFVYL0w2cVo5bHFweTZQaDhzUytSdjRub0s1eFIraDlGSHR6emcydzkvYnQ2SDgwWm5idm5OcmJqRVcvUS9tdm5FOW8xZmIrYVovajdsZ2RvK0lmK1V6L0gzS245aC9wOGprc0hUSC8wby9KSDB4VGUwVm5pTHdqRW1qN2orYU8zMml1MENFM09LTUk1MkIvdEw1aEhhTGlIUGRNL3g5eUkzdE54TC95V0gvSHlYVjBXdlQ1Rlo2VHBqZjhBcFErU1BwOGUwRm5Tc2JhWEVXbjdqK2FTcXUyWE16cjZxd0VuYmcvbXZuSm5hYmlRSDh6SC9qN2w1M2FiaVJ2ZUdPMytQUkQ5aWZwOGgwZE4wMUxqRkg1STd2V2RvT1labW4zdXRZOWp0N0EvM3FqcThlZ25CZk5JMHY1SjFMakZWbitxbWFia0EraFZMVjVrcWFrbjlZNFg4bkZQeDlHU2R2OEFZZGt5YUxDdUZINkhXOFR6OVQ0WVhOWS82RmFGam5hSFUxTDNOcDVDMXA4N3JUNUpaSjkzUGNmbVZEdXIvQVM0cmF4YURIaVhLTWJKMUxKZTNBdVB5Wlp6WXlKMmwwaExwRDFWYVpwS3VRQTNMYnBpa3dhcXFYRDlXZEsyakRzdXh3eDNsRmlCNUt3M0hId2dGS2Vibk45UlRDOE9GT0d2ZGJ6VGRSaVFaNEJmeVdKQnBKQTRHeVNtRnlVcVVyT2U5eDdFWlp2dEJDTXQxaHdRN0ZCdHNDV29VakxwQ2hsMTczNFVpTHFKQ2ZHQ0tNdmlaaHozdGpKcFRvZDVsZE93VDJqTTc0TGh0TGg5TGlJWkZFM1FCcGR4ZjVybWNVUVlOaXBoN21IWm9LWnFJWXNpcWtWY25oejc0MGRvcFBhWHp6VHlYZmlUU2ZRTy9OV3J2YWN6NjlvLzZVYmI1Ty90TDU2cmNabWdQd2paQkdhcXZqdTJyT2owekRrNXBmSXRhYUdrajkvRWo2RWQ3U1dlM0hmRkcvUS8ybE5udEpaNGFSLzBrMzZIODE4OWpOTlpiK2JhcGpOTlgvNWJVVXVpNEg2ZkkxbkRwMGx6amo5RDZJazlvdlBVczdIeVlvd3NBNHNmN1NxY3o5cnVaODB4TWpscld1YU9iMy9OY05PWnF3YjZSOVZML0xPc2EzU0dOL3g5eVRIbzZUdWw4aE9QSHBPbi9IQlJ2K2lOb3pKbUtwb3FVdE1vTXZCSVhPSjhabW1jOFBkY2szUmNVeENzeElrbHUzb1VuUTBUcW1TMXVxM3NHQ09uaVlldDZwbHp5MjQwNi9KamVGVTBzaytzN2k5MXVESmpIRFp1eENSdzNEelRNQkk2SjUvakNwYW5MdWRJZm9kNlY1UHFMdnFYUHVOMEI3a3c5b3R3bDNoS1dNUHhiWU1QSlUyVmIzTkllYnQ4bERUNkwzZGxxZDRWbkg4WnVtV2UyTE4yVVl5ekRhOXNNRnJCcEI0K3F1WlBhazdTSjNsc1dMc2JHTjdFTy90TG1KNHNobWxMajFIeVhQQy9JcHowMi9sblNaL2FpN1JKVGY4QVNyZHRqNFhmMmxrZTFYbnpScGRpWXVQNkx2elhMNW9vcVp0OVIrOVUxWmlMV0d6Yko2MGVqZjhBMEkvSkZOK0V2UTdJejJvTzBLUjIyS3R0OG5mMmxNKzFWMml0Mi9TemR2Nkx2N1M0YXpGM3RPd0NrY1hmYmdKcTBPay9rUitTQWNzSzlEdUgvd0FWWGFLZi9GbS8xWGYybE52dFNkb2ppUDhBcFp2MGQvYVhDZjB3L3dBZ3B0eGw0SEFSZTQ2UCtSSDVJSGRpL0krZzRQYWo3UVFCZkZXZlIzOXBOTjlxUFB6aHZpalQ5enY3UytkRzQvTVBzaEVibUdZZEFxY3VrWUg1TDVENDVNUDh0SDBmRjdUT2VYODRtMzZPL3RKaUwybE02UE5qaUkranZ6WHphM01rNEhBUjJadnJHY1J0VldYUnNMN0pmSXY0OHVEenhvK200UGFMem03L0FNUmI5RCthc1lmYUJ6aklBVGlMZm9melh5N0ZuYXRIRWJmOGZjbW1aOHJRUGdiOVZXbDBYRjZMNUY2T1RUZWVKSDFKRDdRR2Eza0ExNCtoL05PeGR2V2FRYisvdCtoL05mSzdNL1ZnK3czNm9yZTBDdEgyVy9WVmZzWC9BSlJkOTc2YS93RG9SK245ajYwcHZhQnpPMGIxN2ZvZnpWM2hmdElZOVRrR1Nzdjl4L05mR3plMEd0RytrZlZHL3dBNUZhQjhMZnFnK3hxLytBdC9UY2lwNEkvUSswYXYybjhYTExDck4va1ZWSDJpc2ZudVk2eTNsY0g4MThoLzV5SzNxMXYrUHVYdjg1TmFCOExSOTZGOUd2MCtSMk9IcHFYR0NQeVI5WE83ZTgxdTFhOFFhVzM5ZnpWTlhkc0dLVjVJcUtvT3Y4L3pYek1lMUNxTzNoK3FWcU8wU3BsQjRIeUtGZEFyL3dDQ1J6YVhCeXRJdmwvN0hmY1V6TkZWM2ZMSTAvZXRlciswdWd3Ynd4azI2Mk4xd3lxem5WekVqV2JIYlp5cko2eDhvSmRJNXhPKzVXbmc2UXNmM3YyQnlkZHhRVzJHQkwvbjZIVE16OXJVbGFOTk85d1llYjNXaFYrT05ydkdMaVU4a3FrZklYbFRpcFh5RWVxM01lbWhCY0l3czNWY21WL0RGcitvMDZzRW8waTZib0tXejliZ3MwbUc2U0NRbnpDR044a1Q0N0dUR2JtL2lNMU16ZE5tN0lENU5yckJhRHlTaFBjSVpCR0RkanR5U2tySEtjaTI4c01jQ2V1N1NicW94Q3FJT3gyUjhRbkZJV0NNM1pKczhub2tKV05ra0ViWEUwOS9DL3FTdC9SNmVsYlBGZFIxamNta3kweWRseVhOZU9RWWV4cGVaVHNBUFZmcGgyVjVWWmxQSitHUk5hR3U3bXp4OTVYekY3SWZaSkxXWWhCbUNwZ0ppcDVBTGx0eGEvOEFjdnROMUYzR2hyQlpoNEZ0Z3RlankzSk40RDRXdmJ3U2lNakJBMlJHeGFHQm9GL1FvN1lyRGhDME1pQWJCZm9pQ0FvN1dXUkFOcnBkSWFoYnV3c2ltRGxKNHVVV0JxNVJHUmJRZzIvTk14MDRiWmVjMDdKaGcyUnBBTWpvQ05GRGNMTEI2SXJXbzBnR0M3blYwV0RTN2NKcllkRkVwcHdTTlBZcVlDWk5qMFdBMGVTaEJVc0t3V0p3Z1c0UUpCdW9RVzdzTHhqdWpHTmU3dndxQWk1aUgrQ2xwb0FtSm1iOGxZRWR4NXFFSzRzMG9UM1dUOVJDTEpNczNVSWVFbzJVSlpnQnlzU0JzSTVTc2pCUHc0b1NFSmFnbTlpbENYV0tPNWphZmsvVmVpbEVwMkFRc2hSWWlKSk5nQ2Z1VldNdW1yT3B6ZnF0emtBYVBnQitZUXRKa0d6UVBrRUhKRFNhdkE5TFMxclZTUzVUZlVQSkxQcXVtQ0VnN3NCK1lVWklRUjhBSDNJSEU3WnpxSEtUWWVXaEhPQXRaOWxiZlBTWFBDVHFYTmdid052UktjUTdOWWx3dGtiRGR0bHF1TVZBcGk0QmJUak9LMmE1b3N0SHhFdnFaRHRlNVNuQUt5b2trZFVPSTMzS2xUNFpxZGN0VmxIaHpvckV0UjJ5R01XMGhWOWpDVFBVdEl5TnU0VXBvR3RCNCtxaVhTUDRDeWFLWjNRbTZGd0NUS3lzbTdzRmE1WDRodVJ1dDJkbHVlb1lUb0tvc1R5eVlOUmMwaXlCd0RValNwbnZ1VGZaSXpURURsV3RkU051NEFuWXFqcW9ITUpJdVV6WVN4S3BsTnlsSlMwQy9WRXFKM3N1TklTb2dubE55M1lva2lXS1R5a213U3haSklybHVHN1hjRm4zWmtZL3VSa3NvMjB2bUVRUUJxc0pDSDdBQlFGS1hicElBZzU1WmZsQURuM0tzM3dhZVFoU3dodlJHaUZYUHJMZGxVMUFrTGxzTDR5ZWlYbHBIT1B3L2dtcWlGRTVzalc3cGQycHgzV3h5WVpJNGZEK0NBY0psRytqOEV5MElLRTBRZU53bFhVQkYxc2NsSk16YlFQb2w1WUJHTGxTeUZGN29zKzV0SVRrMGxqWUFJV2w3K0FwYUlLZDIxblJZTCtnQlQ0b0pYZlpUTlBoWlB4TlF1UjFKbE4zYnBEYXgzVGNHQ200TmxmdzRheG8zSDRJOFVJdWx1UTZLS3VMRHd3YmhGN2hyZnNsV2ptTWIvN0tPcU1EcDlFdHlMQ2loRVVRNXNzaWpCVFFrNzAyQ0t5bXZ1bHBzTnhRa01PQjZMUHVUWGJBV1ZoNElnYm5oVjFWakxHQWdXSFJNUXBvazZoN3R0N2dmZXFYRU1RZFQ2bWgzcHNnMTJObDVJRHZ4VlJOSzZaMStVeElBaFBQTElTYjhvTFdQSnVTalhjYkN5bTJJbEdnZVFQZUZpa0g2azAybkN3YVpqVGU1UjJkb1hFVjFNTXNwdWFBTmloTzFYNFJLUk5vVWhRY2JLSms5U29IeElkd3hSTWwrNmdaUFZlN3NsZTduMVUzSU5JaVpDRkh2Q1VUdWZWWjdxd1UzQkpBdTlLenJ1dmQwYnFUWWl1MmMybmdTcE9kc3NHTXFIZHY4bHkwR2t5RG5HNjgxeHNpQ005V3FiWXpiaFN3cVlQNzE0M0NuSkYzWkJVMk1kS0xCcTVZVzBYMUc2S3h2a0RkV3VINWVtcW5OOEJOMXUrQTltc2s3Mjk0eDFqNklHenUwNXREaDg5UzhCclQ5RnR1QjVBcTY3UitxY2JuOWxkc3kzMlFRZUJ4WVNmVnE2MWwzSWxQaDdHZnFXbTNtd0lMSnRPVzltZllnRE5FK1NIa2c5RjlQWlN5ZFM0QlR4alFBUVBNS3RvNnVqd0JqYmFRUnY4QUNFUTUyaW5mWVBBSG9scVFMUnZrbFZHMWxtN0pGOVY3eUNDNzAzSzE1bVlLZDhaSmtXcll4bnBsSTh0Z2VISDVvMHhUVE42bGV5bGZxTG0vVktWV2FXdzdOZGY1TG5yc3dWZUtnZEFlb0syUEsrQW1zSU1ybkhiNW9oVFIrYjJPRzhvK1NRSjhEVTdqcC9XajVKQy9nYXZ0RW43d2ZGZi9BS2NLdzJZRkxYM213VUdYTEFucUNrMU91UXM3VTUvZElPbWJIVDlMNzdrVnJ6UVNocFR5VmVRT0VUYkpZTUViZGxscmk1ZktPcmRRbm5tMVorZ09nOUloZ3hwdGVUL2NkTW9LeHJTb2VzaVFyelN2SHdlcFV2SDRITzlGbDVyMkRteVYxcVVja2I5aTBycjA4bC9tWCtaYml2QlJPb3JXc2FRQUZTMVZacWNiSzJrcFlwZnNyRE1IaGZ2cFZyREdXYmhzemM2ZWRsRzJxSit3aHl6RjMyRnNiTUlpSDJWSjJFeGZzcHZ2R05jVUJMUnlvMWRwSit3c2h2OEFRVzBSNFZGK3lwRENJajlsQTlUaTlHSTkwa2F3MXY4QVFVd1A2QzJjWVRGK3lwakNJdjJmeFFlODR2UmpZNk9SckRXZjBGTnJmNkMyWDlFUitTeitpSXgwVTk5aU1XbWFOZEgvQUFLWUpCK05YNHdtUHkyVXpoTkord1VEMWNXV0l3Y0NoYVNmdHJCYmY3YXYvd0JEMGg0WVZNWUpTOUdmaWg5NWd4eXlTUnJtbHgrMHZhSC9BTFMyVDlFUUQ3UDRxVGNJZ3Y4QUNoZVJDMVBMNm11TmlmOEF0b3JZM2JiclpHNFBBUHMvaXB0d2ltL1ovRkxlUkZtS3lQek5kYXcyNVdUR2ZOYk96Q2FZZllXZjBUVDMrRkI0cUxDams5VFZ0R29XN3RTYlFPZnd5eTJ0dUhVNHQ0VVVVME1mQVhQZWFFWmRGbHpjMmpWbTRTOGkxbFlZWGdnamVDOGc3OVZkK0FDd0NHMXpvamM4SlV0UzN3VzlQampwRjhmMExDT2FucElnTzdiZTNLcjZ1cU01T2c2UW9UU05sNTVTKzhmQkNVMjVjbmRScVZsNGdZZWxaQmRNdkk4MHUrM21tcEZId3E1QUZsMW51UXBiZWF6M2xrYVZITnJRSXhMQmhCQ0ozaXdYM1JXRllFUkZ2VkdpQU43Z0ZaYTB1RzVVbzdCMWlsendTUWNaUm41RlRqREFUc3phNnJ4U1hIeEFMYXBxV0tjYnRXQmhkSVI4QnVyR05TU1NGNU1UZlkxbHRFRDlzSWdvZ1I4ZTYyVnVGVXY3QlV4aGRLUHNINnFUeVNpKzRtT2t5Uzh6VXBLZlR5OVFGSUgvQUcxdUl3YWpuK3dzZjVQMGtSdm92OTZjdFVjeWFQTGs0a3pTMzByMlBEUTRtNXN0aHd6Q1JUNlhFYzdxM1poTkVTQ1l6Y0pwMFRTQUFOaHNxdVhWTjhGalQ2U0dMbVNBaU1PWUFBaE9nMHB0ck5BVUg3cXZHSGljbDJkZG9vUmZDbG53N2xXem93Ui9lZ1BqQ0paS0Z2VFVWbmRLWGQ2azZZd29GZ2FuUnlDWEhZSk9oMGk2QkpOM1lPeWZrSUtXa3BSSURmaFdGTkMzazhqWEs2dTEzQUYxVm16M1hMTHJiR1lMVHVKSmIrS2s3Q0tSbjJQeFRWcWNmb3pHbG81R292Y3hvc0lrTXhFL1lXNHR3aWlrNWpLZzdDb1JzQitLY3RUaTlHSWxvNUduZDBmL0FDMU1SSDloYmIraW9UMC9GWkdGUStYNHB5MUdMMEV2UnlOVE5yVzd0UUp0L3ExdHY2S2cvWi9GWU9Fd2ZzL2l1dlU0UFJqUGQ4NjgwYWxxdC9xMWtOQjYyVzEvb2VFOHMvRlovUVZFUDlYK0tIM2pCNk02c2VvWDhTTllqYVAyZ2pCZ3Q4UVd3akJxTnY4QXF6OVZuOUYwWVA4QU5sRDQyRitUTy84QW1PMjQxME4zK0pUQXQ5cGJDTUpvdi9MUDFXZjBWUi8rV2ZxbGIwV2xwNHJ1VUlOdnRyTzM3U3ZSaGRHQi9ObFovUk5KdCtyS0RlaDhZcUpRMkg3Uzl0KzFkWC82S28vMkY0NFZTZnNGRHZRNVpWRkZBWE1IK3JDaHFIL2xxKzl3Z3Z3dkNpZ0hMVTMzbENwNjNVNU9ISW9MQjMrcVVtWWU5NnZ2ZDZkcCtFckkwczRDbmpKbFJ0dDNNcTRNS3R1VllSVTBjYmVCZFRNM1FLQnU0M1FQS0hIUHA0Y09MSkdUUndneVRFcjBya3NaQUw3N3FSdVRLK1NvSzBlZklSZmRMUG5iM1RybmZ6VUttb0l2WlY3dzZTN0xqVWVxM05McDFMbG84cnJkYTQya3lGUTl6dFRDZFFmc0Q1TGUreVhzNXE4ODR2VFliRXh6bVJ2YTh5Z2JFWHYvQUFXdFpXd09iR2NUaW9SRStWOHJ0RFMxcElIelg2SCt6YjJNdzVBd2FDc3FZUUswZ3RjNFc4djcxdEtDZ2p6Y3B2SzdPalpHeVhUNU15ZkhodE5HMFRQallTVzgzMC8zcmFLV1A5UzFzbnhOSFZGYTd1YWhrNzkydDhsaU0rOHpQZU5oenVxN1kvWURhM1RNYjhJaWtZKzlmcEhSRWJGMEtCc0dxQnIxa3cyQzRSQlRvR3dSTnNSY1VhT1BTbUlvbGw3ZFBBVERyTUJnY2lCcXhGeWpOYmRHZ0dlWXpaRkRiTERXN2JvclFpQVpBdFVTRXpvSFZSMG96Z3RwVXkxRUxRc09VSUJjVkF0dXB1NVhnTHFFRjNOSzlwTmtZdVdOUTZxQWlNNEl1Z01jN2RPekVFcUJpRFJkUWdwS0M0SUJnTGlqeXlhU3ZSeWdxRUU1NkYwbzVVWThPTVkzS3NTOHMzdWhPa2M1SFJDcXE4UE1wMkt4QmhwaDVWcGNqZFNZL3ZEd1VMUkJRVWJYamV5eXltamlPOWt6TGRnMlNwWTZVb0tJR2ZTUkZ2QVNjMUcwbllCTTJlQllySUJ1bzBDVmo4UEJ2c3E2cHdQdmdSZGJJWEFYdWxwdFRMa0pVa0dqVEtuSmJaaVNTRW1jaVJDK3picmMzVkR5YldQMFUyUnVrTnlVcG9PelFuNUsxaTJsWWo3UDlSdVIrQzZVTkRRTmxoOVExZzJ1dTdFY3MwYURJRVlHNENZT1Q0S1lhbmh0aDVyWjVjUzAzV3JaaXpHOFJ1RGRYM0FvSEJCSmxiaTB0RmgwTGdBeTlseXZNK0xpZVI0amJzZkpYMkltcXhPVWpTNjErb0tWYmxCMDI3bWJsQnNRZG5OcXVtdmMzNTNWWExTQnhJdGRkWWw3T0pYNzJiYjVvYk96Y3RQaURmcUV1Z2prTW1FYXpmUXBuRFNXMmJDdXdmNUJ4eGpkbytvV1A4bHFlSC9WcmxFT05uQTZpUTdNY0FwTnl2TS9rRmRpT0VRUmphTW9ic0tZNDdOdDgxS0lja1prNTRQd3B5SEpyM0Q0VjFWbUdSQUM0L0Zaa1pUMHpia2dmZUVHMGh5bVRJcjNIajhGS1RJTmdMa0xlcS9INmVuSnM4YmVxMWZFTTZCb2NBNG9leENrZmt5S0w0aTFKVDRGVFJIbHFsWFp2a2xKQUoraXBxakZKNTc3cm02aURWVEJTeERZdDJWVlUxVURMZ05CU3NnbWtPNTVXRzBCZHU2eUxjVGFKMVZXeDE3UmhWTWxLNlVuYllyWW5VRVRlVzNVTzRZejBVM0UybXVEQnk0M0lUVVdGc1lOd0ZiUGMwRFlwVjhtL0ttNG0wWEViUnRvQ21HTTlBdlN6TWFOdVVqTFVHL2hLcjd4dXhJZjBOL2FDdzhNYTI5d3FzeXlrL0ZaWkplOGZFRVNkbmFvelV6M05nVUZqWFAzMUlNekhOTjdvYmFwMGR3aVNPMldBcUdROVFnVkdOaGdJQ3FKNmg3aVVtNWozbmNKMndIZU9WT055T3ZZbFY4azc1YjduZEhaUjZ1UWl0b3RQUmRTT1cyVjRwUzQzSlRFZE1HamV5YjdzTkNpNFhSSEFBallEd0ZoeGFCc0VVVXhKNUgxVTJVbHlsYmcxRXIzeUVHd1dIQXVIeEszYmhvY09GS1BBM0EzTnJLYmhpaVVZamU3Z0VvaktXVjMyU3RsaHd4a1E4UUgxVExXUU0ySS9GYzNocUtOVkdHUE85a1ZtR084bHNwWkY1ajZxSjdzZFI5VU81akZBb0JoaHNka3M3RDMzT3hXeW1SZzJ1UHFva3grWStxN3VZU2lqV2pRdkN3YUo0NkxZWGQzNS9paHU3dnovRlRjdzlwUys2RHlXZmRiSzBNYlR4KzlRZEdFZTVuTnBYZHdQSmVkRGY3S2YwQUxEbnhzL3dEZFRjdzFFUlpSdWVkbXBxTENIdnRzcHN4Q09NOVUvQmprVEJ2ZTZtNFBhZ2JNdHVsSXYxVjVoK1ZvNHdDNnlybjVyWkZheEtGTm5naGxta294ZEhRc0dvYU9uMDNETGhiamg5ZlR3bHZ3Z0JjRGh6ak1YZzNOdmtWY1I1NGtsYUExeEI0M3VnWktQb2Fuem5UMExBZTlidDB1bzFIYkhIVE5jMWh1YmJXSytjS25IcXlvUGhsRmxPamZKTzRHUndKUXRrbzdMTDJuVldJemtGendDVmRVR2FwblJnZ3VMaUZ6REJLUVR2YUdnaytpNi9rakpFbUl1WnFpT24xQ3JxenJpTjRmaW1JMXBBYjNsanQwVzA0UmxLVjVFdFM0dXZ2WnkzUEM4bFUyRXdCem1pNDlRc1ZWVmQvZE12YmhOaUxjUldob0lXT2JHeU1YRzF3dDB3bWpGRkdIRTZWVzRWaGJJWXUvZU43WFFzU3h0NzNHT0srM2tuSVR0UHpJeGR3TWd2dnNxNHg2eUxKL0Z3UktQa2xHRUFOWDJIVlExamp4Qkh3L1FlRkNhZXBkSWZwcVU5MERaV0VUbWdnRGxJeDFRampIelE4UnpCSFJSNnU0QnNGOC93QmZwZGROdjRQWHpQdEhSK3BkQ3d3VjV1ZVBKLzJMZHd1TGczUXk1elRzRm8xVDJtQ0I1YUtZbmY4QXgxVUc5cUlQL2REL0FJKzllVm4weld0OHcvWTlSazlvOU5EalR5VFg2TTM1cEtJMEZjL0hhY0wvQVBWRC9qNzBWbmFhTC84QVZUL2o3MVBzN1hmeS93Qml6SHIyZy9tZlJtL2FDZWlrME9CNFdqanRQYmIvQUtwL2o2b3JPMHhuK3lmNCtxQjlPMS80UHFpeEhyL1Qvd0NaOUdiM0cxMXVFdzFqdkphTEgybXMvd0JrL3dBZlZNdDdUNC85bC94OVVIMmRyL0tIMVE1ZTBIVHY1bjBadWdDbUczV21SOXFVQlA4QTFNZlgrOUhiMm93Vy93Q3BqNi8zcFgyYnIvNWYxUVgyMzAvK1o5R2JlR2l5enFzdE9QYW5CZjhBNm1QOGZlaWp0VXBiZjlURi9uL2V1ZlptdS9sL3NNajF2cC84ejZNMjBQUGxaVDE3TFVSMnFVdit4ai9IM3JJN1U2WC9BR01mWCs5Yyt6TmYvTC9ZWXV1ZE8vbWZSbTFkNlY3djNlVjFxeDdVcVgvWTIvNCs5WkhhcFJqbWpiOWY3MHo3SDFuNFBxanI2eDA3K1o5R2JNWm4rU2g3dzd5Q29CMnAwUkgvQUZOdjEvdlVtOXFGRGY4QTZtMzYvd0I2SDdIMXY0UHFnVjFucDM4ejZNdnhNL3lVeExKYmhVVE8wK2gvMk52MS92UlIybjBBL3dDNXQrdjk2bjJQcmZ3ZlZGcVBXZW5melBveTVFa25rcGlTUTlGVE43VThQLzJObjEvdlI0KzFMRHY5alo5ZjcwUDJScmZ3ZlZCTHIzVGY1bjBaYkIwcDZLUWtsdjhBQ3E1dmFsaDMreHMrdjk2SU8xTERmOWpaOWY3MHQ5STF2NFBxaXhIci9UZjVuMFkrSHpIN0trRE41Sk5uYWxodit4cy94OTZLM3RTd3kzL1UyZlgrOUxmUjliK0Q2b2V2YURwdjh6Nk1aRDV2MlZrR2MvWlFoMnBZWHQvb2NmMS92Ukc5cVdGLzdHejYvd0I2VEhwMnZ2OEEwL3FoRSt0OU8vbWZSbVEyYjlsUmxmVU9GdENKL25Td29mOEFjNC9yL2V2SHRUd2tqL3FVZjEvdlVuMHpYL3kvcWdvZGM2Y3UrVDZNVkxKcmJ0UzcyeWgzQ3Q2UHRJd21wa0RmZEkvci9ldGhpeC9DWjJBKzZ4aS96L05ESFJhNlBmR09mVnVuVDdaUG96UjlFcEhDR1laRDBYUXBNV3dab3ZvaEgxU1VtWU1GWWZnaCtwWFBCMXY4djlpejd6MDcrWS8rZjBOSTkxbDhpaHVwcC8yVnUvOEFsTmdvK3hEOVNwUTVud1I3ckdPSDhWendkYi9MK3FPZTg5Ty9tZjhBUGthSUthcEIrQzZJSWFyL0FNdGRNcHNjd0Z3M2poL0ZPc3huTDMvbHdmaXVlQnJ2NWYxUlBlZW5melArZkk1TzJucWovcTBhT2txei9xMTErUEdzdUMxNHFmNmxOdzVneXkzbUtuK3BSZTdhNzhBeGFqcHY4ei9ueU9OQ2pyVC9BS3BTWlIxbDk0MTI1dVpjcjIvbXFiNmxBa3pObGh0eUlxZjZsRDd0cmwvQU1XcTZkL01mL1A2SEgyMHRVT1kxTVV0VCt3dXB5NXF5M3ZhT24rcFM3czJaZDN0RkI5U2hlbTEzNEJpMW5UVi8xUHAvN0hOdTVxUmI5V2l4d1ZCNVl0MHFNN1lBeTlvb2ZxZnpWZkxuL0EyRTJpaCtwL05JZURYL0FNczYrbzlKL20vUi93QmpXMzBrNVB3V1VYVTlRUHNLNmw3UmNGQk5vb3ZxZnpTMG5hamhBdVBjNHo5Lzk2VjRHdS9sZ0xxUFNiLzFmby83RmFJYWpxeFJram5IMkFuVDJwNFQvc2NmMS92UUplMVhDVHQ3bkg5ZjcwK09IWGZ5eXpIcWZTSy8xZm8vN0ZjNXMvN0tnNXMvN0tkUGFmaFovd0M1Ui9VL21odTdUTUwvQU5pWi9qNzBYZzZyOEFsOVI2VC9BRFg4bi9ZVFBmV1BoU3hkUGMrRldKN1RNTDMvQU5Dait2OEFlaC81eHNNUC9jNC84ZmVtTEZxZndDSmRRNlQvQURYOG4vWVFkMzUreW9IdjcvQ3JIL09MaGY4QXNUUHFmelhqMmk0WC9zVWYxL3ZURmkxUDRSRDZoMG4rYjlIL0FHSzN1NWgwVUhkOE9XcDUzYUpoeFA4QTFKbjEvdlEzZG9HSE8vN216L0gzcnF4Nmo4SlZldTZWL05meWY5aE15U2pocWpwa1BSTm5QZUhuL3VUUDhmZW9uUEZCL3NqUHIvZWpXUFVmaEV2WGRLL212NVArd3FkWTZMQmMvd0FreWM3MEovN20zL0gzcUJ6clEvN0d6L0gzbzFqMUg0UmIxdlNmNXIrVC9zQjF5RG92ZDlKK3lzbk50TWYrNnQveDk2Z2MyVTMreWovSDNvdmR0UitFVjcxMDcrWS8rZjBDQ2FTM0N6cmY1SVArVjFQL0FMS1A4ZmVzZjVVd24vdW8vd0FmZXA3dHFQd2d2VmRPL21mOCtRYlcvd0FsN1cveVFmOEFLcUgvQUdVZjQrOWUvd0FxWVR0N3NQOEFIM3FlN2FqOElIdlhUdjVqL3dDZjBEZ3krU3pxbC9aQ1hPTXhrWDBBS0p4cVA5a0t6N2xJVDlvZEsvbXY1UDhBc05pU1RxMEtSa2RiaElIR28vMlFvZnBScDZLZTVTT2ZhSFN2NXIrVC9zV0JlN3lVVEk3eVNQNlRiNUxCeEpwNktlNVNKOW9kTC9tdjVQOEFzT2tPSnZaWUlkYnFsaGlBOGxFNGdCMFEvWjh2UXFTNnhqOG1oZ3RkZFNOZ0VwK2tBZWlFNnJ1bVEwRXI3RlNmVm9QelExSktHb1RxcllnY3BTU2ZVRUJ4SjYydjFXaERSTkZPWFZJdjBDeVZmZE9JbDhOMENXT1dRYTR3UzNtNml4cmFYK2NkMzVPNHVneW1VdUJhNHNhZnNyV3g0MUR1anp1Yks1K1pnQjd6YTNHNVRlRFpjck16VnJJS0NNeTNOaVI1clljcDltdU01em1oYlEwMHIydWNMdVlPaSs0dXdUMmJLVEo5TkJVWWhHeWFRNlhuV0RjZFZiZVdLVkdTOGNtN0tMMmIvWjVod21ranhDdmdQZkJvZU5iTDczSG12cHdiZjZPeGpXc2J2NFJaZWJTeFViUkZTQVJzRzFtcWJMeHUzYnY1ck95UGMrQy9pVzFHTk45dVVTT0szQXNzeHR1VTB4b3NwWVJCakxkRk1NUGtpYUVRTkM3WUxBaHRsTWNJbWhlN3YwWExBQngzdndtMnMxRGhZYTFvQ25xOGt5eUVIVTR2c3BNQStpd1NTVk5qVkxBWks0OGxOaEJRM2NyTENwWU5FaTIvVlJMUFZZTjdyQnV1MlNqeFo2cUpDOXVwaXlOTWxBaXhZdDZJcFVUYXhSV1NpSmFDRU4wUzgxeExsSjE3RlN3V0x1WUFWNTcya0xFZ04xNFV4UFZTd1dJMUFiZFFqTFFFNUxSMzZvYmFHL1ZTd0FEaTBPNVJkVE5IUlprb3JIbGVOTDRMWFVERjJ1YnFURWM4YmhiYjZJTGFVNzc5RkdDbkxTYm5xb2RDU3ZZc1JNWS9oQ25oMzJLblROMDhsUWg2VjF0ckJDN3kzUUpseld1OGtHUmpRb3lDazgrL0NnWGJiN3FiNHc0cUR4cENUSVlnVDNOSFFmUkJkTmJoWms2b0RnbE1OQkJWRlpMOVlReTFvRjBNdTBwWjJqTDZiWDVwU293T0ozSXZmekNaTXpySVhmUGNkeVYyeVVJL29hQ0svZ2IvQUZVR2VuaVlEWm8raWVuZVFOeXF5cGZlKzY3WnloS1I0dWJBSk9WeE45a2RyZzRrZXFIVUZyR2s3SmJSMmhKOGR5bDU0STR4Y2xMMXVMTmh2dXRjcmNja2ZxQUpzbHRrb3VwNnlHTGJiNktycXNVaUY3RUJhN1ZWMHJ5VHFLcWFxcWxzZHlsdVIyaTJ4RE0zZE5kcElXbjRybVdlZHhEWEg3aXN5ekY1T3JpNlRlMklHNUFTWEliNEpWVFExRlk3VVhQMzlTc053ZVdUblVmdlZxS21OZzJBVS9mMlJXMkNCeUNXRXF4bDV6UmN0U2xUUUdHL2gvQlhjMk9zRFNMS2lyc1U3eHhzT1VEa0dzSlhGd2FlUHdVSFRoR2xZQ0wrZTZRbUJCS1p2QlVRanBnVWpVMVhObElrcGVlbmNVTGtHb2lqNXk0OG9ibmszM0tLYVp5RkpHV29ONGFpTEZqcjlWZ2dnY0taTHIvQ1VHVno3ZkNVU2toZTFrWE9LQTk3MmNLTHk4SDRTc3UxT0h3bEVwSGRwRHYzTzJRM3NjODhJb2pJMzBxTDVkQitGRnVPN1FodzRBQXJMS01ONmZnazM0aTVwNnJ6TVN1ZDBTa0J0SEh4YVR4K0NFL2Zvb212YTRGQ2JVaTZOU0RVVHo0MFBUWUlwcUdrSVRwUVVhWVcwZzNTM3FVWmxReHZWS3ZZVHdVckl4NDZvVG0wdTIxc1k2ckxzWkZyQ3kxMHVlT3FJSmRsQ2JTMmx4WWxMUHhNa0pJeWcrUzlxYWZKUW0wSTZ2ZmY0ajlVSjljLzlvL1ZlTFc4N0liMnQ5RWFDb3dhNS83UitxSWNRZGI0ajlVdTVyZlJRTWQwYU84alA2UWQrMFZFNGdmTXBmUW9tUDFSb25JNnpFeUR5aS9wVFpWZ2hzYjNVdTc5VkFoeCtKa25sUU5WY2NwUXczUEt5R25aQ3drR2RMZFJNaHRzU3NCdDFJUm9BMGVZQS80M0VLWGN4dE4ydUx2bXNTeEdWd0FPbE13eFEwN0x5U0FuMVRMT2VJWWpkWWJOQ2syVjdta0Z0dmtva1BxbjJwNHkvd0F0SzJQQXV6L0djY3NJNlNVWDYyUzJDOHBSc21GTzBtNUpQUXJaTXBZWFY1Z3FXdGlZU0Q1THEyU1BaZnhiR1hNZFBISTF2OUlmM0w2UzdPUFo5dzdLQVkrcjdvdWFOOVFLQm5QRk9hZGtQWWJWVmMwTXRURThOdU9oSytndjBGU1pWbzJSaGpROEMyN1FyR3J6QmgrQndkMVJSczFORnZCNkxUcTJvcnNkcWRSMWhsN3JvdXlGZGlENnA1MEhZK1Nad25DMnUvWFZOMjJLZG9jRUViQVgySkcrNlJ4eVNhb2NJcWNGZ3Rid3FITEpZampCZTRVMU1BNGZDbThKd2xrQUV0VGNFN2I3bzJYc0RiVHhHV1lCNzdYM1MrUDFNa3NoWkdERzBlU2hMUHpCeHl3a0h5VmUwRWdiS3h4K0pnbUdseE95cjVYenRnQWpZQ2JMN1hQVjVKZndzK0hTeHhuOTUwUnFwaEZDVHFBSTM1V2o0eG1LYWNQWnJ1QWJKL0dxREdLb251NFRZbm9TcWNaUHhsMjVwanY4L3dBbGw1SE9iKzRhT2wwMkZjK0tpbU9xZDl6dWpocldDMXQxYk15YmpIK3kvdjhBeVJSazNHUDlsL2YrU1I0VW4vQWFVcE9IM1oyVTRZRk5vQ3QvOGk4Wi93QmxLbXpKZU0vN0tmeC9KYzhHWDRDcjQvOEEvcDlTcGJhNk1HOEsyR1M4Wi8yVS9qK1NJM0plTS83TisvOEFKYzhHWDRQb2Q5NXIvcWZVcVdxUWRicXJYL0luR1QvM1UvaitTeU1qWTBmKzdIOGZ5WGZkNWZnK2hQZTB2K3A5U3NpZkRxRjJsTnRmQVc4SjBaRHhrZjhBZFQrUDVLUXlKalgrekg4ZnlSZTdTL2wvUUw3UVMvNm4xS3VSOEg3SlF3WWZKWGYrUWVORWY5VlA0L2tzZjV2c2MvMlEvaitTSmFXWDh2NkFQcVNYL1UrcFRYaThsTUdJZEZianMreHovWkQrUDVLWTdQY2Qvd0JrUDQva2k5emwvTCtnSDJvdjVuMUtiVEVUd1ZtT2xpZTdoWDFOMmNaaXFaUUJSSDhmeVRkUjJYNWpwOUo5eUkrdjVJZnMvUDhBZ2Z5QmwxbEwvcWZVcEdZVkc1cE5ra1lJdzRqMTgxdWxOa2JNUGNocG91ZHV2NUt5by9aK3puaVZHK3VvOE1kS3hwM08vd0NTSmRPei93QXQvSVI5dEsvOVQ2blBPNFkzcDlWbnUyZEF0b2YyYTVtZlBKVFQwQmprak5pQmZuNktFZlpubU9HWXh1b2pzT3QveVIvWnVmOEFsdjVCcnJpWC9VK3ByWXAyZjRLSTJCZ1d5RHN2ekdUL0FOU2QrUDVJak95N01YK3hIOGZ5UWZabWYrVy9rVDdaWDh6Nm10aUp0bGtVNC93VnM0N0xzeC83RTc4ZnlVeDJYNWxQL2NqK1A1TG4yWG4vQUpiK1JQdHRML3FmVTFnUWdLWGRoYlFPeTdNdit3bjhmeVJHOWxtWlQvM0UvaitTbjJWbi9sdjVFKzNWL04rcHFuY3FRaVczdDdLY3luL3VKL0g4bG4vTlJtVC9BR0UvaitTZXVrelQvd0JQNkEvNGlULzZuL3FOUExGS09FUGFiTGJqMlQ1bC93QmhQNC9rcHhkbEdaSXg0YUp4UGx2K1NzdnBFdHQrSDlCVWZhSmJrdkUvOVJyT0UwcnZlaGEzSzZKUlF5TmhhTGhFeU43UDJmTWV4UFRTNFE2VHhmMHZ5WGNLYjJNZTFlVHhNeTg4dC84QVYvWlhqOWZwbmdsV3o2SHN1bjlVOGFLZmlmVTRiVTByTlBDb3F1bWp1ZGw5RFluN0lIYWpSeGt1d0I0L3JmMlZwdGY3THZhWEhJYjRFN24rbC9aV1NwUS9BYi92OC94L1U0Lzdzei9CUmFTa2pMdmhYVVI3TVBhUTdiOUJ1djhBK3IreXRqd0gyTysxWEVtZ3R5NjRpKzFnNyt5bXgyUCtBbnY4L3dBZjFPVFU5S3pUc0ZKMExiMnN1OXhleFoyclJNSS95ZWZ4L1Mvc29jZnNXOXF4bEpPWFgvOEFOL1pUcWcvNENlL3ovSDlUaFJoQ2lhVy9DN3ZKN0dQYXNQOEE5dlAvQU9iK3lndjlqcnRWakgvNmZmOEE4MzlsVlhpbCtBWjcvUDhBSDlUaFpwSGVZUXBhWWdkRjJtbzlrYnRVakp2bDkzL04vWlNiL1pTN1RSemdUdjhBbS9zcE1zYzEvQWQ5K3lmaitweGQwRmlwc2dCRzRYV3BQWlo3UzJIZkFuZjgzOWxSYjdNWGFVUC9BQUoxdms3K3lsT0V2d0hmZmNuNDM4empWWFR4Mk95clpLZUluNFYyZkZ2WnZ6M1RDenNJY0RiZjR2eVZPNzJmYzZ3dExuWVU3NzcvQUpKN2xEOEJZV3F5UHlaeXQ5SkQrenVsNUlUMFhUSnV3N09NemlQMFlSYmZyK1NUazdFODJNMk9ITzIrZjVLdTV3djdnYXpaWDVNNTBZQ1VHU21OK2k2QkoyTlpySC9oNS9IOGtQOEF6TlpyUC9oN3Z4L0pHc2tGL0FHczJYMFpvZ2lOZ3BDRzYzb2RqdWF2OTNuOGZ5WHY4em1hdjkzdS9IOGwzeDhINFVNOFhMNk0wYjNZRlpGUGNMZVA4eldiTDdZZTc4ZnlSbTlpdWNpQmJERCtQNUxuajRQd29CNU12b3pRMjB3VWhTaGI4M3NTemtmL0FBdy9qK1NLM3NRemtSLzJZZngvSlR4OEg0VUJ2eStqT2ZDbWFPaXlJR2pvdWgvNWljNW4vd0FNUDQva3B0N0I4NkgvQU1MUDQva3VMVVlQd0lOdko2TTUzM0xQSlRFRFRiWmREL3pDNTAvM1c3OGZ5VW8rd2JPcFAvWlIvSDhrYTFHRDhDRXllVDBaejBVN1NwaWtaWmREL3dBd09kbmYrRk8vSDhrWm5zKzUzSVAvQUVVNzhmeVIrOFlQd0lVM2s5R2MyN21RZFJaWkVEejFDNk96MmVjK0UvOEFaTHJmK3I4a1Urenhud2ovQUxJZC93QTM1SWR1RCtZZzltVDhiT2FDbWY1aEdEWGVhNkszMmRzKy93QzZYZjhBTitTSVBad3orNy93ZDMvTitTNXN3ZnpFQThlVDhiT2JXZDZmVmVzNWRNYjdObmFBNC84QVk3ditiOGtZZXpSbjgvOEFnN3YrYjhsTm1EK1lnZG1UOGJPWUJ3VWhwSzZZUFpuei9mOEE3SGQvemZrcEQyWnMvbi93ZDMvTitTcTc0QStGazlHY3lzMVp1RjA0ZXpKbi93RDNPNy9tL0pFSHN5ZG9IKzVuZjgzNUtiNEhQQ3llak9YZ052eXBnQy9QNHJwdi93QU1YYUIvdVovL0FEZmtzajJZdTBHLy9ZNy9BUG0vSlRmQW5oWlBSbk50UXR3b2x3WFVmL2hsN1FDUCt4M2Y4MzVMemZaZzdRSGYrRHUvNXZ5Vm5kQTd0eWVyT1czYW9iM1hXMmV5ejJnSG5CbjIvd0RWK1N0OEs5bFhOcjNnVk9IU01CNTJkK1M3dWdpZUhOK1p3c3ZzZVZrTmtrMll4enZrTHI2bXdqMk1YMWoyT3JXMUVYbllIODExVEtmc2U1WHd4c2JxaW9tTDJtOW5OdmMvMWwzeElvNTRVejRhd2JJMkw0L1VzaXBxU1pyM2NPZEViTDZKN0x2WkF4YkZPNnFzYkVVbE44V2k0QnQ5NVgyRGxuczZ3akEyTURLS25JWllCeGhiY2dMWXlHUkVNaGpheG82TkZrT1Nhcmc3Qk52azFIcys3TWNGeUhUTWl3aW1OUEswV0pKRnJXK1MzZ1RQWkM1c2gxSDBRSEZ6QURheW1ON0xMbGtkbDFSVkVLU25rRWpuM0dueVRqcEdTdUlzYm9MZGxNY1h0dW13ZHJrVkpWMk04Y0tiSDdvVjdLUWYwUmJqdERiZCtxbTAzS1VhQ1V3MlcxdGxOd05ETEczUmhIY0pWa3FNSkRaU3dLQ0dudC83ckJaWlNzU09Tc2h1eVpaMmpBSVJXTlVOQ3gzaENsZ05FM3RXR3RXTzl0NnIzZmVpbGdVWUw3RllMMTdsZXN1S1IyaU92MFVTVVFqWlFEVWFrU2lCY1ZpNk1HYkxCRnI3STB5VUExVzZMeGs5Q3BLTHJMdGcwUkpCVVM1MWxoenJjTExYWFVzQm9DNTc3b3NPb2pkWkx2UWZSUkxpRkxCb0hPWFhRSHVmcFRMMzZpdlNXMGNKaDBTaWM4bnF2VGEyZWFhcDNCcnR3UG9wU3ZCNkQ2S0VLNW9jODdyRDJ1WjFURDdIalpSN2d1SFZRZ0NOeEt4TnVGTXQwb1R5RkdRR0FsSnBEdW1IQWtvVXJ3T2lUSVloQnp6ZFNEcmhUTGh2c2w1WDJLVXcwWUY3ckxyS0JLQzkxaHlrdGpDVDVBQ29tVGJsQmM1Q0pOa082Z2tnZFpNZWlyaVhQdW5wRGZsTHlHelhiZEVHOFBZSUdMdTdtNCtxck1SbExXSGRWZVpjZm13d3VMUU52TmFwVVo4ZFBHNXI5SU51aUp6UUZEK0pFdmVkeDlWVVZralltbmNmVlVsVm1nNjNFRUg3MVRUNWhKSnU1SmxJbEZ2VllxMWhJdXEyZkYydUIzVlBVNG8yVy9pVmRMaUxHRStKVjNaS0g1TVIxa2dYNVNjMDVPOTBtL0VXdEIzQ3JxbkVOWjJLVlk1WkMxZFY2VHloVk9JRFQxVk1LN1QxVUphNEZBMndsa1ExSlc2ajFRWFZMVHlsZmVBNUNsZmU2Q3cvRVErS3pWdGRTRm5xcGlsc1U1SE5zdXRoVU5HQWVuMVVIdEJDRVpQVXJ6cEhBSUhKaHBHZTVEa0NTa3VlRjQxTG1xYmE4Z2JnSVd3cUlpa2pQTFZnMEVaNktReEFYNkxFbUlzSTVDNnBNamlnTHNOaThoOVVDYkQ0MkRqOFZHYXRhNi9pU2pxKzVJSlRrd0draVVrTEc3V1NVMU94eDRSblZvUFZDZFZ0M1RVRHdKVkdIdHRza25VRHI3Qld6WkdrOG92ZVJodlJkVmdGRWFKNDZMM3V6aDBWdytxakcxaDlFQjlRM3lIMFRFR3FLOXNMdkpFYlNseU9haHZwOUZqM2tCcFJLd3VDTWRLWGJYSDFSVGh1cHZJK3FTOTRJSlI0Njh0RzVUQTZRT1hDamM3SmQyRXU4bFpOeFZvSFJZT0tOdndGQ1VpcWZoamdPRUk0ZThkRmF2eEpwNkJDZFh0STRIMFVKU0tzeE9BUTNSa3A5ODRjZUFndUYraU1DaEF4dXVzMklUdW4wWG5STkFSb2xDQkJXRGROUDBoQ2NBVXhFb0dUc28zOVY1eXdHRWxCWjJpWVBxcEFjTEFnSkYxNE5tZTdTeHQwRFlhUks0SFZTRHdlTjFjNFRrK3F4VndEbU9BUFVMcE9WK3c2a3F6RzZva2xhTDc4L21nc0pJNURCQlVWTWdiRkRJOG45bHBLM0hMM1kvaStacEkvOUdrRFQrMUdRdnAzSzNaNWtyS1lqa21xZGJtZ0U5NUdEKzhyZFg5c3VUY3FVK21sTkk1N1JZWGlZcHVPUEdhSjJUZXlrMHNoa3JZV050dWRSQVgwZGczWnZsZko5SzE4aGhZNWdGLzFyVjgzNW45cjJyWnJpd3FHbUxUc05OaCs0TG5yKzBUTjJmNVhSdjd5TnNoLzFjcmgrNEx0MklsQSt5TVo3YWNCeXRHK0trZnFjTnZBNi83bG9GWjJ1MW1iS2x6WU85RFhmdE5LNWZrYnNhcksyZHRUWFQxVHJuVVE5N2lQeEs3eGdtVDhPd1dCamJEVVBOb1VGT0lubHJMazlkSUphaXh1Yjc3TGRHUXdZZkdHQnB2eHNnTXE0WUdnUkViZVFRWHl6MVRyQnR4NXFDOXdXYVlkRHpzcFVtR052Y04zTzZab3NIZEtBWDNCVjlRNFozRmc0S0UzRmZEUTZXZUxqeVZKamRDeHhPZ1dOK3EyakVuc3BXM0JWTUkzNHM2elJmNUtFM0g1TzR5MEdZYjlFbzR1YXh0aGRPNDYxc2NvdDVKSU9rTEJwUDFYMjlObnduSkxmd3drY3BMTjQxTVBkZmxCSHZJYUxQRmt3MWx3TDhvMVozSENFZVNiWE90eWlOZTd6VVdNUldzc2k1SmsxenhjSUkxeDgwVnJqNW9iV29yQUZZVVN1NW9JMXh0eXB0Y2ZOUURWTmpiSmlnSWxrUWRoTnVVWnZ6UUdXQ01DalVDdThvWVBQbWl0SjgwQnU2UEcxV0ZqSzdtRmJ6eWpDWWJiSVlac3N0RGZKT2ppSzA1akRaQjVJclgraUN3TjhrdzFyZkpQV0lxdktOVWRUN3ZNMDJWblZWb25ZMFdWSG9lK1J0aUxJenpKSHAzVnRab0xpaFUzd015U3VqYUNMOHJwSFo5MnF4WmF3bVNocWFYdmk5MTd1UHo5ZlZjM0FmSkVMbFNEWUpKV3VrYVNSdHNueHpROUNoT1ZGNW1Hc2pyc1NscklXQ01TTzFhUWtZSHVubEwzTnNEMVM4N1h5NkJFUUdEb1V5NTdtMDdXc05uWFQxbWg2Q2xOaGhLUWJXUldTbnlTemU4MjNSV2gvbW1MSkQwSTg3R0d5bnlSVzFCSDJVczNYNW83U1QxVEZPSG9WNWFoakVjNS9ZUjIxRmg4Q1VhNGhFRWpnalU0ZWdoNmxqcmFyK2lpTnFmNktVYTV4dHVpc0pSU3dxK0N0RE8yTXRxUDZDaytjOTQwTmlzVDVJSUx1aFRHSFU5UlBpRVlMZ1FVYzhhV04vb1RIbGJ5TDlUNkQ5bS9ESkpzVEQzTklHb0hmN2w5dE4wMDBBQWVBdm1YMmVzRE1FYlpIRGV3SytqcEFIeU9CRjdDNitKKzBXUnh6UGIvQU00UHRuczdqMzQwMzZQOXpXczdZazFrVGdEMFhITVpxM1BlNGg5dDEwRFB0VTF1b2I3QmNzeENYdkhXSDBYaDQ0OGpmYzlqNGtQUUxoa00xVlVSZ1NtMXd1KzVLb1gwdEd3dTMyQlhLdXovQUFKMVpJeHhhYmM3cnVGSEM2Q21hMFdGZ0Fya01XVDFKNGtQUVpiS1h2SVhwSEdOeFFtTmMzVWJoQk1qNUpIQW5wMVYyT0dmcVR4SWVoaWVZZ0hkVnRWT2JIZEVxM3ZBTmlGVVZFOG0rNmE4ckRXV0hvSlZ6M3VjN2NxZ3J5WW11T3RYVlJLNGgxM0Q2cldjVm11eCs2clR5c3R3bkIrUnJlSjRvNk9RanZMYm9OTFhtVVg3em90ZXpEVWFKQ1FlcXJhREZ5d2dYVldXVmx1T3owTG5IS2x0UXh4MDhiTFFjVHFTOTdveHN0cnhYRUltUkVEY2tYMldwVE1hOTdwTGVxejV3eWVwcTRzcmZCcjFYRzZtSmNYK2lwcW1WcHYrc0NzTXlWZnhOQldweVZEWFg1dXFjb1pMN212aWJhR0pualVmMWlFSEN4L1dKWWxoTzZ4NExGY1VjbnFYRWdva3VmNXhFYTRIL1dKSU5ZT2hSRzZQSlYzQ0lTWSswamJ4cHlPWTdlSlZMZE54WUZPc05ySmJqRTZXa1VwUDJrMHg1L2FWVkcrMWsweVJBNHhKUmJzZi9TVE1iLzZTckdQMkc2WWplVUZSR3NzbW0vMnQwYUYyL0tyMnlXODB6SE0zYllvMG9pWkZnSlFFeEZVQ3lyTzhhVVdKMStBVWRSRk10NFpIRXBvRnhWYlR5UHVFL0hJOGpsVmZDUnhySDZERVlkc3JLTTdEWlYwYjNlYWRpbk8yNm5oSUJySDZEalg2ZnNxWHZOajhLZzF4STVVWFg4MVBDUURXUDBHR3ovMFVaazQvWlNRY1IxVXhJNGNGRnZZZmpENG5IN0tNMllIN0tyUkk3elIyU3U4MU43SjR4WU5rQit5aXRjRDlsSlJTSHpUVEhub1ZON0o0d1lOSDdLTkZZSDRVTVNuWkVZNG5xdVJ6TUZwRGtibTdlQkdjMklpN1dpNlhaY2kxd3BDUHVqY2xXMWtiUXQwRWEvUjlpNjg2Y0g3Q0l5UnIycUVqU0hiRkM4akYyZzFPWHU1Tmtkb2JHNjVzVUpwTEFOMUZ4TGpjbGM4Vnk0T3l4cVBJeE0vdk5tdFhnTEFLVkxPeU1lSWJxUklLSlJ2a3J1ZEdCeXNyQldMbEhlME5mRVpQQzh6bFp0Y0tRWmJkZHNnZGxyTHdJdWhoeENJMk1sU3dHTVJBRk1OQThrQ0tNaE5NaTlWTEJNaDFsblhkWTBMSWpLYlpDUWZzb2JLZWhSN3RTd1dRSkFXTlE4MWwwYWdXRUtXQVRYbEc1WHQxeXp0RWxJQkR1VklPSlJKa29tU0FQUkRjOEtMM29Mbm02T3lVRnNzRnFGM3l3Nlc2YllOR1hOQVdXNmRrRjBxbTBlcWxnTUlkTmtOMmxTTGR1aUc1dnFwWUxSNk5tb3FUMml5OUNSdWd2bE91eWNDZTBXSzg5dHdwdU4ycURYazdLRUFhYkZGYTRBS2JtaXlFNzBLaEFVcmJYU2NnM1R6dHdscFdBQlJrUXNTbHBtbzBqckZMelBTWkRFQUxlVXZNM2RHYy9sTFRTWEtTdzBRTGtHUjZtU2dTRy9WSVkxRVM3bEJjNVNKNTNRWE85VW1USHhSRjcwRnh1Q3BQY2drcExrTlNLZkZzR2h4QmgxdEZ6NXJtV2FzcW1uRGpDMzZMclZRN1kyVkpYUk5tQkQya3BhbTJKbzRLNmlsaWM3VzA4ZFZydGYzckM3WWhkeXhMTFVWUVhGclZyTmJrNk9RTzhJdjZsR25aS09UUnpPdVE0bFJxQXh3dnJDM0hGTWxPWVNZMmo3bHJGWGxpcWpjZkRzUFJIdHM1UlExVXJnYmJyTWJDNWx5bjVzTGNIQzROMTZhbDdxSDdsWG9Yc0t3eGdrN29Fa1JUTUZ5ODNCUkhBT1F0QnFBa3hoQ3k4Rk50akN3NkxkQlFXd1RiQVJ1cFdJVG1rV3N2ZHlEMFF0RGJFOVRnVVIwMTI4Sm9VcmJjajZwY2hvSkNCb05NWGViOUVCeFBrbkh1WUFscEpHamhEUVNZczhHeVVtYkowSlZpMXVwU2N4b0c2NmtNYktCN0piOVZCd2NCNnE0bDBEb2szeHRLc1FRaVRLaVo3bSthV2RVUHYxVnhMU2h5WGRoK3JvclNqd0pjaGVPZTF0MFV6M0hLaS9EM3Q4a0EwOGdOcnFLSnl5VDMzUEtnNTU4MTRRUFEzWDhpalNEVE1Pa04xanZENW9iaVFlQ282aVVTaUZZYlUxWU5qMVFMbTZrMXg4MXdiWk1zOVZDM3FwNnJoQ3Y2cUhiSmFmVlMwQkMxclBlRlFtNG5ZQXJ4a2EzeVFYdnNPYkpXU1cvVkdpRFVsUzBYc2s1YTF4dlpESUpQS0kybkJDTkVGalVQY2VxSkdYR3lZRk1QSlRiR0dvMFFpMm5Ma3hGUzdySXFHOEJGWlU2ZWlVdzBoaUtqR3l1Y05vSUlwV2x3YWZtcVZsZUFPVm1YR3U1KzFleUJoSTZ0aGVJMGRIQUxOWUNBdlZHZW5RYW14VGFOdWk1Qy9NVTgzZ2lhOXg0MmFTckhDY3Y0empNalJIVFRIV2JmelRrTFladEZmbXlzbWNiNGs0ZzlQOEJWN2FTc3hxUUJsUTZTNjZia2oyWGNheDk4VDZtSHd1c2JPYmJuNXI2RHlWN0trR0RpTjAxTzNWNWdoQUxlVStlTWg5azFSV09qZk5FWGk5OXd2b3JKdlp4QlJDSWlpYTBnRGV5N0pnZlpKRGgwVGU2WTFnSG1RdHJvc3V3VXdBMDdqMVJvcnl5blBhSEwwa1RHaGtaWVBSV0l3Q1I0QWRlNTgxdm5kUVFHeGFpT05HVzN0djhBTkdWcFpUVHFYSmJta09Mcmc3cStvOEFncDJqVzF0L1ZPSEVlNHZkd3NPTEZWV0lZL3F1MWdjU29Mc3NwSTZTRWJPWUxLb3hIRTJocDd2cDVLdU5QVjE3dFRUWWVxYVpoVzRhOGo2cUVzcVd0bnhTZlJ2YTYzUEFzQlpoOFlkSUFUeHV2WVpoTWRJQkpiMTJWeVhtc0dscWhMUHhWeDRmcmg4a2dmZ2I4bFk0NlAxdytTUkk4RGZrdnQ2UGlMTXgvQWlNVVdEd0lqUmV5ZEVWSUl4R2FFTmpVZHJVeENXWmFpTVVRRVJvdW5JUXlZRnlqTkd5RzBJelJkTmlWNU1td0lvRjFCb3VpdENjaXN5YlJ3ak1DaTF2Q014cXRJU3liUWlOSG9zQnFLR3AwU3ZKbVdDM1JGQVdHTTIzUlExTlJXWmdEY0l6UmZsUmExRlkwcGlRbHNJMEd5STFxdzFxS0cyVm1LSzAyWmFDaWdLTEdveldxeEZGZHNtQnNpTUN3RzJzaU1hbnBGZFl5VFJkTXRpamhiczRrODdvUVowUld4aU1ndmRjSnlSU3pSbzh6ZDE3YkpodzEyMGdMMnFPUnRtMnY2TE1ONHZpR3lha0JpYUpOSENLMEtJQ0kwV0N0TDdqS3JmeGt4d3JqSzBCcWNSakhPNnFMYkZiTjJkUjk3amtMU05pNytLcmFxVmFhZjZNdGFSWHFZZnFqN1k3RU1NOTN3cGppMjEyZnhYVzc2WFBOdWhXamRtZE9LYkJJQ0JhN1A0cmRudkRZbnVKNkZmbnpXNUU5WE96OURhSEcvZElVY2w3U2FzUnZmOGl1ZFlkVE9yYXhwRnlMcmJPMHVxNzZyYzFwNkZZeVBncG1jeDViZnFzYUs1TmxIUzhpNFlLZWtZZEFCdDVMYjNHd1NXRVFOcGFab0FBVGJ5clNUT250V3lYbE5yOUVhNlhtZHlvNHNnbE8wbTZxNnVFa0ZXc2prcksyNEtKOWlJMWF0cDNBazNLMWJHSlBBNFhXK1ZrSUxYL0pjK3pFZTUxcXZKbHpFYyt6RUwzSzFpS3I3cDlpdGl4cWJYcUMxZDhONUZYY2thK09QQTQwdXFOemNoVitKMVFoWVdpMTdLeWllMkdFOEtocm5kL01mSzZweUg0MXlhcGl3ZEk1eEtwQlMySlcwWTFDSW1HM0sxaVNVaHgrYXFUTm5FTFR3S0VjZGtWeEwxNFJrS295OG1ETFZtTnU2TG9VbXNRTUpCb2JXNFI3ZzlFdTAyUm1iMlFob014cWFqQjJRWTI4SnBnc2hEUVNOeENlZ20yU29qc0FVU051NlNBV0xKZ2VnVERkeHdrSXh3blluY0tFb0swYnA2bWVCMENSMWhHaWQ1S0VvdFluQW80YmRKUWc3SnBwSXNnc1cwTnhSWDZsTndqY0pLR1FwNkk4S1dBeHRuQzg1cFBtc1J2RmtZV0lVc0JvZzI3dGtWc050MWtNRFZrUFFuU1FlR0lnY0VMUVhJZzJDaEFzYmt6RzVLTVRNWUtoQjJNM1JVbkhKdWk5NmhRSTVHNng1UncrNlFpbFRJZHdqUURHR3VVOWFYYVZOcHVqUUF3MjZNeERZTDJSbUFKaUJNMjlGTnR4WllVMnZDTk00RWJjck5sbHJoWlpMaGJvaU9rUTVHajNTd2FicG1GcFJXSkdtTkI2SStrVzRVSW1vekJjbzB3R1JERDBSR3huMVJXTVJDQTFIWUpodE9XV0pVKzhBRmxBMU9yWlF0ZmRTd0R6eHIzQ0c5RTFhVU42bGtNTjVYbnJ6ZVZsNmxrSU5kWkUxaTNDam9zdmFWTEJJdWRkWnRaWkRMbFpJNktXUUE5RGNFWndzaGtLV1FCSkdWRnJMZWFQSTdaQ0J1VUtDUE9hbzNXWHVVWGNKMFFTV3UvVlFjMG02d2l0NFRVQ3hlSXVVMkM3dDB5eGpkUFJBY0xQMlhVTER2YTBOUW11QktoS1hXVVk3dDVSSWg2ZHBQQ0F4cEhOMDViVUVDUnVrcGlJQkxQVW9FcmJEbEhjQ2xwdFNqT0lXa1lFcEtiRW84aE4wdE9MQlY1alVCZElFck8rNUtrOGxMeU9WZGpVaURqZEFrTmxNdVFubTZTMk9TQnZLWDFjM1IzOEpjOHBMWWFNT095QzY5MFk4SVRpTjBsaFVBbklCU2RhOE5pSnNPRXhVQThwYVMwa1phVkxPczFHdngwVTBwQkErOVZXSll0QksyNGR2Ym9yTE1HRWE5Ym04MlhONjZLcHBudjFGMWdUeXUyQXpZb3NaaWpjUTdTZm1GS29tcGEwSHdzMzhtaGFNK3BmYytMZFFkaU0wUER5cFl0b3VjVXdLTU5jNW8vQmFkaU5LWVhFVzI5VmQvcDU4amJQdjk2cXNRcldTWDRTenRGSEpUaDk3QzN5Q1hGQ1l5U2JwNFNBdTJLOVZUTkRkcktCb1NOUGZ6V1d3NmZOUUZUWXJ6NmtXMktnVkJRemRUN29PQ0IzdGh5c3RxYmRWVW9aWmw5R1hYSUpTenFkM2tuQld0SGtoKytOdndGS0RURUpLVjQ2SURvSE41Q3NwYTFnSEFTRTFjMjlyQlNnN0lsb0E5VUNSVGRLQ09VdkkvMVRGRXIyUWtJc1ZYdkxnNHBwNy9WTHZsYjVKMFlzQnNHSlhOTzRSbTFkaFlnZlJKVFRnZEVwSlZrSnFpRFpaeVNncGR6bWdxdU5XVDFRcEtzK2Fjb2hXV3dtWVBKUWZNd2pnZlJVajZ0MStTaEdyZjVvbEVsbHRLNWg4a282MTdwRTFidXBVVFU3Y28xRm5iSFhTRC9BUXpLRWw3emM4ckJtUktJZTRmNzVMUHFCZmxLdnFEWktza2M5eFJVRFpaaW9BNnFYdlFWZVE0ZFZKakhPNnJwd1ltZUg5VmlHQnJ1WEZRWXdua283V3RhTjNnSXRnOUV6VHhBZkVickRSYmpkWUxXdTM3d0xBckl4c0xFaExhRFFSejNqWUJROGJ1UnNoR2VXWjFtUkYzeVZ0aDJYY1JydEliVHlXZHR3ZzRRUWc0UlFDN1hrbnlLZ3lTZXBkcFl3RmRheWoyR1YySnZZWlE2enQ5eC9jdXlaWDluR0dNc01yR241Z3BmaUlKNWJQbGlneWxpTmFXNlluYm0yMTEwRExQWUZpV05UUmlTR1N6dks2K3hjQTdETVBwNDJYaGp1RDVGZEt3SEl0RGhoWVd3czhOdk5BNVdWcFNzNEgyWCt4aFN6ZDNQVnNsRzF6ZHBQOFY5TFpZN0RjdFpTZ1kwd1JPYzM5dUZxMkdpbGZTUmhzTFMwV3Rzbld1TSs4MDJuL2lYTEs4bTJIZ29xQ2xhMFFVOExRTmhwakFVcGFyUVA1dGdIb0FxMnRyNGFGaFBldGRaYXpYNXhhU1dOSHBkV042S3l4eU5wbnhTRnQ5VDlQb0ZUVldaQXdrTUlLMTB6UzRnNjRrTFFVL1QwVVVkakxJRDgwdHpIUmkwTU14aWVwY2JORmtSMGMwZ3ViajVKV3B4dWh3NXUyZ2tLbHFjNnRlU0kyYmVpQnlISm15Q2pEaGVWN2dQbWd6VmRCUU51Wkx1L3BCYWZVWTlWMWZoWUh0djVMMUhsK3R4T1FPZk00QTlDZ1VqclJmelp5YkdTSVdzSTZiQk1ZVk5QakVvZTRGdS9STVlYazZHQnJlK2MxeDlWc2xOUVFVVFIzUWI5eWJGaVpLdzFEcmpqRVpIUzI2ZVlUUmVJQy96UzFQSTJSMWdCZFJ4REZJS0J2NjV3QS9wSnFaVmVOcy9HUEhCZVVmSklFZUJxdGNaM2xHM1JWaitHcjdna2ZGR1pZUEFFVnZSUkkvVmo1b2tYSVRVaE1tVFlqc1E3SThmQ2FrS2JNamxFYUxyRFI2SXJBbXBGZHN5M2hIYjBVQVBSRkE0VG9vcnlaSm9SVzhMREVkbzI0VGtpdTJUYU5nalJpeUd3SXpGWlNFTmhBaXRDaUFpeGhPaWl2TmttalpGYUZCRVlOazFJck5rbWhHWUxxTFI2SXpFNUlydVJKb1JnQnNzQUtRQ2ZGRmFVaWJSWkZhRkJuQ0swS3lrVjVTQ0J2Q0swV1dHamhGWUU5Q0ZsNFBBSzl5eGxtWE1wTEFXbDE3QUhsVTdSNkxjZXpPcy9SK2JLTjNMTDNJUEhJVE9VdURKMU9ma3A4ZHluVVpibEJrWVdnbnlWZUpSVU1DN1oyM1RNcThOb0h0aVkzVU9XdEE4MXhPRmdZd010dUVXS1RuSGMxUlRobmFKZ1dSV0tJYndpTVlydjhESHAvR2lZSFJiajJXMC9lNW1wV2dYOFhUNWhhZ0c3TG8vWVZDMy9BQ3dveTdmeDlmbUZuNnovQU9tbitqTmJRLzhBMUVQMVI5MjVJb2hGZ05MY1dQZDlmbW04WnF2ZGFSNXZiWW91RFEvOUhVbW5ZYWVpcTg4TUxLT1Fna2JGZm5IVXR2VlNaK2p0RWw3bkE0bG1Tck5iaXBiZSs1L2V1b1pFdzVyS09OMXJIU3VTMGRPK3V4M3FScUkvRmQveXpRaUREWWJpM2hRUmlXeTNZTkxBcHVJUFZlT2tzdGREa1l5UGRyaVNyYTRJVFFKbEpzcnpzUnNveXkwa2JTWlpDMGpkQzVJZ3RKR1NPRXZJMndWZGltZXNOb1dPREpta2p6c3RGeGJ0U2MxenU2MEVmY3FyeUk0b3MzZXNMR2gxM05HM1VybWViNTJBUHM5djFXdjQzMmlWMVlYYUFBUFFyU3NUeG1xcjdndU8vd0RTVmVVck5ERXFvTmlVb0wzZUlINzFSVFZXbC9LV3FueXhnbHhQMVNEYWdQZHVVaDJiV09xTGg4am5pdzZvRDZjTkJkdGY1b1RNVmExdHJoQmRVOTg2NE95Qm9aalhKV1lyR1p0WGt0V3FJdEpPM1ZibFd1QWFkbHI5V3dHKzM0S3BOR3RqN0ZRd0M1V1hPQ2srRTZqMFVDeXhDcU5GdE1JR0xKRmtVTnVBb09qdWxNYWdYVk5SQWJKY3hGRmphVUl4RDBZc0VRT3NVS0Z1d1RMV0lRa0dqZmUxMDFFQVVxMkxkTnd4ZXFSWktERGJoRWE2eTgyTFpaWTNkU3lVU2E4a3ArbmJ0ZEpoblZOd05LbGtvY2huM0EzVGtiOVNUYTNqb2p4SlZpcUxHSUFoRmE5S1JuWkhpVXNGb2RpZmRPUmsyU1VidzJ5Y2hrdUZMQW9LMStwRWJGZFFieWpORnd1Z2toNGRsUFNvYUZOemVGQ0UyTVRMR2dCTFFtM0tLNSs0VUlGWXpkRTd1NnhmVmF5TkQ0ZVVLQk1SeHB0cmRrTzJyaE14RGhHZ0dZRFZNQkV0NktURzM2STBBVFp2Wk1NYUVCa2RpbUk5bDJ3U1JVV3hFb212MFdXc043bzBReTJJaFpFSnVpdGJaUzRSMlE4MlBoR2paWXJ3NENtMExpWUZERE5naXNGeWdzNFJnNnlOTUJvTzAyQ2c5MTBQV3ZGMTBXNENpYllnM2ZaVHVBRXZmNXFiVDgwVmcwZWZ1VmgzQ0lOeHdvT2FwWktJdDVXWGNxTmxNTlVzbEdITzJVTmFLNjNraDI5RkxBSk1lcEhoZWJZZEZFeTNVc2xFSEJEUEtJNDM2S0JaZFN5VUJrRjFGck4wYXk5WkVpQW5Sb1hWTkhoQ2VFNklMQmFiS0pjUWpEbFFlRTFBc0pFMnpiM0NnNGVKUkFQbVVaalFRdW9XRGtlTmxHUnVteFU1VzdvY3p0a1NJZVk2M1ZSbHNVRnJTVDFSVEViZFV4RUJ1ZUFsSjVBaVNDOTBySXdvV3pxUXRJKzVTOHZpQ2FjTEJKVEhsVjVNYWtMeU1za0tqd2twdDd1VXBNcTdZNUlYTHZ1VUNWaVo2QUpOMVZiSEpCaVVJdFVYeUtMbmJKYllWRVpUWWNwVjc3RkVrTjdwWTlVSWRCaUJJemRJU1JrT05reVpRVWFOb2VPRU5nOXltcktUdkdtNFdtWm13TnNrVHRJdWJMb1ZkRFpyckRvdFJubHU5elhiNzlWTE9VY2hyOEtmVHl1SkZoZFZVNTBteEs2Rm1xbkhkRndhQjl5NXRLU1ppRkxKdEkxQkduWlUxWUhDNXVGWnkxR2ticW54RnhsYWJMZ05GVFZZb2FaeEYwdU1ZTXZKS1Ryb0g2emU2VGM0TTlGQXFMV1RFTGNGRGJpQmQxS3JtVEMrNVdYeUMyeFVEb3NtNHJxMkpVLzBoY2NxZ2tJWmMzS0dLenBkTDJpMVpmT3hFM3RkRWRYQURsVVRTWGk2Z2F3dHVDVk5vU3N0WnNTRys2VGZYZ25sVjhrcGxVR3N0eVN1N1ExWTZjWFBGeW9PeFcvVkl1QUNDOGdKNmlMb3NYWW56dWwvMGdDVWk1NHNVdHF0YzNUb3hRdHBscStxYTRKYVNkcHVxNlNxRGVxV2t4QUEydW1xS0JvZmZVV0tYZFVwVVZaZDVJVXRRVDVKeVJCOFNnaERkSVBOSUNaMTE1NUo2bEVva0dYejI2b1RxbTZFMXBQbXZPYUFqU0p5Rlk2NTVSTlhoNVNwSWIxUXpVbTlnaG9KTmg1WGJxZEs0WDMyU3dlWDJLUEdDL2JoS2NxR3hqWXhMT0doQ1pWK2hXZmRDODdYVnBRWUhMTmF6TDM5RWx6UTVRS3p2M09Hd0tIM0ZWTzRCalhmUmRNeS93Qm5ic1FrWUN3NytpNjNsYnNUcHlHUGtqUG51MUxlb0hiRDV1dy9LMkkxYm1nUXZPbzIrQXJvK1Z1d2lyeENSaGxpc0hXTzRzdnFYTC9aMWhPR3h0MXhNTGg1eGhiQnBvcVlBQ09OZ2J0Y05BU0paMkVvSEdzdWV6aFQwN0dQbGpZZHIvRUYwWEIrelhDY0thMXJvZkVQSWo4bGNWR1lhR2thYnphYktnciswVERxYlVmZUJjZWRraDVtSHNPaFlEaE5OUWhwYUxBY2JyYnNQZkdYZ0FnRDFLK2JKdTNhR21jUTJWbGh0eUVML3dDSXdSZ2hza2YxQ0ZTWnp3RDYyZFd4VTBmODZ3ZitvSUgrVVVVVzc2aU1BZWJ3dmpyRXZhTnFINmcyVnR2K0phZGpIYlZpT0lhbXd6dXVmMlpDbXBzSmFjKzVzVDdZTU53U0k2NW11SUgyWExuZVBlMHBSbDdteFBmZnBhLzVMNCtkbUhHc1VkZDc1QzAvL3dBaFZyaGtHc3ROUkkvVjZsR21GN3NqNlNvZTJPb3hlU3pwSEZwTzF3VnMxSGo4YzdCSTUyOXI3bGZPOUJqY2RDRytJQzFrOC90Qm1zSTRuQTlPVUc4WTlQRStnSk05akR3UTJVQzNxcWVwN1VwYWdsckpDZW5WY2RwNml1eGdoeExnRDVPSzJQQThFa2hrYTUyby9OYzNNUzhLUjBDanhLb3haMnA3dGo1cTdwMncwb0JlUnQ2aGE3U0YwTVFBYlkyV1gwbFZWdkduVllub1ZMWlhlTkkzV254eW1hUm9CdUZmWWJtbHpTR3MxRDdscTJDWlduOEdwcmpleDNXODRUbEo3QUhGaCtpSkZlYnBGcFMxMDFhMEV1dDgwMzcvQU82alM1MTcrU0UvRG54dDB0RnZrdGV6TFVQd2VGMHJpZGhmZE9qWlhVazJYMVhtR0xDNEgxRHBXdHNMN3VYenIydjl2V2lvZkRUMUdvaHdObW0vVmF4Mm45cmNrcktpbGptMGtlSHd1c3ZtR2ZHS2lmSHBaSlpYdkJIRG5FK2FhckxzTVc0MWpHWGZyUjhsWEhmU1Uvakg4NEVpT0dyN3VqODlNTHAvVi9laVJCWUkvVmhUaUNhaFVnaU5HTmtNY0kwWUNja0paTm9SV2k2aU9pSTBKcUs3SnRDSzFxZzNoRmFFNklpVENNQXNqdENGR05rZG9zVTFGWnNrMEVvN0dvYlJleUt4V2tJYkRNR3lMR0VPTWF0aHVqTkdrMk8zelRvbGVUSlczUll4MVViSWtZVFVpdTNaTm91ak1haHRIQ013SnFSVGJDTkd5S0czVUdoSGFGWWlpdEptV3RSQTJ5ODBYUlFGWlNLOG1TYU5naXNhb0FEWkZac25vU29jRXh3cjNLVlUyaHI0NTVDQnBQSlZJTmhkRklkTFNQTERZanpUVWpMMUdLenJYYVBqVlBpZUM0Y0kzTkpEZDdmZXVUd05QdmJyOFdSL2ZwbjByV1BkY01DeEJhU01QSEo4MHlFRkJVaXJqd2hBMUVZQWhYSVJHT1RsOXhqdTAwRnRzVnVuWTlXKzZacHBYSGF6djRyU2dWZjVLcURTWTdBNGVmOEFGVnRWRzlOUDlHYVdpbC81aUg2by9SM0tOUUt2QnFSM1BnditLVDdRQm93eHg4N2hWL1pmaUJteTlTRW0vd0NyL2lpZHBkY0c0VXhvUGlMd0xmZUYrZDlSaXJWU3MvUm1pbi81U0JvR1RjRUUxY1pDMi9qUDcxMXluUGRVeldEb0xMVk1rVVFiVEY5dDczV3lzbjB2ZUNlRWlxTk1QRVNUdWJJTlhWUjBZTG5TQXFweExIUlNTUEFkMFdpNDdtT29jMS9qdUVFcFVRM0RGTTd3VXNibWkxN0xsbWFPMEdaOHpoSEtXdHYwSzF6RjhabW1rY056OXkxNnBvNTZ5NXRhL21xRThqT2hNelp6REdFdG0xRzE5bHBUODdUVHlhR3NjNjVWcFY1VGJJMXpwQzA3K1lWUkRobExRMVFHanIwVkpaR1c5aU51eTFTVldMbHBMSEFGYmRVNVFkQkdIR1BlMTBsbFRHNHFDSmhhZElIcXR6ZG0rbHIyTlpmZXdIS2RHVmpZS2psV1lNSGZHMCtHMWxvMHpUVHlFRTJYYzh3VThOVlN1Y3dYMjZMaW1ab0RGVU90dFpQVWJOR0VpcmRLUS9sV2xDUERjbGErSnlYZ2JxMnA2alRFTjdiSkxMMEF1SU91VFpWTTR1bm55R1Z4NnBPcTJCVlNacFFFSE1CS0RKSHVqRjI2OXAxQXFxeXdoY09VbXVXZTZLeUk3S3N5eWpOOWxoaDNVZzBvcll1RUlhQ1JPc0V3MlZMaGxsSVhCUWhvYlk4a3BxRjVTMGRoWk54RGhWYkNHV1BLWVlBZ3N0WkZqS2xrRGdCTlFEaEtOSlRVQjRYTElOaHFtellxSTRDbUFsV0xvWmpLYVlOa2xIZlpQallCU3dXandjUVFuSUhIWkpOc1NyR2xZQ0FwWURRd3duWk1NZHNzc2hGaCthbjNRQVRSUmdQc2lBM0NFNXRndlJPSk5sQ0I3MlhnYmxSZHlpUXR1UW9RYmc5VVkraURiVHdqUStMbENnUXNLYWkzS1crSGhNUWNoR2dHTkJ1eW14cWlPRWVNYkkwQVlhYm96QmRRRWFLMDZRdUFtZENPMjJ5QVpGNXJ6ZEVpRFFXSEtMWFhVdmlSMlF5Sk51RkpqMWdSM1VteGI4SmFad00xNXNwNnlvdGoyWGdMSTB3V0VEbGtFbFlhTHFZQ05NQUlBcE41V1J3RmczdW1XQ1pXVHdvWFhpNVN5R2RsSVdzVUs1VW11VXNoN3FzN0x6bERkU3dDUlVDMnlJMGkzS0M2UzZsa1BPS0daRms3cUJhcFpEM0s4b1g5Vm0vcW1vQWtvUFdickQwNklMTU41VUhxYmVWRjZhZ1dETHJJakpka0o3VmxnWFVMQ1NPUTVGTnpVTjV1aVJDRFhXWG56V0N5MWdLaEpEZTZORUZ5VU9RaXl6SWJYU3NraENXeGlJU202cjVqeW5YRzRLUW01S3J5R29XZVVwTTVNdlNzeDNLclNISkNzelVzUlpIbWVVbzU1Vk94MUhubXlnNlZEa2tPNlhNcFVDUVo4aUE5K3hRM1NFb2JuOHFJTkFUUForNmZwS29FY3FucVRwdVVLR3NMVHpzbFdKUnNWUTlzZ1BxdFF4cW03aVF1SHpWd0t3bnFrc1VjS21JbmtxV0dqVWNYZ0ZSU09IV3k1Vmk5TWFXcGR0c3VvMTg1aWM1cDJIQzBuTWRNMlhVNFdVc1lrYWJVa0VKWU1hNEc5a1dWcExuZk5LU3VjeEVKb1VyNk5qZzYxcnJXYXFqY0wvTmJMSk1YM3VVbk13T1VDU05WZkRJMDlVSjNlRHpXek9vMnV2Y0phYWhZTG4rS2dhUnJzb2U0ZFV1R3VhYmxYY3NMUmRKU3dhanNFemc1dE1RMVFZTEZRbUFPNFh2Y1NkMUlSRTdGU2dsRUhFd2txY2tUckd5bGZ1MGFPVU9iWXJ0QjdTb2M1MXlFTXRjVlp2Z0Z5YklNalExY1RBMmxlNkkyS1JlSDdxM2M4QVdRREVEdllwc1dDNGxIUEc4K2FyNVlKTDMzV3pTUXQ4a3RKQzNmWk9UQTJsQ3ladzJzVmwwcmowVm8yaVpjbXl3K2piNUp0ZzdTc1pJN3lXVE1WWWlrYUJ3bFo2UzE3QkdtVGFEam44MWg4aFBSWmlnTitDbkcwZXB2Q0pNNXRLNE5lODlVeEZSazdsTXRqRGVpWWlIR3hTNVNPeGlDaXBRQjBScGFjc0hoQ2NpcFMrMnl0S0xEUk1SZFVza3k3amdKWUhoNW1sR3NiZXE2bGdHSDBjTEdGNFp0NXJUV1JDaEEwZzM5RXhGaVU3eFlYQStTcFNtWFk0enMrSDQ5aE9HQnBIZFhBSG1uNSsyR2lvbzlNZW5ZVzJLNE8rQ2VvNVBLR01BZkp1NHQrcUhhSHNPdTF2Ymc5eFBkdU52UXFncisyV3NtQkRkZS9XNFdnbkE0NHR6YmIxUXpGRXpZTUp0NUkxanNOUVJzRlhuL0FCS3VjYlN5QUg1S3RseE91cUNTNnBmOTZYaDA4TmFSOXlLNm1tZnhzUFZHc0NZV3dCSVpaUDhBV0gxVVdRUHZ1NjZjYlJ1YnlRbUlhVTNGMTNZa1N4SDNiVnlMcCtub0dGemJNRjFaVTJIdGVOeGRXbFBocGU0Q0dKNGQ4a0xWQXVkQ3RQVHlSeGl3SUZrM1RhK0NUZGJOaEdTOFd4RXREV08wbnphVjBySy9ZWFVWMmg4OFl2ZmU5Z2dzRjVVY2t3M0E2N0U1QTFySDJKWFJjdGRtMDNoZE5HVDh3dTZaZjdKYVhCeEdYUmk0dHdRdDBwc3QwY2JCc0JieklTMFUzcVdjZ3dySXBqRFF5RHIwQzNQRDhnbG9hUzIzSFJieERMUVlZTE90Y2VUZ2s2bk5rTVZ3eDEva1V4SVJMVU1xNHNtUnN0cXNyaWd5OVNRQWFndzIzU0RjekdwZFlhdm9pKzl5eWphKy9vbUpGWjV6WUlKcWFHUm9hMXUyeTJ6RDZtR1NBQU5GN0xROEp3dWFxZUNRZVZ2V0NZTTl0cmpaTlVTdmxud1dOTmhyWjNFa0MxbHlYdHhlNmpvWldSdDMwOVBrdTRpTVVVVyt5NXYyaFlIRm1BT0RnRHRiY3BxUlV4eWJrZkFlWXNFbXE2eXFsZURhOTkxeUxHNC9kOFhrWTBiZ2ZtdnREdEF5VkRoTkZVdURRUEQ1aGZIT1luTWJtU2NjN2ZtbktKNlhUSzBhbGpuODZMZVNWYVBBMzVKM0hCK3VIeVNZRjJOK1MrNkkvTjdDeGp3b29IQ2hHM3dJcldwMFN2SWswSXJRb05DSzBKcUs3WVZvMkNJMEtMVzhJalFpUWhoQUVYUmZoREE2STBaM1ZpSldrVGlacFRBR3hRZFZrV0lGeXNwRmRqRkswT2ljRHpkR2hnYTNVU1NsOVpZUTFyVWRySDZibTR1clVNYlFxZUdOZkF5Mnl6U1JWT0p3eE9KdEk5cmZxYkxxSGFuMk54WmJvS2V0cHpJUTZCc2h1Q0JjdEJYSmNOTHFTYU9kcnpkaERoYjAzWFFxL3RUcU15WVQ3dFZCeDBORVkxK1FGbGJVV3Fvd2M4TTZmd28wSmpSb0xEOFRWS0E2anBJNFFScWRWeU9BczBsTldCa09sY1phMDhjdGNvSUJ4c2lzQ2cwV3Npc2FteEZ5Wk5vUkdoUkFVZ2JGV0lvcHpZWmpVZHJVQmprZHB1ckNLcllSckZOckY0ZEVWcFZoSVU1b3lJN2hUYnNMZEZsdkNrR3BzVUlrN010Q0szWVdBc3NNYWl0YW5DS0pENUtUUXNXdFpUYUUvVHFzVEsycGFlUmZvRWFObFk1YmQzV0x3bjFTTEFtc01kM1dKUk9WRFVLOGMvMFpmMGtxeXcvVkgzdDJQVkduQUlDVHhIMSthcjgrWXQzK1BPaURydDFEdzlPVVRzWWQzK1dZeUR1SXY0cWl6Skc1K2NIdEoydTM5NVh3bnFjYTFFajlGZEZtcGFXUDlmM09rNWViN3ZRdGNSYTRCUytJWXFHUGVBYkp3ZnFNTmpEZjJHL3VXdVNRUHFKM25mbGVlWnNzcmNRMTFramlDU2ZtcU9YQ3A1Yjk4MHRiNXJhelM5Mjg3WE5rRVU3M2c2MmtDL1ZJbEd3VTZOSG13bWppY1RxdTd5SVZSaU5MVm03YWFCcmdkcjJXN1lqVFFST0p1MjYxK3V4TVFBaGtkL1VLdThiTE1aR2sxK1VxeW5qZEpLSHRCMzVLMGZGbnhVVXBEbmJncnBzMVRMVWFoTk9RMDlDdFd6QmhWRTlqbm1aaGR5czdLdUJzWFpyMkg0czR0QVk0a2ZOTmY1UUNrQnZJUWZtdE94YkVZOE5lNFJ5Q3c4bHJOYm1LU1o5ZzRxa25UTHNUNlB5MWpqSytpa2FYYXZEMVhPczlORU5kSWVuOTZyc2o1bk1ETkxuOGhEejVpb212SU9wL2l0WERsNG9PaXBZM1Z1QXBDVTN0ZXlSd2ZFR1ZHeEk1VGs3ZEx3NGNKclpyWXh5S1lSRGRMVFAxa3FKZnJic29Yc2tTTkdESWhub3NPMlJtMklRcFJ1a3NhWTAzWGhHVk5pSnBWWmowRGJZZEVVRUd5ZzVpekczeEJKa05pRmEyNTRSbXQyNFVvbzdoRzdsS1k1QzhJSmNyS0NJa0RaUmdwTEVGUHh4QnJRbE02Qk1kazNCRmUyeUM5cHVuS1VXU0dRSjNQaDRVTkZpbXlScFFpMjVTV2lCSUduWk50c0J3aFFzNFJyV1hhT01ORzhlU01UclNyTDNUYlk5TmwyaGJKUndtNmZoT2dKZUlwdU5sOTFLQnNPeVEzRzZaWTlMTWFtV00yVGhBVFVwTlp1RkZyRXcwRFpRaEZyZlJGYXpaWmEwSW9HeWhETVEzQ05heUhHTjBheWdJV01YUjI5RUdNSXc2SXdHR1lqdFM3RXd4RUFFaTNLS1FoeGpkR0lSZ21HaTZ5Q1ZsclZNQnZvZ1pERFhJZ2NvalNQSlNEZ2hJRmlPNmFZZGtvMDJSbVBVQUNFWEtreFJHNk0yR3d1b1F4cVJJM0laYlpGaFpkUWhrTnNWTUVXVW5Oc0VKRUxva1JlNkRwdWl0TmxFV1VKUkVCUzBLUXNzcUVvRzJJczNLeVpCYXltWGFoWlE3dFE2RGV3dlBYN2xQVHNzbHdZczIyUm9CZ3lMcUpienNpRnF3akJGWE1OMWdDeWFlelpBYzJ5TkVJZ3FMMmxaQ0k4YkowUUFMVjZRN0tRQ0hJTHBxQkFXTjFrYkloYWh2MlJBRWc5WmtJY0VBbmRFQ0pFQWxwQjZxYlhFRGRFYzNaQWsydWpJQ2ZZM1Mwd0ZrVndLWGxhYklXZFFyS1J1a3BlcVpsYWQwbktWV214MFVLVEpkenVVV2QxcnBSeitWVmt5d2tEbG1EcmpaS3ZISlJKVzJTN3BPaXAyT0F5eTZUd2dTdUZrV1ZtbzNTa3pyQlN5RVM1RGtrNVFpOGdvVWtsMUxJQW1meWtwSk4wek9SWktGdHl1MkVrRWpsc09VR1NyRURUYy9WZWNOSlMxYkVaV2JJR3cwaW94TWlyMUZvK2kwZkhHbW1KdmY3MXZ3ZzBhcnJVYzEwUmwxRm9RMkdrYVpMRTJRRWdmZ3FxcWNHa3RzTC9KV0xIdVpxRHVoVmJVczF5MzlVemR3QnNLcXBoTnllRWk3WXE4cVdEUVZSVkFJY1VQY0pLaVlOd2xxaU1tOWlWaHNoQ2s2UVdRMEZZbDNXNjg2SDBUTmdGa05CUVVNdXl1ZkFmSkx2Z3Vyc3dBcFdXakxOMGFkSGFzcXZkRHpZb1VqQ3cyc3JYVHA2SWNzUVBRSTk2SnNaWDJKQ0ZKR1QwVDRqSGtwR05vNkJTem0wcFgwN2llRk5rRHRQQ3RDeGhQQVRIdThZWmZaRXBFMm10U3hIVndnelI5TEsycVdORHp3a2FpMXRnajNFMmkzdW90ZFFNSUFVOVR2SXJHbzMzQ0xZRHRzSG90MC9CRG5wMnRGeHVVd1NGbUtFT1BpS05jRThPeXZqaExuZkNFNHlJdEZpRWQrbVBaclFUNklrRkxOVTIwc05pajNJbmdOaTdxUnJCY2IvY3B3TWVUWU1CKzVYZE5nRXJyYWdiZXF1S2JBMnhnRXN1VlZublJZaHBXVWxKaGtzb0IwSzNwTU1FZHRkMnF3YkM2SVdiRVVWdEpKS2JFRnQxU2xtVE5DR0NoZDBGSzFvdTRrK29VUTZOdXpBRDl5c0c0QnFGM1NxUm9ZcWJsd2RaQjRpWXpaUlZ1Ti9oRzZpQks0OFdDc3BxdW5qSGdqYThqeVZjK29xcWgybUdqZWZrb29zUjRxUmswWWsrSnhDdzZDR2pHKy93QXducVBLdU1ZaFl0cFpXMzlGc21FOWl1TzRzOXBmRk0wSHpBVEZ3S2VlalNmZTRvanFBSDBURU5XNnU4TEdOKzRMdU9YdlpxcTZndEU1TGZQVVA3bDAzQS9aeHc3REdOZFBMRmNjM0IvSk4zQy9lNlBsS2h5alg0aElORVJOL0s2M1hCK3l2RWFvTkJwM2IvTmZWMkZaRnkzZ3JRWkgweDArZDB6UG1ETEdFbXpCVEV0OHJydTRyUHFHV1hGSTRYbDMyZmF1bzBPa2hrQTY3RmRTd0xzS284T0xIU01OeGE5MnAzRXUyYkM4UGFXd01qOGhwUDhBZXRXck8yR2FjTzdzdUFQRml1YmdIS2VYdWpxbEpnV0ZZSEVCb2p1QjFZRkdmTjFEUjNFZmR0dDVOQVhEcXJQT0lWN3paOGxpcDAxVFYxWUdwenJuelUzSUY2Tnk1T3R5OW83RGNOYzAyK1NxNnp0QWZJQ0d1SDNGYWRoMkJWVTd4Y08zSzJyRE1rU3p1YVhOS1NrZDhWSXE2bkhhdXVjZEpPL2s1V09YOE9yS3ladW9PSUo4eXQrd1RzOWpzMHVZRnZHRVpRZ290Sjdwb3NteEV6eXFqVnNGeWk1OGJTOWhHM2t0cHBNcFJnQzROL2tyc3dNZ2FHdGFBbWFTTnpqeW5veThrMGV3akIyUUFYWU5qNUswOTdaU0cxaDlFbFZWZnVyTnZKSU5xUGVDU1RhM21tdVJTaW5ZM2l1TENScEFJSHlXaTVneFFRdGNRVTNtWEZHMFlmWndYUEszR1RYTWt1ZXRrQ255YXVHTkhPZTJYTUFrd21ab05qcFBDK0ljUmtkTGpjcnIzMi9OZlYzYTdVM3BKVzZ1aFh5ekxDMDRsSVQ1SjhaR3ZCRkRqZy9YRDVKTzNnYjhrM2pmODhQa2xnUDFiVjk2UitibXdrZndCRmIwUW94WmlNemhPaVZwTUkwWFJRRkNNSTdSWk5SWGJKTkhDTXdYQ0V4R2pDYWtJYkpnSmlKZ1FtaXlJSXllTHF4RkZlVEpGdDNXVjFndEFLbXBoalAyM2h2MUtwV01MWEs0d3VyOTJuaWVUYlE0TytoVmlKVm0zVG8rak1IOW02T3ZocDVneU02Mk5kOFE2aGF6Mmpkampzc3dOTFd0RnZJaGJsa1R0NHA2S21naWRLdzZHdGI0aU9nVlIybTlyTUdPdzZXdWpPM1N5MFlxU2ZQWStXYUNYVlhsL3dBM2ZWdjFPQ3l3dnBqcFBGMVBTeVY3UkdOTzI5MU9vbkZYTVhCWmlHbE50SDBLQ240YTM5Nkp2dEMxcmJibnlVZ3p1R2g1M3Z0c3NFWDVSRzhXS0dyTTdJOHlmd1dFYUwyOVVScUdPaU16ZE9RVGtFYUxvelllQ29OQ09PQnNyRVVWWnlKTWhURFlEYmhZZ2NBUXJTQjdkTnJENkt5a1ZKTXJ4SFpGWkhmb21wcVlPM0NOU1FhellDNmVrVTNJVUVSVW1oV3N0Q1loY3QvQlZrNzJ3TzBqcW1wQTdpYlI1SW9RSWhZYWoxVEVUQTkxNzdKcVJ6ZWoxbE5ndWlOYUg3QUx6b25NNldWbExiaVpTeVMzWlVUYndzd3lhS2hyaHlGaU5tcm5aZUk3aDExVjI3OGMvd0JDeEhKc3l3L1UrM3ZaN3J1L3dEU1hmNnIrSVdNMXZFR2M1Q1RwRnh1Zm1WclhzejRnSjZWOGVyN0lGdnZDdHUyOWo4UHhOa3pidC9XdDNHMzJsOE42NUZRMVVsK243SDZDOW5zdTdTeC9yKzUxK2dvL2ZLQ0k4alEzZjdsNFlNSXRSc2g5bUdNc3hmQUk0N2h6ck5GK3ZDMmllZ0RRNjk5MTVPajFzalRUaGZlU3VOdUZYMXpITlk1cDNBV3oxNE5MRng2WFd2WWlXRnBJTzVYT0JkTTBqRktlSXVjUzAzV200eE1JQ1EzWmRGcm9USUNHdEJXajVnd21aNWVRelpjYVErTVdhSGlkVVlTVE5JMjN6VmNUaFZZd2lXeE52MmdxYlBPSFZEbk9MWFBGcjhFcmxtSTRwVlVVdWp2SDdHM3hGWkdXSm9ReE0zak5HWDhOazF1aFlENVdjQ3VhMTFKM0U1c0xBRlBETnNsTkVPOGRlKzNpTjB0VllwSFhST3RhNThsbFNpMHk1R0ZJbGhPTEdDcFkwT0hQbXIzTXRWM3VINnRRSnY1cmw5WlhuRHFvdjFFQy9tckdITkFyNE5PdSszbXV3azBGUTFobU5PcGF2VHFzTHJvOUJLMnRwQTY0SjArYTR2VTFaWkxxQzNUSjJZYjJqTHI5TFhXanVOQ0ROdjFHS1FnZ3FUdk1JdFE0U3MxTkhQb2h4TXVFTFpvUWZCaGoxTnpib1Z0TDB6Y1dRRGdZRnVGTmx5VVJvQjZJMGNYb3FySEprV3gzYXNOaXNlRTQwQURoWWE4WDQvQkpZMkxQUU5zckNLSUVKYUZ0K2llamh1bE1jbWVBRFVhUGRUYlNvaktjZzlVZ0t5YktZUDZJcklOS1lwNDlrWmtIb2dhSlltV255Ulk0cnBoMEhvc3h3bnlRN1NXUmhhTG8raTZ5eUFnOVV4SENVTkFXQlpIWkhZZFd5SUlkdUVTSmxqd3BRTmtvb2VxWmE3UWhscUpFenpVb0d3ckhJN0hvWVp1aXRZbUNnbXRHYTdoQ0ROa1dPR3hVSUZhVVVFbER0cFJZNUxLRUN4QkdBdWhqb2lONVVCRFI4SWc1UXh3aU1hakFZVmlZWW9SQ3laYVJiaEVBWmkySVJ1VUpzYUtOZ2pCUE5DbHBLZ1piYkxOanlnWkNXZ3JGaUNzdGRaRUF1ZUVKQ1E0VTJsUnVwTktnQWRxZEx2Q04wb3h3c2l3Tk45MUNFWE9OMGVCeTlLQUFnaVN6bENEZDdxTG1yT3pnRU53SVhiT1VSY2JLT3BZZEpZMldXQzZsa295Q1ZMVXM3V1VISGRTeVVlYVNGUHZObDdRQ0VONEk0WFFURHpxS09PQWxmRUR3bWh3RWFBWkVyeThRdldSZ21ISUxoZE5IaEJjRWFJQURWNTkxSnpWUGEzQ2RFQUEwYm02ODlxSThJRGdicHFCQkVsRGNMcHB4QkhDQzV1b29nQU5sTURoVEVhOVpFaUEzSFpCZjFKUm44SmFTKzZNZ0owb0FTMHMyeFJTTEplYXhCUVNJaE9XY0pPVTdGR25oM0p1VWxLK3dWR2JMVUVLMUI1M1NUMzJ1anp2NVNybjhxaktSYlVRRXM1ZHNncVRrRnpsWDNCMFlrbHRzbEpoZEdjUnVnTU4zS2JpVUtPQnZ3bDVUWWxXY3dCYndxZXJZZFI1VTNFb1ZxSmtPR1FHOTFKOW5DeUVZYmVpNjJNU0p6dkNFMlM0TjFoMGZxU3NHWm9Ga0xrR2tBa0d0eENyTVN3OFNzZGNjaFdyUloycm9oMVRtekN3UU5oMGNtekZobnVUM0ZvOVZyejdGaFBWZFF6SmhJbWljUUxtM2t1YVloU09wWlhYMkYxMU1QYVZwdkk0Z3F1cWFiblpXKzBnTmh1bHBXYVFiaE1UQWNTaGtoMHBXUzRPeXM2dGhKMkNSTFN3N2hNc1h0QmF5cE1mdWhseHZ3cE5kZm9oZERFaHlOMTFPU1FTQ3lBeGhjbVdNc2t5a09qRUI3bUg3MlFwS0RsV1Fac3NPaUpWZHlaWVNSU0dqc1VLU0FoWGhnMzRRSktZSG9tN3dOaFF2WVdsRGRVdTBrSzNrb2JuaEJkUXRIVDhFYW1UWWE5SVhQZndWNTFNWEFiSzk5emFPbjRMM3VqVHQvQkZ2SnNLa1VRTFJzc0hDeS9ocXZvY01KSTJWblQwYll3QVdqN3d1dk9jV1BrMHY5RFBKK0UvUkZPQnlpMW1yZkdVakgyOEkraWRqbzI3ZUFmUklscVdXb1kwYVJobVUzVkR3WHRXNTRmbDJucEdBT1p2NkorS0VNR3pRUHVSKzhEUjhraDZwbGxZa0xIREdEZ0x3b1dEcGRPVUpkWHlhUU90dGxzMUJsY3lBT2VDcWtzclk1VWpVMjAwUUc4Ymo5eWtNUGRVRzBVVC9BT3FWMDZoeXRRQUR2SEVmY3IvRHFMQk1PR3B6Mm0zbTBJRTVNQ1U2T1VZYmtTdnhDMW1FQStZVjdIMksxVlNCcmEzeGJiMlhSWiswVEE4RlpacjR0dk5yVnJHTSswUFFVb2NJblEzSEd6VlppbVU1NVF1Qit6YkExN1gxQWlzZC9pYUZ2bUdkajJXc0dZMTA3WXRRSFNScTRUaWZ0TDFjZ2MyTXhnZExPL3VXbVlyMjU0dlhsd2JLNFg4cEN0T2tVT1d6N0lwb3NvNFNMQU1CYnY4QXpqZnlVSzN0ZXk3Z0RTSW5mRDVPQi9ndmhhcHo3ak5ZU2UrbHNmS1FvTVZmVjEzODVVVEcvUGpLNVF4WTArN1BzZkZQYVdvb2c3M2VSNHR4eXRBeDMya3E2dGM1c1Vyd0Q1dEs0TFEwVDN5Z2Q2OXhKNExpdDJ3ckpWZGlEV0dLRFVDZWJJYUdyVHc4MldPSTlxbU00bVMxc3J2Ri9SS1RnL1RPS1Axdmt2ZjAvdlhRc3U5ajlkSzZNdXBTYjIreXVtNEwySjFSYTBtbUkvOEFTaTJzWkxObzRyaHgraHhMQzhsMWRjV21TeFBLM1REc2pTM2FPN0orUVhjOEc3R3A0dzI4RGg5eTNYQit6YU9pTFM2SzVIbTFUYXpPeTZ6Qkg3dEhDc0Y3UDNQTGJ3a2ZNTGZzSjdNUTVyWEZyUmJmY2hkVmZnRFlXQU1oYUNQSm9TN2NNcVd1c0dXSG91YldacytwSmNMOXpYNkxLdFBURm8waTQyNUMyUEQ4TWdqQXMxTjAyWFpYa0VoeXNZc0FmRUxuVWkybWU4ek1VN0dSRVdDczNUTTBnV043SmRsT0lPZW5tb21VVG13K1NOSVU4cllRd2lUZFJkTWFacDNzcHRmM0xkMVgxcnUvSnNmb2pRcTJ5SnFmZkNiMzU2cXF4YkVQMGRHZExoZTNSTVRWYllJejBXb1l0VUdvbEkxRWk2VTVGeU1DanhyRTVNU2tjRGMzVkRWVXpxS2trZWRqeXRwOXh2WTIvQmExbmFvOTFwbkRqd3JpYk5QRkUrZSswK3ZNenBXWHV2bit0WVk2eHhYWXMrVnhrcVp1dTY0M1h6azRqSnNyY0RUaWpYc2JINjRmSkxBV2piOGszalF2TVBrbFcvQTM1TDcrajh6TW13ZUFJelFodCtFSXpSYXlmRXJTQ01DTzBJVEVadXdURVYyeVRRak1DRzNuWkdZckNFTUlBalJPdW9EaEVpWnBWaUlpUWJRSElqSXo1cUEyUjRqZFdFVm1GcFhTVXA4TWhDWWZKTFVEeFBKQ1hNVGk0YnB0ZzBScTA1MEtXYUxYd0VZV2FFeEdMb01UdFpUTVkzWEZLek96eXorVWlWa1JnV0xJa1l1VmJnckF4VHlyN3pKaG5DTkcxUURlRWVNV1RVVlpNazFxS09Bc0JUYUZaaVU1c2xIc1UyMTVhRUZqTmtVTnNyQ0tzbUdpcUhPYnVuY0pxQTJmeGNYU0lhQnNwdEhkblVFOUlxczJ2RUttSXdHMXJyVzJVNHFKUzl4MkI2ckxaM3ppeEt5MWptVTdySHFtb1JKMFJsY05RWTNlM2ttbVIvcWdBZkV0cHlsa1E0dFNUVG5TNGh1cmtLbHJzT2tvTVhrZ2MwZ04zNFRJdE4waXU1MEV3MmhMU0M3OFUxWE1pYXphMTFnVmRtZ0M0U3RRSFNiazdLNWw0eE9oY1hlVkNlazZyaFNsSGVzUG1pTmNJcmdxVFc2Ujg5MG5Bcnh6djBKbWxXV0ZlcDlBK3pUaTN1dGYzUmR5UVAzTHVYYmhsLzhBU1dGKzhNRnlINnJqMElLK1creFRFalM1Z2hBZGE3d3Z0ckhLVnVMWlV1UnFKRHYzQmZFUGFQSFdybEw5UDJQdm5zeGt2VFJYNi91Y3Q3QmN4R0tvOTFrZHhKYXg5Q3U5MXQ1QXh6ZHdmSmZLdUE5NWxmTnJRQVdOTWpuY2VxK244dTRrM0VzTmhkZlVkSzhZMGUvQlY5SUo0Q0R5dEJ4bW1scGRSTjdCZEtrYnFxWE5IRmxyMlpxRnMwVGdCMFZlVG9kQld6bWh4VU1jV2x0MGxYMURaNDMyWnlDbWNVd3p1SkhPTFZyZGZqa2RGZHBCU0hNMGNlTk01ZDJndTkxa2VORjczSzQxalRJcEhseGFBdThabXBvc2ZjU0xHKzNLNDluTEJEUU8yYllKRTFadHJDam5lSzAzZnNPZ2NiN0tnYld2cEhFT0pzQ3R3YTFzY1p2MUMxVE1GTHBqZTVvV2ZPRmtlT2lyeE53cjI3SGRWZEt5U2prQUpObFhNeGwwRldZM2t0RjdicTllNXRSQ0hnZy9lbGJDbkxobG0yTms4UU54ZXluaFU1b2FzYjdYVkN6RkhReUJwTmxaQ1R2WXc4RUUydW0yV3NaMkxCTVRqcTZVWEl2WXB1bG5iSVNCNXJsbUE0NUpUa011UXQyd0d1NzF3dTdjbGROQ0ROZ2tiNHJxWU95eVJjQXJCMlhSd1dBWGNyR05nMGhKUU5zUW40ellLb3h5SVBGbEZyTjBaelVMdkxKTWgwUm1FZ0o2S1lDeXEyU2I4cGxqOXIzU21PUmRSeUEyNFJ4WStTcUthWWsydXJTR3hBU0R0anNDY2paZEwwN0FRbm9XWEtoTElHUDBVNDRiOUUwMkM2YmlwUVJ3aW9saVBjZ2RGTmpMZEU4Nm5VQkR2d2xVRFlKc1lJV1JDUVU1SEI2S2NrTmdwUURGR3gzUkEwTlJHTnNvUzNCMkM1UUpNTzRSR2xRYXpoRmJIY0xvSk5ydGt4RzRJRFdiSTBiTEZRZ1IyNmt5TXIxckkwWjJVSVNiMFJHOHFBNVUyOHFBaDI4Qk10YllKVUhZSmxwNDNSZ01NeFRhZDBOaUtBaUFEdGx2WUtmeEJMdEc2WmpHeU1FaVl0MFZ3OEt6cVdPVURJUWFMRk1zR3lnMWwwUWJJU0dMWEtrR0lqR29vWnNvQUNid2pSeldReUxMd1pZaFFnMkhhMm9UMmIzVTRkaDl5ak0vZFFoaU9ZM3NqaDJvSmNSMkYxblhwUTJGUko3ZDFJT0FDRjNpeHJVc2xCUzY1WGlDVU5ycmxNeHRCQ2xrb0VOWHFpTmJmbEVCSGt2YWRTWUtQYUcraWlDcEdNMlVBTFhSb0JrZ0xyMmxaYUVRSXdRUkZsQndURG1vTDlrYUlESTJRMU1uZFMwN0owUUFUaHNoRUM2TTlBY2QwMUFtVEVvT1pwNkl6WDNzQ3N1QWNFUUFxWDIyc3NXUkh4YnFLSkVBeURaTFBDYWVDZ1AySktNZ3BORVd0VlpVRnpTcmVhZTRWWlVtOTBtUU1TdmZJU0NxMloxN3F4bDJ1cTJVY3JQeU12NDEyRVpuY3BSeHVVMU9FcTRXV2JOOGw2S0F2Y2w1SFdSM2xLU2xMc2dONzBJT3NWaHgzVUhuWlN5Qkh2MlMwckE0RlljOHJHdTRLbGtLMFFrdVB6VUpnV0JPdGtHL3pTbFU2L1FydGo2RXk0bTZUbTFOZXJHTmdJMzIrYURORUxFb1d3MGhXV1hURDYyVk83RWpISVFTclp6TzhCQzFmTU1ScGk1elFmdVFXRlE3SlZpcFlRU3RIekxTQzVJUlhZKzZJa1hJc3F5dnhiM29HNVZta0RaU3hFUnVzVmlkZ2R3aFZKSWNTRktHWFVSZEMzUVNWa0JRaVRsQXFNS0ZqWUJXWGVhQXBObEQrVnpjRW9HcFZGQzlwTm1sSVBqa2pkOEpXK3VwWW5qNFVGMkVReWZaUXVWak5ocGJKcEdqNFNpdHEzWDRXMi9vR0lqNGZ4UzBtV1FMa0FKYloycUtPS3FKNkpwazF4d216Z1dqb3BOd290NkpiUjFNVEpKUTN0ZDVGWE1GQUhHeHNubTRNeDdlbjFTN0xPMDFGMXgwUUNMcmNKY0JhYjdCSVM1ZWNMMkFSS1JOcHJlbjFVZ3dlaXRKc0Zlem9sM1liSUR3VWU0N3RBUTFRSFJTZlcyS3k3RG5OK3lVRTBidXJTaDJuVkV0S0d0QnRkV2JLMWdBNFd0c1k2UGdGRk1qd09xVTRXT2lqWWpYc3QwUVhWb2NiWFZKRzk3eW5vS1o3N2JKYnhEMHk3cGE5dEFRNW91ZVZidzV0bmUzU3hqaDZoYTVIUzZTRElSYjVwZzRuUzBVWjg3ZWE1c083QzhreDZxM1BldWFxWEZjMnpCam10cURkYTVpdVozUGM0Uk9zQ3RhcTZpUnppVHZmZlpXSVkweFU0SWZ4VEc2bW9lYjFEaUNxb3Q5NCtPUy93QTB4UzBUcXV3ME9KUGtGc21FNUJucm5OdEE4M1A3SzBvWWxSbXpoeWFtekR3ODhYVmpRWmVrcVhnTWdMaWZKZG95djJEMWxmSkhxZ05qYmxxN3RrZjJhUTN1M3l3RDhFcXl0TnFDcytWY0c3TTY2dERBMmxmWnh0d3VtWmQ5bkRFS3pSZUY3UTZ4NFgydmxYc1Z3L0Q0NCs4Z0d4OHd1cDRYbFhEcVJyQXlPMWdCeUUxS3pHemRROExzejRxeWw3Sjh4bWpmTHhlOWlQN2w5QjVQOW4vRDhKcDR4TEZHNGp6QlhiSTZhR24yWTFHZFloT1VFekZ5OWJ5cjRVYWhodlpuaHRKcElnajIrYXVXNVlvcWRvRFlXZmlyVnNqbEw0dVNyWGhJeUx6M2JaV013dUJnSWJFMUFiZ1dwM29TcndOQUNHK3A3a2J1QSs5VHdrR3ZFZmRsZXpMMGRydUFLSE5oVk5GZndOV2EzTUloQkdxL3lLb3FyTVFrSjhTNTRhSHhoTHpIejNNUFFLdHJzVGpZQ0JaVTlWakRuQWpVcXQ4ejZoL04xVm8wV2l6bHJUSzZ3NnBpT0h1UUNldTZYb2FIV0E0L05NMVUxbTJ2eHN1QzY1QlZNZ0kyVlpOVWlLOTFPZXAwMzNWTFcxQmU3bENXWXdzRFgxQmRjQXFyTUZ5WEVKMlh4RUtGUTRNaE8vUkxvMElJcXFxcWJDQ050bHlydEx4MGhyZ1AyVnYrSlNGejNlUzVEMm55c2FTTGkrbnpSeFhKb1kwY096UlZkN0pNNHJrdGRVM3hTUUFkRjB2TTlTSTJTOGhjbjc4UzR0SmZpeXZ3aVg0a2NVTjUyajBTVU8wcWR4ZHVtb2I4a2pDZkd2dlNQekF3N3BQOUlJQVJRUklpME5JS2lwSTh3alloaGpxTVgrOVdJbGFRRmtZWnZkRjA5NVlCTFJGeitVNVRFTmUwSHpWbUpYWVVRbUlDNkl4d0t0SzJuYjNMU0xmQ0ZXUng2WGxHa0liRHNHeU0zaENQUkdZTmduUlJYa0VqYmRIYUxJYkFqTkNjaXUyRWJ2WkdaY29ZQ013SjZSV1lSZys1SFlFSm9SMkRoV0lvcnlZVmlPMXFFeHFPMGJLd2tWMlphTjBaaUcwWEtNeHFlaW0yRWFPcU13YkliUnNqTkNjaXZJSkdOa1pvc2hzQ01CMFRrVm1aYjhrVmdIa29BRFpGWTFOUW15UWJzUmF5bUl0RkhJTG01SzhCc29zZTd2QTEzd2xPaVY4cXRHLzltbWEyNE95ZU9VaXpoWUIzM0tPYmF5TEZzUmttWTFvdnZkb0MwNEh1TkpqTnIrU2NaVVBjMEVra25aRkdFVkxkNW1CbXh1dzd4M3poWWNiYktNc0kydVNFUXRkQzI5dWQxR1U2NGk2OXRsZWIrTkZoNWZpUXRPMWpXaXh2djFVNHcyYTFpdGl5YmwxbU9GK3A0dUdFNy9KVnVJNE8vQ2FwNE43QWxKeXRPYWl1NGpCbC93QXgzNmx4MmVWWm9Nd1FHOXYxZ1g2QVpLbGJqR1ZvaDhWd2YzQmZuZmxxb0RjWXAzY2VOZmVuWTNpUGU0REEyOXhZL3VYekwydHdmQXAvbXYyUHN2c2JxZjhBelRUL0FBdjkwYUYybllPY05ySFRCbW13SnVCWmI5MlI0bUtxZ0xDOGt0YjFQcUZQdFd3VnRmaGtzaldqVnA2ZkphQjJWWTA3QzhZa3BwQ1FDNE5GL3VYeXBNK3p5WEIzdHdQdkxoNktteGp3QXJZYWhyWFI5ODBnMzhscldOU0F0UHlVYkJndVRUc2NqYkpFNDJGN2VTNUptV0l0ZklBT1F1cTR0VWdOY0ZwOVpoQXIzazJWT1pyWW1jV25scWNKbWRJUmR0eWQxcU9iY1FkalVWdExScDhndXFkb3RQRmhkRklYc0FJSFZjZEZmRlZPbWEyMTFtSHBzSm90WEFLWWxwNUNvNitQVysxcmhiZmlOQjNsVThrN1dWSFUwbzB1UGxzb2FNcTJuSHM4NEkrT1ZrN0FXZ0crMnlVd1BHQkpUdGhjN2NicmVzMHhNcVlIc0lGN1dYSmFxTitFMVRqdUJ3b1lHb2hiTnNuZTJkNDBuNkt6cFp2ZG9SYzMyNnJRS2JHeTEvaUt2SWNhYk5HQmRLMmxlTXpiNkxFUTUrMWxzdUQ0MFlLcU83dGx6aWh4RnJIaTVDMnlsa2JKQjNqVHVBaHVqUXhUTzNZZktNUW8yUGFkdzIreUt5emozWjVDMGpKT1pOSWRDOCttNjNScjI5NlhnaXhYTjZMOFdXY2NiUUFpQVdTalhPQUc2WmlCY0ZVWmFUSmg5Z1VuVlNrZzJDWmtHbEJtakJDQWZFVGlrZHE1S3NvWG15VmloR3BPTTB0UWxoRFZNU0hicTFnbDJDcUd2c202WnhKQ3JnTTJHbGsyRzZmcHA5SlZQVE9JQVQ3R200c2lRcVJkUnlkNEJaV05NZElWVlJjQzZ0WTdXMlJpV0hJRHVpa3lFSG9vd0M3bFl4UWdoTVVRSElYRVlhT1B3UUhOVmcrRkJkQWljUmU3a1RMVkFqbTRUVG9UNUlib2lxMG9Eb3lRSURqWkVZRkxRcE5iWUt0VElaQVJHaTFsQUN5S0F1a0p0Um1JSTRSQVZDRFl0WWJMQlFnL1pFYWJwaVpEUEtZWWIyUUFFVnBScGdORERFZHZDV1lVZHAzUjJDR1k0aEhaSjZJWTA3SXNZQlhiRTBURjNkRVFRSFpFalkzMFIydFhMQmFCTmlQa3NtUDBURFczQ3lZN2hjQkZ4RWI5VVVSa0RxaUJuQ25hd1EyRll1WTkwUURaU0tpdTJGWjdoZTVYbDdkU3pxSmpoUXNpYVZFaTZWUjBnUmRSc2lFV1h0Q0pJRm5tQk1NR3lFeHFZWTFIUURaNWc5RVZyUjVMRFdvcldwbENDSmJ0d2hQYjZKZ3RRM3QzUnBFQnNIb3ZPYnVpTWF2UGFpb2hBOEJDY0V3VzdJYjJvcUFGeU4xQjVzakZtNjlKRGNJMFFVSkpVMnhhbGh6QzBxYlgyQ01nR1EyV0dJcm85U2t5QzRUeE5nWEZZY3pTaXZpMGxlbStGR1N4WnhGdUVuT2R5bUgzM1MwdlZFaVdKVEhsSnlpNFRrb3RkS3lEWlVacmdaQXE2bGh1VWhLTmlyV3BieXF1YmdyTnlGK0JYVkhDU2VuYWpoSlNjRlZ4d3BLZVVsSTdkTlNkVWxKMVZVZWoxOWlnZ1dVMWgzQzZFaUx5TEphVGNvcmxBMjNYYkRRTU5EME9Sd2pHNEJSQTBzVUpZdThDVllRbyswcDIyK1NVcVdFamE2UE5lRWxMdWxCRzY1WVNGMk4wM1NPSlVvbmpmY0E3SG9uWnBBQnNWWHpWZ0JJUFZjRE9iWXRoeGhmSWJXM0sxNlo0amNRVjAvR0tPS1dNbmJkYVBpV0VqVTdTUXJDRkd1U3lOY2VWNWpMY0xOWFF1amR5aGQ5cHNFYUNRMndlYU93SlNLVUVwNkd4M1JCazNSa0M5a3MrcjdrOHByM2xwRnRsWDFjZmU4S3N4NkdJOFdCMjJUQXJtbTI2cG1VeGFDVXFaWkFUeWx0Qm8yUDNsanZMNkwzZU1QUWZSYTBhdVJ2bXZmcEY0QjVRVUVpK2MrTmw5MW1PcmpCK01yVWF6RXBnMGtFclhhM0g2aUZ4c1hLejROazhRNjVIVXhPSHgzS3pITUNUc0Z4WC9MYW9pZDhUay9UOW9VdXdJY2hlbWJDV1pJNjY0TWVOd1Bvb2U3Uk82RDZMbWtXZm5PdGNrSituenFIRVhkK0tYN3F3MXFVamVXMGJTZmhIMFE1c05qSTNhUG9xaWt6ZEJKWUZ6VmF3WTFUemdYZTBLdkxCSXMrS2haMkZSRy81SVRjR2FkamRYVWN0TTl0KzlhcTZ0eEtHSWtOZVB1UUxFMFR4RUx1d2lPSHhYS0RMaU1kRzBqYTl1b1NkZmpqV1JueHJWNnJHQk85d0J1VlpoQnJ1YzhSRnBXWTg0YXQxUTFXS1NUdnNDVDk2TlE0WlY0cklHc2lkdVYwaktIWXhYWW85am5ST3NmTUszd1VwYWhITmFURHFxcUlMV0UzSzNYTDNaN1c0eEt4cGdKQnR3RjlGNVQ5bjROamk3MkljOVF1MDVZN0k4UHd6dTNPWkdDQVBOZHN6OG1hejUreUg3UERwekcrV0Y0Ni9Ddm9YS25ZVmh0RkF3eVIrSnUrN0F0OHA2Q2d3eUZvWTZOdGgwVUpjYWlqSkRhZ0FLV1VKeWJHTUt5N1JZZFlOZ2pHbmI0QXRrb3ErS0FocldNSC9BS1F0T2JpOExBUzZxQ2czTTFIRSs1cW1YK2E2bVowdFBOblZJSzlqMkM0QStRVEVWZlR2TzBodXVXT3ozUnhSa0NxWng1b0dFNTdwSFNtOVUwNythZEhJa1Y1YU9Yb2RrL1NVY0xiNnIvTkoxR1l3Q1EyeTBkK2RxRXhqL1NHSDcwS1BOdEM3Y3lzUDNwcXpKQ1BjWGZZNkJRWTYrUUVPQTVUQXJ3NTl5VnpLcjdRcUttaklZNWx4NUZhN1VkcUk3d2hwMithbnZTR0xRU1hrZHRyTXdSMHNaM0d5MUhGYzJpb0RtdGVQdUs1blY5b0xxbmJVZDE2bXhidmR5N25kTGVmY0hIU0tIa2JjY1ZjNXhKY1Q4eWxhckVTNDdGVW42U0hSTTB6alVPSHFsYjJ4dmgwUHRhNm9JQUpWM2gyRzZHNm5ENm9XRzRkcDBsd1R0WFZDbWpzRTJ4VFZrNml0YlROSUZncVdlc2RPVFlxTXN6cWx4dVV0Sk95bUJKSVFNN0hIVHNqTEwzWU9wVmxUVU1jZWQwS3Z4THYzYVdENkwxRmhFOVdRN2V5QXZ3bW9vaWFoem5nSVZWRytRRGxYMHVFdGlMYjJ2WkFrcDJBZ2JJNWRqa1RUY1pqN2ltY1NMV0JYenIyalZ4cXNTTm5Hd0JGcnI2UXp0TkhTMFV2RjdGZktlYXFzUHE1bkUvYWQrOURGY21oaVJ5N1BWZTJPTFRzQ3VUKy9odFc3Y1hXNForeEhYTThCMndLNWlLZ3lWcmdEMFd0aVhCcFFOdnhnNnFsbzlFbzJNTjNUT04vencrU1diOERma3Z1NlB5Nng3Q2F2dXF6ZllXVnJqV0pOcUd0QTMyc3FGbXpRUnNVWWIydnVyRVN0SVBHMGFTZk5laUJMNytXNnd6aEVBMlZtSlhZOGE4eXREZDl0bGdPUUdEWWJJOGJicHlSV2JDTjhSVFRSYXlYYUxGTU42SnlSWGt3ekVjY0lERWR2Q2FrVjJ3clFqUml5RkVFY2NKNlJWYkN0SFZIYjBRWWdqTjNWbUtLODJHWndqTlFXYm83UXJFVVZteWJSd2lzVUc5TmtaZ1QwaXEyRWFMb3piQ3lHMFhSNDZRemJpNmRGRmFUSnNLTTBpM0tBNlB1L0NWT09NdDNUa2lzMk1OQ0kzWlFad3B0NVRFaEtZVUtFcDFFRWRGTG9zV1RvbzVMbEJZZ1h0MzZKcWptL1hOYWVMcFJ2Q21QQ2Jqb25KRktjRXplWk1QWlVZZnFiWW13NitpMWVaanJ5czR0dHVuOEZ4L3VZaXh4QjM2cEhFcWozbWZVTmdUMFRHMzRpS2ZnM05EK1VNd1RZRlZrYXJOdFpXV2FNWVppRXJkSnZxYnV0V2REckFJMlBtRWVNRWtYSk52TmRsR085Uzh4T1BDL0VZMWhiVEJpRUR4KzFkZmIvQUdBMTNmNFJBMG5vZjNMNGlveHBxb3o2cjdBOW5lZlhTeEMvMlQrNWVJOXJJSjZlL3dBMSt4OU45a2s0NngvL0FHLzdvN2JtQ21GVFRPakl1SEJmUDJOeE95L21XS1JnMGgwdC93QUY5RjF1OU9kcjdMai9BR200RTU3R1ZEVy9EdmNENXI0ZGZKK2d1R2pyV1ZjU0dLNWVpa3ZxY2I3L0FIQlVPWUtqdXcreFdzOWxHYkk0c0paU1NTZUpyVHlmUlR4ekdtRjhnMWNrcVNaMk1PU214Q2N5dk82RFRUdGdCTGphd1VoSlR5QnozUDhBVmFKbkxNN3FKejJRa0hvcWttWFlLalV1M0RGbVZySHh4WFBndCtDK2ZUVXV3NlZ6ajFYVGM1NG5NOXIzUEFkY1gzM1hLOFNsNzV6cjdLbHRaNlRIS2c4K0xkKzNVRHVWVTFkU084REw3SGRWTlhXbWtKM1ZTN0ZIVE9OejE4MU5yTGZpSm96bUdNUmtFRUcvcXViWnhwMnZweTl2TjF2T0lQN3hoSmNUODFwbU1RR1JyK1NMRlRhVk1rZHh6V1d1MFBJdndiSmlpeFY3WGNxb3gyRjlKTThrVzNLVXBxKzR0ZmRIS0hCaDAwem9OTFhPbDBrTzZyZXNCeEV5QmtSZHNiTGoyRjRuM1R3Q2ZSYjNnbFQrdFlRNDc3cWprVkZuSE9qcFZQVU93NlprakR5YjdMZDhQelQza0RMdTN2MVhQNlJ3Tk1IRTMyNnFVVmNXdnNIV0NvU3V6Vnh6NE95UVk2MTdXK0xvRmZZYlZDZHV4dXVUWVBXbW9pdHFOK09WdWVXc1lFTTNkT1BPMjZMeUxxa2JuTkNIS0xxYTRSakZwYjN1OWpzaXdDNkVzUllrS2N0dnNoeU1MZWl0aEh2d29WRVBoTzM0SVN4RmlMWDhCV2xBMEZVTHhwZWR6eXJYQ3BkeHVxNDFtd01Ha0N5c3FZYXJYU2xPUVdBMlI0NTdGRWhNa1dMWDkzYXllcGFndXNxdU9XNnNLWWl3UmltaTVwZ0xoV3RQWXRWTFR0M0c1VnBTaTNWV0lzcXlzZTdzRlJkQ2l4MnNwa1hDZFNLemJzUWtpc2dPajVWakpGZEtTTnNreVF4U0U3QmVzUE5FTVNqM2F6cUxaQ3lNMEN3WGhFdk5Oa0RJU1hyMldESURzb25jb1d5Qld1UjR5Z3NJTmt3eEZ1RG9NTFdYbW9hbUJ3alRBYUR4dVIybTZWWnNtR2NJdHdGRE1ZdVJ1bklva25UeGt1VmxCRWJCSHlMZEUyc04wMUd6aFNoaDlFMUhENkkwaExsUkNPSzQ0UmhUN0ppS0hiaEdFWG9pMkNuSXIrNHNlRmgwU3NUSGZvbDVZeWgyaTFJUmN3QkNzanlRa0hxc1BPM1JBNGpsSUIxWHJyRGhkWmJGdWdHb0tPRjRoZWFMS1JHeVlrU3dkMW15ZzV1NkswWHNqVVFHeVRBbVd0MjlVTmc5RXd3ZWlOSUN6RFJkR2FMQmVhTitFUzNvajJpYkJrSWJ3amtJWUNOUk9XUVlMTHpnTG9oR3lHZVVkRU1rYklUZ21IYmdJTG1jcmxITEFPQzhIWFdYdFhpNndScEVzRytNRUpaN0xGTXZjVU94SjRSMFN6emIyQ013aXlrR2tnYklUMkcvQ1lWN0lUSGNwWnppNVBSeEVnN0lKaDUyUmtzVGN3RUpPZHRpclFSV0pTMVpINklrU3lxbFpzZGtsS0xBcTVlMFc0VmJWc3YwVlRJdUIrTXA2azg3cXNtNEt1Skl1YnFsckcyY1ZsWk81ZmdJVkhDU2VuNUduU1VpNEc1VlJzY0p5RGxKU05zVllFYmxBa2I2Skk5Q1pHeHVoRGZ6VEVnM1EydTlBZ2JDUUo3ZGt0SWRKMlRFNUo0UW1BbmtJZHd4Q3N0VHQ4a2hVWXYzSnNUWldWVFNiM0Yxcm1QWVcrYUU2TGpib2xXSFFjMTdLdjdZUDNwS3RxTzZCc1Fma3RLZlZ6WU5PUTl6cmNibE50eG52UUx1dmRFbllhUmR0ck84TmlVT29ZSDczSDFWSEpYZ0c5N0tJeE1FSHhJMEhRMVd4U1dOaUxLZ3E0bjczVHJzZEFKQklRWmNVam1CQnQ5RXl4TkdzMThKT3BhNU14elhIWThyZVo0STVybTZvNjZObzFXYVBvalREU05lWk1XbFBRMVpBdGRKMURTSEd3UzduT0NPdzBpMTFlTFlqZFAwMFBlTjNXdU1tZEViMytxc2FiRjNNRnRrbWpxWS9WTTdwSXZnQjNzaXZ4QnNuSkNtMnBqMjNYYURUSytXbkhrbG53Qlc3NVkzRGxLeXh0ZGZkYzJCMlZNa2JaTGdoVTJKWVd4N1Q0VnNacDJnOHBlYUJqaFpXbE5FZU01elhZVUdPSjBxdUxXTit3UlpkRXFNT1k4bmEvM0twcThDYnVRMzhGWWpKQ0pRYU5MZTQzOElJVW9ueTI1c3J5WEJpSEd6VUIrRk9GOWs1TkNHbUxVbFZPSGZFcnlscjZvQVdlcVFRdWdkd25hT3FPb0JMZU9MRytJellZTVRyeUxCL3dDQ3pOUFdTT0hKK1FLTmh0UTN3M0EraTJlQ2FtajAzYTA3ZFFFaVdKSU5UYk5hZ3dpcnJ3RzZIRy9vdHp5bjJPejRwSkc5N0FCZTV2c3RqeTlXVTRMU0k0emIraUZ1MEdjNDhNaUlZeU5wc2JXQUNydU5CN21YK1V1eVhEOE1NVHBHc0JBRi9FRjF6Q1pzSHkvVHQ4YkFRT2p3dm1xdTdTOFFlSEFXYUw3V2RaYXRpZWZLeVJ4MTFFZytUeWdwbGZ3Mno3Q3F1MStnb0x0Wkx4NU9XdDRuMjl0akR0RXgrcStSSjg4UEY3MUR5ZlY1VlZKbTJycUhFYWlSZjlwU21GN3ZaOVBZcjIrenYxYWFqOTYxT3Y3ZXE1ampwcUNmdUs0WXlzbnFUNG5PSDNweU9tRDdGem5GU21kOTFPcHo5dldMenRJYk83K3FWWE43VjhjcTViOStiWDZnL210Smk3cUFpOWo4d212MGt4clJwYTM2SVM0dFBFM29aK3h1WUQvU0FibnlQNXE1dzdOZUt4MkptRitldjVybldINGs4dUhoQkMzUERIdG5hTGxMYloxNmFORzNRNTF4SWdBemZ2VnBTNXdyOU84djcxcG9MSW5DeHVyR2xNa29HbG9JU25KbGFXR0NOcnA4ZnFhaDNpZmU1VnZTek9sc1RjcWx3YkRYekZ1bHR5VnZ1QlpZbmxjMjhlM3lURkNSVG00cEN0SkUrUXQ4SjVXMDBFRWhEUlkvUmJCaCtVNDJ4dEwyMlB5Vi9oMlhnWEN6TnZrck1ZR1ZrbXZJb2NQd2FXb2NMdFAwVzU0UmxzTWFDNEFXOHlyV2tvNHFDSUV0SEhra01TeHhqTlRXa04rU3NMR1ZXMnhtdXFtMGpMTk43RG9WU3kxZnZKTno5VlUxZUxpQjUwT0w3NzdsVmVJWTdFeUs1ZnBkNUJEWWNZVjNMcXJ4QnRJSEFPSDNGVVQ2eVN1a0xSYzNQa3F5a2xxY1puRFlnWHRQVzYzN0JNdHNwQXg4bzMySnVGMGZTb1Z3UEt2ZkFTUEFIWGRYczAwT0VNTFJ1ZlFvbFhWc3BvdEVaQStTb3BYbW9jUzhuelhLS3MwNzRJMU9JR1Y1NVMrNzkwT3BxV1dMUnlvQ2NRd3ZlZUxLZHk1alZuT08xYXVOUFR5RFVBdmxET3VKZHozeERoeVR5dTk5czJPTWU2Wm9ldmtudEF4OXNMSmhyMzM2cXhqaGJOUEhHam0rYk1WTXMwM2k2clM4SXFUSmlqNzhXNVAzcWVPNGozODdpSGJYODBIRFNKRGNiSHpDMDRScEZpNk9qWTJQMXcrU1dBOERma204Ykg2NGZKTEFlQnZ5WDNDSitZR1NhM3doSGFPRUpvdTBJN1FObFlpVnBFMk5SV2hRYUxJcmJLekVyc0swSXpBaHRDTXhXVWltd3JRanRid2hONFJtYmdKcUs4Z3JCc2pOQ0hHRVp2S2NpdXcwUVJnRU9Qa0kxcmhQaWlzd2tRUm1peUhHRVpvVm1KV21FWUVab1E0eFpIQ3NJcnRrMnRSbUJEYnVqUnRKVDBVMkVhTEsyd3B6ZEJ2YmxWalJZMlI0NVREc0U2SlhrU3JTTy8yNHVwaytBV1EzTjd6eEZUWTIreWFpdXdyT0ZOdktnM2hUYnltb1V3bkt5R3JBVXgwVG9pSlNNdEZrUU5VV2hFQTZweUZiakQyZHpheHNtSXlITTMzTmtJeG1RY3JFVjJ1c3BQaWFCakpiMEdFbG5XVE1aL1dBSmVSbWtYUklua3p0Q0dVdmlpQkYxSnNzQzN1M3h1WDFaN05VM2V3eEMvMlQrNWZLdFZ0SEVRdnAvd0JseVRXMk1FNzZEdDl5OFo3VlAveS85ZjhBWTl0N0w1YTFycjAvM1I5TXZqN3lsSksxRE5sRzJ0dzJkaEF1MXEzRHZOSmJIMElWSGkxUGFHZnlJWHd6elAwSmpsYVI4dXk0OVBsakhaSVd1Y0dnV3NQdlY0Y3lQcVExenlRQ09xcSswTENXdnpCTThBQUN4L0ZMVU1MY1NnREd1RFhEdytJMlhHelN4UnNzY1F6R0k0aUdTNzI0QzB2RWNYRThqako0dm1uNnZMTlg3enNRNXBQUk5ESWtsUkdDV1hKS3F5N21oR0NPZFkvVk1yb1hBTTlGeUhOTlo3ZzkyeStsc1g3UFhVTk81M2RIaTk3TGpXY01qTnhDUjdQQ0RmZ2tKMnhGbFRvNGJYWmtqZThoeEcvbWxvOFVpZHdRdGt6RDJQMUVXdVJqV2tEZmF4WE9LK2ptd3g3bWxwR2trY0tlR2hzY2pOZ3FheldOaXFtZVpuaURyYnFzanhkeEJhNjQrNUtWdFlYa2tPSDFVMkl0SjJWR2FNS2pxR3VMUUZvVlRTKzZQSVcrMU5hWHRJY1ZxK0t3TmxKS0dTUlN5WXlvcDZnOTQwMzRLM3ZBY1RCa2ozNEFDMEowQml1UU9QSlcrV3F6eCtKMWlEd1ZReVFLaVZNN2xRWWsxMUkxdHhleXpISWRkN3JRc014bHpabXNjNnc5VnR6S3I5VTF3ZGU1NkxPbEF1NDVVYlRnZGVZSjJ0SjJKVzU0Zk1XMU1VZ1BXNjUxVHVBYUpBZUZ0V0NZbjNqUUw4SkROTk03bmhsVzJ1dzVqYjdqZE9VemVucXRTeVRYZDRRd3VCMjgvUmJsQ0xlbDBKWml3clFMcjFRMGFDdkE2VHZzc1RPdUxEZENXRXlncW1FT08zVkd3NlF0ZW5hbWx1TGtLRk5UQnJsWExoZTAxUjRRRTlFemdxblo0TGZOV1VWUnNFU0ZNZllkS2RwNXJXVlMyYlVkaW5JSEVEZEdLWnNFRTUyVnBTeWtnTFc2ZXAzQVZ6UnozRzVSeGtJbEV1NDVDbTJIaFY4TWdOazZIamF5c0psU1NEUHNXcENadTZZZEliSUQ5ME1tY1NBRnBzaGtFRk1QZjZJRG4yVkJsdzhPRU54NVV6SjgwTm9KS1RJaEhlNk13YktUSTFLd2FrczZZWWp0TmtOclJzcG5ZY3FXTUNhMU5ya3JxVTJQdVVhWUxIR2JwcU5wTmdsWUNyT0NPOXJCR21BeHltaDRWcEJEeGRLVXpUY0t6aGJzRmZVU2hLUWVHSDBUYklRb3dOVFRHOEo4WUZlVWowY1FIUkZFZHZKVFlBcHB5Z1ZuTUFZZ2hTUko3U2w1aFlJWEE2bVY4a0lTY3NWcnArVW5kS3l2U0pSTE1XSWx0anV2QnlJNGFpdk5qU1hFc294YTI2OFRkWmRzRmdDNktqalo3UXBORmtScmRsZ0N4UnBBTUxHRWRxRkdMcGhvMlJKQXRrbWk2SU5nb2pvaURoTW9RUWNGQUM2SzRLSEtOSWhFdDJRM0JHTFQ1SWJodWlvaGhtNjlJTEtjWTNRcGlkWENBR3lJaTFjSWI0N0t3cEk5UTNDblBSQ3lORXNweUI1S2JJd2VpWmRSNzhJaktXd1JITEJSc0JIQ2s2SWVTWmlwVk45TllJaE5pcldORFRzbG13NnIvTlBkMXVpdzA0c1VaTEtPVm1oeVRxUVNGZDFsTloyeXJwb2ZORWlXVTh3SUNSa2JxdXJxcmdGa2k2QUpHVHNXTVpUVHN0ZlpVZGJIdVZzMVhGYTZvYTVtNVdObDdtaEFwNVdlQXF2YzN4RldzNEdrcXVjUEVWUlk0VElRWkc3Smx3M0tGSUxqaEN4NkVKRzhvQVRqMjNLZ2FhL0NUSUpDem1BaENkWmlmRktiYmhLVk1CYVRza05qRUIwbDdTU2xKSTJ1dTF3VFBmNlJwc1VHVmhJMUphWTQwak51WFd6aHoyQWJiN0xuc2ozVThoYWRyR3k3Slgvckd1YWVvWE1NellYN3ZJOXdISkpUb2hvcXBKeTlteVdZOStvN2xFZ0lEU0NkMTd2QTF4MktjZ2hlWGNiSGRJeXVrYWRpVlpQajA3M0NYZVI4MTBWUlhHc21iZmxKVlZVOTNRcTVMR0hvVkIxSEcvb2lRYVJxOHN6dC9DVWpOV0ZwUGhXNHZ3YU9RY0t2cXN1c2NEWnFNSTFmOUp0QjhWa3hGaVVUaHlFT3R5NC94V2FxcCtFVFU3cjIvQlFBdVpLclY4Slh2ZkNCOFNwdmVIdzdFSDZMQm1jZXFOSUpGd2NSMC9hV0Jpb0hMbFF5dmZia0pLU2FScDVURWcwYmErdmIrMEV1NnVhVDhRV3F2cnBMZkVobXRrSFZUWWQ4VTI0VmJEOW9GTDFOUUxMV0JpRWpUOFZsNmZHaVJhNVRGR2hieVdYSm1ZVHZaWUw0amZoYTBjVkxqeVZrNGc0OVV4SmluSXRLcUtOL0ZrR25wV3RkZlpJUjFqbm5jby92WmIxVVU3T0pGeXljUkN3S3ora1pDNEhVVlRDcEwrcUkycUlQbXV0Mk9qRTI3RE0wU1VZdGNsSHJNNXl6Y1hXb3NsRCtVd3d4MjQzVldROVJMU2ZNbFZJTEFQU1p4Q29uZDRpNzcwc1JVTTNMaFpZOTZjRHVWM2FkVFJhUU5ZN2Q3aDk2ZVpWVTdMZUZxMTBURjVSUzdiWUVxYlIwV2JBN0U0b3g0UUFnUHh3aDJ4c3Fac2JwRHdmb200TUhrbUlzMG43bE5xR3FSWWpFblNrZUpXTk5WV0crNkZRWlprSkJJVnM3QWU3YUJzVDZKRkFxUTNodUlzRnZDRnN0QmlUallSOCtpcTh2NVNtckhzYTJDUjJyYlpwSzdUazNzVG1sZEUrU0t3ZFk3N0xqaFlHVEpTTk93YkQ2dkVaMitGeEYxMS9MR1NudWlqMXhuNzF2T1hPeTJud3hyQzZNWEhrUXQ5b3NIaGdqRFd4bjBRK0dqR3k2amsxRENNbXcwWWE2d0syckQ2WnNKRFJGOTZ1S0xCbk4zZmF5WWZIVDB1L1g1cTNTUm1UbTJlaG9IU2hwQjBpNnMrL2lvSXdTUnNGUlZXWW0wclNHdkFIeldvWmd6aVhNYzFyN24wUzNPaXVvdVROa3gvT0xZN3RhYmZKYWRQbUl6bHgxY3JYSDFjdGZJUzYvM3JMcVp6YkJ1NVBrbCtQUmZ4NmRORGMrTVNOdUJkNTZLeHk5bG1zeCtwRHBOVEk3OVUzbGJLZ3JKV3lWQUdtL1haZEhwcXFud2VBUlFDenJXMlRFeGVXTzFjQk1OeTlSWmRwaGNNZThmTkwxTmM2Y2tSM0E5RXJWMVV0U2RVanhZcXRxOGFpd3BoSmVQUFlvMHpPVTN1b2ZsazdvRjBydnF0ZXhURzJ4dUlqUDBWTmltYm5WN2l4bXEzeUtyWXk2UTNlVVpxWXNha3VTOW9abjFVd3VUYTZKbVd1YlFZWThsMWpwVXNGYTJPTFVkckZjdTdYODVpZ3BwR0NRRFlqbEJBbU5jbkR1MTNOd05UT05hK1RzOTVpZFZUU0JycjhyZU8xUE9qcHFxYXo3MzJYR0t1YzFjam5PTjdsYVdLSnF3WEFxOXBsYVNUdlpPNEw0WGIrU1RmSnBGZ204UE85MW9SUU1qcDJOZnpvK1NWYjhEZmttY2F2M28rU1diOERma3Z0a1Q4d3lZVnZ3bzBZdVEyUHhFb0xmZ1cwNUZiUnV4R0wzclJhKytwWHNaU3lsQzZPU21BN3dXRGtlRnNSYnJManV0OXovQUI0V0tTSDNidXRWdnMzOVZ6Nk1EdVcyODFlaVVaRExUWStpWWpJY2xuY0JPVWRNNlhnSUZFRmt3d0lyVkdla2V3OVZOZ3RaT1VTdklMR0Vkb3NoTUNPMGRFMVJFTUxFTndtQU51RkNDTzVUUWkyVjFZNGxSb3hHYklvQ0dHMktNQW54eHhFeVNKc1JXcURHb29HeWNzY1JMUXhGRTBPRHJuWk1VNGxrYzR4czFBSmVHSnhoY2I5VjFic2Z3V2h4UjFRMnA3c20yMnI3a1VjbTN1WldveXk4am10S1hUVnIyU2pUWVgyUjVBQVRzdHg3VmN1d1lKak1ycVV0QXVCWm56V21nM2FGY2hrdFdpbmp5eXN3MGJwbGdGa0VEZEZZYktPVmx0NXBWMk1nS2JWZ0M2bUFtTFo2bFZ3bS9JeUFqQWNJYlFqQUo4WEQxRVBIUDBKTk5rUU9Ia2hMMWo1SnkyZW92YkplUVFBZ3FZSVViWEM5cEtmTEhpbEh1WitveXhXUkJSdWlVd3RLTG9EVFlwaUozNjFvU3RQaXh4aytTNXFOUkY0RXZ5R1h1TG5EclpmU3ZzdTFCWlhOYmY3Qi9jVjg2MDFOckJObDlCZXprOFFZbTBjZUQrQlhrUGFoWTNpa2srYi9BTmoxUHNjMHN0L2svd0J6NnlrajFNYTcwQ3JNVWUxMU05dDk3S3hqazFVemZrRnJ1TU9lMXJ5Q1Y4RGE1UDBSaFhZNGQyajRjQlZQZUwzdi9GYzBycXVydzQ5NEdsclcrUnN1aGRwMWMrT1p4MzJjUDNyVTZLc3BzWmhNVWpHdFBGeWdadllVYWxVOXZOTmdBN3VvZEVDTnZGWlcyWGZhZ3dGeGIzMVJBUHVhdFV6NTJNUlk4eVI4RlExamp2WUQrNWZMZmFWMk9aandHYVEwZFRPV2cvWUEvSkNhYWphUHZYRVBhS3kxaTlDNklWRUJjUmJaclY4djlySGFwUzRWV3ZxcWVacFlYYXVkbDhqNHRObS9MMDJwODlWcGI4bFgxMmNxekZxVXcxY2p5OEMzalhZc0JZM0hrK2o4STlwT254UmhwMzl3U1FSd0NxTEg4WGd4Y1BrWTFuaTMyQTZyNXBwcWgyRzFIZU5lZnVXNFlObmM2UXg3ci9OUHEwTVdSSTNXUzAwam93QmZqWUpDdndXYUh4Z09zcTVtWllvNUJLWERjM1YvUzVxbzhSaURDVzNTSlFiR3FkbXNZaFJ2Y05nZU9pb2F1Q1NLK3k2SFZtbUl1SE5OMVMxbEhGTTA2Ykg1THJYQUxOSWljN1VRNW9TOHRPNmxxQlV0SkRXOGdjS3d4aWpscG5rc1liWDZKUVBNMU02TjRzVDVxdkpDSkl0cWZGRGlFVE5Cc1l4dVF0bnkvbUlTTkZLOTNpYnV1ZllkVnRvSkhzZDl2WldFTWpxV3FFN1RzNGdiS3RLSWx4T3UwZUtCc1phWGNyWmNHcmcxampma0xsOVBYRi9kdUI2QmJMaG1LMkRXM1ZGeE5LTE94NU54NFVOY3d1ZnNTQnVWM05qMjFVY01qT0N3Y2ZKZkpkTmlqb25ST2E3aHdLK2h1enZNN01Ub1kyT2NDUllicXBLSmR4czNHYTh6V3RBNDhsbUJuZHRBY09FV0lOMU9QUllJdklmS3lxdUxzdlJZR3VlSHRzQjBRS1J0bmJvcjR5U2JvVGZBNWNvYlkrYWZ2QUNFWndzMnlqU3lnamRabGVOMTBKTW5SZnptNVZ3NXcwaXlwcWJaMTFhdytOb1hUbzFISmF5c0tTcHNSdXF4N1MwTE5QTVE3bFBFczJ5bnFBNGNwMm5KQnVTVlEwY3R3TjFiMDB1b2dJMEpraXo3MEVBTEZnNjVRMi9DRmp2ZE95SVUwUVBLRTRlaUp5c0VLbTBHQkkzNFhuT3NwNlZHU080U21HanpKVmwxeWRsQ09QZE5OakZrcG5hSWpZQlp0ZFpOZ2hsOWlxak9RVkVqSHNWS24yZHVvaDkwU0p1Nk9KWWZZZmhqMUVXVjFSQU1BdUZXVUxSdGRXc2JiQVc4MWVnWitUdVdVQUJJMlQ4TGVFbFREaFdNUFJhVVdVR2h5QmwwMDFuQ0RBUWpoNFZsTkNaSUkxdGdza0tQZUJSTW8zUXRpV21UdlpEbGVMSWI1d0VyTFZKTXBEb3hNeU9GMG5WRVdXSktpOTkwcjMvZW15cXVYSmNqRXcxKzZOcDFCUUROcnJ4ZFlva3pyVFBhZlJGalo2S2NVT3BIRVdsV0JkZys2dUY0TXNlRTFHeTZtYWRRRnNWWUxIaE1OQ2tJYktiWTFBTEI2YkwydEVmYXlYZHlob2xoUWJySThLaXhFYUE1U2lXZTd5NHRaUk1Xcm9tVzB3TzZuM1lhRjJtY3NXampXSklRVHdpdE5pc2tYS1p0Wnh5Uk9ranNPRkdwM0tORWRJc3ZHRXZOMGFpSWNnVWNZTE9GSHVEdnlqMkxObDRrMlJiUmJrUnBQRGUvbW9WTHRSMlJJR2szK2F4SkRjcDBVY3NWTUJjTDdyMFowQTdvc3BNWXNveDA3cEdsTnJnNEtTMUFKc1VsV05EK0V6VjB6bU91cStZdVNuRWdHV21OdXFSblpvQlZuTEw0ZnVWWlZ2dUNxYzRzc3hrVkZaSmE2bzZwL0t0cTNjbFVkUUR1c3pLaTlqa1Z0U2JrcElzdVNucFdicURZdXF6cEY2TWl2N29nOExEbVg2SjZRRHlRZEk4bFh5dmdMR0lPcGk3b2lRVWhEdHdyR09JRzJ5WmhwTlR1RXVDc21TVkNSb0M5bXdWYlYwZmQzdU4xdkZOaDJxUGNkRlQ0dmhwQmRacVRsaXlZNW8wT29qN3NuWkRhV3VCQ3VwTUxmVXVJQTlFckxnTTBGelkyVlNSZWpOR3VZakdmRnBGMXBXUFFsOGJ3VzdycFUxT0dYRHdMK3ExWE10QUdNY1FPbDBNWlV5MHFhT1BWY0xxZWN1NlhVMlRpZG9HeXM4YnB4NHRyS2lwbmQwL2RhbU9hb1c0TmpVc0Z4c1NsSGFvendtWnBqRUxuaERqcUk1VFkydWw3eGlBbjlaMHNwdGpMVVNTRUhkdjRLSnVCd2lVenRtUVhEb291RGlENGJySWt0MFJXeXR0d3U3Z2swSVBpQjVhUG9rS3FpYThId2o2SzRjQjVKYVdPNFhWbG9zYkRWcXJDV3ZKOFA0S3RreStYazJ1dHZrcFhFOElYYzZEd21MT0E4Vm1vdXl3KzEvRWtxbkFYUjMySzM5clFSYXlXbm9SSWIyMlRscUVjOEE1MC9BcFhjTktDL0I1WWh1MWRMZ29ZVHlBdlZHRndTRFlCSDd5anZ1eHlTb29aYm53bXlTa29YK1JYVy84QUorRjd1R3JFbVVZSEM5bW8xcVVMZW1aeDExSTVwNEtrRzZlVjFHcHliRzY5cktzbnlUZTVDWjd5Z0hwbWFEcURmUlNEd2VxM1AvSXd1TmtPWEpMMk5KQ0paa0I0TE5WYTFoKzBVVm5oVmxQbGlhRnh0ZlpEL1Jjck9XbEY0cURXTm9XNzh0SENMRldPOGdzUHBIdE83U3B4UWYwVjFaRUdsUVExTGlFTU5kSzdoSEVBUm9XQnJoc3VQS2drZzFGaHpwTGJHeXVSaFpnQUliZmJxRjZna1kxbndoV1ZQVUIzeGk2clRtbVBUbzloMkR0cUNDOXR2a0ZzbExSUVVUYldCK1lWVlNRVkZYSzFrREhibm91bVpRN0xjUnhreE9lMTRCSXZjS3E1Q3BaVWpWcUtrcWEyUU1wb2crL291bVpLN0VxM0haV1MxTVQydDUydXV4NU83SHFQQlJESk14a2hzQ2JncnErSDAxRlFRTlpGRXlNZ1cyWFVaZVRXYnVEVGNuOWx0SGx1QmdNRFh1Yisyd0ZieFNVRFRZQ0ZqQU5ocGFBc09yWTJtN3BCWWRFbmlHYVlhYU02TFhIa21xU1JsNU4yUTJLS2lpaEdwNXNzdnhta285cnR2NmdMbCtJWjVtYzh0YTRnS3QvVGMxVWJtUXBxeW9TdEpLUjFDdHpPeDRJYTRBZWkxckVjeGdCM2ovRmFsVVl5V00zZGRhL1g0L3FjUmRMbE11NDhMUmZZcGo3NVhFQjUzOVZWYUhGK3R6bkhydVZUZnBFU0FrOHBkdUxUVkJMUTArU3F0bDlZNlJ0bjZWaWpZR0MxK0ZhWUxhYVJydWV1NjFUQ2NHbnE1QTU1SUYrcTNtaGpnd3lJYW50dUVTWlhtamE2ZXFkS3hyYkJnQUE4T3k5VllyQmg4WmMrUzV0MVdpNG5uVmtUWE5oRzQyMldyVldLMTJLeUh4UERWYWNnSXdOMHhmUHpTNXpZM2owM1ZBYXVmRlpMdWM2eDhpcTZtd2xyUUhUU0M0ODBXZkZZcVJsb3dDUnRza2JoNmlraTZaS3lnajNzVGJxRjZucUgxc3pkSTJ2MFdzVTh0VGlsUUxCd2JkYlZUVFJZTlRPZExhNGFlZmttUllEWmFacHpCQmxuRENTNEE2UWQva3ZpenR1N1J4VzFFMmliYS9SeTZIMnpkbzhrMVBPd1NFQUFnTDQ1emptVjFmVlNndkozV25pUXcxek1PS0hFcDNYY1Q5NnBlcUpQY1BMdWJvWFZhc09FZE11SGhUTkR5RXU3NFV4UThoQkx1UTZmalg4NlBrbFFQMWJVOWpZL1hENUpZRDlVMWZjNG8vTUVtZVlQQ0V6R05KRDQ5aVBOQ1o4QVJXdVZ1QlVueUdjK1NwdDNwdUdvOFhkVzBhU2dNUld0VnVMS3JRUjdMT0hrci9COUladVJ3dGZjMjVUVk5NNlBxVllTUXBseGlsVXhoc1BOS05zYkh6UzhyM1NuejNURWJBQU4wNUlyeURNUjI5RXUxd0NZajhWazVJcnlMT2xpdlpPR01CcWF3YkMzVDBMM1dKM1dKS2NSa3RQUEN1KzdUUmpQT0ltUHlCV1FMSzZvOFBIY2FpRW5MVEZ6aUxXMzhsUENtZ0hrYkZHODhvN1czVWZkaXc3WFJJdzhFZUZjMnlYbWMzTU1DV3VFZm10dnlmVVZHRHZmTEc4TkIzV29TV0wyK2EyQ2hyZTZwclg2S3pVVjVsRE5LTEc4MzQvTGlsYTh5T0xycWliMFJwNVh6eUd6UVVhQ2dmSmE0MlJMSkJlWU9LTVcrd0ZvdUZteEhtbjIwQWJZYjNUdFBna2xRTm1YQ0x4Y2ZxaXpLQzlDcGFOWEZ6OGtSclNPZGxzTWVXWFJOdkFESWZYelFoZ1ZWUExvZkZwMzZKajFHblg4YStaU1VOUS80R1VyVzNSbWp6V3lzeUppQlpxaGdML25kQmt5Umk1M05NUVB2L0pBdFhwNysrdm1kZUhVdGZjZnlLUmpMK1pSQkg1cTlneTFXeGpTK0d4VUtyTHRYSHYzUlZoYXJUdGZmWHpLa3NHcHY3aitSV1JVK3BNZTZlSGhTWmh0YkUwM2lzRXpEVFZSWTY4ZlJkdzVZU1gzMFROZzNOUFo5Q3NrcDdPc0FtNmZEaVpXR3luRFR6Q2MzWXRnd3h6QTIwb0RUOGwxWnNjWlA0MTh6a3NWeFVkZ1dod3kwSjI2THJmWWFEVDR5MGNDeTV1SnRFWjBnV3N1bGRqOVhFMnZqTG5XSzhYMStzcWJVL1AvQUdQWit6KzNUdFhEeS8zUHEwU2QzVHhXMzhJTzN5VlhpN3dLVjdpRHduNkdUVlN4SG53ajl5cnN6U2dZZkphd09sZkdwTGxuM3JENUh6ejJsVHNucUpCeWIveFdoMEVHblVZeHBOK3Eydk56VEppTW01SVd2dEducFpJWnY0YW9RbHhldG9wcmEvRGZvRWVVUVk1RVJVTkxpUXBUTWEva0EvY29SRVJtdzJTbXpValJ5RHRYN05xQ1dobWMyTGNnbmtlUytMczdaTTl5eEtYdXdBQTd6WDZNWjR3aVN2d1dad2IwL2d2aHp0Q3BmZDhkbmlmZitjdCtDNG1Xc2tMWEJ3N0ZLVjhHeEhWVlQzUzA3d1dnL1JkRnpEaERZMjY3YkUrU3Nza2RuYk0xek11MG5lMndWcUVrWlU4Y2t6bVRxNmVTRUEzRzNVSWRGaXRSUlNYRGl1dzV5N0tKc0pER3h3blQ1MldpWWpsSjFCVDZ0SnZleHVGWlNURnFlMFRnemZPNXZpZWRrOVE1MExKQTE1TmxxOWJRaWtkZHQvT3lBMk16RHlJOGtweEQ4UTZ6VDRwUjRuRjRqY24xVlRpbUdOZ2ZyWU51Vm9kTFhTWWZJRHJkWWVaV3hzemNLZ05hNGc3QUpUZ2QzSmdLN0NuU0VTaTNoM1FCaVowQ0oxL0R1cnVPb1pVeDN2ejVLbnhLbThSTFIrQ1E4WkRZOHRZbjcxVGt1ZHVEYmRiRmhsWit1ZGQzQjZybWVIVlJwSjI3a0JiWEZWM2paSTF4RmhjcXBMRU9qSTZSUlZ2ZU9MU2RsMFRzMXpHK2hyWTR5L1NDNisvelhGc0V4WVZyV3NCOFEzMlcyNGJYbU9lTnpYRnR2SlZKNHk3amtmWW1GVi92VlBFNE8xWEhSWFlpdEVIVzNLNUIyYVp2YVkyUlBlSEcxdDkxMmFrbEZRd09idUNxa3NaZWpJV25oczI2VDduVTVYZFV3Uk51VlhBaVJ5ck9JOVNzeEZGcEd5SEs0NnJKdHJBd2NwZVdNRjF3Z2FvYWc5UHMwRlc5QlkyM1ZUQ0FHMlZqUk0zdmNvQnlIYW9ocmVVakhMYVJSeFdxQUZyOUV2UlM2eU9xYllwbzJlZ2tKQXVydW04TnQxUVVIQVZ2U1AzQ05NVTBXb21ObDc0enloQTNhdkJGWWxvT0Y1Q1pMdWpDVFpKYUlqMXJCRGM2NFhuT3ZkUkhoTjFYa05paWJCWmVmTnB1b1BxQTBkRW5OV2pkVjJ4eWlIZlUrcWl5VFVlVlhHcURqc21LYzZpRlhaM2JSYVJOdUUxVHR1UWw2ZHAwaE53TTNSeEFsd1B3a3NJVnpRdEQyaTZxSUdxMXBkZ0ZlZ1VwOHN0SVJaTnNkYXlTaGZheVk3N2hYWXNxTkQ4TWg4MFFTK3FTaWsyUkEreFR0d0RqWTA2YzJRak9VRjg0c2twYXF4U25NRFlXRTB1M0tycDV5dk1rZElpaWxNZzNTcE5qSW9SZE1WNkx3bTZiZmgzSjNTM2RrSDVKUExaWlFVemRFYUJuZVdLQXpib21ZNWVFNktZRW1peXBveFlLY3JiSURBYkRsSFlDN2xYYUtsbVlQa2pGMnk4MXR1aXdZeXBRTGtDYzllN3dvdmRlaXdZdlJTZ053RFVTVjdTajl6NktKaEs1UWRnMmdCRWFOSldPNlBxaUJ0bEtPV0ViUFlXVTlSY2h0RmtVRlNpV0MwYm96SXJySTI1VTJ6V0hDc3BGZHRuakhaTlV6QTV1NkRydUY2RnhKOGthUXBzbkpDQzlUTkxjTHpnR2k5MWozcDdSWUM2T2tKWjZLQU40V2U2dWVFTnNyNFQ0aHp1dlByQ0Jld1hZb1ltZXFLSnJ0MEtKN1l3UVVOOWQzdHhkS09ZNmNraS8zSnJhUWFJVjhvTHJCSm1Gc2dKL2lqVkFrRFNMWFd2MStKUHc5M2kyRjdLdkthRFNHcDR0elpWdFRFNEE3Rk1VMkpSemtkMjdVU3JCeFlZcnlBRGJ5VmVjbFFhUnBkWUxFN0txcUkrZGxzbUxHRXZPZzNWVlBUQXRXVm1hTGNEWDVHRFVvaGdURlhURU82b0RCcEZ1cXk1OGx1TFpIM0xWeHV2Tnc0azhKMmticGpOL05Nd09CTHRsVnlNdHc0RW9xQzF0bGM0Zmh1dHc4SlVxS203MlhoYmRnMkg2V2k3ZndUc01iS21lZEZmRGhnYkhhM1JLVm1DQ1c5MjhyYlRSa1A0UlphTzdMNmZ3VE1tS3lyRE5SekorQk5vWEZ4WjF1b3kwVVZSR1c2ZDdkVnV1SlV2ZUFqU1BvcUNiRDNOSjJXWGt4MGk1RE55YzV4M0xsbk9jeHZHK3kweXV3NDFiSE5jQ0xHMit5N1JWVXAzQmJmNWhhbmptQWlvYTU3RzIrUVdjK0dhdUhKWjgrNW13UXd1ZFp2MFhQNitFd1B2NUZkL3hyQ0d1RDR5MjU0NFhKODI0QjdtOTdnQ25ReVVha0thTlNmTjcyMjNIVGRWTldYMGpyajhGWkZ1bHgrYUhQR0h0TngrQzBWQ3hEaUpVdVBFYk9KSHpUcmNhamZ5ZnhWRlhZZVNTVzNIeVZMTUo0eWR6OVU2T05BdE0zMk91aWY4QWFIMVJSTXc4RWZWYzJiaVUwTHQzSDZweUhNYjJEYy9pbXJFZ0xhTjljNEQ3UStxZ1pXanIrSzB3WmpQN2Y0cVF6SUI5cEs4QWNzeHVQZnN0WkFtMG5xdFlHWlduN1FXRG1GcCswRUx3c1lzeHNBY0dySnFCeHV0Y09QdHY4UVdSbUtNZFF1ZUN4cXpJdTVJekh1RHp1aHRrZGZsVmtlTXNmeTVOTnhHTWprSXZCWlk4YUkyWmkzZ3FacUhnY3F2ZmlETjkwRnVKZ25jcWVGSTU0cUxNVmJyOG9yYWk0M0txVGliQU9RbDVNWkRlQ0ZQRGtkOFJGNjJ6VGU2eTZacEZpRlNRNHFEMVRiYS9VTnJJRkpodUtDVHhNZmNrS25xSTRkOWs5TlVPY2JXU2MxSWJYMzNUWXRpSkpGSFdSc3ViQXBWc1FQMlNyazBaTHVFMUJocGNSNGV2a25LeERLS0xEUzg4Rk93NEk1MzJTdHdwc0FzR2tzdHQ1SzBnd3lHSWVMYjdrSElTWnA5TGdUaGJ3cmJjQnlVN0ZKV043czJQbW5tQ2toSUpJRnQrRnNlRlo0b3NNMDZlN3UzekFRT3dKV2I5a1hzb3A2VU1sbVkzejVDN05oRTJINERDR05zQ1BKd1h6M0IyeHR0cFk5ZytSQ0RYZHA4c3dKRW4vTWw4bEdhYlo5QzRqbnVPamFTK1pwSFN6bHJOWjJyeGx4YkZJVjgrNGxuQ2V2SnRNN2Z5Y1VyVDQwWXpkOHJ0L01wZ2EwRDcvd0N4MzEvYUpQUGY5Y2dmNVdPcVNRWEUzWEk2SEdJNXJmckQ5VmVVZUtzWThIVmRBMkd0SnQ3blF4Vjk3dnVwKy91akd6Z3RTT1pteHhXQkhDRkJqVDZoMng1U3R6RDhOUk5pcThYYys0dWxZWUhWVHJrOHF2WTg2cnY2cDFtSXh3c3NEdW1ick9LS1JZTXd3dHR4WlAwOE1OUElDUXFta3hPYVp3REdod0t1NlhDcDZpeGMwaTZsV2NrMFhUY2VqcEtid1h2Ym9xU2JGcXJFNUNCZXg4d1ZjUVpmREczZmRTZjNGR0RZQzQ5RjNzVXBLMlZGUGdvQjF5a0RydWJJMDFmQmg3TkxPZlFxdnhHcnFLOXhhMGFSeDRVS213U1ErS1F1UHpLNjVESXhSbWZFcDY0a1Izc2ZNSnZDY0dkVmJ5RHIxVDlCU1J3Z1hBK2ljbXJCRzN3Z050NUJjVnNKcmdQU0Nud2xwdU4xby9hSG1zZDNJSTNwckg4eENLSncxYjJYR3MyNDg2WXkyZGNXUFZYSXhaVmt1VGovQUd6WnBkRTJWclgzSkJPeTRISTkxVzk4aFBydXQ2N1Vhc3o0Z1JxSkZqMVdnRHlDMllSb2ZRTXlhbmx2a3NXM1VoSCt2S0pZSzVGOEhhQk8rRk1VUEtBN2xGaDJVWktPcTQzL0FEdytTVy8xYmZrbWNhMm1IeVN3L20yL0pmZFVmbHBzTEg4QVdXY3FMUGdDS0dwOFJEQ3hwbGxyZXFYWU5rVnI5MVlUSzdETmJZN29qU0FVUFhlMXQwOVIwaHFDQUJjK1NzcGxkazRYTnR2Wk1RUmh6dWRsS2JCNW9HNm5SdVlQTndzaHd4dmFVMVNLN0dYeHNhQnVGS24wbDdmbW94MFUxUzRCclM3NUJiVmdXU0ttcTB1N2w1LzlLYXBwQ0pKbTBaVXBtdndsNUlGN2orS284VHAzQ3NjR3QydXVxNVJ5Tk1NT0xURTRHNDVDdDRleVdTcm0xT2hPNXZ1RmVsMWFDWGN3RmhiZlk1TkJUdmJSdEFieWtac0ZxWG03UTdkZlJOUDJORjFNMENJWHVyR2k3R3BuT0Y0eHNzck4xcUs3V1hzZW1iOGo1eHcvSnRaVW01RHJLMU9USm9CdUQ5RjlRNGQyU3lSTkFFWVZwL21UbnJCY3hnZGQxbFQ2NmsvUDZHaEhSV3V4OG5SWkttbWVMTkt0YWJzL3JIZ0JzVHJmSmZXZUNkaURSSU5jYlJZK2kzV2c3SmFHbGFOVEdYSDlJS3BrNnkxNW5YMEZ0K1I4ZllMMlJWZFFBVEM3Nkxac1A3RmF0N2dIUk9hUFVMNjZvOHI0YmgxZ1EwVy9wQldycVBEaUJvQUJ0MWNGbVpPdHpYbS9rYW1sOW5rL1Q1cytXOFA5bnQ4N1E1MngrWDl5czJkaDBsR1EwUjZyN2NMNlJiTFQwZjIyMi80Z29UWmlvSWg0K2ZtcWI2NW04djJOV1hzN0N2TDVuSU1zZGlWUFJnR29ZeDl6ZXpnVnNNZllwaGxSTzB0aGliWStSVzZOek5UelBBM0xWY1VsZFRsZ2N4dytxb3oxV3JmOFJwWWREcE96aWE3UmRsMkQ0YkNHdmdoZjAzdWp6ZGwyRFRRdTAwOE56NVhXeHRxWWFza09Hbytpd0pEVC9KVUhuMVc2OXhyUTZmbzJ2dS9VNWZWOWpsSEpWSFRFd0Mva1ZpczdFS0owZndSL1FycHI4VWpqTnk0QS9OZS9TdmZnMmVDT2VWZGhxOVdsOTRYUHB1aS9EOVRrTTNZYlJ1WWJScytoUW91d21qMHV1Mk1mY1YxMkRGV3lCd0xyYjIzSzlKVTNZZE1qZnFybUxxdXFVZnZHWkRvM1Q1OTRmVm5ISSt3V2hNeE5vL1BncWl6RjJLUW1jQ2xEUUFMZUVGZDBwcEpIdmY4QXJHL0NlcXFZOFVpcEtndGx1N2Zva3JyT3E4U3QzbjZISjlGNmNuOXo2czV4aHZZL1NNdy9US0dhOVBVRlV3eTFEbEhFV09CYUJxQTIrYTYxaW1LeE1hSHNjQUR2YTY1UDJoNHhIVk9acGR1SkFlZlVKMnExbWZMRG1RdjNMUWFmdEQ2bmRjdlZiS3FpaHNRZkMzOXlyODJ6ZDNTU0MvUmE3MmE0eWFtbWlhWFhzQUUvbmlxSXAzYjlGNXVTOVQydUdTNG80bmprUHZGYzhxZ3JLUXhnMkMyMXNQZlZMM09CNDZwS3BwQksvVGE2cXlOL0RMZzFXS2prbWRZQXB4bUF5a2c2VHl1aFpheW1La2dtTmJxM0pER3gzN3Nxc3pUakk0eFdZREpWNFcrSHV6Y3I0bTdiK3oyYWd4MTh4YVdneVg0OUYrbnpNQmhoYVFZbkN4WHhiN1V6bzZhdERHeHViZDVISG9WSHdhbUYrSndmSGVNWU1KcUlYNmJxdzdNS21URGFvYUdrMmYwK2EySVlJK3Z3OHZhM1VMRTdmSlZ1UllHd1l5SUh0SXU4OC9OU00rU3psMDYyMmZXMlZleDZQdEJ5cE5WZDBESXlIVUxqZTkvNzE4Yjl0bVZwOGxaa3FhT29oY3lOdXdKNDVJWDZjZXpKV1JSWVlLVWd1Wkt3Tk52bUZ4VCtVTDdEV3V3K294cWhwWFBlNlM5MkRVZG5BOVBtcjBKOEhsTlU5a3FSK2J0WGhjY2pDNHVCdnVxU1dtYXg1YTBCYmprakxtSVpqcTVhYVNDUnBiS1dXZXdqZ2tkVmJabTdOcW5BUUpaSUhOQjN2cFZxaW9zak9WVjFFN2tnOG9Mb082QUlPNjJhcWJISjREWUh5SlNFbEJzZUQ4bHphT2pNcjZYRXBJVFlrMlZpMnZiSTN4Y3F1bXA5QjRRbXNkZnlRN1I2a055TnUxendybkI2d3l3dWpjZDdXM1ZORTY1REQxUkRNYUdScGJ3ZkpWWlJHeFp1T0F5R2lxN2wyeEZsdVVGY0dsdGp6dXVad1luM2pXRzlqZGJsUlNkNjJNZzMySFZWSnhMdU5uVk1vNDYraG1ZN1diTDZaN09jMlJZaFRNRDNDOXI3L0pmSG1FVGtsclE3aGRNeXZtaVhCR3NzKzNSVTVSTDBXZlVOWGlNZFJjQndTTFpkTHJncm1PSFoxTXVqOVplNEJXMzRWaTRxMmdsMTFtdEZpTE5wWkozalVOdDNYU2Z2b2lIS2JwSjJ1YnlFaVNMTVdZZE9ZbkoybHJ3MWgzNktreEdvME9PNlFPS2FHa2FrbGxwRCtJWXJxZTdkT1lIVmQ3SmE2MHVlc0xuSHhkVnNPVkpTK1lJeGJPbFV2aFlFL0RKcElTRWUwUVIydnRiZEVoVExtRitvSmpUc1VoUk92WldOckJHS2FBc0ZuSXc0UWc2eFdYU0xra0xTTWsydWhQa1EzekVFb2VvbmxVNWxtSkNWNVBWSnkzSU82WmxjQUNxNm9xTk45MVViTE1VUmlmWjI1NnF6cEpBTExYUGU3RTdwdWtyU1NOMHRoeVJ0OEU0c242WjRKQzF5bXFDNERkVzlGS1M0STRsT1pzRUFGZ3JHQXFzcG4zQXVyR0VnZFZlaDJLa2x5UGcyQVJHN3BNUzhKbUtRVzVWbE1yME10Zm82ckFxUFZKVkZSWTJCVVd5Y2JvbXd0cFlhaThjcUJweTRxTU1ucW5ZenFWYVVtU2pOUEEwVzJUb2pBYnNGR09HeU0wYld1ckZGVk1Ubko4a3FZZlJXYjR3ZWlFSXJIZ3JpanlOM0NqS1F1NkppT2dPMnliaFlBblkydHNyVVlpWlNGR3cyQUNLeU1CR0xWSU5UU3ZaQU0zUk83SGtzMkhtcDMyRzY2QzJEN3NlUzhZd2k3ZWE4VHNvQll0WlFjYkl4YWd2YWdHMlFMbElJWkYxa0VxRXNLTCtpOXVzTk4wUU4yVUpaNHlDeXl3Z2xSOTNLazJFdFRiQm9jaWEyM1JUTEIwU2dlV284VWhIcW1KaXBSUEZycjc4SnFBUkFlS3lYa25CMkpzaGQyNlEzYVJaRW1JY1JtcmN4N3dBQXB1b084Z3VCWTJTeERZemR4RzNxc1NaamdwV2FUSTBXSG1yUEFQUGtKREQzeHltL0NUcmNRand1K29qelNtTDU2Z2djUTE5K214V3I0dmlYNllZUzJScHY2cXRrbFNIeDU3bXgvd0NWTkliM0xicWx4V3Jwc1ZEZ3h6UVR4WmFCaU1VOEx6WndzcXo5UFRZWklDWGNIb3N1ZVZwajBqWnIxR0J5Rjd0VDIzdjl5czZUTmNkYTN1M2tSbmpkSllWamxQbVNOc2N6aGZZZUkyVlptTExENlFkOVN2WjU3RUZJZVd5eW9teXp4eHZCYzJVUFZjNmU5d3RQdy9NRlRSUEVjNzc5RmZNcTJ2YUhCdzMzNVZhVXJIeGlGcVJxU0ppTjlrZVNvdjFXR1RBOHFwSWVrWWpmWnBDYXBtWEJLVmxib2FTRVNtbklZUXFNMldZbC9nd0RxZ0JkRG9LY01qYnNOd0Z6dkx0MzFEVjAybGI0R2ZJTFEweXN5dFU2SmU3Z205bEowSUxiV1ZoRkFDMjZITkZaYUU0R1RHYnNwS3VqYlk3QlV0VlROMzJDMm1XSFdDcXVzb05pYkxNelkrQzdHYk5Zbm9HdnZzRlMxbUhOYkc1cHR1dHZrZzBiS29yNk56aVZnWlkwelR3WkhaeGZOZUdlN1NQa0hISzVSbVdObGNKQnRjQzYraE01NE02V2pmWVhObDg1NW9qbHd5cWtCQkE0NFZaY0cvaHlPam5OWlNHTjc3ZVpTRDJrYkxZSzU0Y0hGVWt4R29yUmptWm83Uk44V283aEtWV0d0Y3cyYUZZdUlCM1JtYVpBQnlyVU13cVVUUnNRd3Nna2hxcFpxUjdEd1YwcXNwR09ZZkN0WnI2Wm9KczBxeXN3aHhOVmRHNGRVRitwdlZXczBZYVNrYWhsZ3JLa0oyQ1RwWERxVkFUU2VaWG4vRVBtak9ZQTBKcXBnN1FENmg0SEpTejZxUUhrbzB1MTBCemJwcWlnZVFyY1NrakhKUjRzY2t1QmNxc1BpTnJGWkVkdDF5a01VbWJERmlUbmpkeFJ6VkZvNVd2TXFPN3NteFZsOXQwRFF4TmxvSzF6amE2S3hwazZxcFpKWTNUVWVJQ08yNlcwR2k3cDZZdHR1cldBTWFQRVF0Y0dNQU5GbkljbU5PdDhTcnJIYkxQaUczRjhJQjNDVWZXUjdpNFdwdnhwNXZaNlNueHR6UWZGdXJNY1NGT2RtNFNZaERIdVNFQitaWVlPQ0xoYURWWTFJODIxS3ZkTkxPN1kzVmhZa0xjam9GUm4yVmdPa25aVmMyZkt1VWtOZThLaWd3dXBxckFBbjVCWDJGWkNyYW9nOTJmNnFCNGtER1RiQk56TFh6bTRsZlpYZUUxYzlVUnJrUDNxN3cvc3dyQzBlQzMzTFlLSHMzcUtleDBmZ3EwNEpGMktURWFCcll3Q1hncXducVdsdGdVK3pKTlUzN0IraWhVNWJscGg0bUhiMFZWb0x3aytTclpLOGIyS3c1OHNyZ0JjSzJwNlVQRmpHNFcyM0N6N29JMy9BQWtJQnF6cDhFY05nbVpwSmVWdU9GMDc1ZzN4TFhvNUN4dnlUK0g0NGFWdzNOZ3VOV2NsTlNOdEdEU3lnYVNTckdnd1dvaUk4RGlrOEN6ZEU1N1d2SlcvVVdZS0l4TkovZWgybE9mTEU2VEFKS290QmFXcTNaa1M3QTR2Q0l6TTBEWER1N2hYTk5qVHFpTDR3QlpkaWlpNXNTdzNCWUtCd0RtdGRaWG9tamEwYUdEN2xWdm1CY1M1MS92UjZTVnJuQzZ0S0tvVTVzUEkrU1hab0lCU3pzSWZPYnVkWlhNYjRtc3ZjZlZMVkZjR0U2WEQ2b0hGQzdiRlJoMEVRK0Z0d2d5OTJBUUxCZWtybWxycmxhM2lXTmQwOGhya2loMFd5MG5xR1FBK0lMWHNReGt0amZaS3oxY3RTQ2RXM3FxMmFRUFk1cDV1blFYSllTTlJ6Smprc2tqbWkvSzBYRnBUSkRLNTM3Slc3NDFSdEwzT0lYT3MyVjdLS0NZQTI4SlduamdMbEErZmM5VGQvaWpoZmdrTFZ5M1NRclhNTlYzK0t2TjdqVWYzcXZlQVNGclVjRnk2MHhVbGw4WU1wV09GMUVCTzVSWVVKM0tKRWpJZFl4NytkRzNSSngvQUU5ajQvV2o1SkpndXdMN2hISnY0UHl3ODNpQkc4QkdjdzNCNklRSGdSb0hHVFlxM0RFM3lKbGk4dzBjalhOMG5sRVpUdEJCSktBSXd4MXlVMHlNemdCbTVQa3JrWUtQY3F2SnM0Smxra0x3V04xRDFXMFpGaGpseGFKOVJzME92Ym9wWld5SGlHS3N1STN2Qk8yeStnZXlIMmVxakZxcHJwZ1k5eDhRL3VTTW5VSVFRckpvWjVleFU1dXdLa3gzQllvcVJqZGV1L2dhQWVua3EzTGZZUldaZ2thTzVmWW0yd0srNGNvK3psUTBVTFBlSFJ5MjZPQi9KZEx3UHN6d25BdE9tQ0s0OHJyeitwNjFGV2swYStpNk5QdTB6NDJ5ZDdMRWtiMkdTQ1EvTnBYYk1DOW4rbnd5QnVxbjM5WTEzOXVHVXRNTHh4TkZ2SkRrbWJ1TklYbmNuVlhObTVMcEtTT1FVM1pYSFNQQTdnTkgvQUFMWUtYczlwKzdGNHdOdjJWdDlScmM2NWFXaEtUNHBGUk1KZktHL05WMUtVaGJ3eGo1RkxEa3FuZ2NBVzdmSldYK1M5RTFnMDgyL1pWVlZaOHc2QXUxVk1kd1BOYWRqUGJSUVVnZUk1V09JOGlyRWNNcGkzT01EcEZOaFVORzYrZ0Vlb1VxL0hxYWpGaTFqZnVDK2Q4WTdmWGt1RVJkYnpCV2s0bjJ0MWRlOGtUUGFQbUUrT2hsSVU5WEZlaDlSVjJkcVdKaDBPYUQ2QUtpbHpzMlJ4dEorSytibWRwVWoyK0tVbjcxWFZuYWcrRW5TNGsraFZtR2dhWlJ5WnJSOUNZem15eHVKaU4vMmt2Qm5vMUJGcFR0dDhTK1pjUTdTYXlxTm02OTFHZ3pkWHc3NnBOemRhVU5GeDJNckptZmtmUjFabXlhYW9hMFN1NS9hVlptbk5NMUhTdGRySXM3elhJS1BNOVc0OTQ0dTIzUU1hek5VWW1PN3U3bE85eS9JcmVMTDFPODVPenJEaU5DN1hKNGdiS1ZUMmtNd3FlUnJacjc5U3ZuU0xNZFZnMFJaRTkyKyt5UGgyS3o0aEk1ODhqdDk5MTMzQitnbjdWenJ5UjlJNEgyMnh4ekVTUFp4MXNyR2Z0eWlhRDRvL3dBRjg0Q1pyWGt0a0gzS0Q2OFRQQUVub2t2cHR1MmpuMnpxRjVJN3BXZHFveENXN1pBTitoVm5oT2ZRd0RWTCtLNFZSUDBORHRhczRNVUxlSDhicm51RFhrRDl0NTc3STd0VTV1RTBmZ2VCOGtKbWJIUlJPOFpPM211TVUyYTNnRUZ4Mk5rNDNOUWtqY0w5Rm4rNXk5RFF6ZFhVbDNPbHhaL2RITzRheHg1cUl6UWF3bTVHNTVYTEtmRjJ2cUNTVmJIRkJBd0ZwVTl6Zm9jdzY5Uzh6YmNUeFZ3amNkWitxNVptckZaSDFJRnlmRU92cXJXcHh4OHdJdWJMVk1hckdHZHVxM3hEOTZQM1ZvVm55ZUkrR2QwN0hxd2lPTXVQVUxZYzVWM2V6TkFPMTFvZlpwV2lHamE1cDZoYlJJSFluVkcrOWlzVE91RDZEMDY3UlQxVWV1RVdhQWI4Z0lOSmgycWR0eGRYOWZoL2N0MDI0S0RUVTVaTTNaWU00dXoyMFpKUk9oWkx3bHZkTk9nY2VTM3NZYzFrWjhJMkhVTFc4bWVHQWJkRnRzOHdZMHAyTmVwWGxKM3dhdlUwWXFaRHJZR2dHMndYeUw3V0haeXl0Z1pVUk5KSXVUWWZOZlZtWmNYOTJhOHNGcmVTNDkybG1ISE1HcU85Y0M0TU5nVlZ6UzRQVGRHbmVSTnMrRnNtNEdHeG1sZTI1MGtiajBWZGptUVc0TlhlOFJCd3ZkMTdXVnZtT3VseS9tS1JrVERwdUI0Zm1ycXBxaFcwQWZPZHkwZkY4bG14ZnhIcTliQnZIYTlENmY4QVpnamtwOEhNcm0zRFl3Ym41aGRkenJtM0tHWk1PbndYR0o0dS9EWFhhNWpYYmtlcDlGeGpzUHh4bEpseWVLSnQzR0t3dDh3dmlqMm1NNVpwdy90b3JvNlN1cWFhQzdRQTIxdmljdHpUcStEd0dlTk4yZHZ6SGtiS21TczB1cUtkekJFNTdwUDV0b0c1djVyVGUxT3Z5NW1EQm54UVBqN3hqQ1BDeG9LMXViQWNmelBsTTFzbFpNK1ZyR2plMStQa3Zuek5sRG1iQktxYnZKYWgwWlBwWmVobjAyV0ZianlzT294d3oyeVp6WE9GTU1MelBQSEc0bGdHMzFLSFQxb0FHcjhWZFZ1RlB4Q0QzeWUvZU81MWNxZ21vanVHclBsbWVQZzlKanhSMU1QRVg2akhncVhmM0lWVFFoZ3VGaWdna2JKWTNWNC9Eek5HaFU5NE1ZcUwybXJ0QmVmS3l5N3djNy9OVzg5QUlMN0pPU24xOUVxVVIwWm9YamVYRVdOckxiTXU0dHBBYTQ5ZXExQ1c4RHJXVHRMVTl3NFdOdXFwVGlYWVNPbllaaVlFNE45cnJkNmVwRlhDMnpqY2I3TGtlR1ZXdG9JTzYyckRNWmRUZ0FrcW80bHhNNlhoZU5Qb1h0RG5iZXBYVU1wNDc3eUduVitLNFhRWWcydWoxRGtiTFpzcjVpZFNWZ2pKTnIyU2NrZUMvam55ZDhxc1dMV2dYNnBuRDhXQnNOWDRyU1pjVDk0cGc4RmVvc1ZMRDhYVlpjNDhtcEIyYnppRmVIczUzVkRMVytJK0pWOCtMYW1XdXF5U3V1N2xJb2Z0c3VYVkYzOHJlc21NMXVhVnkrbXFlK25hQVYxN0pFR21GcmlPaVhMc0EwYjQwYVlsaHB1NEtENUJheW0za0pBcG90YUkyc3JWcnZDcWFqZFpXSWtzRStJbG9tTE9LeTlvYU9VdExKM1l1a0tqRUR1THBFNWhxQTFOTzFwS0M2b3NGV1NUdWtkZTZuSk5adktveWRzZEdBZWVxQWFWUlY5WUFUdWkxZFRacDNXdDRoVzduZEJRMVJHbzY4T2VSZnFyR2txQVNOMXFMS2l6anYxVnZobFFYdkFWcHZnWk44RzgwRXR3RnRHRk40SzFuQnFidkdOSlcwMFpFYlV1eWhQdVdqWkFDRTR4OW1oVTRtOFNPNnFER2NwMFpDcXN0VFVCZzVTOHVKQm4ybFR6NGtBRHVxMmZFZFIyY3V2SWdZWVdiQS9GUVRhNmJpck5WdDFwN1p5OXdOMWJVMVRzQmRDcFdQY0tSdE5OVWI4cTZvNmdXQzFHbHFPTjFkMGRSYTI2dFJNN0l1VFlXeTYrcUt4bDk5MVdNbjBnRzZPeXZIQ2RkRktpeURnMUVKYTRKQVZJY0VNMUpiMVJLZEUyV091WUFiM1dCS0cvYUtxYWpFZEk1VlhQaXJnZGlqOFJIZkNiTnVGYTNZWFUyMVRUMVdsTnhSd1BKUjQ4V1BtVjJPWkFlQ3pjTy9iNXJIdlRRZVZyRGNYTnVWUDlJRWpsTzhSTTZzVE5pOS9BNnJIdnd2c1Zyd3FTNzdTSzJvQUh4SmJtZDhKbXpSVkdyeVdKZ1hjS2daaXdaMVJQMDRMZEZiOFJDdkNaYnN1M29odUpIUlZMc2RZT1NFcFZaa1kwMnVFTHlvbmhNMlNKNHZ1bUM1cEMwczVqQWFTQ2hETTdpYlhRZUtpZUV6Zm16dGRZRkdhV1c1WFBtNWxlNDdFcXdwc2JkcHU1NUh6WGZFUXJZemI1SVdTOVZrQmxHd2ttL1hkYVhWNTNwNkpydFVyYmoxV3NWSGFoSFZPY3dPc0wyNVhmR1NKNGJPaVZkZTE3OW5iRHlTTlRtbUxEbUhVOGJlYTVuWDU4RVVaSWZ5dEZ4dlBVbFc1eld2TzY1N3drTVdNNmhqL2F4RkV4NFpJMi93QTF6NnU3Uko4UmxJYkliWDZPV3B3d3lZZzRsN3p1ZXFzb2NJWlR0MWJFcktsbDU3bGxScnlMUnVJejFGaTU3ajk2c2FTdWZUdHVYdVB6SzF4MDcyR3pXRzNvbW1UT2VCZTZTOHAzYVhFK0xkK2ROd3Ercm9mZUFYRWxlcGcwdjNJVE5TNnpDR2xKZVFsR3ZNZStqbXV5UnpiSG9iSzlwOHpQWkJvZTh1MiswYnFwbGhZSG5VUWlHbmhNZDlZdlpWM2tROVJQVmxReXVlWERicnNzVXRhNkE3dU5oNWxWMDByWUhuUzRLQW4xOEpUeUlZb0cxUTR3MHRBSkNhanFoTHV0TWJNNXB2Y3AybHhVeDJCU1hrQ1VXYmZEVmkrNXVpdXFBNGkxbFJRVk9xeHZ5bjZkeGU5cXJ6ZTVsdHZnMzdLa0JrTENBdWowUTJhUFFMUjhseER1MjNIUmIxU2l4QzF0SGpaNTdXUGt0NFdYYU5sQ1dLNUtOVGJ0Q0s5Z0lLOUd1RlJreGxSVU9hQmRJMVJGaXJXZU93S3FxbHZLemMwZUMzQ1JUVkVlb213U2swVjJtNFZzOWdTMHpHbGh0WmVkendOUERJMVRFYU5zelh0TFFmdVhFTzAvSTVyQkxJeGxyWE93WDBEVndFRTdMVmNldzBWVVVqWE52Y0VMSmxEazFjY3o0V3g1NzhPbGtqZUxhWEVicWxocWU4Y1hMc0hiSGtjMGJwcFkyYzNPeTRxd0duZTVqaFlqWlBoSTlOR2FhTFBhY1dIUG9vdGQ3cWJuOFV2U3lsanJsU3FaTy9hYks0bmFMQzVKeTFySmhZa0pLYWtaSmM4L2NxZXZxSDB6eVFTbzBtS1BrSUJ1bzRnU1FMRk1NY0x1QUsxMnFrY3dGdGx2ajVHVkVOamE2bzVNTFpKVVhOclhWeFowaW80R21QamwxWDA3S1lrY1JZcmZUZ2tCajRiZFZWUmx6dXlTQXJFZFNrS2VOczFaMERwTjdJYm1HSTJJVzJSWVRZV3NscXZCZFc0Q2V0V2hid3MxcVFXR3dGMG8rOTFzdjZLTHRySUUyQ0cxN0xzYzZKTEEwVUlBUXBLdnVqc1ZaVFlVOWh0dW8vb012TjNmaXJheXBvcnZFMEtzeERVemF5RTZxY1hKbXFvbTBqTnlFaEhVUjdnMjRVYnNPTWFKUHJTMTNKK3E5SlhreDdIb3E1NUxwRDVYVExkSWkzdHdpU1NGTk9RSVlpNXJqY29IdkQ1WGJtd1huaHBmc0xwbW1vMzFyMnRpWWI4YktTeUpJN0hDN3NFeWxNNUFiY2tyZE1xWkZxY1JmSCtySkRqWmJiMmM5azFUaThzYjN4bTNPNFgwdmxYc3Vwc0dnajd5TnR4NWhaODhwZmc5aTVPWFpZN0cyVXZkUGZHNDNBTzRYVHNMeUZUMDhUUUlXM0EvWUMzbHVDTmpEUTBEaE8wdUZ1YjB1cWNNTHV3WlprelU0TW9zWi9xZ0Ivd3BzWUJBeTEyTi9xcmFwS1p6QmJTVWhQUlNYTzVXakRId1ZuTGN5ckdCVTdtMjBOL3FoVk9JNVNobGNiUmorcXRwaHBaQnlTcHpVK3h1VXh3b09NV3pRWFpHaW5hZE1kajZOVkhpbVNQZGJrTVAwWFRHQjBCTi9OVjJJa1ZHMWxsNUpJdHFKeWVUTGJqZXpUOUZWellSM1JQT3k2d01PYnVDQnZzcUhHc3V1aWE1d0YrcXBYeUdvbWkwOUsrTjEyM1Z4VDFkVkRZYjJIcWxuaDFMS1FXSGxOdzRqSHRkZ1ZxQTFGN1JZdEtDMi9LdmFiR3BiRGUzM3JVR1lqRXpld1RzR014am9FQWxvM1dueG1RamY5NnRLUEZITTNkd3REangxamJiQk51eHd5dEFhMnlnTFJ0dUk1blpDMytjdDk2cERuUmdkYnZML01yV2F5S29xemU3Z0VHSEJuM3U1LzFVQW8ycWJNTHFwdG9YWHY2b2NFYjVuNnBicXRvbU1veHlIa0t5cFozVk1vQWJwQ0ZuWlZSNnNqcUdiUU0xQzZYZmhkVkxLMGxoRzI2M25DcWFOa1lNa1lmODA3TXluYXd1N3Rvc2p4OXlvemxtTllGSTZEeE5JTnVpK2Z1MXFGdERES0M0Z3I2aHpWaU1VTk5JZElGZ3ZqbnR1eDczcXFsWXgzMnVCODF0NFVSSTQxVWVLZDU1OFJRaWl1NUo4MUF0V2lFUXR1c09GMU03THhDZ0RBMldRc2xxOEJaZEJPczVnR21ZRGcyNnBObXpHcDdORFBlc1JqZWZDQTNwOXlRY3hyZ3hyVGV5L1FHUEFvOHMvSzJYRjRYS0RENEFwTmxEWGdBRlJZSGgya051dHZ5VGtTdHpWVXNaSENYWE50Z25UelJ4UktVY3M1UzIwVlZKZzh1SmFBeHBjVDZMdEhaWjJGMVdZSHdsMEIzOHd1djlrWHNzejFENFpxaW5rdHp1MGxmWkdST3lDaHl4U3hqdVFITjgyQmVkMVBWRkM2L2MyY0hUM241ZjdISGV6UDJkamhVY0luaWJZMlBJWGQ4dTVDaHdObDRXQnArNWJkRFNzaERRMWdBRzJ3VExiQmVWejZ5Yy9NOU5nMGNiNVFyVEFzSGozc2orQ1lFa2NLWllEdXEvRXExdEZBNngzV1Fvenl5bzFXNFlZMlJxOFZwYVVGcnpwQTZrcldNWHpwaGRDWEh2NDdqcDNnWEdPMmJ0WGt3SmtrYkhnRjF4elpmS2VOZHBPS1ZWUkpON3hMcGVMZnpwc3RyVDlPYzBtLzJNVFVkU2luUy9jK3g4NiswQlE0VkMvdXA3bG82T3V2bi9BRGg3VGMxWTZTT0daL2x3VndxcnhPcXhCNUw2aVYxL041S1RsdzU3bTZ0eWZWYjYwYWlZYjFEa2JuWGRxK0s0aktTMmZ3bnpCU0UrYkpubThqeVNlYkxXNk9rbER3ME52ZlpYN2NxVkRHQjBqQ0FSZE5VSXdGTk9ZVC9LQVNNOE43b0xhNnVtZjRIV2I2aE9VZVgydGRjM3Y1STlYcm9MQmtZSXYxQ1lzOElpbnBwUGtoRkhJQUFYQzU1VGxOZ3hxWGFuQzRVTVBvbjR0V1I2QWJjR3kyOFVqTUxwN08rSWpxRVMxTVVjZUJzMXVlbXA2RVdMVGNKbkRIaXBqSkp0WTdYVVh3bkVLNTF4NGZSVGxvUkNScEpIeVQ0NnRGV2VtTFNHUndZOW9QUkx3UnVGUTRramhCanJQZG1XL2VoR3FkVVB1TnZrblIxS1pXbGdvSk9HeVB1N29xMnJ4djNWd2pqSkhSTVYxUXlNanhiMldyVFZBa3F6dmNYWG9JVGd6T2s4YS9oTm1wOFVsTWVvdTNLakJWeXRtdVR0ZFVudnhobHQwVmpEVW51Q1NBbjdZc3BaSncvQ2JqVDRnZmRoNHh4NXBadU9PamtJdjZMVTRNUkllNGFqYjVwbHRhMHZPNlU4Y2ZRcFN5US9DYlkydEFpSjFibmRlcHNSQkxydUgxV29QeFVQMkRrTDMwZzNEeVBrVXBhV0w4aFB1ODVjMmIwM0UrNmx1SGJmTlBOekIzb0FMcnJuSXhiUUxhemY1ckZQakppbkIxYktTMHNWNURJUmxqT2hTNCt5TUhmZGF4akdNZC9VTXNmdEQ5NnBwc1RNemk3VllEZmxJdzF4eEhGSW9XYm5XMzk2cDVNTVZabzRuS2JSOVFka3NScXNOYVQ1amxkWnkvZzRNN3lRdEc3THNEZEZoVUowa1hhMC9ndXg0UGg1amh2Ym92bXVhVnRuMXZRNDNHaWp4YkNHdmxkdHNxV1dsRWNvMjRXN1lwVG51aWJiclZxdU10ZndzcWZjOUh1cEc0WlRlR3hENUs5cjU3TmN0UXk3VTkyYkVyWktxcEQ0bmRkaWpqd2NYSno3T3VKTlpTeTI1WERzWnhhZXNmTkRyR2s3V0s2dm5Va01sYmZtNjR0anpEU1BmSjk2enN5NE5ycE0zQ2F2MU9SZG9PVm9JYWlTcGthQ1J2Y0ZjcXhMTUh2R3FLSjRHbncydjVMdHVZWlJqTEpZeWIzYVY4NjVueTVMbHZHVFVYZVdYTGlIRTI1dXMxUDRqNkhKckppL29mUTNZVjJoeFUxVkhSVHVMZFpETjlscFB0bDVhOXl4cVRIS1J1clZLM3hOMzJEdlQ1cm1kRG0yU2lxYWFwaWRvN282anBObDAzRXM5VW5hWmx6OUgxYjJ1a0FMcjdFM3QvY3R6VHpTbzhYck1EM09nWFlQbmY4QXlyZ2l3cDhsZzRoaERqYmpicXVpWjQ3RjZQSEtiUm9ZNXpoKzBGOHRZUFBYZGx1WjJ6d0E5enJMN3VOdXQxOU9aQTdWYUhHcVZzbFZVZ1M2YjZiMzNYMEgzekhxRnRQaHZ0Tmp6YVhMdXgzMjh2MVBsYnRvN01INUxqZFRSUjJEWFdzM2ZyNkxsK0VaUmZWdnM1dTVQVmZkZWRzc1VlZTY2cG0yZXd0TGdRTCtaWHovQUl4bEg5Q1lrNXpHV1l4eDZlcXA1ZW54bjhTL1l2ZEw2M2x4NmZiSyt5OHpqOWRrcDlIWjNka0R6c2hRWWFXc0lQa3U5dnd5REdNTjBsalE1cmVqVnl2TStITXdlVjdRZU50MWo1TUN3dWpZMGZVcDU4bHY5em45WlNDUnpnZk95VC9SdWtIWldjb2RQUDRCZmRiTGh1WG4xdE9BV2IyOGxVZEhySTJjNXJNSjd3RTI0M1ZNMXJnNDZ0ckcyNjYzVTVKbWhMaUdFaTNWYU5tYkxjMFJjV3NMZmtxMGtYOFlsaG1JR0o0YmU0OUZzOE5Ucmp1RHV0QmpENk0yZGNIMVYzaE9LM05pVlhjVVg0eU4vd0FzNHIzVDlEbldCSzIrT1VRdWJPMDM2M0M1WEhVSHZBNXB0OGx2R0ZZa0gwSllUYzZlcXB5alk2RW1tZEp3TE40bllJaTRyWW82dzJEZ2VkMXhqQzYwMDFaY213Vys0YmpyUTFvSnZ3cU9TQnJZWm0yR3ZkeGRRTlVmTlZMYTRQOEFGZEZNL2ZDdy9CVVpSbzJNYnRHeTVkZDM5WTBjN3J2T1YydGlvbWJqNFZ3dktFZjY5aDlWMlBCNmp1NFdDNTRWYVhZNDRtM3d5YTM4cDhXSUNvcVNxYTYyNnVLYVFPSVNQTVRLSlpVMjFrNXIyS1doMmF2U1MyQjNUbzloVFFPb3JkUUl1cXlXVzdyM1daNUxYVmJOUFk4clBsWllTSG16V1FwcW0zVkppckFIS1RucTlqdWw3YkhKR2NRcXJBN2hhcmlGWjRqWXByRmF1NE5pdFZyS3p4bTVUNHdHSkZ0VDFYZU81VzA0SEhxYzByUUtTbzFQRml1Z1paT3pTVU1reEVrem8rREVNaUN0b0plZDFyMU5VQmpCdlpOdzFvUFZWM2RsWnd0bDJKTitVdldWV2xwOFNyWDRpR0M5MVNZdGpZYmZ4STB3NDRpd3FjUkl2NGxYbkVTWGNyWHFuR0RPYkFvdE5NNXpicERiTkR3a2phYWF2dmJkVzFKVkVrYnJWS1J6aVZjMHRUM1JDWkNUSytTQ1J0bExVY2JxNXBhamhhdlJUZDdaWE1GU0lBcjhKR1ZraHliRTJxTGdCZFpFMXQ5UzE1K0tXUUpNWk51VTF5S2l3czJuOUk2UHRENnBhb3h6UUNOUzFDb3hteCtLMzNwR294NEUvRWxPUllqaE5tbngwdWR5VU51SWlVOHJVcE1aWTRmRW8wK0t0QnZxUzNKajFoTnpGUVBOUk5ZVzlWckVPUE5lYkZ3QzlQalJBOEpCVWkyVHdrYk1jU3NPVmlQR3pmbGFrTVRkS2ZGc3N1eE9PRWZGdXJTbXdYaVJ1UngzU1BpUzhtWmkwbnhMVFpjWWE0Yk9WYlVaZ2JBVGR5RnpZdncwYitNekIzMmxpWE1yR011WkFQdlhKY1R6ckhSZ2hqd1NkOTFxK0o1eWtld3Y3d2djN09SK0l3TmlPeDRqbmNSUHNKUHhWZFBuSFc4V2t2OEFldUExWGFGNDNONzI1OVNpWVBuTnpnVFVQMGkrMjZCNUdUWWo2R1ptMW5jN3ZGN2VhV1puQnV2NGx3OXVjV1N6Nld6RWkvbWpZam5OdEZENEhnazdibEI0ako0YU84ME9jb2liNnh6NXFPSzUvd0M2aUxZM25qb3VCNE5tV2FyZmNQTzU2RmJDTVFmSTBBa241bEc4cFg4Tkd3WWxtU3J4S1Eya3NENXBFVk0xTTYrb0hyc3FXb3FKR0hZVzNUbE5PWFcxYnFyUE13bGpSYVBxNWFxT3hQUkx3WWU1MG91T3FhcDNnQVhBVFRheGtaSEd5clBPd3ZEUmEwOUdhUmpUY0RZSXI2c1dzVGRWVlJqSW1zMGtEYm9wUjZaRzNEaVNoZVFIWVdzVlpDQ0FXa2twK09sWTl0d1FMK1pXdGE1Mk84TExoTlIxTXN0aGNqNUZLZVFtd2NxbmU3T3VIRDdpa3BjYmNQRFp4K1FSUGNUTHU1emo5NlBGUnNZTnhmNWhKZVZrMkZWVVRTeTdpKy9va0ttcW5oYmE2MnZ1UVdXMEQ2S3Vud3Z2WGs2ZndWZDVDeHROV1pQTE0vZTZ0YU9JdXRkTno0YzJFZkRiN2tNTlkzZzJTbmtEU0cvY3c1blQ2cGFXaWMzY0RqZFRpcW1SbXhjclNtcVlwQjBLUzhqRG9yc1BySG1RTklJdHR3dHJ3eHdlNW00VldLWmhhUzFvdjZCVHc1am9xcHBKTnJxUnljOG5FclIyYkp6YlJ0NkxkSURZaGFGbGV0QWdhTDJXNDBWU0hrYnIxT2l5eG93OVhCM1pzTk82d1RHcEtVMHcwSXhtQVd6S2Q5akVyazlQR0MwcW5ySTdYc3JVUzNTMVZiU2Rrbkt1QmtXelhwRFp5Vm04SFZPMWhzNHF2bU4xZzVvbzBjVGFCU0FQYnVxaXRoYWRXeXNuR3lVbk43aFprb0doQ1p6UFBtVDQ4YXcrWnhacU5yTDQyejdnVHNHeGlSbmR1YU5kdHg2TDlCUlR4Z2xydHdUd1Z3RHQzN1BCV3d1cW9vYld1NjdXMjgxUmp3emV3NTdkSHk2NDJpQkc5MWhsbURrS0wyR2tuZFR2NUhtbEp6M2R6Y3E1Q1J0NG5hRXNYQWtKS3FZQ1kzRFlwMnBxMjNOeWxoV01hZW4wVjJOTWEwV0RIdWJZZWFNNEVOdndrbzhWaURnSEVLd0RxZXJqRm5uN2tQaE1Ha1NwSHVrZGE2ZmxjMlJ0aXF5RXdVcnZqS1ltcWFiVHRJVjFZbWM0TVBZMXAyUDRyQWphL245NnJhbXVqWjhMaVVtN0d0RjdGRjRVampjVVhGUlJzaGFYWEgxVk5WMWpJeVJmOFVoVjQrOXdJdjhBaXRlcnNVZThtMzcxZHg0bVZKNVViQytzaWRja2o2cW94TEgyd1hEVDlGUXZyWlhHd0orcURMR1Fia2svTmFNTWRGR1dTeG1veEYySUMyLzNwV1BEWEYxN2hHWTh0WnMwSXNCZkllRTZrZ0ZKaWJvUzBvVDJQY1FBRDlGZHdVSGl1OWJIZ2VXSFl4T3lPT1BWdmJZS25rekpJdFk4ZnFVT1hzcXk0bzlnRVRuYWpiWUx1blovMklXbGlrbGhzRFk3MkMzL0FMS2V5ZHRGREZMUER3UHROdjBYWmFiRG80R3RheU5yYkFEWm9DeThtb3RseHFLUlU1UnkzUzVmZ1kwTTNBdHN0c21oOTlBMEEydjFTOEZLZFEyV3c0ZkNHTkZ3UG9xMjl5Wm5aWmVoV3c0YThXdW5tUk5nYnVucFhCaDRBV3RZemlMMlBBYXRGWmtpbEdNbXg2b3FZaGU1L0ZWY2xXMXhPNHQ4MVcxTXBtaXU1eEI5Q3FLdHhBMGpUWngrOG92ZURReFlaTTJlYXVaRXduVUI5NjF2Rk15Q0Z4czhHM2tWcU9LNWhsbDFORGlQa1ZyVlRpRXJpYnVKKzlkOGV6UmpoWnZFK2MyeTNhQ1ZtbXhsczU1WE4yNGcyTWtsMjkxSnVZMndPRjMySHpXZkpOajFqT3NSeXRrRjcrdkttK1psYTNRNzViclFNTnpwQTBBT2xHL3FybG1MTW5JbFkvNkphaTdHUEhTSlk1bDZNQXYwN2NyVVphT0prbGhZL2V1cllkU3R6Tmhzekc3dWpaMFhIOGVwWnNGekRKU201MDI1K1pUNHVpdExnZk9FYWh0YjZwdWp3SXY4bENPb0xtdCtRVm5TVlpZRndYUk51WEJ0Y3Qrb1Q5UGgwVUZ0eHQ2cEthdWRiblpMQ3E4V3p5VDgxQUdpK2RKR3h0Z2twWFNQSkRlcU5oMU0rcHRzU3J1TENkSUYyMis1UUdqWDZQRHBZblhsOFFKdnN0cHdqRDJQSUlicCthWWJRUTBiUWIzUE80U2RiaTVnQkRBQVBSTFlFallwYXVLZ2pzOGduMEtySnNXWkpDK3dLMTBWRTFlOGJraS9tbkt5VnRKVDZDZHlPcWZpVnNydGNtbWRvZUppSERKM0IxdkQ1cjRyem5pYnNSeG1acGRjYy92WDBGMnpaMmJoOFVrSWVQSHR5dmwrcW5NMVc2cEp1SGJMZnd4NERVUUJHL0tpUlpGNTNVRmJPVVFzc0hoVDg5bEYzQzZBMERJV1doWnVvbmxjQW82L21DUFZPMGNHeXJZV0NJODZuSGdLOHg2bmROaU1iR05KSkhrdWpkbGZZZlc1dnhPbTFVempHNXczTGRsOTR5NnZhajhzWTV2VXVtYXgyZGRubUk1c3hhSVIwMGptT0k0Qy9RcnNGOW5hbndXT21tcW9HM09seDFBcmV1eFQyZU1MeVZRUXl6VXc3MEMxd1I1THVFRlBIVHNESW1rQUN3WGs5VnI1U2JpbWVoMDNTWXVwdENHSFlEU1lTeGtjRVRHMjI4S3RITWM1bzNzdlJRblhjb3N4UFFyenVTVGt6MFdQSEhDcVJFRGdMQk5pcE5OMWlRaS9JUWR4dUpJbHF0R2ZrdEV6cGlmdWxCTk01MXRLM09hYnVvWGttMWdTdUI5ck9jUkhTVkZNMlFiMzZxN2dwT3pLMTdkVXZ6UG5MdGF4MXVOWWxLeTl3eC84Rnl5WmtUbW1MdXhjZFZzT1o1eitrNUhuY1BkMFNiS0tQdSs5MDNMdGw2TERxbEJVZVY5MmVSMmFzS01oNXNPcXZjTXd2dndBNGZWTlVtR0F1SkxiQzZkRXJhTTJHeXRTMU5saU9sb20zQ0tlbHM5d2FiYnB5WEhJYTZQdTJSaHRocFZmUEs2cWFiSGxDdytoWkU0a2MzVkxKbXN0UnhLSTdCVG5XWFhSYXVtYkt3alFDU29hM01jQjBWbFRTeDZMdUJLcFNrMldVbFFqbHRvd2VvSGVqY3V1THB6RXBwSzZjT0Z3eTZoTEIrbEt0aFpzQnR1alR5Q2pqN3UyOXJiSjFNcU5JVUFiSEtReTEvUlltc1Q4VzZTam1kSFdQY2JrRVdYbmF5NitvZlZXSVJiS3VUZ1BOVDZtWHVrQlUrN3V0YTZMVVloM0VkaWZvazJUTXF3Zk1oYVdQRlprNUoweWM1am5lUEdOK2kxeXJkSFQxSjhRTzZZbXBxaUdiVUhDMTFyZGZKTDcwZFI2clR3NUhablN4WTM1RnVhZ1MxSG9yc1ZrUXBlUmV5MHBsYjNjcnV1M1JHWldQTVR2RjFXOWliYUtzOEdOK1JiKy9BU3ZzZXF5SzRseDNXdXhWTHU4ZGNvd3F5MTUzVG1pczlQajlDNDk0TFhYdmRTYlhYNnFvTldUMVdHem02T01nc1VreTU3NHZON29zY3pYdkcrNnFtVlZoeXN3eWxrNEJjQmRTYjRBeXdUWmJ6VmpJb0hpNHVRci9zaHdGMk5aaWE1emJpd08vd0I2MEI4cnFpdVpFRGZVNnkrb3ZaK3ljMkowVTVadVc4L2NzVFVaTnFkbXZvZEtwMXdmUk9Sc0tiVFlYRzNTTm10SDRMZnFTSU5oUHlWZGw3REJGUld0YmhYcllOTUx2a3ZsT1NkdG4xYlQ0MGtpcHJJdThpV3YxOUVOeXRwZkhkbkNycXFqMUE3S201V1hwSXBNUC9VdlYvRy92SXo2cXE5MTBQMkN0YVNNNk9pNnBEY2NiTkZ6dmhwY3g3Z05yTGl1WjZQdm1TTUFzZUY5RjVsaEUxTThXNkxodVo2YnVLaVEyTnJxWjRjR2pwMTRiNE9ENDNHN0NxZ2s4Y0xUYzY0UEZqVkU4dHNYbHZUNUxxMmJjTEdJTmVRTnh2dXVYVlVrbUhUT2JKdXdFOExBbHhJOW5wY3JsR21mTmVZc1Rsd0RFblUwa2J0TG5hUVNtYVRFNnFpalpWVTBqZzIrNGI1TG8yZnNoVTJaR2lwamFOYlBGdVF1YnVZN0JXR2prYWJEYlllYXVZcHRIYzJKUzVOdVptbWh6RFJhSjQyZDZBRzZuY3IxUmhOZFEwZ3FLQ3BlRzJ2cFl0RFpoaG9HdWthUmR4MWJGWDJCOW9zbEE1dE5VRnhpK0hnclR3YW1XSjNaNHpXOUd4OVMrOHZ5N213NFgya1k1aGRFR3lNbkp0WW5aVStKNTRteENDUjBrVGc4bnF1aDRRN0JjelVqV2pTSEg5cHdDVXhQczFwQkxwakRIQjIvaGNDdC9IMVo3YWJQTVpmWmlPSGhKZk5uSGpucXVwakt5TmtsanRzdGZxYW5FY2ZxeVhSU1dQbXU3TzdLNlNJQnpvZ2Irb1Z4aFhaOVFRTkRoRlkvTUpHVFUrTHlUVGRIV0IzUnhiTFdUSGg3WFRNNU45MTBMRGN0aU1ORFdmUmRER1RXUGUwUlIzMjZLOW9zb2U2eEJ6b2p4NUtqdVBTckhSbzFMbGFLYU8wa1kzSFZheG1uczJqa2hlNFJqNkx0OUxnelpYYk50YmZkRHhURFdTVXpta0MvSEtWS1E2S28rRnM1NU9kUnp1MHR0WXJUb3FLU2tmdUxMNm16emxWczgwaEVaTzY0OW1MTElwbk9PaXlXMk9UTldwcHYxVnlyM0JNUThSYVRzcWRsR1dNY1BWRW8ydWdjNDhKRldXRWJjYWxvbHVQTlgySDFoYzlsbkxSWUtreVBOeXRqd0tidkhDNUhLUmtpWHNNcU9oMDlVQkFMbm9uOE5xQTUrNjFhR1YxMmk2dmNQYVc2U3N2SXVUYXhTNE9nNWNxaERJMCtxNkRRNHgrcmJZOUZ5U2pxTzZMYkZiZGcxV1pBTHVXZkl2VWRJb3NaMGticmFNUHhacmkzZGN1YlVsaEZpT1ZlWWZpWmFXK0pJOHhUUjFxanJXdmFOMGFSNE45MXBPSFl1ZEk4U3VHWXBjZkVueEV0QmEyVU5CM1ZQTkxjOHJOZFdhZ2JGVnduTGlkMEVzYURURFNURWRWWDFGU1FEdWpUdjJLcDZ1WTc4cXZ0R3hZcmlGUVhOSzFIRXFrdGVkK3F2NnlZbHJscDJNemtQS2JGRGt5Mnd1dEJrRnl1alpleEpqR04zQzRwUTE1WklQRXR2d25HeTBEeGhTVWVEcmlkbmp4WnBiczRJMEdLQzN4TG5kSmpSYzBlTWZWTS9wdlMzNHg5VlRsSGtGUVZtNFZ1Tmh0L0V0WXhQRmpJVFp5MTJ0eDV6cExhcnBkdGVaWEFrOVZFaTFER2paNkNSejNDNjJDbWtzQUxMVnFYRVk0MkRmb3JLaXhoaGVMbEE0SFpNMnltbTBqaEhpcUhPS3BmMHJFR2l6eDlWR1hIV1E4RkNsVEtXVGszR2x4SXdOQ08vSG5PUEswcUhNRWNvM2RiNzFHZkhHTTRkK0tzUmRGUndzM2FmSEFHODlGV1Q1aHRmZGFoUGp3SStKS0hGUTgvRitLS3h2aEpHMFZHWVNTbFpNVEx6OFMxNTFTMTU1L0ZaTlVHTnVYZ2ZNbzBySnNvMkJsV1hmYVUzVjNjZzNjdFJseDlsUGY5WVBxdGF4N1B3cGc0Q1VmVkVvRW82VitsOVJPbDZ5L05NVkczOWE4ZmV1Q3lkcTRveTY4aE8vUlUySTlwTW1MYk1lZnZ1bnJFS2JPK1YvYUpBME9FYmhlM1FyV3Y4NEVzMGhCY2JYWEZQOG9KR091OTZqVlp2YlNpNGRjK2lqaFFtVE84TXpxNE0zZWVGVVlqblF2SkdvcmpNT2UzUzdYY0I5NmhXWnIxZzJmdXFzdTRseU9nNHptMXJXbHhrRGo1TFdLak9zbFdURXdHM0d5MHdUMUZkSlp4dTBsV1VjVU9IUmQ0NjJxMStVN2FLc3Y2ZHpRZTlsZUI2RmVxY1NkV3lCbE9kSTR1MWFwTlh6NHBJR1FraHQrcXRvSlc0SkdMN3VPL2hRTkUzR3owMGdwSUx2bHUrM1ZSamtueENZRHhGdDFyMUkrb3hXb0RyMlplKzYzWERaWU1QaUFmdTcwS0NpV2JOZ0VEYVNOcGRhKzNLdG1ZazFzd0hTNjB4K1AyY0d0dVI2S3dwYXZ2R2EzRzN6U0d5Rzd1cUk1b3dkbEpsV3hsdHd0UVpqV2s2ZFNQQld1a2NOMGg4aHBHM2ZwRVcyS0c2dkozMUtoTlhvWmN1Q1FxTWM3dDFnU2Zra3VJWnQwRmIzendMMld3VXNuZHhBNnI3TG5kRGlobGVOTjdyYnNOa2tsWU5SMlNXYzJsMDNGeXgybnV0U2VvM3ZsY0NHRVhXTU1vb1pTM1hHU1Z0Mkg0UkRGcE9sSmJKU0sybW9aWkxiRUt5aHduYnhGWGNVVWJHQUFicnpxWnp4c1FsTmtwRkZWVTRpRmdBbG1SWHZzcnVvb0M5M21wUllacEY5S3J0Z1dhMVZZYSthK2tLcW13T1pvSjNYU2FQRDJ1NWFoMW1IZ2dnTlNaTUpNNURXVUUwVHVTbzAxVEpCOFJLNk5WNWZiTUQ0VnJPSjViZEdUcGJkS2JEVEFZZGl4ZTROS3Y2VXRlUTdaYWdhSjlJLzRUOUZkNGZXRU5BT3lxNVp1SStFYlIwUEJjUjdrTkYxdnVDVnZmYWQxeDZnckRjV0szL0t0ZmZUZHc1ODFvYUhWTzZ2ME12Vnc0T2xVODJ3RjA0U2RLb3FPbzFFVzNWMEgzWXZiNGNtNktQT3VOTW5HZDFpY0F0VU5kbEY4MXduWkh3REZGWFZ3M0pWWk96WlhzbG5YdXF5b1p5c1hNeTlCRlRJM1lwS2NHNVZwSXpsSVRzNVZCbHlKVjFFTHJGd1BDVHgzQjRzWndXZUo3UVhhTGJxNGEweVhZZHJyQXBqR0hOSjJjcWJqUlowODIyZkJQYTFrNTJBWTVNOEN6YmdiZk5hRk5UZDZ5MTE5WSswSGs3M3FLV1pyTG5WL0ZmTHRaUlBwWkh0TzFpVkU2WjdEVE80bW9ZalFGanRpa29xSXZkdVZ0OGxBS2hwdVI5VlM0aFN1cENkS3VRa1htaWt4R2lzUEEvZTNSVnZ2TlJTN2EzV1Z1NktWenR6ZENxY1BNc2ZyWmFhYVpTbEpvcm00bkxLVGQ1U3pxK2U1L1dHeVAralh0Y2VFR1Noa2FDbnhTWlVua2FBdnI1T3JpVUYxYzYvVlprcDNBMktqN3VQSlBVRVZIblpFeWwvS2dZdGZSRWJwQjRSbUZ0dUUxVWdPV0tDakIreW8rNmQ2NEN5c2RUZlZGcDRockRodVBOQkxKdEhZOFc1a2FmQlE1bHlBbmFmRElvK1FGWXdDOE8yNXQwUTQ0WHp6dGphQzR1SUZncUU5UzBhTU5LbWVvY0hkaXRTMktGdk8yeStqdXlIc3FFTEdUMURCeGZ4QlZuWTkyVk9kUERQUEZZRWgyKzNLK2s2TENtWVpTTWlqQUZoWll1WE8ySGtpb0lVTkF5aWhiSEEwQ3greW1xZWtMaUxoTjA5TTVwQmNMMzhsY3c0ZUJwTmxTamtjbVpjOHJ1aXZwOFAyQnNuQTBRajVKOHhDTm4zS2h4T3Q3b3UzV3hoaW1oS2U0VHhPdWRxSUY5bHB1TlkvSFN1OGRyK3FZeDNNVGFUVnVmdVhNOGZyM1lyTjRUdGZxaGtlZ3g2VkR1WU03bHJMUStmUmE1VTV2a3FXMklLVnJLRVF4alhZNzlGUjQxVVFZZkVYQnd2YSt4UXBObWxEVHBETmRqNGp1U3RkcnM1c1lTRnJPTFptYkk1elFTdFVyNjd2SEZ3S3R3ZzJNZU5JM3B1WjJseExuMkJOOTFQOEFUMEUyM2VOQlhLS2pGWlgzRFNVS0tvcXk2NGNGYmVOQzR4T3d4VkxYYnRuQVYvZ1dZM1J6TmdlOGtFOVZ4V254V3NnQU92WWJxeW9jMVBlZSt1UVdiYnBFb1VkbkhnK3ZPemJHQkJNOXBkY1M3ZnVTUGFuZ3pLYkU1YS9TQzE1c1ByL2V1VzVEejNhZWtCazZyNlB4ekw3YzQ1SGlxV0FQZmN1Ty9sWXFzN1JrNWVHY1J3K1IwcDRQS3RvQTRPQXNoNGZUdHBwcEkzTkxkRHkzZjBLSlBXc2hrMnVpQUgvZHU4YUw5VTdSNE5GcUJkSTM3MVVuR0FJOXJwT0hGcWx6eUE3YS9rb0MwYjlEUFRZZXl3TFNVR2ZITzh2b0gwV3J4TW5xckZ4VnJTVW1pd2NML0pRQmoxUFd6VlVnQmNiSzZPRXRtZ0JOaWJKYWl3c3NBZGEzVlhGRzRqd25nSlFwbEV5QVVSZGR2UmFiblhIUGNLR1daenJhVnZPWkt1T21hNGdyNXg3YmM0aUtLU2xqZjhUZUI4bGN3cmtVY1Y3U013T3gvRXBBSDdNY3REa2JjZDBPUnVyYXNqY0h2bUozZnVxeHQyU0dROVJaZWh3cmdkRkdBTEJRVTczVUUwVlI0OEladWlIaFFkd29DeUtnZVZOUlBLZ0I5ejlrSFlIaUdmY2FnbHFLWndZSGFUcEJQWCs1Zm9aMlg5aitHNU13cUJudTdPOWF5eExveGU5MWQ1RzdPOE55cEE0VTlQRzEycTRjMjYyZU9ta2ttZFp4YTBGZS93QTJkeTRUUHo5aHdiWGRESWQzYlExalJhL0ZrMjBDdzJGMEJyQkViSGNvNDRDeDhqdG0zamkwaUs4ZUN2ZFY1REZCeTdnNDMyTmlFSjhXcVRVQ2ZORmtBZGF5RzBsaE4wVDdneTdHbjlvR1pQME5ReWdFQTJJWHgzMms1cmRMTFBkNU55ZXErbCsyV3BiM0R4Y0RmK0srVGMrWWFacEhscHZlNjA5UEtrZWUxTVcyYW5TajlKeUVrYWxjUllFV3NKSU5nTDJXY3Q0VVlybHdWM1d5Q0lPYUFyT1RJa0RneE0xQ29sYzBsdWtOc2JiSkdTRHZON2xXT0lNTG5PczNxZ1U5TTkvTndpZVJNdHVKV3lTZHdiWFR1SHRPb0c2SlYwREJ1WEM2OVFnYXdFbHlzRGFPdVpjRFpHZ3A5VFR5aXZoRFl0WG9sb2F6UVMzMFNuWnlocWtJRHJjRzZ6V09BYmZuNXFzZk82Rjk3K3FadVo0Ym55VFlzck5DY2s3VGZZWCtTckpYazFBM05sT3UxUlNHeVNMM1BtYXIyTmxXYUM0bVIzVGQxakNuc2F3QW5kTFlsSEk5alFMcFNuam1pYUR1cjBaRk9VUzlxb1dkdzQzV2o0dEV3eVAzVzF5eU9mU3UzM1dtNGlUM2o5MXBhV1Zzb1RpSTBzcklwSFhOOXVxODJwRDlRSEYxVjFEaXlZMmNpTWNXc3VEZGJlN2d6NW9OSlZpSjZ5Y1NEaDBWVk9YUGszdXBDSWdjcHVPUW5hWEh2Z3R5c3RxcjlWV052c2pNT3lETXptRlVXaktvZWFoV1ZnMWdoeENURC9WQnFuZ3MrSUorSEp0aTdCeVkzS1NOaXloUmZwUEdxY0FsM2pYNkRkaW1WeFRZTFR1TGJINWVnWHhYMkZaYmRpV05SdXRjQndLL1JuSWVEaWd3cUpnRnJMeC9WczZiWjdYbytCcEswYlpTUkNKalFCWVdDTkliaFpMZExRb0VFbGVFWjdkQWRGK2lIUEdIRGdKMXNhaVlnNWNISW9aNmV4dlpEQjBCWFU5S0xjS3NuZ0l2WlFhbVZXSVdtakl0ZGN1empoUGVCNURmd1hWS21Nc0J1dFV4K2xFMFR2Q2hrV3NVdVQ1engyak1MM2doY3Z6TmhqWkdTRUJkNHpaaFZwSkxCY2x6QlFrTmtCVlNhUFE2ZVp5Q3EvMGFSelM0MjRzdFJ6SGdUTVQxT2EzZm5ZTGY4ZHdkeGtjNEhxdGRrYjd2ZHJ0MVZacXFSeWJFTVBudytRZ2drRHpWYlZ3ZTh4MzBocEhVQmRCekJIRkkxeDBoYUZpUmN4eERHbTNvbkpsT1VhS2lueFdyd1dXOGNzZ0EvcGtMWjhIN2FhbWljMFNscnRPM2lOMXI4Y0FsdjNyZW5WSVZPRVJTazZHZ0ZPaXluS0xaMWlIdDFaVVJnT01YNEoybDdacVpoR3FSZytpNGM3QUpXL0NTUGtvT3k5V1BPejNCT1VnVkErcWN2ZHVPRzB6bWw4c1IrWUMyMmJ0Mndxb3A3Q1NIam9BdmpLTEx0ZTIxcDNwK1BDc1JqWlkxRDExNUVKOEZuMHpXZHRlSHhPZHBtWVBsWlZSN1Y0SzkxdThiWW5wWmZPazJDMTh6d2UvZWQxWVFVbFpUQWVOMnlGNUVHc0xPNFZ1WnFXc2pPN0hFanlDNS9tUEMyNG9aSE1idGJvRnJVVlZXTWNBWFBzcjNEOFZMUUd5Qzk5dDBIaUlMd1djeXhYRDVNTW1jQzNhNU82eEJUKzl4K1J0MFhVY1h5MUhpMEJrYTBYc3VmMU5ESmhkV1k5SnRleTd1UWNjTHNybVVCZ2NlVTVoa3pvWlJ1UUxxdzl6TTBlb0JKU1V6b243QkxteTFER3pjS0NzRDJOMzNzdG93aW9BQXY1TG4rR1RGb0FOMXRPSFZsckFMUG15NUdMUnRzVlVHa2JxOHc3RkEyMW5MVW9ZbnZzZDkxWVU3WHhFY3FqT0pxUU44cDhWMUFicXlneElzSU56OVZwVkhWYWJYS3RvS3JXUnVxY3VDMG9tL1lialZ5QnEvRmJOUzRnWkdjcm11SHkySU4xczFGaUFZQUxyaVp4d05qZlVXQkpLU214QU1QS0ROV3RMT1ZRVjlicEpzNU5Lc3Nac2NlS05Jc1RkQk5RMXdQQldwc3hPeEc2czRhdlUwYm9rTFVHZ3RhUTYreTB6SG90M0VMYkpDWkxyWDhacGk4T1JsaVBCb3I2a3hTYzIzVnJSWXJwYVBGK0tyTVlvWHhFa0JVRDhSZFRYQjJVMjJQczZQVFpnTVpBMS9pbXBjek9MZmkvRmN0anpDTC9FbS93REtOcmhhNm5oMkM4aVJ2WnpFUzdjaE13NWx0WVhDNTdIaTdaRHlub0tzUEkzWFBCWUhpbzZKQm1FRnc4WDRxMlpqemU3Rm5BTG5USjlKYWRhTkppbmR4L0dsK0VNM28zK1BIYm4rY0orOVNPUHVkc1hmaXVheDQvcGQ4U1BIbWlPVFlFTG5oRTNvMzJUSFhONGVSOTZpM01jZ1B4WCs5YVIrbU5XOTlsTm1Pd3NIaWNGM3dqdStKdkRNeGJidS9GQU9ZZzJUZC9YeldnMVdab1l3YlBIMVZEWDV1YTBFdGVpV05pWlNTT3luTmtVYkQ0eHN0YnhiUHpaQTROa3QwMks0dmlHZlpHNmdIbGExTG5PUWwxM0hsTmpqWlN5WjFFNjFpdmFFNkRWK3QvRmFWaXVkSks1NXRJZC9WYURpR1kzVC9hS3JoamdaeWJsT1dNb3kxYVJ2Y2xYM3UvZU8zOVVXREhXVVFzWFgrYTUzL2xESTIrNVFuWXRKTzdrcDdpVlhsT2pWT1p2ZWRtdTU4aWdzcm13dURwbm14MzNLMCtpcUNBQ1RjcG1vZExpTHdBU3dXc2tTUXQ1RGJqakJrYnBnQWNtYUpwbE91b2NXVzNWUGc4ME9GUTNtSWViZFVMRThaOStmYW5PZ0UvWlNHQThodEF6UEZTQXRqTFNSOGxHS3VseGFRYm0zb1ZSWVhoemRuVFNEZmZkVy92OEFUNGVQMVphU1BKVjVLeGltYk5SV3crTVhhTDhYSVJaTzVuT292SldqVnVhM091QUN2VW1LVkVvdnFkWXFyT0RHS1IwR0RHZmRMTWpBOGxkWWRVU1ZoQmZzQ3VkVUdJZDNKZVhmNXEwcXMzZTdzQWhhZnVWVjQyTlRzNnBDMm1wV2gydlVlZHdsS3pGOVIwc08zb3VZdzVucVh1OFQzV1BtcmlpeGN6V3ZjbEY0YklvTTN2RG1tWWh6bkg2cTVseENHbmFMUDNBV2swdGJVRm9ER3V0NkswcHNOcXExd3VYYnJ0VVBqQmx4TGl2dkEwdGNtc093NTlTNEVnbTZhd1RLYmpZdlAxVzUwbUZ3MGJCOE53cGFRNVFLM0RNSDkzTFNSK0MzVENhSVBEZGxWUk1EeUFBcnpEWEdDeXJTUTVzMnZER01wbWk0SDNoWFFxQllkRnJFTlFaQUNGWXgxQk50MVZtaXZKbDNGTGM4cCtJM3NxYWtmcUlWM1ROdTFWSklyTmpzZE8wZ0ZOUjA0dHgrQ1RoRHlmUldkTTAyUXJBeEVwR0d3aHArSDhFeEpSc2UwYmZnak1qQ08yQy9WU1dEZ1J1NUtTWEMydVBDQTdCbzNOSUxiL2N0ak5NZ1Bnc1ZUbnAzWXhUTkpyc3N0SWNlNy9CYTlVNWZjeDUwdEkrUzZoVzA1TGVPaXEvMGVKSG03Vm41Y1RMY2NwcFZKUnZoSUJDdTZjeTRZNXJtaytmS3ZUZ1RTTGdCWVpoYnB6WjdkaHR1Z3c0MnBFbk5OR3c1WHgzM2tCcjdYVzZpVHdEVHV1WlUxRkpSeUF4Zy9jdDB3V3VjWXdKYjM5VjYzU3Vrakh6SzJYdmZDMzl5ZytVSmZ2QVNzT2RkYjhzaW9vcEdaSkJ1a0puWEpURHlrcGVxbzVIWStLb0U2M2tsWjJjN0prT1VKR1hCVkdVYlk5RkRJOCs5RG9wejFEV3ZqdVVXcGcweVhWRGlzajQzTklKMlZmSTZSYXhsWjJrNE0zRnNKazB0MUhjOEw0Mnp6Z0VsTFZUZUF0R29yN1lqbjkvcFhSdjN1RHl1RGRyMlZXeHVrZXhvM0JPeXpkM0o2SFMrUjh4MURIVTU1SVN0UklKbVcySlY3anRBNkdRdElzcXFLa3MyNVYvRlBnOVpnZkJVeVJkM2NrQkFjNE9Cc25zU0FBTmxWc081QlZxSWpJMEFxQUdsTHlzRGh3bWF2blpMRjJ5dHdNMmZJak5CdmV5QVk5anQrQ2ZrS1dlTjFiUlgyRmQzR2wzM29qVzJUTWpOa0F0SUtPSEFLZ1RiSHEydHltV005MUh1NDNMOTkrVUZsN0lzWkpQZlA1YnR1dTVacWl4RlVYdEhSQ2lweWR5NlFiQXJwUFpIMmJ5NDFpTWRYSkVTdzc4WEcyNjA3SUdCMU9hTVRpWnBkM2JIZmRaZlkyUjh1UTVmd3lLTmtiUThlWHlYbk5Sa3RsdU0waTR3bkNXVUVNVEdNRGRMUU5oYm90aXBxRXpBY2xEbzZidmlObGVVMU1ZUU5sa1JpMHpLelpRZFBRZDFhNHY4MCs1dWxvMi9CVGpickNCVXo2R20vUlcxSlJSblF1Y2hIRUpORVp1YkxudVlzYUZPWGpWd0ZiNW94ODA3SEFGY254bkZwS3VWMXliRkRMS2VpMDJrY2tuUUdyeEk0Zzk0Tys1Q29zUmZIUnRMaWJGR3JhMktpakpCRitWemJOMmFIdkRnMXgrNWR3d2RucFBDY1J6R3MxUnNFZ0R3YkFybVdLWmdrckh5RFdTTG5xcTdFY1hsZklkVGlrNmVkajNia0xjeGNJQnZ5SXl1ZTl4SnVrNW1PY2JicTVMR3ZiY0FJRDZjZVNlNUlTOFRrVkw2TUFnb29aM2JPRTFKRWJvbnU0TEFqc2JnZzlvaEhPYjJzTjlsR2VMdWFaOXRyN3A5bEczVjBVS21MN0o0VXNHTUxtU3k1ajhsQld3M2RZQjNtdnZYc0N6Q01ieXN5RWtQL1Z1Mk8vMlYrZnBoWXg3SEMxd1Y5aCt5VGk0ZTFsTzUyM2RrV1A4QXdybkJRNmxqNC9xT1oxd3cwZUl6RU4wWGM0N0MzVlVRdzB5UmgyNVhWKzE3QlcwOHdrYUJ1eSszeUMwS0NLMUxhMjlsVlpsUW1VMGRKdGF5c0tEQk84Y0RwL0JHbzZVdmZ3dGd3cUVNdGNkVUk1ejRGWU1GTVlHeFZ0UTRmYTEyMys1TXRiM2pnQUZlMEdHRXNCSVFHZGtueUFiVFhpMGdmZ2hTMnBJbjNBRndya1V4RHhZYkxYTTExQXBZdkpIaVFwWkxPY1oxeHR0RUtoNzMvWlBLK1RNODRxY1hyWm5oNWNBNXc1WFhPMlhNNzQyUFpHNDNKdHQ4MXdlcWNXd1N2ZWJseHZ1dHpDaXhGMlVWV2J0dGZoSUh4alQ1SmxrbmV5eUE4WFF4SG9tZDVXV2xFc1JBV3NvT0d5TVJjbERjTHFXSVlJaTZ3UjZLWkN4YTZsZ05BenVzV1V5MjI2d0JkZHNBL28yaGlleVFOdnNVV2VSMEJiYnFzMHUvMVJYQUVpNHV2VVNtMmZHSTQwakVRN3hnYzdsR0N3UlliQlpIQ1IzSEVPcThSeXZGZTVDYkZDNUF3TzdOenV2UEllMHIwdTBaQjVXQzM5VGJxUXV5T1BzY0o3YndXdGRadytMejlWOC9ZdXdWVWxqdXU5OXZOTytDbU1odll2SDcxOC9ZclV4eHhsN0hYSVZuRTNSbFpZMnc5TlJOZ2d2YTJ5cWEwQjd6NWVhWmZqRXRYU05ZMW84STZKQjhoRktHdjJkZGN5eWFMbW54S2hPZGtRQjJTTDVXdE5tZ2hOeWdONUtYY1d1WEZrWng0eEdlbWtuSk53bDZScFpNQmJxckNRVzZxVkpwMThENkpxbUpjS0c1blhwUjhsVFJzMVNrbFhrcmJ4L2NxR3NKWkp0c21ia0tjU1U1RDNnSmgxUUlLZmJ5NkpDb2U2UzJueVU0bmpSWjUzWFV4RGlJdXFEVXltOTdLVU1EZTlCVTVuaUozaEFOOXVFRmpERElBU2Q5MWFoSXFUaU0xVEdBTi9OS3p2WkZEdUxLYzhHbTBsejVxbXhldU1qV3RiKzBya1owaW80ak1kMzA3OXh5dEl4eVY4VXorbTYzT25EbTZEMHN0WXpWSDNramJEcXRMU3o1S09TQnBsUlVQTWhKVmpnamhXYk84N2JwZkVZU0lBQU43cFdHcE5FUlkyVzN2NEtFNEZyaTBEYVVYRnZ1VlpGV0YyeUxVMXBtaXVUZlpJUXlkNC9aTnh6RTdDeVpMNm9uZjJIS3JacGhHUnV2ZCsyUmx0WDBVY3R3dFIyanJxdmUxL3hVUzEwaHRjYnFzMWhqdmlLc3NGaWRXVjhiUmMzU2N1WFpFdVljZStTUHJUMlhzdW1XUnNoYjBCdjlGOXpZTkNZWW1zNkJmTW5zeVlLNm5vWTNHTWJzSFQxQytxb1dGZzRYZ2VvNW5LVFBvWFRzS2hCTUxJZHJMMGJRVkN4VW1MR05WQm5DeXcxcWswWFJIRHc4THAyNkFTTXVQUkpUd0EzVmtBZ3pBZVNnU2thNWlGUHNWcnVJMFlkRzY2M090anUwN0xWOFhpSVk1QXkxajRaeUROOUdBNlN3NkxpZVo2ZHpESnQxSzcvbVJ0M1AyNkxrZWFLSHZOZG0rZlJWSm01Z2tjZHhXTHdPdXVmNHZBWFNteTZibU9tTVFmdFpjNXhHSzhqdVZWWnQ0K1VhcmkxQ0pJenh3dFNxYU9PTjVEbXJkNmxsdzdkYTdpTkpjazJYTncrVURYSjhOWlA4SStxRkZoSWlON0swRk9XdTRLS0wrWDRJbE1yUEhZbkZRc05yaE5zcEkyTi92V1N3bGU3cytaUitJR3NSRmtSYVVYM1V5QmVqSUJUME9rZ0pMeUR2QlFsN2tXSVV6R01HNFYwS2ZXTHBTcncxOHpyQnFCNUFsaFJRdmtqMVdzVXhUWWI3MFFXaFdYK1RieXpWcEtzc0d3djNkNERyL2VnOFJoK0NodkI2WXNZSTNOTmxRNXN5bUhmcnd6MVhTYUNtaTFOSkE0OGtMTkRJQlFrYlh0NUp5eW5QQ1NPSjBNVFE3dXlMSmlvd05ydDdEZFpyUDFkV1MxRmZYNlFHbnlST2RuZHFRcXpDZTc0SDBWalEwUlk0RWkzelRlRnRiSVE3bGJSVDVlbXhXUDhBVng5TCtFS3ZKMlRnSGhiMnlhUXJ2M0VQWUNBcWFEQmFyQ3B2MWpDTEhxdHZ3b0NXSWFnT0VxZFVYSUZReWlMVHNFNVR3dWFRYkZiSFQ0WkZOLzdLeXBjRFk0YkQ4RlFtckwwV3FLT2pjV2p5Vmt5VWdYdndtNWNGN3M3QS9SS3pVem90ckZLMnM2NUlpL0ZuY1g0VlhYVjduRGxIcVk5TjFYVGdGcENjY3BNVGZpUlk3ZDFrN1JZOFNRQzVhM2ljQkxpUVNMS3RHSmQwYlh0WkdoYmlkVW84U0VvK0lmVll4QjdYam02MEREc2Q2YS94Vi9EaXdrRzdyb2hWRThSbzJ6c0k1V2c1andmdXc0dEMzNlNxRHh5cW5FcVAzaGgydW1vNDJja05NK041dnQ4MENhb01YSlcxWXZnVHRUaUFSOGxxR0pVRWpBNFdLc3dTWlZtMlJibUR1SGZFbnFmT1dpM2lLMUtlaGU1NTVVQlRQajV1clNqRXF0czN4MmVUdDR5aHpaemM5bnhsYUxJQVRzNDNVbVNsZzV2ODBqYWhEMURSdHNlYW5PTmk2MS9OR2d4enVEcTFqejVXalR6dmNmQ1BvaHlWVXJoYTUrcTV0UUQxVWpmcW5QUWlaWVBLcGFuUE1ranRubjhWcDBoZVRjay9WUkQyZ1dKVTJvQjZwbXcxdWI1aWZqUzMrVUVrekRkeW8zdGplZmlLQzU3SVFUcUtOWXhEMWNtV005YzZSeEpLVW1xQlltNlFseE5nMnVrSnNRTWpUWXBzY1lEeU9ZelVWbmlzQ29zMVM3bjhWWFF5bnZkOTFabVRVMFcyK1Njc1lydzJ3N0l3L1pNeFFDTTNTY1IwOHArQjJzV1hIakcwTlF5MnR1bXhqSVlRSTdncFJ1SHVsM0JQM0oya3dkb0lKdXFzOGJKdFRKT2ZKV051NDNVNllta054MFRqWUlvckFteWVwTUlqckxibmRWcFlXVFlWb3hxZWNhV2s3YmJwZDFST1pQSGNqNUxiWThvdGpBSUIraXkvQUMwV0RML2NoZUZscFlrVU1MR3pBRWl4OVZhUjFZb3kwQzUyNkpsdVhYdTRhUjhreEZsNlZqd1hNSithVzhKWWpoTVJuM3RvSUIrOU8wZEN4eDhiU2ZrbUlzUGZHeTJpMjNrbktHUXdQQWMwZmVFdDRVV0ZoUXpoK1gvZTNBQnRoNnJjY0l5UHAwdUlhZnZWWFE0a0lpM1lCYkxoMllnMndKQ1E0Y0R2RE5rd3pBb0tkZ0RtZlJiTGhtRlJ4Mk5yZmV0YXBNd3NjQnUxVzBlT0M0c1FBcXM0aHFCc3JIOTBRR294aGZQWTZoeXFXUEZ4SXdjSnlrbmRJYjNLcXRCYlRZYU9GckxYSStxdElnMGdXV3Qwczd0WEorcXM0YWd0c1ZIRXJNMldqT2tKK0g0bFJVZUtCamQ3SnVMRnk5M1JWSnhGU1J0RkRZRWJoYkRTdUZnYmhhREZpVDdnM3NyT2x4dDdBQmRWSklTNG04d3p0dW40WkFRTExVYVBGMmtqeEs0Z3hOcmdOMFhpcEZhVUdiQTF3dGU2TTJZbTI2cFk2NE9IS2FaTUJZM1hIbFRLamk3TFpqaTdxcEdLOXlrWWFnZWFkamVIRGxBNUprU1lPNGwySUtFNkFOTndFeHNwQnQraVJQR21jakpvREVlQVFuSE1qMDdEZXlHMlAwL0JNUnc4WFNvNHFZM2Z3WWgwTjVhU21MZ2tGclNFYUZyV2pjQk1hMkFjRDZMU3gvQ0lseVJiS2JCU01wc2dHUVhYdThDdGVLVjlvUXltNkhNTmw3dkFodmVwdnNOSUJleFdTYjlWaHl3dVdnMGhERURhOWxTWWxFSFV6bkVjQmJKVXdndHVxYkZkNlY3UUJ3cVdaVWl4aTdtbFVtTENDcWN3bTJ5ck0xWWF6R29IRnd2c3Rlek5pRDhNeEFrblNMZ2MrcTJUQTY1dUl3TkY3M3NzYVRwbm85S3FvK1krMGpBaGg5VWRMQ1BFdWV5UERZbDlLZHJXQUF3dWZvOWVGODI0bEE2R29jTEt6am16MG1LVkkxNnFjWGx5UWMzU1ZleVUzZWJXNVZkV1VocHhxdHN0bUlxWFlycEJxUUpJN0tUNWUrZFlINkwzeEszQXB5RTN0M1VSRmRNU3hrcURZeUZiaUR3QjdxNjk3c0NpdUJkc0Y1c1JCdnVpbHdTS3NHS2ZUMDJUTkxSZS9TdGdZM1ZxOGxMVjRTMjNPeTNic3R5NDZmRVkzT1pxQmQxRitxenMyUXNPTkt6dHZZWGtxSERxVHZYeEVPYzI5L3ZDN25SVWQ2Z2tqd3FneWZob284UGlBWUcrSG9GdVdIdzZ6ZXl3OHR0bWZrbnRIS0tJUkViSzJZQTlvU3NVWnRheUxxTVFKNFVta2tadFBJRWZJSUduNUxVc3g1aFpUUnYzc25jYnhrUXNmNHJXQlhJczFaakZSM2dEL1BxcUVwR3ZwTkhKdE5vWHpCbUp0VTkzaXV0SnhERjJSRjNpMythRGlXSkFhanFXbFlyaVdwN3JPUDFRcFNaNzNTYWFNWXEwRngzRm52WS94aGMweDNFVHFkZTZ0Y1V4UjRlUURkVk5SaDgrS00yWjA2TGZna2grZUNTNE5XcVg5L2NqZEswY0VycGJhVHo1TGM4TnlUS0pBWHRjdHVvY2tORG1udTkva3JTbWtZY3VKR2xZZmhyblJna2RPcWhYVXhpSnNML0pkUmx5WTV0UGRyRHg1TFhLekw4bE9YaHpMN2RRaGN5empuRmR6bjhrbGp3Vk1HN0V4aXRFYVdWeHNod083Mk1pM1JPM0ZqQkZPTEJSRTZsR28vWFNBQUkwZE9RNU1RUmpVTGpkVGNkaGpXOFRwY0hNNWNUYmJ6WGZQWnVxSDRUanpHWHMzVGEvMVhIb3FGMHIya1hIeVhadXllak5QTkE3ZzNHNm00cGRUeExhZlJYYXJVQ3BwNFRlL3dDcEg3Z3Vhd3RCanNGdm1jZzZvd2hwRzlvMmkvM0xTOFBodkU4RWIyUXM4UEdWTUpSUnRZTDlWWVVZdDlVbFR4ZHpZa243MWFVOFpra2FBUG9oSE9Ub3RNSnBlOW1IaEpGMXVNY1RZWVFPRWpndE9JSVFTMGNja0o4bnY1QUI1M1FHZGtseU5VZUhpV0Z6eUxHL1ZjaTdWcXMwTUV0amF3WGFwS3BrTEdqWVdBWER1MkJvcXdTMDdLMWlqeUJDMno1UXpTOStOMXNna3ZZYjdybVdZNVRGTDNUZU9ObDJETmJHVTBiN0FBMlBBWEg4VklmSTgydnVWc1lsMk5YSEZsSVkrNmFIZFNvT09wdXJ6Ump1NCtTRktGZVJaN0FYQlFjaUVLRGhaY3NUUUk3RllLSVVOd1VzQm9qd3NXQlhqeXNnV1VzQ2oram1sNCs5R1BJUWFYajcwWThoZXIybnhqY1Rkd3ZCZWNzamhUYWMzRUY1ZTZyeE5ndWRnZ2RSdThMRXBzSTFtK3BwUGtwUEdwclQ1TGttQyt4eXZ0M3dUMzdBQzVqZHc2KzMzTDVLcjJSeE1tWTU0TGc0aXkrNzgxNGFNWHdXb2pJdmFOeEgwWDUrWjhvcXZCTXdWRWNnTEdtUjVGeGJhNnVZVlptNXVHWncvRVdSUGthVzNDeFVWQW1uTFJzRnJzR0lNWktMM3VVNDZvdk80dE50a1dXQmQwMHVDd3FkSkd6Z2xXTkY5eWxvWkh5dk4zRGxHZkM4Y2ZncVJZY2VBcjRRUnNRb1UwWmE5RXBvbnZHNk9JOUp1dXAwVnB4RGxtcUw3bFE0bENRNDdMWW9SZG4zS3R4T0w0aXU3eXUwVm1ITlpZaDl1ZXFoVlVENXBMeFh0Zm9sREtlOXNEYmRYMUJXc3A0YnU1c3JTWlhhS2w5T0tabjYza2VhUWtmN3hNTGJXMlY1V1JmcFY1MC9QZFU5VEI3aE1MYi9BQ1Q0c3F6Uk9Sam5NYTA4S3N4S2xqZ1pxTnVWWlQxZ2JFMTFqZXlwY1FtZFd4a0ErcXNLUlVraVZGVXNtYWZRMlZMbUJnTnlON0tXSHlPaGErNXQ0a1dlQVZjTWhKR3c4MXA2WjhsU2NlRFNxaVZrbDJtMjI2MStxbDd5ZXc0Vm5pb05QV3ZhT09GV1QwL2RQMWZldHZkd1o4NGprckEya3Y2S3Z3K1lDVTZ2SldOUC9wRU9rbm9xcXZoOXplUzM4RTNISVZ0SHpBSjc3cGVWb2cyMUplbXJYc2FkMHJQVXZtazNPM3F1NFh1WXJLcUhtdDczZTYzanN2b0JYNDdUc0l2YzIvRmFEQVhOYU54dXV3ZGd1SGlvelBTYlh1NytJVmZXT29selJLNUwraCtoL1lkbDVsQmd0TzdTQmVQK0s3RktBRzNDMVBzOXc4VTJYNk93Mzd2K0syMThkNHg1cndPcCtLVFBvV200aWdLazBMS3kzbFV5NEZZRk4zQ2l4U2R3b0MrNWp6UUorcVA1cGVjN0ZRaUVwSEI5d1ZRNHhFM3UzSFpYTWpyWE4xcmVPMWVoamhkQXpTaEU1L21DbkRuUDRYTnNkbzJsa2hzRjBMR0syNzNBbGFKamtvN3FUY2ZWVkptdmdYWTRwblNIU1gyQzVQaWJpeDdycnNtYTR4TTkvWGRjcnpCUmhyellLcEk5RGhqd2FqUDEyNnFzcW1CM1JYbFpCcGFiQlZFcmR5TEt2dUx6aVZNa1FEdUY1dE1IZEFuSklybmhIaG8rQ3VibUtVQkptSGwvQVJtWU01M1JYTk5BRzJ1Rll3aG9IQzV1SHFKcm95NlFBVWFIQkMwcllpQ1ZsclRkRFlCWFFZTUJhNmVPRlJ0SUpBVGNZUG1wdmFTRUxZU0VwYVJnanNBT0ZWbW5kSEpzTEsvYkdYSGRRbHBSejFRV0dnVVljSXdXbm90ZXgyU1dRRnBjYmNMWW8zbU9OMXpheFdyNHRXYXBTQnZ1aGpKaTJ6V0pzT1pxTG5FTFhjVVBpT2pwdHN0bnhMVzVoMGxhMTNKZFdCaDN1cktmQlZuSTNIczF5OVU0MVdNajB1TGJyNjh5TjJVdzBsQTE4MGJiMlBJOUZvZnM4WlFnbGJITVdYTmdWOU9ZbG9vS0p6VytHd0s0eW84bko4NjlvK1VLZW1jN3VvMml3NkxRNmZESFF0SUFzdXY1bnJtWWxMSUR2WWtMVnYwVUhrMmFxMHBHNUUxYWdwNUd2M0o0VnpRUGtCM0JWazNCSE1kY05WamgyRkJ4M2JaS3EyTWNxS3pTWlBzcU0yR2lRY0xhUmd6UjlsUW5vTkhEU25SaW1WcFpXYUpYWUk0ZzJDMXJFTU5raXZzVjF4MUkyUWJ0S3FzUndSajJraHFRV0l6T0xWbExJZFd4V3QxMkd2YmMySzdKWFplYnFQZ1ZGVzVjQkI4S0pGaGNvNVRIM2tEK3FzNmJFbk5BdVN0aHE4dGFTU0dLcG53WXhrK0VveGJRYUxHQmNYS2ZqeEJzcmJMWEphQjhlNEJYb1paSWp1RDlGeE1DaTdxWVd6QThMVmNkdzlqV3VzQXJ3WWdRMnhCU05VMDFJUHFueG5RdHdzMFNTamFIblpBcUtOcGFkZ3RvcThNSXViZlJVdFZBOXBJMG42SjZ5Z1BGWnJiOE0wNmpmcWthaUV4K3EyS2FHUVgyUUJSZDV5MGxIdU11V0Exa3l1YmU3VXVKWFhOMnJZcXFnYXdud0ZJdnAyZEdsVGNJbGdLeDFuRGhLeVIzNnE1R0hPbFBoYWZvang1Wm1rTnd3L1JUY0plbk5YTUxtYmx5VW5hWGtqVXR6ck1zelcyWWVQSkx3Wk5xSlRmdXo5RmRWREhvNlhZMDBZZnE1Y3BOb21NNUlXNTFHVVpvZnMyKzVVbUpZSE5EZXpmd1RvMElsRFlVc2tVVWU5d3NOcW9tajRnc1ZXSHloaHVRRlN5MFV3ZnNicHFvUTh1MHN6aUl1UW1LYkZRdzdsVXo2UjBiUmZaTE9Ed2R0L2twdEtmdkJ2VlBtS05nQXVFeFBtWmtUZG5CYzlIZWRiajVyTWpKWlJhNm5oMk1XZG0zdnpJWlg3T0t0c096VzZtMCtKYzVpYkpHZDA3Rzl6cmVKZDhGREZtWjJLZ3p5SGFRODdlcTJPaXpSU3pnWExicmhNVlVRQlp5Y2d4YVdGMXc4SmJ4SXZ4ekgwTFNZblRTRnRpM2xiRzJwb1pHTjNaZXkrY0tYTjgwRGZpUDBLdGFIUE01TzhuVlZad0xrTXA5QVJRVXRSc0N4SC95Y2lrRjJrTGkyR2RvVXNjclFaQ3Qvd0FKN1EydmlicWxIMVZTVWFMa2NwdGNXWEgzdU9GaWJDNWFiZmRBb3UwT0IxaHIvRk15NXRncXJBUEJ2NnJPa1diUU9Hb21pSUc2dWFXdmxkcHVDbEtHU0dxY0RmbjFXendZWkF5TUc3ZUIxQ1JLTmtzRlRZbytPMTdxM3BzeEdLd1ZKT3lKcjdCd1B5S2k2RU90WVgzU0hBbG03MEdQTkpGeUZkdzR2RzREY0xua0VENHdEd25ZSjVXa2NwTWtCdE9qMDllMXcySVRrRmUxcFdsWWRVdnNMbXl0S1dvMU9zU3FrMEM0RzNSNG0zYlpPdzF3Y05sclVGaUJ1UHFyQ0dRTlZTU0IyR3gwdFk0T0c2dktXdk5nTHJUNEo3RWJxeGdyYmRWUWttRFBFcU4ycHF5OXQxWk5xeVFOMXBkTGlIRzZ1SWErOXQwbW1VWllqWmFlcGNUeXJhbW1PMjYxaWtxZ2VxdG9LdXhHNmRHSXZ3eS9hL2hGWWJwS09YVUJ1bUkzb2xLeXE0RFFzc3RsTjBNT1JHZ0o4VUpmQVpzamlwNmo1cURYV0M4NlVKZ0pMV3ZhMUMxd3ZhVnl3cUo2MUZ6MUVqMVVDVkxPTkVpOVp1aEtUU3VLVEJJeVNYT2txdXFXQjkya2NwMTRQdkRSMEtCWFI2WHgyODFZelE0SDRlNXhidGV3c1FSdWxZTFdkZmI1clJzaTUwRWRXSW51NGRiZjVydGZhVmd3cjhKbE50UnNWOGY0cFVTWmJ4aVFnNmJQY2Z4V0JranllbDAzWStqODFVTGNkd2t2YlozaHZzdmwvT3VFZm8ydGtEaFpmUS9aem1WdU00U1kzeUFuUmExL1ZjejdaOEQwMUVraldrQy9QM29zWnN3ZEhFcEhpTjEwbmlNalo0U0J6WldOVEFIc2Q1alphN1BNNWt4YnZhNjI0bG1jZUNvMG1HUnhQa29SMVExZmVtOFRaNGJoVkloSUt1UU0yZkE4NnFiYm9vQ29hZkpJdmFmTlphdzI1VnVKWDNEYnBtdFBSRUU3UzFVOHJuRjRWalRVNWMwWFhjbllaaGRzc3NQcC9lWlc3ZFYzYnN2d3RzTThMdEk2TGttV2FEVzl1MTE5QTltVkVKSll2bUFzYkp5elRhVzA3aGdNSU5KR0xkRnNWSXdRcXF3dUQzZUJsdkpXclNIQzkxVzJKbUZuN2owVXVrWElWVGpPTU5nWTdvaTFPSXNoaVBpdGIxWE9jMTVoRFM0QnlwWlpjRm5SWUZPU3NyYzFabmRlUUIzb3VZWWppRG51ZVM3a2xNNDlqUWxlN2NsYWJpMks2R216bFJTM1NQb09sMGNWRk9nT040am9hYk9XbXoxanBYbmNsRnhMRXpPNGk2QlJVL2Vra2kreTFzT0ZORnFjdkQ0RldRZC9LTlE2cmJNSWhwNG94ZHJTYktqRVlZZGdVMVNTbldON0JGdllpY3R5TnFaRkc0K0JnKzVYT0VVYnBKVytIWlUyR1ZEV2h0OTF2bVhJV1NPWWJIZEVwc3hzNnJrdDZUQm15VTNpYURzdFJ6UGdzVVJrczBjRmRWcHFkdmNBRHlXcFpwdzd2ZGR0MHhPekVucUhDVkh6bG1YRGRjajlyY3FpaW91NUIyWFJjM1VJcGk3WmFobzd3TytTZFo2M1RPNGxXeU1PSjJROU9pUk9GbmRQV0hSQXZCQ2xqOGErTXRzS1lINmJoZGN5RWU1ZkZZY0VMbG1EUlhjMWRteURRQ1FSK2E3WlY2a3ZoT3d6eU5yY0lBUE9rRDhGcTdxZnVDK3kyR1dJMG1IVzlCKzVWTGdIc2NUNUoza2ZPbDNGWXFjelJnaFhXRFV1dVZ0eHdrS0dZTWFCWXJZY0VqQWJxTzIvVkNNZll2QzVzTk9Ham15bGhwM0pkNUt0NzkwazRieUxxeWxjS2FuSkIzc1VKbnpYSlg0MWlwaWpjUWVGeDNQZU1pYUtUVWIyVzdaanhVZTZ6ZUxlNjRMbmpIaXhrNDFLL2pSYng0MVp5YlBtTWFxaVJqU3VhMU1uZUUvTlhlUFlnYXV2a3ViN0xYM0c1STlWcTR6VmpDa0xPRzkwSjR1bUpCWkQ4MVpzQ1lzNEtCR3lNUmRES0d4YlFJaFJjTEloQ2k0S1dDd0pGbG5Tc3J3M1VzQm45RzlOL0ZGZDhTRlRJcDVDOWFuUjhVSlA0WG04TDBuQVhtY0x1NDRaSTJRenlpSGhEUEtsMlF6cUFBWGo2TEFIQ2tTR3JyaFp5RXZVODVvZEc1cEFzUVF2a3oycmNsQ0VTWW5UeEFOampOeTF0dDdMNnZrbmEwSGNMbnZhcGw2TE51VmF5RFNDNXdzUG9WWXhjTW82bDJmbTVCaWhNeGFlV0ZiQlRUR3BqRWdQUGtxYk9HQXk1ZHpQVndPWVEzdmJENko3QlpMeWR6MENzU3BnYWVXMHRDMHdPQnVWWTArSUFNQUlCK2FRckRmYjBVcVNNRzF5cytSc3QyaTFqcVRKd0I5eWt3YWtlZ2lqRnIyVmkyaWphMitvS3MySmNiSytGd2FiWFMrSk1ENDNFZVNacUdOWS9ad1FaV2h6RHYwWFZJVTRzMDRYZE00ZXFZZTh4UmczS3pWeENtZTQyNjNRMlNDY0VGWGxPeW8xUXpRWXdJcmcyNHNsNm1jV2M0NzNOOTBqV3c5eTY0S2szOWJDZDA1Y2xXU3NMM3dsaWNMRGhhMVZ6dWhxSERvcnRzb2lhNFhXdllqT3g4cnp0ZFBpaW5KQ05mVm1FK0RxbXNQYTZyaWRxSkczUlZUUVhrbVFiWDZvVStOKzVBdFo4dGxxUnk3dUN2TjhGVm0yRTBjNTBpKzl0L21xcDhMKzZCdGZaVHh2RlRXTzFQSFcrNnJ6akFMUTBoWDhhYjVNMmNrWkU3NG5rY0tGWks2WnZGMEdTcER6Y0JGaGVIN0VjclNqUGFpdnZGWVo5QnNRdlRPNzNnZlJIcXFkc1lKRmt0RklOVmlpaHdjeWNrNEd1YTRBM1gwVjdNK0c5OW1La1BQakg3MTgvTmN3a2NjcjZaOWxPbk1tWUtTKy9qSDcxazY2WEh6TlRRUitMNUg2TzVOcCs0d2ltSDlEK0t2WkhlTWpvcXpBV2QzaGxPUDZQOFU2WlAxaHV2SFpIY2oyK0tQd25pN2RZRWd1aHZjaE9mWXF2WmRTSEJJRVJrZ0hWVi9lMkhLOTM2NVpObGowc2d0eWtaWmcwRzVRNXFrTmFkMVFZaml3ajFEVWgzSFZqWTVQWHhSTmNTN3F0R3pKamNRTHZHZ1l2amVoci8xbGxvR040djNqbmVOSmJObkhoWUhITWFZWE9zNWFQaStKYTJ1czc4VXhpTlgzam5lTmF6VzFRTjkxVW16ZDA4S28xN0hIbVRVZVZ6N0Y0WE9lYmhkRXJYTWVDdFZ4T25ZNXg0Vk9SdTQrRWFWVVV0d2RsVVZOR0xuYjhGdDFUU2JGVTlWU2tFN0pMSG11dW85K0VlbnBiRUp4MU00SGhGamowa2JKTWlBeEJZY0k4TVZ1VXhIRnE2STRnQVNtbVFnMk1HMnlGTEhiaE1TT0ViVlhUVlhpc20wSlFSaEljTjFZUnZhUUZYUWVORWJyRGh5dVVkTEl3NnhjSUV3N29HNlBCVUNObmk4bFQ0dmlqR2FnQ0Z5amxsZmlWWGNPQU52a3RmbE9weEovRkducURJNDdwS1dRaTlsYXF5bnRGNnF4QkNxbzRXTnJHbE9UeU9jNzBScU9pYlBWUjdoYzJneWRIMWI3T3I5TURMZnNqOTY2OTJnNG82R25lMGJYMjJYTi9aOHdzTXBXSGI0Uis5ZEM3VEtVaU4xaDFYYW9vVGFzNUs5dXFWeFBVa3AraXBnNDhYVlZWVDkxSVFyRERhMGJicXBKbTBrWGJNT0QyL0QrQ1lwY1BEWGZEK0NMaDlVMlFBSzJwYWJXNEVCQWprblNCMCtER1lDelV6L2s0UTAzWmY3bHNlRjBXd3UxWFl3NFBiWU5UNG9veXlKTTVaVjRHNGtnTXQ5eVRPWDNXTjJsZFJsd0hVVDRVdkpnWWEwK0ZTUzREam1SeDdFOEJMZFhnL0JhdGlPSEhmd0RiMFhiY1R3VU8xZUZhamlPWExoMW1xbktQSmFqblJ5V1dnQUp1d2ZSVmRaaEltNFlOL1JkSnFzcnl1ZWJNS2pEaytSeEJMVDlGMVJIck9qbVVlVXJ0dm92ZjBRWk1vaHppTzcvQUFYYUhaYlpERnVCd3RleEdDR2xlYjJVY2hqK0k1ZFZaSUphU0duNkxXOFV5M05RM0lhVjFtc3hhbmkyOEpTVlI3cmluaHN5NVVqTGs0c2I3bkdwR1BIaGMwS0RNUGJKY2xnK2k2YmltVVkyeGw3UU9MclNLK0UwYjNOc3JjWkZtTDJtcTErR05lVFp2NEpObEZGRURxMis1WGVvblVDTDdxdkdDMU9KVklFWWNCZm9qc1c1SXBxNk1FNlkyQjE5dUVTaHlWTlZPRGpHYkhmaGRZeXgyWmE0MlBxQUw4K0lMYTZyQWFXZ2pBYTF0MmkyeUJzSGhuSHFQSW5jMkxvejk0VjVTWlVHdzdzVytTMnlaalMvWVdDUERKSEMzeFdRV09qRGl6WFdaTmpjUVRHRDgycGc1ZHBxV002bzJqYjlrS3hteHVLQU9KSTJXblpqemNYTmMyTTcraUxHbllpZVpOVUxZN1NVVGRaMkZoZjRRdVJacHpGU3dTUGEzUWJYSEFXd1luVTErSU9jR2E3TzIyV3AxK1FxcW9tMVNPY2I3N3JZeHhiUms1blpwbGJXUHhLWUNNQzEraWJpd3N4d2FudC9CYjFoT1JHeEZ1cG9KUjh3WlNtaWcvVnhrTnYwVnRZMnpLbkJITDZtaWlxcHcxemkzcHNpeTVkbWdpYStDUHZCYSs0VzFVT0J4Q1c4aEZ3ZXEzWEsyVVJqMWJGVHNjQTBteWZIRXlpOFduaHlwSEQ1NUJHTk5TMFJ1OUFvUmFaSjJ0dHp3dnZiQ1BaSnd6RXNGZFVWRXNQZWFIRWFnZWJmSmZLSGJCMmFUNUV4MTRhMDkyMHVzUU5ySjZUWGNVOVRDSENaekdxZjd0THBzTEZZaWdiSklYRWtYVGJteDFqMmFyQWp6VGpzT1lHalM4YmI3SmJ5VUI3MUNYZGxaN285dm1wQ2xsWjR0N0oyV29ZMXdGaHNMS3hnZkZMRllnY0lGSVlwTkZSRld2YU5Pa0tiYXNNM3VyTmxGRVNiZ2NMMFdETWZjYWh1aWVRZXM3WEFoRmk0RHJhdDA0TXd1Z3RhVncrOWVmbGtoMnBwMlhuWmFmS05sV2xQazQ4azVGaFM1cW1hUitzUDlaWCtIWnpramNDWlB4V255WURORU5yN0paMUZVeG5iVWx2SFpjV0pvN1ZoUGFSM0FiZDQrcTJKbmFmSlVORFd5RDdpdm5NT3FvdnRPQ3NjUHhxV0Q0M0hielZlZUN4OFo3RDZKd3JOa2xUVURVL1luelhTOEd4Q0dXRnBjUnR1dmtPa3pxK0I0MHVOMXMxSDJsMWNiQUd5UEFWWjZWc2V0WWtmVlRNVWhxWkF4aEhrcjZpb3U4ajFhUVJieVh6RmxidE9JcVdkNi9ydmNydldWdTBTaXFxVmpTOWw3ZWFvWk5NeTR0U21iUVNJRFk3SmhzcGJZcXY5K2hyM2FtUGI5eW5KVUJqZVZsWk5PN0h4eXBseFQxaEZ0MWFRVlpJRnl0TkdJNkhjcDJER2JBS3Q0TEhKMmJuRlZBMjNUTEtxM1ZhclM0a0RiZFdFZGFIQWJxakxFemppYlBUMTlpTjFlVW1JQTIzV2pSVkJQVldOSFdPRGh1VlRuQm9US0owS2tyQWJicTVwWndiYnJScUNySkEzV3gwZFZjRGRWSldKY1RiYWV0NDNWblQxZ0lHNjFTQ1k3YnExcFp1TjBpQ2RsU2NlRFloVUFpOTBhS3FDckluM0hLeXh4QjVXbEI4RkNVUzhaS0hCWWVMM1ZmRlBZY3BoczkwK3ppUWNHeUowUVdPUm1ib3FGR0NvOTJQTlRMVkhTVVNpQVk3c0wybXk4UVFzRzRScFVDUmM4YXhzbEt6eEZxYkxQR0V0VkN4Q2Y1REpTNUtYSElPOG9wUVJlN1R6OGw4WDl0T0dPb2NVa2ZhdzhSWDJ4aXAvMGQzeUsrViszckRtelR2SUgyU3NYVWR6MVhUWGErUm9uWm5tNzlIMWtUSFNrQzlyRXJxZmFWSkZtVEFDNklBdXVUZG8rUytiSVRKaDFVMTdTUllycU9YODIrOVlXWXBIWDhKNStTRENiMldKeW1vYWFlb2xZYjdQUDcxVzFzQUlMN2V2Q3VNd2pSV1NPSEJjVCtLU25hSDBoUFd5MDhZYyt4cTlTN1hkcVE3Zytxc083Sm5PeTgrbUxkN0xVeDlrWjB5dWRUWFdCVEVCV0FoSlVKSXkyNnNDS0t4c05uY2ZncktrakxpMEpmUnVyUEM0aStRYkljajRHYWJ1YnBsU2wwaHBJWGJlemM2SjJmTmNpd0ZnaFkzelhXZXoxamhJdytxeXNqTCtYbEhlS0twQXBtQW5vdlMxb1lEdXFXbW5MWW0zUFJKNG5pUWhZN3hkRlVjaktlTnRpV1pzd2lOamdIMis5Y3V4N01IZWF2SGY3MDVtbkd3L3ZBSGVhNXRpbUtYMTNjczFZM1o3SFM0ZGpWbnNSeHdhblhLMUd0cnpNWGJubFF4Q3QxT2Q0bFZ0cVE1MjVUNHhvOU5ESWxHZ3JJRExKZmRYK0h4Q09QY2RDa0tKZ2tGd3JWa0RyV0NzeGRGSE44VDRLNmVhNWNBQnloMDdYdmtGbGR3NFUyUStxdU1QeSswdUJzRnlpcGxuU0FZUEE4bGx4ZmRkU3dLbTdzUm4wQ3BNTHdKakEwN0xiNkdqTEEydzRSb3dzMlpQZ3VXMUlqaHRmb3RleFdidkNSeW42cHpvMldWUE0vVzQzVEVaa283bWMyN1FLYlN4eHQwWE9ZNUEwdkM2em51QVN3dStTNVBOQm9tY1BWQ3owMm5kdENrMEJsZmNCR1pSNlc3M1RVY1hHeVlmQ1NCWkNtZXF4UXVBM2dWR1M2NjdOMmUwNWJLem15NWhnTktRTDJYV3NnUk9NemJEb3JFVHordlhMT2o0aTNVMWc2YVIrNVVOY05CQTRXd1ZSQjBYOGxSMTdOY2pRUE5XWmRqNSs1Y2txS0l1YTFYekhkMDBXMjI2S3ZvWVJIQ0NVNVRYbU82VDVpbklmcERxT29wVEc4VTkyamNDNUhjOFV6RGNyVGN6NGhyMTJjbXhRcnV6VTgxWXdESElRN2JkZlAyZjhhRWhrWUgyUHpYU3M0NHIzTlBMZDNtdm5yTStKT3FLMTR1U05TMHNTTlNFVFg1cjk2NXhTamh2ZE5WTHZDbGlGcXdmQlpTNEF1RjBNaTEwWndReTFESTQwQWUzWkJjTEpoNFFYQkVWd1o0VUNMb3RnaGtMb0RCRUtCQ0s0S0pGbEFUK2phbUk4K3FLN2xWdE5JWDdnb3dxaTkyaGV4bkZJK0pEcnlDQXN0TmtHM2N0MUU3MjZwV0d0WlZPTm5jR3lwdVNUb2hZbmhDSkc2REpVNlc2UWtwYXQ4QnYrOVdJMDBjTEV2dDFTMVJVbHJlVUNhcHZUbHhOaXFmOUpPTG50UHcrYVJITlpVY3RvelVZZzdjWFNzRlNKYnhPNGNkMGhWWWpIRElTSFgrYXJLakh4RElPN3NSMUtWazFMaUphM25EZmFCN0lZaEora280Mmt2SmVTQ1BWZlBkTGh2dWY2MDJEanRicXZ0RHRFckc0cGdVdW0wand6ZzdyNDJ4b1ZkSGpFclo0KzdqdHQrS2ZnenVZcXRoQ3JrQTM5RkducUQwS1hsbkw0SEwyRkM3bjNWbWNYUnB3eVdYVkhVT3Z5bW40cEpwdGRJMDdORXhQb3ZTTzdzclBud1cxeU13eVBxSk56OVU3TFRIUjhRK3FWcElUT050dmtwMUVUb09TYkpTWkhFUXI2THZtSHFxQjhacFpEMFd5dWtJWVRGNHgxdXRheGVZeXVMV2p4K1N1WTVOc29UaUJyWis4YnlsSTYzVEM2eUVJNTRRNHp0MHR0eXFaK0l1aWM2SnU5ejFXbERzWjh5eU01bjE3cWd4RnJtVGtnZzc5RWFURUpJTmlMYTBuTk02ay9YdTNCMjNUckU3YkNTenRmRGF4QjlWcUdKVklqbklPMjYyS1d0aW5lSjlWbXQyTnVGb3VaTVJiTFUrQThIb3J1blhQSlJuQmhxeHpKMjdlYXFxMWpZZHh2OGtxNnVmR1M3b2RrSVRFZ2x4dmZ6WG9zYmlrWnM4VFk3VDFJdHVuSWFsclZRKzhXZFlJenBpVzhwZVNhOG1KOENSWnZyUGVMaS9vaEZsdDdqNnBOajJNNWNVUnptaGw3bEJIT2g4c0xDKzhsa2pkK29YMW43SlZZMTJPVWUvMngrOWZHMDFRMThnczdxdnFuMlA2di9wNmtCUCtzSDcxaTYzTlp0NkhEVCtSK29XRVRCMkhVLzhBd29sUTdUSWQxVTRMS0RoOU52OEFaVEZaS0E0N3J6VGxiUFg0NFVoaDlSYnFsWktuZmxJVkZSWWNsSk9ydE45MExMYWpaYm1xc09VR2JFdzBjclg2ckZ3eSs2cUsvTUlpWWJ1U202TFVNVm15VjJOaGtaOGEwTEg4eUZybldlcWJHczBraHdEL0FNVm9PTDVsZnFkZDM0cExrWEk2Y3Q4ZHpOSTdVQTlhbFY0dkpLRDRsVjFXTDZ5NGwxN3F2a3I5U0J5TjJPRklibXFudWNidVZMV3lrQTJLTE5WSGZkVjBqeWJrbFY1T3k1amhRalUxSjMzVkhXVGx4TzZzY1FCUENwbnhtNXVxekxrUmFXZTQ2cEtVQjZzSE1DWGtpdjBTR1BFaFRCM1JaZlJCdTZZYXl4VXBHYklXcklBamcwckUzaENNM3doQXFKTDNRYlNDRWorOHVFbyttdTY2WU1aQkozVWd3cGxDaU5PTzdGazJDMGorOUE3a25vcE9wN041TjBhaUEyTFY4K2hwc1ZxMWU1OHJpZVF0aHJLVnhIVlZFMFJqZFloR29XQTJWUUJQS3dZZGF0UGNROGkzVk8wbUFtZHdzQ214aUtuSkpGQXpDblRHd2FUZjBXeTVieUZVelZjYnU3SkI5RnZXVmNtT2tEQ1k3L01MdUdRc2lneVJsMEE1SDJVM3d6THlaallPeEhLajZHamJyYnA4UDhWcy9hWFFORVVseGRiamx6Qlc0YlRpemRPM1FMV2UwVndramtIS1ZLTkZaU3RuemZqY1dpZDl2TW9OSTl6UnNyVEc2VXVuZnQxS3poMkhsemVGbXM5TmFvc01GbmNYTlhRY0Z0SVdYOUZwdUgwSmE0YlcrNWJkaGJITkxWRXVTcGxsd2J2UVJOQUZsc3VIMGpaRzdyVmNMMUFDOTFzOUZJUTBicTFHSmtaSjhqTXRHeG9PeXFxMkpyUVZhdWxMeFpJVkZFWmoxWFhFclBLelhLcUJyeWRycFIrQ0NZL0RlNjIyREE3bTVCVmhEaFRZMjdqOEVpVWFHUXl0bWlzeXBFV2t1WXFqRktDS2lEZ0c4TG9lSkZrRENPTmx6dk10Y3h1dmRKY2tpL2pjbWFSamRiM1VUN0czelhLTXhZaEpKTTRCMTkxdU9hY1M3d3ZBUDBXbSs0dXJaZUNkMW1xVGJONkhIYzFTcXBLbXBOMnRKK1FXYVJzOURLMHVCSDNMc2VVOG1pWmcxUkIxeDFDQm5QSkxhTmhjSTdiWDRUVVdkOGFOVm9uKy9VbWwyL2hXbjVoeThIem53OG15M0hESS9kcEN3OGNLMWRnc2RmS3drZmFIUk9VbWl2S1hvYzV3N3N6ZldnRVI4cmE4RzdQbzhLZUhQanN1M1pheXBFK25qdEdEWUQ3S1R6Tmd2dXpTQXkzM0sxWlQ4VTVqaXN6YU9JdGpPbGFkaUZZK1hWYzNXeFpucHBJM081V25QRXVzZ3QydWhjaDJQSlpYVlZkM0pQS3FLckYzUHZZbGJOUGhScVdidFZkL2t2dVNRVUc3azBvVFZHb1ZUNXFpNEhWS1UrV1gxa29MZ0xYVzNUVVVjUFRqMFN3cWhDYk5BVnVEU0V5d0RlRVpNZ1l3YW1pL3pDWXE4bUNWd0FhRUNueGlSaEZsdE9GWXEyczA5OVpvRzJ5MWNPUkdSbnh1SlI0ZjJkYXBBNHRGdnVXTTJaWWdvcUNSdWk3ckhoZElvS2lua2FHUnUxRTdKZkhzQjk0cHBYRnBKTFRZRWRWcXduRm5uczBwSjBmS2RGbFUxT0lTTWMzbDV0OVYwWExlUjhVd1dTS3FwTE5BT3JpNnBNUXJ6bGpNWWJpYlcwOFdvbTl1bDE5aGRsR1dNS3pubHFPYWdjSjVCRnF0cEhtdHlHT0xQSjZpR2JUcmRPVE9iNFoycFYrRjBUWUs1enpibXpTdVFkdDFWRG5ocnBHUnZMdEZya2VpK21NMWRpK0pWczhrYmFQUzFvdmRyYmZ3WE1NZDdPS3JEWVpZWktmZS9VSmt0TW1qRisyTUVKYlp5WHpQaFhFTXJUVXRiSUdEZ3FvcXBLcWxxakdiK1hCWDA1aVBaVlVDdm5sTUJzNDM0V2s0cDJZMVVtTlBjS2Z3N2ZaOVZtWk5LN05mRHJOUG1WcWErWnlxZ3dHV3NBZDNaSlBvcnFoeTNJMTREbUZ2ekZsMmJDY2l1dytTSnJvQmF3dmRxNkJWOWloeFRDR1ZjTVJCYXpVZExiTHIwMUlSRHJXT1RwVjh6NWx4REw3NmVQVUcvZXFudTVvcXBqTC9BSExzT1ljR09FUkdtbVlBNXA2amRhN2wvSnJzeFk5REhHMHVEamJZZXFxVHhVYnVtMWtNbEYvbEhzL2x4dWhhOHg2cnR2d3R1dzNzWGxsZmJ1YjdlUytnZXpyc3piZzJEMDdaSXQzc3R1MzFYWHN0ZG5GTTJOczc0eDR0dmhWUjRqMGVMSmhybWo0dFBZTFZTbitaSDBRNXZaMHFuTkpFUDRMOUFvT3ptaWtBMHNCUC9BbTR1emFFRzNjZ2ovZ1NkelJTOThUNFB6VXhQMmZxeUxWK28vQmFWaXZZdFhRTmZhSTdlaS9WNnU3SjZPb2pPcUVDL2t3TFJNd2RpVkFZcENJdC93RGdVM2hxZmlkajhyS3JzMXJxT1Vrc3RZK1NRck1OcXFBRnBhN2J5Qys1dTBEc3pwOE5kSm9pSDlWY1Z4YkpQZnZjMFFBMzIrRmRXU0kxWUpQaytialhUMDBsMmdnajBWL2d2YUhXNGE1bzF1QUhvVjBldDdJWkxsM2RIZmZoYTVpblp2TFNnMmlJKzVCSlJhQWp1czIvSzNiYkxHR05mSzc2RmRCZzdWVzFMVy9yRHVBZVY4NlI1VnFJWkJwYTRXK2F2S1hDOFFnMGtCeCs4ck95d2l6VHd0bjBMUlp5YlZINDczVjdTNHlKTEhVdUE0VmllSTBaQU1ldzh5dHZ3L01kYS9TQ3djK2F6SlFTTlNETzEwbUkzdDRyL2VycWtyOVJGM0JjeHduRlpRR2wzSkFXdzAySVNTRVdXYk9LTFhrZE1vNUJJMGJncTNwR2VJTFNjRHJaR2hvUDRyZWNPYVpOSnR6WlptV0tFeW91NklGdGxmVWtoQUNxNk9FdEF1RmVVc2VwdkN6WlI1Rk1janFTTGNxd3Bhc2kyNVZkQ0JmaFdFQTJDVW9VVm5HeTVwNncyQXVuR3lnMjNWTXcyVEVVM3FuUmRGZVdNdVkzMzZwcU5VOFQ3bmxXbE51RTFNcnVORmhIMFIyQktRUEY5MDYxMXdyc1kyVWlRQ2tYYkxEVGRlVmhRQVpCemtNdjNSaU5sQndRT05BZ0hTZU1JTlR1UW1IUmxMVHRzRjN5Sk5OTXI4VGpEcWQzeUsrYisyeUN3a1A5RXI2TnF2aGRmeVhBTzJtSFZITC9BTUpXTnFPNTZycGI3ZjBQbVRFUnFlNEM2OWhGVStCMmtHMnlzS3ltSGVQVllJaEhKZmhCaFBWVFZveG1BYXQrdGxVc2sxUmx2b25jWnFRUUI2S3Jqa3VDdFhHaE14T1dFTW1KUktnQU5HM1JTbWJkOTBHVjNoc3RDSFlveVFFT2FMN3BhcGxGN0JEcUFTZGlWQ0tGenVibE9zRGFUWkVIY3E3d1NtdklObFd3MFRudUZycmFNR3BqQ0FTRlh5UzREd1FhWnNWS3p1d3kzbXV1ZG56Z0F3anpDNU5ESmZTTGRWMUxJUTkzWTBrbmtIZFpXU3k1SkhTSjhRRUVZM3N0SXpWbUowYlhocmo5eVl6RGpJamJzNnk1dmorWUFXdkZ3Zm1xMU1MSGlUZGxWak9MdmxMeVQxV2pZeGlSRi9FbXNWeHEydmZxdFByYXcxTWgzVnZ3a2VxdUtYQVlWVHBubTVVU3h6WFhVYVh3MlZsSEEwMlhQRE9iMlBZTEtiZ0ZiZlRoam1YditLMUNBQ0hmaFBSNG9ZeGJVaDJNWXBJMmlrZGQvd0I2MkdnZGEyeTBmQzhWYkU4YWp5YjdyZnN2eU1xaURzaTJtVnFKV3VDOG82aHpiYkZiVmgxUUhocXI0S0pyNGhwSDRJakgrNzNDbFVlZHlidHhaVjBJbFpzYnFvZFFFazdLd3BpWlRlNUtabmgxdDJDNE14MTVuTnM0VTlvWDdkRngvRURvcW5EMVhjTTV4YVkzYmRGd3pIbjZhNjM5SlNmQ043U081SWFwNDlUUVU3Q3dQSTJRcUJtdW5hZXFlYXpVd2djcXNwY250c0tySC9RMkxDb1F5RUczUmRWN05JUTk5eVBzbjl5NXhnOFAraXRCNmhkYTdOS0V0Z0RpUHNuOXl2WStUeVhWTWlUWmVWejdPc09pcml3eVN0MjZxem5pMVNIcnVneVdqSEFWbG56NlFSNDBRdEEzTjdiSitDSVFNQjQ2cEdpZnJPKzQ5VWVzcXdXYmRFS1F0S3hURkt3Nkhicm0rWjhTN3N2czViTmpPSkFOYzI2NWxtWEVSRUpTVDBLc1FpV0k0MnptM2FCaTVheVFCeTQzV1A3Nlp6ajVyZHMzVi9mUGtHcSs1V2lQR3A1V2xHTkd2R0FHUWFqWkJJUnpIWXFEZ3JjV04yY0N6eFpDS1BJRUZ5akZOQW5JTHQwVTdJYmhzbUZXaUJBQ2dSWkVJdW9PNFhRUVRsRlpjc0FYVUFvL29mcFE2RTJLYmM2T25ZWkhFZWExR3J6bEN5TXVFZ3VQVmFUalBhazd2RENIT3R4d1Z0WjlYUzdueEEzM0g4NU1qRDJNNXQwV25VZWJacU9vZHFMckZ4SzFsK0xlK2tTRjNLVnhERkl5UVduY0R6V0RMV3kzRU9zMDJhUkpFSHVQUzZaZ3pGRFdYQkkyWEg2Zk1kNHRBZDBzb3R6S2FFbHhrRFJicVZvNGRXMmpoMWFzeHU5dzEzaENvY2N6ZEJTVWo5SkhlVzZMbDJMZHB6YU9GN1dTRngvb202MU1acmZpMGozdmZadlBpMlY3VFFzcDVWUjBMRE00UzFkYTRTT0laYnFyV3B4cUJzUjB5QjU1MlhHSzNNN2FLUXRqZHVkcmhMbk5VdUgwN2pMS0hFN2pTVXZVNCtVTXd4VFIxbXN6TlNRVXNwbWxhN2I0U3ZucnRJeHFpeEd1azdoakdHL0krYVV4ek10Wlh2ZVd5QVIrUldrVnNqcDV6WWpWNXJVNmZodGNsZlVxaHNWRGJhYmhPNGU4Q1N3NnJYeUhNbGJjN0p1bHJlN25qR3JxdGJKQlVWOFdUazNFd2xqQTlDa0xaVDBYcHNSYjdpM3hDNVBta216QnUrb2ZWWkdXQnVZNVdpOG9xbGxNM2NoQnhERVdUa3RCRzZwSjZ2d254ajZxdG1yZEFMZzhiYjhxazF5TWJMd3puRDQzQWp2QWQxcU9ONDNGUXZkTzRnOWRLWXBjMXdWTVQyVkVyUTRHd3U2eTVsblBFeEpVdURaV09qSjZPVnpFaXZrWEFYTUhhZjcyL3VZNGl6ZmtIKzlMVW1PZHpFYW1iZ2I3clNxMkduZU84akhpQnZ5cURNV2RnNkUwak5RMnR1Q3RLUENNbWZjMyt1ejNEVnlsckxEUWVpcGNWN1FnNjFPZlBsY3FiaTdxR1J6eWZqOGtHcnJQZW5DY1g1U3BUbzdGV2RXeGJORGFIQnBDSkx1Y0FSOUZwck14ZCt5U1J6cm0xMXE5VmlGUmlNN0lIT3N3aTI2WG4xVWxvK1FkalpQOGZaMkk4U1pzWnpPSkl3TGNJUnpPZEoySzE5a1lhNGl4V080dTA3THYyaEpjV0w5M1RMVTVvY0pPdktaL3lwT2xhdTZtR3ZoU2ZBUTNnb3ZmWEx1T2pwWW13bk1ja2tvc1NyZ1lzOTlMeWIyV25ZZEZyZUNRcmtTaGpRMVNPZGk1NEZZN1NWVWtrKzVLK3R2WkFxUC9BTXcwbS84QXJCKzlmSDhWUUlqZmRmVEhzaFk0RzVtcEFYVy9XZFQvQUVsUjFHVnMwdExpU1AxaHdXUzJGMDV2OWxRcmF3OTRSZFZlQTRrSDROVEcvd0JqK0tXcTYrOHp0MVJoeXpjcmdlbnE5clhWVlZWdGdkMHZVVmhzVGRVV0pZaVdNZDRsMWxxRWJNWXBpMmpVZFMwZkc4ME9BY0FVTEhzY0xTL3hMbjJJNHozcGNMbmxWcE0xc01DMnFzeEY1Y0NWcitJNG9KQ1ZVMUZiZHgzU3puZDRWV2JOV0dOVU1PbUxqNktjWnVvdGc0VERJZGxMTFNBU3RTOHJOSTVUYzdMSkNlVW5ZWFMyUGlWMVd5OTFWVE4wMzJWMjV1cmxKejA0SktVeXdpaWt1M29vRHhKK3NnMGpZSlNHSTZqc3FvNEE5aEM5cEx1aXNEVFhDbEhTanlYVWlGVytJb0RxWFdWY3pVNGFnaU1YWGFJVkpwTitGQTBsaXJzUXRLaE5DME51alNFc3FERUdnM1NwTGlTRS9PTEUyV0lZUTVQaWhVbUlQYU5PNFZaVjBvZTQyQ3Y1NllrMkF1bWFEQTMxTnZBVDl5Y29pR3pXc1B3bVNhUVdCSzZQbEhKejZxVmwySzJ5cmtrenlzdkdlZkpkenlaa05zT2h4WlpjZ2pNelplQmJKdloweHNEQzVnWFNzR3dHUERiSFNObGJVR0dpaGlBR3lZbHNXSzN0NE1TZVZ1UmdWTFdzTFJzdEd6bkgzN1pGZlYxWDd1VHV0WHhmRUJQcUJOMVR5SXQ0blp5ZkdzUERaWGJlYWpRd2hyYldDdXNmWUM1MWxXMHJObGpubzkzQTlSTUdvYkxhTU9pRjJteW84T3A5VGhzdHB3Nmx1V280OXl2a2x3WHVITkFBMld3MGdHeXFjUHBObXJZS1dsc0FyMEVaVSs0d3ltR3lMN3NBTDdLUGVsdjNJYzlmM2JEdWphNEtsR1h5Q0VIalpWMVhqVFkyT3NSc3FuRmNjMEZ3dXRVck1ZYzVydkYxVkhNNlJid3d0aDh3NWlQaUFLNWZtSEdaWkhPM0t2c1JxVE84N3JYcStoNzIreXhzbVJwbm9zR0ZOR240ZzExU2ZtckxMK0RHV1JwMHF5cDhFN3g0OEszYkx1QnRqQUpiWkRGV1hjdndMZ3RNdFlZMm5oSGhISDhGV1p4b3hVeHVCdHhaYmN4Z3BvN0Jhem1BbVM0dXJjVVpUenZkUnlxcndjUXlFaENnZStHUnU1c0N0cnFjT2RJQ2VWUVZsSVlYRlJvdjQzdVIxanM1eEZsUkd4am5DOXdGdE9ONWFaWHQxQ3h2dXVNNUZ4YVNqcTJ0SjBqVjErYTczZzlVYXlrWWRRUGg4MCt6SmNtY2h6UjJldGUxNURRVnpERk1tU1FQZGFMcXZyR293c1ZXclVObHJPSlpVcDU5UTd0QTJGSEpUUG1BNEsrSzRMQ0ZIOUY2cmkzUmR1eHpKRFdOSlpHdE5ueXJJeDdyTUkrNUJab1F5bkw2aktRa0xqcUc2UWt5VmM5Q3VrMU9GVFEzdURzazJ4dWErem1sRjRsRitHbzNjR2hzeVlRUWRQNEo4NWNJYnBZZEJ0MFhRcVdtamUzY0lWYmhOanJqc0V5R2RwakpZbGtSelkwbFhnMG5lYW5QYmU2MlRCY3lSVjRheWV6ZlBVcmVwb21WRUJqa2JjMnN0SXhmQUphV1l2cDdOQzBvYWwrcGw1ZW5xVHNoMjE5a3NmYURnTTFaaGptd3pzWnBHam05djdselgyYnUxL0creUhPYjhKeGNUdnBPOUVRZEpZTnRZRmRxeWJtcW93aVJ0Tk80bUVueEFBcER0TTdLc0t6bFRlKzBFVFcxcEd2VTV3NVhvTlBybTJsWjQvcW1rbnJJT01UN1N3L1BlV2M0NFF5cXBxcW5aSS9sclNiMldvNWp3TEJjZG1JaGxoSnRZMnV2emlyY1I3UnV5dVFzcHFnbW5idGFPTnp2VG9Wc0dWUGFSekxoN2RkVStZT0Izdkc4TDFHRE1wUlBqUFVmWlRWdWJuRnJ6OWY3SDFmbTdzemdoQWRFV0VIeVhPOFF5SlQwWmJLOXJkM0FFbjVyVlQ3VGxaWFVqZTlsa3VCMWFWUVkvd0J1VStJVUFBa2RxdjFCVHBiWHladVBSYTNSL0MyditmME9zWXhsdkI0TUdkT0pJUTlyUjUrUzFtSHRUdzdBNktvcHBIUnVhRzZSY3JpOWYyaTRyV1lmS3dTa2h4NHNWcEUrRllybUdSd2F4eExqK3dWVHlUUjZEUTlKeVNrbTZOZzdROGNabXJGRDdnMit0dytENXJzUFlWMlZ6eFNRVjFSRWZDUWZFRlc5aHZZUExLNkdvcllSdHZ2c3ZyakJzT3BzSW9HMHNNVHJob0cyL0FXUGx5Y24wUFM5TGxDS2ZCUENhQms4Y1VUUUIzWXN1aFlGaHhrWXlFRzJuZGE3Z0dGUFpJNStralY2TGVNSXBuVWt1dTRGOWxUOFFzWk1VOGZDWmJmbzlsSEdDQ0hHM1JacDZnbDF1Nk52TlgyRFlSSFdXTXBhUWZVSTJZWFlWZ0ZDK1I3NDJrTnY4WVRKWUZWbFdFV25ScnVJVnNVVVRpNGhtM1ZjZ3o3blNudzJDYTA3VGEvQldsZHNYYjNEaFZUTkRTdmM2K3cwWFBYMFhCcXpOT0o1cmMvVzQ2WG43UUlXZmtodE43QXFvdTgyWjNqeFdxZXdFTzNWSFM0ZXlwY0hhQVZUUzVla3BaTzlrZXptL0lWdGgyTngwalF3M1B5V2ZKdEc3amFvdUpNSWdsWUJvYmV5b01YeWhGVU5QNnRxdmFPdjcxd04rVmNOWUptamE2ckxVTmhMVG81ZFQ5bTBjMG9QZGhiWGhmWmJBL1NId04rOEZkQ3dYREkzRUVqNnJhYWFuaEZnMGJya3NyWTZPTkk1VkwyVVVMV1g3bGwva1VzM3M1cG9qWnNUUXUzTndvVHQ0UW41ZVlEZlNxTTVzY3VEazFOa0hTUlpvK2kySERjakFXdTFkSHBzSWJ0NFU4MmdiRU9GbXltTWNqVHFQS0RZd0NBTmxzbUhZVUlpQVJ3cmFLTVdXWlhkM3dxazJLa3lUYWNOYU5nbktVNlJaSnd6Ri9LUHJEZXFweVFxMlB4MkJ1bW81UTBjcXBiVTJIS3c2dHQxU3BJYWxaZWlwYmJrS1VkUzIvSzFwK0lIb1ZtUEVYRThxdTN5RE9QQnQwVllBUnVyT2xydGh1dE5wNm91STNWMVJ5RTJUWXNvemliWFRUWHNyQ045d3FTamZ4dXJhRjF3RnI0MVprc2VZYmhaVUl1Rk05Rm9LS29Cbmp3aHVSQ2h1VmFhNUJSa2tXUzA3UVFWUFVoU3VKQ1Q1RmpMRXJLdG5oZDhpdUJkc0xDNk9XL2tWOUFWSThEL0FKRmNIN1lUYUdhNDZGWXVvN203MDEwL2tmTjlZUDF6eDZxcHFJeUhGV2xaTmFxZU4rVW5WSFk3SWNKNnlVdURYY1JqTGdWV051eHhDdjZsdXBwVkxKRWU4NEsySUlYTHNDbGZaQmViaE5Ud0V0MkNYTGJEZFhZbFZvVWRIYzhKbW1wdU5sRU44U3NLVmcyMlJNNmtPVUZJQzRYQzJHbXBXdGFMV1ZURmFPeEN0YVNwOFBLb3laZGhDaHlOZ2E1dnpXOTVjeFVSeHRBUEZsem1vcTlCKzlXMkRZaVd0dnF0dWtWWU0xeWJObVhHZ0drbHk1amplT01jOXcxSnJOK05FTklEeDlWem1hcWxxcGVibzQ0MFdzQmJUMUFxZ2QxVDFJRVQ3cCtLbmRFd0VsSVZyTlJUcUxXUE01TVpvajNvRmsrNll4aFU5RlVpQURkTXpWalhpMnI4VVNpYUM1VmpuNlNzYlhSbVZiWDczQzEyV1E2aVFzTnEzTTZydXdST2UxbXplK2tTQWdyYk1Eelg3azFvTHQxem1rcVMvbmxOeEY3NUJ1cTdSVis4ZlFXV3M2c3FOSWM3bGJTNmR0UVdscEc0WHp4aGRmSlE2Q0hkVjEvSitMbXViR0M2L0FTMlZjdUZWWjBQRElnV0Q1S3dmRHBhYmpvcS9DcFBHQjBWNVZ4MmlKQ1dZK1NXeDBjNXpkRjNySGl5NFhtU2hMYTY5dnRMNkR6SEI0WHJpK2FJZjlMNCswaHlkajBlaTVraEhEbWFhWm9zbjZhTzVzVU9pakhjQk0weC9YQUtpbnllM2k2eGYwTnZ3cUs3SW0yNVhZOG5SKzVZVzExclhCSDRMbCtYYVh2WFFiWFhZbzZadE5nVVZpQWI4WCtTMWNQWStjZFl6TlRmOUJWMDRjNXg5VWpVUzYzV0N6STdTRFlwV04rdVFxd3p6MGx3V2xGWnJDVDVLdHE2elRHL2ZxanpWSGNNNXN0YnhpczBBMmR6NnJzVWNoRzJVR05ZZ2U5ZHYxWExzN1l0cGE4QXJkc2JxZkE5MXh4NXJqbWNzUU1randEZFhJSTFzV1BnMGJHcHpMSTgzNmxVMmtBRXAydWtMbmxMV3UxYU5VWG94RkhueEZRSVJ6RmR4S0U3aEVtRTBMUENDNEpoNFFYaEdWcEtoWWk2ZzRYUm5CRGNMcHBUQldVSEM2S2RpVkI2NkF3QkN3cGtMd0Zsd0dqOWV4ajBra3pRWkhXK2FXeFNwRXVodzVXcFV1TUNWMTc4TEZmanZkdEJKMkNWaDBzajRodlJ0c2VKdlpBMW9QVkRmTDNNZ0RuazMzM0sxZkNzMFFUWFk1d3VBcXZIYzFpbWNmRnYwVjMzWnJ5QWMwYmxpZU93WVZHSk84MzVzVm8yWU05SEZtdWpqZmIvQUlUWmFKajJaS3F1ZUFIUDBYU01WWUlvd1M2NVdoZ3hVaGJrYlZoMWRORzRtUnhlQ2IrSTNScXJFbnUrRTZma2JMVW00aytVMmFUOXlJK29tWTI1Y1ZjUldvdEo4V2xpZFk3K3BTdUlZbTFqTDk2U2JjRXJYYTNGRGNndTNWUFBpRDMzMVAyVm5IM0FrblJiWWhqNXNRMGhWREsxOGppVW82b1k4N2tFb0w2b1JFV0d5MWNja2tVWnBzZmx4ZDdHa0VCTFUxYTR6YXlldDBuaUZaRzlvMDJ2WlZrbUltQUt3cElWdFp0bGZtT1NPRWhwdmJmbEk0Wm1XYXRMaTUxckcyeFZWUVYwZFd4NGZhNWFlZmt0S3hyRTZyQ0h5Q0lPc1NUc2w1S29zWTdOenpKbnViRHpvWVFlbTVWVmh1ZHFtcWFkZHJFSHF1ZTFOZlVWdjZ5WFY1N29VT01PaThMTC9jc1hLdVRTZ3k1ekxYenpUdU1jMGpiL0FMTGlGcmRSUFVFRFZJOXg5WEVxYzJKRjc3dTNTY2xhSFNBRWJLa2g3R1c0bSttaE9yZTR0dXRacjMrK1BjU0J6MFZ0aXRReHNJSXR5cU9wcW1QSGd0ZjBURTJMYUtxcnB6R2R0L21uY0lwZStIaVVvQTJWM2ovRk9pRXh0dkdQb21XQlFHdG9tZzNic1FPUWxEcEFzZHo2bzg4N3U3SU43cW5NN3UrNjJ1bDJIUTRiUnV1UWk3U00yQ1FxcWtBRDVwcWhsRDI3cVdTaURXQmttNFRoakQ0K0I5RW5VeUJyd21xYW9CWnVwWjJpRkxIb0oydHVpT2Q0bGh6dzBHeVdFdXFUbE5zTmxpTEZpNng3T2VOZm8zTjlINHRJMTM1OVZ5UFhaaTNMc2RyTzd6WlNXZGJ4ZnhDbGxqRXVUOWdNZzVoRmRnRklBNjU3ditLc3ErWXNsY2JybWZaQmlHdkJhVzdyK0QrSzZIaU1nY0RaU3pld3JnU3JNVTBnN3JXY1d4ZTdYRFVqWW5PUUhMVU1VcWo0dDFueVpmeFFkbEpqdUlhM3UzV29UejNjN2Zxcm5GSmRSZGRhKzhYSithcVNadDRvY0FYZUp5TkZHaEVXS0t5U3hDaVkxd0c0d21HQW9FVzlrMHh1eVpZd0c1dDc3Sk4xRnVTUXJNczNRcEhBTGgwcDU2YXdTRWtaRjFleU5EcnBDZUVBcmxCV1ZENEQxRjBBdzZUc0ZjdmdCQ1ZrZzNTUjhXSUJoQ2tRZkpNbUZRZGF5NE5zVGtCS0NRZDAyK3lFNjFpb0treGR2S0hORVhlYUt4cEJLeTRYWEl4WWxNUzkydmU0VEZIaDVxWGdBSDdreEZUT2tJMjVLM2JMV1d0VWpDUnpZcTNqaUp5ejRLN0JNaXVxM3RKYVRmMFhUOHZkbWpkTGJ4ZjhxdjhBTGVYNDRtTk9rTGY4TnBtd05iWWNLNG9tRm15Y2xEaE9RVzBoWTd1N2YrbGJsUVllMmtZQUJhM29tWXBiZ0FCVExTbnhNdWN0d2RqZ1cyUWFrNll5aVI3SWRlUUlDaHlTNEJ4UWJrYUhtQ3MwU0c1V3BWdUliTzM2S3l6WldhSm5DL1ZhZExVR1MrNndzenRucHRQQ2tMVmRaM2ozRG5kZXB3WGtiSVRZZFVpdTZHamFXZzJDcEkwSjloN0I0amNiTGJzTnBEZHV5cHNNcGdDTmd0dXc2SWVIWk9pWmVRczZPTFMwYkt5amswQkx4dERXS0Q1UTI2ZW1WaWM5Y0dnOEtscjhSdUNMcjFkVkFBN3JYYXlySmNkMG5Ka3RETWNhRnNTcUM4dTNXdTFCSnZ1VmJUdjFrK3FUZlRGeDRXWmtiWnFZM1NLVjhKYzVTYlNGM1JXd290K0VlS2tBSTJWYWl4dkU2TEROTGdTMzhGc0ZKRUkyaXdzaHhob3RZSTRkdHNyUGtWckNQZmNGYW5qZzFTSGNyWjNHN1N0Y3hXRnpuRTJRTVpFUmhwZytFOWRsVFZ1RjNrSnN0Z3A3aHBDaFBFSEU3SVdPUnFjVk82S2NPYU5OdkpkVHlYaStpTnJIT3ViVzNLMHc0ZFpwTmszZ2t6NldxQTN0ZE1oSURPdURzN0poSTI0S0hORjZmZ3E3QzYwU3dOM1ZvNTRlRmNpMHp6K1JOTXFxbUJyd1FXZy9jcVdyd2hraFA2dHY5VmJVNkFFWFNVN0FEYXlqaU14eW81OWkyV21PQjhBK2kxWEVNdHRiZXpiSDVMcjlYUkNWdkMxbkU4TTNPeVZSc1k4cXM1bXpCdTdKNTJDV2xEbVhIa3R6cWFEdXlWVFQwRFhYMkNCbzFzZVZOR3R2YnFIQ1JxTVBFdDdpL3dCeTJTYkRpTDJWWlV3UGpPd1FsamRacTlkZ1hkTkxvMjcvQUNTTkZpTlZoODFuandqb1N0cWU4eC9HTGoxVmJXeFJWQU5vd0NyRWMxQVR3cGszNWx3dXBqN3VyZ3AzNnRpWHh0UDcxVjF2WjlsUEhBUzE3V0YrOW1SZ2Z4VmRXNVhmVkV1YkxvNnJXY2FneERDUVREVVBOaDlsWDhlcXJ6TTNMbzkza1dPTGRpT0ZOYVRUVFNPdjZmM3FpaTdBeldTRFQzcGI5NkZRWnV4TmtscFhTT0E4N0szZDJtVldIRnRtUE82dngxbGVabVM2YmI3ZnNYZUNlejdDQzFzalgyOVF1cjVQN0JzT29TMlIwVjdiN3hybGxOMnV5UGdEMkJ3SXR3VWtmYVNxc05xREU0dkF2YmtmbWlqcS93QXhqNlhHajZ2cDh0WWRoY2JZMjJpNmVGb0NzNmVscGNPQWZmVjE4UVh5Rlhkdk5iaU1mZVJTU2MzMklTc1h0Q1lnNXBaSjNtMjI1Q3NyVm9yL0FHWXZ6UHMwNXl3K2kyZTlqQVBRS3F4YnRod21oWTR0cVczYmM5RjhRNWs3YXE2b0IwU1NOK1JDMG1UdEN4R3VjNHZxcExXNE5rdVdxUWE2YWw2bjJuaW50ZjhBNkVEMjA4a1Q5Sk5ya0xrMmMvYWR4UE9iblJ1bEViRHQrcmt0KzVmT2h6SUs0bHJtNm5YdGNwZDBOVlBJREMxd0JQUlZYbE9MRWs3bzZwK21LT29rNzJxcUhQZjVQTi8zcWRSbnhsRkhwalpFQU9DQUZxdVg4Sk1qQjd6TnBQazVYanN1eDFSQUZpRW1XUWZHQXY4QXB0Mk16WEx5QmZocFZuQlNrRnVtN3QrcUMzS3NsT0FZd2Z1VzBaYXdoNUxlK2I5VlhjMFBVU3h3ZkNYeTZOajBXeXhVcHBRMjQrcWN3dUNPRFRzRTdVUk1tdGF5cnRqV1l3OXhlQllXK1N2NkpwRGdxbkRvQkdSZGJGUndiZ3BNcEMyVzlGOEkyNkp0d0hrZzBzZmhDYjBYU1d3S01STnNlRXpZYWVFTmpiS1plQUZueUhvREtMSFpRQTh3cHlPM3VndWtzcXNocVJNdUFIa2dQazM1VUpKVUIwbDFXYUdwQm5URzNLajNwUWpJRjdVUFJLbVdFZ3paRXpBM1VVbTF3VEZQTDRncWtrREpGdFNNc1FyK2lJYUF0ZWdsNFZ2U3pHd1hVVVpvMk9pSGlHNnZxWnV3V3VVTDdscTJLamQ0UXRYRlpqNU94WnhOMlV5eFJpT3lZRE9GcHdUb3pKZHdCYlljSVQycHNzUW5zUVNRY1dKbHVsQWtiZE9UTjMyUzgxbU11VldqOEkySExLeW9hYk9YRU8yaGxxYVRiN1A4RjNKemhLVFpjZDdhS1lPcEpQOEFoL2dzalZPMmIya1hLUGxLckY2eVQ1cUU3UENkazlYVSttc2srYVhuWlpwU3RPcVBXNE8zSlF6YjMrYVJtQUZ6WUt4a2pOejgwblBIWUZhbVB1QmtYQWcrUUM0TmtqSThYS2JuWVNTcTZhNEswWTlpblRzbTBndVZoVGJBS3RwOTNLeWk4SVNaOXk1alE5REluSVpOMVd3bE9RYzhxdVdtek5kS2Jva1ZXV1JIZXlWcnpaVTJKNHNLZGhBUFJFa0tLN01GVzZTZjRpUmZ6V01LcGpLMEhUK0NTYkw3OU5jK2EyTEQ0MndSV3QwVEVxSFJkQ3RTZERiY0trcXdYWHNyVEU1QzI2cTJPRHlicHFHdVJVVkV6b2I3a0pWbUpGcjkzSDZwM0ZJT2JMV3BnNXIweEF1WnRNZUl0ZkdCc2RsT0o0a04xcjlLOGh2UFJQUTFlbmE2YWdISXRtMW9qZU9BcmVrcmc1ZzRXb3pTSFVMRlcySFNIUnVlaXB6aU5nemFhZXVzNEFucXVtWkRydTRtajMySkM0d3lVaVJ1L1ZkS3laV2gwMFFKOGxWY1NaWDhKOUFZUlZpb2RIYTMzTGRKS1p6cU1HMTF6ZkxkV3hza1c0WFlNTll5cm9CeHdWMUk4NW5YSnkvTjBRamdlVHRzdUo0NU0yU3FjM25kZHY3UzJHanA1ZCtoWHo1V3lPZlhQTjdqVXFjejAvUjQxSldNUnhscmI3cHZEQm9rMzMzNnBPU3BEV1dWbmw2bk5YTTBXNnBDanlldjFXUkxIL1E2ZmtlRXl2YnRkZEhydThpZ0RkN2VTMWZKTkMya2F3dUFHeTZCTXlHcGlzQzFhV05VandlcG1wU1pwTlpON3NlZWQxS2xkcmJyVnpVNWVOWUhPNkFxaXFtbWdjWXlmUmNnK1REbGljZVJURmFyVnFGK0ZwMktWdnhYY1NyekZxblFIRy9LMHZGcWp3T04xb3dWb1BId3pYY3k0bGFGdzFXMlhJTWNxdThtZnZkYmptbkU5SmMzVXVjVjlRWkpDVS9hYmVLTm9Ua0Z5ZHJwZDRzbVNMaTZESUZhUlphRjNkVU53MlJpTG9iaHNqUlhraFdRYkpkd3VtcEFsM2hHVjJnRGg2SVQwZHdRbnRVRU1BNGNyQjRVM0RsUVBDSVZJRzRicUI1VTNjcUI1UklTejd4Wm04MGtaT3I2SmVwenQ3eEErN2p4MVdoNHppTHFUY0c0dDFWUCtuRzFUU3d1c2ZSZTF3NmFKOEFsS2pkS0xOOGtkVzR0ZnNBaTFPWTVNWGtCdWJEYmRhTFR6TnAzM0RpZW02dXFPc2JvNkptWFRwQ3Q1ZXZ4WmcweGIzNFE2cHJtUmg0Y055cWxuNjZXOStxY25CYkh1U3E4WUpEb3V5WXJacVFoMnJiblpTbnpETkpGcHVlUEpWOGxTTDc5RkgzdHR1bjBWZGhwQVh2cUttUytvZmVvVk1MOUh4QzZ6SlZqVUFMQysyeUpQVGFXQjF6dUxvb3NqaHdVclM2T1E2aUVTb3EyaHZCUHlRNnFBdmViRXFFYmU2Rm5iL05Yb1RvcVNnS3pQTFJxS1JucUJJTFdLdEh3Nm1sVmpob2tPeXNSbUE0RmJKaVRxRisyeVV4VEVoV3RCTnpzajQzQVp4c092UlVWUTUxRnRhL3pUSk8wY2pHbUlZblhGc1pZM2JvcUNHb2tpa0pKVjNYVWpxbU15RVcydnN0Ym1sTU1oYmI2ckx5OXkzRW5VNGtHeWdDNkhKVkN3Y296UXNJMVgzc2s1SldzQkYxU0xCREZNUjFSYWJxa2pxSFFYTHZPNlBXanZTU0NxK1YvaVhMTzFaYjBWVDd4SUxiZk5iREhLMkNJM045dWhXbHd6aGcyTmxjNGRWZ2p4T3Y4MU54M2FScnFxem5DeFNqbUJ6ZFFUOHgxazNhUG9ndVkyeWdlMHA1ZzU3N0oya2VXTldKbmhwSUFIMFdHQ3d1b1NpRlRNUy9sWmpxaTBDeVdyTnloUU9JVU9VV2huSmJ5b3dQTHBFc0RjSTlLUUhvdHgxb3NKSGtSbmRYM1poVkduelhTbTl2Ri9FTFc2bC9oVDJVcWw4T2FhTjFyQWYzS2JpeGlYSitwL1luaUptd21rR29mQi9GZGxxMm5RVjh6OWltTHVkUVliWS9aSFgxWDBsTFZtU0xoVGNiMkZjR3RZcTNaMjYwekZHMjFicmNzV2lJYTQzSzBURjNsaEt6NVNOckREazFuRWdkVHJLaU1wMUg1cTdxNnpjalpVOG8zSnNxa3BjbTNpandRQjFJaldLTVE4U2RhMFd1dXBqWEVuQ09FOUVMaEt4TTNUc1Rka2FrSm95V0pXcGpUcDRTMGh1VVNZREViRVhTVldTSGNIbFcrajBTbFRFSEhoR2diRUNka0Z6ZDAyK0xTRUJ6d05rcWhzWkFTd0VGS1BndVNuUzNVZ21NbFNodDhDTDRFRjBCdnNGWUdtSkthZ3c5emh3dTBLbElxR3dYNkppbm9USThYYXJpbndrbDNDdUtMQ0xFZUZPU0t6bFFuaG1CQ1F0T25xdWlZRGhQZGxtM2txdkQ2RFJwMjZyY2NMakEwYmVTc1JSUnk1T0RaTUtweXhqUXRqcEkvQ09GcjlJZElDdXFPUzRBdXJLb3hNamJMU0NRQTdwaDFSWWNGQ3BxY25kRnFiUk1OMXlUb3FZL2lZSTFWcnBMRWF3Kzd1M1NGYmlUWTNIZFVlSjQ4MXNMaHFXZmx5K1J1YWZENW1sWnZxeWFoMi9WYTdUdjFqbEV6SGlQdkZTYkhxbEtFbXdXZkoyYm1PTzFEVVZ6Sjk2MlBEbUV0Q3BhV0FsMTdLL3c5cGJiWklPVGZCc1dHVTk3YkxacUZnQmF0Zm9KQ0dqWlhkSkxhMjZKTXo1bHRKTDNiT2VpcUtxdEljYkZTcTUvRHNWVlBrdVQxUmJoTkFxdWN2dXE0eEdWeWJlZThOa2Fub25PM3NxcnRqMXdWL3dDajc3MlVUUzI2TFlHMG1sdTQvQkoxRVlGOWtwd0dLWlVtRURvc2FMSnAyeFEzdXQwQ0RiUXhTc0d4bTZNR2JMRExJaGNBRkdSTUE4NmJxdHhCb2MwcXhsZnVVaFY3Z29HTml5cFliUHRaSExBVmtNQUtJUnNoWTVNRzlndFlJQmc3dHdjQW0yQlRzQ2VFdFdnOGpVa1crQVY3ck5hVGI1cmJtUytFV1BSYUxUSFNSYmI1TFpLQ3F2cHVicTdqa1krV0hKZlJ5NmhaUmxwdGR5Z3RsQkFzbUlKZk5YSTB5bTFRb0lYT0JCVlhYMGhjU3RoTy9DVHFvTlE0UzJoa2NqVE5JeEtoSXZzdGRtcEMwbmJxdWdWZUhsMTlscnRaUm54RFNnY1RTeFpqV0h4Z2l4Q1Nub212dnNybW9waTF4MlFRMnczQ0JvMFlaalM4V3BoSGZ3bjdsVFNOYUdrZ0VGYjVWMFRhbSszNEtxcU12ZUVrQS9SYzhJdkxVSTBTZXNsaWZZWEFXSHcwbGF6OVl3a25sVzJLWWRMQzRnUmkzeVZZK2swRHFGMVFhSFJ5eGZjcDZuTFZJOXhNYkxmZUZRNHRsS040ZFlENnJjdTZMdGtPVERIeUc5aVFpcGp0MERtVk5sNTFDOHNMU1FUZlpWMk9kbTN2clBlR3RGK2Q3THNINkpidGRndjhsaVRCOWJiVzJUYmFNaHViT0VZZmhqc01rRVQyRzNHd1d6VW1VNmJFdE9sb0JQbVF0NXJNcUNSeElqSDBRSWNyU3d1QmJxSHl1alVtQTk1b09POW0vY3dsekdoMjMyYkZhYzNKbFVaN2QyN1QxOEsrajhOd043Z0E5dW9mMHQxYnR5bkRJMjVoWUQvd0JIeXdMbWNFd2pzM2dxQ3dzaDB1MnVUNXJaWXNvT3d4Z0dtL3lYVDJZR3luZHN3RGZvRWRtQ05tNWJmN2t0NUFOcU9XTXlwTlh2QllMYjMzVzFZWmxweld0dUJ0WUxiMjRReW40YmI3bEh1OUY3Q3lEZUdvb3AyVWpZQ0d1YVQwMlZsQlJzMEF0Rmo2cVRuTnZ3UG9zaCsreUJ5RG9QRTAzc25vR0ZMVTBaa0lWelJZYzU1R3hTM0lVVHA0UzYyeXZhWWxvYnN2VWVHbHJSZHFzR1EySEg0SlVwbmFzSkJKc0V5SkV1eGxrVUN3U1hJbTBZTHRsQjBucWdoeFdIRlZXT1NKdWZjY3BhU1RsZWNiWFFYRktZNUlpNS9tc0FnMzNVSEd5RzRwVGlOU01sWmFDU2hBaTZJMGhWcHJnYlFkbzJSb1JZcFVPc21LZVlFcXBKY2d5UmFVeE53cjZoanVBcUdsZUNRcjJpRjdiOVYxSW96UnNtSHczSVd5VWNQaENvTUxidTFiVlJOOEEyV3ZpWEpoWldOUVJiSmdONFVXS1Y3QmFrVndaY255ZUxRQWd2YnpaRTZyRnJvSlI1RGl4VFRxZHVxM0dYOTFEdDVLOHFJaElOdGxybVozaW1vWGsvczlWUjFIK1dpMWcrSmxiaDFRSk5YaUJJQjZyay9iSFY2cWVVWCt5VnNlRVppREt4N0M3N0swTHRYcURMRzgzNWF2TjVNbTVucWRMaTVzNE5WTkw2cVRZOHBPcllCY0t6bmtzOSt3VkxYU0V2S3RZbFI2TEdxUWhMRUJkSlRSaFBQM0NXZkJxV2hIZzVKV1Y3NmNFSDgxUjFjUkJLMmMwWHFVblZVTmdmRCtDdHhsd0kyY2xEU3RzN2RXQklBNVNzOEdoeHRzZ2g1QjVLajVIeFZGakZLbklaRlZ4RGRPaDlvdnVRUlZzWkptTVNuQVk3eERqeldqMTh6cXFWd3Z0ZXl0Y1psY1hPczQvVlVjRHRjdjNxd29DYjVMYkM2TXh0RGxmVTdDK3dTZEJGK3FIeVZoVCtCd1FOVU9peFBHYVhUSGYwV3NsL2R2SVc3WXhUOS9EdDVMVHFxazdpUWszUklsc1huQWxhVnJXSk1FYmlRdG1jNE9hVnJtSi9FVXhBV0xVOCsxazFINGpkSVJqbE13a2h5YWdiR3U4TG5EbFdkTk4zYk52SlZ6Smc0Z1dGMDQwZUJjbkVzUmxSWVUwL2VTTkYrcTN6QUpIVWtzVGg2RmM4b1cvckcyUFZiN2hsVFlNRzNBVktTU096ZG82M2xmRlpKWm9nTGxmUVdWYWgzNlBhWEcyeC9jdm52czhqNytvWVNPcTcvU1BaU1VCSk9telQrNUI1R1RramJPV2R0bVlCRTJSZ1AyVCs1Y1NwNWhVYTMvQUhyZSsxM0VHNHJQSUd1dmE0MlhQS1MxUEFSMXNxVFZucDlCVUtZVUF5eldHKzYzN0pWSmFWbmhQSzB6QllqTk9EYTRYVnNwVWdqRFpTUGh0MFVVT1N4cnRUVWEvVTNpalBjVTdTRFkyNnAybXhWN0R1NndWUEpKNzAwV050SGtrS21xTTd4QTBtNE45bGJpcVI0NXpjNUcvdHpHMkNBaTUrNWFiamVJZTh6T2VQTzZzYVNpa25wTDJKdFphemlrdnUwajJ1U29Ma3Y1SUpyZ3FNVXFlOFk0WDRXaTR2aU9tTjRMcmI5VmU0eFhCc2p6ZXdYT2MyWW1ITmNHdXQ4bHFZMFZZWUh1TlB6UFdHU2QxamZkYTBXYXhjcXdxbkdSN2lUZEtFYnExWnU0SVVoZHdzZ3lDNlpjUFJBZUxJN0NhRm5EeVEzQXBnaTZGSndqVEs4a0tQR3lBOEpzcGVYbEhaWGNSWW9Ua1p3M1FYQzZJcXRBM0JCSVJqdGRDZHlpRXRBenloa2JvcmxDeUpDbWo2enJLS09vaU9zajcxb21MVXhwYWc5MmRyOUZ1azRsbDJCVkxpMkdPalpyZHVlVjcvQlBrL1BVMEo0VU8rWU5aMzlWWndzYzNncW53ME9kTFlHeXY0WkJzRTdNK0NzdTQ5UU1JM0tQWFNFaXdRNHBkTFJhNncrVHZEdUNzemR5WDhhNEFHSWxwS1VjMDZpRlp0Tm96ZlpKYnVtMmFUdXE4a05RcFBHNXJnZlZQUXlPcVFHbjVMTlZFZFB3bjZJTVZVS1k3N0phWXlpVlRUQ050eXFtZHd1VmFWRmVKMjJCVlpMRVhPMjZwMFpDSklWaXFOVndmTkxWRWQzWFRiNlR1ZHdoUDNDc1FrQkpGYlVRNmh1cTJXaFpMZHp3TnZOWGoyWDZKU2FsTXJDMEJXdDNBaG8xWEVaR0JwaVlCNWJMVksra2JDWE9jQmYxVzQ0amhUcVo1ZVJ0eXFLdXBUWGdnZlBkVko4akltbnVjOXhOellYUzBzVi90SzF4Q2tkVGc5RlJ5eVAxRVhWQXNoR3dNT3hJUTVNSEJCTjBFOTVxRmp0ZFhMYnZoRzk5a3RzWWpYSnFNUkcxMU9uUGRrZUpFcm1PN3l5VGtqZU9FRmpLTG1wbWIzWXNSZXlySFR2MUhjb1RwWE1HNVVmZVFSMVREdEJqSzM3U0VLb1hTODJwOTdKWU9JS2gyaDk1RW5WWUVlbENqZHNzdWwzc29TaWJaTGdoSHAzK05BaWp1THJMU1dQWExCWmF1YnJhbWNKbEVHS3d5VzQ2cEdPWWxuQktuSEozYnRWaUNQTlN4K0pjbjZCOWdlS0NlZ29QUm8vZXZyR2ttRXRLRFpmR0hzMzFMWk1PbzduZlNQM3I3S3dvdGRRdFVzM3NQWXFzWGY0SExROFlJSmR3dDZ4bjRYV1dnWXl6ZDI2ejVzMjhMNU5acTJzMUhoVmt3VDFXMDZqdWtwU1BOVkpNMjhmWWpFTjA4d2JKT0hsT3R0WlJNYTJIaklUVENMS3RaSWJwMkoxd2lURk1PN2RSN3E2OFRzc3hQSlBCVG9zVElGSXpTQ2twdVNyU1Z1b0pZMCtyb25vUXlyazhRU2tzSlZzK21EU2wzeFhOa0FjV1ZicnQyVW8yRWxQbWpEbGh0UHZ3b09zRkRCY2hYRkhTZ2diSldDQ3hHeXVLT08xbEJNbVRwcUlBalpXa0ZNRzlGQ0lodGt6SElMcHFaU2xJY3BvN1cyV3cwTGcyeXBLWjRzRTlETVJ3VXhNcVQ1Tm5wcWdiYnE5dzg2aTM1clRLT2NsNHV0MXdSb2VHa3B5a1ZKUXMydWpodXh2eVZkanJ1NWlPL1JXdFBPR1JqMFdwNXZ4VHVvbmI5RjNNNlJTMDBMa2FaakdJbHNqdkV0VXhYRnJ4dXM2NkRqV09YbGVOUzFtV3RNb2RjOGxZV1NYSjYzQkNvb0hKTjMxU2JucXJpbGEwTUhDMStJRjAxMXNWR3dsb1FJZkowWEZHMXBJV3dVTUxkdUZTMFVCdTFYOUd6U0FnSzgzd1hWSkcwQUp0cExVbFRPSUlWazZQd2hRcFM3aTB6aTRKVXd1S3NXUWx4NEtZYlNEeVhPUVVWbFBSK0lFcTRwNlpyR2NCUmJHR0hoSEQ3Qk5VRUM1QzlRUTIreXFLZzN1cktwTnlVcE5EdGRSd094WldPanVWRjFOY1hUb2lzVjV3QVZLYW91UVJYRm1sUWU2d1Rra2FUbWJaS1p5eFo1dmRCa0dvSXptODJDZzFwUEtCalVKT1pZcndGd2p6TXQwUW10ODBMR3BrR3QzVWlMRlpBc3ZIbEU0MEtVMncwUlZoUlRGcmh1cTJJMlJZNVN3cVJkTTVKV2phNldmVzBicDZONjF5aHFUdHVyaUdlNEc2dXdrVUp4NUxVT3RaRGU0SVlsdUI1ckY5UlQ2RXVKRjdRNEhaVmRWaG9kYzI1VndJMUJ4RHRrRFIyTXFOS3I4THRld1ZMTlJGcnJXWFE2aWpiSURzcXFvd2tPdjRVTkY2RXpUMzRlR3R1Q0NscGFkd0JGcmhiRWNPa1k0MzR1Z3kwN1c3RUZUZVhEVUtyRFdURTNZRlVWV1dRUVNMTGYzVWJIL1pTa3RDNFg4bDJ4aWswYzJteSs2SWtnWFNyNlNTSTI3c3JwWm9XbjRtbEx5NFRDLzdCdXBZeFpXYUEraXNBVk9HbEY5MXVOUmxzMnVBRWtjQWV3L0NsT1pZam5pVW42UGpkMENJekM0d1Jkb1ZxN0MzczZMSmpMaGF4MlMvRWRqSG1qUWxIU3hSOEFJM3U3M2ZDTmxMM1p3ZGV5dEtNdGF5eEJ1ck1jbGxhV2VKVk53a1NHNVdIVUFnQ3MzUGRIZTNtZ1NhcGtrV1U4MU9YM3NWWFQwNTMyV3h1cFN4Qjl3MW40U29jczFjMGozTzRLYmd3eDdpUENWdE5MZ29jUmRwVjVTNEUwQUhTdTBjY2pYc053VWd0dUZzMUpoalkyaTRDZWdvbXgyMjRSM05zTEJWR3pnQnNBWU9BaDkxdW1iR3lHN2hKYkdJSHBBV0NRQVZseFFuRktiRG94ZmRZYzdaWXVzRTdJQnFRTjVRQ1VWNkE3elhCeVJCN2tKeFJIb0xqeWdvYWtRQU4xTm9LRjMxdk5UYk1GVWtnNkNpNllnYllwVnM0NFRVTWdObFVrZ1pJczZSNUJDMkxEMzMwL05hNVIySkMyakRZUlpwVVJRbWJaaGJQaFcwMGJmQUZybUdOK0Mzb3RucFcrQWVhMjhTUE81R010R3lrVzhMd0N6WmFjVndaa3U1QWk2aVJzaUVMQUNHU0RpeUxHTzBtNjB2UDFSb29IaitpdDZNZzdvcm52YUFOVkZKOGxtOVRXMlBIb1c5SnpJNG5SMStqRW5lTG9xelA5WTJvcGp2Zncvd1N0VE9ZTVNmWXFzekpNNmFBM045bDQ2RGJtZTYwa2ZoUnptcUk3MTZxNnRnM1Z0VlJFeXUrYXJhMklnRmEwZUVhZllxQzdjb2NsK2laRk9RVHN2UGFHdDRWOUhhSzl6bkE5Vktkd0xGS1NRQjFsNmFQd3BrV1NpaHJXM0pWYTRXY3JpdGJhNnBwbmFYSjZJTnhtMWxpZXBER0ZCYSt3RzZScnFnQnAzWFlJR1RLL0U2alc0N3BLbFpaOS9WQnFweVgzNkk5RzRPdHVycVhBcnpOZ29ha0JvQ3RXT0JiZGE5VEd6aHVGYWU4YVdBQXF2TWJFc0JOM2dzVnIrTlFsMTlJVmdaOU5yRlNFWXFCdWhRMmpUMnh2YVRlNnE4Uml1U3QxcmFGc1ljUU9pMDNFU1E5MnhURUMwaEJrSXNwTmJwV1Evd29abHNVMUFVU2dObjdxdzk0RFdBS3A3M1NlVm52M1BjQUxsU2I0T3BteVlXZThlMnk2QmdGRzZwZXdBZVMwbkxGSTZZczhKK2k3WGtYQVE1OFpjMjNIS3pwdWdtYi8yZllYN3ExcjNDMnkydk5PWmZjcVdSalhXMklTZEt4dUhVbTIzaFhPYzlaZ0psY0E2KzZUdUs4bzhtcFpnckpKNXBYT0pOM0Vxa2cxU3lXM1I4U3hIdm5XQUoyVFdFd2FyT0lQM29FYk9DVzFGL2dGRUk5Sks2VGdyeEhvaUgyckZhVGhVZHkyeTNuQzRMTWJPZGkzelQ0b3pkZGtiK3BZMTFSN2hHTEg0d2hZWkRyZjM3dXFVcUpEaVV1azhNUFZQd3Y3bUV4ZVFUREd3OG0zWVBpVURhRjRPbTkxempObGUxMVhKb08xK2lhZld2cFlaTE90YzNXbTR0Vm1SMGozT0NaQ0NOWERKemZKUVk5WDZCSjR1aFhMc1pyM1RTUEYrcFd4NW54Z3RtYzBHOTl0bHFGV05icitlNnRMZzNjZUJOV0tBYWdTVUI0M0tjMDZXZVNWY055cHVDbEhZTGtJTWdUTGdnUENlS2FGeUVHVGhNT1M4bkJSb1JKQzVTOHZKVEJTOG5KUmxab0E0Y29UZ2prWFFuaXdUQ213SkNDZVVkM1ZBUEtNVElnOVFVM29hSkNXZldIdmNVWjVTZUlTeDFNZktxeTU4aCtKWWxMbU50cVh0WU0vUGMrRUJaVEJrbDJraFdrY1RydDJTTkt3eVhkZmdYVXFiRXlaZEpid2JLeTFhS3lkTXY0WGFHRFVPaUxFNXJybnkzU1FxR3ZqRzRHeU5SeU1MckZ3M1ZHY09TOWptZ05iVmwwVGdBQmJ5UjZDc2JGRGR6UWR1b1JNUm8yUjA3aUxlYXJKQVJCdDVKVzRNdW4xOFV0S1RadDdIb3RMcjY1MDhyZ05oZTJ5WmZVdmppQXViS1BjTWVMaTF5cFowalNOdTNjbFBSV0Y5cjdkVWwzYm1uWk5RU2FCWnloMm1CZVM4a0pWelMxM0NkbEFZN2JydXBzcERLTDZVT1hJcU93eHV3ZE5RbXFBMlVxckRoQTRiSzJ3MWpZU0FRbThUb05ZRGg1TE44VDR1NWIyY0dsWXZnN3A2VWtNdnQ1TFFLaWlscFpuZUd3QzdIT3o5UVdhTDdMVE1Xd3g1Yy93RFZFQWkxMXBZc2lvcVR4bkxzYWN5ZHhEZWVMTFVxNkl0ZU5yYnJkTWN3ODRmVkhVYjN1VlE0dFFtYUFQakhTK3k1SkNWRmxPWEdLRVdBUHpXYWV1N2s2VDFLUU04a1Boa2FmdlF4ZVIycTlsVmE1SFJWRnBWVS9mRHZCODFYNndTVzI0VGNGWnFiM1orU0JWdzkzZHdSb2FpdnFSck95R0JvYWlIbFFsNFVCUE1Hc2xEbWlzZUVTaitKSG5qQUtnYUV0QkRGR1BuZE5QQURFdXdYZW9FTVV6OUozUnBQSGF3UytndFROT05TRkhJajFBUkdCY0Q3MWpGTlR0Mml3dDBYbVJrY0ptWnVxbWNTMUcreDFkejZ2OW03RXozRkd6VnVBUDNyN2t3YWR6c1BZUXZ6dTluUEZTeXFZM295MzhGOStaVXhBVk9GeHF0STlKcE93NWlkeXdyUXNiQnU1Yi9pQXV3clI4Y2ozY2tUTnpCM05NcStUdXF4elRxUEt0YXh0bkZJdWFGUWwzTi9IMkl4WENmak95VWpidW5JbWxDRFB1WmFON284YmtJc05saGx3NUdjYkhXaTVDYWJJQmJZSlNKMXJKc0J0Z2RrYVltUk85eHdvdVpjY0tXdG9VVE0yNlltVjJoU1duSktEN3R6c25ueUJRRHdmSk5zNVFnK25JUFZGWkhZY0k4aENIckFVc2xCWW1nZEU1R1FBcThTZ2RVVnRTTFd1dTJUYVBhd2VDbTZkdzgxU01tT3JsV0VFbG04cDdtaFdXSEJjTnFBM2E2dWNKakQ3WE4xcUV0UnBON3F5d1hHZzJaclNVdFRSWFdNM3lHaklMU0F0bXdoeGpEUVZSWVpWeHpRdE54d3RpdzBzZGExaytNalB6eDVMMldUVEdEZm91Y1o2eFFSeE9CZFpiM1hUOTNBU2R0bHhUdEN4UUZ6d0hkVWliNEdhR0h4R2oxMVozMDU4UlNVa25rVlh1cXozcDNUREhhN0xObTdaNmZ0RXQ4TTNjTDdyWW9PbnpWQmhqTnd0bHBvcmdKSWd2TVBQd3E0aDN0WlZkQkVmQ3J1bmdKTFZFaXBrZkJhWWV6VlpYN0tUVTBiSkRDNk1sb05sZlJSRUFLeEZHWmtZc3lpdDBSaEFHamRNbGxtOEpTWjVhVlpqMkt2Y0RMWUhoQmM4ZEZpYVc5MEFPSktwc3NKR0p4ZEx5RFpOUEZ3Z0Z0MERZNklpOGJyQkhvbUh4OVVFaEFPUXRKZEtTTlBrclF0YVFodmlhZWlVeHBXYUQ1TDJqMHNublJOUVRHa002SnlSZ2poS1NSYjhLME1WME4xTmRKYUlWb2JxMldUU25sT0NsTERleTg0YldzbXBCUm1oQXNMU3B0WlpIZEZkRHZiWkdrRzVXaGluZnBJVm5CUFlEZFU3RHVuSWlka3hGYWFMNm5rRnh1bkEvWlUxUE51RSt5WFpNVEtkRGpYWFh0S0F5VkU3eTRUVXpqUEZpZ1k3ZzdmZ3A2bDR1MlRVQ1YwOUpxdllmZ3F5ZkRpU2Rsc05ycUw0UVJleWc1U05ZT0hrQTdKVjFNYm5aYlBMRU54Wkp1b3JGUWRHUnJ6cU8vVDhGRDNEclpYcjZjTnZzZ3VqSGtvT1V5dGJUdEEzL2NzU3d4MjRIMFRqNmMyNVM3NmNucWxiUm05RlhQU3NkZXcvQklQcFIwYVBvcjUxSmZxbDNVbm9oY1ExTW9uVXZwK0NpS1ErWDRLODl5dWVGTnRCNklOcDNlaWxGRVRiWkViaDVQMmZ3Vjh5ZzlFMURRRHlYV3dkNXJiY0tMajhQNEo2SEJBTGVIOEZzTEtCbzZCR01JYjBTbVRjVTBPR3RqSHdqNkk0Z0RSNUoxN2ZSQUxUdWxOZzdoWXRBUENHNGJjSmtzMlFKQlpJTENBdTRRM0RaRVBWRGR3aFk2SUYzS2dlVk4zS2dlVUExQVpkaWh0NVJKa0c0dWhZMUdYa0lMcktUM0laS0Zqb2c1Q2dPUlhsQkx1VXRqVVJOdkpRdUF2T2NoNnJGS21GSkJBVWFsZDRrcUhYUjRIV0tweUdSN0Y1U1NiaGJWaGNsdzNkYWJTT09vTGJNSUJPbGNpak4xSjBMQlFDRzllRnNrQTJDMXpCQnN6N2xzY08xbDZMR2VUeUlhT3dVZ1JzaE9OZ3BzM0swSUl6NWNCZzI0NFdERjZJckc3SW1pNk54RjdoS2FBYVR1Vm91ZnFacHcyVGMvQ3VnMUVKRENiclFzOU0xNGZLTC9aV1JyMThKb2RNKytqNWF4Tm9peFI5M0ZWdU1WUWZDUUQwVDJaWXpIaWNtNjErcWZyYVJkZVFhK0krbFlHdGlOY3FHRXpFK3FTcm9yMithdDZtTU5KTmxYVG5XVmFSWkt5b0hGdkpMU05zd3AyV0lrcGVkaGF3N2RGYmlIWlN5L3p2M3BxcGFlN0h5UUhSRjBvK2FzYWlIOVVQa3JjRGhyRllMWFZGV09zNVgrS04wWFdzMVVsM2xXMGNNUGxzT1ZXMVQ5Uk81UnA1TklLVGMvVWlpTGwyRm50QnVnMHpTSDhubEdsSUNqQ1FDblZ3STh5eGdjUU9VL0ZJVDFWU3lXeWJnbTRTWkQ0bG0wb3JaTEJKOTZwc2ZkQzBPR25uVTAzMzJXcjRzeG8xYkQ2TFoybTdEOGxxK050SURpaFM1RnNvamJVVUtlTWFTVUl1ZHJLTG9mSllXTzZ0UVlIbUpzYVo1TEJiTGhHREIya2tYK1lVOEx3UnVwcmpiZmRiVlEwTFl3QUxKT1Y4RHRwZVpYb29vTkYyam55WFdjQ0laM2JtZ0FBRGhjcm9JblJscEIyQlhRTUV4TnNkT0xuY1dXVk83SkdQSnMyTjVsYlQwaGoxQUcxbHlqR0swMWM3amU5MDVtWEZ6Sk9XaDIxMVNoNExOUjVYWXFpN0NKT09JUlBEaUwvQURWNVF5Q1FOQUFIeVZCRlAzeHQ5eXU4TFlROXZWR2tjeXJZamNzRW96ZHA2TGJqTCtyYTBiYmRGUjRDMENNWEN1b0l5NXliRXhNdVZOMEhwbVdKS3pVVGhnS01RMktQN2xSNGxXQVhGMDVGZFFjM2FFc1Z4QWFYYjJYUDh4WXVHTmNBNnl0OHlZbUlXT3M1YzB4ZXVkVXVkdVVjVlI2ekhDaEdzbDk3bEp2ZEtQWG8zRmp0OTFKd1ZsTGd2UmlLeURaTHVIS2FsSGtsM2k2VzBkYUYzQkx5RFpOT0NYa0NlaXUwTFBGN3BaeWFmMVM3Z2pSVm1oV1RoTHVGN3BxUUpkNk5GV1FNOElEMGM4SUQwd3B5QVNJVHVFV1JDZHdqUlhrRGVnbmxHZWdubEVWMmZRemFvc1BLT1h1bmJ0eXFtS2Z2RllVZFIzVHJmdlhzTVUwMmZBOG1QZ2JwYndrZzdBN0xFc0VjVHRRRzUzUmFpSjFTM1UwV3R2c2x2ZU8rQloxR3kwb3UwWmtsVEdHUzYyNlE0ZlZNMGxQTDNqU0hDMTFTKzdQaWxEcm15dXFLcER3MFg0UVNqWWNKR3cxTUptcExIbXdWZlBUZDNEOXlzSXExc2pBTCtpdytNU0xKcWkybVVCbzJ5dzc3Zk5LTXBYUkUrVjFhWWxBVzhYRnZKSXhWTzlqWkRaWWlyTXdnT2RZZ3FOWlRrV0xSMVQ4UTE3MkgwUm5RRjR0WmM4UklzeGdWMUpUZTh5dEJXMVE0SzFsS0R0ZTNtcWVrdzk4Y29kWXJZb1ppMkVBK1N5Y21ac3VSeDBWYktEOVp0MDNUVGlYUkVFOGJKaGpkUk95WGxqRFhjbFZQRTVIYlZRUEM2U09xcVMxNDJ2MVdjNFlWU1VWTTV6YkYyL0JDYXB3ME5OdGo1aFZXTDRhK3FmY3ZlNFg0Skt0NDgxQ1pZN09PNHpsOStPVkRqcHNBU0JkVWVJWVIraTRneDdDUmEyd1hjNWN2c2NSWnR0dWdWZmpHVVlhdW1JMCtLM2t0RHhreXU4Vkh5L21LbmpOeXhodmRVd2FZck5zUmRkanh2STN1MDczRmhMUjVoYy96SGhiSUtrT3B4cXNMRVc2b2s3Rk9OR3Z0Zzd2eDhLVDVUT0xib2s4YjVtdEVvMEFlU0RVeXhRd3RaRzY1dXVpYm9ScVFXSFlJWThiVTdLTE00dmRKQmptdkp0c29kTXhudTNlVzZacWI2UVFEd2w1SW5WRGhiYXh2c3JtTmpUQUFSYzJIUlFORkJKTHRhNm5UTTFPQktoVTB1cXA1SUYxYjB0QTBSamxRSWdZTlRkZ3ZSeEZydUNyS2toQTlVWWxySGNENklUa1NOTFQ2MjNJVEZReHJhVjRzalJWQURRQUI5RkdwSGlCdHRaRyt4RjNPdGV6NUsxbFhQdllpMzhGOTZkbXRZSjhPakI4ais1Zm5aMkoxbmRZek1OUkFMaHQ5RjkvZGswclpJR0RWMFA3bFdsM1BTNlRzZERydDJGYVZqYmZpVzcxWDgwVnB1TUM3bkpFemF3UGswYXZIaktyeXJYRm0rSTdLdDAzVkNYYzNzYjRNeEM1VmhDeTlrclR4M0t0cWVIWWJJUVpzbDdxSEM2Z2FRRG9uR01VekhzakY3aXVNZWxZRWhLYWxodWx1N0lLN1pPNWtrbFFjMDlGSXVzb0dRS2JpYlNMM2tLTFhueldKSndCd2xKYWtoT3M1dEhIeWVxWGZONnBRMVJ1aFRWT3k3Wk5vMmFramdyQXFUZmxWb3FMSGRaTmExaWxuZHBkKzhCZ0c2eitsUkdQaS9GYXJWNHc0Z2dLdmZpanpmZjhBRktlUVpQSFp0dFZqdW0vaVNkQm1MUlZBYSt2bXRNcmNVY0w3bjZyWHhtSHVzU1paK3c5VnhURmVHa2o2cXl2akQ1NEdia2l5NmRsdHBuMGxjTjdOc2NGZlRRc0ZpYldYMFRsRER4SFR0ZTd5VnVETVRWS21LNXFlYVNpY2VOdjRMNXJ6eGpEcEt4N2IvYVgwTDJtNHRIVFVNamJnV2IvQmZLdVphdjNxdmtJTi9Fa1RrVzlKaXJrVlpKcjNWeFJDNUNwS2Z3Z1hXeTRWQmZTYktsSjhtdlBoRjNoc2ZDMmVpaXVCZFVXSFIrTm9zdHZvSVBDM1pBbVZMTE9nZ0hoVjlTVTF5M1pWMUZGdU5sdE9GVTQyMlRvcXpOeXpMWENLVUJndUZaQ01OWHFhUFN6YlpSZTdkVzR4TXlVN1pDWndBVlpVT0J1ckdWMW1sVTlaTUJjTGpkQnhWaUw1THVJdjFVNDBrV2xwSnVlVVJsUmJaVTJ5MXRHWkQwUTdCU2FPOEYxQ1hZV1FOaHBFWDJ0eWxaT1ZsOTdyRGZWRFlhWkJyVGRTTFBrcEZ1eUU5cFNobGczdHNlVmd0MlhuTktscnVMSVdpV1FEVVJzWUs5YTZ5R0ZEdEpaSjFLSEJBbG9MQzlsWVF2dlpNdWJyYnduYkNvcDBhMUpGcDZKWjhGdDFzRlJTNnI3S3FxS2NpK3k3UTZNeEVDeFJtU1dDaHBzVkt5NFdFN0hLZVRjS3dZKzRHNnEyTzRUY0Q3cUpsWnhMQ00zVExSY0pXTGdJN04wNkxGU1FaclZJTXVvdEd5bFpOVEVzTDNLZzZNRkVBMjVXQzBvemdzK0M2RStQMFR1Z3FMbzc5RkExSmxYTENDbG5VcXVId1g2SVJwejVLQjcyVkJvbkhvaHVvSGVTdXU3dDBVVEhmb293dDVSbWljT2loN242Szk3dm5aRDdyMFF1Z2xNcVcwUUtNeWhIa24rNjlQd1dlNzlQd1MyR3BpWW93T2ltMm5BVFZyTHlTMkZ1QkNNV1FaUUFtSGRVdTlKa3dreEtSOWoxVU84SGtVdzhCRElGdUVwc0pLeGR3UzBuVk5QUzhuQlN5NmhVOVVOeU1lcVhkeWhZNklOM0tHVHVwU29Ma0ExR0prdjFSM2NJTHVVTEdvRElkMUU4QkVkMVVISVdPaUFlZ25xaVBPNkhmbExZMWR3RDlpVU1uZEVta1FHeWJwTXV3NlNDQW85T2R3bHkrNFVxVFozM3F1MFJkaThvZDNOVzY0TEdDR3JTS0p3MU5XODRCR1hCaUtNVEoxVDVOOXdZYk4rNVg4UTRWTGhUTGFOdkpiRkNMTkZ3dDdIRTh2a2tSZC9GTVJ0NFhtMjhsTmkwNFI0TTJiRHhpeW1EWUliQ0ZPNFQrQ3ZUQTF6eTJFcm5lY3BIR2ptQjhsMFN0SUxmdVhPTS93QXVpaWVCYmhZV3ZYd3MxK204VFI4dzV2dU1RazNXclNQTG5XNVcwWm5ZK1dza0lDbzQ2Y3RCSkM4aTE4UjlEd3krRkZMWE5zeFZzTVd0NnVzUmJib2txY0cvQ3NKRnBPd01sQ0R3RlgxbExadkMydWxwOVRkeGY3bFhZcFMySjJWbUlTa2F0RFJBdTNDblBHTkJUVTBXbS9STEUyYVZiZ0ZacUdPaTExcDlRNDZ5dHp6RndWcHN6dkVWYmlHSjFSMlNRUEtOVXlXdWxoT0JkTmloVXV3R3FmWkNaTFpEcTM2bkczbXZSOUU2aEF5MlUzVHRPODdLdmFlRTlUbXdTWklmRXNJM2wxazFIc0VqQzlPTWRjSUFyR1Erd1ZKalJCYVZZUGQ2cW94WjExS09sTkZBSHk4SzRndzVwQU5rdFJ3NmpleXVhZndDeFUzVVNnOUJBUU9WYTBzYis4RnQwclJVeGNldTYyRERxRFM0RXF0S2RsdEt4K2tqY0l4Y0lzdFdhU00yY0IxNVJwWld3eG5wWmExVzFKbkxyRThxdTFiR0tKNnFxVFBLU1RmZFREenBBdWtJWGt2c3JKbE1kT285RWFpR21rVFl6M2ZjN2RWdGVXSWpWU0RZa2VhMUdLUTExVXlCdTVPMnk2cmxyRFAwYlJzSmJ1OXZKQ0tpdHFwcmJ3WGxORDNEV2hvdWI5RmRRdERXZ255UytEd2R5VE00WEJGdDB4UEkwdFBSR2tlYzJ1VXhYRUt2UXcySzAvRk1RdHJPcm9uOFpyUkRxM0s1L21ER2QzQU9SbzlMcE5MdVhKVTQ5aXJxbHoyM3YwV3RTWEpLZkRoTk5xSjZxdmtxSHNtazB0QkFLZXFSdlJ4VUQ3dTU4bEZ3Q204eVRNRXVtd1Brb3U0UnFTSGJLRnBCWkx2VEx3aEhxajRZcVNGWGhMdjRURXlYTFVTRXlRdThXQlM3d21aUlpBbDRSb3BaRUt2UUhpeU85S3pjbzBVWmR3WjZvRDBjOElEMHdxU0FTSVR1RVdSQ2R3alJYa0RlZ25sR2VnbmxFVjJkdHBqM1RnQ3Jpa1lIMksxeDFWZDRWOWhzaGN3YjlGdVljamJQaTJYSHdiQlRWRWNiTkp0dnNsWktIdUpOUTRPNkV5bkwzZ2tnVzMzS2VtcU85akFHNUFzdDdGSzBZV1dOTUhORUh3N2MyVlpGTTZta3Nma3JLQWx4SUlQM3BIRm9ORGc1b3Z2MFZobFpLaTRvbk9JQnZ5cktLVThLancyczFCb0t1SVhiZzIyV2RPRkZtTERWRUhmTUtxR1VnYklmbXRnRXJSR2I3S29IaW4yMzNWREk2TkhIeU93VXdFWUtrd2pYeHdyQ25wdFZPTDdiZFVLS2hEcE9uMVZDV1F2d2lNUXRhOERZSmtNSG9zMDlIcGFzbHBEN0xOa3k1Uk9OZ2FPaUM2bDcwbmNKa3huUjZxRksxeGQ5NlY1bkxJc29lN0hLeStuYVIwVGNvY0dwY1J1ZW1KblVnYmFZU3NObFYxRkxJMlFnM3NycHJIVW84K3V5bm9FKzlqZFRIbWJaMlVValM4WHdGdFZFOEVDNUJDNURtdkpMOEdqbWxjTzl1UzRMNkxudzl6K0FxekZjb2ZwcHVpWUJ6U0xjcll4U3N6OGlvK0s4VDd5YWQ4WWpNZGphNnI0OFBkQzh1a2RmNXJ0WGFoa05tQXk2NElUdWR5MFhYS0t5bWxranVSWStTdXBHZkx1VkxubDhnRnRrelBURVU5OVBSWmlZMXJnUzA3SjUwN0h4YVFDZHVpRU1wOE52M2hEbXEwR2tOSXVFQ05yV09OZ1FWSXdQdnNWQTBMUHBkVXR4NXA2S0lobzNXR1FrY2tJZ0pCNVVDR0tlSWdLRHhaKy9tbUlaMjZmVkt6U2FuN2VhRTVFZGlEZE45bG1SM2VSaytTaEN3dWFqdGlES1orNHY4MGI3SFYzTms3SzlVT00zQitKd1gzdDJPVFBKWTI1K0grQytBc2cxb3A4WmhGN0V2WDNsMkpWNGtuYUQreWYzS3RMdWVrMG5ZN1RVYnhmY3RTeFp0M09XMno3eExWc1VIaWNrVE5qQjNOTnhXUGM3S25Jc1ZzR0p0dVNxczArLzk2b1M3bTdEc1FwVzNJVnpUdDhLUnA0YkVLMWdpMlFnelpIaFRCdUVWME5rTXRzbStSV1RJT0dwQmtoc0NVd0dsVG1ZQTFMWllpVTB3SVN6aWJwNm9idVVzNWdzVUZqMGdMeU5LUm5lQmRHbWNiRlYxUTQyVml6dEhuU0FYM1NzMDFyN3FEM0c1U2RYTnBhZDFMSlJPU3EwMzNTTStJV1BLUXFLd2krNnJwcW9rOHFXU2kwa3hCcFNVOWZhOWdrOVZ0eVVDV1Q1cEliQlZsWTU5eFpJVTlBSkt4cEx0eW0zdmE2OXh1aDRlSHk0bEcwSGs4STRBdnNmUS9ZMWg0N3lFWHZ3dnErZ3BSVFlXSEFnV0IvY3VDOWh1VTVKWUlaUzNvQ3U1NWpxL3dCRTRWSU5RRm1ucjZLOUJjSG10Wkw0cU9JZHMrUEJrY3JHdTZFTDU5RlE2b3FYazc3cmN1MHZNTHE2cm5icTFidUMxR2dwd1l5N3pDenBzM3RQQ3FIb0dheUFQTmJYaFRkbXJXY09hVEp1dHR3ZU81RjFWYjVHNXV4ZTRldzYyN0xjYUFlQnExN0Q2Y2FtcmFLU096UXVvb0l1Y1BqdTV1eTI3RElkZ1ZydUdRM2MxYmhoOEZtQlhNWmpacERqRHBhZ3VHNlpjeXdTYzhtbTZ2VndabC9FRG5QaEtvNjFwMUZXVXN4M1NGUnVxays1bzR1U3ZsM0NXRENDbTVnRzMzU2JwUEVxaGNvZGdrMGl4WG43b0VadWpFN0lHUm9BOXFHVGE2TklOa3U5QWNQZDVzb0dSWXN2YUVJUkV1dXBCaXdXRlpFaDRVUkNiVzdLZDFobTZLMkpGUkNjVVpCQlRrYmRrR1BvRXl3WENzMFUycUJ2anVrNnVrQmFiQlduZDNRNTJYYlpBMENwVXpXSmFhempzZ3VqMHE4bnB4dWJLc3FHYVNiQkFXNFRzVmFiRk13dnNna0xMWFdTVU9hTE9LWDFUYkhxbWpsc1UvSEplMjZiRmxlU0xPTjJ5SmRKeFNlcU8xL3FuSXJOY2pJTzNLa0xJQWZ3cHRjbWpLRFdGa0crNktDaDZGMEdqd0lLOVlXNFh0Tmw0bXlod0VXWFVTd0loTzZ3U2s3aUE5QXNVTFFqMzJVTlNGeURRUFF2Rm15SnFXQzVCdUNGeTFRZHR3bUhENklMckJMWTVJRWVxWGZ5anV0YzdvRDBwajR4RjNxRitVUjRRdWgzU1dPVVFEMHZKd1V3OUx5Y0xnNUM1NnBkM0tZZDFTN3VVTEhSQXlvTGthVkJjZ0dvaTdoQmR5ak80UVhjb1dOUU05VUo1NklyaU45MEI3a0xIUkFQY2gzNVUzb2ZRcGJHb0JNVUJ2S2xOSWd0ZnVrU0xNa0hJWG81TkJRekpzcE1GeWxKQStSYzRXOHZrYXVrNWRaNFdiTG51Q1FBeU5YVHNBaHN4aXNSUmlhcDl6ZDhNanNHcTdhTE1DcmNPYjRXL2NyVjFneGVtaEE4ZE9USUIyNkkxMWt1VHZ5aUEyc3JDVkZkOGpBZllMQmtRaTZ3VUM3ZEM1QnhpVGxlU3czWFBNOWtPZ2NPZGwwR1o0N3JsYyt6ZkgzclhiaFpPdjhBdW1ub0ZVamhXSzRleDB6eVFPRnE5VFRDUFZzT1Z2Mk0wUmJLNWF2aU5EWnJyRDZMeUQrOGU0eFA0VWFYWFFoenVGR2x3OE9JMlRsVkFSSWJqcW1xT0t3Q3Nyc1hJTU5TWWUxckZTWTVDR0U3TGFvbmFZK0ZxK1lIN2xPUkV6VHF4NEJJU003dERVNVZ0MU8rOUkxMjFoNkszQWZFMWpNRzhSSzBLb2x0S1F0OXg2M3U1dWQ3TG5GWSswN3JLM0VjZ2RTN1VDcTl6ckZIa2x1Q2s1WDdwOFJNdXhsdzFxVFJaQ2JJVVVkRTZ1QkJNR3hUbE82eVJ2dW1vQ2t5SHhIWXpZcHRzbGdsR0FxVDNXYWdSeEJYejJWYld1N3dxY3NwQ0FIYTNJbXVBME4wRFFBck9LSHZIQ3dWVEM0dHNBRnRXQTAvZkFGd1ZhYkdJY3crbUxTMjRXd1JORWNWL1JJUElpY0xkRm1XdURZdWVpb3AyUGl4ZkVxMGdrQXFzaUJOL1VxRlRVR1dYcW00SXRUbWl5Y2tPc0pRVU91WFVRckd1SGRNMHRHL0d5UEd6M2VBT3RiWlpvb0RpTXpRUmNYdW1VVjVTR2NvWUE1ODRxSGk5bmRWMWZEb1JVUk5iWURRRlNZSFFpbmF5RUQ0ckZiS3lMOUhOQkgyL0pHWmtzam53SDcwTUhjamF5cmNWcXpUUmszVFJQTTNtdFN6ZmkrbGpnRDBVb3Q2YkFwU05leC9HUzV6aGRhWlZ6ZThPTnltcXlvTlE5eHVxOHNJSlhEMjJsd3FNUlo3VEcrelNoTklaSE5kdXB4R3lZYU5NNHVWc09TY3V4WS9qY01NbWtNTDdIVVFFVFkzYWtyWnBqWFRPcG14OXk0RUZSdWJicnRYYVhrekRzbzFVd2lMQzBDdzBQQi9jdUx2TjVua2NhaWgzTk9nUGhsRlNqMllGN2RrdS9aTnZBc2s1ZmlWaURzcXk3Z1pRZ0VKaVFiSUR1RllRdVM0RlptMlFKVXpMWWxMU28wWjJVVWVsWnVVMDlLeThvMFowZ1o0UUhvNU95QTlNS3NnRWlFN2hGa1FYSTBWNUVIb0o1UlhvUjVSRmRuVkphamZaWE9DMWg0SzBrWWtTOEFoWCtGVnRnQ3JPRjB6NURQazNWNGZPQnB1TitpdEtLRHU3YXQvbXFUREs5cmdBUmRYVUUvZUVBTGR3NVVqTXl4SDNzRG03QWZjRXErajFYdUwvTldOUEhxYmNyMHpBMDdLK3NpTTJVVFdwbUdrcTJuZ0xZS2VzYk5GR05yMlM5YlFpb09vRG9zMGRCSTA3WDJVeTUxUWpGZ2RsalVVL2VRQ3hOL1Jld3lpN3Q5eUw3OVUvUTBNbFFBTEh6VDdhSXg5RjUzVVpMWnZZTWJRTjFPWHNGcmo1S0VkSVdHNXVuV01JRzRRNWlXazdMSmxLMmFrWTBpTVV4QnNqQityb0VwR0xPVERIV0s3WVF4RzBrY0k4TlBZK1NqQVFRRXhjaFFGbUpJQVZCdExjb3pRWElyV2tGUTRZTkN5TUMrNnl5Q003RDl5ak9IdjRKVE5CU2ttNUtlSmFKTm8yNlR0K0NqSFJtTnJoYmtxeU1ZWU9Rc2Q0MFNBRzFsWnh5b1RLSnEyTlpIangrbWthK01PY1J0NGJyNWw3Vk96MmZLZFhKSXlFNkwyM0czSyt2cDZwMU05cGFDV25teTFuUEdBVW1hcUNSc2pHZDQ0RzEvTmF1UEtraERpZkNOUjN6cGU1ampCamQ4UnR1Q3NpRVVOdEhpYy9rTzZMYzgvWkZyY3BZczZNUlBraWVTN1dCc0IvZ3JWOFNvaERCRzhTQjBqaDhQVUp2aUpsVFk3SU9vM3VqRXpHM2NlUlpEa3ZDTnh1aTBiNWFhbmErUUVnN1dLeFVPYktFdHV3a3FFd1RJVk1PTUkvTlphQXhSbEllVUZCMlJpZTU3dDl0MDB5SWJYS2dXTnNOS2dBL1VPYklnNE1zNFRwRmh1dk5hZS9idnQ1S1ZIWU44WE5sRnpTQ1hJV092a2N5NE83ekJURzVBN3hmZVBZWk8zM2hwdjluK0MrQnNLZVlzV3BuZjA3cjdUN0NzVEpraU4rUi9CQWJlbGx3ZlVVejlVUStTMTNFNDdncTdoa0VrRWZxMGZ1VmJpa2RtbFZwZGpYeGR6VEs2THhGVmp3UVZjMXZ4RlZqMktwSTFvUGdsUzhoVzBQQ3JLWnU2czR1RkVTVENLTGh2d2lXMlVTTjFHTFJBRGxRbDRLSmJsUmtHeVRJc1JLcXA2cXZrZllsV1ZXTEFxbm5mcEpTV1BpQXFKT1ZYeXlDNVRNeHVrWnVxYkVjQW5sRzZwcTE5d2QwOVV2c1R1cWlxbHZkR3p1Mnl2bkpKU2tnM1RMemNsQ2MyNnF5UVNnS3l4dU8rNkdLaVJvMDZSOTZZbWxzUUxKZVdkclFBR1hKVmhQZHdMeEx3ZVdLMUx3MjduYkt5eUZocytONWtweEd6VTI5dnhDczh0OW4rSVpybGo3cUYrbHhIQVgxTjJOZGd6TUJmQlBWUmpXQ0hlSUpzY0w3bERXYTJOVlowL3N5d0FZVGwrbWM1bWwzZCtYcXFMdFp4NFFVTXpIUDA3RmRMa2diaGxLMWdzR05DK2FQYUh6SzBOZkhBKzd0UStINXF5bnNWR1BqWGlTczRkak5WNzFXekhVVGQ3djNwckQyNll4ZnlWTlMzbWxMajFOMWYwemRMQjhsa3laNlpkaTF3K1BVN2hiTGhzWjFDeW9jS2FiaTYyN0RhY0J6VldZTSt4c0dGUWtnY3JhYUdsTmdxVERHQm9HeTJTaGY4QUR0MVJ4TTZac09BVXBMaGZ6VzQwMFhkc0czUlVlWG9BZEpzdG1lQXhnNFd0ajRQUHk1RkttYXdza1pKQVVXc2RjbFY3NUZhYjRCUzVCenU1U0VqcjNURXpycFI5eVZSeVBrdVE0RkpXazNTcFo0azdJTGhMbHUvQ3FGdmVpVVlzRkV5a0xMVFpEY1FsdEhOeEl6RW9UcEw5RjdVRklOQlM5aDNjQ0Y3b2dLbHBBSEM5WkR0WjE1RVJ1c2hub2lDUGJoVGpqTGp3alVXSmxrUkdOaVphTERoR2hwcmpoTU5wQWoyaVhNQXc2OXJKaGtCdGRFWlNobTZNQ0dwOUZaTUNJeTFlY3k0NFJ6NGd2V0NKUkRUSzZvaTIyQ3JKNGJrN0xZSklyaEpUVTRJT3lQYU1ValdaSTdFb0piWXExbXA3RTdKR1dQU1ZXa2k2bUJhTEk4VHpmbEN0WUxMSFdWZnpDZkpaeFAyRzZPQ3E2S1ZPTWZleWFpckpEekRzRWRwMjJTa2JrekdiaEZFQUtwM0ZsQzkxa0ZXVjJBWms4S0o0VXVWZ2hMa0FCUEt3UXBrS0pGa0laQlNBMlhyQlpRTU5BendvbmhTUENpZUVBUU54c2w1Q2lrb1Q5d2dZeEFIQzkxRkVjMVJEVURIUkJQR3lBNFd1bVh0UUhqZExZMUN6eGNKV1VKeHdTc29RREVLUDZvTCtFdzhKZC93b1dXWWk3MUJUZWhuaEFXSWtIR3dTOGhVM1AzUUh1UU1zb0c5Q0ttU2hrb0dOaWp6dGtCN3VWSjc3SmVTU3hLQ3h5Rm5uY29McExGTVBjM2RLU09GMHBqWWtoS21hZHJYdUc2UUxrOWhjTG55amRDbHlCbGFTTnp5N1NOTG1rcnAyRFV6V3RadjFXaFplcENBM2RkQ3dtQWhyZDFiZ2p6T29kdG0zMHdBWTNib0VkeDJTdE8relcvSkVmTHN2UUo4SGw2NUo2ckZTTXdBU25mS0psUXVRU2lOOThzOThMSkh2VmtTN2NvSElOUkMxRTM2czdyUXN5UExpN2RiWlVWUGhjdFJ4bzk0WExPek8wYVduVk01MWpMYk9jdGRuWnBZNisveld6NDYzU1hiTFdXeWQrSEMzV3l3OGtlVDAyQjhHcTRqQ1pKVFlkVU9JbUFBSzNyNE5ENzJWZEl3T1FSalJlM0RVVW8wZEZyV1l2RTAyVjNFOGdLbXh5Mms4SzNkamNmYzB0OEpMaXFxb09xUy9rcmFwbTBQSUNwY1JsRk8xeEo5VWNGYk5HUFkxRE45WUd4NlFiTG4wczJuY3E3emJpQm1xTEE3WFZCS3k4SUswSVJGVDdnWm5iSmNPQktKTWJoQ1l3a3F3VjZKRnQrRk95bUk3QmUwM1FzTkl3M2xPUW0xa3V5SzZaallSWkJZZERqQ0ZKNUZ1RUpwc0FwRTdKWklya1ZtYmU2SFQwNWM5Tk9acUtMSEZvSVFzdHhYQWVrb3dDQ3Rsdzl6WW0yNFZIU2tteXRhZHJ0a3RoVVdYZVhHNlRxV0YvQktKVnZFTE5qdlpLVTA1bGt0dXFsRGFDUVV4dU5yL0FEVi9obEdDQTU0dDl5eFEwYlhOQklDWnFwdElESXZ3VEVoYmRHS3ArdHdqWUw5RmVaZnc3dVFIT2JZL0pWbUYwZmpFa3UvWGRiYlJ0RlFHdGpIWG9tSVh1TDdDbWFXaHhIQ2ZFL2ZQMGVTVnNJR3RhT2JCUHhVd2hnTXJ0dHJwYUtXM3hId0pZcE0yaGhjU2JEZmxjb3pKaVh2TWp3SFhGeXRuemhqL0FIam54dGQ5Rno1eGRNOTF6ZTVSbzlkMC9UTksydlFXYjFLSElMa3BwN0ExTFNlRzZORzVranRGelR1ZEtDeTVrNkJkWXlGMlk0cFhZWFZZalR4UC9WTTF1TFNSYmNMbHRGRTVsNm91dUdINGZOZDF5cDJ4MCtVc29WbEk2QVNQcW9kSTM0M0hyNkpjRW5MNGl2cUhramp2RXJmSC91Y2N6bFhWczJJeTA5WEk4dGJ2ZHppU3RWY0ZjWTNXdngrb2RQWXhYM3VxZHcwN2MyMlRZbkpJRzlBY0J2c2p2UVQxVm1QWXJOQzcrcVRtVGorcVRtNm8wS21LdlFuYm9qMEJ5YkV6OGdDWHFsWHBpVXBaNTNUVVo4Z0x1cUEvaEhkd2dQNFRTbElDZXFFN2xGUFZDZHlpRVNCUFEzSWowTnlKRlptejE3bTA4ZzZLeXd2RUFXRGZvcTNHSXZlblhiNWRGWFU5VzZsbGF6MXNyRzNhZklPNTAvQ0swRWdYdDgxdU9HRUV0Tnd1VTBsWTVySTNBL2FXKzRiaUxkTWRuYjJDZERMVEZUaGFONmdjUXdBQW41SmhrSGU4aTN6VlZoZUxXQUJzZm10amcwMVRMOGZKWDRaRzBaODhmSXFLWU1pUFZQWVhUaCtxN1Q5NkZISDNUdDl4NnF4cHF4ckJZQUQ3bFV5WkpGckhqUlo0WEd5T1IxeGJ3bENIamtkc2JYV0dTRjlpUHdWalR4TnFtM0hUYlpaZVNUTkdFVWhGMFlBUzc0UThweXBCWTdSOXlYZTQwNHZiNnF0eVdBWHVJOVBxb09wckZFRWhlVVZqVHl1cVJ4b3hUd0VFYkp5M0N3eVhSdFpTa2NRRWFkaXBERURHbFRsWUIwUWFJRjcxWnl4Mlp1RVlteEVOdjFSNHRUZU9FSnRLUzdWdW1vUUpQQjFWanVTeGlLQXpEa2ZWTFZNQmFDOGRFOHlsTklMM052VlFjMWpXbTVSZGdHSlFTTnFJM05lRGNCVkZWU3ZFNTA3Tkc2dHk1b2ViYklkUzBPR3luaU5BMGFkbkRMdFBtbWdmRExIcXFiYVd1UEhDK1lNOGRsdUtaYnJaS2lYUzZBdXUwTjZENnI3REhnZHFMUmI1S2l6YmdOUG1DZ2ZIcERuYWYyYnA2eXNXNEh4UzJXU3YvVlgwdEc5bmJJTlREM1EySUlIa1Z0bmFSazJzeTFYUE1FUkRMMjR0MVdvR1BUQ1d1SjFGV29Uc1JLSkttZ0UvVWZWUnFxUXhIWkJvMm1sa2NTVFkrYXMyaHN4TGlicTBtaERURW9tRmd1VVVTdDhsS1psa05qYmxEWTJFUm1NRjI0Um5PSHV6dk5CYUxCWmFiT3NnYkRwMlNnazBWVk1mNlMrc2V3aXVHbUEzL3dBV1h5aDNJZkxHZlZmUS9ZYmlBcE80QmQ5ZmtnczJOTGRIMnJoZFVYd3g3MzJDbmlJMU00VkxsckVCSkZEdmZZTFlhMGg4SEhSSmwyTnJFK1RUNnVLN2lxMlJ0aXJpc2JaeFZhUnVWVWthMEh3UWdHL0NzWXhzazR4dW5ZdUZFU1RDVzJVVHl2TzRVZXFqQlBXc3ZPRndwQVhDeUJwQ1RJc3hLbXVic2JyWHF0MWlWc3VJT0drclhhcHVvbEs4eDhTc2tsOVVuTkxzVTFOQmEvS3I2Z2FXbEhkRG9xeXRySmlMcXFxWG5xbkt5VWh4U0VvOTRlSGRCdHNwWmJTVkM5OTFKd0ZycVVnMVdBSENCVVR0YkVXM3M1VGJZTGFRQ2VSdTl0ejZMZU96UHM1a3pkaU1ZZEE0dDFjbHV5UTdPTWhWT2NjU2pJamM1dXEyM3pYM0QyVWRuRU9XcUNMWEExcjlQSlp2eXJPREU3NU1IWDZ1TUl1bU45bTNaRGgrVXFDSjc0UUhEeUk4bHZsWTJObGhFQ0FCWk91YTJKbXgrNVYwN3d4am5Ib3RqdzBvbmlYbW5seWQvTTFQUGVNdG9jSGw4Vm5hUE5mRW5hRGpqOFV4ZVVQZHFieitLK2krMnpNellxYVNNU1cySXNDdmtxdXEvZUs1N2liMzZsWXVvbFRQWDZESDhLYkRVUnM1YkJRTjd3Z0ZVTkcyemhzdGl3N2tMUGt6Yk5rdyttQUFXMVljQmRxMWlnYVRwSHF0dW9LYlJwTzZyTmdUN0d4WWRIY0JiRFJSRFUzNXFpdzk0Rmd0Z280dGIybmZsTWl6T24zT2g0QlRockdINUozRUpPN2FrOENkcGpaNkFJbUtTM0MySThJOC93QjJWczA1SlM3amNMSjN1Z09ldXlrTWpFaSt4UVh0QlVuTzNVYmdxcEtRNWNFRERjY0lMNEFyQmtadHdvU1U1UFJMSXBNclhSYkplU0k3MlZxYWExOWt1NkVOSzQyR215dUVSdndtSTRDZWllZ2F5L1Q2SjFzRFhXdCs1RGFES28waDhsbGxFU2VGZW1rRmh0K0M4eUJyVWRGVGN5dWhvTDlFeEhRZ0ZPOTJGbGxnalVRRzJCRUlqQ0c1OWltSlRzbGlkMGUwRGttSk5XMWlwZDNmZFkxZ3JHNjd3Y3BrajRkbEZqdDFLNnhwUnFqdllrYkVYUVpHM0JSTkt3V291Q1dVOVJIenNxcXBiYTYyT2FPNE95cTZtSG5aVjVSTHNabEs3cWhYSUtla2kzT3lYTGZSVkpJc0pub1g3cCtKMXdxNGJGTVJrMkM2Z0dpempkY2hPUjhLdGg1Q3NvZmhSeEVCaHdzckJiZGV0WldWMkFaTUhaWkZyS0M4bHlBUEVLTnJLUk5sRzkwSVpFaFlXU1ZFOElHR2lCNFVUd3BxQjZvQWhaeDNVU0V4WWVTZzRlaUJqRUxrWENIWXBraTRRM01RTWRFWGVndlRMbXFCYnpzbHNhaEY2V2xDZmxic2xaQjZKVmowaEI0NVN6K0U3TTFKU2pkQTJXSW9YZWh1TmdVVThJRXAySVFXV0lvVGM3Yy9OQ2NVZHhIa2dTRkxzdEpBM0ZESjI1V1hHMTB1NDJRdGpvbzlJZGtySTdsRmVka3JJN2xCWTFJQzRrb0xta25sU00zb2hPbDNTdyt4SVJtNnZjRmljWHRWUFRndkkyNnJiOENvL2hOa2NWeVVzMHVEYk1ERG1ocTMzQ3JsZ1duNFZGcExkbHVORTdUR09pdlFqWjV6UEsyWFVUN1czV1pKckRsSnNrMlVKWlNyKzh4OWdjeXJ4bktUYktzU3pCQzVoS0ExN3h2eXBHYzJLcjJ6Ym9obnNnY3c5Z09lWFkzS29jUU9yVXJMRUpPOE95cU1TdTJBL0pWWnUwVzhhcG1sNWdBTG5BRzZvNlRETkJKUFUzVnpWc0w1ejFDSDNXaFVaUnRtemluU0tERWNNMTMyV3VWdElZSFdzdDhuYUh0SzEvRUtiYzdmZ2cyRjVUTlZuUGNzSjRXcTR4WEZ4SXV0bXhtWHVnNXExbWVqN3dPZWVPVVVZbWhEZzF1WnBlU1R3dE16ZmlKaUphMDlGdEdQNHhGUTYyNmdDQXVUNDlqM3ZNcmhjSGNxM2pqUmRpK0NweE1lOE8xSDVxc21sMHNEUXJGMG5leEZWdW0waHVyc2FSeHF3SUdvaE13d0N5aUlyRzZNd25oUVdvbUpHV1FXTnU1T0NBdlJXVWxpTmtEWXhJRERINkpwc1FzangwdXloTCtyTmtGaEpDeEp1c3Q1UkMxcDZxTG5GdkFRV01qSGtsdFlsQ1pWYTNXRjFoenBIbXdIS3NLVER1N3M0am5kQTJXVXVCdkRtaHdCSVZ3SHRqYjhsWHNrYkcyd3NzRjVrMkI1MlFXQTBZbHJEVVBMZHowVnhoT0czR3NpM3pRY053ZzZ3OGhYRTFZeW1pREJZRzFsTnAxeUp6Vkh1emRJUHBzcFVNZmkxdTMzVmJDVE8rKzV1cnlsaUxXalpUYUlsSWVoZWFndFkwRWROMXR1QzA0b0k5VGlPUE5hNWh6UDFnMkMyTmtEcEdOdGZsU2hEYkxLaWxOWk5leE5qWkd6QmlvcGFFeDZnRHB0eW04TmdGSFRFdUFIWGNMbjJjcTh5VkJBZWJYNkZLUnA2RFR1VWxacWVLMUxwcWx6aVVwZlMxRm5icUYxRWpaR2o2QnA4S3h3Rk84TG5xTlUzd215UEkyM0NDL2pkR2hHYmw4Q2tYdkVMVHFlTzZ2dUZJeU1xbk5aT0M0Zlo5RjU2V2s5TnJJVkVVU3haN29XQ25wM0JybW5jK2lyemZTTDg5VWQ5M091YmsrYWc0SnlRbVNBUFFYZFV5UjZKYWJaTlhBcHhGMzlVbk1uSmRrcTlHaWpNU2VsbmxOVGNsS080VG9tZmtGNVVzNDdvOHFXZnltb3o1ZHlKT3lBL2hGZjFRSDhKcFNrRFBWQ2R5cG5xaHU0UkNKQTNvYmxKM0tnZVVTS3pMRm1LT016V0VFM1JLeUJ3YTJVRDFWTjcyMDFUVHV0a2JWc25wV3NzZUxMVnpRcEh4NkhKN0RjVTFzYXcrYTIvQ2NRY3g3THUyV2lHSVVvRGdPcXNxSEZ0YjJnSGpaWnQweXk0Mmp0V0NWY2NyVytJTFo0SzR4V0RUY0xrbUE0bzVtbnhMZnNNcnUrYTBrM1dsaFpReUxrM1BlUm9QbUVTR0VnM1ZmUjEvZVdGN3E1aE90bDdMbVNBcUUrUnVDZHJHV1BLWnd1cU1MaUR3VGRWTDJFRzRUbE5KckFJdmNMTW5IazBJU0xpZUVTRFg5NlRsWUpUcEtZcGFneW5RZmx1aTFOSDNJTG1rSDVGVjZIV0lkMDFpeTJRRFplY0M0OExBcCtxcldQYURNYUhFRkhsRFMwV1FHalIxVTRBWk9VNkxLOGc5QzlySDdwNnJxMjZiS3M3c3Nmc2l1aWRJQVU5RlZoRFVGdTNtaVJ2TVIxb2JXQnhCUFJIWmFYd0JPanlMM01jaXF6V050eDFTOG1va2k2bTFnb3R4OGtyTk9kVnduN1ZSRTJUN2l3dVhKYWFacmJpNk9YdWZIejBWZStsa2ZKcTZEZEprZ3JNT2xMbWtPRnI5U2h3MHBhNGt1dUNtcFF5cEFhd1dJRnQxRTA4a2JMWEZrTWVBM3lhNW1qSjFGajlQTDNrVEhQMGtnbTYrWWM2OW44K0UxMGpnMGhnSklzRjllTVk0UDNHeFd0OW9HVllzVHc2U1JqTlR0UFQ1SzFDVkMyajR4cm9CRVd0NmhFaGpJaGJZN3Jhc3laUm1ocnBieGxvRHVvVkFhUjBMOUhrcmNaQzNBVm1hYklMQVFTcktlbjhOejVKZHNOeWJDNmJkam93SUM2SXlFdWNGTHVmcXBpYlE0YkZBMkM0OGc1aVlTeGRoN0g2aHpudzdrTGtNMXBpMWRUN0s2Z1V6bytpQTFkTkhnK3k4bDFuZU1nRitnWFJuTTFVd1BvdUw1QXhFdmZEdnRzdTAweis4b21ublpCTHNhZUxobXNZZ05MM2JLcmMzY2xYT0p0R3R5cW5LcEkxWWRpREJ1bW8rRXVPVWVQamxSRWtFZHdvOVZJblpRdnVvenFKdDRYcEhXYXNBaTNLRzgzU1pGbUpXVjdycW9rRjdxMnJoeXFtUTJKU3ZNZkVyWjR5THFzcVc3RzZ1cW1VYVZVVlBpdWlaWmdpaXE0Z1NVbXltSmpkYnpWdE5UbHprdlhPRkMzZnl1Z1hjZTNTS09ybUZHeDE5eWVGWVpHeVJYWnl4T0x1MlA3c2tFN2JKWEQ4TmZtTEZJb2cwdWFYVzRYMmwyRmRtMVBsN0RJSjNRMmZZaTQrU3VZNDduU01qVVovRGkyeTY3SnV5T2x5dEJUUGV4bXF6WEhZOHJyeHBteHRhSTdBRHlRNFlUSkdBM2F3dHVwc2U2SjFpdlJyQ29JK2RhblZ2SXowamJNM082MTNNMkpNb0tDUnhJRmxlVjduQnBJSzQvMnZaZ2RRNGZLMFB0NGY0S3BtbFNML1RzUGlUVGY1SHozMnhaa2RXVjBqR3ZKR3F5NUZGQ1hPMUZYdWFNU2RYNGhJWEcvaVZXMDZHaGVlek8yZTl4NC9EaVBVamR3dGd3K0xjS2l3OGFuQzYybkQ0OWdxa2hwZTRjMjJsYmJSTzFodjNMVmFRV3RaYkhoMHR0TjlsV2ZjQ2ZZMkNrYTRFRmJOaGJ6ZG56V3IwOVR1RnRHRGtQMHBrVE9tYjdoVW1oamZ1WHErZlVnVWJ0TVkrU0RWU1hkeXR4OEl3STl3WmNodmFzNmhibFlMOWxWbEl0eFhCQXgzWG14YnJPdEVEOTFYYnM0d3dzQUZOckE0Slo4aDgwU09RNlV4OElGSXhQcGEwclg2eXFjTDI4MWExc3gzQ3E1NEE0WFZTY21oOFVKUjE3MnU2cXlneFFnQzZyM1VvRzlrS1E5MnFyeU94MjNnMm1QRWU4YU4xaVNzSVd2NGZWNm5XSjZxMWNROW5OMXBwbFBZSEZlVDFYbVlodnlrVGNYMkt3SXlFeE1td3NqVzZ1cXl5VFVxc2tnbzhVcEFSMkZzUllNbEYwd3h6U09WU2U5RnA1Nm84ZFo2cGRpM0V0U1I1cjJvSldPb0R1dDBVT3YxUnFRdHhDNmd2YWdoWDlWNjZQY0EwU2V3T0NTcUlCNUorK3lCTUxnb3BMZzdCOGxKTkRhK3lRa2p0ZFc5UUR1cStWdk95b3lMOEdJbHFtMDJYbkRmaFI0UUlZMFB3djRWaEJKY0ttamVicDZua0taRXFGdzAzQzhXb01VbHh5bUR3cks3QU1nZGdvNmxrOEtCS1hJQXlTb2szWHIrcWlTaERNM0M4ZUZHNnlUNFVBYU1LSjVVbEU4b0FpSkYxQnd1aW5oUmR1Z1l4QVMxWkxObGtyem5XQ0Jqb2dKRzJRWGNJc3JrczkzS1d4cTdncGtvODhvMHorVW85NTNWY3RJRE1SZEtTaEdsZHVoU2xBeXhFVVBDV21PNlpmd1VwTWdIeEZudXNsNUhJamt2SVVETGFRTjdrQnpyRkVlNUx2S0JqVWlFcnJCSnlQNVJwbjJDUmtjU1VGalVaYzRMRWRuT0N3OW0zS25UUlhrQzRGTHNYRkJTaDJuWmJoZzBkdE95cE1JcGc1clZ0K0ZVZW0yeWRBeDg3TG1nRmlGc1ZNK3pSdXFLbmowa0sxaWtzM2xhTUR6K1Y4bHUyVGJsQm1rOVVzMnBzT1V2UFVybHNUUTJKaDVvY2t0K3FROTRQcXZHbzlVRFlhaVBzZXZQbXNFb3liYmxEZlB2eWhiQzJqVGZIdVZXNG1RNEZvVGdtMHhuZFZFdFFaSnlQVkx1eHFWRlBQUmFTVFpWRlc4TnVGdGxjelRDU0F0T3JHdWRJZGp5cHRMY0pVUVpkNEtxTVdrRVlkZGJEVFFmcXpjZEZxV2FYR0Z6dWdRN1M3Qm1uNDNQR1hFa2hhSm1qTThlSDBqdzF3dmJvclBPbUlHaGdlNE90dGRjSHpKbUNTdXFIc0xyaTlrY1lHNnVCWEdzeHk0alZPczQyS3BaMmg1dVR1c2xuZEhWeVQ1TExJblNjcXlsU0dwbUc3TXNnKzdsenJwMXROWk1SeEJxVzVVeHk1SzFzQk95T3lqNnAzM2ZTYnFUVGJheVo1RW9YYkdHQkVZUVVZeEY0NEtHSVNIV0FLQnNOSURMTTVwczBGRXA2R1dyRjlKV3hZSmx6OUlQRjJFcmZjT3lYSFR3Nml3Q3dQVkNGUnlUOURUUjdrRlpHSDc3cm9PTlUwVUFjQU9GcTBvRG5IcDgwcXl4R0lwQlF4TmJjZ1hXWFgzQUN4UHFCOEp2OGszUjA1ZVFTQ2hZeWhSbEkrVnc1VnhRNFNTMEU5TjA3RFN0WTBHeU02dGJUc2NPTnVxRVJJSExWc3BZU0JhNFd2dW5mV1ZWcm0xMW1xbWZQS1J2WWxXV0dZY0dnUEk5VmJvbzcyV05EUjkzRzNaWE5QSGNnV1MxTDRnRzJWcEJGb2UxTFlhZGx2aG1IM0FObHNOUFRocGFMZFVyaEROVVkydnQwVjFIRHNTZHJDKzZHaGlqWUhINjV0TFIyQkFPbitDNUpqRlVhbXBjYjMzVzNac3hJdURtWDQyV2xsdmVPSktybnM5QmhVV25RQXN1MnlHUjBSM2JPSVFuQkdqZnlUMnhvV2VFRndURCtFQjlqZEdpakY3aFJ3UzhnVFR4Y2xMdlRVZ1JWM0tHOUhlTElEMFJ4cXlCNFMweVpQQ1dtNm9nV2hhWkt2VFV5VWVqUmt6RkorU2xIY0p1YmtwUjNDZEV6OGdyTWxuOHBtWkxQNVRVWjBnYitxQS9oSGYxUUg4SnBTa0JQVkRkd3BucW9PUkZlUUYzS2dlVk4zS2dlVVNLN0tpdG05MXFXOU5sc1dGMXJaSW0zUFJVT013OTY2NDIyU3VGVlQyVkRZN20xN0wwbWRjSHhMRytUb1FZMm9oT3c0OGxTbGpxS2MrVjdxNHB3V1V6SFg2cjJJVXJKbzlRQXZaWU9TUHhHbkY4RG1GNGpaclNYVzJYUU1zNDdIWU5jL2tXWEZtVmo0SjlGemE5bGRVK0x5VTJrdGNlZWlaajRGVFBvZkNLcHNNclMwNmdkOTF2RlBOSEpUZ2dqVlpjTnlQbUExR2dUTzN1T1YwakRjUWVKbStJNkZaY3VDbW9VYlpCQzZkMjQyVGRORUlUd3BVVThVMExkRnJueVRYdStuYy9OVTVsbUNvQTl6aTRXRnZrbjZNWGI0eVQ4MElhQU9BaHlTT2FmRHg2S25KRnRNSlVnTXZZSmRydFNNUDF3c1VKOFpqS1ZzRDNvSElDQ0xlYXNJM0FOSHlTc1VmZWNvOGJDQ2lvRnV3dXZmZ0lrY3BJdFlLQURSeW1ZakdHbmhkdWdLc1VrcHlEZmRIZ2QzYUhKVUJ4SVVXRzZLS09PQVdwcUxteWlJN2dGUmZEcTNYbzNFbXlzcnNBNFVTMUZpeUtnOGFRbVk0UTRicWZ1ekI1SVdnZHBXeXdQNzVwYU9VMCttZVdOSkNzS1dFVFR0QmFuc1JnYkJFMnplaWtvcElZc2JOZmRHV3gvQ1BvbDJzQVk1cmdIWFBEdDFhTmIzcmZoU2t0TzZNRnhDck9WTVpHRFJvK2NPeitMRmFTV1ZzUUJ0ZTdXcjV0elBnVHNCeENSb2JlMjNpWDJEWDFUcEtLU05vSjhOdGx3ek4rVjNWdGJJOTdQcW1MUFhBOWNIR1pZQytCMXh5ZzBsSVkydnVML05iVGkrRW1qTG02VlVpUFJjRnRycTFEanVjZ2lvampQdkx0dHJMSnA3TmNiZGZKV0poREhhckxFclc5MlU1OGk4aW9wUzBoM0MzN3M5bUxKMkJhYVkya2xiaGtndFpNMCtpZERnc1lIUjlONUlyaERUc0pkNUx1ZVhzWVpOaCtuVmM2Vjh5NVhyWGU2YkhpeTY1ay9GU1l0SmQwUXk3R3hBM0xFVHF1YnFwY04wN1Z5YW9RUWVxU2NWV2ZjdXhNQUc2WmpCc2dOTzZaak95Tk1LakxnaEVibzdpZ09jcTdZOUk4M1lyRTBvc29tVFlwR29sSUIzUXNzUlFLcmZlNnE1aHVVYW9xTitVcTZZYm9Dd2hhZHR3VldUUjdsT3l5a2twU1VFN3JxbFlTVk1YTWRnU3RmeFp6Nm1UVGJialpiSGJmZExZblN4dFpxQUY3SUgzTldNbDRiL1EyL3NkeW9LckVZcEN5OW5BN2hmYStYSUc0ZGhjVE5JRmo1TDVjN0I2Y3kxQU50aC9jdnF1bkFFVFcrUlhvTkd1RDV4MW1meHY5UzFpZjQyMjJDblVQQXNoTThKYjhrS29rRnd0Q2JwSGtzaTNNVnhldEVGTTgzNEJYeXYyMzV2Zklab3dSd1F2b1BPZUpDbW81ZkZ3Q3ZqcnRPeFgzNnVsQUY5M0JZdWVSN0RwRUtwL29jN2trZFUxQmVlcHVubXdNa2pHKzkxNkdtYTVnMkFLY3BxTTJCdXNQSStUMWVaRFZCRll0OFA0TFlhT1BoSTBVTGR1RmJ3c3RheVROOEhaY0Z6UVJDd3VyYUp4SkZncWVpRDl2SlhsS3diWFZaSzJkVXFSWjBkeVdyZWN0VXBjR215MUhESVJJOXV5NlJsMkFSUkFrZEZkeDQyekoxT1JXV2tqQXlNZE5sWFR2RitVN1d2SWFiS2dxSm5hMW9TZkJsUlhJM2ZWd1NzZ1dTY1VwSTVSM1RBQlVwTXRSUVhVdkI2Vk05eWlNZmRCWkdocHNpbjNteVdDa1hnQkliRnBHSlhnM1NUNUxsSGxsQXVrQzY1S1cyTVFiWWpoSTFjV29GR2RMcFFuU2EwRERSVFBlNmxlVGNqZFcyRjR1Q2JPTjBsaU1JZTBrYkxYcWl0ZFF5QW9ib3RSVm82VjNnbWJkb0NoWXVQQzFuTDJZbXo2V3VJM1c3VTBiSkdCd3NiclcwOGlocUlNUjBscmVFdkxVNkQwVmpVTmFEWlY5VEFDTHF6a1pVeHVoT3BuQ1g5N3NPVkNyQkJTRXJ5MXAzU0dXVWk2cEsreEc2czQ2OE90dXRMaXF5MTNLZXA2ODM1Uzc1STRXYmpIVUFqbFpNMXlxV21yTGpsT0NXL1ZPaXlyUEd4N1diOVZPOXdrdStSR1RYMlRVem0weE8yOTBuSkdMY0p5UndLRkszd3JyT0lxNVdnSGhBZFlIaE9UTjVTajJxdEpGcUpIVUFqUlNXS1dJVW1Pc1ZYU0dGdERKc04wKzE5d0ZTeFNIWlBzbHVCdW5SNEZNZEp1RUlteFVRKzZsZTRUa3hMUkI1VUNWSnprTzRRRVNKZzNYdFYxRUhxc1g4a0REUk85aXBjZ29ZTmxLK3lBTkk4VFpSSjNXQ1ZCejkxR0dpWmNndU5ndkYrNkZMS0xLdklzUlFPWnd0enVrNU56ZTZsTkx2eWwzU2dBcXV5d2tZZTVMU3ZDakpOeWxaSnVVdXk0a1NlOGJwWjd1VkI4eUcrVkE1RFVnY3J0a3JKSnVwVHlYU2ozWEtDeHlSR1dUbExPa3VpeTdwWjNCUTBXa0Nsa3NVQ1Yyb1dVNVJZb0V4RFJkU2gwUUwybmNwV2FRTktKSlVjaEp6blZ1cFE1RUtxY3NjTjFaWWM3djJqNUtvTVpxSGhYMkUwL2RXUk1WbDdHMFlGR1luTnV0MXBKZ0EzcHNGcTJFUmd0Qk5ncnFHY05JRjBLWjUvT25aZk5sQkEzVE1NMjNKVlRCTHF0dW5tU1dIS3N4Wm1TanlQR2EzVkRkVUJCYzY0UzByN0RsRXlKRFpxUU9VR1NvRjlpa0h5bS9LSDN4SjVTcERZb3R4VWVEbFJqbDhXNVZZS20zVlNGVHA2cExZMUllcUs0TUdtNkZGNGpyVlBWVGw4d3NWWnd6QmxOdWQ3STFNS01ROHRTMXdMVFpWc3RNMlIvQStpQ2FuVk1kMUNvcSs3Y04wYWtCSlV3VlVHd0ZhUm5VQ1dKemh0dmZaYlhXeW1RWFdsWnNxQTJua3VlaFJialUweXRIQ08waXUwd3lEVWRnZXE0YldUZDVVUCthNmwyalZUcE8rc2ZOY2pjRDN6aWZOR21ieUdvNUEzbmY1cHNPQkFWYTY0S08xNUFDYmZBYUhBejFSRytHeVhpTG5kQ25vYVp6N1hDVTJHaVRBNlRheVlqcER5UXJHbW9RM1RjSm1lTnNUQnN1U251NExjc1d4V1Y3SU9sdndWdmhXQSs5U0R3Mys1SjBjVHA1V2dEcXVrWll3VjEyRXM4a3RRZDJVY21WUkhjdTViYlNSQnhaYmJxRjdNV0tpaGE1b3NGdGZjZTdVMXVObHo3TnhiS1g4WFZpTDJxaWhMTGJOS3h6R0JkeEJCdXRlTlE2cmRzUG9yQ1doZlV5T3Z4ZE0wdUdOaVBBdXF1dzNzYzBrTDBHSEE3dnY4QWVyYW1ZR0VORFJiNUlrVkM5MXRJUDNKeWVGbUh4WGZiVmErNmJGRmZObVQ0RmFwN0tTTFdUdmE5bFFUVmh4Tjloc09kbEhFcW1XcW1zQ2RGMDFodUZPZUFXQzU5RTVNcVFnNThrNlNqTXpoNGVObHNGTlRDTmdGdWl6VFVIY05HMjZmcHFSem5EYlpTR0d5dHE4dHlTUFUwQmFlRlkwY2JIU2lPKzVSMlVoRE5tWEtGUVFPWmkwUmRzMUp5NFhEazFkTmpVOGY5RGRzSG8vYzRnOXd1Q09xeml0WlpqaTNhL2tyQ3JuaWp3MkhTUmZTdFV4R3JKZys5RGp6N09HYU9tMC94R3E0MjR5dmNxbGtKc2RsZVR3OTZTU2h0cFFBVW1yUFhMUHhTS0Y4UmE3aENlQXJlcXB3THFwa1lRU2lVUTFOeUZKUmRMUFltNUduZExPNVRGQU5SRm5jSmVRYkp4N0VyS0VZRWtMT0ZrRjRSM2NvYndvSnJrQVFsNWswUWw1Z29OaWhHVGxKekp5VGxKemRWWVJtWjBLUFM3K0V3OUx2K0ZPaVpnckx3bG44bE15Y0paL0pUa3pOenZrWGR5Z1M4STd1VUNYaE1LTSt3RjNDR1RaRWZ3Z2tvaWpMdVJjb0VySk95Z1NpUUlyamw2ZVFOSEJIUlZRLzBaelpSODFzR01nWDNGOWxUVFJkNHpaZXF5eHRId2lFcUwvQjh4Q3FZMk1rL2V0aWZzMERvUmRjNW9tbW5sQjNGbHVlRzRtYXRqVzdFalpZODRjbWpDZkFwalZPS1p2ZWdpL1BLck1LeFgzdVFOY2JXMzNUZVkyU2hoTzlscTFPOTBjbCtDUEpER05EZTUxTEFNYU1FN05MdElIbXV2WmZ6QzJwZ1kzVjRyZWErYnFLdWRVT2FXbTF0dGwwREsyUE9nYzFoZDZjcU5NNVNQb25Bc1NkVHVhUzY0OUZ1MVBYdHEydEYrZzVLNHhndUwzYXdsMnhQbXVoME5iQ0tQVXlRazdLdElZa2JoN2pkdW9FRWZOQWtBaU5pc1lKWFJ6UXVEbm5oRXJJaFlGaHZ1cXpZZE1odEZ1RXhERjd3RUZzVnh1ajB6bXhFM0tYdVF0SmtKNC9kaXZkNENGbXZuYThiZWFUZTh1NFF1U0dKQkpYbm9VTnNqNzhxY1RDZVVSOGZvdURVakVVWkozUjlPa0x6YkFCRmpGMHZkSkRPQVlsUGtVV0NPN2hzanRwOVhUOEVlT0RUMFErTTBDMVpPR0M0VWpUbTQ4bElBc1JHdnVMS1BVSE5oT0Z6SUptcHV1a1pVUk4rU3J6VHVCdnVwdEJ0Wko5NWJMYWlnUTB3dFJlNGJWVXppZGo2bGVOTVhrYktkVEV3QUFPSTI2SWxQY0U0cWlraGdhMm9leHd1Q2JLdXgvTEVkU0h1WXhiQksxa0RkUTNLblF6Q3J1MTI5d2pWRlNYQndETVdVbXlWRGdXZ0RmbGMvd0F5WmU5eDBsamIvSmZVR1pzaXNySUpKRzZnZlJjbHpabCtTZ2djMFI2OXVYQmRsckl4OHl4amljWjkxTDRoc2xxbW5MV0VMWkpvVEMzeHREZnVWSFdPZUtnYmJMUzAyVlpSV2FORkc5cFlUZlpiRmxHWXRuQUJXdllpNHlPdHg4bGE1VGIzRlZjazhkVnBTVkNjY3FPN1pZck5OQWQ5N2hiemxiSFhNbTAzTnJybHVXWjlVWTMydXR0d2F0RU5ZM3B1a1NmQnVRZG5kWWE3dnFSaEo2cnhmZGEvaDlkMzFLMnhWakJVN2hWN05HSFlzR3VOMHpHL1pLTW5EaDBUTVIxSTB4dEJudlMwajB3NGdCTFNsVjdHcEF5OGxMVlE4S0s1KzVTVlpONENnYkxNVVZOWEpaeHNVbzZvdGU1VWFpUzhoU0ZZNzFLQ3l5a01HZTU1V0RLQ2xXSFVwRnBDWEJ0aFRWRTNQK2FEVXhGOExpU0VlTjRHeWhMR1N4dzMzVGwzSEtWd1ozUHNBWXhybjNJdllkZmt2bzFrOTViQTdMNVQ3RzhSRkxXQmhjUmNnTDZpcFpORk8yVG0reTNkTEpKSGdPclFia3k5Nyt3Ry9SSTFkUWI4cFdhcUFzTHBURWNTYlNVajNueVZqTGtWR0ppdzc1R2tkcFdKQ09ta0JlQmU0NVh6SG1HaGJWVk1qdWJrcm92YXJtOFZGVTlqWlB0ZEQ2cm44VHU5M085OTFoNXAyejJ1aHhlR3ZrYTBhRnpaQTBBMlZrTU9leUpwSG1ycjNZTyt5RDl5S3lrSnR0c3MyU2JOWEpLeE9pb3lMSzVwNmExdGthaW9OaHNyU21vN1BHeVRKTURKTkVhT0d3SGhLc1lvUzA4RUorbXByQnZoSFBrclVVSWswZ042ZVM3Q1BKV2VTa05aWG9EUEtMaGRNcHNON2lDOXJLaXlaaEJhNE9MZndXK1Z6R3gwNTJ0eXRmRkJVZWYxV2I0alVLMld3SVd2MVVuaUtzNjZjaHovQUpxZ3E1eVhGVlp5TFVFTU1uc3N2bnVPVlh0blhvMzZqdVNxTXBGeU1SMWtwdW5ZWGJKS0d3Q09KZzFEdU9PSTMzaURMVVc2b2Jxa05DVWxmM2gyU2R3RzB6TFVrbmE2bEh1b3hNdGE0VFlpRmdvY29XZkhkU2lwcjhwanV3c2FMY0tFSzZzaFBDMW5IY083eUlrRGV5M09kZ0EzVkxpVUd1TjN5U3NuQmR3TGNjOW9xdDlCVk1GN2JoZGt5NVhlOHdSalVEc09DdUtaaUlwNWliMnNWdHZabG1FeVNzakxyK0syNVZ2VFpEdXB4Y1dkVW1ndVVqV3NMR3E1Tk9aNG15QWJXdWw1SU5RSUlXcStVZWVrOXJOVHJCWThLbnJEWnBXMFlwVGMySDRMWHEyS3pEc2dsMkxzSldVZmZXY2pSMVdramRJMUx0RHloUnpXZHlxemZKYmlyTm1vNjQzRnlydW5xUVFOMXBVTlpZamRXdE5XM3R2K0tOU0k4YU5sZE5mZ29rVXA4MVV3VDhicHhrNENaR1JXbENpeUR5UXBQUHFsWWFnRkVjN1VtM3dWbkdnVXd1VXU1bDdwdlpMVkhXeVV3NGlyZ29BQUZTY0ZCSlNIV0hZYmRVM0crOXQxWG8wQjhTTUZxeTBqZGNjb3dQcWsydTJDTTEzcWpUQW9rU2hIbEVFZ0t6cUJIQ2dOQXd2TEpLanBRTUpJa0NwS0ZyQlMxSUE2TU9LQzgyVER5TEpXWW9HdzBEYzduZEp2bHVTaXZjbDVIRGRWNU10UVFDWjNxa3BaU0xwdDdoWkpWRGh1cTdaY2pFWGRKY2NwYVdUMVFwcERjb0Z5ZVNVamtzSkUzeWVxQzZRbGVld2VaUTNPYUJ5aEdwRUpIRW9MbE44b3RzbFpKOXlnNUhKSHBaRXU2U3lrNXQ5N3BlVFpPb3NKQTVaVGRLU3k2dGtlUnczU01yeHVwUTZLSVBBMzNDVm1lQWJYWHBuK3FUY2J1NUtsRFVpeG8yZ09IVmJMaDdOVnVpMTdDd05RdXRqaGtBWUxiTGpFVDVSZHdWUHU0QUNhWlZtNDNWSkMvZmMzVGNUaUVyek12TGpzMmFpcXJnWEtzbTFIRzkxcWtOUTRHMTFhMHM3aUFuUmtaazRGOFpydDVRSlpib0RYazlWNTV1RTVzU29rWHZRNHpjRlpmd2dqd2xKa3hxUmh6N1BXSjV0TGVkMUNXVU5DUmxrdWVVcHNha04weis5ZGQzbjFYcXl2TVRkSUtUZlYyYlliZkpWMVJPWEhtNlNwREl4TE9DcHVTU1ZCMVIzMHdGMGpDN2JsRXBXNlNTZk5FcEFTanlGeE9idUlManlYTTgyNHBxamtGK2hXL3dDTDFiV3drRTlGeDdPbFhjeVdOa3hNMDlORTVKbkJwbk1wNTNLNXZWVTVqa2RzVjAycmNKblBCMzNLMSt0d1R2MzMwL2dueGtiS1JwMFVKZjBKVDlMUXVrY0FXSDZMWTZUQld3OHQvQlBNalpEOWx2MFRiNERTS3Vqd1VFQWxxc284TlpIYmo2cWJxd05iWUFCS1BxM09jbFNZWllpRFNSWmVtcE8rQUM5U1A3eXl1Y09vUGVabWM4cFdOdStROHVmY3FIOG41Vjk2ZXdsbDEyQ2l3R0xEcWRyalp0Z09xcXNvd1FZYlRoendCWUhrZWlUelRuS0l0Y3lPUUMyMnkwNDFSa1NUa3dPYU1hYlRnc2E3MDJLNXRpZFc2c2VkK1U3VjRtNnNlNDZyL2VxNTFPWHU2cXZOTytCa01QbXhPR25HKzNWTzBXRm1hUUhTYkswdy9CM3l5TkRHYWdmUlh0WkhEZ2RHWkpMQjJtOWlFL1lxSGVMd1VzOFVXSHd1YzRnRUFuY3JuK0xZNDdGWm5CcE5ta3QzVTh6Wmpmak03bVJ2TFJ6NFNxZW5pN3BoSjV1Z2NhS1VwdHlHNDUydHN5MjUyWFFzajRheVpvYzRBM0I2K2k1NVR4ZDQ2L2t0NXlmaVlvWm1OY2JEamRLZG0zbzZhNU5oeFBDeFRPSnRZZWFOaGxNSm5OYTFwZGZ5V3lWZERCakdGT0ViaVpDQmEzeVd4OW0yUXFvMU9xV0VtTy9KRjA3UjV0enBsUHJtbldtK0plaGQ1QTdMMjQ5QzEwc1lGd2Zpc09pc3NmN0NqUU5kUEV4aHQ1RUZkZ3d2THJxTERveFNzOFFPOWhiWk9UVHZGSTVybUIxdGpxM1cxa3hSbkhzZVJ4OVd5WW5TZkg2bnlUak9HVDBNam9YQTJadFlCYWhpVS9kRXNJTnd2cG10eVRCaldKeWw0c1hPNEFYT2UwbnNWcjhObWtxNktuZkkzMUJzc2FlaWJkbzlyMHZxc01qVzUvVTQvRzRrWEtDK2F6dVZMRTJWVkJJNWxSR0k5T3hTcmRFMFpjMXhKVkNtajM4SGpmbWlGWExxNm9ENllFWDIrcURVU0ZqeUNobWQ1WE56UmZoR0hxUW5wN1hTTWtOcnB4OVNlb1FYa1Nicm5paDhJcjVCeUVuTU9WYlNzRnVFaEt5NVZpeXZWbGE3NGxoM0NkTVhPeUFZU0NkbDJ5YkJVdEZrdE1CdW5KaFlKS1Z0eVZMSlZDRW5KU2N5c1hqbEtUY0ZXa1p1ZFdpdWVFdS9oT3lEbEtQM05ySTB6TWNMRTVkZ2xuRzVOa3hJOTBrb2lhQWJteTlYNGM3Q29STThIeEcyNkt6T3o0bVY3dVVDWGhHY2I3K2FYazRLc21aTUc0N0pjOG9ydXFFZVVaUWwzQnVOMUZaUEs4QWlRSkRGSEYzMFNjVGJ0SUtzcWlJUEc2VWJIb2NWN0dhNFBnVVdJelJhWEd5c01GckJUU0FIelV6VHRrQjZwQ1p2Y1NjRUxObkV1NDJiVldSdHI0TmhmWmFMaTlNK2ptTm1yZDhFcTJkelp4NmVhcHMwT2drYzRnZ20vbXE5RitQWW84TXJQZG5BRWM3clo4T3hBeHZhOGZOYVU2Y2Fyam9yTERjVERuQmh1bVNoU0JUTzI1WXpIM3JHdEpYVThxWTNFNm1JbGVPZXErYThPeGdVSlpZOG0yeTMyaXpJSW8yYVhia0FyTHk4RnFCOUw0Wk8xOE9xTGZib3RndytZUGhBa1pjK3E1MWtITXRLTU5CbGRjNlBOYjVoV09VbFkwNldPNEt6SnlvdEtGaGF1UVFncXBscjNCMnk5aWRkcmNRMjVTc1ExaTd0dm1xQ3lzSHcwT3hUdWw1S2NpTFRaVlFtRVpUY0Q3OVUrTTdCY2FMTnIydEhSUWZNQ2RrQVhkeHVqdzBwZmE2dFI1QllXbWFYbFcwRkpkdDBLQ2xFZHZ6VDBjbGhaYStUU3FyS3NadHNHV2FPaTh4OXlpUEdvY29VVExsWStYQWt5NUIyRUxkU0xIQmV5eXh2b21ZZ1J5RlQ4SXRxSkpqTlF0WmVkVDI0Q2JwNE9xS1l5VHdVWHV5anlJaEsyS1JRWDZKajNCc292WUt5b3FIdlFMaGJIaEdCUTFFcldGbDdxcmtsNFphN28xekNzdE14QitoelJiMVd4SElVR0h4Nnd4cHQ1TGY2SEtsUFFRTmxhemNpK3l2Y0x3YUhGd1dQakliYSsreXljbXVsSHNVcDl6alF3K0dxYVlmZHh6Wll6QjJPMFdJWVM2WjBVWUpaZmNGZHRHVGNJcFE1N1lEcUI2RWZrc1l2aDhkVGh6b1lHRWVHMWl2UFpOYlBkM0x1SS9QYnREN0lESDN4cDlnd0YzaEMrZDhUcHBxV3VmRytNalM0dDM5Q3YwcHpYa2g4RlBPK1VzYU5CdmNnZEY4TzlyMURTWVJpTTVqQUoxT0owbS9WZTM2TG1jNnY4aGVvWEJ4bXN1SnJrVzNUMkRTajNxd05sWDFkVzJkN3JBZytxOWdybkd1NVh1Y2k0TXhPbWRhd0dzN2xqZDF0T0MxWGZWYmQrcTBiQ1RxWTNmeVY5aDFZYVdkcHYxVkdSdll6dk9DeXRaVE44U3RJcGhmbGM2d1hNQmZDMGFsc2xKaVplUnVxek5UR2JiRk51TjFaVTA0c3RhcEtqVUJ1cmltazJDTkZtaTFjL1pLeXlXdWlPZGRvU2M3K1ZYWTVJZytaVjFkTFpwM1I1SDJ1cXZFNTdDd1BSQXl4RVNsY0NTVWxPNEZTbW5JYVZYUHF2R2QwSllRM0RKWXBndUJDckd5V054dWp4VEZ6ckk4Y1E4bzIyTWx3dDVxMEZIcWFEYm9oME5PSlFEYTZ1bzRRUUJiZnlSeVZCWTE4UElobDNHSDRQak1KQkliclgxM2t2SFk4YndTS3pnWGJuOEF2a1BFc00wV21hM2NicnFuWXRtMlZyMjA3M0ZvRFRzZHVpdVlKdEk4eDFIRW0yZHdxcXkxUmErd1ZQblRFaERnN3lIV09oWXJLa2g0ZmZrWFdsZG9HTWx1R1BicSt5cGt5T2pKMFdLNUh6L20zRUgxZUt2dTRrWEg3MDlocnc1clBrRnBtTlluL0FOSk9PcnFQM3E5d2V1dVdiK1N6WlN0bnJZeFVZRzhVbE1KQUZhUTRhSERoVnVFemg3VzdoYkxTa0d5ZEdGbFBKUGtEU1lZNGRGWlUySDJlTHA2bGV6U0VkamdYN0FwTW9sYWVSakVGRTBNR3lzS0NuMXlnRkFqY2RLYncrY05tRzZHS3BpZDNCMFhMdE0yR0VIYmhIeGlwSkJBS1F3dXZEYWNXY09QTkJyYXJ2SEc1V3BqZkJoNm43eFJZamJ4S2huRFM1WEdKdUZqdXFHUWt2S3laczI0SWlRQXZSY29VaE4wVWVFRGRVSlBrdVJYQXlKZExVR1Nwc2VVQ1NXM1ZLdmtKUEtHeU5EcjZyVWJYVFZJZGZLcWFjNjNicTNwUllDeVdtQTBPOTN4WUpvUkVBS0ZPM1VtSFRCcVltTFlBeGtLQllVWjg0UVhWQUNOQUFLendoVTlkS0JFL2ZvckN2cWhvTzYxSEdzVjd0amhmWkl6OWpSMGF0bWlaeW4vV3ZzVTMyWDFSR0lNRjl0WDhWcnVZOFJiTks0RnczOVZzWFpWUW1XdGpjT05YOFVPbms5eGYxVWFnZlVPRjZaTU1ZU045S1NNWTcwanBaTjRTd3N3OWd2dzFJVmMvY3lHeTlIRGxIaDlSeExnUXI2Y09CV3NZblQyQjJXM3lmckdFclg4U2l2cTJRU0g0NW5POFdZWTNsVi9lV0FWNW1DTFNYR3kxVVRlSWkvVlZKR3RqZGp6WmlEeXJLanFUdHVxTnNsK3FhZ20wa2JyaVphU3MyK0NvMmFtMnozdHV0ZHBxcTRHNnNJcWk5dDBjV0ltdUM5Z2w5VTZ5WFZaVXNFdkc2c2FkMXlOMWFYWW9UUTVxUVpOMUo3dHRsaHU0UU1XaGR6VUlqZE5QQVN6dVVORFRDbkViRlFXV3JnU0doSnh1anh2dUVocUlLWmhjb2RvYWFMMlJRM1pEYTVTTDdJeE5HU0F2YWdoUGtzZzk0U2dZYUdDNVJMcm9RZVNzNnJvQTBGYy9aS1RQUlhPOVVwTTduZEtaMklKNzBuS1RkR2tkenVrNWFnS3RJdjQxWkY3allwR2R4dWp2cUJZcEtvcUFDZDFYYkwwVVJuMGFlaXI1SkFMMlE1NmgxenVnZDU1cnREa2pFMVE2NXNoQjd2TlNrY04wRXpoQzBOaWlaZGJsRGM1dm9oU3ozQ1VrbE8rNkNoeVFlU3BDUm5xN0lFazNxazU1TDlVeWhxRFNWbCtxUmxtY2I3b2IzNzhvVWtvc3BRMUVYek9KNVVXWEpDaDNndWp4T0htcFEyaTBvSDZBRlp4Vm5pdGRVbFBLR3Q1VW9ha21ibnFoa1ZUWi9lZERiM1JHNHB4c3FXV2Z3Q3h1bUlMR3lxdDhpWm92YWV2TG5EWmJEUVZGMmpiZGF0UmhvSVd3VVVqUTBXUnBtWmtYSmR0bTRVKzlDcld5a29va05sWktLUTBaTmtPV1VBSUJrS0JKS1NDa3lHcEVKNXQrVXE2VzZ6SzY5MHU1MWtwalVnam1raEt5TklLSUo3ckJPcEJRK0tNd2tnSmpXR01KUVl3TElja3RvM2JvMGdaTGsxek1lSW1OcmhkY2l6UGlQZU9mdXQvemJNUnFYSXNmbkxudXNqU05QVExnMTJwcUF4N3ZtZ3RyZ2IzUUtnRnhja2lTd29vczB4NmVxTjlsNXNoZnlsQkpmelJBKzNSTzNjQm9ZN29IZFJNYlFlaTh4NWZzbUdVWmtOMHBzTklMU2VCdDFhWVppUGN6WDlWVzkyV0MxbGxvREJmcXV0YlFvNmV6WThZenJMU3dGc1pJdnRzdFVneE9weENZbDVkWW5xdlR3ZTl1c2ZPNnVjR3d4cnBHQU5KVElaSGRBNU1LZ3JHcU9rTG1OdUxraFgyRjVka3JYdHMwN2xiSGdXVkJVc1lTM290NHd6Qm9jS2hkSSt6ZERTN2MrUVYrRWQzSmg1dFM4YnBHc0RENmZLOUFaYXJUcUFCOFM0Ym52T0VtS1lnNkdBbnV3NjIzRmxzdmJQMmd2eE9TU25wMzNEUVdmVFpjeHc2SzBicHBkM2tYWFJPR2JrK1FoZ0ZQR0h1SUxpcGgydGhzaE1lYTJVdE93Rys2TXhtaHBDSHVXM0h6R3FGd2FEZFgrQ3htV3BiWTIzV3V3R3dQUlcrQzRnS2VjRy9HNkZ4c3VZY2pnZlN2WmhobEUyT045ZE94cmR0bitTNnhobVA0UTJiM2FrbGlCdnB1MGxmR3VLNTJyNVF5T2ltRVkwZ2VKSTRKbnpHY0ZySFNtb0dxOTdnSDgxelRZZGpGZFd6KzlPdnlQMFR3cXBaUlIzZFVpUUVXc3JOc3NVbUZUa3hBdUoyUDFYd3hnUGI1anRSaWtjYzFYZUlPQk94NHY4MTlNNVM3WjhKeGlxbzZGMG04akc2aVhiWHNMcmJVcVI0L04wNzRONlJ2K0haV05ZWkoydTdzdDhWa1BFNEhTeGU3eXhkOE9wS3NwY3dNcFk0VzBjN0MyWGF6WEFwMWhZeUlTemtPTHR0aXJHTnBtSkRVVDAwNjlEam1jZXlIRGNlaWNJV3hSU09ISUIySzQxbWpzQXJjSmpmTFR6T2UzbXpSL2N2cnlzd05zalMrakxXT08rNUNvS3hsWXpWRFUrTmgyMkNwVDBrWHl6MDJrOXBjdkVVMzhrZkEySjRiVVlKVU9qcVlIRWphN2xYbTQzTExkVjltWnI3SU1Peks0eXZwN3VKdmMyWE84MGRoVGFHbmMrS0FXQTZXV1psMHRka2ZRZEQxcnhhVGwzUG0yWjEraUd3Mlc0NDlrMldnbWUwUk9PazlBdFJyb24wcjdGcGI4d3MyV0dqMW1QVWIxM0ZwWk9Vbkk2NVRVamJoS3ZaZlpIWm9SSUFyTWpSWmVETEFvWmVUOGxMSDBLenQ1U2NqZVZZVE44S1NsNjIzVXNUSXJwQnVVcE0xT3ljbEtUY0ZYekx5OGlVamVVcE80TXAzdTZoT3lEb2tHUU9xY1NqcG1ndUQvSmNzWGpodUxuSitBaXZmSlBJTm1iN3F1ejNVeHl6dXBZN2VFMzIrYTNxcmlibGZBZzV0bXVsWjBQcXVUMUVycTZzZlV1UHhCUk1WbXdwZHhjN0JMeWNGTVAydWwzbllxOGVReUFIZFVJOG9ydXFEZEdaOHU1RUM2a0dYQzl5aU5DSkFrc1FoY0R4WlY4a2JnemhXK0pTM1B3cXNuYzdSOFBSZXlaK2Y0a0tFTzEzS2pqVXZlMjBnRGJvRkNsbklkd25UQTJhTWsydWxTTEVTcGltY0lpME9JTnVoVlhWeHVNbDNQY1I2bFc4c0JaSVFQTlYrSnd1RGJnZFVsbHBNVGtwZzF0OTFDTHdIYlpTaWxkTFlINUxFb01hVWtIUTZ5dmRGYmU1Q3U4S3pNVEkxczd0SkhDMWVGNGR1YkxOU1JPUkpHZEduYXdTY2tMUS9HNlozSEt1WTV4SkhwZWU2L3dDSmZRK1FzYXA2bWxBMWd1SVA3bDhYNVZ6Y0lKRzA3eHY4Tnl1MTVWeHVvcFkydmdlNXdPMW1yQ3pZWFpxWTVwSGYzT2pqcUxOT3E1dnVvMThRYXhyd2JlZ1ZGa1NyT0l5czc5KzVQMmx2R0k0U0NHRUc3VjVyTEtpKzFacmxPUGVXZ08yOVFySnRKY2l4Tmt3L0NkTUlNZk4raTlUa3RjQTdvbVlNaVFtV094aUdJd3NIVk13VkhpdFlMMnBybURoTTBOSzE5enR3cjhzcUV2RXhtSWNibEVrZVdOMlFJbVBhNCtTY2pZMXpiRkZrMVNhN2lvNFdpcmRWdk16VzlDNEJiZkZnOEVjREg2blhJQlAwVkMrbGp2Y0FYNVI0cWlja05jNDJWTHgxZmNzS05ENURJNUxEY0p3TVpJMUwwbE1KYkZ6dDFiUTBHb2JGWElhaEpDM0lIUnhhR20yL3pWemgxQzZySkFZRDl5dE1zWldrcmh1MDJ1dWtZQmtkc0c3bWhZZWZxRXA4QnI0T1RSc015ektYL0FiTGZNcTVMYVh0TGc0YitTM0hEc3R3eHVGMkJiTmgyR3d3MjBnRDVMdW5TelBrUmsxTklxNlRLRU9nWGM2dzZFSjltWElhZHAwM2I4aFpYVWJOUEM5UE15TmgxRUxYK3o4Y28zWmt6eXlreld6Z3NjYmp1VDgxVFk3VlUrRVFGN3JDd3Z1Rlk0dG1HR2hMdFR3RndydGd6NlJTdWJDODhkRjRDVFRsU052UzRadHB2c2M4N2QrMDQ5M1BGVHVhTDNIaE5sOFJaN21mVlZrajN1TDlSSjNOMTJ6TStPZnBLV1R2emU0KzB1TVpzamErZHhIRzY5ajByaXY2RnpQQ29uTGF1SzB6ckRyMFVLQmhaV2czSVQxZEdCT2ZtazQzYUt3Zk1MMjY1UmhTaTl4MGJCZ1hOWmEvQVY4MEZ4QUhLcHN2UGIzTEwyNEN1NFpXdG1ISEtCczlJdkl2OEdMcWZTU1N0M3crYldHNytTMEUxYkd0YnBQVmJMZzJKdDhOeWt5SHdmSnU5TlAzZHQxZTBOWnFBRjFwc2VKTUlGaXIzQ2F4cnJiaElhTktETnViTGRsMG5MSjQxR0thN09VTjdydVNDNGpNN3ZDVlFWenJ1S3VhaDNnSzErdGY0aW9PaUp6dThCVk5NYnY1VmpWUzJhVlZ0ZHFlRkJxSG9DWXdMcG1IeHZGa3ZhOWg2SzF3K21HeElRcmtqNE5nd2FEd2paWGNOTC9wa2UyeXJNS2FkZ0JmNUxiS0RDNUpuc2ZwS3NSZzJVc21WUkFuQTNWUkZtM0h5VnRsekJYWWZpYlhBRmd1T05sdCtCWUdIUWd1YjA2b21KVUh1Y2dlMXYyaHdyTWNabXp6Smw5aUVsNDRpRHd3ZnVYTHUwbXQwMFRocTZMbzBzdmVVV3J5QS9jdU5kbzFRNlNPVm9KMlZYVUlUcEkvRWNKeGFYdkswa0U4cTN3M0VOMkM5dGd0ZnJISDM1d0thdzl4MWpmcXFVTzV2eWo4SjFQTDFmOEFEZHkzeWdxdzVnM1hJc0hxekhwM1c2NGJpWjB0RjFaYktEUnY4THh0dXJTbG1GaHd0VW9hc3YwN3E2aHEyeHRCSkNSSmxUd21YaGt1RXMyY3NrMlBWSUhHSTJnaTRTc2RlSHljOVV1eVBHemU4SnhBdGFCcU52bXJPZXZCYWQ5MXFtSFQrQzkxT3R4QXMyQlRveTRLc29jak5WWGFpN2RKQ1hVNHBhV1c0dmZsRFpPRzlWVXN0MFdRWnFDZzZPM1VwWTF6V2psS1B4UFZleFF5a3FPeGcyd3RUSUdubExObUhta3FtckpKM1NvcUQ1cWpPZkpjaGpkR3hRek5jZGxhMGpodHV0UHBheXp0eXIyanIyZ0R4QkZ0RVR4czJtS1lOVXBYdGFMM1ZHTVFhZnRCQnFzUzBqNGxOcFc4T1ZsdytSdk4wblVZaTJBRUVxbWZqYldOTjNCYXpqV1ptdDFXY3BSZHg0bVgySlkyeU9KOTNMUk1keDlqb3BMT1ZMaXVaM1NNZlp4V240bmpEM3h2OFIzU1VyTnJSWVhIdVYyTDRtWnErd2VlUjE5VjNQc1NnTW5kRzE3dUMrYjZmdkt6RW1XdWJ1SDcxOWFkaXVFOXhUd09JdDhKVi9DdVNyMVBpUHpPend0TEtVRDBWWEkyOHB1THE0YzVvakRiOUVnK01CNUszY1hZOFlueUt3dTBOTjFYVmdFcE5nbktsd2JleVRaNGk1TFlPTlV6U3N6VVJzNndYTzZ5TXhQUFRkZGV4K0FTTmZzdVdZN0QzTG43ZFNxOGpXeFBnVWhsc09VWmsrL0txWTU3bXlhaU4xWFpiTGVtcVBFTjFlVWM0SUMxYUI1RGh1cnVpbDJDaUFhTDlrbkc2c0lKK04xVHd2dUU1QS9jYnAwV1Y1SXVvcGdRamQ1ZElRdXYxVEFjbkpsZG9NNVFjTmxQa0JlSXV1RVlBdFhyZWlMb1VkS2dKaHRnRVFHeUdzRjFsQjhSdGowWFhza1JMYnFwTm1VRjBNdU4xZ1BBNklZTjFsQ3draVplQWh1bHNzUE5rQjU5VUFhUmw4dnFsSnBmVmVmSnlsSnBGV2JMa1Vla2s5VWxQS0dYS2xKSWQxWHp6YXlWV2t5M0JHSmFzSFpJVHYxbmxUa0NUbW0wWFZabHVLSk9ZZ3lPQVFuVmFWbXFib1JxUVdTb0RlcVVtckJaTHl5azNTY3ppYjJLTkJKREVsVmUrNlRtcUw5VkF1OVVDWG5sRWcwakxuRWRTZ1N5YmNyTDVMQkp6VExxTEpDV1EzNVFETVNPVmg3dFNpR0VwaURSSmhMaW1XTU51U2dzYnBSV3kyTmtZWWFNbnpSV09zVkJqZGxJY3FrY0xDbmtKdHZkV1VYUlZFRGdCeW00S2pVNEJTaEdRdTZWOWlOMWYwVTFnRnJsSDRpRnNOSEg0UXBSbDVPNVp0bEFzaUNjSlFxTnltMFozbU9tVzVTMVRNTExMVDRVdkxkMTBMQ0FtZjFRNUgzVVpHRnBYZ0xoQUdZZSsvQzlIS0dvSUpCS0c4a0Zkb0pqNUlrQnNxeXNEcm14S2VwMytFMzhsVlloV05ZU2dZM0gzTk16ZlVkM0E3NUxrMVRlb25kMVhXTXpCdFRDNzVMbVZSRTJDZDNDRTI4UFlvSjZEbFYwMUtBVmYxQnZmWlYwc1JjVS9jWFpGWDNJSFJSYnFjNjFsWnRwQ2VpY2l3eG9zYkJBMktvUW82VXVJMlY1VFVRRFZtS2pFWUZnamdsbXlYWStKWDF6TzYyYUVwN3FBM1c0a2RWZFZESXczVTZ4UHFxeDBNbUlUQ0tGcHRlMnlrSU95MUdjWUt3RU1ScVpHc2pGOStpNlRsTExqaG9jNW5rZHdwWkl5Q1Exa2s0K3E2amgrQnNwdExRQnd0S0VUQjF1cFhaTUxnR0V0aWp1UllBZVMwbnRYemF6QTRabzJQRFNidDV0enN0NXg3RW1ZSGh6bjZnRHBYeTMybVpwZGoxYzlvZmNYdjhBaXJLTXJGa3MwbXZuZlUxVXIzRXUxT0ozMzVLelRPUEN3MWdlUW00S2ZkREkxdHZCN3V6YTRGajZKcWxvblQ4M1RVRkxxdGNKOFJpbGNBQjZxcEowTWdpcW5vakdMYmhRcDJkeWIzS3M4Ukg2a09BM3NzNWR3dzRsSlk4S0psK0M0RVBIVXVCM0Z0dGtmVUdzMDIzNFZ6am1Hc3dsdTF1THJYaE5xSkt0S1JVV0dueUVZVFR1TGdiRTdYVEZEbWF0d0tZU1FUU0Z3M0JMenNrVEozMndYbzNNaGQrdGFIRDFScVFieDJxTy9kbG5iZTlrMGJNUXFEWWJEVSsvNzE5RzB2YVBRWXZTc01OVHFONzJ1dnoycW5sclErbWYzUkcvaFZ6bGp0RHhMQmlHdm5rZTBmSkh1b3BUME8veVAwZnk3aU11TlJpYUlsMmp3MkJWcS9FNmVSM2RWR2xyMjdEWWJyNGR5WjdUVlZsN0ZJS1o4Y2trVHR5YmkzNy9BRlgxRmxyTmRCbW5Eb0s4MWNjUkxkYm1rcXpEVXA4SGw5UjBtVUxiWEIwV0NHR3RPZzJhd2JnZ0k5VGdrTlJUT2lld0VIcVdxam9zeDRiV1JOaHA2eVB2UnY0VHVub3NWZFRQSGV1TG0rWlZsVFVrWlN3VHd5dFdhRml2WlJoczBsVysycHo5N0ZxNHJuanNJOTdkSStDTjlodUxDeSt0clExREEvYXp0MVc0bGdzVlpaa1FCM3ViZVNDV05TTjNUZFZscCtHejg3Y3dkbldLWVBLL1hBNE5hVHpkYTAvQ0pvU1RJMGl5L1FqUFdRYUd2bzNXcDJhdE81MzhseWpIdXc2S2FpZkpHMXJTUmZZTE55NkpvOTdvUGFhT1pwVGFYelBrT1NJZDRkME9hSnphZDIyNjZ4bURzZHJhVFc5akhrQVgyQzVwWDBjMUhWbUNTTndzU0RkWk04TGd6NkxwZFpnMUVGVWl2cUF5V0tKcE5pUEpWVlk5MUZLUTBCdzQzVmhVYWRkZ2JGdlJWYzFScnFITmNMN2RWMk05bzNMajNmZEU1UEdiK2FYa2FqM3U0L05BbktzUElZOHNiamljQktlNXZaWE9UOFB0S0ozdEIwdTVJVmJIQVpKRzdjbGJMVXl4NFJoeDAyRGlBZHZrcEYyYUhUc1h1c1o1SmZxVTJlOFpFNGJDMTJ6ZHJMUlc3TXNyT3NrZFhWRXIzSHFrWTQvMXpnZUxLM0JXZVg2anF2ZTg4bEVWbjRTUjVUZFFkeWt6eXJoNXpKTGR3RGVoUEZrZHdVSE0xRlFvN0hka29JdFc2TSswZktuVDJZM2RMVnN3dnN1VVhNZVJRN2pGVkt4enQ5a0tWc1ppMjMyVXNWbzJsMnppTmxtbnBXaUUzSk8zVmU0WitiMFZMUzFzaDJLSkRLNXB0NXFjOGJHU0g4a05zaGZNQllBSlVoaVptWnZWSnpORXJYQWc4SzFsZ2FXdEtCT3dOakFBNTJTV1BValVudUZPOC9OUy93Q3NCT1l2aHVoMm9kUmRWa01uZFNCcFFKVVdWSkE2Z09waW9kOFJZTU5oNnAvRTI5NUFIQWNGVkRYR29kWWROdGtUUXhNS0tsbFBJMTdkbmplNjZ2MmVkb0RLS0pyS2w1SXNlUGt1UlZGSVkyMzNVc1BlOXJocGNSYnlLcXp4cVF4WktQc1hzOHphNnVybzNST0picS9pdm9MQ2FsMkl3Uk1jZDdkVjhiZGcyWmFlanE0MjFrZ2FkWTUzNnI2dG9zZVk1dE5MQVFZK2JoZUcxZW5jR3pmeDVGSTJyRXFaMkZRYW5EWTdiTFZheXJMQ1hOQjMzVzJZdmprR0pZRkUwRUYrcSt3K1MxREVLNFFSRU1hSGZNTElqSnhaZmpGTkU2V3ZNamdMcmFNTGRkZzhRNDgxeitscW42M1BBM1d4NEpVUzFjZ2E2NEhvaW5uZnFINGFOb010K0FUOGxsaGM4N0FwbWdhWUdnT2FDUE1oT3lQaWpqTG1nRjF1TExPOTViSzhra0tSVVRuMkpUSmdjOXdEV2xPWmVwcXZHS2tNYkVDRDVMcHVIZG0wc0JqTTBSR29BOExuanRGT2RlUm8yRDVkcUtrQWhoSStTM3JCTWtTeWFTVy9jdWs0QmwyancrbEFjMGFpMjI3UXIzQzhPRVV4ZXlOcGFSNUxudnRlZjFLa2w1bFJsUEEyVVVJdXl4QlcyVXpXNnJBRUtMWFJSWDJBK1FRM1loSEdTUVFxV2JWNGwyYUNsY3V5TGFPTUIxOXJJbnZzZE52NWVxMUhFczNNcEwyY05scm1KZG9jVEdrZDRGWHg5U2NIOFA3aUk2V1UzeWRGcWMyd1FBM0pXbzVoN1FJbzJTYVhHNEJYTjhUN1FHeUYxbmo2clVNV3pXWncvd0FXMWoxUjVPdDVsd3IrWnA0ZW1KOHY5aHpOZWY2aXRtZUJKdGNqZGNnenhtWjdvaUpIWHVuc1N4VVZGZHM3elhQZTBTdkxJbVdLUnBieVNOakhqakZHajQ5V2QrWE9hYmZOYy94NmZWSnpkYkhYMW5mMDlyN3JWcTBhbXVYMFBRWTlxWDlDanFta2pTYXp4Vkx2bWtueC93Q21ENWhXOWZUMmxKOVZYVFBESlcrZW9MMXVOMmpGcTJiNWdyQ3lPUDVCV2t3TEJxQ3JjRWZlQmg5QXJLU1R3dXVrdG0xMlFhaW1kTVFDVmZVY3BpSXNWcUZQUGFmWXErb1o5eGNvR0hGbTEwZGE0a1hLMnJDcXNnTjNXaTAxUUJiZGJKaFZXUER1aG92UWtkQ3Bhb2xnM1JmZURkVmxETUN4dS9rbWRWM0tvYWFEVk01TEZSMUxya3E0bCtGVXRZN1RkUWZFcTYxK3lSZ04zaEZxcE5UbEdHMXJxRFVQQjFuTlY1UlNqUU4xclRhaTdyK1Nlb2FyM21Wc2JUdmUyeW1OV3hPZDdVZE95cFJDcmtqMjFiOUYybkNzdVJ0b0EvVHZZTFF1eTNBQzJKa2p3VHQxK1M2MUE3UXdONmNMVnh3NFBNYWpPMHdWTkUybWpzQjBTdU1VN1pxTnJ1dDAvd0FuaEFyaGRoSFJXYVNNN3hXMlZMQi8wWkw2R3k0NW5PUHZIVkFYYjZWb2twbncyM2NWdzd0UGM3QmFsNUkyZWVxeXRTdURkMFVsWndYSEdtSEVwTEN5eGhzOTNqZnFtOGRJcWk2Y0RjcWxwSnU1ays5WjBPNTZDWE1UZWFDYmhiVmhrMnpUY0xRY09xdThBM1d4VWxUM1lIaUtkSmxKeHRtLzBlSzZMYjhKaWJIQ1JZT1duUlYya0R4SWd4RU9jTjFYa3hxZ2phNGF4OHB2ZlpQUVZUbU9GMVE0WlVod2JkWGNqbzJnRUhvcTdsUjE0ck5xd3ZFU1dBWDZKaXJsTDk3cldjUHhGa1hWUFRZdXd0TzZKVEtzc0E5SldiV3VnR3NOdVZVT3F5NG5kRGZVRURsSWNnbGhMU2F0STZvTEtzazhxcmZWZXFETGliWWdkMGlVbXkxREFXODlVQURjL2lrWFY0SDJ2eFZGVjRxeDk3dkkrUlZSUGpFTVJONVRmNXBEVFphV05JMnlURnU2M0RrTnVhVEdiYTFvVlZtQWhwMHV2OTZSZ3hYdnBmRTRqZnpSYnBGaVdualIxYUxOanJmRW8xZWJkVGZqdVZvSnhCcldlRjEwQTFSYUNTNC9WVGRJVEhUUnMyV3V6VS9lemxydGJqVWxRVDRsVlZsYnZjbElIRTJOdmNybTZSb1k5TEVhcWFrbHJybFU5YlVYWVFDb1Q0bEhNVFo2VmljSloyaTl3U253UTVxT0pHMDVDd1lWMWJHNXplbzVYMWwyZjBvb3FPUGExckxoblpuZ1RaaEU2M0crd1hmY01JZ2dZMGJXQUMwOFVEeWZVTW02MStwc0lyeTZZdHVpVkUra0UzVkV5cC9XOHBpcGwxTTVLMDQ4SThrMDdJU1ZSa2NVU1A0YnBJTzNSNDNiSVdoOFkwQnJvUktIZkpjenpkUmFBK3dYVEtnM0JXb1prb3U5amViWFZlU0x1TjBjbkowU0VKcUdleXhpdElZWm5HMXQwcERMYlpWMlhvdXkzaGwzVnBSem56VkhHOGJLd3BIMktFTnhOa2duTnVVOUJPVFpVOVBKc0ZZVXo5d2pUSzhrWGRQTHNFMjJUY0t0aGRzRTVHNUdwRmR4TElIWUtZRjBuSExleWFZN1pORnNsWWVhOFc3TEJVdFFVQUFQUVhsSGxPeFNjbDdxRDRraTVaWTgzVUFFUnBBUTJkU0dXTzJXVEpaQUVsbEY4NkJzTlJDeVM3SldTWlJra3VnT2Zjb0d3MGlUejZwV1pHa2J0eVVCN3dBYnFrNUZtS0ZKRHlxeW9mcEpOMDNXVGk1M1ZWTWRSTzZVM1piZ2dNdFdSY1hTTThwZWl6TTNTenpiWkpaYlNCbHZyK0tGSUFCeXBGZ0J2ZExWRGdBZDFLSDBEa2NCZmY4QUZJelRXdlpDcUpQRWR5Z21iWkdrR29rak5icWw1S25mbFJsbDIyU01yeVNqb0tobVNYYmxLUGRjOHJIeGRWNHgyUlVNUEFLYkhJUm0wYklrRGlUd29HZ3A0UXlEcUN6TVNBdlFTVzVVc01hYkpzRkV5a0ZEQnVWS3lSUUF4RE9WWjBqTndWVHRHNDJWdlQzOEtsRmZJellLQUFXV3cwanJNV3RVQjRXdzB4OEtsR1prZkl5SDNLbUNFTU5Yckp0RkR6SnVrc29NZHFLOVpRTHRrRFFSQ29BQ1U3MnpySTBsM0lEbWJvYURNeUN3dWh0WnFVbmkzS3dENUtVRXpEM2QyQ3RmeFJoY1NiaFhzdTRLb2E1dWtPdVNoYUc0KzVxV095bU9Gd3YwV2cxRFRQTVN0MXh4d2NTTHJXcEtZT043SUtOdkQyS1NXSUJLbU1YVnBVdzgyU2pZQ1hMbkpjM0VJNGdTTmxZdHBRQUVLT0MzUldGTkZHR2J1TjFBVzBLT2FHalpCZWQ5d2oxQmRITDRCY1hWemhHWFpNWUxDV0VDOTlncHRzVzhsRkxTWUhQaTByV05hYkgwWFU4b2RsRGFlSnM4clczdGZrSzF3SEwwR0dNWWRBTGdCeTFiQS9FakRIWWVFRHlWK01ERXk2MlhaSG00ZXlrYm9aWVc5VXZYNHF5aGhjOHZBMCtxcU1Wek15bWE4bDRCQVhLTTJaNmxxbVNzWTd6R3hWaGNGRmJzOGozYVYya09uRDZkcnlSOEs0bE81OVJVR1E5VmFZbkpVVjFRNXhCZGMrYUhUNFZNNGp3ZFVEblJzNGRMUzVJVVZKcmNMcThwOE51QllYVG1IWUMrbzArRWo1TFpxREFYeDJHaS93QTBtV1N5NXdhOURRRm8rRlBVdUZtcUdxUnVrRGJ4YkxjYWZMa1picmtCYnAzNFd1Wnl6RERERWFhTFMxMXJlRVdLUTVXR2pXTWNMWVQzYmZGYmJiZFl3TEdCaFF2dURaQ3BLUnhhK2Q1TGdkeGZkVlZaVTZweUFBQjZKa1UySDRsRnRqZU9uRndiazhXM1ZFSmRGMjNXWkNDTmtzV2VMa3F5a3hVOVF2SWRpZjNadXBURVQvRWxveUdqY3FFMVlDYkFvMG1MaG10akFEbWl6WEFCUklEZmkzdjVKWXlrdHZkUmlxZ0hXSnY4MGRHdml5UnJrWWJIRkg4WXZMOWtoWGRCMm1aa3dTRTAxSlZoa0xocEFzZVBxcUIwd3ZmbFFOUUQ1SDdrSGhiZVRpMjVlS04zd1B0b3pMbHJFWWFxV3IxTkx3MDZRZUwvQURYMVZscnQycHN4WVRGTFBPTllZMEVPZGJleStJTzhFZ3NiRWVxbCtrS3ZERGVDYVFONXNIa0JUeFhBVGw2WEhLclMraCtrbVh1MVRESzFrY0RkUmR4ZSszN2x0bERqN1k2eDVqZjRTUE5mQkhacjJuR2hBRlRMcElISmRkZHp5OTJ4MGo1R2h0UUhIMUs2dFhSNXpQME9WdXYyUHBLb3FvcStoa05qZS9WUWtwV21oRnhxOFBBV3JaV3pWQmpXSGw3M2h2SHdyWWFmR0lJbXUwdURpT0FWcVMxTVpJdzVhVEppKzdaVjErRDBMc0lsZk5DNHVMSEQ4UGt2bSt2N0tXWmp4YVY3S1p3YjNqaGR3MjVYMVpGaUVHTHhkMVVoc1RPbWtEbFpncEtLbGE2bUVjWUVodnEwQy84QWpkVVp4V1JsN1NkUzFXbGRjL00vTjdPUFo3VVlMak5SRXhtb0I5ck5GK2kwWEZhQ1NncW5DU0o3RHh1MGhmb1hqUFlyU3R4bVRFR3RkTDNyOVpEMjNBV2s1MjluV2p6TE5QVm1OMGZoTHJSc3NOcm5va2U3Sm4wUFErMGtkcVdSL05udzUzSXRjN0plV0s3aFpkUXp2MmN3WVRVeTBrRG5sNEpBSHkrOWFFL0I2eUtYU1l2QkdlVm1OTTlub00rTFZQbG9EU1VnRFM0N1dGOXlxYkZjU2RYU0dLK3cyM1Z2aWxWRXlMVHIwdTZnTFdwZzEwdW9GT3hvWjFEVVJ4eDhPSG5hRXB6N3VRMGZhOGtHWm5kTTd6cWRrU29QZHlCM0k1M1N0WFdtY1dBRnZSYVVFZUtlTjRtOGo4eXVuTnlVc21uOVVCekZZc3c0OXlMbEtGbXJsWmExVGtsREcyNFJwRFpVbFlDcWw3cHV4VlZKTVpIZFV4VlA3dzdGQmo4UEtKUk1yTGthZkJjVkRIeXVHNlpncFhPanRmb3B1WmJkZVpVbU0yWHNtZkJFSVZPR09MNzMyVUpZV05lMjFyZ0orYXNKMnZ5bEpJQzJRT0p2ZmRLa0VLVldzYWJYUW4zN29YVFZWTzFvYUV2SWU4WUxlYVN3ckZhaUUxV3g4bHF1TDBycWFZRWVhM1hhSncyVmZpT0hpc0lObDFvS0UyYTdEVUNXbkRYZFZHT2lFQjFiYjdwK3V3bjNXSzdSeDVLdmhyZS91MDNGamJkTGJMMFhhQjFEeElkS1lvYU1BZzJTejR5SmJqZmRXMUVidEFRM1pHWFZEQlBEcHFLYVF4NmVqVjNic3c3VHcxc1ZIV08zQTA2bmxjVG81SFEweGEwN0ZBcjZoOUJHSjRYYVpCdXNyVzZaU1ZJdjRjcnMrNEt6RUlwc0xqa3BaeEpkM0RWS2dMWnFZbVlYUHF2bDdzbzdYcWxqb0thdG1KWVNCMUc1WDJMbERMSXpKaDhVME9sNGUxcDJOK1F2RDZyRExETnFTUFJZSjJqVklIc2pxaU5JMDNXMTRiTEVRTzZhTlhvcnlQc3ZkTElXQmdMdlJYMkRkbU1tSFZNWmxaWWFnRmg1WmNscHk0SzdDb3BwbTZYeGtYNHV1aFpUN1BYNHE0UGtQZzUzVy9ZWjJZVXRaVHhQamEwRU5GN3VIa3Qwd2JMdjZJZ01iYkRhMnhWV0tNZVdVb3NDeVJSNFE5dWlOam5EeXV0dE5DZStqMU5zMEFjcWRKVEJzeGM5d05oNXBYR3N4UjBOTzkwa3pBRy8wZ2h5Y0lWYmt5M2xpZ2JHd0RUZXlScnNUYlFVNUljQlphTU8wYWpsZEkwU1hMZklyUnM1OXBjbHBvNEp3QnBPMTFpWnNydmdmREZadjFiMmlVN1E4Q1Z0d2JjclRjVzdVaEZJUTE5L3ZYQ1k4d1ZzOVRMcWt1SFBKL0ZIYXlTcGRxZTRLclBUVDcyYThOS2pwbGJuNlN1dlluZFVkWGpra3pyRjUzV3VzY3luWnlDZlFxdWt4UnduQXVVL0RncnVXUEJqQldiakc1MHJOUmNsNTlMbXViZmNpeVhvcTB2cCtlaUVYdU1oTnhZYnB1VEhGZVFtV3EyY0kxVEZLYVNnbGRJNG0xeVZ6SFBPTk5uYnBKRnd1cFoxeFprbEs5dDdFQzI2K2Y4QU5UM1Bra054YTYzK2w0MDVJSHhPQ2xmV0J3SUJWUlhWSWJkQ2JWRnNwRjlyS3ZycHk0bmRmUmNPTlJpcU1iVTVHMksxY3dkZFZUMkNTVnZ6Q2FxTm1rM1ZWNzJXemdlb1d0aEttTjJ6bytCMjdobytTczVXK0IzeVZKZ0V4TUxmdVZ6SSs4WjNTamJmWXJtYlRsVzFIT1FSdXFkcC9YRlBVenJPVU9JdTJWbWtqZFhtRjRqWXQzNnJVRElicXp3NllndCthN1JiZ3pyV0dWNGMxbS9RSzNqbjFGYVRoRlNkTE4vSmJIVFRFMlZFMlVYVWt2Z1ZIaVV0Z1UrK1R3S2p4S1c0TzZnNkpWeVNGejBlTndEVW9EZDV1Vk56cmNGUWFqTWo5SUlCM1c0ZG4yWHBjUXIydklKYmRhakZDWnF4alFMZ3I2QzdOTUxpcEtKa3BBRHROK1V6RXVTcnEzOEowdkwySERES0pnYUxIMFY2MTFyS21vc1NiTTdSZXc5VTlQVWdXc2ZvdFNIQ1BGYWh2Y1BpUUJ0MHBVMURTMXd1RXBOVmtSODlGU3o0aTdXYmxES2JFeFJZeFZudThtc25ZRmFUMmw0QzNIOFBmTTBDN0czVjNVMWVzYU5RMzlWNXN3bHAzd09OdzhXVlhVZGpUME9SN2o0eXpMV3Z3eXVmU3VhUnBTVkU4VGtFRmRXN1p1elR1SlpxMktMVVNmczc5VnhURDZwOUxPNWp3V2FYVzhRc3N5SzVQV1JsdWliaFRTKzcyVjNSMXZlQWJyV0tlb2JPMGVJSDcxYTBUKzd0WXJzMlJLelpvcWd1c0xweUVFbTkxU1J6YUxHNmRocndCeXEwM3dEQjhteFV0WDNJRzZjZGljaitwV3NpczY2aDlWbCtOTmliOFNweWZKZmpHemJxYXRjM2N1UkpzVnQ5cGFPY3pXMjFLRHNkMTc2bEZJUHc3TjRHTjZRb1NZOEFPVnBNbU5nTjVWZFU1aERiMmNsTmpZNGtielBtSUMrNnJac2JNbDd1c3REbnpLMEUzZVBxdGZ4N1BiS09KMm1VWHQwSzdGTnNkc1NSMEhFc3hNaEJ2S0FWcWxibWRra2h0T0Z4akhPMGlvcUpYTlk4bmZ5S3BXNW9xNWQ5WlYyR0t4RXFSM3FUT3RKVE4vV1NOKzhxc3FPMENtMWZxNUcvY1Z3UEZzVnJLd0hTL3dEQlV2NlNyYVc5M0UvSUszN29pdkxVcytsb3UwMkdMNDVBZm1WbDNhbkJJYkI0K3ErYUk2NnJybmMyK1lUVWMxUkc4SFVwN29nWTZqaytpNmpQc1VrZHc4ZlZVVStkZTljUTF5NDg3RjUyUmdYUEN1TXU5L1h5TkdoenIraFU5MFJxWXRTZE13ekc1S3FVQzVOeXVsWlJ3YVRFSll5YnJUc2w1S2xta2pjK0lpOXVRdm9USkdXQlJ0WVMyMnlvd2p5Vk5abXFQRE43eUpoUDZPcG1YMnNQNExlS2Fyc0xYVkxSTjdxSUFGTWx4ak43clZ4cmc4ZG15T2NuWmRzbDN2ZFNsckRhMTFTc3JUNXBsais4dHVyQ0tiaVdUWkwyVGNUOWxXTWR1RTVFN2JsRXp0RXAzY3FqeEFpVmpnVmN6RUVGVkZUSGNGVjVCUWZKenZNVkZkemlBdFZjd3h1MzJYU01YcE5ZZHN0Q3hhSXhTSFlxdTBhV05rSTVkZ242V2JkVTRjZGs1VFBJU3l5elpLYWZZYnF6cFp0d3RkZ2s0M1Z4U3YzQ2xpSm92NFpkZ200NWR1VlZRdjhBQ0U1RTRybGxkb3NZcERkT3h5Ykt0aTJDYVkremVWYUtyRys4QzhKVW9aTitWTU9YUUF6blhRWDhxV3JaUWNRYjdxRDRtTmRsRXZzaGwyNndYWFNoeVJJeVg5RjRHNVF5c01lZ1lhUVZ3dUV2STZ5SStYYmxJVHo3bEF3MGd6NmtFSk9lYTkxRy9WS1ZFbGxRYkh4QlRlTzV1a251dGROQ1M0S1FuZGE2QXR3UUtkNEFWYlBMdVVXb2xLUmtkYzdvYUxjUWNsU1JkSVZGU1hYM1JLbDREU3F1V29BUEtKSXNwRXBDWEU3b0xwaGF5OTd5Q0R1bEpMa28wR2tGZktDZ3VJUGtndXZmbFRhQ1VhUWRFYjZTcEIxOWxNUjZ1Vk50UGJkSFFJTDNmWHVpUkFOSTRSZzdRQ0VzNGFUZExZYUR5YVNPaVhOZ1ZKdS9KV1RGZnFQcWxzTUlPaUl3WFEyOUVhTUtVS0p0YjRnclduSHdxdWFCY2Jxemc2S1VWc2hjVUhSWDlNYkFLZ29WZVV4MkM3Um16SGh3dmRWSUhZTDNWR1VrUlBCUzU1VFJPeUNRRUxDQkVLQmFpT0ZsQnhzRUZCZ3BRTElHbEczSlhpelpkb0ppc3JyWFdzNHhNUXgxbHNWV2JYV3I0cTY0ZGRBeHVQdWFUaWNqM3lIbmxKTWFiYmpvcmVxaURwQ2s1UTFnSVEwYmVMc1VkUU55Z3NqM1Qwc1lKSzlIRUxydTBpbUNiSDZMMDFNN1VOTHVpY01Jc3BSUXZCdWQva2pVU1Nsd1RvcVZta0dRQW4xVzJZRlV0cG0yWXpwMFZKUVVMcWtpNHNCNXF6bXFLZkJtRXVrYUNQNlFURkVwVG16WjZHdWV3M2xjUUw5VlY1bHpqVFVFSjhiYjI4MXpuTlhha3lsWTVzVW05dWk1aGltYTZuSEpENDl2VldFVjU2VTNmSE03dXI1bkNOeHNmSlVyNmtWQTNGN3JXNk9KOFp1NHE2d3Q3WkhBSHo2b0p5TkxUYWFNZVJtS0JoZDhBSzJERGNQYktHL3F4dW9VbEhFN1NWdDJDMGtJRGR2eFZLY3htZk40WENHTUV5NjBnSFNyeVdpZ29JdFQ5TndPcU5IV1I0ZTF0aU9PaFdxNXZ4NTAwSjBPNktuNGpZcFNLTE9HWjN3dWN5bXZiandyUUgwZFJpdGMxN2k2M1c2dWFkL3ZjcDcwRTdLeWdaSFIwN244RUZXY2JzSnlLbkVwVzBWR3lJYzJzVnJNdW0ybzhxeXhPcE5aTzdmWUhxcWljRWt0SEEzV3RqaW1pcFBJMExtUTM1WGliS0pkNmNLQmxUdHBYaGNtU2RJNElUbUhVQ3M2N25kWm1rQUNKUk5DR1BnOUlkTWYzS3VmTTRQVE1rMTIydWdSdzk0KzZQYlEzYzR1ZzBjem4yVExHYWhkQk1BaUd5eDd6bzIzVk9lWTJNT0xieU1rNlZKczNnT3B1cEtkL3I1VEZQTXlPTTZ4ZjVLbzN1WnJ4eWJVTlFPSmE0c2QzWlRHSFk5VjRiVk5JbWM4TklOZ3F2dmpMcUVaMC9OWXAydlpJZFpEaWRoWkdzRmdTelJmQjNYSlh0QlQ0SGlOTkROQTk4RmhxSk8zNzE5UFlOMmowR1pjSnA1YVFzN3dzdTVyVHZ5dno0YUd4VVVqS2dhNUhHN1NPZ1cyWkV6emkrVDVESkhQYUE4TkFON2ZWY1RhSytvNlRGTGRSOStVZU15KzR4anVYQjkrVnNGQmlBcUlMeURSSndMOHI1ZHlwN1NNRTdZVzFicENYT0FOd1F1MVlkbldneGg4RXRQVVJocGFDUVhpL1JPV1ZSUEo2blNjN2RwMHFpcnc0bGt2aUhTNmVmUnh2Z055R3RjQ0xMbjhlYVlIT05uaThmVzZuaDJmRGkrSnVvSXk0Qm92YzhmNDJSKzgrUmlaTkJOOHhWQWNhN0pjSnhiR0dUOXhFL20reDVYTnUwenNqb0tDbGNLYWdqMXZITFFWOUY0WkV5aVlIekVPdnZzVlhZcDduaThwYVdFNkNoY1VGcGV0NWRIcUl3VForV1BhTGwrYkwyWUtpT2FCMGJBTEMvRjdsYVhVVXoyVXNrMWpZTDcwN2V1d1dYT2RRYWlpamFDNlFFNnJjWFhNc3grelMrZ3lsTzkwYk84YUIxSGtWeFFwbnU1ZFFXcGpESlo4bEY3Sm9ISGE0Q3FpQTBYNXV0d3pIazJwd0thcFozVHJBMjJhdFNld3RweHFhUWZVSzNBWm56K0poUy9NVWR1b0d5a1NoeUd3dW1venBSVVR4ZUFrcW1VbTlsbVdVMzJRL2pUb2xESmthQU5OeVZHUTI0VTVCbzRVR2tPNVQwalBsOFROaTcyVFNidFFRMXozYmhTcXFveC82dXlIRFU2K2xsNmMrR294VXdqYmUyNkxIVGpUeVNnVkx5N2dyRWIzanpRaEN0ZkZwT3lEU3YwOHB1ZHBrNVVJb0FBaFlZTjB0endzWHVPRVYwUXV2V2EwSktpV1dJMUROWUlJdmRheGlsQTZrY1hBVzZyYTVudEJWSGpsUUhteGIwWFh3Y1hjcFlxMXpkaTBmZXJyQ28vZWlEKzVWSHV4ZTI3V3EveTFoMDhqeHBZNVZwWkVpekdKZlVsSTZKbTROdlZWT0xtNXNTYkxhL2NKaEZZc0lXcDQzVFNDVzFqeXFPSE1wRnhZM0VSbzNDbnFJbnRjVzZYZzdiZFY5OCt5cDJrQ2JCbVVzWmJPL1UwZU0zUFZmRVdXTXVPeENlSU80TGhlNis5UFpteTlnZVY2V0Y4czhCZVMxMWpkWVhWSEZ4NS9NdFFma2ZSK1ZhREU1cXVTcU5LMHNKMUM0L3VXNFNVRDhUcVNKb214VzM4SVdzVWZhWFE0Zk0yS0pqSE12YTRLZXhidFFvNmFJdmJHME9kdHNmNzE0WnlxUlpXSnlMK0RIblliaU1XSFJPdVhqcWQvOGJxd3h2UDhPWEtkb3FudFlYaXd1dmxqdFM3UzYzRE1jaXI2WXZEV3N2WnYzTG0rYSsyREVzZXA0blNTU2pRTDdrTGp4c2RIRWZXbGIyMFF4dmw5M2xhL3dtMjRYQSswbnR1eEdvbWxnamZzNi9EMXg2bHpkaUZaWnpKWkxIbTFsWXNaK2xIQ2FRWEkyTjFXbmlaZnh4bzJyQk8wVEVXTU9zL3pubTVPejE5Vld2OEFlSFBkWjM5STJXdHh0aDdzQm9BTEFpUllzWEF4RGhvdXFqd095L0dqWUc0bjdzNFhBdXJLREV4VU01dHQwWFBKY1pNOGhiYTFqWlh1RzFaYkVMbm9ueTB6b0Z5TnRpcW1SbnhQSitheE4zVTd3UWZvdGNmVmF6cy9kTVF6U00zTGlxendNVzNadDBFeklJYmFqd3AwOHJaZFIxSGdyVmhYT2NMYWxQOEFTd3BHSFUva1dVV0IySmNUViswYkV0TTVzNGdBZEN1TzVueGhrc1drTzNXL2RvdGMyU0NSNGR2WmNEeFRFSkphcDR1YkFyMTJnMDdVbHdMeVM0SFdUQm92ZmRMVnN3ODBvMll1MlFhMmUyM292YllvVWtZdVoyd1ZTOHVhZDBoSHRLMi9tbUMvVTBwWFVHeXQrYTBzWlJ2azZCZ2t2Nmh2M0s0aGVUZFV1QXNCZ2I5eXVvV1d1a3lQU3AyaUpJN3dxUWZad1FubjlhVk1EY0twSVloa1NiS3d3MlR4TlZXZmhDZXc0K0lLSWN1RGZzSmt1R3JacU4zQzB6Q0p0MnJhS1Nld0c2U2tYMHkxcUgyWVZyV0lWSGlJdVZaVnRhR3huZGFqVzF1cDd0K3FLaDZrT09xTEE3cUVkWGQxcnF0TlJkdktneWNhdVYzYVBVMGIxbHhqWFRzY2Q5K3E2N2dPTUNqZ2FOZHR1THJpR1hhN1FRU1ZzNXpJSW1ob2NwR05GV1dMY2RuaXpleGpoNHdGYnc1MWlqWVBHRDgxOCtQelhwdjQxbWp6WTk3L0FCU0cxMVpUcEZPZWwzSDBSRm05bFM2Mm9XWHFxclpVQzRQMFhEWWM2TnB5RDNpdnNPejAyb3NOYUJ6S2N0QzJkRkpNcnRpZHZWT1VwTE9TVnE5QmpzYjJnNmh1cnloeENPWnc4UVVqS3hFc2J4bHBVNGRIaVVMNDVHTmVIQWp4QzY0WjJtOWhVdWlhb29JbmttN3ZDTGM3cnZMWnhHMFdOMC9UMVVPblJVTUVyVCswbXk1UjNGcWRqUGdLcG9jVnkzVk9pcUlpMW9OcmtsV2xCallJQkx0MTlaNSs3T2NLeHVuZE15Q0tOeEY3N3I1K3hyczdaUVR2RWJ4WWVTenNrTFBSNE5ZcUtWdU9tVUFiZmNtWWF4MXRWL3hWRFhZVExTYXJPT3lxSk1VbHBTUTU1c0ZtK0F6UWpsUnQ5VGpja0pzRXJWNG9YTnZyTzQ4MXB0Um1OZzNjOUlUNXFhUWJPWFZweXlzNk4yWmlRQjNlZnFzeTQyeG01ZVJiMVhOYW5OV205bktrck0yeUc0RGlqOEE0ODZPclZ1ZElLZHAvV0RiMVdyNGwyanNGdzE3ZnF1WlZlTXpUMy9XRkt4TmtuZmNrbEdzWW1Xc1RSdUZibnVhWnhEWGMrUlZGVTE4MVlUZDdqZjFXSWFOdW5jQXBtbmhZMTI5bFlpa2ltOHJteFdDZ0xqZHd2ODB5YVVBY2Znbi9BQTZmQ0FzQ0J6eU5sWlVrZFViRUk2UnVoMjNYeVdZY0xiSnFKYUQ5eXV2Y0FJMHhSMFFBY2dZU2trYTQzQ1dpVWdOdDhnbjZQSmt0YzRkMHd1dXRtd3pBeldWYlFCZTVBWGYrenpzMGhhMko4akd1dlk3b1NTeUpIQThIN0dhL0VwR0EwN3JmSXJ1WFo1MkNOb1k0M3p3a0VlYlYyakRNQW9jUDBqM2Rsd3RnZVkyUkFSTkRCNklTbFBLYXJSNVFnb210RFltalNBTm1xK29hUmxQWWNmY2p1dTdxc05ZUWVVdWpPYmJMV25BdDhSVXFpcUhGMGxIT0dENGt0TE1TU2pRRExDR2E3dVZZeFNiRGRVVk84a3F6aWVSWkdnR1hFVXRySTRxTmh1cStOK3dSV3V1bStRcER6WkM0RktBWEx1dTZQQ2ZDVU5yZHlnWWFLNnRpMWc3Zmd0SXpCUjNjZkNQb3VneXN2ZGE3ak5FSEIyeUJobzV4STNTL2hIaWNMS2VJMDVqZTdwdWxvM1cyVk9pOUZscFJ1MzVWeFJ1M0NvS1Y5aXJlbGt0WlFhYkRBOGFRbklqZFZGUExzRlpRdXUxZEVTUlpOZUxBS2JTVDFTY2JpYkpxTW9vbGNPMFc2b212WkExMlErOXVVODRNT2NvSDVxQWZ1cEIxd2tTN25UT3ZTc0dZWFdKRXVlVjBOREd2VW9QTnJyemVDbDVwZVVxUTZKNlNYMVM3OTBPU1FrckFmdHVsTWFpTWhzbDN1RnQxbWFWS1NTM1FNWkZFWjViWHNxMmFwSkpDTFBMdWQwckxZSk1pM0JBSkgzdmRJMURoZE1UdUFHeXFxcHpybTEwaGwySUNzY0NDTHFvbGkxTzJKVGs1ZFlwSnpqdW5EN0JtSFQxS3c1NUlzc1BrZGRURFJ5alIyd09nazhJckdIeVU5VFFPaXgzd0I0UkVzbHBzaU1PeWk0N0JZYThCR1N6MHFYbmRxT3lQSTY0UUxlTGRBeVdTalpaaWt5SXZQSlVaSFdic3MwczIrNkVsaDlOdWlrMXBQb3BDeXlMZEVxZ0xKTmFRbnFKNUxySlJxZW9vYk9DbEZmSVg5Q05RQ3Y2U1BZS2lvUnBzcjJtZllCU2pNeVBrYkFVL3NyRFFzdU5rOHFrU2drSWpqWXJCL0ZDeUFIQ3lHU04wU1RoQWNnT2s0M2l5RytUZFpqNEtFL2xFeG9sWFBHNjFmSHBXQ01rSG90anhFZUZ4WE5zMjE3NmFDUzVLQ3VSK1B1VmxYanNVTDNOMUM2b01TekN4cmlRNWFUaXVPeW1yZjRqYTZwTVV4MTJuNGsrS05iRytEbzhlUE1rKzBFY1lxem5VdVIwdVluNnZpS2RmbUdRTTJjVVcwVFIxYVBHb1dqeFBScVhPT0YwUnZKVUM0UEJzdUtUNWtudVFIT3NscEpKS3dYNzR0dXB0SlIyakdlMStDS0lzb3pHNDJ0MFhPc1h6ZmllTXlra2tOSit5NHJUWmkra2Rjdjd4TVUyTE9mWWFDMVRhY290NXFFMTB6UytSNU52TW9rbUdHbExDeTVYcUZqNTNOY3dyWUlLVW1LN3hldzZvVXFMSGlJVGpqZEpUTjFDeEhrbUtNc2VkbkVXMjJTZGJKSUg2STJuN2xZWUpsK3FuSU5uV0p1dVNmQXR5TC9EWkhYYUdrbGJYUVZIY3gzZVNDbE1Bd0F3RWQ2UHFuTXdZYklXanVMamZvcVUrUlQ1SVZXS3pCcEFKUDNxa3FJYW11ZDhKSVRFbEhPeTJyVjk2STJvZFRzK0c1WEI2WXJGZ2tzUTFGbHJLa3h1dWRFeHpSMDJXd094Q2FZa05hYkZKUzRONzRUcUhQbW13WEpHYUM2YVdhUWtCUWxMbzczQzNpWExzZE8wbXdXdTRuU3RhWFdBV2pCY0ZPUlFzZHpkQmVmR2lQT2x4SHFvRnQ5MWFvNGtRbWRzbFh6RUEzVGhBY2w1b1FMcVVPalloSk1TVXpTdThLQTZNWFUyVE5qVW9haHRzaEpzcEZtb2NJVEptZWlJWkFSc3Frb203aGtEZkJ2eXZBNlJ2d3ZQY1VHYVd3U1ZGMk9uTkdKYWpTZGpiNUpxaWx2YTVWTEpJUzlPMHNoQUNzUjRHWXBHeVJkMjhpNXVyV2xpakxlZHJMVTZlVjJzRFV0aHBIT0VRTitpekhNOXAwek9zcXI4eDJlRWY2dHhhZWx0bGlnelBqMlc1aEpESks5b054cWtjZ3RjNTVOamNvQXFaWTNGc3NaZVBWSWxrTG1UUitKTzZPMjVEN1dxckZHaUtyY0dHMXRuTHBzZWZHWU0xc3NKYTU5K1R5dmwzQ3hMRTRTeEFzNjdMY2FIT0RZSXRGVDR5QjlwSTN1eWxxK2x4Y2VZbjFSbGZ0bnBjUWFHWWhPMkozQUFQUmRJd210anhPQjA5R2U5YmE5MThFWWJqVHN3NHF4dFBVZTdDOXJCZDJ5WDJ1LzVIZTcwVTdqT0pQQnFKV2pGMzNQbVBVT2xMQ204YVBvTmxhNldkMFVzYmRoZmNYV3ZadHcrU3ZvcFlteERRN3lDZHBjMDBGYmhzZGFIc2E2UTJ0ZjhBeDVwdU9zWkpBWEJnbGFWWml6eTBaNU1VcW80dGkzWVZoV1lLZVUxSUxKSEQ3TE9xK2R1MWoyWUtqQ0k1WjhMaGtsWTNmY0ViQmZkODhNZFF3T2JhSzNJVlppdEhUejRlK0tTTnMrb0VmVldVelNqcTBsOFRQeUp4bkNLakNwcEdWVE83Y3h4YmI1S3BGVTU5MmdBczgxOXRkdGZZSkhpVEtpb3BZMnhsMXpabzgxOGpac3lmVjVhbmtpZkM2d050VmxiZ3pVZzBqVkpqb2RlUHhIMVF5N2JmWXJFTXdoZWRZMUczQ2c5OTdsVzB5dm1rcTRNT2RkWXZaUWM3ZFl1dU15M2sybSs0N1MwOFkyRnR2TlVzY1ROOVA3MDVtUXZkS0JjOEpDQ0lsZzVYcUQ0c2pENENYWHVqU2FXTkhtcFBoOEEzS1JyQTk3aGE2RUk5SzY1MkNnMXltMm9NY1drZ1hzbEJNN1hlMnlGaGhYWEpXTkJJVW1FK1M5SzgyVVZEYkZKb1ZSWW14c2tvQUI0VnpOTVdoMS9KVmRMSjczS1FSMXNrWmVFTmdyRzhPdzVqbzIzSFJkR3lSaHNBc1hNUEIvY3RWd25DdDJuZXk2RGdnOTJpQUFBMldGbXlOT2pSaEFKaTdxZUJwYUJZL05hcy9CVzRyT0FHOVU5bWFwMFZBMG5vaTVQbTc2ckd2elZEVHVVZTVlZFBzYnBrbnM2dXhwRFJlM290OHd2QThWd2VyWjNjckdNSG4vN3FlV3FvUVNNYTIxanN0K3E4TGlyYUxRU1d1ZUFiam5oWkhVczZxdjFEeHdiWVhCYTZzRG9oSk0xL25wTjFzbU9ZMVQwOUV4MHgxT0RyMkJXajRiU1B3QXlGcm5QMWNheXEzRThSbW5ua2RLU0d1RnJYMlhqazkwamR3d1ZjZzg5WnViak5XeWpwaWZFMjF6eDBXblZUWFFORWMzaUR0dGs1TFJHam5MOTNFbTRKVUsxZ01Pczd1QXZ1dG5hcUdiRUN3aGo0WlN5RWhqUU9xdWFiRTNRTk1RUEo1QzFLTEVudWwwYk52MUNzNFhkekFiazNPKzZGNDB6cVNROVBpazhFdG11MmVlaU5EVnpSTjcwdkhpMnNrYVZsMnZlN2NjaTZyNThVN3FxTGI3ZVNEd2tkc3ZHenRqZnEzdWQxY1VsZVh4Z052d3RmcDNlL2FRZHJqb3IrZ3BEUnREZ0xqMVM4a2trSTVMQ25kTHFCSnQ4MWNRVkJsWlpJUXU5OGJ3QWVkbDVra2tNb2JiWlo3bGJDc2RhOGg1M1ZQbVNaOFVMM0J3MkJLYXJKekVBNG15b3NackdWVksrN3VBU3JHT04xd2R0VWNtelJtMlNvam1qY1hiRWpjRmFLMlFUR1I1Ty9LdmMzMThicEpHdHRzU05ndFE3d201QlgwTFNhZEtqSHlaUnVscXIxTG1uaXloWHYzUzhUOUx2SXIwcnJyYjJKSXk4azdNeHU4QitTU21rMHpENXBsdkNVcUI0L3ZUSUNMNU4veTlWWGhhQjZMWktkNWNDdFB5azY4WSthM0NtNnBFajBPT1ZncEcvclNWN1Z1dlZBL1dHeXl3S3BJdlJSTXZzMU40Zko0Z2xiSmlEWWhSQm0zWVM4alR1dGdobnMzbGFyaDB0Z0ZhTXFnT3FXaXp1SE1RcXpwTzYxcXJsOFJJS2RyNndXTzYxcXByOUxqdW1wSGZFb3NIMVdsaHVVb01Scy93Q0w4VlNWK0syYmJVcXVIRTdTQzdrNVJKNHgwbWh4ZnVXWDFXUVo4eE9kTGJXQjk2MDJveDV1Z0FPdHQwVlJQak81T3MvVkVvSFk2bEhRYXZIUzF0eElQcWdqTlJZUUd2OEFvdWJ5NDd6ZDUrcW5obUlndXU1NU8vVmNsRnBGbU9lTE9rUHpCSkt5K3RGb001eTBValFYbmxhTWNSQjJEbEIxWGZxcVUweXhITEJuZmNHejQrVmpmMW5rdHZ3TFBUaE8wR1MyNitaOEp4MTFJNFhjYmVwVzFVV2F0UllRK3g5Q3BHMEsxR25qS1BCOWk0UmpRcjRHdUR3N3J5clJ1SUJ6eDNseUF2bnZJdWZSU3RqYStXL1RjcnNtRTR4RGlzYlhOZHViY0swblo1M0pwbW5hTnVxVDc5Uk9iRWJlSHF1TFo1cHA4TW1sYzQzK1M2M1JWQWJkdXJsYWoyZzRjMldDVjlyN0hvaGNVeG1PNEh6Um1ER0p3SkxPUEpYT3NYeEtxa2M2eFAwWFNNZXBRMmFVVyswZWkxbXF3cHN3UGgvQlViUjZPQ09iMVVWYk02NGNMSVBjeTIzNVc5dndvUnVJMC9nbEg0SzBrN2ZndXBqelI1b0hwVjFHWG5nM0szdVRBZ2VuNElQNkREZDdmZ21XaExacHNXQnkzQnR5ck9td3d4TjhRVzBSVXJXajRSdDZKYXFhV213YVBvdWJVSDRQNWxJOWdac0FWajNZMzJWckRTZDl5UHdUMUZneDFna1hDNDBDNGJSRERzT01wRndyeVBDZ3dmQ3JLbG9PNmI4UDRKeHNaQStFTGdEeTdTbEdGdWMzWkdwY0pkcXRaWDFKUXVlYlc1V3o0TGxSOVJJMTJnMitTUHlLenluc2daU2RVenh1TFBWZlFlQTAzNlBoamFTTmdGcXVWc0xiaHNUUVdBSDVMYTRSZTI1UWxhZVl0M1NNa0lQVkZhODZiQXF2akhxVTFISUFFSlZjMnhuV1FPVkV5dVBWTHVsMzVVUSs1NVhLQ3NaMHZkMUNMcHVBbDJPVXdibzBnR3h1bmFBZVUrMDdLcWlCdjFUOExySXFBc2VobU53RTR4NlRhUnNqTUtOZ29lamtzaWNDNlRhZDB3MTJ1eUJob3h5U3EzRTQ5VFRzcmdOc09FQ29nTWdPeUJoSTVwamxOcEx0aXRmMDJKVzk1aG95UTdaYWRVVTVhVHNrdUpaaklIQzZ4Q3RhZVRoVkVVWkRrL0J0WkEwV1UrQzhwbjNzcmltY05Lb2FWMXJLMWhmdHNoWUVpMmk1Q1phUUFrb1hYQVI5U0tKVkNPZXNYKzVSYTVZY2RYQ2VRSUhMUGVFSVREbzVXWEhVa1M3a0NHUzRXTmFFNTFsNE9RdGpraVpsMGdwSnp5NGxGbGZhNldMN0pVbU9pakR5aHVmWUhmOEFGUmxmc2twWDduZEtiR3BHWlpVdTk5eHl2QitzcU1rZTEwRmo0b1ZtTnlscWs2VzhvczNoSjNTRlc3U0Nib0dXSW9Ubm5JdUVuTFVlYW5MT0wyUzhoMW9LTEVRRlE4RUd5UzVPNFRyNGU1M1B6M1FpOFNiV0gwUkRyQkNBRkNleTJ5Wjd2U2wzeDNQSlJvbGcrN0xqc3BpbDYzVEZQR0FOMUdwWnZzVVJMQXl1c0VBUE55alRNc0ZDSnc0c0VaTElhejhsbVk2Ylc4bGlvWmMzSG4wVXdOaGRBeVdlWTN2RzdyTElkQjJXT0ZOQ1N3b093VWc2eFViMkN5emNvYUJzT3h4MlZwUnVOd3ErSm5DdHFKbGlMaFNpdmtaZFVZdUFybW1ac0ZWVXJoWUsxZ053dTBabVJsZ0NMQlJlb0RoWlRxRUEzR3hXQzY2ODlCUU1oSnh1aHVBc1ZnbFFjZGlob2hCa25LRzZUY3FFcHVkbEh2UXhwWFdoa1dKWWhMc1Z4L3RTeEVVOFR3RDlsZFN4V1crbzM2TGhuYXBYZDVJNFg2S0pjbHVDT1pWVS9mUGU1YTdpTXBjOGduWlhFejdncWt4Qm9OejFWdU1iTGFsUUNCdWszdVBxbSs4OE5ycWtmS2RXeEticFpUYmRNMkUzRHBjM2toUzk0Wkx0RjRUNnBTZVpMdWs3cHdJSlUyRTNENzd0M2tOMUJqWkpYZ1JlYVVtcTliQUZiNWJmR0pXbDUrcW13bTgyakJLYVNpcHc1NFBRcStvNmdWSWMxRGxxMlMwbG1odkFHd1ZYUzF6cWVkM2xkSmFLdmlNMmJENkNFMVhqYmRidGg4c0ZBR2dEeTRYUDZUR2k1NHNBdGlvcWd5Mkx6WklsRnNMeERjMjFEYWh1cG0zelE1TVJaQTBoKzl2SlVKeFQzWm9ERGRBZlhTVmQ3alpJZUpzNzRobkdNZkpkWnQwdFR2a3EyWHZiYnFrNnFxaGl1WkNCWmE3aXVmNkhDMkVObUZ3bWVDenF5bThVK21uSjF2YU52TklZbG1Xbm9HT0lsYmNlVGx4VEhPMXVXVjdtd1BCQjIySzFlWEc2N0VwTG1SNUR2NlJUWVltZzNsNE94WWwyZ3RrYzVvZVNxT2JNelp5ZHpjclRxT25sTWQzbDF5T3FaWkJ2dTRxL0NKV2xrTHFTcDFPdUR6dXA5OGRDVW80N0FYdWZtalNPMGxOb1lwRW81anE4bEovak94dXErcHFyYkJUb3B0dHllZXFtMGNwREJwd1FValZSRmhLWk05MzhwZXZkcWJzcHRHcVNGbzVDRHluSTVpQXFzbnhKNm1kNGQwbmJacFk4bERKcWJjcGFlVU82L2loMWtvc2JLcWRJWE8rSS9WQTRFbm1MRm91VTNGdGJkVjlNYkRsTkY0dU4wRFZGdkJPeTJnWVRJMnkyQ0pyaEFQa3FERHQ1V0ZiSFRONzF6R3J6OHJzOTkwWEZYTDlmOWdkSVg2K3Fzb3FXYXNONUhDdzIzVmwrald4VTRjVzIrNVZGVlhOYmNOZGEyMnlUelo2dDVJWTN5V0RzUkZCSG92ZnBzcUhFc1ZpZVhGd0p1b1N6bVM1SnVxVEVLblNTRTZPTnN5ZGZyb1JqUTNoZU0xR0dWUXFLV1FSaHB2dXRpaXpzYTZvaWZPNHVmRWJncm43bWliaDVGL0pFcDVHVXAzY2Z2V21vSGc4azkvM3p2bEYyelZMS1NHa1pNV3NZOEcyL292b2JzNDdYS1YyQW1Xdm5CMDIyMVc4MThIdzF6SkNDSG5tK3l2V1pocUJCM0VVOGpXRWI2WGtKMFUwWmVmU2FmSkY5clAwR3kzbjdDODExRTBWTThEU2JYTHRsZDE3b2NORmk5c2c0OERnZjNMNHM3TGN5akFxREVKalZTR1Z6TGpVODgzSHF1djhBWlYyazBHS1NodUxWcm1CemJDN3I3MjlTbXBIaXRkb3NpbC9sMmRUeG1HT3ZoZGJkcDZMZ25hZjJTMG1ZSXBTSUxTZVpzdTd6MVZGVHdsME14ZUhlSVg4bFI0dUpjUWhzeUpwYVJ5QXJrVlFxV3RjZUQ4M3UwanN2bnlsVlNPN2t1WURid0MvWDBYT3BHbGpyT0JhZkk3TDlHYzVaQ3A4UW9uZC9DMXhkY1hMQVY4cTlyZll3TUliTlYwVFh1SUJOcldDc1Jzc1lzNnlyazRVNDJQTmxIVmJsTVZHQzF0TVhPbmlMU3pkdnFnTmdscVl3K1J1aS9rcktoWUdhVVkrWnZPUEZycFJ4d2tkWWJHMjNrbThjaFBlamUreXJwTHNZM2xlaVBqYUpQbGNXSU1VbXI0Z2l3dTFnQWhZeEZncHJGb05yWDJRaENzd3U3aExTYkVXSFZNZTh0Y3czRzlrdXlRU1NXc1VEQ0hHQnVnRkx5T0JKQ00xcEREZlpLYVNaRDVKVUpCQ1ZlUXhwU1dGczB5MzlicHpGV2NBRWNxVkZTZDI1cDUrU0hMOTB1WWxadE9GQjFtN0xhcU9xYkZFZFZnYkZVT0RodmRiam9zNG5PNks5bDV2T3VUWHhyZ1VyYW9UVloxbmE1NVZ6bGlQWFdON3Z6NkxUS3lvTTlRTlBLM0hzK2tjeXZicUJPNmRreGVIQ3l0Z3lPVXFPNTVVb25kNnpYNTlWMkdqd0dTb29CTVhhUTBCYzB3WWd1WTZ4YUFiN3JwbEhta1NZZjd2Ryt4SUE1WHp6cW1WcVZmcWVsdzQwMVlDTEJqVU5sdjQ5QzBETXJlN3JYdzIwYWQxMFNpeDRZYjMzZTNkci9aWE9jN1Z6S2l1ZlBHQ05SdCtLenRLdC9MTFc3YndVN0pPOUJFbkk4MG5WTklPL3dwa2p2dExtK1NIVkh2WXU3dHZheTFGSTd1WWsya2hsOFROT3JuWkFxSkQzZ2FPT0VhbHBuMFRpWGNIYlpaZlRYbmFiYmVhWXBXU3pNay9jVTF1cENwSTZSMVZQclBDdDYxb2RvYUNEOTZJMkVVMEFQbnNtbzdaS2xrTFpHQmc0MjJXOTRRV3lVNEVnRjdkVnJ1QVlRSFdlYkhlL0syQnNKWTROYnQwV2JralpLR1hGc0Rqb3Q5eXhIVXRtZURwNFdKbys1YmNtNlhEMnc4RG5kVjQ0N1l0OEVNUnFXeUVNdUIwV201dHJHWWJTU0h2QmV4Q3NNY3EzUXYxdFhMTS80ek5WUXVickEzNnJjMCtuVG9US1ZIT01aeFIxVFZ5NzN1NC92V2FkcE1WL1JWVGdYMUI2bTZ2NmFJQ24rNWU5MDZTbzg5T1JYbHhiSlpHZWVFT1J2NjByTCtpdVNLVXBFMjdoTFZJOFgzcHFQNFV2VWNsZGdjVE5weWsvd2ZldDFvemU2MFRLVC9EYjFXOFVPMTFYa2IyRjJTcUIrc0tpeEVuSGlLR3psVkpHdkRzRVRFSElTNlloNktJNjN5WGxJNnpRbUhURUt2cDViQUticHQrVUVSalpDdm5PazdyVnErcUExRzZ2NjkvZ2Q4bHBlSVNraCsvVldvb1JLVkZmVzE5MzJ1bERXNkFUZEkxVGozcDNTVlZLV05PNnNKRmR6RzVjVmNTUnFTMGxlNGpsVlVsVFluZEROVGZxbXBDMDZHcWl0ZnEyS05SNGkrTVh1VlVTUzZqeWlkOEEzWkU0V2dsa2FOanA4WmM1OWlWY3cxNGUwTFNzUHZMTVBtdHZvNkJ6b3diS3JMR01XZHJ6TGVOd2VXMktzNmVidWdOMVRSUnVpSTVUZXJVemtYVlBiUnM0dFQ0bkROeXdYR1hNTGJQdFpkU3lkbjU5TEl4am5tM3pYQXFTcGRBZVZkWWJqRG1TTmRxdFpkWEJhbkNNbzJmWm1XOHdOclkyeWErbDB4bU9vRlpUeUM5OWl1QVpNN1FYUWxzUmtzT0YwNkxNVGFxQW52QWJqelJXWVdkN0h3Y256YlNPaWxsSS9hSldwTmxkY2doZEx6VlR0bjFIbSs2MGlURHcxeHNGVjhNMUk1aWlxQVhPNFJZNlVPQ3NIMEp1ZkNVT0tKK3F3YVVheGhQTzZCc3d2dkJzaU55NjZUb3IzQzZOMGhBTFN0dXcvQXpJMEhTVVhobGFXbzVPYVM1VmREdVFvc3lxSnVXaGRuaHlvYSt3MEh5M1RmOEFtOGRBM1ZvQ1ZiQ2pyMitEaE11VWpDYnRiMVRETUdkRUI0ZUYxMnJ5dVdFalFVcEZsa1N1c1dGRjNIK1B2UnpBVWJnZmhUMU5obmVFWGF1bERJN1hpL2RvME9TKzZJT2poZDJpSmNtc1lQbHpXOWhMZGwwRENNS2pwSTJrdEhDYncvQjJ3QnZoSXNySjFLYmJCQ3luS1pGb0IrRVcrU2RweTRXUWFlRFQwVE1aRGVpRVRkc2FEalplRDNLQWt1alIrSUlSOFkyWkRpVVJpd3lQMFJnd2djSXFCTWdvOFlTMitwT0FXYUVhQVlhSUFJN1NsV09LWmozQ0lHeDFyK0V4RzVJc080VFVSS2pJaHhwMlI0SkEwN3BabTZrNWhid2dZYUc1YWtEaFJqcVFlVUdPQXlJcHBOTyt5QmhJck1XcEJLeHhzdExyNk1NZVJaZENuYUhSa0xVc1ZoSWtPeHNvMEhGOG1zT2cwNzJVbWVFcHVvWUFFcHdreVJjaXgybWtzVmFRU2NLamhmdXJPbmZ3a3M2eThnbDJDWTEzVmRBL2pkT01kZnFqaVZCbGpyTE1aM1E0emNLVHpvNFR5SHBuV1VXU1d2ZFIxYTBON3RQQ1JMdVFJK1ZSRXFDOTNxaGwreVd5d2ljMDIvS1hkTFpEbWZ2eWh2azI1U1pEa1prbHYxUzduWFVYdjNVTld4U214eVJoeEVlNlZucmRPeXpMTnFGcnBHWmw5N3BaYVNJUzFXb3BPZWZ2TmtSN0xYUzByZElObEJxUUIwTnlneUR1OS9KRmZQcFNkUlVhZ1VWREVZZlVlOGJmY2dGbmRtNkRIZUp4UHFtMmZyUWhHV1FFbXBRZEdUd2pHRFJ1cGpoR2lXQWFDQW95QWxHZTZ4V05RSUtJbGl4OGV5d0lMYm96V2FTc1BmdFpHU3hXVWtHeThMcVpacjNVYklHU3pDbW8yVWtKTEpYUlloY29EVGNwcW5HNmdOajBETGdLMXAyOEt2Z3NBckNsTjNEZFFyNUN6cDNXc3JhbGsyVlZDMU9RdjBxR1pOOGxtSkF2R1VGS0NYMVdUSW5pdzdwRUp6OWtGMHU2ZzZYMVFzZ1IwaUU2VUFGQmZMNm9ENWRpZ0lFYkplL3pTTlRVV0pGMU1TMmFkK3FyNVg2cERjcnRCdzVFY1VxdEVVaEoreVY4ODlvbUxObHFwRzM4d3U1Wm9tN3FtbTN0NFQrNWZMbWM2dDBsZkw0Z2ZFNzk2WkJjbDZJaFVWSTBiRlUxWE9YSWt0UmFJYjcyVlpKVlhWNkNPdVJNTnVVZUk2QWxZMzZpaVBrMGhPb1Z2Q3l2dWs2aVlqbFpkUHp1bEpaZTlCM1VvbThLYW9GdGdkMU9qckpvNVc2U2JYNktwY0hNZjZLMXcrZG9MYjNLbTBtODZsbDZRMUZNM1VmSlduNk9ZOXhOd3ROd1hGekJFTnlGZVUyTzY3K0w4VlVhRnMyakRNT2lEdHlMaFdycWlLQWJ2RFFGb3B6SzZDUTJmWmEzbWZPOHNjTGhHODNzcEdGaW5LanFWZG1yRDZLTWw4MFpJSFVybm1ZKzF5S2prYzJuQWNQNkpYRmNZekJpT0l6dS9XalRmcWtJaVdtOC9pUG9yc01Db1U4aHYyTTlwOVRWc2NHNm0zOVZxRW1JVm1Lemt1bWRZbnFsbnNqa0hoRnZtaE5xMzBiN2hXSGhVZXdwWlRic0t3UmptaDBoRGo2cStnZ2lwcmVBYkxVTU56THNBNGxiSlFZckRXQUF1SDNsVlpZNlk5WkdYRGE1bW5TQUFoU1ZBYWIzU00rbG03U04vVklWRlM2OXJycVZDM05tMFUrSUFXR3lOTk9ITnV0VnA2czZ4Y3E0WlVhb2h2MFIwV0ZObVpTWGxFam0wQkxOa0JKdVZndnNlZnhVb2Fwc1lOUjR1Vm1Xb0RtcE9SMjF3VXMrb0l2dXBRMVRIQThFbzdKUXh2S3FXVkJ1dlRWWmFPVUtpYU1aY0RsVlVnZzdxdWpKMUg1cE9XdEpkeW1JNXhzbzRpWno1TEtKNUFHNk8wdWNSODFXQ3JGd3JHa21EclhWS2ZjMHROSmwvaFRpWHRCVzBVQjdxUnJpZGxxTkpPSXBtZVN0NnZGQkRBMGgyOXZOWkU4WjlGNmZxZGtUYk1YeHhrZEdXZ2p5V28wODdwNUhFdTJKVkJXWTYrb3NMN1hSV1lyM0RSWXBNY2ZKVzFPdmx2cXk5cXFnUXM1VkhVVkxaeWQwdlU0bWFrV3VxeVNZc0pOMXA0OFNvd2RacXBTVjJQZDUzVi9FbEtxWnorSEphV3BjOGNvSmxJNnE1c1JqNXRadlZSR29hMThKRjNLK29jWWF5S3hOejVyVDVudWRleFdJcXd3VWozT1BpQjJSS0JTak9mZHMzK2d6QlBSdG1Ja2RvZU9FNmNZcnFuRGcraXEzMDBqYnVHam5aYzlvY2JNekhOYzd3MjZwNkhHS2lFQnROSUdqMVhkaHpKcW93NGtkbDdFdmFIck1BcnZkTXh2Zk9CSllHY2o0UWZSZlZJekkzTStHUTF1R3V0R1c2eTJOZm5SanNOUGlKYlUxVnBKV2kxd1Z2dVJQYWVueUpCSGgvZVNOcHJhTEJydUZjMmVoNVRXNEZEayt4NnZGaFUwWWhtSGR2QjNMbHo3TnRQVFBrc1d0cTJrYnM4MVc1YzdUYUh0Qnc1czFMTTBTdXVTSE8zdGE2dXNDd1dveHl1YTJtcHBYRzl0UVlTRTJFZVRQeFp0bDhuRHUwUHN4a3h1TnZ1Vk9ZSnBQZ2phTjNIeUMrZ2ZZbTloOGgwZVljM3hDb2duaUxQY0twcDhCMG5mWWV2bjBYMHAyTit6bkJJWThVelJDMmQwZjZ5azBrQXNQcno2cjZKcG9oVEh1WXhhQWNCYWNNZnFZbXY2cEtMK0ZuNEZZdkdJWkJmZmJxcWlvcUd1QUd5czhjWkk5NHNEd3FaOEJZV2tyVVI1V1NEcytBYmRWWVBZMlNtTndDZlVKRHZHdGlVS09xZEpHNEhpNjVJRkZkS3pUTTd5VEZJR2x4TmhzUEpaZlRtUjdpRm1DRXNlVlRtaXpFbktQZUluV0ZyYmJKYWppTG5QWVFuWE9iQkVSNTdvRVJFZXVRZk5jeG83TXFNWHc0eFNsMXp5bThKQmNXZ2hDcUtrMXRScHNyckQ2UnNSYWRsVjFMTHVuUmFVYmREYjJ0c2xjV3JneHJoc3JJYVd4ZmN0ZXhVZDQ4MldTdTVlbVZOSk1YVk80RzVYV3V6bWtaSlZ4bHdIUGt1V1V0UDhBNlUwV1haK3ozRG5hbzNEWmM2akw0RG1rWEozSDNHbkdHdHNkSjlBZzRMU3NiSVRKSTRDL21ndWprRkUzeG5aQXBaVEpjYTlCdlplQXlxNUhwSUxoRjFpT0lSMHpMUm5YODFxV0kxUHZqL0dBTitpOWlWUzZGL3g5NGxJeWFteEkwcFZVWGNTQ2hnamFnZ0I3OWxPcWY0Tmt2U0VtUThwZ1l6UEVBemRBakRXVTc5WE4wNVVSbDFoNWxLWTVTdnBvTHQ2aSt5aWZJRE5mN2srOXVkY2tYVGtsU0hFTjlVQ25hNXpIa2pleXJKS29zcTlQcXJjZXdKdldYc1JGRTVyWEhrMzNXMUZqYWxnbEI5ZGxwZUhVd3FReDRkYllMWVlxNFFSZDFxM3RaVUlncFVOU1NzY0MzVnVFbEpOWUVGUjBtNWZxMlNGZldOTHJOSVN2RGNwQTVKVWl0eDJWc1VMM0U5RndUdEJ4clhVT1l3OWVuelhXczRZZ1k2Si9pNkw1L3dBYm45N3JYWE45MTdYcG1Pb3F6Rnl6NVBZZXd1ZUNkN3JZQ05NSDNLdHcybitIWldrb3RIWmJVQ3ROY0ZTN2FRcnhjU3N6ZUY2OXRkWDQ5aWpJeTF4c2dUT04wMDBDeURNMGJvZ1VYdVdIV2UzNXJmcVg0QjhsenZMRDd5ajVyb0ZJL3dBQVNaZGpZMHZjWmw0UUdjb3NpRXpsVXBHMzVJbjFURVhSTDlVeEh3Z1EyQS9FZkNGNis2aEE3WlNKUklLWFlWcjNlQnkwbkVXRXVmenl0dnhHU3dJV3AxeHVYS3pBcHpOZm5qM0tyS3NIZFhrOFpOOWxVVmtaM1ZtTEtja2ExWGt0Y1V1eDltOHByRTJXSlZlSFdCVm9xQk84OFhLYmFROXQxV1hSS2FaMmczODFBVFpNQ2thYWdOOVYxREM2UnJvVzdmZ3VNWU5VdVpYTjMyMUx0bVhweE5Tc1VCc2NmaERYc0pBMytTbzZ2RC9kNUNia0JicEV3YU9WUll2U21SeHNxRW9tbmluVEtCMVV5S3d1cG5FQ0xXTnZrbEsyaGtZYjdwSDNpenJFY0pEaWFrY25CdFdINCthZHpUcXQ5NjM3TG1kckJvZEtUOHl1UDMxTkJCVGxCV1BnSXM0bzFFVkthWjNtYkgyVjdRQTRFMlFvWVM5MTdYQlhNY0d4OThVZzF1SkhxdWs1ZnhtR3FhMEVpNnJTaVdZU1JkMCtHQ1Zud2pqeVM3Y0pNVWh1d2ZSYk5oOERaV0F0SXNySVlVMlp3c0FsSk5NYkxsQ1dYTXYrOXVIZytnWFNNTHlqM2JHM1orQ1F5MWgvdXJoNFYwR2lCY3dXYXJFWlVadVRHMkxVR1hXeGdlQUQ3azFVNFVBeTJrZlJXQWVZd05rdFZWWkRUc2piS2tXYXpWNFFDNCtBZlJJakJBeDE5QStpdDZ1djBrN0t0ZGk0Sk95VzJpM0ZzbXlnREJiUVBvaWU2dHQ4QStpREhpR3ZvbW81cmk5a3B5STJ3RDZhdytFRDdrQjBSSDJVKzZZRWNJRDNYNkpaRkVXREQ1ZmdwUGl2MFJiSHlVMitMb29FdUFkUEZ1bkJEdHNGR05tbm9tV2IyMlhRMU9qREw3YkJIWTNVT0VUUTNUMFVtTTNUaXRaQVVnZHZaVEZNUW1HTUtucUJDNlN4Y1I2ZWltSDJSQzI2d1lWQ1dTaG1EWEoxa2djTmxWNkNIYko2a0J0dW93VU50azBsRTc5dzZCTFNiRWZOSGRLM1NOdWlXeGlETXFuVzRDakxWUEtDMlVlU2krVWVTQmhvSVo3SGRJWW5HSm9qWURqeVRFZzZxRGlITUlLNndrelRhaUFzZWJwVjdkMWM0ckRwY1NGVnVha3lMTVFiQW5ZT256U2pXcHVIaEtaWVJZTWZaTVJQUG1rV0hkTXNPeVlWcUg0NUxkVko3a2tKTFdSWkpiaEN5VVQ3eTNWU2E2L0tUTHQxTnN0bWxBU2dqbWc5U2w1SS9Vb1luTnlveVQ3SlRaYVNJUGFHMzNTd2VYRTdxTXN4MUx4T2dYU0pEb29tNXZodWxKcHROeGRabHFyQ3lTbGZyTjByekhJekliYnBTV1czVkVtbDJWYkxLUzdsZEdvTTU5d2QwczExaWIrYXkyUlJKQ2d4QWFtVVdLcTVYWGNucWh0MHNJTlJVRFJHTWFySnFPUFpSRVdoRmpkMFJIRHgyVVhKa1JCd0tYSTNzb1FFOFhReTBvK2xZTEZDQWdmTlljeTZsYmRSYyt3VURCUGhVYlc2S1RwbGt0dW9RRVhEeVVTOEtUMm9SYnVvUUt4NHVtNFRkSnRaWk1RdXNVSjFzc28yRTJWakF3dHR5cTJHWFlLd1pOc0ZDck5scFR2c0UyeVM2cTRYbFBSOGJxRlNROEhBMldISFpLaWY1TERwOXVVZGxDZ3puSlNXZm5kZWRPbFpuRGZkRWM3RXpVZXFCSlU3OG9MbjI2cGFhUkVqbGpFa2dhZVVqTEpaNE4wdlZWbWw0RjBwUFY2V1h2MFRMSmp6Y211OW9XTHRnb3BScXNiRmZMbVBWL2VWTXhMcitJL3ZYYXUxSEZUM1VnRHVxK2ZNVmwxU3ZOK3BUb0syYUNtcElnK2N1SEtYN3dFMkoyUURNQTA3cFoxVFlyUmhIZ3J6aW1XVHFsbEp2R2RYWGRlR0lDb0ZuK0g1S3Q5LzduNG9kU2kvRUlwUjhJaktpeE1ROGlROU5JeUw0SFgrYVdrbS9Wa3NOeWtKWmdMMmZxSG9rM1ZKN3QxbjIzVEZoWWlXWkx6SDIxTS9pdXdXODFZNE5WTUV2NncyUGt0V3AzVk03eUdhbi9KYkpndVg4VW5mZGxGSysvRmdtTEF4TDFFZlUyMFZwa1lBQUFQUlppcUd4dXU2UWo3MUdoeU5taWNEUmhOU2IrUUg1cDZMc3R6bE8vd1lGV1BIbzBmbWtyVHNCOVFqNmxmVzRuR09IbFUrSnpDcFphOTlsdjBIWW5uU1pvSnkxV08vOUkvTk1mNWc4OG0zL3dDVjYzK3FQelQ0NmRpWmErUHFjTnJNUE9za1hDVUxURWJIOFYzMTNzOVoya2IvQVBwYXQvcWo4MVhWZnMzWjRkY2pLOWIvQUZSK2Fjc0RFZS94dnVjWUxJd0I0aWxabnhEa3JyY25zNDU5SklHVjY3K3FQelNjL3MxWi9kLysySy8rcVB6VFhpZEM5VHE0dnN6a3o2bU5uRHJJK0ZWTDNUaHZlT0Z6MEs2TS93Qm1YdEF2Zi9KZXYvcWo4MGVtOW1ydEFaSzE0eXhYaTM5RWZta1N3T3FvdmFIV3dqM2ZvSU93ekVKYUJrMVBHWkF4dHlTU3FLUEdwWDFUbzZsb2pJSFJkNHl2MllaM29NSXE2ZWJLTmJJZEZnUzBlWTlWelRHdXdQdEN4UEVwSklNcVloR0Q1Tkg1cXY3cy9RdjZuWHc4bWF0RGlBYy9aM1ZXY0dKNlFOMVlVdnM3ZHBEVHZsZkVmNnJmelRvOW4vdEdaYi84cjRoL1ZINXAzdTdNMWRSajZsWUsweWJoWjk3YiswdG1vZXdUdENBOFdWOFEvcWo4MDRld1RQdy8vYTlmL1ZINXJ2dTdIeDZqSDFOUDk3WVI4U1ducVdjM1c4anNFejkvL3E5Zi9WSDVvY3ZZRG41MS93RDhyMS85VWZtcDd1eHk2bEgxTkhHSVIrWVFaNnhqaHNWdkE5bjNQdjhBL3JGZC9WSDVyeDluN1Axdi93QkwxMzlVZm1qOEJoeTZuR3U1emFXUnBkZTZaWlZOQUhpVytPOW52UHAvL2E5ZC9WSDVySC93K1orQi93RDB2WGYxUithVExBd0k5VGpmYzAyS3NZT1NuWXE1Z3R1dHBiN1ArZlIvKzE2NytxUHpURE93TFBvLy9iRmQvVkg1cEQwNzlEVXhkWGdsM1JRc3haZ2FQRWxxckZnNGZHZnF0c0hZUG4xdi93QzJLNytxUHpVSGRndWZIZjhBN1lydjZvL05KOXdsNkdpK3V3L0V2cWFVSzluN1c2d2E1NDNQQzNNOWdXZkFOc3NWMzlVZm1nZi9BQS9kb2Q5OHMxOXYrRWZtaldnZm9VNTlhZy80a2FjL0ZRM2syUVhZeEYxZXR2cXV3ZlAwTGJ1eXRYbi9BTkkvTlVkVjJRNTVnZFk1VHJ2Nm8vTk1XaGtVNWRXaS9QOEFjcXYwclR1MkQ5MWgxVUhidGRkV24rYXpPRFJ0bGlydi93QUkvTlkvelY1M2ZzekxOYjl6UithSmFka2ZWSWVwVHVxNUdrMkFzcStwcTNTT3R3UFJiWkgyTDlvRTdnQmxxdjNOdmhINXJaTU85bHpQMkl1WnJ3R3VpRHQ3bG9UNDZkbE9mVkkrcHkxMVVJWS9pSU5sS2d4aDJxMTc3TDZPeTU3QnVhOGVjd1ZCcUtRSDl0bzIvQmRzeVYvSmFWVll5T1NwekNJZXBEbW4rd25MQS9Rb3k2bkgxUGhGODVlMDZIbDkraEsyakxYWXRtRHRIYjNlR1VKbWVSOWtHLzRCZnFmMlpld0psZkplajlKeVVtTDJJSkR3N2Y4QUFMdnVYZXh2S0dWSTcwR0Mwc0RnT1dhdnpUbzRXVU5SMVpTVkg1eit6SjdCT1pzT3hHS3F4Nk90cEl0TzREbjI0OHRsK2hHUSt5SEM4aTBzVFdRTW1jMEM1bGpCTi92VzkwclkyRHU0WXhFQjVLWGNQWWJ1ZnJIa3JjSVVlYnk2bnhId0RkQ1p3MW9ZSTQyOEJnc0VVdGJDeXpQRWZWZWZQcWJvYTJ4V1lJKzUzZWRYelZ4RlhidVB3V3hHRmpuajVlYTF6Rm85RnRJVnppaExaaHVlRWpWRU9pRnhmWlYwdzNFcG9Zakl5eFRJZ0VFSkk1OUY0anc3QlNaTHRZb3hWQzFOT1RJNEVGTU9JMWtxTWhCT3dBV0dHeHVxOGtPaVlucHU5akoyQ3JudkxHdVlma242eXFQVGJib3FpdXFnV1dReDdIRzdNVWNiV1Q2aVI5VmVReVhjMEEvaXRld3lMdm5YdVZiMDBHbXBidVZuYWhtbHAwYkFBZTR1U09GUzFRdklkN3F6clJhbWFBVHdxcU9HNHVTU3M2UGNzNU9DVkt4aHJZd09WM25JRkdSVHhHMXR1cTRYZ0ZEMzJOUWtFbmZoZlNtWEtjdzRkVDZXaStueVZIWHp1Slowa2VUYXBJM2R3QnFGdm1xbXF3K1ZyU1luQWRlVVN1cVpHVXd0MEtwWk1la0pMZGw0NmZNajBNVlNNT1k1a3Y2N3hiOUVhUU5MQ1k5dm1oUnltcTNJV1pEM1d4U21pM2pGZSsxa2czNVJxWForeWdXYWp3bmFTRzNSUnNPZzd5Tk9xeDIzU2N0Y01TYVdrRTIyVm80RFE0VzZLdnBJTzdMckRyNUtKOGd0RmROVHRoaWYwdUZyYjZQdmFvbGJKaTBENVR0Y0QwU0VOQ0dFRnhOMWFneGRGcGdqbnd4Z0VyMVZPL3Y3NnRycGVXclpTdEFEcmJKVjljSDdncGJ4dEMzS2k1a3hZdGkwNmxVVmM3b21sNVBxa1pabnpQR256V01lcnZkNk0zc05oKzVYdE5nM3NvWlpuTzg5NXBMV3VqMUh5WE1vQ2F5bzFLMnpoWCs4VmpnRGZ4S3V3eU1rdDJYc05OaldPSmpaSld6WmNOakFhTG85U3N4VXBFYlR2d0VLb2pMZk5NaU9rdUN1cWdiN0lRWWRrNlhBQTNGMG0rY2tuWUJYbzlpakpCbzJiY3FFMGZoS3hGSVhGSGNOaWpCU0dNc20wMisyNjZGUjdzYjhsemZDcGYxNHR0dXVpWVU0bW5COUVtWFkxZEwzSG5jZmVoczVYaklRNVQ2QlVwRzM1STkxVEVmQ1g2b3pFQ0d3SElDcFBOaHlnNnJBS0wzN0pxUjFpT0p1TzlpdGRxV0UzVi9WdUJCNnFta1BQelRVVjVJcm4wNElLcksybDJPeXR6dTVEcVk3c095ZW1WNVJOQXhlT3hLcFhOc0N0cXhlbUlEdGxya2tYaUt1bEJvVkhPNkdYNkRZSWs4WkhDRzdaUVN4cWpsN3VScnIyTjExakpPSjk1QzBGM1QrQzQ1cU53UXRqeTltRTBEbWpWYjcxQlRaM1NpcTNTdTAzNnJZcURML0FPa0Jld04xelRCczFzbkxOMjlGMkxJbUlOcVhONE4wbVNMRUpVeW14VElwRFQ0Rm8yUFpLZlI2bk5qOWRsOU9WbUd0bnA3NkI5RnE5WmdiS3lON1hSZzcyK0ZWSmNNdlJ5T2o1bmRDNm1KYTRXdDVvUnFORGwwbk4rUkNKSFBZMGplK3dzdEJxc0ZmU090WTdlYTZtSHVzYW9pWmlMR3kyZkNhNTlDNXBEbHFFTHpIYm9ub2NRMDIzUzZzc1F5SFo4QXp0M1RHdGM0cmRjTHpoR1hOdTVmTzlOaXhiYnhXV3c0Zm1GejNOQWVmcWdjQzVHZG4wM2hXYW9TR25WK0syMmd6akJHMFhlUHF2bWJETXhPallMeUhqelZrN05qZ05wVDlVcW1nblRQbzUrZDRYYmF4OVV2Tm1xS1JwOGY0cjUvcDgwU0U3eUg2bzhtY0hSaTNlSDZyckZSMDZPdFlqbUNNazJkK0tybVlxd240aDlWekVabGZVRytyOFVDcHpTK0FmRitLVkl0eDA2T3d3NHZFMjNqSDFUYmNmakZocUgxWEIyNXltZSt3ZCtLdEtYTTBqbTd2L0ZLWng2ZEhhMjR4RzRmR1BxanhZakc3N1ErcTRvek5Mb3pmdkQ5VllVdWNyRWVQOFVRRHhuWjJWY1JIUDRvbE93T043ajZybDlMbTRPQThmNHE2cDg0YUFQRUZCRW9IUSs3QUEzUklvN3JSNE02QnhBMUJYTkZtaHJ3TndvSWNXYksySW96RzZRcXFERzJTa0M0VnJUenNrYnltV0RzSm1mVHNzRDk2ekl5L0FXTkxyY0tXQTQwVEd3VXRXeFdHa2pvcEc1NktXQlJHTnVwM0hWTVgwQlFFd0hRTEJtQlRHZFFRU2FsanZybmhRNVVvM1dTMkdnckhBcUVqd0NvU3lnSVFuQ0JqRU10azFOUXIrSW9EYWtNZHVqdHFHU0RvdXNpRksrbUQya3JYcG1FRTdIbGJYSTF1azdxZ3JIaTd0aDlFbVErTEswQ3hUTVd4UUErN2t3eDRTbVdVeG1JYmhOTkFBU0xKUXN1bDNSV0xvYko1WGhKYzJRWW4rYXpLYmJoQTJTZ3pyZWFHNTVHMTBCc20vS0lYWFFXZG93NTFrQ1NSRmRMc2xacFVteTBrUWVRVGREa2xKRmxCMHFIUEk3VHdoWTVJaEtPdDB1OSttNlhtbmZxVVJPNGczQ0NoeVFDU1lrbmRMdTNQS25JelNTVXUrWXRVb2RRVGdGQWJOYzJ1cysrSGl3M1VPNkxOL1BkU2poSjNpWG0yQzhIMzJVd1BJS1Vkc2l3OTRiV1RMS2NXdXN4Z2VTeklkdkpRNVo0blFMSUphQ3NrM0hWQWF4d085MUNXU2NMQkRjVWM3TjNRSGdLRXNGcVdITXVzM0YxNHZBVURzQTZGUk1oUlhTamRBZElIRlFsbmkrNnhkUTBrbFMwMlVKWmt5RlRoTjNJWkNKQTI3bEtPT1JhVTdMZ0ZPUk44UVNsT0xOUkd5YVhLVVZKeUxXRVdDT0o5SVZkRFZBRGxUZFZDNmxGUnlHeE1WaDB4ODBvNm8yUXpWRHpScUloc2FkTjVGS1RWbHVxV21yTnp1cStwcm1HNWViRk5VR1ZwVG9lZlZtM0tTbXJ1ZDFYeVlvNnhhMEF0ODFSNGhpVXNaSlp1bkxIWlhlVkZwV1loYVRsVkdLWTEzY1JzN29xU3Z4MWpYV2tmcEtvc2R4ZHNkRzU4YjlXMTkwY2NFbVRjbytacUhhSGpuZkZ3MWRWeUxGYXc2bmJxOHpQamt0ZFZ1WnRjbllLenloMkU1MDdUSjJEQjhNZFU2allhYi93QzBzV25ZcWVzVVBNNTRhZ2tMTUVNMVFmMWNiNUQwMHRKWDJmMmQveWNtYXNaTVgrVWVHMUZGRWVYTUR2N2w5UTVFL2s0OGxaV2lobW1xNm1TWnB2cGxqdVB4Y3RLR0JvejhuVksvd0RrL0tYQzhvNWd4WjRqWmh0WTRPT3hGTzgvd1hUY28reURuTE96MmR4VG1EVi81MFpiKzhoZnNsbEhzWXkzbGlGalc0VlJTYUFBREpTc0pOdm1Gc293L0Q2SjRGUGh0SEVCK3hBMXY3Z3JLd0dYTHFEL0FPTS9MakxYOG1KblNwaFpKUE5SNlR5QzVvLytwZGF5aC9KbDRiVDZmMHpTd1REYlZvZXorOWZmd2xqTVZnMXJQUm9zZzZyY1hUNDRVVTU2NmZrejVueTEvSjlkazJGc0JxY0RjNlVEbHIyYy93QlZiclEreUoyYVlXNXZ1dUR1WnAzSGliL1pYWXJyS2VzU0s3MXNyNy9VMFdpN0ZNbTRlMENQRDNEVHNOeCtTdUtUSStYYU1nUlVqaGIxSDVMWWJMMWg1QkI0S0o0c241aXJNR3c2RnJlN2lJc2Y4ZEUvM2RNR2l6VHdoV1dVYXhJQjVaZW9WaHAyL1pLdzU5TWZzRkNzdkViSS9EaUQ0a3ZVSUlLVS9ZSzg2Q2wvWktHRmxjOE5BVHp0a3ZkNlUvWUtIUFN3UXhtemRsSUxKM0E2cnF4STdqMUVvZ1cwVkxHMEZ6Q2Rma3BSMDFIQklReU1oRTU2TDIza2k4R0oyZXFrL01sM2RNUHNGWTkzcDVEOEpXTGp5WHRRWFBDUkZrbDZoRzAwRFBzckQ0cVhxd3FPcjVyRnd1ZUVnbGxsNmtteFV2N0JXWFFVMzdKVUxqeVhpVjN3a0Y0MHZVeDNkS0Q4QlVneWtKK0FyRng1TDF4NUxuaG82ODB2VW4zRklmc0ZEZEhTRDdCV2JoWnNEMFFQRWhYalRYbVE3cWtQK3JLa0lxUS9ZS3pZZVN4WVdRK0NnbHFKK3A1OVBTQWZBVjVsTlNIN0JYcmhlQkNZb1JGKzlUOVRENEtVSFpoUkd3UmJYR3loY2VTOXFYZHNVZDk0bXowK0gwY3dzOWhLcXFuS1dFVkpPcUFtL3FQeVZycUM5Y0xtMklheno5VFd6MmM1Y3ZmM1IxL21QeVJZc2g0QkNmRFRPSDNqOGxzQUFzc1czNFErQ2hqMUUvVVFoeTFoRUZpeUFpMjQvd0FXVmxFYVpvRFd0TmhzRkZlQUhraldKSVM4MG41a3BHTmQ4R3lFNzNob3MxNDArU24xWGtmaG9VNXlZTnJZb25BUGFYUE85d2pTWHMyeDhQa29rQThoZS9jaDhOSFhqa1NjMGxsNGpwZDZyTVJrakg2MXdkOGxBYkx3M3N1YmFGYlhFSUdNZTY3UlkrcWxJQzhXSlVPRkljSWJIUm5SK0IyT00weWkza3EyWmhNWVZ6ampiekMza2tqR0RHUGtxMFdXcElwM01zMUFEU0NuNnBtbHV5UWViRk9LNzdrMnQxS2ZkMkNoRTVUa2tTcEJJV25qRGgwVkhpRU8reXU2NjhiTGhVanB1OGxJS1g1QXJ1U3dvT2lWbFRURjFRMURwbU5heFNnR2ljRlpPcFpzNmZzWGRTUzZGdnlWYklYUnRUcG4xTllMRlprcHhKR051U3FtTkJaZTViNUV3NzNpdmplVGZmOEFpdm9YQ1FJcU9KdmtGeWZzeXdCN2kxOXZ0THNOUFNkMUVBZWdXSHJKY00xTkt1VUNyNmtHUFRwVlRGU1JTdnZ0eXJPcFkwbHdzU3EybmdleVEvTmViZkxONUxnYWJFeUJ1MWt2TEVaamNKdnVTNXU2aHI3bTRRU0hZMEFoanViZmNyQ0pnWUFscWY0citxUEk2d1NXTkpQa3ViS0RiUmdrb1d2ZmNvNFozN2JMcUFZblBLeDVPd1ZMaU9wcDhOd0xxOGx3MHRKZDBWVGlUeEUwZ2hXNEFNbzY2WHZIQ3o5N0t1cXF0ME1lMit5ekxGSUhPY1NPVXNSM2o3T1doa3hwR1pPWllZRlV1cUgzYzA4ZFVqbnl1YkZTdUFJSGgvZ3JTaWZIUlJ1SUI0UEM1M25yRkhUQ1Fhdk5hMmh4cC9Rb1pKSFBNUWY3eFd1SjM4U3RzTmhhME4yVlJGRVpKaVQ1cllhQ0UyQzNwL0F1Q2sxYkxsc3dEQjhrblZTM0pSdTdJQ1RxUllsS2dXSmRoY2tXS1VjOWhjZUVaenRpRWcySjJzN2psWDQ5aWxJZmlBSXVGT1RZRkRnWVFFU1UrRW9nVVJ3cDRGUVBtdWtZUzhHbmI4bHpQRDJrVGcrcTZCZzdqM0xSZm9reTdHbHBlNWNFZ3VVK2dRNG1YTzZJcVVqYjhrZTZvekVIcWpNUUliQWtTVkY1OEtJUW9QR3hWaEVLNnFQS3FuQzkxYlZMZHlxMXdGaWpGeUVnUEdwenNCWVZMVDQxbWY0U2lURk0xVEdtZ05jYkxVcHo0eXR2eHh2Z2N0UW1INndyUlJuU1FsUDFRWW96SnltNUk3bFlhM3UyRlFyVEZKWE5qMjJXWUxPM0JzaFN4bVdWWkxEQUJZcUZaOXpZOEpyM1U3aDRsM3ZzanhqdjZoalM3cUY4NjBiUytPNjZiMlY0d2FMRTJBdTArSWNwRTJXRWZhQWpENlJ0dDdteVJxOE5FTFNSeWQxakFNVGJXNGZHUTRINzFiU3NNNHNTRlFsTGtzUVpvZUxZTUtwcnJoYUZqZVVXdkw3TkM3RlgwK2dXQTVXY0x5Y2NYdTdUZllsTFVpd2tmTVdJWlhsZ0xyTU5ycWhxS0dXQS9DVjlYWXoyZU0wdUhkTFE4VzdOUTh1dEVtUlpFemdUcXQ4SnNRVmFZZmlnaklKVzY0cjJZdmE1eEVKK2kxK3B5WE5Uay9xaUxlaXNKV09qTVlnekFMQVhWalRZdUpDTHVXclM0UkxUYmxoSDNKT1d1a3BUc0R0Nkpjb0ZtT1E2TkxqTFlHQ3g2Slp1TWU4UDVXaG5HNVo3RFMveTRLYm84U2RIdVFSOXlXMFhZWkRvMU5pSWpadWVpU3FjUkR5YmxheTNHSFBHMXlqUlZEcWsyczc2SmJTTGtjbkJzbEZVeDMzdGRQdnJ3d2VGYTNGQytOdDdXVWpWbHV4dWxPSkhrTDMzM1YxUjRhbXh2cVZBSHViWW9zVlE4K2FXZG8ydURGREhieEo5bVliMkYxcU1Ubk9XWHZNZTQvQlFVNEptK1V1Tmx4RzZ1YWJIM1IyOFJYTWFYRlRFZDdxeGJqZzIzVUE4TkhWYVhNN295RHJXdzRablh4QUZ5NHpTWW02WWp4S3pocTN4a09EbDJ4RGdqNkd3dk1FZFMwWGNGZHcxY2NnMnN2bjdETTF2cHJEdkxMZGNHenMyUnpRWkI5VkxGU2dkUGZLQU5sZ1QzV3R3WmhaS3dlTUhielRNV0xOY09WTEVPSmJ2Y1BOQzd5eDVWZjc4WEhsVGJQcTZwM2tJUmF4ekN5bnJBSEtxeE1SMVdYVlJ0eWdZeERzajlYVkxtNGNCZnFveFRGM0s4ODNjTGVhQmhvWnFvMmhnSWNPRUttSXZhNnhMREk5bzNDVjhjYnVWMWdvdG5zdU9WVTF0T0JkTlJUdkkzS1ZycHpZOHBNaDhTbmUzUzRyd2ZaUmtrdThyQUNVeXdocGhLa1R2eWhCOWdvUGxzdVdIUTlFOVNua3VPaVFqbktNWmIyM1FNbEhnODNVKytGa093dHR1bHBubHJrSktHblB1RXZJZGlvOThiSUw1VWl5MGtaSjNVSmFnRVdzaHVsNTNTejMzUEM2TlJDZVVFOElCbUhGbE40QlFYdGFMcURrQ2MrNVF5eHJsQnpqY3FUTHVVSGsvZDIySjJRNEQzNUk4alpNTllUc3BDbkZOdnQ1cUFNQk5UOTN1Rk9uWUhqZFRkSjMyeWp2RDBVRnRrbThyMHE4dzNYcE4wQjBHaUZ6Q09pRWVGQnJEZmxRaDZYZmhMdmFVeS93aEtTMUdrbmxRaGtNUTN0V0JNVjR2MlVDQXZhb3Rpc2lGeTg1L2hVSURkWUJCZExZcWIzWFE5QVAvQUxycERJZGNJc2NsaW9DUGJuOFY2MXVxSVcyV1VOVllCRmZKeHVxalhwdHVpKzhrZ2JxRldiTEJzeEhCV1RVV1BLUWJVRHpRSnFtMXpkUXB0bDFKVkRTTjBwTFdnQTdxa214UTJJRGxXVk9NV3Y0aDlWY1VFVkpTTDJxeEVOQk4rRlR5WXl5b0RnNGhoQnR1cU9yeG0xL0ZjZk5VZGZpQXJTWFFIUmJhenVWYWhqTS9Ka291cTNHSHh2SURpRythb3NTeGVSMzgxS1hrbm9pNFZoT0tabXFHVWROVFR2Y1RwMUNKeEMraE95MzJNOFl4TVFWZUlDTHVYRWFtdUlCdDE1S3N4eEZDZVpMbXo1enczRE1VeFdacktURDVjUWM3OWdmZ3VyWkw5a1hNUGFLK04xVStiQjRqdmFSdTF2b1Y5MTVLN0Jzb2RuOGNENktnTWRRME5MbkFnK0xyd1BOZEZEeUlHc2dPbG9IQlcxajB5TWFmVUpQaEh6TDJjZXd4bGpKZ2lmaXphWEdudDVNZ2R2OEFnRjNyQmV6aksrVW1SL29yQnFha2MwRGVLL1AzbFcvZU92WjV1VkxXNk0rTTN2NUxSaGdTS1U5UktmZGhtVkxtaXpXMkE0QVdIeUdiNHBPNythdzE1QTFBN0tFam9hazJjMDZ2Tk44TklydHVSSjRrYVIrc0xncEY3V3Q4VGJsRFkyUm91NXdzb21WcnpwSUttMFZ0YkNNSGZjR3l6d2hQQmkzYXBBbXlCOEhmRHNudXZLTi9WWUo5VUc4bmdrMTVRdjZyMS9WTXM3dko3ckc2eGRldjZybTQ1dUpMQ3hxOVZpL3F1Ymp1NGw1TFBWUXV2WDlVMndJeHNuZFoxS0YxNjVDSGNkbEN1eFBVdmFsQzVYcmxjOFE3REhZUzRYcmhRMlh0dk5GdURzbmNMeEtodDVyMWxOeHl5Vi9rdlhXRjVUY2MzR2JyMTkxaGV2NnBlNEhkWks0V05TamZaWXV1N2dpZXBlMUZRdXZYWGR4QW1wZXVGQWZOZTI4MGUwRGFpZDE2Nmg5NnpkQTBFb21icjExaTY5ZEJYSWRFOVM5cTNXQWVOMTdaT3VqaVpMVXZhbEg3MTd5UTdnaVdwZTFMQzh1Ynp0SWt2THdPeTh1N2dmSHM4c2pleXdzamxEWkhMY1NVbThLSEtrT09VREEybjRMNHJDZFlKdngxVmE0RnBDdDhWZmQ0K1NxM2pVNEtyRXVTRjYxNEVTcW5NM3VyZXVndkY5NlFNZDFZWFlyUHVSanNCd2dWQUpPeU9XNlZCd3ZkRElZaXZyWmhISFluNnF0cDRPOG0xY2k2bmpyajNnQVBSTVlYSCtwSlBrcXpkSVBBdVJ0MFFMQUFnMVR6U3ZhYmRGNHl1YklVT29lYWtiampaWmVaV3pSZlllcHNTZElBTERaV0Vja2t6bUJyUnU0SkhEcVVDTWtnYkJiZGxMRDIxOVd4dWtIY0ZJaTFGRGNhczY1Mlk0VTV0R3dsbGliSGhialVOTURuQkF5MVRqRHFXTUJ0dGdpVnNwbW5zQjFYaWNrN3Mzb0VhYU15UGNTQnVFczZsRFhrK3FlYzExTkRxMGxWQnEzUGM0ZXF6NVNMK01NNndRWHNEN3FiUTU2eVdFSU54ZWl3TWJkUnNpUGQzYlY1NDdnWFE3OThsc2lBdkhldXVQd1JXU2FMYnJEeDNJUVE4RkZGSFdQKyt0MFdKQ3BzVFl5ZlZaZXFYT0hCS3IzeXZ1UWJxN0JGV1RLZW9weDNwRzZyNXFRR1Z0aVJ1cjZXRU9kZTR1a3BxWDlZQ0QxVjNLck03SytCaU9uamlvWGx4MzBuOXk0bm0rcDcycmVBZHJrTHFlWUs4MFZHOGF1aFhGY1NxRFVWcjdtOTNIOTY5SDAxVXZrWkUzeVpwV1dBMlYvUnhGekJzcWFGbXpGc2REWnNJdXREVjhraUYwK0VKR3NBQVR6M2dCVmxaSmRLZ2hzbndJdjZwWnZLTzUxN29EZVZlaWluSWFpTmdpbmNGTHNkc2lGK3hUQ0loRnRNTGJicmVzQmQrcUYvSmFKR2JTaGJ0Z0R2MVkrU0dmWTBkTDNOaTU5RlBvRU51OWtUb0ZTbDNOenlNOVVWcUQxUm1JVU54bVNzSGhaUEt3ZUZ3QmlkUjFWVThibjVxMXFPU3F4N2IzUklWSURaWUkyTzNSVHNGNGpZbzBKWnEyWVJzNWFkTzNjcmRNd3Q4TGxwODdkeXRJem1KaFlrZHRaRkROMEtWbGthRXRDcm1hanQrQ3kybEwvTloxV0thZ2R1TG94VkROQ0RUZ05JNVZ2aHRVYUNxWk5xTFFEZmJaSnhzYktRUlpUcWdYeGhyZWJkRURpT1NQcG5zcDdRb1o0SW9ueWduMVBvdTFVVld5cWN4elhYQkFYNSs0TG1Pcnk3T3h3ZTRBRUx1ZVNPMlp4ZkMyVngyQUc1Vk9jQmtYUjlIMTRmTEpHMXJlcTZYa0RCVDdxMXoyZEQwOUZ4WEtPZGFYR3FpRUZ6U1NmTmZTV1dHTS9SckhSVzY4ZkpVM0JqdHhXWXhsNktVT3MwZmNGcWRUbDJLTnh1d0g1dFcvMXdmNGxSMU5JNlVsZEt4cGMrV29KemJ1bTcvd0JFS2d4cnM5aWUwa1JEN21yb3NsRzZNb0ZRMTByYld1aFk1U28rZTh5NUdFYkhBUkQrcXRPcHV6Q1N0bS9taWIraStsTVN3SVZSM2FwWU5saU9KN2J4Z29HeHl5cEhBS2ZzYWVDUDFKL3FwcVhzUGtxR2kwYng4Z1Y5WVlia3VLY05QZGo2S3lmazZPQm8vVmdxYldLOTZSOGxZVDJEdmp0cWplZm1Dbktyc2hHSHVEZ3gyM21GOVZ3NWJqYjlnQkpWbVVZNmwyOXQxTmpIdzFpdnVmSTJLWldmQlpqWS9UaElPeWUrU01PMEcveVgwL2pYWnpFNDNEV2xhUmorVmpoMFoweDdCVFl6VGhyRWNSR1dKM3U4VENBTnRrM0hnRFkyaHR0L2t1aVVzTVV6OUJqQU43Syt3L0k3YXdoKzF1VXZhTWVwUnlhSEs4MGdKYXdrV1FKTXR6VWhPcGg4OTEzWjJXR1VJQUVZY2hUNVNaVnVGbUFiS2JSWHZLUG5tdXcyU00zMDJTVEdPdjhBSmQ4eDdzK2F5a0xnd1h0NUxtRlZseDFQTzhGdlJUYU5qcUVhckhpTDZkMXgwVnBSNCtKUnBjUmREbHdvUkIyb2RWVHlVVW9tSmpCdGZvcFEvd0FWRi9WWWozVzdYSDZvTWVhSktPUUh2Q1AvQUZLb3FESkZINDc3ZWFRZk15cWRhNHZ3cFJOeVoxckx2YUNIaHJYU2ZpdWpZTm1TS3BhRHI1WHpWVEIxTVE1cnZvdHN3SE1jc0phQzhxVWNwTStpbTRrMTRGaWp4VmZxdVg0ZG1wcmd5NytnV3hVdVpJM05IakNRaVNqd2JzSzhEYTZZaG5IbXRSaXhWa2xyT0NzSU1UYWJXS2FtVlhHalp4VU5zcHNsQklWRkhXYXJicHlHcUhtbWJqcUxrdmM0SUw0M0RleVdiWGh2eVJQMGdIQzFrb1JSSVR1aXRzdlZUMnp0OVVKenhJZ3lFc1FEa2l1cWJSUEtFeWNPNm8xVEVaVldTaDBMaUVJNURvZUQxVWc5bzNTY1JCNnB0akd1SHhCTFoxRWhVTkd5OUpGZmNFb2I2Y2IrSUxFRDNPZFkrYUJqVUhpbjdrRy80b0ZUVmF6dFpFbWpzTDNRQTFwUFJBeHFSSjFWdGJaUjE2d295TmFFSXUwalpKTENQVE02M1NzOWFiV0FDOU5LNi9vc1BZeHd2c29NUU9PWXY1UTUyNmlpQm9id2h5RTNVRFJHU1BZYkwwYkxMSWZkU0ZsQTdJUHZkRU1lc0RjckpacUJLVnBwSGF6ZnpVRnNQYnVkMU1WSWNPQjlFT1kzQ3hBd0hsUUJtWE50dXN0Y3B6V3Nsd2JKUTBuSTRJQk5sSnprTnpnU29RODV5aTVvSTRXRmd1c0NvUUNYaS84QWNvdWVGQWpjcnhaY0lnV3lMcE4xa2paUk1ha0hiSWtEWU43UlpMdk5pbUh1Q1drY0RkR2MzRURJVDFVbU85VXE1MWlWNXMrbFJjaTVNWmtOdDdvYmFuVUNEdFpLeTFnMzNWZFc0Z0lnZEpUVWloa2xROU5XaUozeEZJMW1MbHdzQ3FPb3hCemlTU3F5cXhsckFRVHVuS0RaUmxrTHVYRVpZTGdDOTk5MVRWK0lRUHVXVEV5OVczNnFsZFZWT0pTbU5qM05lVHNGMWJzczluZkh1MEdzaTcrQ2FncDcvd0ErOGJPSG4xV2hpMDdNdkxxVlhjNTFoMUJpT1AxTElNUGlNOVU0Z2FGOUo5a1BzYVl4bXlXQ3F6VFRUNGRDYkc4V3F4YWV2VG92cG5zdDluWEx2WjNSUk1xbzZhdnFZLzhBdkJCdWR0dkpkUmxtSWEyT25iM0ViUnBBYnhZTGJ3NHFQUFo4MjU4R29aSDdIc3Nkbk5PeUNuaGlxWGdhZFUwTFNmcWJyZFo1V3hzSGNSc1kyL0RHZ2Z1V0k1Um9zK0h2SGZ0THpHeDN2SThSK2hWOVJveXBTc25xMUFYM1hnNjNDamNkRHN2WENzQUVpUWVpd2QxZ2tLSzZRbXNXQTZLSzhvUUpxMlh0dkpSQkM5Y0tFSlhDOWNlU2pjTDF3b1FsY2VTOWNlU2pjTDF3b1FsY2VTOWNLTnd2WENoQ1dwZTFCUnVGNjRVSVN1UEpldVBKUnVGNjRVSVN1RjY0VWJyRjBOSEhqSjZndmFsRzY5ZFNoU2h5UzFDNjlxVWI3cjF3dTBXSXFpYThzYWw3VXVnbVY1WTFMMnBRaGxlV05TOXFVSVpYbGpVdmFsQ0dWalVzRnl4Y0tFSmFsN1VvM0M5Y0tFSmFsN1VvM0M5Y0tFSmFsbFF1Rm5Vb1FrdkxHcGUxS0VDRGhlVUY1UWhOU0hDRXBoUWhKWlVGNVFoS3l5RFpRV1E1QVFJc1hXTDJDeGNLRUNYc3BBM1FyMlVyM1VJZmc5aWpQMWcrU1IwMkl1clBGVGVVZkpWMVc0Qmd0NUtqRXRTN0Vhd2d3N0tzaUYzYithZGlCY3pmZEsxVGJPMjIrU3NMc1YzM0J6c3NOa284MmE0K2llYUx4bjVLcnEzOTJIL0lvWkRFVU5WVUNhWWcrZGxaMFQ5TVZ1TmxyZ2tOVmlBdHhjOExhVEFXMDBlM1JaK1dWRm5ER2did0M2NkhVeU1wWUM1UFFRQjBIcUZTWW4za2wyZ2VpcTF1TGpMdkJxMFR4UEZqYTNWZFY3Sk1NRlRYaHhiY0J0Ny9BSExsdUN3ZDdERkdCWWtXWDBYMlRZQUtIREk1WGl4c1JjajBXVHFaK0haYnd4czNpTXRib2FCc0FBZ2xyZmVXV0JPL1JQUVUzZlUwaE94QjJzbEtBT1pVdmFSY1g1SzhUa2tiY1VXMWZUUlNVQUlHL3dBMXF6NkJzYm5IYmxYZGZQN3M1MWlTRHRZcWxsSmU0bS9LcHliTFVDQmNJOWdoT2x1VWRqZk5Bbkc1MlVSY2l5TXhFd3NveER1N29iMmxubWhpN2lqR0lMVUh2RWhVWGhGK0UrMGFOeXEvRTVoSzBnZmdtd1ZneWRDcHF0WG1rcW1vc1RzVjVsU0lYRzZsSzRWWEFIM0JhTUk4RkdjaFp1c3V1ZUZDVU9HL1JNdllMV0hLY2ZUaUxENUhrZlp2dUZiaEhlek95UzRPU2RvbUxPaFlXQS9hdCtLNTJScW1EdlBkYkhuMnM3N0VYdEc0dVAzcWpFVjlQeVhwdExEWWpMazdZOVROdUcyVm02UXh4QUMvS1R3NXVubFdiM2kxckJPemZFdzRnWHluU3EycWx1VTNWeTJhVlZQZVM0bzRRSktRUnB1RUZ2S2tIbXlEZFhJeEt6WTJ3anpXZHQwcTBtL0tPMTJ5akRpVEg4NEZ1T0FIOVdOK2kwbHN2NndMY01CT3BnK1M1SmNGN1N2azJ1TW93NFMxT3drSmxVcEkyNzRSanFqTVFlcU0xQlEyRFBPTzZ3ZUZnY3J6K0Z5aU1WcU9xcm43WFZqS0xncXVuWVJkR2tLa0NJOGxraXpTb0RZb2pqWUlraExOYXpDUENma3RPbjVLM1hIdDJPV2tWRGYxcCthMENnMENEZDFDb2JzbW8yM0hDQldSZVYwYUZOQ0dpN2s1QkJjTDBFQklUY1VKMUJHS3JrWXBvaXhxTkNBSk4weEJUblJ3bDVJaTJUcXV1aDFvaGlkRTJvYnNMN3F1Wk0vREpBVzdXVjVHZkRZaEsxOUlKOXdPbmtsTkk0MmJYa0R0S213M0U0QTZRZ0IzcXZ2M3NhN1M0Y1Z3bUZyNTJra0hiVjZMOHdaV3VvbkJ6ZGlPcTZoMllkcjlUbHVXRnJwaUdnamw2UzRXY3RuNmV1a0ZTMjRJSU8vS3JhdVFRWDNYRjhpZTBCUllyQkN5U29aZXpRZHd0dnFjL3dCTFZFR09VT3Y4bFUyTTZ6Wlpxblh5b3hQWTRYV3Z3NDE3MjI0dDl5dThDZ2RpVzhsMnRCdHNnY0dMYllDcG5hMlFBQThyWXN2WWMyc0RUWlZGZS9ENldZUnVsOFY3YnJaOHRUTmlZMTBYaWI2b2RqRnVUTnJ3eWxFRFFPRTFQR0hCSk5xdFJGa2VXcC9VMjYyVmphVm5CbGZXemlDNEg0S3RNejlZSkthbHU1eEozVlhWdkxuK1NtMDRrME15SHZDTlIyV3I1dm9ZbndId2szV3dUekFRczMzc3FqSDZscmNNQmRhOStxbTB1UWNxT1hOeTQzM3o5VzNrM1hRY0d3WjlKUmh4SUhoV3NZWFZmNlpld0kxZGZtdDFpck85aGEwYmJkRW5ZZGVaaVpnWlBOcGUwbE94NFMySWcyOVVWajJ4dDRGL2tpaXQ3dzJVMkN2R2RncXJDNDZ5bkxDT2k1ZG0vS0Fna2tjeU1uNWJyckpuR25sSVZuZHlNZnFhMTF3ZVFwc0hSek0rY1pjc211bUxORnQ3Ym8xUmtsdEJUNnl3SGJvdWtWV0hSaW9jUTBEeEhnS0ZiUWg5TGExOXVxRGFhVWN4eEdzeTZLMFNBTnRacE82NXJXMGttSFZFbTNEaXZvU3N3b2g3N050Y0hvdWVaaXlxWm5QSVp5VDBVMmxxR1UwS0hFeTVsamZaTXc0cjNQV3lKVVlDNmtKdTBqN2xXelVXcSs1NFUybGxaQzVnelErTDdhc3FUT3NqWEFhMXp1VnpvM2tBbFNGY1kyN2xJMlVXZkVUTzU0TG04eWh0NUJ2NnJjOE94anZOUGpCdjZyNWxvTWZkRzl2akkrOWI5Z09jZTQwYW4rWEpTM0ZvQjhuZjZXdXUwZUpXRVZhZHQxelBBODJNcWkwYS93QVZ1RVZleVJnSWNoRk5HMWlwQkFVMjFBQ29ZNjhXRzZhanJMamxTd2RwZE5ybXRDOGF3UzhxcmJPRDFYdTgzNVFOaHBEa3RWb3VrSjVlK0oyS094NDZxRXpoNUJEWVlvR09hZVFFZU56eDFTMHhPclpHaWVBeEN3MGhwcm5PNm91cHNRdU9VaXg5aWQwV04rMjV1Z1k1STlMVmwreWcwT2R1aFNTNlg4QlpkV25UYXdDQmpVZ3J0K3QxQ3lBMEc5N2xlZEpZSkkxR0pyYnBVT0pQS0krY2JvQUJ1b01RUWtyQVBSWTFLSkJ1b0dpYkdiM1dKU1dxZXV3QVVTLzBRV0J1SVJ6SHFza0JtNFhpNzAvQkRhL2ZkU3lXVHZyVWd3c0N3MlN5ODZhNHNwWk81NXo5WHFvNkxCZWl0QnVmbnVzVFZRa0ZoK0NFWUNsOUVHTWx4VXRaWW9pY1FsUWdZdHNOMHRLYkUyM1dYeUdmajhGRnIrNTJQeTNVSUNCVXdkbG51NzcrYUc4V1RLRnN5NGl5VkwvVlNra3RzbDVFYVFxVEpQZnNsbnlHNjg2WFNEY3BTZXFBUjBKY2dreDI1M1NFODJqcWh6VjNkRzdqc3F5cHJtVkxuRXVzVzhXNm80d3NUUElFcXFzdEJKTmxUMVZiZTkzQkoxMkxTbWQwVTRFY0ErRjQ1SlZIaWxWTEhlMzgzNTNWL0hoc3g4MmVoeXZ4WFFOSU56NktlQlphcjgwVmNNVk5CSkk2VjRhMHRZU0FTVnR2WkoySFk3MnFZZ3o5SFVqNmlsWWJ6dkYvQ1A4QUJDL1FQc2Q3QWNCN0xhS0owc1ltckFMRnM4UU50dlc2MG9hYXpGeTZ1amtYWWo3Rmd3MDBtSTV1amlxdzROa2FJM051R25lM1hwWmZWdEJRVWVYYUdHZ3c2TXhVOGJkQWFmSk9sNERBRzdOdHNCNUlCM0szb1lFanprOVEyWU1ESEFHVWFvK2dIbWltRjBnSGRrTmFQTkRCK2ltRDVLeXNhU0tjc3JaNFRTUStHKzZoSkZGS2RWUUM4OUxLWEpYanVGeG80dVNRc0FBT09pemRDWGwwWUVKVWIrcWl2S0VKWDlWbTZnRFpTVUlTQldib2VwZTFLRUNYWGtQVXM2MUNFMTVRMXIydFFoTzY4aEIxMUxWWlFoTmV1b2gxMUJRZ1c2OWREYXNxRUpkRjdxc3R2SHU3WlNQZHZITzY2Nkp2c2dMTHdOK3F3NlBUeGNoUmJHeHcxc2NYV1FXQzdKcktHeVV6TzAyNFIzUVRBQVJzMUlkeHkyakFJdHlzcUw2ZnUzQ0s1N3gyOWxDUjAxTjRaV2FXSGE2WUdFdVBNTDEwQnJHUGRhRnhlNGRGbTl1ZVZDQnJyMTBIVXZhbENCcnIxMEhVdmFsQ0JpZGxHNkhxWHRTaEFsMTY2SHFYdFNoQWwxNjZIcVh0U2hBbDFJSFpCMUwxMUNCcnIxME85bElHNmhBbXBlMUtJNFdWQ0dkU3pmMVVWNVFoSy9xczNVQWJLU2hETjFJRzZIZFN2WkFRbUNzTHdOMTVRaElGWldBc3FFUHdncnlYU0EraXFxMlcya0szcWg0MVFZbTRpUnFveExjaHFuUDZ1NkRVc3Z1czByajNJUkpSZHFzSXJQdUt0SGhJV3Y0MU4zV29mY3RodFlPNkxVOHlQT3NnYjc5RU1oaUVjSXB3NmZXZC9GL0ZiaERHMmVJRHlDcE12VVJrZ2M0aTIvVlhGTElZWHZDeWRRelJ4b0hMZW51MEtzcVJlWGRxc3FpYlhPUTRFZk5MNHFXUnRCQVBDNWk3TWJMdWJCa1dpT0lZbEN3RFlPWDFiZ2VHTW9NSWlqRmdRZnlYejUySFlZSyt2ZS9UZlNRZjNMNlRpZ2NhcVNHNERRMG5kZVo2cExhM1JvNmRDMDg0ak9pUHI1TERwR1JSNnJBT0lTYnlZcTRSbmU1Nkp6RWFIVFRza0RoeGUxMTVTU05lSldTVDYzRXZPM3FsZ1E0bExWbFQzalF4cHNRZXFsQTdZSkRSWWlNT0lhRXU4M0t6TThOSEtBSkw5VWFqd1BUTTFWaUJieVFJQlk3b2dmM215ODVwWUwySzRXVndlbmNBRFpVbGNkQUpLczVKTDN1cXJFRHJhVlp4cmtUTmxITTh2azJUMUlkRE4vSlY4aDBQVE1VaExPQ3RTQzRNNmJDUWFwSnZTNmN4L0VXVXVEdkJJQjBKZkQzQXNMcmNGYVhuN0dqSFR2akR3TnJXdXJPamp1a1p1UjhITDhhcXhXWXJKdUNzUWVNZ0t0cFFhaXRjNG5weXJpaGlEbmZldlV4VzJKbnQ4bGxTUldhanlEWXFjVWVodjNJTlJJUUR5bFBsam9kaENwbEJ1RWxkcEpVcDdrbENhdzNWNktFeVpNMkFLWFBLSzRXdWdGMWs5SVVUWWJJN1RzbDJtNk8xQTBPaVJjM1RJRnVlWERlTWRkbHBFc3RwQXQweXVkYkI4bEpkaTFwdTV0c1Vta0pnYmhMdGo4a2NjQlVaRzNmQm5xaU1RMFZwc2hvYmpNQnU2ODl1eWsxZWVObHlnMktTTnVVcE8xT3ljcE9jb2tLWW1SdWh2UmJYSlVYdDJLTkNXYS9qVzdITFRxaG42dy9OYmpqRzRjdFZuWmQ1K2F1bE5nV05zMUwxTHJteWQwMkJTRXJidlJvVElacFl0VGVFN0ZUN2paWncyQUZ2M0syaXBOK0VZcG94U3hYWmF5RlUwL2lWclMwMW04Sld2Ym9TZHd0U0s1elEwSlNvcVdOWWJFWFVxcXBzQ0xxaXFudVk0NzNDS3hpNUIxVTVsa0l0Y1hROVJnc1FMRlRFekd0dWVVQ1NyWklTTEZkR3BJdU1Mem5YNE00R0thU3c4bHYyWGUyK3NwM043K1Y1QS9hSVhJWHlpTUV1MytTcmFxcERqNGJybXhIRDZ2cGZhUUZNeG9CSjM4LzcxdGVGZTFLSXFZc2JkcFBrZjcxOFEwNzNFK0k3S3pwcXdCdzA3SUhBRnF6NmpxKzNpdHhIR1dQRThnWVgzdGNMNm83RXUwMkhFNkNGczhnTGlQdEgwWDVtMGVKT1k5cEI0WFdzZzlxOCtYVEZhVXREVDZvZGh6WWZxWGhzOGRVME9hOFdPNlpxTnRnVjhqOW4zdEtOcW1STWZVV3RZYmtoZGZ3YnRkcDhTYzI5UXczL0FLU1JZdVIwdWNsbDBoTzFwWVRzcTJiTmxQUENDSm1HL3dEU0NDekY0NUl6K3RaL1dDbGlHdzFRUzl6UUZyR2ZhNFlmaFFMbjI4U3Q1c1Zqak56STJ3OVZ3ZjJoZTBadUgwVFlvcGdTWlFMTk4rb1VzSlNONHlUaUVXSnVjYmcyZmI4VnY4R2xqVFlnMlhBT3g3Rm5TVWZlRnd1NXdjdXdZYmlicG5PQktLampSZk9uMVNGcUk2UnNiYmdpNnBUVnVqbmR6YnpXV1ZUcGRyOVYyaFcwc20xWmU0aEw0bldpQ0Y1YzYxZ1VXbWhESTNQSkhGNzNYTCswN09yY0lFckd6TkI0NVVvYkZCUmo0bnFudER2dEVmaXJRVnpUQnVlaTRqbGpOemF1c2NYU3QzZWVUNnJmempESFFEVEkwN2RDbGJTMG1YTlRORWRSMjRXcVZRYk05d0lIS3kvRkM0bTdoYjVwQ2V2WkhjbDRIM3FiUjZuUlZZN2hzZmNPZHNObHpERjZwbEpLNW9JV3o1MHptMmtoYzBTQTdkQ3VJNHhtMTFYVU84U20wY3NqTmxtcW8zUHZjYm9FejJ1YnNRdFNiaTduT0hpVDdNUjFNK0pFNElzUXl1eTJoTm4zdXJTbnhMVGJ4Y0xXNmVydjFXVE02TjJ4VldVS0w4WldkQ3dyTmpxT1J2aks2Umw3TzN2TFdBdlh6dDd5L1kzV3haZnh0OU81bmlzcWpWTU9qNmtvOFhiSUcrSzl3RmQwdFNIdHZkY1d3RE1wa01ZTCtnWFNzR3hFVFJ0OFE0ODBsbmFOcUZSdHlqTm00VlIzOTdiM1RiWk5naFpDemptMlVKWnJwYU9UYmxSbGVVQkFqbmh5eXlXMnlVWThrRlpqZjQ5MUdPUTI2U3hSNDM4WEtWbElzTEc2aTJjNmh5aFkyS0c1UTNrb090aDhsbVFsOGYzSk5ySEY2QmpraG52VkI3aTVlTGJEbFlTUWlCaUpXU0xCR0JGanVoQTdsUVlnYUlCZFowaTNxc09VRFJrbHRsRzdWRXNkeXNGcFNpdFpJbHZDSG91Vm5RVmxwVURSalFWQnpDQVV3RklzdW9HaERTK1RaWjdrczVUTTVFQXVFdUpqTnNvTU1XYVVLU0x2RVYwWkIyS2s1bmR0NVVJQmlEWWh2WlFtRFpPRU9aeEpYb3JnYnFFSmQ0aFN2dUZrcGFWOWduaXBFWk9icGFXVUJlbG5JS1VuZnNTRGRHaXJKa1pwUXEycGt1U0xyTlJVa1hzVlMxbGU1dDk3RkdrVm15ZGJVaU9OMU00M2tmdUhlUzEzR2NiWlRSQ25qQU1ydkRxSElLelVZZ1RxcUpYYTVXYk5JNkJhOUU1dFhpSVozTWsxUk02MFdocE5pdERIQXpjdVdrRWZQUFQwMGJITk5WTzkya002M095NzU3UGZzdll2bjNFS2V0eGN5VWRJWEE2SmhzUVR0d0QwVy9lelA3SlZSamM4T1pjMnhNbHcxd3ZIRWJOZUhnWEd4djFJNkw3T3BJSXNMcDQ2WERSM1ZMRTBNMG4wRmx0NE1TOHp6V3B6MjJreFRKbVRNRjdQTUtpbzhNbzRZWm1NMFBranZlUTM5VmVPYjc1K3RtUGN1L1pjbCs3WWJTUEY1UnUwK3FtWlJXN1QrS1RrbGJjTUtvODdrek5NWTFnYkEzc3NIaEFhUU5rVyt5aWtKYVBYV2RTRzQ3cjJyamRPYjRGMXlFMUwycFExZXF4ZjFTV3g4VVRYbEcvcXZYOVVSMGt2S0YvVmUxZXFoQWdjcFhzRkFHNnlEc29RemNMMXdvcjNLaENSSVVWa2dqa1dXTEtFUEx5ellsZXNWQ0dGbHZLa0cyVXRIelVJUldRRklOWGdGQ0hnRmtCWkE4bElSazlDb1Fqb0xodWJMd0hkOE4xSDBSSm9lNkdxV2FPTnY5TndDcGNaenhnV1dxWjB0VmlOTDRSY2dUdHYrOUljMFdvWU4za1c1cXBBTGU3RW9mZmlCaEQ0KzdhZDlSNkw1dTdSL2I1eWRrb3p3aDBzMGpRUURDUzRYKzRMNDg3U2Y1U2JNdU8xRTFKbDJxbllIa2hnTWJ6OHZKSmN5OUhTdnpSK2wrWWUwN0tXVWFlV2JFY2RwS2VSb3Zva2NRU2Zvdm5UUG44b1hoV1hLcVdrd2JERzQyNTNnWTZCM0pPdzVjRitlOUpodmFkMi9aa3BqaS9lejBjc3R6cWdlTnJlWksvUVhzTTlobkl1VzhCb2E3RjhKTWxleHdkcWE1dXhGaU9oNnBXNXRuSmFaUlZzbjJNZHFPZSswM045TFBpR0NWK0QwY3I3Z3lodHRKSXNlVDBYMWhOSjduRlRNbGQzenpzYm9GTEMvRDZhQmxNUXlDQmpZMk5QUUFXSDdsbDdtVlRnNTRKa2J2ZGFLTWtKOEZTNTdSb0JGckxHb0x4MVAzZWJoUlhUaEs0WHJoUlhycUVKWEM5Y0tLOG9RbGNMMXdvcnloQ1Z3dlhDaXZLRUpYQzljS0s4b1FsY0wxd29yeWhDZDdLUUtnQ3MzVUlGQzhvWDlWNi9xb1FtdktOMTY2aENZY3BYc0VPNmtDb1F6Y0xON0tDa0NnSVR2ZFpCc29LUU4xQ0VnYnFXcERVMUNINFZZazI4ZytTcGE2bXZwTmxmNG9CSElQa3FtcWRxQVZLU0wwbUxRV2ppQXNpc0FqWVNmeFdBendCU1BqWlpXY1hZclM1WXBWV2ZFK3d0c3ROcXhlcklPL3pXNDFvTVVEL2t0VmloOTVyTDI0M1hNem9pUmQ0YlRPYkNMTnR3andzTEp0eDFUZEU4Q0VEVHhaSlZVeFpMc09xOC93QjJiT1A0VWV4aG8wNmdBTEcrd1ZEWFZVbGFkTVRRNndzck9ybWZNMjFqdWxzUFkyREVJNGd3U09kdlpjbkpSaUt5Y3MraU93SEo4MUhoMHRWTkdXaDdOUU52VUxwOVk0aVYvZEVrcDNJRk5ERmtpa3N3UnZkQnY5VlJWdFM2a3FqWUY0NFhrZGE5elp0YUxoY2l6S3A4RldIT0FOajFTOVRpajZpZXhKdGZpNnRIeE1uWnJzTHFreENBMDVMd0ZqeU5OQ2xaRVhWVG5DOWsxU1NocmJIbEp4U3VtZGUzS1pOTzZJZlBkSkhJRFdPMXYyS0Mxbmg1S0xKQzQ3b0pKYW1vY21GWWU0TjB3S3hzakxiSmRyTy9DaEpDWVJkTHh4NURiNEY2NlN4TmxWVkUycHBDc0ptbVM2cTZpemJyVXhvcVRZazF0NWVMcDV4L1YyQUNXWVBGZFd0TFRpVUM2c29xU1lqRElLU21lWGJiM1hGTzBLdE5SV09EWEcycmdGZGN6alVDZ3BYZ0cyeTRMajFXYXF0Y2IzOFMyK253cG1QbllsU1JFQUVjcllNRmdJNTgxVVV6YkFmTmJKaHJkTFJzdGJVY3BDY2ZjYnZvUENSeEtvQWFlRTVVR3d1cU92ZVhGTDB5b2RKaTd0MUIzS21lRkIzSzFDcURQVkJrNFJqMVFaT0VERFI2Sk5EaEp4bXhUQWZZSVF6RXpkcnJic3BQczA3OUZwejVic0syYktVMXlRaGFHNDN5YjlUeWVNMzhrY2NwV0Z2aVRMZVFxOGtiR0o4QkdpNnpheWswS1ZraG91SmtWa0wxbElEWk9Ec1ZtU2NnVDA0dVNsWHN1dWdNVUxVQ1kyQlRqMldCU0ZTNjExQUxOZHhnN09XdTh2S3Y4VmRjT1ZDUjQwOHF2c1prc0FxMTQxUE5rL003Wkp4TTFTZmVqUlZtWG1DVXhlUnN0dGl3ODZCNGZ3VlpsdWxCQUpDM09LbmFHRGhHVldVMzZQTUxia0toeGlBNlN0MHFkSjJzcVhGcVJ2Y2wyM0NnUnkvRU5UWGtYS1FlU1J2dXJURzJnU3VzcWdsRWhpSU8zQ0VXM0tLZUZHMjZNYWtCZkVTZ09wNzlFKzV0d3NkM2ZvaHNadEs3M1lqcCtDekhHUWVGWkNDNTRSRzB6YjhCQTJUYUNwZ1FBcktLUXRic2JJVWNJQVIyc0FDQnNtMHRNSXhPZWpPcHN6Mjc5SEVMY2NEN1RLM0RaVzJxSDdIcklWb01MdEl0WloxQU92WksyaE5IZWFmMmdhdW5ZeHBtdUw5WHEvaTlvcDhUV24zZ2NmdHI1b21xUVdrVzNWWEpWek5KdVhXVTJpSkpIMWJWKzBvWnFjeGladHlMWERseWZPV2RwY3oxUGVPbEx3SEIxdFYrdDF5WVZNcmpjT0tQSGkwa094QkttMFU0bjBKMmQ5ckRjRjd0ajN0YUcyRzVYYjh1ZHMxRFZPYnFtWVBQaGZDTDhRa2FRNk54QjlFL1I1cnJxSnZobWVQa3VKQTdUOUdmODVPRlR4RDllMEg3bFVZMTJuNGRoYmU4Wk9EWVgzc3ZoQ243UjhVNDk1a3Q5eXpWWit4R3RicGtua0k0M3NqU0p0UHJYTUh0UXdVZE5KREhMRnhia0w1NnozMnZUWm1xbnViTmNFMzJjdVoxZFhKV1hMcFNTVlhQY1lUNW9xTzBiblFaN21wSlE0U2tiL3RMZk1FN1hIUlJnUGx2dDFkZGNPY1FSc3BSelBqNE5sMGI1SDBMTjJ1TmNObnQrcXFjVzdVQk5HUUplblFyaXJzUWZ4cUt3K2Q3eDhaVUJObnh2TkxxNTd2MXBOL1ZhODZidkhYdVVrV2tubFRiY0tBandudGJjcG1DcnQ5by9WVkJlUXNzbUlLVnRMS21iUkJXQWRVNnlwSG5kYXJGVU9zRTdEV0U3SUpSTEdPZkplUHF0K1UxU1ZkaU4rcTEvdmk0amRXRkZja0tqT0pxWTVIUmN2NHVZM3N1NC9WZFN5L2o5bU5HdjhWeFBDbmFDMDNXOFlKWGFTM3hLaXk3RTdiaDJNZDQwYjNXdzBkVUhnYnJtbUMxNGN4dmlXNTRaVWFnTjBxUVRSc1FrdTVFa2VOS1NpSlBWRWx1QWtsYVM1Q1ExQXYwV0pwTDhJTEdhZXF4SWJMckdJWmdmNWxNTmZ4c0ZXeHphVFpOeHpnMnVnWTZLR1hQTmtCN2pkRkVqU09pRzh0M1FzYWlCSjh5aXh1RnQwc1pMM3NzdGNRaExIa0ZtQmNkaVVmZ0JBWTdVam5nSVdBeUt5QmRac0ZNTlFBTThiRG9oa3FiZ29hVUJEdzRLR1FmSkhERVVNYmJvb2RFMmczUjJBK1NPSW0raXpab0hSUWxpMDhBUEtCSkdHczRSWnBTWFdRcEFYTVJraUxOUGk4MWlWMTFFTkljVmh4dWlRNitEQUF2d3NPSUM4ZGt2TkpaR0trMFFxSGFRU0VoSk1icGlTVFdsWm1nQWxGVmxhVTl3R1dRT0JWVFZWaHBJSHNaNG5FM0YwYXNxTkY3RmEvV1R1anJtVE9PcU5vM2FuUWpaU254eVRxcTZOc2Q0WGE1ajhUVDBXdFluaVhoSW1PaVE4Z0xPTzR4R05UYWNBeVNiQU41QzE2T25xcEhSUmFYVk5XOXdhWXZ0QysxMW9RZ1VwWjFBekc5ODgzdXROZVdTUTNBSyt6ZlplOWxac2JZc3dabmdmRHJBbXBBNW1wcnpjRHJiMVdQWlc5bDJPTXdabnpCRzF4aWNIQ2luQnU4SGZwOHZQcXZyOGlLS0dPbnBtQ0dHSVdqamJ3MGVTMnNPR2p4K2ZQYjRHNmd0aW8yVTBjVEthRnB1QkUwTkgwQ0EwZ0FBS1BpampEcEhhbkhiU2VpeHJ1dHZIR2tZdVNWc01Dc2p6UWJxUWNqWXRCd3M2a0lPV1E0QlFNTGMyS2lzYWxnRWhGWUxraVlLemRRQnVWSzZsZzdqSmV2YTBMcXBYSlNvdGt5T1dQbkZ5U3Z5cFIwNWxZWHR1UUNvZ1hzaVBMbXpOalliTkkzc3JIaVVqdVBQSi82dkJocGM0RUFidFhvSkpwWGxybTJBRjdyTlJJNmxER3NqTWhkelpMNGxYVVdEMExxMnZybVVUR2draVQwU1paa0hQTk5mNlNzY3A0blZVbWkyMTdMbjNheDI5Wk83SHBLS0RHOFRiUzFGU2RNYlhXOFIzOHo2RmZQUHRHZTNDMmhvNm5MZVNNTWRqR0p5QWhsUlJHN2c0YlczY09wV3BkZ3ZzdFpuN1ZzV2h6Wm4vR1o1NFM0VkVXSDE0SDZ2cHBHbHZ6NnBDaFJibGpjVjhaOW81S3p1enREeTlCaTlIb2t3eVUrQ1psdHpZSHA4d3RqamV4OFpERGNoQ3dQTHRGbCtsR0g0ZEN5bW9JOTJSUi9DUDhBRmduMlBER2tDbXR2eW0yb3JrcjFCdWt3RURaaHE4QUlVNDJGMGgxQ3c2cXN4Zk9lQ1pmamMrdnhLR2x0MGtKL0pjcnpEN1dlVHNCcmhUeFloU1ZSTGcyN1hIcWJKTXNpTEdQUzZuSzZ4eHM3TStXbmVic2ZjamF5bEZOTkxkakdBaGNueEwybWNrNEpRdHFEaU5ISTU3US9UcVBVWFhMTTIveWcyV2NFWkkya3BvYWh3NExIZjNya3RSR0hjdXc2SnFaY3FQMVI5WUNubWkzTEVDZXFwS0tKMGxWSjNRQy9OVE8zOG83aU9JVFNOdy9DNTJnOEdNaiswdUc1djlyRFBPZEMrTmxkVzRXMTkrcmR2M3FyUFhSbzFOUDdQWjV5U25IOWo5Wk14OXZtUjhvdGY3L2lyWXRQbnAvTmNHN1F2NVJQSjJYakxIZzJKVTlUSTIra1AwYi9BTDErWldJNHRtbkczT2ZXWmlxS2hydHlIMi9KVlRjT3A2Y2wxVk0yZDl2dEtsTFZidXg2M0I3STRKUnViYS9xajZvN1EvNVJmTytiR3pRWWZSMHdoTjJ0Zkc4QTI2Y05YemxuSHRpemZtcVYwbUoxMVhTeHZOeUk2bDl2NEtqd3pBOFF4cXFFR0VVVWxVNXgyRVF1dnJEMmYvWUh4blBrOE9KWTVXUG9hZHRwREJPM1p3NHRzMHBVY0V1NTFZdEQwcFdwZk0rWE1uZG5lWXUwaXZoaHdRMUdLT2xjQTd2SkhPOEo1UFhwZGZlbllEL0p3VUZFK2t4TE1EYWlPUWhyM05ld3VHKzU1Syt1T3pyc0R5aDJZMEVNRkxoVko3eEgvd0I0WUhYSzZKTk1aV3RaRTd1R0FXQUMwc1dGeFBHZFQ5b29aRzhlT3E1WFkxdkxIWjVnR1JLS0dqb01PcEpPN2JwMXZwMmF2clpiSkpOQkMyNzdSMzIwdEZnaGt0WXl4T3QxdVZDSVJ1UDY0Z2pvQ3RHTVR6V0tjczN4R2RWeHNmQ1ZCZU8zeVVTYm82QWNpV3BZMUtOd3ZFcVVEZGs5UVdOUVVML0paMUtVY1pMVXZhbEc0WHJoUTZTMUwycFJ1RjY0VUlTMUwycFJ1RjY0VUlTMUwycFJ1RjY0VUlTMUtRS0hjS1Fjb1FJRm02Z0NzMzJVSUVYZ2JLQ3lIS0JoRjVSQnNzNmxDR1Y1WTFMMnBRZ1FjS1FRd1ZrRzZoQWl5Q29hbG00VUlUVXdib1Y3S1Y3cUVQd3F4V1l2a0h5U1Q0N3RCVHVJajBTSFJVNUlzemRJaklkTEI4MW0zZGhSNnFiSmU4SENzNDFTSzZkc0JXdDcybmQ4bFE0YlRodFdiam9yYXVtTE5sQ2lqYks0RzMzZ0tqcUpVWHNjYkg2S0FhYjIyU1dKTmF3M0FLMlNscGdjUGZ0WS9KVldJZDJ5RjROaWJkUXNqRjhUTkthMkd1Q3FZZHJIZGJMMmE1WUdOWjd3K0tWdXVOM0pISElXb3p1QmFBT2JyNk85bHJLRVdKMUVkUk9EcUVnczYxenlxdXJsc1FtQzNTTzBWVkVNRndPbWdoR2tOWmI4U3RMa3FXbVYzZUF1UG91aVo4bGl3Nk5sT3czNmIvZXVlZTdrRHZBTDNYazhrdDdOekN0cUlDdDd1QnhzZVVHdHFHejAzclpIMXRlMGl3K2lyNUkvMW5vcURSZlJDaGF4c0xDUVFicHV0a0ZoYmZib3NpbURvOXR2a2d4UmFiMzMzNnBWY2hwa0E2N09Da0p6NDFZT2swbXdza2F3bDdoWWRVMUlPdzFPM3U3RlNuUGVpeUxUaTdSc3NTbTExMkZIWElyWHhoZ2RmeVd2dkhlekVlcXVNVXFDMGtYc3E2aXArOW1CSkswWUxncVRrWmJSQU5CTnZxbjZKbmR0UG9FS3BwdzF6QUNWWVF0YkZSdWNlZ0ovQlBVR1ZKU09XOXAySjZJcEdsd0J0eGRjYUY1cWh4UEJLMi90WnhQM3ZFeTFqallBaXdLMWlBV3A0OXQ3TDFXSEY0ZkprWlpEMUxUOGVTdmFlUFNBcXFtR3FCdHVicTJpYnBEZmtuVCtJbU14V0hUR1ZydFZOcWVRcnpFcEIzWFBSYTJaTFBOMDNGQ2laSlVNRStFS0RpTDhvRDVMcUcvcXJsQ1V3NTVRWlZKcmtLUW9HZzB6RFR1aTMyUzJyZEZhNUJRZG1TM3dGYkJsTittWWk2MWw4dDNjcTF5L1BwckdiMjNSTkJZNWNuVTRwQ043SDVwcU0zSTNRV1NCOUV5MXIzVTQraXJ5UnNZbU94N293Q1hpNFREZUZYY1M4bVFJV1J3aTJIa291RmdpR1dLekRkQWNPVTA4Y3BhWlFDeGFVV2FWVDFqckVxM2s0S3FLeHR5VkFiTmN4TjNLcGZ0RldtTTdFcXBhZVU4cnZzRG5YcVdPOGdXSkgyY25LR0hXOEVJMFZabTM1ZFpwYTNaYk9aQzBXNFd2WUxPSUdnV0gzclkyaDlXQnBiejVJeXBJWG1IaUI1K1NwY2VxaEZURVh0c3R1Z3dSOGJMdUJOOTkxcDJjTUprTEhXdVBrZ3NKSE5hK2J2cG5icXFjZDA1V3hPcFpUZTZUY2JoRW1XSW94ZGVBdVZFdEpLWmdpdmJaSFpZVVNRaXVBcHRnVGNVWEd5TjNOK2lXNUR0b28ybkN5SVNuNDZja2NLWXB5T2lCeUpzRVd3RkVFSlRvaXNPRjR0djBRdGsyaXpJcldVM05ZQmNoR0xiRGhMeThKbkF1Z0VqNHdlQ2xKWldTWHNDalNOSkpVV1FiOEtBT05nbzJzSFFxVWtNYittNmFiVDdLSnB6ZFFIYUxSVS9tc1BnTGpaT21uTnVGTmxQNklMQzhNcTVLZDBJdUZoc2hlM2JZcTBrZ3Z5RXUra3R1QWlUQmNDck16MlA5RVI4clh0M3VVMCtDM1Q4RXROSGEreU93ZG9Kc29YbjFBc2dPaklRdEpCWGFCWWN5YWlwZDg1QmFWTWhTZ0FyWmoxUjJTQWhLQUlyRktCRHVhdk5adXNLY1pzVkVrY3NQRkhjSnlDQkRoSXNtWTNrdVF5U0g0MkVETkpWalJ2NFN0dkJ1T2k5U2s5NFBtcU0wYW1PVE5vbzVpTExZOE1xM0J3M1d2VWpObS9JSzdvWGFTRmtNMlluUWNHeEV0YU4xdW1CNDFxYzBhbHpERDZpelF0a3dtczBTTjNzbFNIYlRzTkJYQjRHNnNKSkE1cTBqQ2NUR2x0eXRscHE0UGJ5a3NWS0kwK290MVF6THFRSnBRZUNveHVYV2NTRE9kdWlSUE8yNlhlYnFjYlVER3hRK3h4dHlzdUpOMEdOcDgwWFFoWTFJekF6VWQwMFlSWkx0YnBSbXU4MHV4dmtUampBUlB2UXJIeldBUFZBMkF4aHBSV2k2V1lOMHd3RkJZdG1TMjY4STBZUjIzVWdMN0tIQVRXYkxBWWJwZ1U1ZHVwYUxkRkNBTkJzaFBhVTA4V1FIbFFnbzhBT1hwSEFScWNyYm9CYWpJaFIwM2lPeFFpZXFabGNHMzJIMFNnRmlpUXkrRExqc2thbCs1M1RFN2hibFZzMnhKdWpLMHBrSm45MExxdnFLNDJ0ZFRyWnpPTGVXMnlxS3FvYkUwaSs2ZW9tZkdkZHdWYlVhcm02MXZFTVJjR091NjdPcmVwUnE3RVN4eDNXcllwVlduRTRjVHArejBXaGh4MlY4K1pKQVpuUisreE9namM2Wnp2Q0FMbS95WDJCN0tYc3h5NHpYUlo0elJDMStIek4vVnhPczJRUEF1TGc3OHVIUmFIN01YWUJWWjV4dVBHNjZuZDdyU1BFdzhKTFNOaHY5VitnTlUrR253Nk9pbzQyUVVySFhhSW1obytnVzVpd2NIa2RWcW5mREMxTWtMVERIUmd4eFFzRVlCOGdBUDRJTFQ3bzdYSjRuTytHM1JCYVFBRk1PdU45L210cU9OSXdKWkd3bXFSenpQTVE1anRnQnlwM0IzQ0RxMnRmWlpEay9zaEhMQ2h5a0Q2b0lOMUsreVd4cURnN2NySUtYQlJHbXlMeUpKOEJycklOMUViaFNaSGRoZS9ab1FOaU81Sm9KNDNVaHViY255UTZlZVhVOXRNMFNEN1JQUlRnZ01WUzZWdmltSThURHdBZ3NZb05tQTNleDU4a1ZyYkhmbFpZK0NXWVZEbkVQWnRwSENJd0dzbERpTEJwdUxkVTVwSkJZc3lUcXR4alRwNTJXUkUrYVFHTTZUNXVVcTZlbmhqa2xxMzkxREdDOHVIcHV2a2Yya2ZidHdyczlqbm9NclZOUFcxN0drQmtta2VJQzNyMVZTY2t2TTBJNmYzaHJpanYzYXgyejRCMlE0Rk5YWWxWeFN5c1lYQ09HVUYxL2tMbGZucG52MmxzNisxVmo1d1BKUnFhU2hrZTBrMU1EdzB0SjMzT2tjQmFOazNKSGFEN1hHZEpLK3NGV01OYk4zazRobmVXdGJZRGdXSFZmYWRIRjJjK3lKbE9DT3BsZ1pQRTdSM2s4TE5aT3c1SnVxY3BXYjJuMEVNYXBMYy8wTEQyWi9ZcHdIczNnaHh2SGFOazJQdUxaeE5HNXRnVDRqNTliZFY5RFkvbWpDc24wZy9TYzBjVURSK3FEbmh1MzMvZXVCNEI3ZE9RcXpLZFpYeVl4RTJwaGZwampHbXhHL3I2QmZEdnROKzFYam5iVmliYUhEWmU2b2FkK2xzbExLV2x6YkhuU1BWTGxxMGtNd2RKMU9zbnRsRnBmb2ZvNzJrOXYrRFpieUhUNDNodGJFNWhrM2JIS0hPc05OOWg4MThyZG9uOHBHMnFwSllNdHlWTUZVd2FOVDJQdHFHM2tPcStLYURFOHhRWVN6RGpXVmRUQzAvRExPOXcraFVLYkJHVWJpOGpVOXgxSFVPcW81TmF6M0dnOWkwcW5PWHAzaWJUblB0NDdSZTB1cm5kVzRteDhEamNOYzBnMis5eTBLUEJxa1RtV3FJZkx6Y2VhMkVVeEc0YUdqMEM4WldqYmtxZzlXejIyRHBXbDBjZHJpbi9RcHFpQ3N4TUJ0UzhPakd3SG9sNDhzWWJmOVpDUzd6L3dGc0RnV2k4Z0RUMEFTOGtqMzMxdERZaDlvZVNDV2FjeE1NZUxFN25CQ2tPRHdVVmpBQTIzcWlWTnBMT21lME1BdFlteXJNU3gvRDhPa0VjTlFYek9Pa05kNW5oZEg3TVBac3p4MnpWMEhkNGJJS0dRZ2Q1RVhjSGpnSXNlS2MzeVY5WDFIUjRJY0tLZjZvNXRWWWhKVnlOcE1McHA1Wm5lRzhjWmNML2NGM1RzTjlpdk5uYW5KVDFkZEd5T25lUVhDZHVnMjVQSlgyMTJGK3c3bHJzM3A2YXF4RVBteEFnRjBkUkZxQWQ5NTlGOVI0ZGhkUGhrWWlpb29LU0VmQ1lZZ3pmN2d0M0RvMVMzSHpUcUh0RFBjNDRaVitqT0dkanZzZzVKN0xvYWVaMkcyeEJnYVM5am1rWDY4RHpYY21OTkxFeUdtOEVMZGdENUlwczJjTmwydng4bEYwRlJvazdsbW9IcVZyS01VZVIxTTU2ajcyUXhLR1NNQWtHb1gyc2h1WnR2OEt3MXMwTkswUGJaMTFGNzVJM3RqTGZpM1JKSXpvYVBGZTZVa3pGMkhaZ0lkNnJ6bzJSNzFBMWZKUklrdmJTRkVPZE04eE82Ym9rVExLT0xqSDlDZHdSY2ZDbzZ2TGRaMU1Zd3dnMzFkZXFoVE1iRVhoeCtMNGJvN1JXMnN6ZTV0MVdMZXF3Nk4xSTd2d0w2dHJIaGVKYzRYdHlwYU9xTEpYV1B2UXdTQ3ZGNmxvS2dnT3l6ZFFIQ3c3bEFDRXV2WFFsblVvUUpkZXVoNmw3VW9RSmRldWg2bDdVb1FKZFNCMlFkU2tDb1FNMCtxeVNoQXJOOWxDQkwrcWtEZERYZ2JLQmhnNVp1aExJTmxDQkxyS2h5c2h5aENZS3pkUlhnYktFQzNYbEJUSENoQ1FLeXNCWlVJZmhmaUlDcnJjcXp4SUJWMjIveVNQTVpOOEE3YnJ6TE1VZ0xrcUhkM0tzUlhCWGcrUVZSU2U4Y0ljRk02bmUwZExweU9YdXpZcDZDTnRRTDJ1VmlhdDAyYnVDTm9zbzN4aWxEQVJjZ0xYc1VvM09EamZaTnNhOWxhMW9jQ1BtbGN4VnJxYUVpOXJoVWRMeVd0Vnd1RFhxU2lGUmlVVUlON3ZhUHhYMkYyVTRFN0wxSFR1cHpiVTFyanArUytYK3l6QVpjeFk4MTJra0N6cmtMN0F3QU93YWhpYTgvQzF2SHlXWDFPVkw1aXRNcllQTndmVkVPZSs3dlZhN1NUZDNFNXJ4c0dubFdPTFlrNnNxRGE1YmZ5VlhYMlpFZWg5VjViRzl6TnpzaW1GVVJLL3kxRlNNdW9ncEtacEVoc3JLa3ArOGozMjI2cFVpOEVncXJDeWc1Njg2QU1jYkVINzFsamRUckpYbWNzVmtkWTdxY0laS1FDQmROVkZGK3J1RXZTVXJ0YVlqbGxyQlFqUUNoVkZFTEd5YlpVNkdnZVNYbHFpNG05MHJHK1NObXNZdlFYdlpVa2JuMDhsOStWdHVJSFdEeXFWOU9Ia20zMVcxaDVLazJBZ2M2cGthRGRKNXZ4VTRQUVNDOWpZaFdkSVJCSVQrSzVuMno0LzNjRG1NZUxsMXJBK3EwNFk3YUtjcEhJc2JyblluaUVqeVNmRWYzbzhJL1ZzYjVCSVVERExxZWVTNjZmcHQ1TEwxV1dPMUdSTmx4Uk4vVnRDZU10bXBhbGJZY2JJMHpiTUtyUVZzZGpaWDEwK3U0VlJLTEc2WXFaUDFwRjBuVVNFSy9HTklUbVpBR3hVdThBV0hDd0NXZThnbzZPSVpNaUc5NkVIK3F3OTNxZ2FEUm5YdWlOZnNsZFhxaU5kc2QwRkJrK1Ntc0lsN3V0WnY5cElNZnV2VWM1WlhSMzI4U1kwY3h2azdaaDd1OG9tZk5QeHR0WlUrQlRhNkJtOTFkUmNxdkpHeGlZekVOa3dHb1VZMkNPQXE3UmZUTWh1eWk5cUpaUWVnSFdMeURjcFo0MlRUMHNSZFFGaU5Sc3ErZG1vRldGVnNsQ3k0UHlVQU5NeHR0bkZVN2VDcjdIMjJMbFFScDRwOWdFb0plRmJVREN3dFNyWWRUZ3IvQzZRVFNzRmthS3N6YXN0WVVhd3QyWFVNSHkzSEhHM1UwS215VGhJWXhycmRGMER1akcwV1JsU1JVVm1Gc1kwQU5IQzByTmVGTUZPOGtEaGRObllKUFZhRG42WnRQUnYzQTI4MGs3RStjODF4TmpxWEJ0dWVpMTl1NnRjeFZabXJINzNWYkd3M3VRalRMc0VTamp1VlowdFBjWFNrRExsWEZLMndDTXR4Um1HbjNUQXB3aXhNQVJkS3IyV0tJeFFBQlNkQUFPRVdNcVVuSEtGc2xDYm83S1BkN2NJcDVSR2dXS0N6bENNamJKV1Jxc0pSc1VtOXB1bTJWUmZ1cmxGYkR3aU1aY2hOaUFXSDVxYmp0Q3JJdlJFYlQzNkp1T0RmaE5SMDRVczdSV0duOUZsc0hvck4xT0IwV0JCc2RrbFNIN2VDcGtpVUh3Z2poV2N0UHZ3aHlRSWxJVkpGV2FhL1JLejBkK2l1U3pTQ2xaellGR3BDV2pYNVlBMjZUa2pzVmJUamNwQ1Z0eXJaV1lucEtLVzdCUzBMeDZMb0RNQUlyUW9EZEZhRndFbHlweGk1VUFFMVN4M080U3JPVU5RUm15ZHA0YnU0VTZXbjFXRmlycUREYkFHeUdUSDQxeVY4elEyUDdrT2piZVFKNnVwdExiS09HMGhjNGJLaE5tcGpSZjBnTHRQeVYzUTBybldTV0dVdXB6UVF0dXcraEFhM1paak51SktocFNHaFdkS3h6SEJHZ2dEUndtb29MSGhLa1dVaXl3Nm9jMjI2MnFnckNXamRhbFR0MGtXQ3U2T1F0QVNXY2FOa1pQcnNtR1BzRlUwa21vaFdBZFlCZFpYU0dOZDBTT1hkTFJtNkxHRGRBeHFSWVJQUjJ2U3NMZHQweTFvODBMSElZSTJDd0I0bGxoOVVWcmI4SkFUTXNGMUlNM1dMMktPMFhBUU1Ca1dNM1RMR0tERzdwbGpVSXRrQTdVVVprUFZURk9CWXFZMjJSQUdBUTFaTGRsTHV3Vml4VUlMeU5Tc2pkMC9JRXU5Z0pVSUp2Q0JKd1V4T0xKSjV2ZEdkUXJVSGRKenVMUW5wUnlxMm9tRzRSSTVKMExTU09OMGpVVEVKeHp3UWJxb3I1dEpOa1pVbTdBMWN3WXcySVdzWWhVTzFFa215YnI2eHdmYTYxN0djUkRZckErS3l1d1JUemZBcks3Rk1TYTBrRGNyZU93SHNlcisxZk8xRFN1WTltR3lPMHlWQkhoYnVCditLMHZLZVZxak4yTVU4RVVMNWkrUm9JYTBtd0pYNlU5alhaN1Q5amVTMlVqSXcydXFHc25hNWhCQXVDZDdmOFMyOU5Denl1cjFEWEJ0K1hNQW9NaTRGRGhPSHhNaWtwNCs3ZStPLzYzZTZicFpETkVBOGFYZnNsTERVWGQvTWRVajl3UWlTUzJZSlA5YWRpVjZiREJVZVh5emNtR0w3RlNEMHVIWEFKS21IYmNvck9VRzFxWWRkTGh5SUhjYnFXU2d3Y3BhZ2hBckljdTl6Z1lPUkduelFBNFd2eVBORllkVzRYV2NrSEcvM29yWW5PaU1CTzc5N29MRGNpMzFUc1VUekkwdmNMOUhFN0JKa2NnclpHQndtamRFeHZjZDJMUGs4MW9PYnUwS09rckJnbUdFVmxjMTQxdmkrTFNUYitCWEMvYVQ5c1dqeVhqRlBsZkxqcFJpdFZKN3ZJNk1GNDFXSjZEMEN2dXlJd1pIeTBNOFp4bmlkaTB6SE5rZHJEWEd6YmpZM1BMaWt1Vkd4aXdPUzdIMFpnVktNTndmdnEyUzduQVBPdnBjWFd0NXo3WU12WkN3eW9ySnErQ1I3RzZoRVNibjBYeEoyemUzclU0NVdUNGZscWVXbmhhWFIrTnJyWEczb3ZsN09QYU5tWFBreGJXVlFramNmRmNFZnhXZlBXVWVyNlI3S1NuSlBMWGY4QU03WjdTWHR4NHZuNm9td2pMVUU5Q0hPc0pZQ053VHh1U3RJN0NmWm54UHRQcmhqZWJNVWRoOEhlWGMrckcxaWIzMkI4bHpMQWFDZ3dLcWpsTVR1L2pJZHFiNmZjdWk1azdmOEFOR0tZSWNNdzJyTVdINkF4OGIybTVJRnZNZXF5c21zZG4wQ2ZzbkhZdkJTWDlXZlRtYy9hUnliMkE1V0dYTXAwTkxXNGgzWGNTMVZJVHFKdmU1dVI2ZEY4VFp6empqL2FkamMySTR0aUU4dE5KeFJTMnMwM0p2c1A0OUZXVFlOUjFGUzJ0ampMYTE1MVRQUFUvd0NMSjZHRjh0VTdjQjl0eVVwNnB5TFdoOW40NmIvVVNmOEFWbFIraW5pRjBVVXZkUkhsZzRLc2FiQ1ltVS82dG9hOER4T0hWUE1mVEdxYXdzZDZsTGtWTEpaZTdkYUhxUFJKbEpzOVhEQnBzZjhBcHhveERCK3FBNzhOZU9xeXlNdHZxZnFVWkJCTkMwUXRMWnI3a3FGUUh4dmEwdUIyNkpHMXRqSlpzc1ZTZkJsOHhjN1MwYmVhaEwzVURkVDNnSDFRTVJ4T0tocHdRYnlFY0E3b0dXOHE0M242c2pocEtPZC9la05hN3VuRVhLZEhEWm01YzBlK1JncXJGV3VCSWNIUEd3WjVxNHlmMlc1dTdUc1JpcHFQRGFxbXBuT3NabXRGcmVmVmZYUFlEL0o4VkptcHEvT2tjRlZHOGg0RFhOQkRUdmJjbnBaZmIyVmNoWlI3TE1OYkZSUHA2UmpHV0lmTXdma3RqRnBFKzU4KzZoN1I0OHFjTWFkL29mTFBZRi9KK1laZzFMUzEyWVh3NGxLRGN4enRON2dlZ0Mrek11OW4rQ1pYcG9vc0xvb2NQN3RvSDZ1L1FjN3JtbWVmYXF5Zmtac2pKcWxrNVovNU1vZCs0RmZQbWZQNVMzTEZBMlJsREZXZDZMZ0VOY1IrRFZwZUZERXVEd1dTT3AxczcvNXlmY3N6ekNScWk3MjMya3JWNHJSeGo5ZlZNaHQ5bHhYNWI1aS9sSTgyNGpyR0VWczBFZlFQamY4QTNMbW1MKzJGMm81bmU4L3BjV1A3VEhEL0FPcFZaNnp3blJldyt6T2ZPcmJYMVAyQm16Ymw1cncrYkdLZGhidFlrL2txNlR0R3kxSEtRY3cwekdnK1ovSmZqSlAyemRvZUtOZStURTJFWDN1RC9hVlZObjdPbFkxNGRYTTI1MlA1cmkxTExXUDJUMWMxZHI2bjdYczdVc3JWRS91OVBqZExWUzlHdEp2KzVYYkhHc2lFN0RjV3UyM2t2eWY5a1BOdENNL3lPelk4U01qaDEzMWFSY0J4NjNYMy9nSHRVWk5reFNsd3FsYkk4YVF3RnJyamF3OGxkeDVkeXV6enV2NkhxdEpLbWp0TEluZDNxTFRleUZKRTlyTzhaR1NUdHN1VVptN2Y2ZGhES0R2R1gyM0IvSkpaSzdXY1d6QmpNdEdjUmhoWTFoY085ZHBGN0h6UG9yU2xabllkTEovZVIyV0prRkpFWDFValkzYytKVnJNMVlGaU04akc0akJHYWMrUGMvNDZyaytiNU0wNDdVZDNCanRBR0VXM21iL2FXaFlMMkVadHBxakVhaVhITU1lS3ZjQnM3TDlQNmZvdWJ4endOZVI5TlNaaHdPcWFTTVdnRVkzNVA1SktQTytWWlhGamNkcFhPQnNRQ2Z5WEc4QjdBOGI5dzdxYXRwSkNRUWRNalRlNC93Q0pld3YyU3ZkcWgweGJDU1hGeHM1dm44MTNlVnB3Mm5iUmpXRDFJL1VZakRML0FNSlA1SXJHeHpDN0pRNGVpMGpDZXh0dUFCdHd3VzlRdHp3M0QyME1WcmNEb3B1S3o0QzhMRHVWbTRKV0hjcG9CaFl1RjY0VWJxRUpYQzljS04xNjZoQ1Z3dlhDamRldW9RbGNLUWNoM1VnZGxDQkFWbSt5ZzArcXlTb1Ftc2h5SGYxVXdicUJrd2JMT3BRQldicUVDQXJJS0cwK3FsZFFoTlpEbEM2a0RkUWhNR3ltQ2hBcVlLaENZTjFMVWgzVTFDSDRYNGl3K3FSYTBnSzR4Q05WNWpzRXVYSXpHQmFkeWh2aklPcm9wa2FTVVNJQ1JoVmlEcUlFbGJCTWIzMW1xNnd5ajdoaDFYM0Z0MVNVdDIxTnJYRjFzVXNtbURZYnJ6R3ZiY2pkMFhFU3JrcG00ZlhnNmliNzdxaXpaV2lyRWJHMnVQSlN4U3NtaXFPK2t2cGI1ckdWOE9kbWZFdERkd0hJWWZDaFM3bldmWjJpWkhJeU56RzZ0SjNJMzRYZnNVcE80akhJQkYxeWpJMlczWlZxeEphd3RaYjdpdVBHcExHaS93QUlDODdyM3UrcGV4SUxGR3h0M09BKzhLZ3g2cGprY1d0ZGI1SzcxQTBaY1RZMldyVkVJbW5KTWc4MWlZMVROS0FvMWptdnZhNDlVOEh1bGowdEZ0dWlqRFo0SXR4c3NNbTdtVGNkVnd0QWRMNlovaXZiMVR6SXRjekNQSkRxM0Nkb0xSdmRFb3BDWlczSENCb2hZVm9FZE93ZWlXb2JGdkFVc1FrTHd4b1VxV0lzaUJLRWg2Wm9hb0JvY0NzVlYwdjNwWTBxTlgyT3BpbGZJMk54Q3JxcHplNklISldNV2xjNXhJVkthMXhtRFNWZTA4SGFFNVpLaDJycUcwbEJNNDJIaDVYemgyZ1Zqc1J4V1FCNWNMZzJ2NnJ0V2RzWWJTWVc0QjFpV3I1N3FhOFZWZTV6dDcrYTlqcFkvQ1lPYVhKT2tZV3RBVmxTVWpnNE9zbFlpQzl0aHN0aHB3d1U0NHZaYURLTm5tUHN5eVhySnk5aEhDSzE0RGo1Skd1bmFRZE5rVVk4a3NyaXdkNFRjbExWOCtuWUFjckx5NEVsTHl1RC9pVitCTE1hdGdWZ3V1RkV1MnNFUFVnQ3NrNElUelpHSEJTc2pqZEN3MHpHbythSzBteVcxYm9qWGJGQUhZUmt2NjBJYjMvNlhFUnR1b3hqY24xWGkyOHJYZVJYR0N6c0dVWnU4dytNTFphVi9pV2xaRHFPOWlheS9BUDdsdDhCczc3MVhrYXVsZGx3eDQwaFREcnBXTjJ5T3dYVmRvMTJFYmRaY05sbG92WlpjTEJDeGdzOGJvRHBQR0V4SU55bFhNT3U2WDVrRTZ6eE9hc1RSaHRNVDZGU21GNVdvT0x6aUNtSSthYWlHaTQxS0M5Ky9VcW9qYmNteVp4R1F2bGQ4eWh3TTJSQzVyZ1lwbzd1Rnd0dHdxbWF5UmhXcVJQREhqNXJac01xQVhNOFNOR2JOY25Yc3JWTElZRzc5RnQwZFkxNDVCdXVaWUpXaU9Odmk2TGNjTXJvM3RGM2hFSUxlb3JHVUVUbk9QcnV1SjlwdVkyVkd0algvY0Z2dWNzWi93QkdjSXp3T2k0TG1TU2FxcUg2cjJ1Z29ialZHcFBIZXpFOG9vaHVqZDAySTcyUldNdVZLTkxHdURGTkRibFdzTWV5UllOQlQ5TzY5bEtMRkJtdHNwMjJVbXMyVXU3U2cvSUNUWW92SUNpNkkzVWJrS0MyWkxGRXRzczZsNEc2Z0ZBWkhiY0lCYVNlRStZMmxRTVFCNENJVW9pekl2Uk10Z0l0eXBCb0I0VFVNTG5rYklXdzFFeERGZXdUOGRDWEM5a1dtb1R5UW5tUjZBZ3NOUkt4OFZ1aXcyRStTZWRFQ1NzaUlBTGlMRFJYU1EraVhlMnc0VmxQWm9QQ3I1SkJ1alJYbEVRbmI2SkNXTW0reXNKWFhLQzRBZ28wVjNFbzVtYzdLdm5adndyeWFFYnFzcVk3WFRpcXl0Y04xZ3QyUkh0M1VDN29vQXlBRmtWaUdCZEhqWmNLQWhJRzc4ZFZhMGxPWkhDd1NsSlRsemdGdU9DWU9aTEd5T3pqWVRDOE9KYUx0VnlhY1FSN2hXZE5RTnAyYmkxbFY0eFZ0WUNCWkl5UGdzWWxiS1BFRHJrc0U3aEVGOU95UWEwelNjTGFjQnc0dmN6YnFzdkkrVGZ3dzRMN0I4S2NDMDJXM1V0SG9ZTnZ3V2NNb0ExalBEMEN1VzAxbWpaVWpUUWhIRlk4SjFzT3cyL0JHaXBibTlrMjJtOUVMRFF0REY2SjZGdHJMTEtlM1JIRWRrQWFIcWUyeWNCMkNScHpheWJISG91TVFFYVV6RzdoS05LWWlOeWt5Q0g0aVNFY05KODBDQnBLZVlCWktiRFFRR3pRandtNkNSZmhIcDJGSUlGTExvall5TElsZ0J1c05sRjFBR1RZTGRFdzAyVVlyT1RMSXdvQ0ZaR1MyNjlGRDQweEUzWkZqajhYQ2dBT1NHdzRVU3owVGN6YkFLQmp1RkNGZkt4SlNOc1NyU2FQWkpTczVVT2xkS2RXeVVraTJKVDgwZWxKU3ZzQ0Z4STYyVnRRN1JjS3BxSWlMbmRXMVMzVVNxdXFtc0ZZaVY1TVJsZm9CM1ZIaUZVQVR1ckdybTJPNjFqRXFqYzdwNmkySmMwaExFS3hvamRJMDNrSEFXbnREc1V4RVJ4a3VrTHJhVTdpOWI3dldOakx2QzRYSlhXdlpxN0hwYytacGJpRWpkTkpSeUNTUzQyY05oL0ZibW54Y293ZFhxRTR2aytoZlpBN0Y0OHVVN00xWWhUQnhuaWRHR3lzMU5CMDlMLzhTK2hLaHdlOTNVQTJIb0ZpclpCaGRLMmx3NXJZNkpwOExZL2hTb2t1T1Y2ZkRDa2VKMUU3a0dKQkZsRy9taDYxNE9UWklSQU5maFNCUWc1WjFJaVN5YnVFR0JVMmxBRGxOcHZaU2lSZ01OVXdOdDlnaHNSMkMvS2xISjQrVE1ESTN3dWhoY1hzY2QzSGtGTVVaaGgxUjZ5U2RqZEx1cHlKbXhRbloyNUlWcFR3UnpON3RyUnJHem5Eb2lsOEhjN215dVh3eEJOYTJONVkwMzhycm52YjcybzAvWmQyWjRuVnVtRE1RWU5VYlhiWEZpZnlWN20vdFJ5L2tSazFKVjFrRHF3QXQwdUoxQW5ZTDgxL2F5N1JzWXpQMmtVdUdtc2xPR1ZFYmlXYmFiZUczNEZaZWZVeFNvOVAwWG9tWFdUVXE0NE5mN0xjUGt6RDJnWTduYk5KYzJLR2IzcWtEenJhN1pvNjdlYWwyOGR1V0tkcldLUzBGRkthYkRHdUQyKzZ2TEJ6Zmh0dklLb3pGbkFSNEpRWWJTeCs3Mlpva2MzN2U1V3J3VTdLR0VPYXdPY2RyaGVielp0emRNKzI2THBDMGFUbEhudDVGWlI0S1dPQmRkenVwUEt0RzBvaWJzTGZjaUFrYjJYdFJkeXM2MmV0amlTOGdXd0p1QWZ1WG1zSDdJQStTbWJlaURKSVc5TmtTSDdlREwzTWI1QlFhMWpqY09JUG9wUnhpWWJteWhMRzJFL0dFUWlVVFBqSnV4b0pIVlFkSk5hejJBQkxWMVI3dVFXU1hiYmNqb2xuVFZsZHBpdytGOWRNN2JSSHpkU09Cb3FaTStIVHJkR1FlZVZsUGR4TmxVL3BZVmMvY1VMdS9yU2ZCR2VxNjcyWWV5M212dEhraWt4R0twd1NuZHU1MHpSWURrOUN2cWZLUFpQMlg5Z0dIQ3J4dXR3ekhhK01CK2lRdUR2TWpnTFJ4WTY3bmt0ZDdRSi81V25weTU4bjNPQjlnL3NSNW43UmFxTEVzeFVVOUxoN3lKR1BacUlMZVBUMVgzSGwvTHZaaDdOT0Q5eldUUUdhQnA4VlJBd205cmNrcjVPN1cvYjlrbmprd2JLbUJ5WVhCQityYk5URVdJNXZ1NCthK1djeWRvR2JzNVZEcXZFOGJxWllwTmpITGEzN3ZWYU1aUlNQSHo2ZnJlcHozNnBiVitUUHVYdFEvbEQ4TXc5dFJUNVhtcGFsN0NXdGI0Unh0MEJYeWIyZysxRG56dEZsa0VwZlN3T096cWVkdzIrNEJjeWZna0x5SHQwdWNkeVIxS2ZwNlB1V1djN1NGV2xsdnpOblNkRzhKcjRTcWRGVTE3eSt0eGF1ZTg5SHp2ZCs4bzhHQkJ6Z1gza0htN2RXMFRZbS93Q3JFaDgxTnJqMEZsU25PejJlbTBpZ3FvWGp3dUtJZnpiZjZvUm1VN1c4TWFQa0VRdktMSFlxcksyWFhwcjdJd0tjQnV3SHlzc3h3Z1gyRy9vcHN1U2lkMlJ1aVVoN3Bxa1ZWWlFUQ2JWQk5MVDZqWno0bkZwdDl5NkprSE1PRTVGMFZNT0tUVk5TQ0hFVFBKMzVJM0pXcE1BZnNRaHlVY1lkNFdBL0pOVXluazBuaStSMHJIZmFqekNYaUtocEtlWmdOZzRrWC84QTdWclZaMjk1enFTWkdRaW5lZVRGSVduOEFxQ09uamliYzA0djVxYmFWdFU3WTZCNUkvRWZxVW4wZmR6WDdGbEgyNTU2RHI2cGIvOEF6M2Zrck9nOXBUUHVHU05kZVJ3QjRkTzc4bHJ6b1d4N2FicndoWThieGhBdFQrWllmU2RMa1ZKczdYbGoyODg1NEtJMlRVOEphRHVYdnY4QS9TdTFaTC9sSGFTU29oanhXZW1nQnRxc1c3Zmd2aWFURGFkL01iVlhWZVhZeElPNnB3Ni8yZ3JtUFYxNW1IclBaWEJtVGF2Nkg2K1pQOXBMSXZhRFRRdWd4Z09uY0xsclNPZnF1aXhWMFZaVHRGRTd2V2RIRmZoeFN6NDlnazNlNGRpMDFLV0craU8zNUxyUFpqN1kyYU1pNGhGVDRuTFZWekdXdnJMZC93QVF0WEZySStaNEhYZXgzZDQ3djlVZnJZSWZkM2g4bXp2SlFsWk9UckxMUmMzWHo3MlErMnJsZnRFZ2dwY1NkVDRWTTdTMjhyamZ5dnlWM2ZETVp3N0dJdTlvTVRpcll5TGhzWjJ0OUZvZThxYTRQbnVyMCtxaTlzb0JHeVJsNWRHNHVKNkxCdWpWVnBvUXlPSHVYZzNKQ0dCWVc2cGtiZkpuUXdTaTdtWUY3cjErVjRxQlBLZXAwVzNQRkR1ek4xa0hkUTZyT3BDTDNCTCtoWGc1UkJzczZsQ1dUdXBCMnlHQ3BhbENXVEhDa0RaRHZaUzFLQzZvbmRldmRSdllMQUtJTGRRVUZFdWd0S21Ec3BaM2NFQldVTUhoU0JzdTJNM2hBUXBEbERHNm1PaVd5YnJDTlUyOEtEVk52Q0JnTldmaDlYTktVMCtGWGxUVGVIaFZrc2RycVErSWEvaEt4N055b0Q5VHNFZVlBRXBlTm42NERtNjdrbHRRV09PNWxuaGRBS2lUVVFyU3VwR3d4bmNiZXFhdzNEZzJtMStsMVdZcEpxZTV0eXZQWi9qa2JHTDRFYWxtbVpsUmc5UVdpem1tMi8zcmJleFBEeFJpU3BlTjdYL2N0S3gyenBPNFliNnQ3THNuWlhsNEdoYTUxeDRlbnpRNS9nUW1ITE9tZTlERXFScjJnZzM2b2NER3ZrR3JZamJkV05OREZEQjNMVHVOK0ZXVk5EUEtIU3RhUUdtMnk4em5lOW10aWp3VHhhcWREVGFXTzZMV2FWMDhzMTlRc2pWRlpKTklZVHlEWk5VVkFXY2dyUHJhVzF3VGplSVNCWllxU0hORGdDbUh3OTBia0lVMVFOTnJENkpkRHJQWWZJSk5qNUoybnA5TDlYcWtLVnBlZGdyR01PdFlpeUJvbGtYeDY1bWpuZFdFOGZkVTdkdXFqaDlHQkpxTnluc1NlSE0wdEE1UVVTeW5rSWNGVjFjd2JjQldsZEU1c1JzTExYSHlPYktiNy9OUGhIY3dIS2hlcWNIdGNYRzJ4NVdsMTJJZDFWWGFlRDBWem1ldGNHT0RUcCtXeTBXZXFraGllWERyeVZ1NmJCWm5aY3ByL2FGanJwb1d4aDEraTVyVDBoZlorMXlydk5GZTZvcWlPbDFYMDBlcU1icjFPSEhTTVhKa3RqdEhEcXNmSld0TzRrNmVpcmFHS3crOVdWS05MMHhMa1R1R1pvTkVaZDZMVmFxZDBjanIrYTJURko3UmtBclY2aDJvbFdJd0p1SXVyYngyU1pKbGNTaWFWZ2tOUGtyS1ZFM0VXdUpOaWlBS01qd0FnbVQxUzZEM0RCY0FDRWxJN2M3cUVzcDgwcytUMVF0QktRYlY2b3JYYkZJZDV1aXh6ZXFDZzl3NUc2MFpXQSt3Y1VPSndNcmZKWWwyY3VOSFd6Zit6V3BMcDlKUDJmNExvOEFHcGNtN1A2cnVxKzNHMWwxYUVHelQ1aFY1STF0S3l5aUhDY2lac2xxUWJCT20zUlYyaldiUEJaUENpQXBhVXBqeGVUa3BkN2s0NWlVbkhqUy9NZ2lRWFREYmE2ck0wZUNuKzliQXhvTGhzcVBOc1JkQWJEcW14SWMrcVczZVNwUml6UHVVcG5XSkNoRHU3ZEVObkhnWGxtTFgrU3U4R2xlK1J1NnBzUWcxRzQ4MWQ1YS9uV0FvMFpXVlViclNPa1pFMjNrcnZDcWlja0FYM1FLQ0JyNG0vSmJiZ09GTWxMVGI4RVJVb1ZPV1pjVFo0bTN1RnJ1TzltaGJHNTRZQ2ZSZG93Nm1FY1lhV0Q2TE11R0NaeHV5NCtTRzBOaTZQai9NZVY1cUtZK0FpeDhsV1F3NmRqc1F2cUxOK1JCaWNiOUVJKzVxNFZtckpNbUVWRGk0T2FOeXBhTHVPUnFza1lGazNTTTJRNWFMUzBiblpTcDNkMjBBK2Fsb3V4ZGxpMXFPeU1PQ1g3eGhBczVGaGtBUEtTY0Rkd0NDbFhRV1BDc28yOTRCWlRkU1g2S0hhS2QwQjhsQXhFZENyNk9pOUZpU2dCUENoTnBUTWlMckN5WVpSbDNSVzdNT3NBYmZnaXRwUTNvcFpFa1ZBdzdlNmRoaEVkdGs4S2RRZEZ1Z2JEVVNjVW9BVW52QlEyUkVMTDl1VUZocUtJV0JLeEk3UzA3cVFBYWxLbzM0UklOMEsxVXBKdDBLRDd0cVJBTG56VXJPWjBSb3J5b1ZmUUZBZlI2VmJNSWNOMHBWeXNaZmRNUlhaVFZER3RCdVZUMVlIbXJLdjBQdjRpRlQxQlpHMDJjU2ZWTk05aVVvRzZVMUVsVGZJNTdqWlNnc3pia2xRQTlDQ1Q1bFdNTk80MjhKK2l1Y3NaVWZpa3pYYVNSZTY2WkQyY0h1Vy9xejlGQVRtbUZVaGRNM3duNkxxR1hjTmIzQUpGdGxPREpyYU40OEg0SzZheHVIVXhKMnNFTGtjakd5cXhoemFkamhjRGJ6WFBxMm9NODdnRGNYNkt3emRtSHZKbk1ZN2s5RlhZTkE0dUJjTDNOOTFYbkxnMU1FT1Mxd3VpMTJ1RjBiS21FNnRKTFNxREFNSGRVeU5PbmIwWFhjdTRHSUlXM2JiN2xtVGZKNkRGR2tTcHFBTWEzYm9tRFQyNkt5ZkVBQUFGRmtHcm9xMWowSnd4ZVlUTEl2Uk1DQ3g0L0JHRGRoc2x0aElXRWF3NXRreTV2b2hQYWdzTkVZTmltd2R1VW1CdWp4cmpZZ08wMlRWS0x1Q1ZhalJPT3F5VkpoRjNBd1dDSzUxalpMMFpKYUUyNWhQUktiRFFhT3h0dW5vSXdHM1ZkREFXRzl5bTJ2TFFBbEFXR2xkWTJDekhUWE43ckRIaHdVNlpwMWZlb0EyTlF3MlRrYk9Fc0dteWJwMm00VUJzZWhpMlRNVVc2ZzBYQXNtSVdFQzZPZ2JJVk1RQVF5Mnc0UnB1Vmh6YldVb2xpVXpkdUVqSzJ3VnRKYTNDcmFwaE43QlNpV1ZVNTFYVmZQSHNTckdhSTNLUXFJenBLUGJRTmxSVlBEYmhVZGFTTHE0ckcyY1Q1S2d4R2J4NnZKTmdpdmtsU0thdm0wQTNObHFXSzFaYnF1Yks0eHlzMXVhUWRoeXRQeE9zOTlsTUpObURkcEhKSzBjZU96THlaYUNZSmwyb3pwakVXRndNTDZ5WTJZYlhIUDk2L1Nic2N5QlRkbU9SS1NDT1B1NnV0ZzB6a0VibS85d1h6dDdHUFpVK3RuYm02dGd1S0tiUU5UYnRJdWVmNnErdFpxaHRYSk9PR3QrRURnTDFHSERWSGpNMm9jdUFFVWhwYVlVcE4yTjRBWGc1UWhIZHMxTzNKODE2L1ZhOEZTTXFYTEM2cnFRUHFnaHl5Q1ZKSFlqQUt6ZjFRUXN0NVFJREhBT0NqTjZJRFV5SDl5eTd4WjNSTTRSM0xrMmNCbytsMHkxdHR6d2xhVmhxWGFqc0J4WldzZEpVMUEweHhnc0hWSWxrU0Y0M1BKelJtSXRiWjhBTFNQM3JSZTJ2dGt3YnNaeXJVVmtrN1JXMUVSTGREd1RxdjVENUluYXoycllSMlE1VXE2NnZxV3cxY1kxTlkrMWlMRTlWK1ZYYkgydzR2MjNacHFESk04WWZCTGRuZHlHeGJieSs5VXRWcVVvOEh1ZWk5Qm5yc2l0Y2ZvQjdRdTFyTVhhaG02Zk1iNnJYUnpFRmpYQWh3SUpQVStvVmRpT0pZcG1hV0tvcnBoSlV4TkRJM2NXSDE5QWhVOUF6RDZKa1ZMK3NzZUNFd0xnRGF4OUY0L1BubEtSK2hPbGRJeGRQeHB0THN2S3V4aC91cjQyZCt3dWxqSElRbzNFVEdWMy9WanMxdlVGR05qMFVTQmExdHZKVjR0eTdtemwyNWVFakQ1bTlGaHAxTEIrU2lYSTZJa2tRbXVDc09MWlJiOTZ5WFhDRUFEL09FdEhvalNBazBpRHRUVFpwQ2JwY0FxTVRMUUxlSTJ1VXNCVHhFT1pJWE84aXJDbXpUVzBBdERBeHc4ei83STBpak9hTjZ5bDJGT3F0TW1KMVZLYVVtN21HVm9OdnZLNkpRWTcyUmRqclJLM0RacE1VYi9BS3lGd2NOWDNNWHpsaW1Zc1h4SUZyWjVvZ2VrY2hIN2xUeFlYTksvWFVUU3luLytSeGQrOVd0eVJnejZiazFmYWRJK2dNNysyN20vRklwS1hMRmMra28zWERXU3NkZXg1NmpvdUJZL2pPTlozcUgxT016aWVvY1NkVnZQNWtvejZjUjdNWVBvcEFWQkg4MEFQa2dlVm9YSG8rbjB2eE5xVC9Ueksyam9QMGEwc2VMOTRMTnQwVElnTERvcWZIQU9BUE5NRmp6YlcxWUxtWHM0cGZqU0xtTnJzNFVnVEkyTVA2a2FmbXNtTnovNTNjZWluM2NiVGRqaVZrT2YwQUlYTnpOTnh4cGNVZVlZNFBnQkNJeHdkMFVBelZ5TElqUjZJYkVxYVQ0SkZnSVVtTUlYbThxWVhDNUNhYTVQU083c2l5S3lYV3pxbzJ2MHVwc0hwWkp0bkZpb3pHMjVSTkJpTndzTkc2bmJaVGNXWTFFejNza28wazdMTEFJTnp1ZlJaYU51RksxNzdLYml3c3NWeFJsandlUXA5NHdkQ3NBV0NtQUNPRXJZeXhqVVgvQlJnTUVvTmh2MHVybkt0VFNZZFZOWmlyVEt3bS9oOHZ4VlUwVzZMRXJYenZCdGEyMXdvclFyVWFWNUkvQzZPKzluV0M5bCtNVkVyc1JvWGFqMWM5bzh2TnFQblgyWjhxNTd4YWYvQUNXTkxUWEZ3WloyZXZ5WHozVTBUNW9iUlZNMFRyZjZ0NUg3aWo1ZXgvRnNwU2g3YTJwZFlXdStaMzVxNUNiUjRuVjlHMU01V3N6SGM4ZXlobVRKTmVLdWxxS2FUUUxqdW5OY2Z3Y3VqZXk3Mitaa3lkbTZQQmNhZkxGVDk2SW1sOGJtdEkyT3hPeTFlaDlvSE1GSldSelBwWXFtaGoyZStZNnYzZytxK2lNMDVCd3J0d3lOaE9LNVRpWTdIYVNIdlpvNldNTThkeU55MzVqb3RUVFpMbDNQSjliMCtQVDRxZU8yMTNTUHR5anh1TEhxTnRSUXUxQjMyd2JnajVyemdldDc5VnovQU5sN0Q4Y3dIc2Z3dWl6WEFhWEVtRW1RT0pMdmhiMUlCODEwbW9samVTSWJPWHFzTW91SjhXMWVUYk54U29TY2JLSE43STN1cGVieVhhUFJZZXhzWHdIVjgwY2t2SXFMQXN2TGtBdlpTQnV2QUdVN2l5a1d0WU50eWhPMGVCV1ZFT21Qd3NCQ3p2MUNoQ1FLeVNvTHloQ1lLa0NzRnR3bzZUZEV3NUlLRGRlSEt3eDVieUZMM2hzcHRGWnhRTmxmekpOVTJtNFVXeE9JL1dEU3ZPWVcvd0EzNGowdWdzYW9OazdXV1dtNmdIUzZTYXRvaThyZVN6dENBNG53TzRLbTQ2NHRCQVVVZEVCd2RGR0tob3ZHNDJ1VVZwdUwrYTdkZ2RnclVRSUxVUUc2ZytQSitMOVd3YVNxS3IydXRrckkvQ2I3TFg2MkltOXQwT241Q3pjRkZVdkljbmNNb2pVRVBQUktUeEV5QVc2clo4R2lFVUlGdWJKT3JsU0xXa1ZoWTY3dVkrNjlMTFdzdzFCZ0xuWDUyVi9XUWhqeTlhZm1hcTczdytxeG9mRXpTeWZDSVlOVHV4REdvblAzYmZyODE5QlpNWTZucDJNWnNMVzJYSjhoWUM2dWxZOE4zdXZvRERNQUdFWWF5VWdBNmJwZXVkUjRFWWU0djMwbFBpSkxpZEoyVzJDdXBtWVE5cGEzVWQxcmtNUDZWWVpBTitkMGhQTElMeDlPRjVlN2JOdkd1QlFRaDliTklCdHF1bTZlZHpxa3RzYktGTzlyQ1FlcWFZMWtUdFlCSlBrazVWUTFrcXAyb0Q1SmNVaGszVEV3M0JUVktMTjNCVmNNaFEwWVlSZE96OTJTQXdDOXVpaTA3RzNraDBFQmRMZHg2b1dRZGppY3lLNEhSUmpHdDNpL0ZPdm5iSEhwOGdxNlNYeEVqcWdJQnhLVUdNaXkxS3RrMGx4c3RwcmkyMWo1TFdzVjBNamNmUlhNQ3RsZkkrRFE4elZsOVczQzVyanVZaTJON1ExYnRtZXFBYy95WExzYWZFNHYyWHI5TGo0UmlacG11Vk14cTZrbTNWTnhSNkdCQ2hqYnJKQUtjTVpQSEMzNFJwR1JPVHNQU20yeXNZUmJkSlJSV0k4MCtCcGl1cThWYkdXVitKeVhCQ3BKQmNsUDRuUDR5cXlXUlhveDRKWklOQlFwWTdGWWJQdXBQa3VFVFZFc0JLbDNOMlJKWDN1bHk4cFlWZzVrbkk2MTB6TEpkS1NjRkMwR21DTXB1cHNsc2dPNVhtb0EweXlwWnJ5dFRWdzl4VlRUdjB5QTNUTVZUNHp1dU1OczJqS2tuYzRrRjJXQi93Q3BqLzRRdUQ0Slc2TVNidjFDN2JUVEUwMFJHNDBEOXlyeU5iU3V5OHBaVThIQWhVdEpKY3EwamRkdktyczFtTk5jaURjSlZycmxIWVNxN0xSSnpiaEp6czhhY3VnVER4SmZtUVhqSGpDVnpEU2Q1U3VOazNGL090K2FkeE9BU1VoMnVtUkljYXJLWXNrZjh5Z3dNSUsyVEY2SU1lNDI2bFVza1duZ0l5OWtYQmgwSWxCMlRPRXRNRlFQbW8wbTVzbVhON3VacEFSb3hzeU4xb0ozbUpscjhMZU1xVlQ5YlFiclI4RWUxMU8zNUxiOENxUkM4V1JGRm82cFRQYVdzdGJnS3daRHFBc3Rad2VyTXVra3JhYUdVT2MwRXFsdUU3bVcyR1lLMnJiNG1nM0hWY2U3ZE1xTXBRNTBiUjhGOXZrdTg0ZlV0cG9iK2hYTk8wNWh4c1BienRaVGVQeHpaOGpWZE82TjdtMktySmc2TUM0WGNJK3pVMTFUOEEzS1BpM1loSWFmVXlIVjhoZFRlYWVPUncyRncydTVQUWxwNElLMmZHK3pDdHcwT1BjdUFIOUZheitpNTZONUQyT0Z2Uk5IajlQTVdiV1ZoRzdWWlVqcHpFQmRwK2ljcHF5OXJxREVYRWJVWVJhdWlTanFodFlweUNvRGh5b01TRGxteUc2TW9rVWdjN2xOdFkwdDVRTVRaWGhwQlV1N0I1Q2Jld0JBa051RUREVElhQUFsSjIyS2FEcm9jb1FXSFlnNGtJTDRuUFR6d0FoUGthMXAzVFVBNUNSaUxkMHRVVkJIUkVxNjRNTzI2VGRXeHlBN0c2TkZlVWlUYXF3TjlsWDE4dXR4OFN6TzR1UGhSYWJCWjY0ZUJoZGZ5RjBhSzdrYS9pTW9JczExL2txdjNlV1k4a3JlUjJlVnBPc3d1SS80VW5WNEhKaHBBZkU0ZmNuRlZtdTBtR25xMjVXeFpjeVRMaWxXMEJwc1NyZkxtREN2a1lOQk55RjlHOW12WnJHMFJTRm82SGtLQUd1NUk3T1dZZlNzZTlndmJxRnVFMkZSUlJrV0d3VzU0bmh6Y05oREcyRmhaYWZpTlFXYWpkUUUwYkdpS2Q3amJZTG4yYWNlTElYTWFWdE9kc2FiREZKWTcraTVSTlVPeFNwYzBna1g2cEZsdUVCQ2xoZGlWVHFmODkxdU9GMEFMMk5BNkpHandyM1RTUU4rTmx2R1ZjR005UkdTMHF2Tm1waGpSdUdUTUN1MXJpMWRDYlQ5d3l3QzlsM0NHMDFHMDZkOUtkbUkxRVdXWk44bXBGMFZydHlqUXhxUWl1VXpGRUxLdVBRSXN0MFdOQ1pld2JxQWFnWVNGM01RM01UVDJvVG1vUTBLQnU1UldOWGlBQ3BDeTR4Qk52Q1pnQTFCTE40VE1ETndsU0NMdWlEZEtmY0dnS3Rvd1FFNGJsSmJDUVdKK28ydDFUQml1TG9UWWhHQWRsa1RFYmJvUllScmJKMm1ZQlpBZ2IzZ3VVMUVRRkFHTUFjSjZsWmRWNEpKQ3NxTTdCUUFlZ1pxS2VheXpVQ25ad21YbXdDYUNMU011VmlRYkpnTnVFQWk2aEJWemJwV2RteFZrNW9za2FrZ0E3cnBDbG1JQktyS3FTd0tzYWdia3FwcmVEdW50Y2NDa3lrcjVSY3JYTVNONmQ3dkpYVmVia3JXc1hsN3FGMGQrVVdOY2xiTStEVThWbUJnbkgyaU5sWDVMeXhVWjB4T2h3eW1ZNDFESm1Pa0xlZE54ZS8wS0hqY3Bqa0JCdjZCZlVmc2E5bWtjTmNjM1ZVVm9haUZ6R2s3RytrLzJsdDRZM1I1M1BPclBwSEsyWDZmSVdVcVRES05qV3RsZ2pmSVdmdGFkNy9lU2lndWJJeHc0SjhTblUxdDVUQTgzSlBoSTZCQnFKeFRHTm5QZWJiTDFVVlI1QzJ3MVZMcmxJWjhLd0hiQkJlZTVkcEp1ZlJTMWJEZE9zNVFZT3NWSU8zUVdtNmxjcFRZRDREZ29qRUFIanpSMmJFWDIrYUpEY1R0REViYjliSTJoOFoxRnBsWjFLZ3h1MTdGT3htU2xoTlZJYjRleitjakh4SC9BQnV1WkpVZ0pZdkVra01RTmpqcDNUeU9FTWJCZHhQUUw1NjdlZmJLd2pzck1sSlE5M1gxRFhhZE1idHhjMnZ5RnAvdFZlMDlWWWJoejhLeW0yb29aYkdPWjBzYnRMdVRzYkQwWDU5bUNvemZpYjYzSG5DcHJYanhTRGcvdldMbnpVZlJlaGRCV3BTbEpjZis1MGp0czdjTVk3Yk1URXBsbXBxRXRMWFJralR2YjVyVHNId3B0UEVBeG9iWWVKdzZwdkQ4UHBxS25OR0didjNIa2p1MTByVEhHZkE3WXJ6Y3RSS2ZjKzRhRHAyUFFVMGdiSngzN28yaTdRT1FzRjI2ODkwVFl4SEMwdG5CM2NlTEtJNlg1U051N2szc21YeEkwanhObGdtNndUNXJCTnZWTmpHaXZqanNKRnFHNFc2ckRwcmRVQjgvcW9KY3laTzZ4TTVyaFloS3kxYlk3a3ZBK1pTY3VOeFJnN0dXM1JtNk5KbFhKbHBkeXlZMW5PeUhOSnA0VkcvSFh6TzB3VU5VNG5qVEU0L3dUZExnV1pjWHNhYWdxd0hjWHAzbzlyTWVlb2o2akxhaXhOeHBYbnl0Zi9yZ0ZhMFBZbG4zRmkwTWdsYnE0MVF1SDhWZjAzc25kb3RXME9Ha1g4NHorYXNMR3pMeWRWelQ0MGs2WDUxM05IRWpXLzYwRmVNNWIvckYwZVAyUGUwUnczZEhmL2cvKzVDZjdIbmFXeTVMNHlQUm4vM0lsZ3NxeDZtc2J2TzdmNUhPKy9CTzcxbjlXNzdZVzMxM3N1OW9kQUNYdDFXL1pqUDVyVzYzc1R6M1FrNnFlVWdjMmhjaTkyTHE2eGhtcWwyRTdNWnhJSElqWkhEaHQwakxsbkhzS3VaOE9xenA1L1VQL0pDanhXcWhkb2ZRMVFQRzhMdnlTSENpMWkxUGlQdVhEZCtkbE1CS1ExTDVnQzZOOGY4QXhnaE9OdFlXTjBweG8xOFVOM0pJQkVBdW9peW5iMVMzd1dsR2lRR3ltQXNBS2Jka0ZGMU96SUNJQW9qNW9qYklHZzFEY1phTEtZQ3cwS1l0NXBZYTA3Zlk4R3FiUlpZQVUyMjgwMlV1Q3k5UHE0Y3VTTWdmVk1VeEEyZUxmTkNZTGI3N0k4cm0xSUhkZ2dnVzNWUnpvN0NXUk9wc2hMVHVhL1cxKzNrRVZnamxiWjdRNzVyMGJIdGJwSkZsSVEyZGRSWmFOTEhIQkpmR2hTYUdOc2JubUVOaEhNZlFxd3lQMm1aajdOY1U5N29wNmgxRzUybzA3TFdJOHZ3VURHK3BxNDRubThCRzRVcFlaSjNpS053RU1leEI4azZHb2NXWWZVT2pZZGJGeDIvVm4yZjJNKzNuaEdOT2l3N0djT1poMy84QUpPNzA5SEZmVG1DZHAyVjh6Tmo5eHhHbWM1NEJzd25xdng1eGJLbUgxMVE2UVFuV053ZlZXT1c4M1pxeWJNMlRCNnR0T0l6NGJnL21GdDZmcURYRFBsWFUvWU5UdWVPbDM4MmZzb1lYU00xeEh2bUhjRUtEWW5PK05tZytSWDV4NUM5dkROV1YzeFUrTzFrdFJFUERhTmovQU15dnBISnZ0eFpUekxIRjd5MmRzamp1WDNIN3d0ekhxdC9tZk10ZjdONm5SdHFOT3ZTejZJRW5JN20zcWhpSHZYODJWUGxydGJ5dm1PTm5jMWNEUysxdFV6VnNiZmRLcHdmVFZsTVFkOXBXbitLMGJSNXQ0Wkx1aFdlQjhIQkorU3dJOWxaUzBraFp0UEU0ZWpnZjRvSWkrLzVMdDJCc2E4aFB1MTd1MDUzZm92ZDExc1YwbXdXYkdRaUJvSEtNV0cyd0t3MkRVZDl2bWlZTWtEdTBkQVZMVXlWcDBSZDE2bzRwSWdMdWxqYmJ6Y0VyVVlqUXdSdU11SVVzYlJ0Wjh6Ui9GSmt3WVk1TjlpRFE0UHRyMWVpWmMyVUFhWW5mTmMxemw3UldTY2d4dWRWMURKcEc4bUtZSDl3SytYKzFUK1ViajcrV2x5cTJzN3gvaGpMSTN2M093NENTNUdsREM2N0gyWG12T2VDWlF0VjR2aXNOUG9iZjNlVW5jZlJBeXZuK0xPcjNPcEtVT3BXYnRrYndSNThyNFo3Sk96UHRPOXA3TU1PTjU1cW82akFOZWwwRXJDeDVZVHQ4VGowSGt2dS9LZVVLSHM1d2VtdzdDbys1aGpab2UyNE54ZS9SZE9aTWFSZFBwbnRxQzh5ZnFPa2ZRSWdQQ0M1MGxTN1d3Mmc2TlBLSU5nRWFNeWFwaFFVUUZCYWJJZ082WUhBL0duRjV5L2piYm9xR3BxKzZZYmdLL3dBUWpEVHY1S3BxY1BFN1Z6VFMrQmtjVzJWVk13MWt3SWF0akRmZDQyZ2kyd1FjSG9Hd3ZGd0UvaXJHZ0FOOGw1dlZOeXpmMU52Uy9DaWh4U3BER0VyUjhSbjk3cW1BZnREOTYybkgzNllEWTcyV3VZSGg3cTJxYnRmZGFFVnRnSzFUdG5adXpHbmExMEJEQWVPaTZ6WEFWRURHY0FEZ0xTdXpqQTMwVk14OGcyMjVXNnZqTTd5R2RGNVdVK1MvRlVMMDlxS0lnRG9xV3ZjMW9jYkRjM1Z4VXNNY21oM21wVm1COTlUNmdlUXFrcElmRW84TXBCVkYzS3Q2ZkRtd3ZjSFhPM1ZDdzJtOXplNEVwOHUxUE82cnVRNUZYVTA0Z2x1bjZlTHZvZGgwU2RVSFRQMlZoUWZxbzkvSlYyUHNIR0RBNGdqcGJkUlpEcGRxdVJmZEduYzF6L0paZTJ3KzVEUUxZT1NTd1NyNXkyNXNqdXNlVXRPNWpRYmtMbTFnV1UxWlcrOFZJdWJBYmJLbnpBNE9oYUdFazJWbFhSdGNDNWpoZjBWWVdoelg5NGVQTmFXamo4U0U2aDhITnN4Uk1iQTh2TmpZcmtkYy9WTThYdjRpdWs5cGxlSTN2WkM3cjArYTVjOXhlNG4xWHV0TEg0VWVZelBrUFMydnduSEVIWUJKd0N5WTFjTFFZbUxIYWFtMDJLald5NkdlU2xUMU4yaFYrS3oyYWQxMktvR3lxcXBkVHp2ZEJ1Q0VyTE9TOHFUSkxxeWtTd3hBdHdvazhySU53aHZPNkZrc0UreVVtZFpOU0VXU1V4dWtVTUYzdTNXWGJqaGVNZDE3Z2JvV0dtTFNOUXk0Tk5rZVhoSlNPOFM0RWhqVmNpeUlScFpkQmoySVI1bkFSL2NscEJTWktncXU3cW85L3REOTY3MWwycDk0d3BuVTZXL3VYemxETC9wVExmdEQ5NitnOGpOTW1GTko4Z2drYW1rTmpwdHJxeGhHcUliOVZXL0FTbmFlVzBBdXFVKzV2SWRZN2hNeG02U2hOeUU5RTI0VlNpMkZCMlM4amRpbU5LSE0yd1hLQVluQi9QSytqaDcyRzFyM1ZFeHVtUzYySERYaHpCZXlsQW1qNXJ3WjhlcHdhVnBrb3RkaEc2N2ZpdUh4MTFPN1lYc3VZWTFnaHA2aHhBNnJ2SmZqeWF2R0RBKzZmYThiRXFOWlNrRFlib2NRSjJLbllYa2hhTC9DOFJFVGdDVnV1RjFqWkEwZzlWekJwY3g0SXV0a3dmRXpFRzZpdTJZMlhHMnpzV0QxMmxyUmRiVmhOVnJrQnV1UjRmbU5qUzBhZ3R6d0xIMk9zZFFSTXJiYU9wdXhCc1VCMzZGYW5YSDN4N3V0eWdWT05DU1BaeTlnOVMyb2tzVGZkSlpMb3RNQndlODdTV0RueVhYY3ZZQkRQQTBQaWE3NXRCV2o0VEFHbHBBWFFjQ3F6RXhvdlpKWjNmUldabDdONkt2WVdpRnR5T2pBdVM1bDluOXRVOHZqaFAzTlgwRFdWUkR4Wjk5a1drZXlhd2VBZm1rb0ZUbytLTTI5aUZSaDhUaTJGM2gzNEs1TmlPWHFxaGtjREdScEpDL1JyTnVEMGxSVHVCaVp1dUs0L3dCbWRIVkdRdGpaY2tucW5SSHh5SHlQRXlvQXRwVmhTVTlSMWF2b3FsN0c0SlpkbU41OGxlUjlpVVRXWERHL1JPVEhySWZNWWJVUmZZV0RYU3M1Rmw5T25zWGlsMkRHL1JWMkk5Z1RuUmx6SS9vRndlc3lQblp1Sjdib2JLMGIzUFZkU3huc1VyS1dSMm1OMXZrdGZxZXkrc2hOdER2b29Fc3lOSk5lR3UyUWFyRXRRNkxwZUY5ajlYV2NzZDlFL1Y5aDFVMWhzeDMwVUQ4WkhFNXNaYTNrMlNyOFNiTWJCeTZaaWZZVGlidzdSRko5d1ZMSDJLWXZUU0V1aWtzUFJGNG9wNURTUzQvTy9tbDVvakg0dDF2R0paRXE4UDJmRTY5L0pMVStScTJ2bmF4c1Q3SDBVOFVxeW1hN2dtRzFPTjFiSVlvOVc5dGw5TzlrL1lvOTFQSExVUUU3ZFczNkpqc2g3SUk2UFJQVXdpOXIrSUw2RXA2ZHVIeE1pcDRyQUg3S25pbFp6TkxQWmhUTmgwKzdzOHY1c0xtV2R1eFpsVzl6bXcyRjc3TlgwL0hSbVNNYmJrS2x4dkNyeG03VUNaMXp0Y0h5amhQWnF6QnBCcVlSYnpDNmhsYVUwTVlhQnhaV1dPWUs1MHJpMFdRY0twUkEwbCsxajFURXhhaTJ4WEhhaVNvdVN1WlpxeFVVVFhndXNWdTJiY3dRMExIQVd1dUQ1eXh1WEVKam92WW5wODBhWmFoaWJLVEdaM1lsSzhFa2drcFdudzlrRGI2ZHo2SXpHRTJOcmxXRkRoVTlYSTBCcHN1U2tiTWNURFlSaHo2dVJ0bTNGMTF6S1dYVEQzWkxMY2RFbGtuS2dZeGpwR2kvcXVtMFZFeW5ZTEFDeXo4anN1d2pSaUtMdVlnTFdRWnhlK3lZbmZ2WUlUbTNDb1NMY1FESXQwWVFteXd6bEhEdGtzNExPaUlQVmVOZ09FWnp4WkxPZGNvR01SRjZDVHVpRXFEaHNoR1dCYzVRRDE1Nmlvd0JoamsvVGJrS3RqNVZwVERoS2JJVzFOeDl5YUNVcHpZSmtPM0NVeUJoRVFiN284VmdlRkVQRGdGTmpTU2dBRzQzQzFrWDNieEE3b1ViRTFDUzl3Q2dMR1lJZ0doUFVrUUpDWE1aRWQxT2trY0hCUUF1b3hzQWlDTzZqQmF3dW1oYXlNV3hjaTEwcTRiOEp1Wkt1NFJJQmlzeEtycDNIZmRQMUNxNTNibEdBeXVxQ1czVlBYVGJGVzlhUUFWcjljN1lxemdFWmtVdGRLQnFLMHZIcSsyb0xac1RxQXpWdXRFeHVjU2FpQ3IyMjJxS2Jrb3AySjRKZ1V1UDVudzZrakJlSjVRMGo3aXYwWnlSbHB1U3NnVWVEYU82bGhjU2RySGdma3ZsWDJSc2lITStQVnVJMUVmZ3c5d2thWEQvQUlmelgyQmorSUN0eEI3NHRvendCd3ZUYUdOSThqMURKY2hRdXVibmMrYThTSEVYM3Q1b1ljYkxPcGF4amt5Ni9LbUNnNmxJT1VJSGE1RWFkOStFdTF5bmZaY0lPRmtiWldtRnhmTDBhVXhURVZUOU5UK3FlMzRRT3FTaGpJcG56TmRkNE95ZWhqRTBMZDdTRWJIcmRMVVBENUpMSmwwM2tOc05VS2p1SllnMm5Id3Y2a28yWk1XdzNLZVhKOFN4eWYzVERJaGVTVG9OajhramlPUFVHUk1EbHhQR2EyTU5ZeHhESlR5UU5sK2NIdE0rMUZpbmJCaXRUZytGelM0ZGhkM3d2MEVGanJlRy9YMVZYUHFsQkhwT2s5Tno5VHlKeFhtdnFBOW9mdHpwKzBQTWMrSDVhaHBxdWhnbExaSm1zYUhCdHVkZ2ZNZFZ5R2hpaWhmN3MwMzA3MzZwYkNxTVljM1N3YXBKTnBKUjlyMVZ3SHhRdDd2dXdIZitkNXJ5R3ExZTVuNko2SjBySjAvRWxKZVg1ZXBHd0o4QnVRc0YwN1RzeS96WG51RVc3ZCtxaDd5NSt4RmxTVnM5S3NUWE1pUVpMSmN1WUI4a014a2o5WHVWR1NTdy9ucmVpU3FjU2pwZmlsREFtS0RZakxrd3dYeE1ZMWdPdElkS2pVVE9pSDZrYXg2cW9xc2VqY0xRTjc5NTZONVR1QlpJelpuR1ZqYUxDYXJRODJEbUFXSDRweXdTWmc1OWRvNDNjd0ZmaThGRTI5US9RT1NrYUI5Ym1HcGJEZ2tmdlVqamEzK0xyNnE3Ry9ZRnhUTVZYVDFPTzRnNkdOeEJNVTdlaCtUVjl0WkU5bXJKUFovUlF4L29laXFwMnRzWmdIWHY1OGhhZVBTeXZrOERyL2FxR2tpM0JwL00vTjNJM3NjZG9IYUFZNUt6Q3BvYWQ1M2RHWGZrRjlJNUIvazNjSm9YUXlZalBXYXRpOFBEalk5ZVhMN2FvNDZUQllnMmlwR3Nad0dzNkloeENYcTB0dXRqRnA2Ujg1MW50VGsxcnBWOVRqT1d2WTZ5Tmx4ckM2MHJtLzhBbVFBL3ZLNlJoblpwbGZCSTJ0cDhPbzVOUEdxbForU3V6S1g3bHl4MzVhTm85U3VyR2w1R0w3NU83bEl6QmgyR1IyQXdtaGFCeGFuWVA0SnNVVkU0ZUNncFI4b1cva2xxZXBmSnRKQ1l4NWxGYlNTek8vVnZJSG9qY1VqbUxKamo5MlRKZTVRdE85QlQvd0Q5SnY1SWhaU3NGaFEweFByRTM4bE56WTZLSXVxcXBzWUFKSmN0RXpYMjZaTnlYVFN5Vk9NMGNqNCtXRnhTSlNTQ2ZqWnBLTUZadWpLS2xxSDJmaGxHUi84QUlhZjRMRlpsN0FDMTNmWWJSTjgvOUdaK1MrTCsxRCtVaXdyQis5cHNId3B0YzRlRVBoZCtibDh0WjA5dHZPT2E1SkhVckszRFd2MkFCYnQrSlZaNUlvMzlIMFhXWnFkUDVuNlQ1NWk3TWFDQ1Q5SnRvNllkU0thTmZPZWVzWDdCb1d5R1BGb1d6ZnNpQ01iL0FOWmZCbUtaOXpubVp6M1ZPUFZibXZKMmRiOGxWdzBWYk0rOVJXT21jZWRYL3NzcWVwaStEM2VrOW5aNEpLU2xMNW82MTJuMW1VY1JxcEJnTldKWTczQmEwRHI2RmFGQkZDMTIwaEtXZ2FLRUM4V3ZwZE52bmh0ZXdZczJjbkkraDZUZGhpb3pET2lCR3hYbTZXY2xWc21KeFFuZVlmSkQvd0FvSStHc0VoOU9xVjRiWnFQSm81ZjZrNkx0ajQzY3VSZzJJajRpdGRHTDEwaC9WNFhJUjZmKzZtS25HSEM0d21hM29CK2FZOU5JcFMxbW44cEY4U3djT1V3UTYybFVIdldNTjV3ZWMvY1B6WG1ZdGliRCt0d3VXSWVadCthQjZhUjNIcXNGL2VOa1pjY2hURWNidVhFRlVFZU50LzFwN3MrUlRzR09VaDJNalNVdDZhUnM0dFRncjd4YzkxTFlhbTJiNW9rY0VWdDNHL2trNmFaczNOU0NEMFRtbHJRQzEycEpuT3kwdDBld1E2bWJNQUk5VmxvdDBzVm1KOXh1TEtRM0twdFd5MURJNWNORW1vb0YxQm91aWdMc1lsdU9sdzVPWlNaNGM4YithbTFZQVUycGJuSXVMRmk5VElhQ2VQd1dEU3M4dndSQUZJc3YxUy9Fa0U5UGlhN2lFK0RRMUlOMkFuL2hWWlVaV2x1VEZOTkVQNkRpUDNGYkxIRVJ2ZFNjNHROaXJFY3N5dExTNEgzTmV3eVRIY3ZlT2l4R3RlUWJnR29mK2EzWEFQYU16OWx3aHNUWHpBYmZySm5IK0NxWHlNN3dSZ0RmcWh6MGJJTkx3UThuZlNyTWRaTkdQcWVrZE96UnFMZi9BRCtoMlBML0FMY21iY01EUmlOUEJHMGMzZmYvQU9sYnRoWDhvUks2b1pES0tVWDlXL2t2bDZwcDRhdU1HV21EQU45K3FXYmhOSld6Q1JsRTJIVHRmelY2SFZKeFBGNnIyTzBlZVRmUDBQc3lpOXZ6QzJHUnRUVVV6Q2YrRk5OOXZuQ0hSQnNWVFR1SS93Q0ZmRUZkaGVIMHpnWE1qZTQ5TjBzNk9qZU5MS2RqWGVuUlc0OVptbDVHZi9nYlEveE9YMC9zZmIxVi9LRDB0TkdRMTlLYmVlbjhscW1NZnlpcjlEL2R2ZFhQNkM3ZnlYeHJXTXBNUG1GeXlvY2R4R3RueWoySDQ3MnFWa01kSmdzOURBVHZPMXUxdlBxbVExMlNmQmk2djJaNlAwNU9jOGt2Ni84QXdkS3pUL0tENXhyYWg3S1dtcHlIK0Z1bDl0ei9BT2xhMGN5ZHNYYkV4enFXa25ZMlRZZHhVUEhQeUMrdXV3LzJFc0Z5aGg4RlZqejZmRlpBTjQ1UWIzdDZBTDZSd0RKdVhjc1U0anBNQmdoMDJBTEw5UHZXbGlqTE4zUERhdnErTFN2dzlIVXZMbEg1Y1lSN0hmYW5uV3JhekZvY1JiRTQ3bnY1U3ZxM3NMOWczQmNoQ25xOGNNMGs3RGN0cVdGNHVPUGlLK3VxV3BwSXlURlROakk4bEtvcXZmbkVIWURkYVVlbnBxMjJlZHlkUTFXb3Z4SUpmb0RvNldpd2VqaXA2S25ocDQyTURSM1VZWmV3dGZaUkwrOEp2dW9XSk52SlNEZElWbXFQUHRza1RiWWJCRUNCZTZLMDJVT0JXbnpSQWJJTFNwZzJVSWZqYmlkeTc3a0NNa002bE4xemJCQ3BOaWRsVXgzR0RMMk5iaVZLM2s4V0hWSVZsYVpDZWR0bFpWVWdBTnR2a3FhcGYzYkhHeXhKZkZtL3FhQ2V4R3I0OVY2dkNTclhJbEozdFRDZEpJMURnTFdzWWNhaXJhQjVyc2ZZL2dZZXlKN21BMjMzSG9yMmVTaEFSSk9iTzBZTGh6RGc3TERTZExlZmtsbzNtaGtsSkJQeVZzNGtOamEwV0FhQllKV3JrRVlGMmpmMFhoNVNkbXdrVXpKZjBsVnVKdTBBWDhXeXM2YVYwa1JidWJHMnlScVlPL0FMQnAzK3pzcnZDb1BjOU9vWHZZN3BEYkRTS24zSno1SEU3Zk5Ca3AzUXVOeUZiNHRJOHZhV3RBRitpUm5qTTBJdnlsT3drVjhkdFhudW5JNDlUZkpCaWhNUnVSOVVTU2V6ZGt4SVBjQ3FJZEJ1Z1MxdTFsR1N0MGtncFVUQjF5bXFGZ09RWXo2aDVLc3JwQ2JnRUxGYldDTWJHeXFYMXBrUG1uTEVCWk1NZkRHNHVJTzk5bFhWOGNrbExNNW5JQ2FkTzVvMUhjS0xxd1VkTk5LOERUYSs2MGRMaXFTS2VlZkI4ODUxbmxHSlNza3VQbUZyRVl1VnRIYVZpck1SeGlWOFlhQVNQaEhxdGJoR3N0c3ZhNmVGUlI1ekxMa094bGhzaU5iZEVhM1N6am9wUU4xTzRWaVNvQ0xKQ0h1bTM0V3U0MVUyTmdWZTRyVUNDRWk5dGxwVlRVR2FjM045MGNZa3NsQU5aSk95bEdUcXNoeUV0YUxiTFBmTkFDZFJMSEE0QnZLQks4YjdwV1NxSG1sWHphdXBTWk1saHBhbmxMR1lrOVZIdkxjckxaZ1R3RkhHaGxoV1B1RjZVQUJZRGRRdWs1cXNDNHZ3bE1OTXhNOUt1TnloVkZZT2hTYnF6ZmxKWWRsaytiUmJkQ25yRHA1U004K3JyMFFTKzQ1WGFDa3gyamsxMVVmL0FCRDk2K2s4akFEQjJrZVRmM0w1cHcwYXFpUC9BSWgrOWZTMlFCb3dkdC82UDdrRWthZWtaZGk3NUNFOEl0Tk8yM21vd2dQTDlrelRuU3l4VkthNU41TW5UQzlsYVF0MlNsTEVlYkpsb0ljcWxGdXd6bUplWUpzdUdsS3lDOTFLQmJGSmJOM0NzTUtuOHowVlpKOFNZcG5hYldVb0N5Nk5XWXdSZGE5ak1JcUx1NVZqUFBkdjNLdG5mZTY1UmN4enMxV3BwYnVJc1VpNms3dTVzdG5uQUpPdytpVWZSQW5oQ3kzVm9vUkhjOEZHamFXOUZjTW9iZlovQkRtb3lEczFEWlRuakZZZThqY0RkWHVHNHhKVEFlSlU4elNTc004STN1aXNwUENiN1I1aWRLTEYxMXRtV2EwbVZwdjFYTE1OcVdzdGNyYk11NHMyS1p0M2RVTDVLc3NUTy9ZSlVCMGJkK2kydWpyZTdBWExNQnpCR1dOR3Ridmh1SXh6TkhpUU5GV1dPUnNUNjJWMGd1ZGxaMGVJRnVuZFVEYWdPRzFreFRUSFVrSkE3V1dtTzFuZXdGYWMyVnozdXY1cStyNVNXRzZveWZFZm41SXp0TkQrSFZBaWtDMlJtSXNMTExWWUhFZEU4MGt0Nm9reVd6WTZPUmdlRHo5NjIzREdVOVZIcGNMN2VhNXBSMWhpTzU2cmFNQXhIWE1MSGE2TUhjelpNUXloUjFMSE9NZlE5Vm8ySVpJcFhTdS9WMjM4d3VvZTl0OTMzSzFiRnBHdWM0Z3FCcVRLYkRNcjBsSTBXWitJVmwraHFTVzkyZmloMDB0aHVVMHg0TnpkUU5TWVdnd0hESnRueEhuelU2ekkyRjFFYnRNTjdqekNyeld1aGsyTmx0R0NWZnZFVmp2c3ViRHU1bkVNOTlsOUk5ejNNZzJCdjBWUGt2SU5JK29CZkNScGRiZjVydmVZcVVTQjNnQnZ0dUZyV0hZTWFaN25CdW5lK3dVMkFPMlJvOEJncG8yc2pBYUJ0dVZkVWVHUXdOdTRCeDlDcTJzTG1BQUVpeUxodGVJeTNXNi96WE5nRzFteDBkQUR2YlpVdWFJV3d3azdEYnpWNHpISW80aHVBdWVaOHpNd1JPczljSFF4TnMwWEhjWVpCTTRYV280M21hT2toZHBkWTg4cXN6Qm1admZQR29MbmVNWW0rcWM2enlmdlVzMU1XbkJaa3haK0p6dTN1THJXcEtKdjJta2xYbE5TdW1PNHVyYWt3RXprZUcvM0tielRoZ1NOVnd2QWUra0YyRWdsZEx5dmxXTUJwZEdVNWdXVmREMmtzL0JidlMwektLTWVFRGJ5VmQ1TE5IWXFKVVdEeDA4ZTFoYjFVL2hCSHFzZTg2K0NoRndKNVZlVWdkdEFKTjNxVGpZS1JpdnVvRmdDcnRuTFBOWXBPRmdvdGZwSzg2WUVKTmphQXZLQmRUbGRjcncyUXRuU0N3VHNwdmNMSmFSeUN6bG1IaFEwTEc5MFdNOUYxczZUamJ3ck9Eb2xJbVhWbFRDOXRrbHNnM0I4S01laWd4dGdqUmdBaEtiSUdoYVNRckNGZ3NnTWNMQ3dSNGpkUUFOZTJ5ZHAyQnBCU3JJN3AybWFSWlFGakVrbzBnSm5Eb2c4M0tVbEhDSlN2MGticUFGeTN3b2drUzdkd0ZNYkpxUXRoU2IzUzdrUXZDRE1OSXVpU0FZbFVubFZOUWJFcTBua0ZpcWFzZmU2TklCbFhYVG14VkJXemVGeXVhMTQwbGF4aXMybHJ0N0t6RmJSVW51UnEyUFZaYVgySzB4NWZVaDdXZ3ZjVHNBTGxYMk5WWTF1RjFiZGptV0hZLzJoWWZUaG5lUnlIY0VYSElXenA0YnpDMVdUWW1mWVBZUGxXUElXUTQ2bHJORW1LVTkzVytmWCtxdG9nSmpnRFhIeEJGQUdINFhSVVFzQkEzVHA4dVVINEhkNTBPeTlIaGhzUjQzVXozeURhdlZldjZvT3E2a0RaV3hRUy9xcGpoQkJ1aWF0dGwwZ1JybE8vd0I2Q0Npc2NMcUVIS2VRQ25kQ3p3eXVPeFBDWmdlNm53K3NtbDhjMFRieGx2bnNrSEh2aU5PeDlFN1J1N2tFUDNCNUJRWlpXcVIzVWFqeG54RS9PdjJ1KzFIdER6Tm1LcndLRVZNbUZ4RVBEUlR2SXRxMzM0NEMrYktDYVdqRG1mbytyWVhHOGw0WEM3dXZSZnRIV1pjd2ZGUzR6NFpSeU9lTE9lNm5ZVGI1MldwNGg3TldSc1VEM2FJMlBlYmtOZ2FMRS9lc1RMZ2xrWjdYb2ZXNGROcHloNmVmb2ZrKzNNUGR4YUJTMURYV3R2Rzc4a09QTllhTzZxS2FkN1J3Qkc3bjZMOVFhcjJMY2tWamk3dlh0djhBc3hEKzBoUit3NWtWcEJOUkpmOEErVi85eXBQcGpseS8yUGU1ZmJ1RW8xR1AvcVB6Q1ptR2FRblRTVkpIUzBUdnlVZmZzV3JYaGxQUVZsenRmdUhuK0MvVnlnOWpqSWxDV3VEeTYzN1VJL05iaGcvWU5rM0E3ZDNTMDhsdjI2WmlaSFFmOG95cCsydVdTcFJmL3dDeCtTdUM5bGVjTXlGaGlwWm1hallhNFhCZGZ5UDdCdWRzNXlSdnJYd0NKMXRuMmJ0OTdsK25WRGdXWDhMWUd4WWZSQzNIK2pzSDhFOGErblkyME1NVVhsb1lCKzVYc2VoUzdtRHF2YVRQblRwdGYxUGxIczIvazk4clpiN3VYSHFHT29sYnVURzluUDBLK2pzczltdVVNaHdDUENhRjhHa1didUQrNEsza3FYeUcrby9WUkV2M24xVitPamlqeW1icUdweWQ4aitZekhYRUhTNy9BTlB5UW5pWXYxT2VESDVJVTByR0RWS2RFdjJXanFzeE5kTXd2a0phMGJ0OVZZV0pJeVZLV29WU1ljem5TQlQzYTd6S2c2V2R4OGJnUjZJRVZSTlBJWTJNQmpIRHVxYWhZUmNTYkkzdGloa2NXTEY2SHRUQTNna28xSVpIL0RjZk5lbGF6REtkOVZVK0NuYU5SY2VnWHoxMnorMnBsTHM1RlJTMEdJUXkxckFRSTM2ZWVBcThzc1VYSWFLZXIvMDBmUTFWaWRQaGNMcHNVcmFkc2JlanBXdE52dks0RDJzKzNCa3ZzMVpMQkFaSmFnZUc4THRRdjl3WDU5OXJ2dGM1dzdVSmFpRmpqVFFQTG10ZFR6RnUzVGdCY2JodzJxeEdSMCtJVmRSTTkyOXBaSE8vZVZrNU5Xdkk5bm9mWkxKQ1NlU1QvcWo2UTdWZmI0emxuaWVhUExkZkpUUVAydE14L0hYcU9pK2ZNWnh6RzgzeXZmamN3cUJJU1hFQTlmdktOU1lheUxhTmdQM0t3Z2lqN3NzbEFiRWVYVzNDeXNtcmJQcEdpNkRwOFVWdVNiNDhpa29jclVWRit0cDRpMTUzSlZ2QlRQbjJrSUlSYWFhVnNqbzJzQnArTlo1c3ZQZEhITzhVN2k5b0Y3bFZ2SGt6YTJZdE54R0NQQmpZUENOa0NaN2FmOVlYdDg3WFZiUGpMcXlwOTJwN09xQ2JCcTdqMk9leHRtN3RTbmlxc1FvcDRjT05uZDVHWGZENTlFK09tbEptZHJPcjZmVHhiaTAvNm5GdjB4Tld2RU5QUzFFN25Hd01jYm5ibjVCYjVrdjJkODhaMW5qRElYUk1sTjI5N0VXN0hqa3I5SHV5ZjJNOG05bmRQQzV4TlZWUjh0cVlRNzk1SzdyVDBHRlVFYkdRWWZTUjZBR2dzZ1lPUHVXaGowVGZjK2I2L3dCcWNqYmpqVDgvTS9PL0p2OEFKdjVneE5rYytJdnBYc0l1UVhOQi93RDdsMjNLMzhubmxMRFkySEU2Q09WN2R5V3ZaK1JYMVErdERXMlpaZzhtN0pWOVc1eCtKMzFXaEhSSkxzZVJ5ZFgxK2QycHlYOVdjcG92WTk3UGFJTkJ3ejRRQnM5djVLNWg5bWJzM3BtQUhDbkg1T2IvQUdWdlJxSEg3VHZxc2Q4VDFLZjdzdlFxZmFPcS9udjVta085bkRzMWR0K2lYM1A5SnY4QVpWYmlYc25kbmVJTUlrd29rSCtrMyt5dWs5NzZySXJUNWxBOU92UWZEcVdxL3dEN0QrWjg5NWg5Z0xJT0t4dmRSNFkxa2g0TG5zL0pjWXpmL0p3VmNabGt3bHRORTFvSmFDOXY1cjd2Wld1SERqOVVjVmhkejRqNUZBOU5IME5ESDFiVlI1OTRmelB5S3puN01XZGNobVY4ck8rampKMmhqTHR2dUpYUG84VXE4SXFEQlhVbFN4elRhN29uTkg3bCsxOVhCVFZiTkZaaDlLOWg1TDRXdS9lRnlidEc5bHZKWGFIQzk1RGFhYzcyZ2hEZC91SVdUUHAzL0tQWGFEMjVudVN5UmY4QSt4K1lVV0lOckdneFBEZlJ4Vml3M0EzQlhiTzFMMkVjeVlEVVRUWlVwYW11aFo0Z1hsdzJIMTZMNSt4ZkJzMVpJbGZGamRBS1pzWklKTituekN4ODJrY1BJK3ZkTjlvdExxWXBOcFBqekxwb3Z3aTJzRnJtRzVtcDYxOW8zaHp4eUZlZTlsNC9XQU5IbUZsU1VvdnNlcmpraG1Wd3lMNWpMVk51NkhGTEhQc0hmUkZFT2pjRzZPVTRWMkwrUE9ueFJJQlMwdWFlVjVwYzdZRGxTTlBORzhFdFNIa2hab3huYTdFbVBMUnV2T2E2VGNOTHZrTHFjMFQzUkE2ZWlZd1hGVzBFemRiV214KzBMbzQ1WUZmSk9yNEsra3dURWNleFdLbW9LYVpqbmJhM1JtMzFXeDQ5MklaeXdtZ2pyalYwN285T3J1MmtGMzAxTHF1Vk8wQ3VwcUh1Y0l3bWpxcXMyMDZvbTMrdWtxclpSZHQySlk1NzI3S3NMc1AxNmhlNWJwK1dpeTNNZURFKzU4eHpkY25wNWZFcVg1dnVjT1pGaTFTenVaNEptdVo0aTUwYmdDallaZytZc3cxektMQ29abTZ0aTR4T0l1dnA3R01yNTZ6UlJSd3c1WHBJNTlWM2QzRUFiYmVURjNMMmVPemJGTXZVZXZITURwb1g2d2RUb1FUeWZOcXZZOUJqbjZmSTg5ci9BRzB4d2kxRHZ6L0VmRjNabjdMdWE4MVk2OFlxMEdJUCswM1Q1ZVpWNW5YMlpjUndQUDdzT3BZUjd2cmEwMkZ4WXVJTzYvU05qNkNubGVJYVduamQxTEkyajl3U1ZSaGVGVmxZWnFoa2ZlODZpd0UzK2EwbDBuRlhsOGo1M3EvYXJXNXBic1UybCtVajVScC9ZTndOMVZoOWJMUnh1Y1lXdWZaemVTQVN2cUhKR1RzTjdQTUJnbzZLTHUzTmowYkVIcjZCWFhlQnJRQWJ0QXNQa2h2azFjN3Evd0M1WVk5cVBMNWV0YWpVcmJubTMrckpPa3FaMkI3bmkza3N2cUpERVE5d0tEM2hBdGV5Z1RmcXA0ZXo3cGg1Vktidkcva1pwMnRMbkVoRWFIZDRkQnNQVkRhYktWOWlRdStMa1hISlZXWFU0K0pSWVJrbGp1c3ZrUWdWSUt3V1FzWTFLUUtnTmxOcFVJVGFpQTNRMm9nVUlmamxpRWdRWUQ0U2w2NmU3K2Jvc0g4MWZyWkpsSGJCbDNTdTJaY2RibFZZL0kyQ0U5TmxjVTdOYnQxUlp2Z0xZamJ5V0JIL0FGZjZsL0p3YXJoOUs3RU1SYUJ2NGw5TWRsMkVlNVViQzV0dGorNWNRN09zTEZUaUFKRi9FdnB2QktadEZTTWFCYm9nNmhQYkVkZ2h1TFNua1krVUEyUzJNd2c2ZEtZZlJHQjdYN2I3cGVxa0QzTkJJWGs2Tk9xQTBkSmVJRWhTZk01dFEwV05rOUE1cklCditLVmRLeVNZYkZDMFNobXJheDFPMGtDOWxRenZlQ0xOTnJxMnFwZkMwQUVoQ2NHZHp1RGREdE9DVjJ1QTRRNVltaHBOd3ZhU0NmbWthNnFMR2tBcGtVQlpWNG04TmNRQ2xJaTdxVjZwZVpuYm9FbFYzZTFpRmNoRUZzSFhBdVNzTWJRZDdKb3Y3MGJwR3BKak95dVJpQllhVXNNWmJzcWJQV0l3MFdBdURYQU9MT2lKTk01azdSZnducXVUZHBlWlpIeWltYSs0dnBzRnA2YUhKbVo1Y0dnMVZSNzVLWE9OeVVhZ2h1VW5CQWRhdXFTSU1hQ3ZXWVkvQ2VmeVBrak8yd3NGS2xBYUxsU2UzVzZ3M1FxcDN1OFRpZHRqeWltdVRzQ2p6VFhOWTB0QjNzdGFwaDNqaTVKWml4ZDB0UzVvTjdYR3k5UlZXbW5KdjBUVWd1U3ltZUNDTGhWOGtwMzNTTW1KSHZDTDdJSXI3bmxFemxqam51UFZaYVRibEtlK0R6WHZmZlZWcGR6bzREcVhqWmd2ZEorOUJ2VkFucjlpQVU5b1lPeVlnSTJrWDZLamxyQzR1MzZvYzA3bm5sQ0xiaFZwREVaZElYOVZIU1R2ZGVGZ3NoNnJzSThYRXJQUmVhTGxTZUxCR2dwRmhoQXZQRi94QmZTbVI3Zm9ZZkpxK2JjRkg2NW56QytqY2d1MTRTQjhrTWpUMHZjMnlqKzJqdEhIelFLZndoL1JPMGpkZHZtcVV6ZVQ0TFdsZ3N3TEwyYVhKbW5iWmd1b1NnYWxUb3VlUUI1c0VKL0NZZU5rQjRzRktBWWhQc2JyRWNsaXBWSjVTclgyY3BRSllTRzRTMGpka1F5Z3Q1SDFRcEg3RmRhQXhUZGlVNHNVS0s3bktOVk1Xa3FWRktIT0h6U1diT04yaXlnaEJBMlRRb1dQNkJacG93NEN5dGFhakxoZXlTMk1hS280QXg0dnNrcW5BYlhzdHlwNkI1YndoeVVEdFhCUjJkZUpHampDSHg4RXBpR0dXbUlJdnN0dWt3MGdidEtETlFOdDhLNklsaFFuaG1OVFU3Z05UbHZPRVp2a2lEYnVLMG4zQUEzQVIyTUxHMkNnaDRFZGp3ek8wVXVrRnd1dGxvc3h3U0FIVUZ3R21iTlREVmYxVHNHWko2ZDRiYy9SSm9wUEVkMnJjYWpldzJjRldVbGQzMG4zcm1jZWFaSkdpN2p5dGh3ck1MQVdrdXN1Q0pZem8xT0xnRk5zY1FPRnExSm1XTWdEWCtLdktMR0lwUUx1Ry9xdVdJY0IwdzcrU3VzRVBjUDFFcW5NN0RZNmg5VVFZaUlXbXpyZmVuRThNM0dzekFJb3kwT1ZhM0VEVk81dXRPck1VZEs3NHI3cXp3bXR0YTVVRFdNMlZwTFJ5c21xTER5cXVURVNEYmRaRlRyQUtnU3hqN2laSEs4d2l1Tk1BRnJaeEJzZHVVYW54VnJqemI1cGZpQUtCdU5UVmlxWWRsVHVxeTBrYWJicFZ1TXNqYWJ1SDFWVlhaamhZSFdkdjgxUEVHTEhaYlZFckhpN25BS3BxYTZHQU9QZU5GbHAyTTV3Y3pVR09XbVlobXVlVngvV2NxZUlOV0t6ZXNWeng3dTE0RCtGekhOT2MzMWhjQTRsVm1MWWpKSzArSzkxcjN1NzZpVTMzWERYeDZkRlpYelMxTWhOenVpVUdFT3FYQzR1cnFMQmliZUhxdHF3SEFMRnQyMlMyelJoaVNScjlCbGcrSHdyYWNPeThJbWk3VnRGSmhESW1pN2JMRlpLeWxCQVA0b0d4bFVWellCU3QyQ0hMT1pObGlhdkUxeGRLOTVZN0tqdUp1RE5mM2F3d20vVlFBNzFIK0VCQzJDMlRCTmtKNU4xa3pLRHBMcmdKRjd0a0J6emRFSnVGQXRDVFpZUGNoUWMreUp0WkxTR3lCZ004NlJETHJvYm5yQWNnYkFDTzRVNGhjaERhYmxNd3QzQzZ3eDZCdHdyQ21aWWhKUTdXVm5FMndDUzJkR1dnRUlqR2JoQmFiRk9RQUhkTFpBN1k3QUkwZXlDSGxGajhTSUFiamZ3ckNQd2dLdmpad25RNndDZ0RDTzNXWS9DUXNNTitxSllCUUVzWTVMZ0kxL0NxK0I5eW5vemRvdW5vV3lMalpMMUUreVlrdDVwR1p1eU5BTVRtbHZkSVRrRzkwM1A0UVZUMWRTV2s3cGd0bFhpa3ZkZ3JTOFhxNzZoZGJQaWsyc0ZhVGpCc0hHNnNTTStFbSs1cStMTzFseDZyNkI5a0xMZ3FMNDlNei9xMDJtNStaL0pmT2RWVUdTc2lpM091UnJmcVY5eGRoR1hHNWI3TzVvTlBkdW5MWk4rdHdUL0FCWG91bngzZC95UFA5UW5YMU41cVpCVlZVN3h3RGNKZDh1dGdaMUNpSDl4NGZOWUFBbEp1dlF5VzA4cXZpWVFPdHNzM1FyK3F5SExvUVlPUk5RUzkvVkV2c3VrQ2h5SzExMHMwb3JUWlFnM0E3UWQweVpOZkNTWTdXaXRkM2FDTWJCamx4UTdvc1lKdEFzU21ST0J3NEtxWkpxVEVib21qY2JwMnhKQnVlUEoyUmFSMUx2MmltMlZCUE1pcVk2bUsxZ0NpYWc3Y0pUeUtQQnpaRmNzc2hNNi93RE9YVWhVMjVGMVhOZWlCN3JiRUpsSVAzckMreVk0YXR2SGRxT3NBM3Z5a3krWDlvTHcxT0l1ZDBMblFIaXFYM1IwekE3S0JlNDhJVEl5U2lpN1R4dWc4ZWdkdVIrWVdDemgzcys1SFFyTDZlV3RkcWpjV01aOWtkVm1NTWUwbW9HcE5Vd2ZRc2ZVdm5qaHBXK0k5NDREYjcxSGtHd2h6VVNkT3gwek81RVpoMDdtVDBXa2RwWGJobHZzb3dtZXBxYXlucktpSVg3Z2szTzMzTGpQdFA4QXRwWVYyY1V0VFFZTE81OWNieDY0U1hqZmI3Sy9Oek91Zk16OXArSXpUNHJWaVpzcjNGdHdSWnBPM0o4bG1aODllWjZycDNzL2sxMGxKMTVkN08zZHZQdHM1ajdTTVJtdy9CUGVjSHBXdkxkY1JGbkMzelBtdm5xb3BLN0VwZS94U3VmWHlubDhuSi9CUFVHRCs1UVdmWXV0dFlvMEFhMTVFNExtOUFQTllXWFZPejZ4MC8yZmhvNHEwdm13TVVESVdpMU1OdXFJMlVQZGJUcFJIVFRRdXM5MTJkQVBKU3ZESTNWcE9wVjU4bnA1N3BjSTg5cm1DN0RmNUxNY1Ruc09vMmIxSzlFOStxemVGNmV0YlRnc2tQaE81Q1RISHVaejRzVVhLVE1UVmpIUXVhMGlJUmpjK2E5bFhMZUs5cEdMUTRQZzlMS1hGdzFWRVF2c1QrUVVzblpNeEx0UHpMVFlaZzBidTdkSUdUWGFTTGY0c3YxVjluTDJaTXVkaXVWNlNzbm94K25OMnlTTWNEdFlEZ0QxSzA4T2xUbzhUMVhyK1BUWEhtem5YczQrdzNoV1NZYVN2ekEySEZwbmhzcEV3TnhmY2pZQmZVOVBSMEdYNG1VbUdVektLSm8wMmo0c21KNjZxcTJXcDVBeGdGck9TRHBvNzZad1h2NHVGNmFHSkpIeHJOcTh6bHV5U3NjbW1EWXc0U2h6a3NadlZCa01NUXVXa2owUzVsdWRsWlNVU2hMWFliK0pPeHAwMXVxR1p3bDNFbERJS0I1S094MWtYOTBaNzhyM2ZsTDNYdDB5eGZnUmZJeDM1VXRZODByY3JKSlFOazhHS0cyeUR6Uld6QzNObFhBbTZrSDJHL0NFSFlrV0RadGV4ZnI5RklTYURkb3NrUStNL3dBeUN3K1pSbVRGbjg0Yi9KZHRTNERrOFVmdUlzNGE4bGhhK1BXMGl4OVF0TnpmMks1WXovVFNzbncybVpJL2x6Z1ZzUGZUUC9tWEJvOVVlS3RmVDdYM1NaNlZUUlkwMnV6NEpxVUpWUjhhZHFIc0FzbGRMVVlOaVRLUS9FR1JOUDhBRnErWnMyZXoxblRJazcydHBxdkZXTTZ0YU4vM0w5YjJWeHRxZWJoUmtaUVltMXpabzNFT0Zpc3pKMHVFdkk5N292YXpWNEVrNWNmb2o4WUhWT08wRGkyb3dLb3A5SnNTNEQ4MGVESHRlMHp1NVBrNWZyRG1Ec015VG1NUEUrSGx4Zno0aCtTNXJqWHNNWkN4VnpueFlZMFBPKzcyZmtzaWZSWCtSNy9CL3dDSUdqNHVNdmt2N241NURIb0krSm11OWJxY21NUnZJUHZnWDJ0aVg4bjNnNWNmZEthRmc2WGV4VjBmOG50VE5kNG9xZTMvQUJzVlI5RWwrUnV3L3dERUxRSmNxWHlYOXo1QUdZYWVPT3hxR3UyU3B4Mm5jL1VKR2xmYTFOL0o5NFRjZDdUUW4vMXNWMVMrd0RsaUlEWFJSRS84YlB5WEYwV1M5QldUL3dBUWRBL0tYeVg5ejRhcHUwK2JBSm15d2x6WE40RFYxWEkvdDMxV1ZTeUN1d09Xc2crSFc0aTF2NndYMUlQWUl5Uk5aMDJIc2M0YmZ6alB5WHB2WVJ5SlV4bUNURFdsbHJmR3o4bHF3MFVvbmplbyswM1I5YkZ4aGpsZjUvOEF5SDdKdmJKeVRuT09GczFOUzRaTkp0NG5HNC9FcnYxUGp1RzRyVE5kaGxmSFVDUm9jR3huelh5amlmOEFKMVpjb0p1L3dTa2hnbEJ1MHVrWnQrNWRDN0wreVBOZlpsUEcycHE2ZDhMSGVFUmtIWWNjTzhscVlzVW9ueXZXeHc1cE9XRlYzTzN3aU9JT010bXVQbWwzVnphZVVrVTNmZzdYQ0RKT3lvampOVUM5dzVzc3VxUUl3Mmw4QTlWcHhja3FNbUxuaTRzTVp0UXZhMStua29tUWxDMUVnWE8vVmVCMzVTZGtrZDM0SmY2a2JDYTdxUWRkREM5Y2VhWXVPNGF5Yk9jSEFXNmxxUVFkL05TQlRWT0htaVBXdGNaK1FvS20xeUVPaUkzbExBN2hRYktZS0VPRk1jS0VDZzdJZ0tDMDJSQnlvUS9GWm9jWGk5eXJhQy9kZ2VpR2Fkb1BBVFZPRzJzcy9LN05EVHFpZFBkcDRWVm1MVFBBNWw5eUZkUERXTVB5V3ZPWTZycmd5OXdWWHVreTVQbG8zSHNud0h1NTNTRWJiSGNMdURDMWhzT2kwN0lXRUNrb0d1c0FTMWJhR0FQSkpYbHRlM0tScWFSVWhnMWI1bTZTUFJLQ2k3Mlc1Y1ZnMWpTU0d0M1dZMnl1T29YQ295WEJZYkhtMERXcytKeUJQREZHYmh4UjRYRzFuTzNXWmFFU051SGhWMmdHQmdrWWR1Zm1vMU1aTjdEWkVnbzlEK2JyMWEvdVJheU5JQ3lucW42V2xVZFpNQ1R1cnV2YjRDVnE5YzhoeFYzQkdtZGNrUWNBWEFwZXRrWStWb0Z1RmxzdDBNUWQ1T04xZWswa1Y1Y2tuc1lHTjNTVlZUTWtaY0UzVmxWMGJoRTJ4U1h1cjJ4RnhKMjNVeHV4TE5Tek5pWDZMdzJiVllIa0U4cjUxeG5FNUszRlpYRTZocTZsZFY3WE14TmpZK0poK3piWmNpb0dkL0k2Unc1M1hxdExpcG93c3NoNm1lNHUzQ3RJZkRHbFl3MWg0VFIyQUMybndqTWwzRFVUclNFOHFtem5pQWloZUFkUHlWekdCRkdYSGJaYUJuYXU3eDdnRDFYSVNHeE5SMWQ1TTRuZTdqeXB5RXRic1V2RS9jL05TbGs4S0VjRGRKeWhJYm5YS21PRUxJWnV2RW15OHNIaEFRSHFQbVZGM0ttUW9rYm9UcUlXSGtvUDRSZEt3NWxnaFlhWXVzZ0tUbTJLd0Fnb095Yk5ndkhjaGV0WUtVYmJsU0tCWGN1TUpIalo4MTMvQUxQR2s0Y1BtRndMRFJwY3o1cnZYWnhKZkQvdkNPUzROWFQrUnVUMjJWdmhVUk1UVDZxbmxmWmJCZ1RkZE8xWm1UdWVoeFBndDNBQmd0NUJLUEZ5bkhEWkx2WnVxWllCQVdRYWpnMlRCQUNCTjFVSVZrM1ZJVHV0ZFdVN2VWVTFiclhVSUJqcTlEdHlVNjJ2YTVscmhhOVZTR081dWttNG1XT3RkT1NLc21iQlZrU1hJU1ZOUDNVbTU2cFJ1S0J3c1NoU1ZBQnVFTW9qY2N1VGZzRW5FdW5xdDN3NkJwYUxqbjBYS2N2NGpvY0xuaGRDdy9HMk5ZM2NLbktKdDRzaW8zWERzS2JKYmJuMFZpM0xEWkRmVCtDb3NJeGp4dDNXNzRiWE5ld0ZLMnNzN2t5cWt5ZnFId242S3ZueWU3ZndINkxmNHFocmdwdTdwM0lDbDBEVm5McE1wU0MvZ1AwU3NtVjVHSDREOUYxcnVJWGRHb0ZSU3dFTzhMZUYxVE9iTE9YU1lNV3R0cFZkUGhla25iOEZ2MVZSZ2wxaGJkVXRWUTNKMlRMRDJHcHVveTBiWFhvWFNBMkJJKzlYajZBMzRRL2NtczZCQTJjMkM4RlhKRlk2ejlWYVUyWUh3MjhaK3FxNTRnTmdFSnNCY2hzNTRmNUcxdzUxbGl0cU93OVU3Rm5idnRpOGZWYUhQSmZZQlNwMk92ZTlrRkNQZG16bzBPWW9uMnU1WE9HNWdpYTRlTmN0RG5ONGVtNGFpVmxyUEtGZ3ZTTm5ZZjhBS1NuTFJkd1dZOHhRSDdZWEluVjg0SHh1VVc0bFVOUHhPUVVEN2t6c2JzZWd0OFlTaytaSVdBMmVBdVYvcGFvTmhyY29tdm1lZDNGY3NLT2tmb2REcU0xTjhRRW5UelZCVVkyL3hIV2VmTmEySHlQTjlSUjJ0a2tzTEZTeTNEVFY1Qks3RjN5QTczVkRVUGxsZmNYV3dSNFMrWGxxWmp3TGNYYXBaYldDalhHMEVsUUJzVHNucUhCWEJ3dTFiU3pDMlJBYkRoV2RGaHpIMjJDYzJEUlc0YmdIZUJwTGZ3V3cwOUF5bExiaTF2Uk14dFpTTjRDcHNVeGJ1d2JGVjVNbEZoaU9JTWhoSUZoc3RNcnNTTDVEdmRDcjhYZExjWEtyNDNHVjI2ck5uYUcyeUVubE13NytxREZEd25Jb2JBSUNia0hqRzNDbTkyeTgwZ05TNzVFREJmSjU1M1VMOHFEbjdyR3JaRFlPMHlYS0ozNnFBTnlpQUpBWml4c2hTRkdjYkJLeU9VSUJmdVY0S0pkdXBEbFFoT0licHlJV3NsSVc3cDJFSUNGaFRqWldVUFJWOU1ObFpSRFlJV0F3NEF0d2p4Y29JYnNtSWhaQUFIYzIvQ1BUTlM3SGFpbUkzV1JnakphYnBpL2hDV2E3VWk2cktFQ3RkdW1HSlJqcmxOdzdsUWcxREh1RTF3MUJZNE5BWG56aE1RdGtaWGI4bEx5ejNCWHBKZVVsSy9uZE5pS1lPcGt1Q3FPczVLdFpYZ0E3cXBxM0RkT1FsbXZZdk1HTWN0SXgrWUJnMzVXejVna0lpZVFlRm9HWXFzOTNIdXJPQld5aHFIU01aWHdzNDltT2twbURVNWt6SG4rdC9jdjBGRUFvTUV3OWpSb0Fwb3dRQmI3SVh4bDdNV0JIR3UwS1p6MjZtTmkxaS9vSEZmWk5aVTk5RXlMb3hvYjlCWmVvMDBlRWVSMVV1V0JiS0pHbFlqY1dIY3FERzkyMHJ3OFJXcWpHa0YxWFV3VUFPc3BoeU00SEJSR2xMaDEwWUZRZ1ZxSURkQkIyUkFWQ0REZWlJQ2dOS0swMlVJSGJ3cHRLRTBxWUtoQmhpT0RZSlpoUmdkbHdnWU85VVJoK2FBMXlLMDNRSmNpY1B3cW1IYVZLelFPOEJQZURocUdIYkZFcDJhR21kNXUxcCtGTnFoMFpMRkxjeWNHcHBMeVBGeUFtNEh1Zk4zbFEwTWFkaGJ6VWFlMGhEeUxEa0R6UnNUcjZURE1QbHJhNlJsTkJHMHZCZndTQmRMYlJZelkzcmw4SkxGcGFYQjZKMkk0azgwOUJHUEZKNUJmQW50VmUyL0pVelM1Ynl0UEhORTBtQ1Y3SGhybWl4Tjl2dVZQN1lQdGVWV2EzVldXY3V5dmdpYzEwWm1nSUlCSGg2bGZJZUM0VkpUVFNWVmU0MWs5UnVYdjVCL3dGaFpzeXFrZlJmWi8yZW5pbXBUVDcvbDZEREJVWW5WR3FxcW1hcm5keTJkNWVQeEtzV3hobHRnUGtGTjBUR08vVjJCOUZsM0N3OGs3WjlmeDZkWU1hVkVTZk5ZSkhrdk81UXp1VXRGbkZPdUF6R3RxUEVUeHNvdGEzV1FPaThHZDNDNEE3bFRERzBrWGVQY0xrWDNRcHRzWENDZk9UZ0Urck5ISTRsbzAyNnJHRFpReGp0T3hTT2l5N1Rtc3FIblNHdHZ6eDB1cTdFc1dhMTBEblIvcTN5TmFUMHRjTDlJZlliN1BNdU55c01hcFlhZXNxbVNOTjJYdUNia2o4RnBZSU5zOGYxdlh3MDBHb3YxRGV4TjdOVS9ablE0amlHUFVQZDEwa1ljMXNyTlZuWGJ4ZjVMNnE5NGJVUE16amFSM01ZK0VMTlBxZEpLQXozZGcrejVwT2FvYk5WT3A0MjZYTkY5UVhvc01hUjhSMTgvZk1qY21TbUFiZXppUGtsVHBKNXVzeWc3aTZHMXZxcnowNVNlaG5qNW93OXcrYWgzYno4SXVqRmpTYlhSUkVJN0VPRHZSTDhQYXhHMXAwMExEVzM0aFlLUkVUK1hFSDBSSEZ6ai9Oa2hGanAydUhpYUFVK0xpaHNkSXA4c1c3aVJ1NGJ0MFh0TW43SVRncFpYSGcyVXhoOHBGOTBxVVV4bitVK3pFdTZrZDlsWWtZUU5oY3F3OXpsQTZxTHFSelJjRFVVdFkwTGNVdXdneHNnRzdRdlNNQjVOaW1YQ1JwdDNSWGhUOTV1ZGxaakJDbmtsRVJ0SS9ZdERSNktiSW1qbHh1alNoN2Rpd2dlYXhIQ0g4dXNsK0drRDRzSmZkWkFtM3dsZUVtNjlPenUrTi9raDZTcFZIZmpmWkREWlBWU2JNQjFzbENTRkhXVUxiSnZhKzhXSW02M1JXMVR2MmlQdlZYM25xc2lZanFwWXpldkl0eFZPdDhSK3F3YXMvdEg2cXJFNXVwOTR1N2p2eHZzaC8zeDM3Uitxd2F0MzdaK3FyaTgzWHU4OVZONTJzL29PbXFmKzI3NnFCcUhjNjNmVkpkOHZkNXNuY0hOOURocW5uL0FGanZxb3ZrTHVYRS9OS2g2bnJVNEo0aE1tNndObEF1dXZLV0M1QmVpeUNvTktJMUlPUlprYnFUNGdiRUVyQWJzVU10ZTAzSktnNFpFbmRzc3BRSHZEdWdSdkR0aXB1SmpPeWhYbEcySDRLbTNkQ0R0Z3B0TjFCb1pwVXh3aEFxWUtoQXJTaUEyUVdsVEJzb1EvSFdSZ0E1SDFRNmNIV2lWMUtXSGtoRW8yYVdYV2I5NDAwdHBtcWFSR1VITGVHbXF4V1BhNHYvQUJXS3lxczdUc3R6N09zSjk3bGJKcHY0dWJlcXBaNWJVVzhhM3M2WmhOQWFYRG9yV0hoVUt5WjBMT2JYVmcyRHVJUUQwQ3E2NjFaZHJlUnZzdk9admpaclkxdFJtamEzdkFUdmRiSkEyTHVSYXdOdk5hcFFPYzExajBObGNRUW1VN3VjUGtWWGxIZzdZeE5FUzRscmg5VUdKMDFqdmZkRmxwV050ZDd1VTFUdUFBRmdxN1FEWXJUeU9FbmlVTVYwdWJmbmRPVlFzMjRBQ3A2bVFnT3ViN2RVeU1RTEs2c2x1d2hhNVdORG5GV005WFl1djVxcnFEMzcrVnFRaFFsTnNBMkc1MldSRTlremZKTzB0T0c4M1JaV0FTQTJYSm82K0NNd0ppYjhsWFloT0tlaG1KT216SGMvSldSbEYyK1FXZzlxZVkyVU5CS3hyZzBtNDIyVm5CaWNxSzA1cEh6MTJnNHFhM0ZaV2gyb2FuRGI1cXNvM0NLSm14M0NXZTB6VmtyM0V1MVBKMzM2cTFwWWhZYkwzbURFbFI1aVdTeHVGclpJZ2VxWmF5N2gxUzRaYmpaRmlmM0xUZE15cWhQZGc4WHFCVDBwM0EyODF5WE1GZVo2aDI5d3R4elhpUGhJRHZvdWZTdTFTRW5kSmdoMFFUWFdVSkpTVk1OdVZGOFNPaHhGcmJxYXpHMnlKWkMwUUV2SXRsalR1Z29nRXRXRHVqeWl3UXJJYUlESXNwdUFzRmh3VWRKY0VEUVlOdzNVTnJxVDJFS0xXRnlHZ2lUbE9DeGNodllRc3cvR0Z5S0lpOW94WnpQbXU2ZG1vLzBEZnpDNFhRU0RXejVydW5aMzRxQVc4d21TWEJwWUhSdXNyZHd0cHk1RURUTlBvdFcwN3JiTUFZUlR0V1hrWEp2WXBjRDdnZ3lOMlRia0I3Z0ZVb3Vpandib0VvVGpwUnZ3a2FsU2pvbFUyc1ZTVnQ3bFcwMXlrcDJYdnRkU2lHclY3eVFWU1R1TFRkYlBYUTIxR3kxK3FaY2tXVG9sSm9RTlVXSGxOUjFuZVdCS1NtcFhPMzNRbXRjMHBqU0l1RFphS3M3b2dncllLUEdITkE4UzBPS3BNZHQwOUZpZW0yNnJTaWk1RExTT3FZWG1jdGthTlIyWFE4RXpPSFJ0dS9wNXI1OXBjWUxiYnJZOEt6RTVsdkdSOTZUS0pkamxQb3ZEOGVhOGJ2SDFUVGNaMXUyY3VLME9hQ0EwZDUrSzIzQ2NlWTV6YnZ1cXM0bHpIT3pwVU5jWERsWWxxQzc3UVd1d1l1eDdSNHVpWVpWaC93QnBWV21YSXRGbEk0T0NUbGphNHFMSmk1U2M0bFdkM0E1SkFqU3RjRHNrM1lkckorYXNXWHY2SWpBTDhJR3cxRkZETmcvb29Nd3ZTT0ZzVDJBOVB3V1dSRHkvQkMyRnNSckg2REJ1ZEtETmhwaEd3VzdSMFFPK244RUtwd3dQSEg0SXI0QVRSbzdhT1FuY2dKMktJbXdWekpnVG5HNEJXRzRRV25nb0d3MDBLUTBPc0tiOExIb3JLR2djQllBb2pxQ1MvQlF0alU0bFArakVSbUVFbmpaWEw2SXhFWEhSV2xKUjk3RjhQVHlTN09XalhZc0dKSTRzcmFEQzJOdDRicHA5SVlYZFZaVUZOWmx5THFXRHZTRW9xZGpCYlNVYnUyRG9RanVacGw0Nm90UTF1aFN3ZkZRcStqMTc3TExIQ2xhZDBGOVlJd2QxVDRsaXdhQ0xydTRDaDdFTVd2ZnhMVmNUcnpJU0xwZXB4RXZjZDBrNlF2TzZVNUVvSXhwbEtlcHFTeDNzbHFjQk5PZUIxc2t0a29mWUFCeXBtUU5IS3JEVTZlcWdhejFTN0t2STlKVkVHMTE1enJqbFY1bDFkVVVTRkRZMURCZDk2a0NoTmViS1lOMEZqVlJKZzNSVHMxUVkyeFUzR3dTeFl2STdsTFBOMGVWeVdQS2hDQ20zZFlzc2hRZ2FMbE93aTlrdEdRYkoyblFFSHFZS3lpR3dTRUxkZ3JDRWNJV0F3NDRURVhDQ0JzaU1CUUFCb21lSk1hYldTZ05rWmowWUk1RTI2bWd4bEhEZ29RbEgwVGtSQWJkSnRjRVRYWUtFR0RPZk5EZE1TZ09kcFdSTUxKaUZzeTZVbEJsa3NDb3l5aExWbFlDeTNvbXhGTUJVMUdrSGRVZGRXV0R0MFdzcUxBN3JXTVR4RU1MaGRPUWxsZGpXSkIxSk1TZHdWenZGc1E3ME91ZUZlNC9YaDBiN09zdEJ4T3E3ME9hRHVyK21qeVpPcGw4TFByTDJPOE9iNzgrdExUWjhEaHE2ZkNmelhmNTI5M084ajlvcmx2c3I0YjdqMlVZZFZsdG5PMURYYmY0UjErOWRMZS9VODNON2xlcjA4T0R4MnBueVQ3NHYyVWk3UWhBaFNCODFjZkJucmttMTExTUhaQ0hSVGFVWkF3S09Ec0VzRFpFYVZDRERTaUE3cGRwUm1sUWdkcDlVVmlWYWJJMGJsQ0RJS21DaE5OeXB0TmxDREREWkdhVXZHVWRwVUlFSFJGYTVCdmRHaWpMa1NRdVNxU29LQW1ZS2QxVU82SHdIbTZneUVsV1dIMDVrY0lqczUzRmx5YnBEY3VOemlxQzA3WWhUeVBlUkZIU2k3blBOaGIvQlh3VDdjSHRZbGtsUms3QUtoM2Z4djhUMjNjd3RMckhjYmNBcnRmdGtlMGRSOW1tVlRndEJVTWJXMXNaaGR1R3VCM1BQUFJmbDFTdXFzZXJuVjFlNTgxVS80akk0dVAxS3hzMmZid2ZRZlpYcFR5dFBJdkx6WDVrOEp3ZWFSMGxUSVIzOHJ6SVhlcE4xZDk4d3g5M1k5NDBXSjZMQUdob0FGcmVTanRlOXQxNXVXUnMrMzRZNDhYWklpMnhIZHhpMVFOM09QRmw3VWVDcFhBSlBCODBKMjZydDJ4bVRKdjRSUFk5VmkzS0VBYm96ZUUySXZHcTVaRUEydVNGWHVmVlk5ak5EUVVzVWsrcCtod2phWFc1NXNtL2RLM0ZxbHREaEVmdk9JeWZ6Y1huL0FJMlgzQjdEWHNuMXVDVmRaanVic1A3cVNhMHNEWldhd1Q0UnRmNUZYY0duM004dDdRZFU4REcvQzlGMmY1bE5rMzJEMzV6N05ZSytTbmpqcUNIT3RLV3ROdzBIZ3JwZnNpNEpXZGg5ZkxsS3ZpZTJlcHFTK043V25RR2h4NjhmYUMrdmNRbjl3L1V4d1J3VWdQaEViUTBmUUtwcTh0VUdNVHN4R1dKa0VzWXNIeHNBUDErNWVrdzZaSkpudzdVZFd5NThqamtiNytvOWlFc3N6THRjQVQxVlpBWW1PTFd0SXJMZUtROEVmNHVpaXFOV1JUVS9qRWUxK3FMTFRSVTBSOTdQZEJuaUxoeXIxUmlqT3lZOG1YbkduL1FUZEc5Nzdja284ZUh1NWVRd2YwdGx6WFAvQUxTT1JjaE5lK1hGbXRySWhZUnUwMk52dlh6SjJrZnlpbmVpU253dDFLL1R0R1dsb0orZ1ZHV3ZYYi9jdjRlbWRRek9wS1Mvb3o3cWZUVWtMUzZXc3A0d09kVXJSL0ZVV0taK3l2Z1lMcHEybmRwNTB6dFg1U1p0OXJUUDJhWFBEMkdDa2R3K0tZZy9nRnpqRWM5NWd4SFU2b3hLc2FIRzUvMGgvd0NhcVQxYlo2YlRleTJiSlRuTnIraCt1dUplMUhrUENMdGUvVVIreklQeVdtWXg3YStRNlp4REd6RWp5ZC85cS9LR1RGVEs0bW94YXJ2MXZNNC94V1cxRkM4WE9KVkRqNnlIODFVZXJrajBHTDJXakh2bCtuL3VmcDlON2ZXVklRZExLaXc0dGY4QXNwQ1QrVUx5dzAyRWRWOUhmMlYrYk1OWlN0STFWVHlQVjM5NnM2WTBWUnhPNG4vSHFxL3Y4elZoN0o2VCtiSDVMKzUraWJQNVFqSzcrWXFyK3E3K3lyS2k5dm5LQmNOY2RUOUQvWlg1MHN3cUovd1NPSlBDTzNMcldDOVROSkVPbGllUHFoKzBKTC81TFgrRU1FbDhNMC82SDZiWVg3YldTTVRJYVd6TkovYUpILzByY01NOW9qSnVMYVN5ZGpDNDdhcFFQNEw4bGYwQ3d1L1ZWdFFCNWg1SDhVdzNDSm9BREhpMWMxdzNzSjNqK0tuMnRKZi9BQ1ZwZXdqbHpILy9BSlAyWXcvTitDWTYxb2lyNmJ4QVd2TzM4MVlQd3lPUnV1R3BnZU9mQklEL0FCWDQyNGRuYk5PQVN0TkZXMWMybmdPcUhycCtWZmJBN1FNbmhuZlV6SklSeTZXVW5iNzJxOHVvcDkvM01MVmV3K1hUeGJoYi93RHhQMDdOS1dmRU5YeVFIUmI4TDVTN05QNVFYQnNVYkZEbU9wcHFON3RuYWRQOXkrbDhvZHArUzgveFJ1d2JFL2VaSGdiQzNKK1JWN0Zxb3pmYzhWcXVsYXZUUDRzYitUTEI3QU9pQzVwdndyZXB3OHhHNEYyZENVcExHNjNnYmRiR1BiSldZMjJLKy94K29ub1dMQzZZZEROOXRsZ2hQWXdIY202Q2tDdExIeXlFYkN5ajN2a3MyUFRqcXZhWVhPMHhQTGllZm1oMm9KNFpSN1NzaVpGRXlGTVNVdmRSNno1SU1FYktva09OcmI3TG14RmVVczBlMWtWSWNMMm1WcDJhTEJURFpUOWxEWUxUTURpNndIRnlJSTVPcmJEcXN0WWIycHgzbm5melUzQUs3SUFxUTQ1V1RUdUc4ZzBsWmF6WDhsTnhaakJzOER1aXROcktMNHdXOThkbU4ySlJwMndVbEJKWFZ6ekRERTNXMGpxRndtMW9qUEkybmljOTdnd0FIZHhzcXpDc2JHSlNPWnViT3N1Y1lyblRFKzBqRi8wWmc4WWtvSTNCNGxqTm5FWDM0SGtGMDdCOEQvUlZQRVhBaDRhTlYvT3lnVmpqNmZRUTRiS1FrdU4xQ1NjeU9zRVZzZG03cUJkeWJUY0tiVHNoaFNhVkFBMTFOcFFnYklyVkNFMm9nTjBOcUlGQ0g0LzRuZHp2dVFtdjdxSGZ5VTVwUk5JT3FEV2dDR3dPOWxtNHZ6TmJOd0lqL1NhaG9IVWhkdjdQTUw5eG9RNXczTml1U1pYdzMzdXNpdnY0aHN2b1NpcFcwbEhFeG90NEcvdVdYclhSYTBuSUtycUxza0NvYUtaM3Zqd2R4cFQrSlZBaEpBTzU2SkdtSGoxZFNzS0h4TTE1cWtOVW92THgxV3lVVUEwWEp0c3FlamphWGpheXNwcEhSeGVBOUZ5WFlVdzg5TTEvMng1b2NidENUcG56elAzT3lzWmFVdGFENkt1MEF3Y3N6U3hVdGJLQnFWakt3aTRWVFhSMmE4MzZJNG9FMW10UGlkWTlVdkN3a29jdFFYU3VIcVV6VHlXSEMyWXJnQkl4S1hzNHV2ZCtTMjVSWkpOZlFvVDRkTFNsT1BKekk2UkZ6OU1UM25vRjgrOXRHTU9sbmZHeDMyaHg4MTNiR3AvZE1MbWRmU2RDK1dNNzRtN0VNWWthVGNYL0FJcjBPandwcEdMbXlVVWNEZHdTT1ZaMCt3Q1hqaHNHcHVLTmVweG84NXViWWRycmxBeEtZUlFFaE1CbWtFcWd4NnMwd1BHcTMzb2NxSHhOTXg2dU1zeGJlKzZwWE1zTG9sVk1aYXAxL05ScVhXYUFQTkRqaVBTQlJuZFRlZGxKa2V3S3c1dDBENEhBNzJVbE5rZHdvZFVEUkRJQ2tHcnpkbE1CQVFCTHdoZ1hLSklGaGdYS09vdzVpOUUwRGxFS2c4NlVEQ01UUkFqWkJZd041VFVSMWpkTDFmZ0pzZ29JWGU3Y3FVTGJsUkxMb2tRMGxTS09vdGFNV2MwK3E3ajJZVGE2RC8xQUxoVlBMWXQrYTdmMlNqVlFuL2lIOFVjdXhld3M2QVgya0FXNFlDNy9BRVppMDk3TFRENXJjc0RaYWtaZlpadVR1YmVKOEZtOW15VW1iWk1Pa1MwcnlxUnBpcitTazUzN0ZOU3Z0ZTZyYWlTOTFEb0dSM0tWbElKVTN2UzhqMUNDMVhUaDdTcVNxb0J1VmZ5djJTTXhEcmhER1F0eE5acUl0Qk95VGZDUEpYOVRTaDkxV3lVNUFUN0Z0VVZqb3ZKUjA2VTIrTFNoNkV0c1MzUUpzN21sT1UySXZqUFZMdTBnY0ZSRDJnOEZScXl6R1ROZ3A4YWV3RGNxL3dBS3pTOWoyK0k3TFJtVE5UTk84eG00S1JLSmNoTTdKaG1iTlFhQzliVGgrWVdQYVBFdUJRWXMrSWl4Vi9oMlpYdHRkeFNIakxzY2gzV254a09JVHJjU0JBWEtNUHpRSGFidVd5VWVQTWtBOFkrcXFzMVV6ZG1ZamROUlZZUFZhcERpTFhEbE9RMTEvdEJBMk9pelp1L0I4a2FLWUVyWDJWZDdicHVLcTlVRmowYk5ETGNCTUJ1dm9xR2lyZFRodXRqb2kxNEc2QnlLdXd5eW1EaHdvSER6cTRWeEJFMGhHZEcyM2toM0F0VVYxTGhyVGE0VmdNTGl0dUJkVGFXdEd4SDFRSnF6UmZ4RDZvTjRMc0RWWVcxeDZMTk5UdGdCR3hTVmRqd2hhZkVrcWJIZS9lUnFUTEhVV1ZjMXQ3N0lsSk93TnRjS2l4akZ4QzBrT1ZBek01WTQrTHFwWURpYnpWU3RiYzNDcDYzRmd5NHV0ZHFNemw3ZmlWUlBpenBpZDFMQjJGOVU0dUNEWXFqcksweXVPNlE5NGM0bjVxRHJuY3BUWTZobGdEK3FtMXU2V2pmcFJtU2hDMlNoZ3lkMkVCOVdib1VzdnFodGJxUWtvYmRJWEJSYmNsQ1k4azIzVFVUUWJKVmlYRU5DeTlrN3BhMERoQVpzRkF5a213UXNGOERZSUNJMnlXZ1lYbFdVRkxjYjJRQTdpT213Q0RJNnlha0ZoOGtqT2VWd01DOTZFdk9PNjhvUTh2THl5T1ZDREVmUlAwM1JKeHQ0VHRPRDVJQ0ZuQndtNFg4SkdKMWdpeFAzUXNCbG8xd3Npc095U1kvWk1NZnNnQUNGMTFPTXBXTnhMdnZUc1FGa1lJekc2elY0U29EbldVUTRoUWc0MlZFYktrZzhxV3UzVlFnN000V1NqcGRLSEpVN2NwU2FldzVURUxZZVdwRys2cmEyckFhZDBwVlZ1aS9pVkRWWW81OXhkTmlKa00xMWZzUmRhamkxWGZWdjBUbGJXRXRKdXRSeGZFdEpjTlNjaFRLWEc4US9WeWIrYTB1anF6V1l6RkJlK3Q5azlqMWVSRy94V1ZGa2R3ck05WVhGZlZybkF0OXhXdHBWeWpEMWJwTS9UTHNib2hoUFlsaFVRQUR4SWIvUnF2ZzY0UU1yUWU2NVRwNkcybHJEZXgrUS9KRUpzZVY2L0NsdFI0dlVQNGdvY3BCeUVDdkJ5ays0bUF3MDJVMmxDYTVUYVVad0tDaUFvUU4xTnZSZElIWTVGYVVGaUkwcUVDZ296Q2x4MFJtS0VHR2xFQlFtbFRIUlFnd3dvd0tYWWpEZ3FFRFFna3B0aDAyUzFQdVIxVGtUTmJnQXVKamR0cXhxbkJmYXdWWDJtWjdwT3pUSXRkamRXNXJab0JkckhIY2l4UDhBQmJQUVV6WTRYU3UyREdseCs0WFg1NWZ5ZzNibkpqV1lHWld3NmU5Sk5BV3lORzR1QTBjOGRTcXVvblNOanBlQjZuUEdGY1dqNWs3WXMvMTNhdG4ycnJwNVh2cG9aOWNiSFd0YTF0dnFsYVNLUGVjTkVkeGJSNUtxd2ltYlJSTWM4WEJIaXQxVnM1elp6M2tXMEo0YWVWNUhVNVdwSDZFNlpvSWFURW5GRVhJYmlwbjVvTHpaSXF6UWVNOXJYaHVoa2xFYnlOMTNhSENIcVpEYkxOdGlPTG9sZ0I2cUQ5Z2JybllYbGxzNEdjbjV3ZzdNY3gwK09UVXd4UHVEcTdyejNCOHg1TDlWZlo1N2NNSDdVTXEwWlkrTENwV1FnaUluY20vSFh6WDQvd0NZTkZSU3ZncHFXYWVaM0FqWVhFL1FMN1o5aHZzT3pqVk9aaWRZNXNPSHRBa2JISzNTN1RjYmJuK0MyZE5rYVo4cjlvc2F4eCtKL3dETFAwSWlMbVZUdThIdk1OdGllTHJFaExuNm5IdWFiN1JQQVR0WFBTNFBoOGpwcFk0S2VKcGVlOGVHOEMvVmZCL3RTKzNFN0J4VllKbEtwa2lsczVwY0FYRFVOdWx1cTNQSFVZV2ZPZEowMTY3UFVWNTl6Nk43WC9hVHlqMlU0YklZYW1scTY0Tk40MnVPcS9sMFh3SjJwKzJybVR0RXE1b2NMWlZZWEcvN2JDTFcrcFhDc1NxcTNPbGZKaWVQdjk1bG1kM2dMZlBqMVR0TFFNcEl3NkVhWVR0WThyeitwMThrNlI5aTZiN05ZOEdOUElrMy9VcmNYT05Zek02cnI4WmxyQVNTNFB0MTZjSlNrdzkrSnpNZ29xQTEwNE5yTUc5L3FydWt3cXF6UGowR0JZTkc0elZJNk5KRjl2elg2SWV6SDdJZUM1R3dxTEdzeFVRbHJabUNSam1FQWgxL0t4OGtHTEhLZklQVU5kajBVZmg0WjhiWkM5bFBOM2FJeUpzOUpVNFBDVGU3MmkzOFYzM0xYOG5UVU43cDFYalFjTEM0YzAvMlY5NDAxYkhTUmd3QXRwT0dNUElQK0xJVStKMVgycEFXbmo1TFh4NlJTUG5PcTlyTlpDVGpqazEvUkh5eGgvOEFKOVlGREUzdnE2bWtkYnFEL1pUdi93QUJHWG03TmxwVDYyZCtTK2tEV2F6dnVWbjMrYU1lQjFnclAyY21WWWRlNnJxT1ZsK2kvc2ZMK0lmeWYrQ3pOUGRWMU8wK2dQOEFaV25ZeC9KNXVZMXpxWEZHK21rSCt5dnRBVmozbndHenZNcGlIRU1RaFBobWJaSyt5WS9rYysyK280bmJ5ZlJINXZaaDloVE0xRTk1cDhSbWRwM0dsdjhBOXE1cG1EMmVzNjVWYStTV21xNjVyTDdhUnY4QXVYNjZqRzZqZnZIMytTV2xaU1l5eHdxMkY4ZkJDcTVlbHhTTjdRZTJHcXhUU3lTNDQ4a2ZqQUsvRU1LcURUNGhnOHRHQWRPdVFmM3E0aHJhU1ZnZEVXU3VQUUw5TXUwZjJaY21kbzFMSzJIRHlLb2paejNOQXY4QWVGOFA5c1hzaTVrN0xhbVdxd3FOcHBXSDRZbTZ6YSsvQjhsaTVlbk5lUjlWNmY3Y1lwSlJrM2Y2STUxSEhIVXQyQWpLaCtqTlR5SlIzclBWVmRGaXVxbzdpU044RTdEb2NKUVczSTJQSzJHS29jNW9hVHlzV1c2QjlOMDJTR1duazVUS2JFY0JwTFhncFdoM20xVHdQTldac2wxVEtuRHNVcUlXTU4rNmp0K1N2V01kVG01TzNDaFBCSEtidEIzWGNlc2xqZmM1cnVrYUhXNDJsRGxwK2I4ejZiN0NQYmZJZEZobVlLUnhQd2QvT1I5ZGl2c3JMV2JjQXpqU05xY1B4R0NRdkcwYkNmSmZrSmlHWFlxaXp3M3hqY0s5eWQybjV5N09KWS8wTld0Z2pZZUxFN2ZjVnQ0ZXJTWG1mSE9yZitIVTlWSnl3YlYvVm42M0hEWlE0blVYam9vT28zRC9BTHVYZXErQXNDOXZUTUZLSW1WOVROSm9BYTdTeC9SYmZUL3loTU1VZjYzM291dDBqZjhBa3R1T3N2elBuY3ZZUHF1RG5kRi9QK3g5bUdqa2R4VGtLVGFGbE13dWtpRVRlcnowWHhGVy93QW9mSys0cG0xbHp4YUo1L2dxVWUwZjJyOXJkUUtUQWNSTkZUeStIL1NZM3Q5T3JnbngxVitaVXkrejJ1MHErT1MvNS9RKzZKYTNDQktXdHhhR1dYL3lRVGUvbHd2U1hsYjRZREV6OXRjUDdJdXlmR2FQVGltYU1Wb0pxbDNqSkV6UnYvV0s3My9sUmc4Vk9LZWV2cGl4dTl1L2IrYXNyT3ZVOC9tdzU4YnBpbmMzKzBzZHc3OXBSZG5UTE1aSTk3cC8vd0NzMUFrN1FNc1I4MWxQL3dEMTJydTVlb3VXQ1hvTSs3di9BR2lvdmEvVUJHMHNIVndTWjdTY3NEaXJnLzhBNnpWNDlwZVdxVmhiTFdVNXZ2dE8xVGN2VVZIQksvdWxsN3F3eDNkVkJ6N2ZDb3dVVXN6dXJHODNYUDhBTTNiN2tIS0ViNnFya2JNUjRyUlNnbjhBVndUUFh0NlFZN1VIRDhuMGVJTmZJUXhqaEJJOEM1dDBhRjJ5L0RGWGRIMVBtZk9tQVpDb24xTmZpVURwR0MvdWp5YnVYQ3A4MTVsN2JNZTkzb3FlcHdqQ0lwTGQ2TGFKR1crL3ovQmExa0RzQ3pkMnRZcEJqK2ZKNGF6RFNibUw0WDZIYmdXTGowSGt2cVBCY0xvOHVZWkRoV0NzOTNwb1c5MjlyanlPZlJNRVRpaFBLR1ZLVHMvb1dRd01aV1RDNE03Yjc3VzlGYXkxVDVuYmdnSG9zUGNZV2lLQTZiRllubUFzTGIyM1hTaExoaElOTGR6eXB5UDEvQ2dOYVhzdUZLRitnN2hRRlNETk5ncHRLRUNwdFVEQ2dvd0tBRGRGQlVJRkIyUkFVRnBzaUE3cUVQeCtqaTkxSGVPdlllYXJwYWdUeXVBSk55dGt6TlNlNzRkS0cyMVc2TFU4SXBaSnFsb3NUY3F0clpLalJtck9qOW1lWFh6Vm9xTEV0c3V5UnZiNEdub0FGUmRuT0VpandlTjdtMmNRZjNLeHhRT3BtT2VMcnlVM2NqVjBpbzF6Rm1mOUlYdWJha2VBTjcrL1JWVlZLK1djdU4rVWFPVjdTMDcySnNobDJMMlYyYk5UV25zQjh0azhLZlFCZTZEaDdHUnNhNjR2WUZXVVFiVWJBaFU5b09hU2FJVTRZMFgyVUo2MGFTTmtlb3BEQ3drRlUwd1BpMzZvMGl2ajdncHFzRjUzVlppRDlUSEgwWHFseGJJZ1R5YW1PdjVMcWlQa3pXcmE1WGZOUDA5bURoTEdNTmtOdk5PMDhXcHU2MUljSXA1SFpKejJ1NkQ2SVhkM2Rma0xOUTN1M1dIbW1YQVJVeGNka3ZhNVNRdFNwSE91MG5HeFNVRG1CMXZEWmZOMVJLYTJ2YzRDL3F1cjlyZU1CMGpvdzdyWmNyd3JUcUxuV3VRdmJkTWpVVlo1blh5dGtubmdKbWs0UVRIcWVuSUk5TExyVmFNNklPcWwwdGQwV2c1cXF0V29CMzBXMzR0VWlOcjkvTmM0eG1xTTBqdDc3cFRMTUN0QkJ1ZXF3d1hkdXZNRnlpdGJZcFRMQ0Jyd0Nub1dkS0Rhd3Q1RzJ5R0l6ZEgwMkNpQXB0TzJZYkdiTHhaWkVCc29seW0wSXdRTERaUUlGK0ZNM3NvT1NqbGtEMVVRYjhxUjZxRFJZb0dFak5ySWJ6Zm5kRkpGa0lpNVFCZ1hNMGxTMWVGRW5iWUQ1SUNDWUk1UkF1ZTM1cnUzWkV6VEUzeTFCY013d1hrYmZ6WGQreXR3WkcyM21FV010NGU1djArMVd6NXJkY01JOTBhdEZxWGY2VXcrcTNQQjVkVk0zZFY4M2M5RGdmQTdJVkUvQ1ZqVmNyMGhzMVpqTkJNcWNRSkJObFh1Y242enhFcXZlTElRZ01oU2tqU1V3OHFCQUlLNVlZbTRKYVZsMDY1dHlneU4yVXM1UldTUm02WGtZUEpXVWpSdWtYTUpKVXNsQ01rR3JvaEdsUGtyTVEzNklqYVgwVXM1UlJtblBraG1uOVB3VjIrbHZld1MwbE1XOUZ5eVVWUnBENnFUUVdwNHNJNktQY0R5UldHa0x0ZVFqTXFTMzBSVzB0K2lJS1BjYktia0dna1dJdWFSNGlQdlZ2aCtQT2pjTHZQMVZRNmhzQW9pQnpDcWpMTWN0Ry8wV2FBR2dGNnRxUE1RMUR4L2l1WXNrZXpnOEppbnhLUmp1U2t5UmV4Nmlqc05QbUJwQThTZml4NWhIeExrVU9OUGJieEZQdzQ4NERsSmNTOUhWbzdCUTR3elVEcVd5MFdQTVlCNGx3aWt6SzlyaDRpcldMTmpnMGVJcExpR3NxTzlRWm5pYmJ4aFNxczB4QnV6d3VFdHpjLzlzck11YTVYL0FHeWdjUWxrUjJZNXRZTCtOVjFabWtPT3o5dm11VHg1amVUdThvNHh6V04zSU5vZmlJM2pFOHdkNjNaeUJRNDdvUHhMVFc0bjNwc1NuSUp4YmxHRHZSczJJNDRaV2tYVkd5b2M1eDNQSzgyMG5KdWp0aWFQSkN5YjBGaUpjQmNsTU5pQjZwY2VFYkx4bGNFQnpjaGpVQXZjaENCNEttQ3VOaUxNNmVWaHBXYjhxTFNnWWFQT1lYS1VjS2hxc2pSeTNRTUt3c081dFpOQWFSZXlIRXdOM1J0WUlza25HenpaN2JJa0VHcDEvTlNpcGhKWlBSVTVGa0RGc0pUMDRBVElacEhKV0dzTFFvdmNRZ0FaQ2QyeXJaM1hLWW1sNVNNajdsR1JIaXZhMUZwdXM2VkEwU0c2STJPNkd6WkhZN29vR0ZnMktzb0hBRGhLc2lBc2p0RmxCUXozdGxtT29Pb0pkRlpwVUJMQ0dXNlphNFc1VmRHZkpGRHpkUUFmWVFDbUdQU0RaQnR1aWQ4QjFSTmloN3ZRb3VsQVNScVFPcUUrckhtbHNKSWRmVkJxRTZ1QXZ1cXVlcjUzU2I2czc3b0R1MWxwSlc2TG02U3FjVklDclpLaDdyOHBlV1N6U1NqVEFhQlYxZTk3aXFxcXJkSTNVNnpFWW9yM0lXbzQxbVdHTnJnSEJXb0t4VW5RM2lXS3RZMTEzV1dpWTVqN0dGM2o0VlhqdWJkUmNHdVdnNHJqTXM3ejRpclVZQ0hNY3gzTS92R3RvSSs1V1hZT3gxZDJtNFNUZHc5NUd4MzZMUktqZGpuRXJxUHMwVXpadTBUQ3phOXFnZnVXN28rNTUzWGRtZnFYV1E5d3pTUEQ2QkozQ2V4MTJpcWN6eVZmZmhlaVhZOGZMN3pDRFpaNUJRNzJVcjhyaU9NbTA4SXJUWUlMWElqU2pCRGczUkd1UVdsU0RsQ0RMU2lncFpqa1VPdW9RT0Npc1FHbXlNeHloQmxpTUNFdTF5SUhLRURzTnltV2k0c2xZeW1vellLSFJxa0FnR2s5ZDkxWVVjUGR1THoxVmN4cGtickhSWGVGUkdvZXhwNEhLN25kUkRtdDhkcUtEdFp6dlQ5bm5aL1ZZcE5JSXpORkpFTCtaYmIrSy9Hbk5lWVpzNTVzeENxa2VacjFNdWx6anFJQmVWOTBmeWovQUdvSERzdHR5NVJ5bHNzZFEyK2c5QzVvL2d2aEhBS0psUFRtVjVCZTg2OS9YZGVVMVV1VDY5N0phU1VNY25KZVNMT09uQnAyc3R1QlpSWmVsYnBVNFh1TG5ub29sd2tsSUt4M3l6NmRvM3N6Ty9Rd1RkREtrNDdxS1BjV3NiOE9MczlhL1JaZXhyS1p6M0d6aHdGa0N5bkJLMTBnYTl0MjlicnNlVFBYeFpOMzVrcDJhb1lIUjd2UFJVZU40MCtta1pUc0FOZTk0WjNmek5nalloS1o1SE1nbTB5alprWTVKOUY5WWV4bjdLaHpqV1FabHpMRUhReU51SXFnY0VDL1Q1aFc0WW16SzZ4MUdHbWh5eTc5aWIyY2FuRkh3Wmp6Umg3V2QzSUN4ajQ5YkhOSnZjZ2p5QVg2RTBWUGhPVzhLa21FY1ZGU1VyTHVNTVlZTGZkWkpZTGdWRmdVRU5GUTA3S2VCalEwNkwyMkZsOHNlM1A3UlVXUmNCcDhGd3FjT3FLeHBpazdvN3RPNTN2OGd0dVRVVWZFTlY0blZOWEZ4OURsUHRuZTE5UGpXS1ZlVnNxMUxaWVkzWDF4djB1SUpzZVBRTDQ1dy9EcWl0cUgxRlc1ODBqM0Z4TWhMdHliOVZIQ0lwcXViOUlWYmpWVmNnczR1K0szK0N0ampBamJzMjExNS9VemNtZmNlaWRHOTIwOEpiZkpNRkZTQmxoYllkRkhFSnhGQ1dqYjBUakFYQXFxeFdOeGNEMEJ1cWNPSHllajFVdHVMYWo2by9rL2V5OXVQWnFwOHcxVk9KVzA5UnA4Yk5RK0wxK1MvUkhFWjJTeUduWTFyR1Ftd2F3V0MrUS81UGlxaGZsZVpzRnRmdkFHM25keSt1S3FPMHNwSHhkVjYvUytSK2RmYUtUaE50K24rNVhTVERXWWpzMGJvTHBQVmVxaUN3YWZqNjJTanBEMVdxMXdlUWhQeFlOQlRJdkNSS0dRM1h1OEtrR0t4SjRaY2pRazhrUnN4OHlxL3ZOK1ZrVEtEeXk3MjQ1VW9haTN5VmIzM3FpUlRnRlFoYlIxZmR1dURiNUt4TGFQRktXU0dxcG9aeEkwdFBleGgzSTlWcjdaUTVOUXpGbzJOaXVVbUVwTk96NUE5cXIyUVF5bnFzellCRElhbU5ybk5pamFXc0pJdjArWGt2ajNDcXVXT3Nsb3E3OVZWVXAwbGc4LzhGZnNaSzFsVlFQaXJyVkVUdVdQNElYd043WW5zN1NaUnJJTXlZTzM5VlV2TTBySVJ3TEViM0hvRjVucVdDNHRvKzBleUh0R3NHU09LYjgzeno2SEQzVEdRQnp1U2l0RjdiS2x5L2lBeGJENDVUNFhIN0t2V1dzRjR4NDNDVFAwaG85VkhVeGprWDVNem92MFEzUU5kc1dqZjBUQUNscEE2SmMyYU9iSDd3cVJYU1lSRXczN3R1LzlGTHk0Tkc4QWlOdjlWV3J3NlR6WG11MGJFSnlrMFUybG0rR2lPRHRndzRoenFlSjdtN2dPWUR1dHJvKzIzR2NJajBVK0ZVY1duWnJtTWEwL2cxYXE5bXJqWkRxS2NQSUhvbXh5MTVtYm02RkhPN2EvWWR4dnRxenJpa3BFYnBZMjM0am1jQitBVkhOblBPZFMyN3FpcUh5cUhxMlpTUnNpdnRleUF5QjhqOWliSm5qZm1CRDJmdzQrNi9ZcHptRE1KaWNUWDFuZTMrSDNoLzVyRk5VWTNWdGUrcnhLdWl0dTIxUS9mOFZkMURJdzNVMWdKSE5sVzE5YkRUMDdwREswT2FMOTM1cmtjenlPa3lqcU9rWU1pdVNyNUZXN0ZjY2JPNWpjUnJEQzBYMWU4UDhBelZEaVdiTVd4R29GTlI0cld5MVBBWjd3L242clpjcjVVeDN0UHhLS2t3NmpucDQzdUY1bUFFV3Y5Nis0dXduMk5NTHlkN3JXNDB5SEVaRHBrUGVnM0Y5eU9BdG5UYWVjM1o4MTZ4MWZUOUdVb1FxK2U2OUQ1VDdJZlpIejcycjFNVlJqSnhHUERTZFd0czBodTM4Rjk2ZGtYc3c1VzdINk9MM2FOdUkxYkFRUldRaDVBdGEvaUpYVW9hU2t3T2xaVFlYQzJtWTBhYlJwV1ZzNThUNVMwK3E5VGcweml1VDRSMVRyL3dCcDVIU1MvUkRFMVZIRXp1NFd0aGFOdE1Zc1B3U2tZT29rZFVGekQxTjFKajlLdkdKWWVSK2srcWlMT1FublVWTUZRZ1ZwUkVGcmtRR3loQWdLSTNkQUJSV09RRURpeWtodEtrQ29RSzNkRWFVRnB1cGczVUlma2ZqMkp0cUoyeEYzaGNQTk5aT3c1dFRpVVlEZFExZEZSWWpoN0hpd2U2NjZiMlZZRm9hNlFndTJ2Y3JIMXVUNFRWeExlenFkSEMyaG9XUnRzTGRGR3VpYlYwYi9BRFFxaGptekViMldaMzkzWnZtRjVqZDhSczQ0N0VVRlpoYllvOVZ0MHZCUkNTbmFiYjNWM1dRZ1JheVR3bDhPMFZCTGZSUERiM0I2R2tkSXdYSTJWaFNRUGhsMk4va2cwc0R5UzBYNVZuU1FTVTd0UkZ4NnBMS3MyMlF4R1Z3aU45dm10ZmJOcjFDOTkxZVk1TTZvamNHZ0Q1TFZZbU9nYThtOTc5VUtaWnhRQjFZOFpTRTdnR08zSEJUbmlrYzY0MlNyOE45NGxPNSs1V0lxd015b3BhUnhubGNDRHoxVmc4OXczWlpkVGlDWUFDeWxQc0dsVyt4VHZjaGRydS9jTDM1NnBUTldJZTRZYS9mVHQxK1NzUTNXMXBBNE45bHp6dGl4NFJVeFkwNmZCYmI1TFIwMkxlMFU4ODlpT0VaM3hWMklZcTl1cTQxMi9CVnNORVlvZzRKV3NjK2V0TCtmRmU2ZWZLNHdBVzZyMkdteCtHanplZVc5a0dIeEpreWFZanYwUXFkdW9jSmV1ZjNURGMyVnBvUkUxN0g2M1NYaTYwaWNsN25Iekt2TXcxSGVQTmlxSXBUUlppWWlhaXVBQ2lDc2lNdSthVlJZUml3V1JhNnhNSFJQREhpemlMZ0xQY2U3RnI2aTdHTzRLN1FsSjJaSEZsNFJoSERHbTc2Znh0UG1oRUcrL0s3U0hwTkVYUm9aWWluWlk2RlNqamRBWGNLQkhxcGtIeVVDTEZWS08yUVBLeThXQzhTUEpRTjBMUWRnaTgzUkdDNjlwOUZJYkJCUVZtS2pkdGtycDNUTGhjSURoNGt1YU9qZUhuUzhmTmRyN0xwN2hvL3BCY1Nwalp3K2E2LzJZU2hqMlhQVUk4YUxHSjhuVWFrbnZtSDFXMVlMTURBQmNMVmF4NDBNS3NNRXFiQURVVlh6STNzTXVEYTRqdnoxVTV2Z1NzRWdkYmRPQVhadXMxbzBGSXFhZ2JsSXlnV1ZyVk0zS3FwNHp1bFM0R3hZakxzVkFPUm5SRkNmRlpKYkhMa2c0ZVNXbE5rMEhhalpZTk5yUFZjM0ROcFZQSjFJamFlOWxieFljMGpjS1g2S0k2R3ltNG0wcTJVd3Z3bUcwd3R3ckJsQ1dIZ3BsbE9BT0ZOeE5wUk5wUTUyNFUzWVlIamhYQm9kWjJGa2FHaUxPUVZMSnROWGx3amY0VU00VVIwSzNVVVFmOWtIN2w1K0Vralp2NElISUpJMHIzRFQwV2ZkQ09oVzB5NFE4Y00vQkx1dytRZlkvQkE1aDdUWHU2UEZsZzAxK2kyRTRZZjJmd1EzVVRtZlovQkR1UWZnbEY3cGZvc3R3c0RleXRIc2UwL0QrQ3dZanpaQTVIZGpSVlBvUzByTEtkd1ZqcFBraU1hUjlrZlJCWjJtaXRaQzVoNEtuM2oyZEQ5RmNNREhXMkgwVEVkTkcva0Q2TGhZM3NvNDVYbm9mb2p4eXZQUXE4RkRGNUQ2S1JvbTIyYitDQm9OVFpWTWE1eWFpamVVOHlsQTZmZ21vNmNBY2ZnZ3BCNzJLVThUbXVDdDZaaElDREdRRHdtbzMyU2h1NGNqMU40VE1aZHNsNEhoT1JrRkN5YmdqRDVvZ0FReVJkWlp1RUJOd1hTRjQ3SVk1VXh5bDJIWmpVZDFocnJsRnRzZGtQVHVnYkRUSmFOWENQREJkRGpDYWk0Q0N3N0dtVTl3Rk1VdGxobHpaTlFzSnQxUUNkeEtuYVdXVm5IYXdRWW1nRGhIamJZN29HZHNrNTREVW5QTUJkTlR5QU1LcHFxY1hPNkFoQ1dUbmRLT2RkeXhKTDZvSWVib3dxRzJMSGVYS0d4NmsxdGpkUTZHak4wekhId2dSbE5NRndvY3NhRWxnRmtTYnFJZHNGZ3VSQzdEaCt5OHk5MHRxUkd5MlVBYkhvNXRQS0o3MEFxNDFBSFZRZFdOQU82Z05sajczNnFMcTIzMmxTT3JiMzNRSktpLzJpdVV3QzlmWC8wa3VhNHU2cW45NGFMM2NVbkppYllDU1hLYlJpYUw1OVVTT1VGMVFQMmg5VnJGVm1OalI4WVZQVTVyWkdIZVA4Vk5qR0tTTjRueGVLSnB1NGJlcTF6R00xUnd0Y0E4ZlZhRFhaeEx0UUQvQUtGYXBpbU92bkovV0g2bzR3RU5teVk1bk1sendIclJjVHh1V2N1OFhKUzg4NWtOeTRsSlNpNnVRaVU4akZKbnZtY1NTbFpZdGluakdkOWt0TnNDcnNVaW0yVk03Q2FkNjdIN0tsTDNtZjhBRHphOXB4KzVjaGVPUXUyK3lJMitlMkhtMHcvY0ZwNlR1WSt1KzZ6OUxNeW5UaTBnNkt0dnduTXdPdmljcXJMN2hlaFhZOGhMN3pHUVZtL3FndE4xTnBYSWd2c0dCNFJHbTZBT2lJMG96Z3dDc3RRUWJJekZDQkdsRmFVRzlrYUpRZ2RoUjJKWnB1VVppaEJscFVnZDBOdkNtT2loQmlJM1RrZkNUaUtlaVBDaEI2amNHeEZ0dVNyZW5xQlFZUFgxVjdkMHpWYzlPRlcwWTF6TjhsWGRwMktOeTUyYzQvTTkyalhURWc4ZFFsYWlYSEpaMDBYUEtvbjVZKzE1blNUT2ZiTmljSms3eUlhWEMzL0U1YzhwNHphTm5UU0FsTWR4RTQ1bnFxckM0eUI3ZmlKdjFLc21iQUx4K29sYlAwYjBUVFJ3NlpQMVNKdmtFQURmUHlVWldhR0I0NUt5VGZsRGNicWt1VFpYd3ozRVNkZ3NxTnQxSnJVdm14K3BkY0lJQmREcXFxbm82WnhrYWJvbzhncWZNQnZBNk9md0FqYXl1WVZiS0VwckZqY242Rys5bW5ZUGoyZDhjbzhib21qM0NrZUpwUVc3bHZHMi9xdjFvN0ZLV25qN05LQ0tPSjBWbkd3ZUxIaHE0UjdEK0taWXhESjRvSW54UzFCZ0RKQTVqU1FkUVgxUkJRTndWd28yTUVkSXo0UzBXM1hvc09HMGZFZmFYcWNwNVhDTDgxNS9rVStmTTBVK1FjalYrTVZqd080M0ZqdmF4UDhBQmZqUDJ1NXVxTzBudEt4U3JxM21hbGpxZGNJOGhwSDVsZm9UL0tEZG9Bd1RzL3I4SmptTEh6UWFnQTZ4UGgvdlg1cllBeDFVRE00WEx0eVQxVlhWejJKbm9QWmJwM2pUamxsenkvTDhpN2doYlRXbWhHa0hiZE4yMWJsZUxBNm1iYnpVZ0xBTEFjdDdQdWF5Ung0bGppdXlDUitGcVVybWlXTjlnYjJLWldTQVFSWlY1dmF4T1BCNDZhWjN6MkJlMGtaVnpoVDRCVVRDTVZOUnJzVFlmRi9ldjBpbWVIQjB3Y0hObDNCQnV2eFBwTWFxY2k0OUJqMUU1emF1bjNZMEd3UEIvZ3YxUjltanRkd3Z0YXlOVE1kVmgySVVzQTcxalNEWjEvNzE2blI1bEtqNFQ3VWRNeVNUbEZlWHArWjBhVnZjenVrNWFSWkpTRzVKVmxOQzZOeGJJTFJqZ3BKelJ1dCs3Ujh0MDhIaW00eUV6d3NEY0tVd3R3aENTeUdJL1Z4cmxFbDVZMUwycEdBajE5MFFzTFJ5aDNDeVRzb2REeHVJNm83WkNOd1VrMG9ySGJoUWhiUWwwZ0VsUTRPaEhMUWQwaDJnWmFnenRrckU2R29aM2pEQ1d4Tjh0MFdGaGU5cjduU09SMFY1aDlRMlZyb1NBUTRXdFpJMVdOU2lIcHA1Tk5xb0pOby9JUE11WFpNaGRwRmJsN1IzY1VETGdXMjVjUDRLd1liMnN1bisyeGx3NEYycFYrSU5qRWJaSE5icUF0OXMvbXVXWVc3VkZHZWJnTHdHc3g3R3o5bmV5MlY1ZERHVGY4TWYySEdGUzFFTHhIaTRVbmJMRGZMUGZhQ1Z6YWw2RW81R2hwUUhqdkpObE1MTmdqYmFSWXpZWTRlVWVjTzdDeGN2TnVxeWV2VllqWUxHb2NiRm0xdWlYYktjY3Mzd2p6b3BIYkJ3QzhIU1VvSUp0ZlpZSk4rK2RzRzdoSjE5ZExXMjdwb0ljYkN5ZkdMWlh6UEtrM3lKWXJpN3NQRG9XdGRMSy9jQ01haitDNkQyTmV5L21MdFJ4T091ck5EY09EZzhzbEFhUzM3eXZkbStBWUJnOWZEVTQ3VUZtTFgxUTAwZ0RtdWJ6MVB5Nkw3czdKYWZGYXZESTVSaDBOTlFOWmVPU0pvYnFiZjBDOUpwZEJUVGY3SHduMm05cU11REhLT0I4MTVQOHl5N091eHJMUFpqaGNVT0gwWmlyR2JGNElJdGIwQzNXZXZsZXpUcThJRmxDdHJZblI2SVhhNVFkd2ZKSUdYYmNyMTJIREdFVDgvYWpxZVhxR1YrTTNiOVg2bVh5UzN2RTROZDZxRHFtVWovQUVvOTUvd29icGZWUjFYOVU2V1ZSNEswdExqanpGb0lKZzdZY0xEa05TQlRBQ1RUdWlBb1NtMHFFQ3RSQVVGcFJBYnFFSmpsR1lndDZJclRZSUNCV3FZTjFBY0tZVUlTSENJaGdvaWhEOGtxREMzVjlXeG9kZTY3dGtyQkJoMUEwbmt0WE5PenZCcEt1dWpMaGNhdjRydHo0RFEwMFRRT25SZVgxaytEYTBTdDhpTllDSkM2eUcyQTFGajVJOVZLM3VXbnFTc01sRk9QbnVzQ0wrSTI4bkNLbkUydkxTd1g4bFYwa0UxSEpxM3N0b2thMlFGNTM2cXZxSldQT214VjVkaXZCMk1ZZlhqdkdEU3RwN3lOMUxld3ZaYTdoV0dOY1E0aFAxbFNLWm1nSDBTSnVrS2lyWW5NOFBsTGJYdnNoejVlZUl5OHQyTzZadzFqYW1vako2dUM2WFg0UEVNSkQ5aDRCMTlGVlV1VFp3NCtEampzT2JHMTQydXFaOEVrYzVzRFpiUFdqUlhTTUJ1QTZ5QlZNallDZVQ2Sy9qa1V0VEdtYW5pTE5NclQ2SlNwZUN4dSs2ZHhJL3JDVHQ4MVVsNWtsQTVGMWVrakt4L21GRlFLZW1lWGRHay9ndm5IdGJ6STZwcTVHQWtnWEM3cm11dEZEUXllSUEySTVYeTlteW9GYmlNbC9GNGp4ODE2VHAwTDcva1pHdWxYMUsra0hlUmFpM2UxMTR2TjdXVHRLeGpLY0MxdGxGMGJTZGd2VjdWRkhub3UyWXAvQU4xVFkvVTZJellxNHJQMVRMaGFqajFScVlkMXhvT0pxbGRNWnBDbFFMcWJ6ZDVXWWhjcE1rV1lubU1SbWpSdjFDSUdEU2hTT0xUY2RFcGxoR1pIZTlSR1J6TkQyN0FGWjl6OTlqYjNzMm5UOExYZFVhbG9xckZkNEkzek9Hd2pZMHVjZnVDMkNoeXhKaHRiUjFHUFlmVXcwWWRjdGxpY3pVUFM0UzdHeGh5YTY3RHBXMHpkekRIZlovUW9SWllXdmYxWGRNLzVvN004UXlKVDBlQzRaVVFZaTJTNWUvaTNoL29qeUs0aElHNmlXN052dDhsTEd5alNGM0N5amJaVGVvSGhTeWhOODBSY0FndkZnaWx5Z1JkTERUQUc5MW15Sm9YcmJJR0dnU2llVk04b1o1UUJwa2p3RUNRYm80M3NoU2hCTVl5VUQ3T0h6WFRjZ1ZuZFRSaS9VTGwwWnNRdDF5ZlVGdFZIWTlVY0VNeHZrN3BMVWE2VnJyOUZMQjZ5endMcXVobDE0YzNmZlNoNFJLUk52NUt2bU52Q3pvVkJXQWtYS3VCVXQwYzdyUzZDcTNHNnRtMWhzQmRaclJvSmx0Sy9XVFpWOVNRQVVXbmxMeHlnVmZCVmVSWmlKR1FYVVNiaERkOFpVeHVxekxNU2NVQVJ1NnR3RkJqdEpUREpMbmdwZGxpaU1iSDZoYTlsWmFQQ05saW5EU0JzbUFQUlN5VUxkeGZvcGlsSlRUQUV3MEN5bG5hRnFlbjMzUlpLVzNDeTJYUzdxbW1QRHd1dG5LRklvaTA3cGlOOXpZdFdaSGFIQVdQS2JaR3l3TmlreWtHa1JqaGJJTjJvaHcrTncrQUpxRnJmSlBRd3RKR3lTNUIwVUg2SHVmaDJVamdqQ053RnRMcVpyV29CaDNTZDdIYnpXSk11eGtId2hWOHVYSEMvaFcrTW85U2FaaDdIN1dYZHgzY2NybXdOMFp2cFNyNlR1OWlGMXFveTZ5VnV6UXFLdHlwdTZ6VjNjUzBjODdqUVY0RXRPeFYvVzRFK0xWNFNxU2FsZkU3ZEh1SW9tV09kdHVyQnBOZ2tvV0cyNmFqazNDQnlEVVFvdXBna0xMQ0NGTWdGRHVEMmtHY283Q1ZDTnRpaWdJQXFHb0hKMkoreVJoQ1lqZFlvV1NodlVpUmxMZ284ZkNBbEJnRk5yVmdkTEtiUWtXTUpXdXNhRk1ib2pXM1FOaElqSEZkTlJ3blpUZ2l1bjRvQWJJTERBeFFHNFQ4VEFCdXA5MEdyRjdLRmRCQnNVVjd3QWx3Ni9WQ21sSUJRTU5BNnlwc0RZcW1xSmk0OHBpcGx1VHVrWGk1dWdHSWxlNEM4MXR5Z3RlVWRqMFl3SzFpTmNXUU5hOEhrcUFNT3gyNmNpZUFFZzAyUkJJV3FDN0grOEhtc0dVQklPcWJEbEJmVjI2cHRBRm9aaHVnbXBBNnFxZFhIZmRMdXJqdnVwUURMZVNzdDFTa2xidnlxdVd0TnVVbkpXRy9LbEFseEpXQm9KdWxKY1JGdmlWTFg0aVdOK0pVVlJqbWk5M0p1MDZ6WktuRjNSaytKVWVLWmc4SnM1YTdYNWorSWFscjArTE9sTHJubE5VQkxsUmZWT09QY1Q0aXFhdHhWN2liT0txNWF3anFnOThaVWFnaFR5TVBKT1gzOFNWZUM0OHJPaDExS3hBUjdEam1BZEdib2JtRzZhTHZtb3lNc0VhVkNaT3hWek5ralVzNVZnNGxMVE52ZEhZbG9wSmhaeTdsN0lrZi9BT2Qybi84QW1IN2d1SVZRdEl1N2V5SzMvd0RPYkQvL0FDaitDMWRKM01mWGZkWitpMlBPdmkwbzlGVzZ0MVlZNmY4QXBlWDVmbXE2OXl2UXJzZVFsOTVoR202bUNoRGhUODF5SUw3Qm1teW0wb1RTcHRSbkFvS094eVhCdWpzTmxDQkwyUm9uYkpjbTZQRWJCUWdacFJtRkx0Um8zS0VHV2xUYVVGcHVpTlVJTlF1VDBSdWtJVTdGMFVPbHJTbnUzdFhNUGJOeDA0SjJXeU5ZN1NaNllqYjVuOGwxQ2diMzB6UjBYejUvS0RWeHBzaVlkRmV3ZEVSLy9jcVdxZndtdG9JMXJJSS9NVEtrWnFLZGxTL2R6dHJsYkdkbFJaVWNHNFRFMGVhdlhjTHgyZHZjZm92VFBacHNkZWlNYTFqbFFKVW04SmNPUy9GWEJNa0JkVERMQmVZTGxFc2ljUW4vQUpra2dUallIZTNxaDVad0dwemJtK2t3cW1qZFd2bTRhMzVqYjhWbXBjR3NlVHdBVjJ2MkVNQUdQOXNPRlZ0TTNRWTVpMGwzbnJINUsxcDF5WVBYY2p3YVoxNk0vUkxzQzdMY0x5SGtQRFpCUXgwMWJKQitzMk9xOSt2MFhTS2FaOHRUSTZRYTJCcEl1aDFreGUrR0ViZHliUDhBVmVaVUdDcW1jRC9vN21Gclc5YjdyMW1uWHduNTV5U2VxenZjZm5GL0tPWmdmWDUzcHFGcmlJblV4QkhUaHErWDhJaGJTNGV3RGt0WDBsL0tHWVEra3pwQlY2U0FJQ2IyOUdyNXZ3RnBxcUtNbm8xZWI2azJrejd2N0lLTHdjZXYreGFSZ21rWjgxTURZS0xIYWYxZmtpZEFzVEE3WjlGeFlmRWxLendGbElOc1Y0S1ZycGVxZEJMSjd2a2NVTFloUlJ6dDF2YUh0QStGV1haVDJwNHgyUVpuanFxYW9tOXlsa0JraVlSYlQ1SDZLRU1IZXNNYnZpUEI2S3N4bkRHMTFPK05vczFncysvVldkQm5ia2pPNmgweUdvMDhtMGZyUjJQOXAxQjJ2NUxwc1RweXhra2x6M1lPK3dCVjdVQXNjNFc0SytBdllKN1NLbkI4N1B5MEpDS0NLQWxyTitTMXcvZ0YraFZkQURDMlRqVTBPK3E5dGltM0ZINWg2NXAvZE5VMGw1c3AzZUpMeU0zVERqWWxBbGZjcTFFeUgvbXdSa0VMMXdvQXJOMHdXU3VGalZaUkpVYnFFQ0IxMFpqa3NDaXNkdUZDRnBUeWFXYU9wVmhob0xLcU0rcXFJdDY2SWRDRmE0WEozdGJvL1pLNU4zRUhKa3ZVUmE5RDQxL2xDS0dON3pVdEFEelVOdWYvQUZoZk1XRE8vVXhqeUFYMDMvS0RWSWh2RnFGeFVOMkIvcGhmTCtCdUppalBvRjRUcWxKL00vVy9zUm5jOUxHUC9iRXVqd0Y1NnlCZXl3L2hlWXg4cytzWTQrSEswWTZCZTN1dlh2WUx4MktmSkV5WjNsZE05dXZQYVhqVHcwOHJ3NTNXWjVBQmR1d1hJUVRZMU9PS0RteGFhWWFDMG5TMWczSldyVjFaVjQ1V3g0WGc4TDVwaThEVkR5TG0xMGV2eEtURUs2UERhUnJwSlozYVBBQzc5eSswUFpJOWxxbnk1SEJtYkhhWUYwalNBTmc0RURiYm5rcmF3NExyZytWKzBIdGZEUU9VRTM4bDZCdlpkOWwrWEJxU0RITTJUL3BDWnBhOXNOU045SjN0c0I2TDZwWUlZSU81cGRORlR4Q3pZMjhFZVNqaVZhUytOZ1Aranh0REEzcllDd1ZUVmw5MnZjNEdMOWtjMlh0WVZHajhzYXJxTDFjbTVobjFEWXBuU0J1b0VXdWwzUzMzODFoejJ2YnFadEIwYjFReVFyU2xmQmhQRHVlNkJrdUpLeURkUTY4cWJlRkhoM2NqRnZoeEpoQWJMSU4xRUc2OWRNQ0NhbE1GRHVwQXFFQ2c3SWdLQzAyUkFkMUNCbXVSR2xCQjRSR202QWdkcFVnVU5wVWdkMUNCV3VSQWJJTFR1aURoUWg4QjltZUVHanAzRnpCZlh5UjgxdStJemdRblliQkN3aWxqb3FOOWdCdXAxTWZmeHUrUzhHN1BWZGpYWjZrdURSMHVySDNXOGJUdndFTVVBTFFmTGRNeHk2ckR5MlMwamdFVTV0YmRLejBJSjFXVnFiQVhTMHJyM1ZpS0FZcEhYT2diYXdGa2hVMXpwbjdsTWx1c2thVU1VN2U5YmUzS0xMRzBXdEpCd2xiTExBMnZkSkVSKzBGMHJHNnFSdUNXTzNnSDdraGtUQmFXcVl4ejNNMkY5MWFaOXFhYWx3OTBiQzAyYmJiNUxKZU43ajFjYzhWQ2pqNzVDK3FudjVyRkhUNnFpUXVKSTBubEp5VllOWEpicVZoOVlZUzRpKzRzcitLTkdCcW1wdTBhN21LWXZrZTF1MWlSc3Era2U2R0Y3bkRwMVRlS2s2M0VqbFVPSzR3eWtwSGpZYkwwbW1qYlI1L1dUVkhPZTFETXIyR1ZqWFc2V3V1TTA3akxPNXp0N3VKM1czWit4ZHRiVlBBM3VmNHJXSUlkRm5mZXZYNmVQQjVTY3JZdzZNYWRrTnJ0S205NXNnT094Vjl4S2t4ZkVKdzFoV2lZM1VhbkVYV3pZdlZXYTdkYVBpTXBra1B6VmNiRVRBdTY2SkczZFppanZ1aXNadW9XNGhHRFpZSXVlTjBRRFpRZDRkd04xQTc1T2srejNtckM4azlxR0ZZampnaUZKRWJ1Yk0wT1lSY2NnN0x1ZnR0OXZ1VU8wN0E4c1UyVzQ2R09TaUJFdnVrTWNaUHg4NmVlUXZra05OUlRPbWUzdTN0MkJLQkM4UTZ1OS9YNnZodjBWVFp5WHZFVkU0NmlPcmkvWE8wZGRrTjFoc0RzdlNTNmhidU5DR1NqWEJYbE95TGtNa0tUM0laTzZadUt6N21MTHhHeXlzSGhJWVJBZFZteXdPcXlnWVFNdDNVUzMwUnJYV0NCWkEwR2dRc1VONHVpMlVIaElHU0FFTFljcTFZZ21iYzlWUUhsSG9aREZPMGcyVUJqM1BvREJKZS9vTDN1Tkt4RE5vcWlMMlZma3lzRW1IYVNkOUtQSjRLdHhVTlhGS2pac1BxaGNicTVaTmNEZGFqUjFHaHczVi9SekI3ZVZUa2EwWkd3VWRScEhLekpJRGRWekpkQVUrL3VPVlJ5TXZRa1luUGlYb2lneVB1VktOMnlwU1pjaXc4UUpjckNCb3R3a1lyWENzSWVFZ094aHI5S2JGVnFBRzEwa2l4TjNRTU5ERFhGeFZoVHNPbmhKUmFRUndyT25rYUdvUTBCamlKZHdpSHdkRXpGcENGT0E0N0xqQlJtSWE5N1hUa0VqWlNCdDVJTkkwV3NqR21OT2RRK2FWSWRFZFpFR2k0Ukd6RUd5RFRTNnRpbm1RdFBGa2xqVVMxM3NtS2VQVjBVTzRzRTNUTjBwSXdLMm5OdUZKa1JhVWRyd0FwMkJzaFowOHdiS1RxY09IQVAzS2JBRXdBTkpRRUtTdXdsdFN3Z01IM0JhUGp1WDNRT0owcnAwZmhKQkNTeGJERzFjUk5od25XUkhHWFJHTTJPeWxFMnl1OGR3WjhFcmlBcVY0ZEgwVXNZZzdSY0lyWFdTc1Q3bXlPN29wWVNEaEZZZ05Ockl6SElXemd3elpFRzZFMG93RmtEWWFDUjNUVWZDV2pGMDNHTGhCWVNETTJSMk9RdE93c2lSc0tCc01NRzNPd1RVRUJ1RUtLTzZzWUFOdGtpUUxKeHg2UU5rMUVRRkZyYmhGWkhzbGMyQVoxSWJuTERuSUVraWZRUVhYWW9GWE1DM2xDZE5hNlVrbEw3cnRCb0c5OTNGRGR1c08yTzZ5MHJsQkVReFR0WlNzQUFodmVob0E4WFdLSVhDd1NycGJJSnEvVkVrRFE0NmJUMVVQZnczcXErV3BCNnBLYVkzNVhkb0phejFvSTVTVHF2bmRJUzFYcWxYMWRoeW5KQzNJdEpLb2VhWGRXaG5WVk0xZUFlVlcxbUtCbzJjbXFERnVkRjdVWWtMY3FycU1hYkVUNGxyOVJqTmdmRXRieFBHWGF6WXBpeHNVOHFOb3I4ZkJEdkV0WXI4YjFPSUR2eFZYTmlEcEJ5a0pDWEhsTlVhS0R6bGk2ck1wSjFFb1Q1eXo0dGtteDVhalF4dXFqWWl5Sm9aamw0akdvWVJVL0NUZEg5MmxwallOdVBWVzJCNFdDUnVDVmVWbVg1bnhseklpUVBKVjVTTnJGb1hrVm1xTXByQzV2ZGVkR0FQTk16d1BpYzRFRUVJSUJQS0pHYkpWd0JzUEw4RkJ3dU9FZDRBUVUySWxvV21idHdxK2RwM1ZwSzNaSXpNVGhUS3FWbmdjYkx1UHNtQzJiMi93RHpSL0JjV2xpL1Z1WGJ2WlBicHpjMy93Q2FQNExUMG5jeHRkOTFuNkU0ei8yaElrT0U5alcySVNKRFZ1dlFyc2VRbDk1aEFzMzJLZ0NzMzJLNUU0d2c2SWpTZ05LSzAyUmdoMjhJdzRTN1NqRGhRZ1J2S014THRLTzAzVUlIalJVQ003bzJwUWdhTW83VFpMUmxIYVZDRGNLZGo2SkNFcDJJOEtIVVhWQzd1bWFlcFh6Zi9LSVJHYkkyRU9IU0kvOEExTDZMcFRya1o1TGlIdDJZUzdFZXpxQjdScTdtQW5iNXVWRFVyNFQwR2hrdmZJTS9MYks4Zi9STVJWNk5nRnJ1VUo3MEVjVHVSdXRoQzhublhKK2c5T3QrbXgxNkl6c3NnTElDbUdxdkV2eDR4cEVveHNzdCtKWllMQmVhM3hYVW1XWUttTDRnTFF2K1JYMG4vSnlVL2VaNXBYZ2NWSjN0L1RYemRpSXRCSi93bGZTdjhuQlVOaHpyVE5jUmMxUi8vdldubzN5ZUs5cDFlQi9vejlKOFFOcXA0SFFwUFhlVUMvQlI4UmRwcTVYZENVZzJUOWNTdlVSN0g1K3h6MjVXZk0zdCtkbHI4MVpCcnNhb1lqTFdRUWFXdEEyK0grNWZuWGc5WkpTMDRwQzBDb2dHbVZ2a1YrMTFmaGxGbUNoa3cydll5YUtYbHIrUDhicjh1UGFmOW5ER2V5N09GWmp1SHd5MVdIVlV4a01jWThMRzIrN3lXVHFkTzZiUG8zc2wxbFk4c1l6Zm0vWDBPYlFPaG5wMnVEcjFIMm0rUVRVVFl0UDZ0MnAza1ZyK0VZM1Q0MDBQR21qZWVXSGtLNExXMHd1eVFTbm5aZVd5eGNKSDZFaGx3NjNFbkdYa0dBZUgrSVdDWWMwT0czSFZMd3lPbCtKcGI4MGNpdzhKdWxyUFhCWjArbVdKazNSTk5vWVNYTmR5N3FDcS9GcXR0TEVJd2ZEYXp6NUp1TUVQRFE3VGY3WGt0ZnhHdFpKVkhENHJWTTlTZERiY2cvNEM1cGNFbEt5cHI4a05GamJiTzRleFRsK1d1N1dwYXFoQmxaM043K2xuTDlNY1drdlJ3TjRjMk5vTnZPeStaUFlqN0haTWpaUnBNYnJZOU5WSXh6SEI0MytIKzlmUnRYVWQ2NDM0WHVkTENvby9NdnRQMUtPb3l5akd2TVVBc3czU3BOM0ZNeXVHbXdTalRaeFdyMlBFNlBHM3l6SzhzYWw3VWhHbVZoeFdDNVl1RkNFbThvck5paE4zS1BHMjlsQ0RkTElYdUJJNDZxNW80aFN6UnlkSEc1Vll5TU5qOFBLWW1ydmM4QnhDcGsyN2lQVUNmbUVPVmZDSG9wcVQ4RitiUGd6Mjk4WkZibldwcEdQTHRNclRhLzhBVFhGY01iYUNMYjdMZjNLNzdjYzAvd0NXdmE3aUpMdGNla09GL200cXVwb3d4clFPZ3N2blBWT1pmTS9ZL3NiaGVEUjdHdThZL3NOZytFSWJqeXBIaFlBdXNYQndmUXNjSGpkTTlBQmZ2ci9EMFViUHFwTlJGbU44bDZadmR0TWJEZS9rcys5aUtMdTlObkhhNjdKK0p3ZzVaVkYrSEx6SVZNOGR5QWR3dGF6Rmo4bFBTdmlnczZxUHdNODFZWXZWeDRkQVM1NGRJN3dodlc2Njk3SnZZQlVkb09hYVhIY2FoTGNQaGwwbUtZZUZ3MWM3ZWdWN1NhV1RrbWVCOXBPdVkrbFlHbEpmRW4zczZMN0gzc3JOeE9NNXB4NktSc2hhS2lCcm1selhHNEhYNzE5bVY5V3dRZTZ4eHNnYzAzTWNiUTBEN2dnUzBNV1c4T3A2TERMUXd3dDA2WStDRWlLZ1NBeVAybFBJUEsraTZLQ2hGV2ZrN3F1dGZVODBzMG4zL3dCaUVycjN1VXRJNi9KV1h5WHVsM3YzVjA4NFQxYlc2TEtGclVnVjA2RmFmTkVCc2d0S21EWlE0RlhnYktDeUhLQmhGTWRFSUd5bUhLRUN0M1JHbEJhYm9nS2hBdzZJalNnTktLMDJRRUR0NFVoeWh0S21PaWhBamVVWnZDQzNsR2J3b1ErUFpvOUZNNERsRXBvcjB6ajZJTlhNYjJVNFo3eDJ2MFhpR2oxWWk5MmdFSkpzbWdrK3FzYWhnTGlxNlZtNVFKY2dHSFZoSnR1alFFU2NwZHJSNUtaY1J3ckVZblBNblY5M0VkbFhWWUphSE4yVi9oR1dLakZvekxwY1FEWlZ1TDBwb3BERVJ3YkpqalpvT1NpdUEyWHN5MUdHaXdmWVdRTWF4K2JGWEZwZmU2cTN1QUZ1Q2d4bHI3N3BQZ0NYcUgyc1JxWVRBL1VPdmtoeVRhbUFuOFZaOTB3bmMzK2FScjRXOUU2R09nSGszRkhqZFEwTU52SmNzenBpT2lCNER1aTZKbUdjVThMcjlBdUg1NHhQdkhPQWN2U2FiRFRSNXJXWmJSejdFcFRVMVpKM1JZenFEUWhSRFc4azdvZ2RwdXZWNElVa2VlM1d3cjRScHVxNnJrN3E0VFRwN2RWVTR0VTJCVnAwaU5GRGk4dHc3ZGF2TU5VaCthdHNTcWkvVnVxaG9MbmxWS0dSUVdOZ0FSR3RzVkd4Q0tCYmRTaXdtWnRzaFBGenR6MFJWaTNPeWxBT1JBKzhhZTdtZUhNUFFMQmRDNXpReHBCWXZFM1VIQzNDamlqdTlzek5VT2tsTGI3Qkx1UHF2UDU5VkJJa2dsSXc5Q1BLSTVSSVNIWjA4Q3ZIaFJVaHdpb01pdktkd0FodTRRdEJFaFpTdHNnb3JlRUZCSXdXN0lNb3NFd0ZHUnR4d2tVTVpYdWNqVXB2dXNQaTNVV215bEVSMDNKR0o2V2xoY09MTGJhaDkzNmdWeWJMbFgzVXc4Ukc2NlZSejk5Q0RlNmxGcU1xTEFWQmFRcnZDcXdFQzVXc0NXNXNtYWViU2VTRm55UnB3eUc2dW52d1VWa3ZtVlJVZGFBMFhOL21qeVZvZHdWU3lJMGNjN0xkenI5UXNzY3Eybm1EdVNuUlkyc1ZSa2pRaElzWVhXSVZsQWJoVkRKQUxKeUNleUNoMWxvRzNSd3l3U2tVK3dURFpib0dnMHdnQnVyQ2xZU0J1azRocVRVYlNMRkJRZGxpWWkwQ3luRlQ2K1Y2R3FFclFOdHRsNTd5M2paQXpxQ3VoN2tYSFJTcEs3M3gyaHdJc2JickVEVE1OMUlSQnI5dHZrbFNIUkhuVTRqQUlUTkpkOWtpSnRET2JvOUxVRngyU1dOUmF1ZHNpUWxDWVJwVTlhU05HMUpraEpDQkV3dTNKUnRRMkNGa0c0eUxjcVprc2xXQWxNTUd5QWdVV05pcE9lQXdoREEwcVdwZDNFUlQ0bGhyYXNPT2xhTml1RTkwWDJhZVYxUFNIQWl5cDhWd3RzckRadS95VTNERWNvN2tzY2RsTnhzRnNXSTRVWW5Idy9ncVdhbGRmaFRjRWdiTjBkZ1dHUWx2UkhaeFpTd3FQTk80VFRSc0VEdVM0M1IydTRDVzJFa0ZqNkpwZ1M4VzVUc1RlTmtOaDBIamJleWNpaHVnUXRJSTJWakJ3Tmt1d2JJdGowOUNuSVk3V1dCOGg5RVlFV0NGZ05tU2RLeTJld3NvT053aE9DQ2dMSnZkeWxaWFdScEpiTlNNOVFFK2c3UFNQUVdDNTVRM1NhbEVPOGxLQ0pTaXhXSTE0dnNOME15YnFVSFlVdVM4ajFHV2NBY3BPYXBGaUxxSkhHeWNzb0Y5eDlVaEpOWW5kSzFVMXlmRVVuMzViZTVUWXhGT1NHNWFxM1ZCTlhmcXErcXJBT3FSTmFCZmROVUJUblJhVFZIcWtaNnV3NUNyS3JGZ0I4U3BxckZ4dlp5YW9GTjVDMnE2OGkvaS9GVU5WaVpOL0VxNnF4YTl4cVZSTEtYRStJNytxc1JpSWxOamxaaVJ2c1ZWU1ZEcGp5dk9hWEhxVk5rSjhrOUpDZHpNaHAyUlk0eS9vVXhEU2x4R3lzNmFoc09Fcmdka3dlWlh4NGVYa0d5dGFhaWJvOElzVXpISG9GcmZnaU1IY213NnBVanVDTGhJWndVT3A2a0Z4R202Nk5CbVdncGFKekpBUzR0STJQb3VjTmhsY05RRmg2SWNqM203UzQvVlVKM1o3RFM1NHhqVENZcE95U2FWemVIT0pDckE0RW9qMms4M1VUNFFyQzdIbTVMbGdaZ2dBS2N0eVZJUjJHNmRFUkpDOGcyU2tyYnA2V0V2NFFoRG92Y2RFNUNXaXFtYityY3UxZXlrUC96ZTMvNW8vZ3VNenhrRXJ0WHN0RFRtNlBwK3RIOEZwNlR1WW11KzZ6OUFjYjJyNUZXK1NzTWVJOTllcS95WG9WMlBJUys4eVRWbnpXRzhyUG11UkJmWWswb2pGQWRFUnZLTTRFQlJRZlZCYndpRG9vUUswbzdTbHh3aXQ0VUlNUm5kRjFJVFRzRVZ1NmhBc1ozUngwUUdvNE53b1FZaEtkaWRzcStNcHFJOEtFTHFrZjNjUmQxV3JlMFJnZ3pEMlVZb1MzVzZLbEpGdm1yK0NTMVhISDBJVnBpTkczR3NyNHZoNUdzelE2QUNMOVFrWjQyalEwdVhabWpNL0Q3REtZNGZpcjZjalNXamc4OVZmRG9ydnQ4eWpKa0x0a3hPaGtZWW8yTkFBdGI3VGdxU2hrWkxGNHpaZVYxRU9UOUM5RTFNYytuUzlFZ3pOMFpvQkNISUJUQUZ1NGQ1cVdsMFVJbkc0Y2JMTjdHL0Q0cGJRakZodnhMemQ3RkZBRnVGekx3aTVWTVVyeGVGL3dBaXUzK3dQaUpvdTArZ2lMdElkT1R2L3dBYTR6SzNVMTIxOWx1L3N1WXFNSDdic0ZoTHRBYysrMjMybXE3bzVjbmsvYUhGdjA3L0FFWit1ZUw3UXNrSDJoeXFhU1FzaGEvektzSnExdFJndUhsdGlITTUrOHFycU5taG5rdlg0K3grYjgwWERNeWNrbW1vamxPNUFRY3hZVGgrZHNLbXduSG9qVXcxRE83aURkcmZQbjFVTzh2NnFMWml4NFBsd21aRXBxaGtjM3V6VHhQNUh4SjIvZXdQVVplRTJKWlRpaGhoQnVHM2E0MkIzNEk2TDVPeERDTWJ5aFVTUjE5RlUvcTNGcEloZGJaZnRCQmk3Skk5RTdXVE42aVFCdy9GYXhtN3NzeWZuNm5mSFdVOVBUdWVMRXhVN0wvd1dSbDBDeVBqOWozSFNmYVhVWUY4YmRLdk0vSWVITmphcG1oc2NrYmh0NDJrS1grVUpwQ2RZYzc1QXI5QnN4ZXdUbEt2cUhUVVZWVVhjYjJhd2dmZzVJVVBzQlpXMU5OWFYxVENEZTJrL3dCcFUzMHJuLzJQZnc5dGNlT0Z5ZjhBNmo0Rmp4UEVNZm5GTGh0SlU5Ni9ZTzdweEg3bDlSZXk3N0cxWmplTE16Rm1LQmpvNmR3bmFIV2E3b092elgxdmtMMmNNb1pCTWNrTVVkUTVsaUROQTAvdkpYUTVheU9takZQUlFSUXhnVy9WTkRkdnVWdkRwVkZuak91ZTFzdFhCeGcvL1YrWmlXV2xvNkp0RGhyVEZUTU4ydGQvajBWWk02dzlVU1hURUx5SFNVczUxd3RySERhajVqY3RWTnlreUdzbTkwS1Yya3FUaWhIZE1ZMmN2QVZJSURzdlhRd2JLWEtFaEk4S0t5SGVhODZTL0FVSVNqNkpxUGtKZUVFbmhPeFJtNE5sQ0R0R3dtcFl3allyU2ZhTnpZTWo1QXJBeVFSdXFZQ0xYNTMvQUxsMFhDR2FxdU9TVWFXRGtyNGQ5dXp0Wk9NWXJobUNVY29jeU9VeHlhVGJhemovQUJXZHE5UnNpZW85bWVsUFZkVHhLU3RjK1g1SHk3aFd2RnEwNHM3ZDh1eFBYL0c2MjJGdG1oVldEMExNTXAyUnhlTnc2RlhBM0hrdkFhdklza2o5a2RNMHkwOGNjVitSaDNLeTBYWGl2ZEZuTDRUMU9vcFN0RVlmMWRjelh1UFJJWXBVTWpkTElQc2JoT1NSeVNOUGREVk4wQ3BNVDBRMXRMSEk0aDBqclNEeTVUdEpqYzVjbVQxS2NaYWFXZURwcWpZK3hic3R4SHRwenpIVG1CeHBJeTJZdWtiWnBBSkozTzNSZnFGbGJLMkc1RXdDbXcraGk3dUlSTUVqYmpkd2J2OEF4WEgvQUdRNE1Hdy9LZE43dkhDYW5RNEYvZHQxZkQ1OHJzMVhKcWM2NTJ1dm9HajAwZHFkSDQ2OXFlczVkWHE1WVp2aE5ydUFkVVBpZktaWFhhNytidDBWWkk0dXFITysxNW90UThucWxYT081V3lvN094NExKYmp0Z2VjL3dCVU11M1E3cVhLSVdTQlJBVUlGRUJ1b1FJMG9nTjBFRkVVSVR1cERkUUJ1cEFxQmtnVVFGUlVnb1FrT0VSREJSRkNCR2xFWWhOS0t4QVFNRFpFSFJDQlV4MFVJR2J5ak5PeVhhVVZ2Q2hENHZucldQNmhHcEpOZXkxeUtSenVTcmZDNTlMdHl2R3RIcXkybXB6YTZTbGhIa25xaXNBWnR1a3BaU1JmZEFseUFMZDFaWUxMRWZOVER5U2h5eWFXaytTc1JRTE50d2pOTUdFNFZJMHNHcTYwVEVzWkdLVnN6d0xDOTFYMWVKaXAxUmk5dUVrMGluSnNQaVZpRWJCZVZzYUR0YzdoZmF5aEdBeTUxZFZEZHQzZzdsTE9sZHZ1clN4cWdPNDUzbHp5aFZSYUdFbHc0VUlJbk91YnFpekhpRDZOai9FQnNlcUZ3NU9icU5WenJpYmU2a0FkNWhjTXpKTVpaWDc5VnZXWnNZZEwzbTk5eXVhWXRWYTNuNXIxK0RGVkhsZFhQdVY4Rnc1R2V6UzI2blF3Q1RjN2JMMVM3UzByYWlxUmt3ZHNySjVOSktvY1hxTHRkdXJLdG5zU3RaeGFvSkpGMGpKS21XNjRLbDhuZU9OL05UaGphaE1pSmRkTU5ZUWdDUVF4dFBrb0Z0bE5nS3k0TG8zeUFrS0o2b2psQTlWQkRZSGRSZXBGUmVnc3RiUUQxRWk2azllMDdiSmN1VGxFQ0ZFaEVVQ0xKVzA0UURWN2haSTJXRHdwUTB3U291NFdWaDNDQmhFZXFLM2hDNm9nNFF0Qkl6ZXk5Y0xEaUFFSXZOMGdKTUk1dHdVaTg2U1UySDlFdFVpeWdhRDBGU1lwZ2I5VjBYTCtLQjBRYVN1WVJiV0t2c0l4RXhPYUwyQ2dWblRBNGMzV1d6Mk5sVTBsZDNyV2k0TndFNzB1cThvbHVFaTVwYW00NVRjYjNPSTNXdU1xekdRcmlrcXdkTnlxVTRtcGlrWFZPOXpRTjA5SFVHeXFvNXdRTEZOUnpDMjVWR1VUVWd5empxVGNLeHBaTlZ0MVF4djM1VmhTejZiYnFvMFcwelpJZHdtWTNXS3A0YTJ6ZVUxRlZYSTNRQnBsekZJQlpOc21CRmxVd3lYVHJYYmNvUTBXVk84UjlVejNvZXF1bmVaRGE2TTl4aUd4U0dNUmIwOVMySVdVS2lSekhYSHpWVkU5enlDclNLUVRsb0o5RXBqb2p0STB6TjNUMGNUWXZKS3NjSUdiZVhSWmltTXp0MGxqVVdNRXVvMlR6R0FnRkl3eDkyQWJwaHM5Z0FralJ4cnRJc3NzSGkrOVFoYjNnVFFZQUFnWkFzWUZrWUJBYTZ5TzBvU0UzRFpCNEtQeU4xSFFsV1FrdzdJRHpydUNwa2xwUTVIK2hVc05GTGlsS0hYTmdxQ1NpYnZzRnVFc0hmZzNTRlJoWEpBVXNOR29Ha3VUc3N0b3Z1Vi9MUTkyT0VxNk94dFlvckdGZTJDd1dXMHB2d3JCa0dybEdiRGJvaFlhRW9LVGRXTVZMc0ZPS08zUk94dDJRQkEyUXRiYmhIWnBIa3NQWlpDM0JTN0VEb2MyM1JSMTdwZHJqNXFSZDZyb0RER1JDZEtOMEI4dnFscEo3WDNYVUNHbm0yS3I1WDNjb3ZxQ1NkMEYwaWRRUXd3M1dTOE5TdmZXQ0RKVTJIS2xCcGpVc29BNVNrbFNCZmRKejFsaHlxK1d0Tys2bEJXUDFOV2JIZFZzdFU0azdwYVd0djFTMGxWWWNycVFoeUN6VkJ2eWxLaXNEVzdGSjFWYUFUdXFhcnhBMk82c3hSVm5NYnJNUTM1VlpOaWVrSGRWMVRYYytKVXRaaUJ1UUNyTVlvck9ZN1hZcTdlemxVdXIzeU81S2c1eGw1dWl3MGc1S2R0b3JibWVheDBodVNpaUlsRUg2c2dBRXB5R0VHeFFOMEd1UldLa3YwVGNWRnVOazdEQUUwMkVCQnZEMmdZNlFNQU5rekhabzRSR00xYkl6YWRMVXJIeHk3dUdDRGRYUlpjUUptMzRSdE9oRGZGM3U5MFRMVVlKOG14d1NVM3VXK20rbGF6WFBIZm5SeDZLTG5TczhJZHNvOTJlU3E4bzJQVGNUeldod1M4NHNqeDNRcHdVU0VNV2F6VWJvc2d1QUFpMDhkd2JxVVVXdHliRVRKQzdJNzhoQ25aYmhXVDROSTJDWGREcUIyVGtLWlMxTVFBSzdCN0w0dG0rUC81by9ndVMxdTExMXYyWU44M1Ivd0R6Ui9CYWVrN21EcnZ1cysrc2RIK212U1BrckhIRy93Q21QVmQ1TDBLN0hqNWZlWkp2S3o1cUxWSzY1RUdYWW1PaUkzbERIUlRhak9CRzhJZzZJYlVRZEZDQkJ3aXQ0UWh3aXRVSUdhZUVWamtCdlJHWW9RTTBvd0tYYVVadlJRZ3hHVTFHZXFUalRMTjFEby9FOEVpZjluWlh1Q1RhYWxoZDhManVGcmJUb2IzWFIyNnRLU3A3dHJRRHUxY3lyZzdrbDRjZHlQaTMrVVk3SEhtcG16WlF4WE0welduUU9nZUQvRmZGdERJMnNvaTFqZzJSbmhJNjNHeS9acnRKeWZTOXFXUnFuQ0tobXQ4Y2I1QnFJQXZwdjErUy9IZnRHeVpXOWwrZjZqRDVvM1JSU1R5UEhoc0xhdHYzcnpPcGp5ZlhQWlBXT2NKUmsvSkRNREd5VW1sN2dYTkhWZXA3dXAyd3VGN2JwVU5jRERJSEFoL05pbjVIdGplU0ZoejRaOVgwUCtabWY2RVd0c2JJZ2Jzb3QzUkFGelAyTDB2dkVIY0ZMNVh4ZDJXTzBIRDhYYVMwUTlSOHgrU2FJNVZIbU9Jc3crVnpSNCtpYm8zOFJrOVl4YnRNL3dCR2ZzMzJaWWhIbW5zNHdPdFk0T2Q3dnFkYi9pS2FuYnFtY2VsbHdYMkR1MGYvQUNueU5WWWJOTzNWUlV3YTFyalkvRVBQNXI2QXFJeXh0eUxIMVh0c0x1SitiT29ZUER5eVJWUHV3bFJFb0ozUnFvM0JTZmQ5VStLTVRGanQvRU1oN1J2dHNpQ3JZODdBUitxcjNrdDZyMnVNL0VDVSswaXhMS3NhcEYxQlZ5Ump3dkxoNkxFOWE5L3hPTGZtcVlWRDJmelIwaFRFenBmNTQ2dk5KbGxvcWVCazFMdE1zR1RpUVdNOTBwUEkrSjkyM1B5UW52cGgvTk1MU29kNjRkZGtFWWdlN09YZGhYVDkrTFAyK2FnWGl5QzV6WDdubFkxcXlpekIrQ3FKdWRkUXVzRnl3VDZvV2NsSHh1U1dwU0JRN3FUVXNJbURmbEVqWUNncGlHTWxkSUhacEZrL1R0MTJBSEtTamd1NEFxL29xVnROVHVua0lhMk5wZVNUYmdYWEdkU2RtdGRwZWM2ZnM4eURYMTlRNE5sakdwb1BOckVyOHRNV3pETm4zTzJPVnRWcWRIMzJ1RXY2YkRqOFY5RGUybDIzZjVYWTRNc1liTnFnbGlMSDJOeGNBRG5qcVY4ODREUnhSUkNOalMyVmdzNG5ncncvVWM3cHBNL1NYc0owcU1zWHZVNDhwdjhBWXRzTnBQY3YxOHJ0YlhDMWltQ2Jrbm9oTmMrcW1OTTQrRnUvb2lmRHRmalplVVUzS1hKOTRoQ28zNkdWanpYckg3bGc4Ry9DWkxnUGY0a0UyQXEzdlpFV1JIbi9BRm82TFVwNjk5Tm1UREpZb2ppYm81YnZoYnk3WTdkRmVZblh1cFdPaGlkcGpkdVI2cjZuOWx6MlZzT3E0em1iR3ZkNnRqbWllSnNValM1dTRHNDNQbXR2UjR0c2tmTC9BR3k2dkxvbUo2ZS92SlBqbnpQb25zTHJLV3Q3SWNOeElZSU1IcTVIRU9oUHhBV2I2bnpXMFRUWEJUSk5OUzB3aHBXRmxDUGdZZVFmOFdWYk0vYytTOTNwblVUOHA5Uml0VGtlZGViYkY1NUV1WHJNeEpLQ1NWYWs3TWZIazhKM0l6cVVnVU5TYWZWUU1tQ3Bnb1NtT2loQXJYSWdOa0ZxSUNvUW1DcHRjaEJUYW9HR0Jzc2dxQUt5RHVvUUsxeUlEWkJhaUFxRUN0Y2l0TjBFZEVScFFFRHRLbUNoRGhUYW9RTTAyUldsQVlpZzJVSWZDVU13Y2JCV2xORVhBRWJmSlZlSFV4YzdjSzZCN2xvWGtwdEhxRXd3ZDNkcm0velRNVWpaRzlFckUzdjB3eU5zYlNkUVZkY3NOc0hMRzBFbTZycTJWckdPRitpUFZWVFdralVxYXRuRC90SzlqalpXa3lyampJa2NmVkZkYXlrYk44a01tNTJWN0VpbzBUYndrYWg0YVNtaS9TRGRWMDhna2xBVFpMa1UzUmJZZWRVWitTMFB0RHNPOHM0aGI3Q3p1S056dVBDdVJkb09KT2RMSUFWZTA4TEZ2SWtqbDJQVjRqTDJrOVN0VGsvV3lGM0l1bmNmcUhTek9zZk5MUVJqdVRmbXk5aEJIbDVHR3pXMkd5QmlEeG9YZ0NKQ2thNm91MHByRkx1Vk5iSmU2MXpFRGQzM3Eyckp0enVxYXBPdHlyU1ZscUlIUWZKWkRTRVZvQnN2T2JaU2dVZURyQlJVSEd4VXh3cFFhQnU1VVhLVHVWRnlsQmtIRFpDUENLZUVJOEpiT2dpT1ZGVFBWUVFNaEJlUEM4dkhoQ1Fpc0hoWldEd2xoa1BOZTJDeXNIb2dZU01yeDRYbDQ4SUJoQTlGNnk4ZWk4Z09vOGd5ZUpHUENGcHVsc0pDOXJJMFUyZ2pleXhJMndTemlRVUxHSTI3Q2NUczVvMUxhYWV1RWpSdXVaVWs3b25EZGJEaCtKbHRnU2xNZEdSdmtJRHhkWUxuc2RjS3BvY1ZHa2JxMWluYk1xMGtYOGN4K2t4SXNJQkt0WXBUT0FRZm90ZGtpTGR3RVdueEYwQkFJVlZvdnh5R3lzckxHeWVwNm9IcXRlYlZOSUJUY0ZUNUxQY1dYSXpOcGhsQkhLZnA1ckVicldJYWwyMjZ0SWFxd0c2VTRzdHdrYlBCVWl3VEludjFXdjA5VDZwNk9xRzI2VzBXNHlMMkY5cmJvL2ZnZFZUdHFyRGxZZFZtL0tXMEVwRjAycGFCc3N3VlQzTzI4MVR4ems5VTdCVnRaYlpKYUdxUmZVOWM1bHRXNnQ2V1R2bTNGdnVXc1F5OTd3RlowOVU2RVdDVTBNVEx1T2JlMTAxSExaVWxQTVM2NmZqbUI2cExReXk2Z3FnMEpwa3ZlY0ZVakpSNXAraG1Hb1hLVkpCcGxtendvN1gzU3BrQkNMQTRGSmFEVEdudUZ3bUkzRHUvdVNZTjB4RzdheTVRQkg3U2wzUG9zU0RSdXZDb0JDRm9KQVpXYVZEb1VTUjRjVkZyUTVCUWFZaExFSkNka0IyR2FoZXhUem1kMjRsUmRPQUxLVU5zcDVxUFEvcnlpOTBBQWpWRHRUbEY3ZGdwUkxNUnRBS2s1NENGZTNDREk4cVVTd3htVVRJbHRhOFpBRnlpV01kNFIxVUpKdHVVQXpCQmtsOVVhUUxZY3pYSEtWbW0zNVVYUzdjcFdlWGNvNkFzSzk0UVh5Z2RVcytZZ2NwT2FwSTZwcVFOanpwaHZ1azZtcUZqdWszMVpIVkpUVlZ5ZDBTUUxZeEpVWEozU3N0U0FsbjFIcWxKcWoxWGRwemVIbXFRRlhWTmVBRHVoMWxTQTNsVU5aVzg3cDZSWGVWQnF6RWR6NGxVMVZmdHlsYW1vMUU3cE15Nnp5bUpGYWNySXpWTHBIV3V2TWhMK1JkRVpDRHVtV2FXRGhNUldhc0dHaTFyZmdzdGlKS0xERnFLZFpUaFJzZWtRcG9SYmNYS2FoaU4rRk9LR3ljZ2c0UU1ja1FaRVFFeEhHVVVSQkdpalFNYWtDYkFRZUVVTklDTTRXNklMM0plTjdYeUU0WDJCeUJEMGxFSlVFeWM3SFk0VVkwTDJoWlh0MVczME5samI3SHJEeVVDeS9UOEVUU1ZsckxsR0FrQ0Vmb2pSdzZiR3lLMk1GRXQ0VVFUUUdRZ0RoS1NiWDJUTmk1NUNIVlI2R2xHaXZKR3VZZ0xhbDFyMlhuL0FQNXZqLzhBbWorQzVKaWJoWnk2cDdMcHZuQ1Avd0NhUDRMVzBmY3hlby9kWitnbVBHOWEreXJlZ1QyT2Y5Y2NxOEcxbDZOZGp3MlQ3NFVGWlF3YnFXcEhFRmhXbFRhVUlGVEIyWEFRd04xTnA0UWdWSU9VSU1OS0sxeVdZNUZEbENERFhJclNsZzVGWTVRZ3kwb3pYSlVPdVVacnJLRUdXbEZhNUxNY2loMTFDRHNiL1hkT1FUYWVxclluSmhqa1hjR2pZNkdxQXNMMkIyUHlYekg3YnZzNlJaL3dhYk1XQ1UvZVlqVHc2R3NqWllFNmV0dmt2b2FDZlNPVmNVazlOaWRFK2xuWTJTTngzYTVVTThMUnI2RFA0V1JjK2grSk5EVVRZWGlOUmhkZU83cUtaMmh6U2R3ZjhGYkN5TjhvMHRGNCtqbDlSKzJIN0tiNkNwT1pNQlpmVTR6VFJ3RDBJM3VQa3ZrVEJzU21uZDd2VU5kU3lqY3RkeXZNWjhEYlB2SFF1cVFqQkp2L0FKWmZ4eEJ2S0wzVitFdnFQUTNSWW5FY2xabVdMbzlwbHpTMC9NU1h3TERzT2pyVHBrMmFlVVlNRHlMcjFYRzV6ZzJNMjI1Q1RobHRrUFdUM3ZHMU5lUnV2c3M5ckUvWnYya0NocVpUQlIxZFFJd1M2MXhZZFB1WDZ0elZkUGpGT0sybGRyb243TWVPcC93UXZ4YnhTUHhRMU1BN2lxcHZFSGprbi9CWDN4N0ZIdER3Wmd5M1I1V3h1WWUrUXRMekxNZHlkTzNIcTFldDBtcFNTUjhYOXB1alZONUkzNWZzZlNkWkE5MGw3YkpXYUpybWdFa0ZiQmlOQThROTZ3RnpIRFVDUEpVcGg3eHI5N0VMZDNLUzRQbEV0SkNQM0d5dGtCaUhoMythd1NweHRJbWMxd3VMS0xtbTY3MjVLMHNlV1BrWTFXV0M2Nnc2NkdiM1JMVXFBbi83dUNkOTFtNVExN2ROOGNmN3RGYzJFdXNGUTNXZFNIeGJCY2NjZTdNa0xGdm1zZzNYdDF6eEFQRnhMekpHSWdkVktPNEt6RmQ2WlpDTG9ZWUs1WVdMeE8wVndZWXpVUmNKMk9qbWtxWTIwVGU5Qkc5L05ZZ2FEWVdWaEZSMUllMXNMWE1CMzd3ZEVlU1NnZ3BSbXBMWXJaaUdsYlBWeE1iZnZXSDlZM3lYSC9hdDdmNkxzNHk1TGhkQk93NHE0bUo4UklCQWRadC8zcTM3ZU8zL0FBTHNseTNMREZMRFU0cFBHVytFK05ydnc4bCtjZU41aXhidE56QkxqdUtUU3VpbTRpbHRzYms5UG12UGFuVXhWcXo2bjdOZEExUFZOc3MwS1hmaXZVVXBJcWpGY1VucnFoNzVaSlpYU0J6M0Z4R28zMnV0a2hoN29EYXhVYUNsWkMwV0EyVER6NGw0YWN1ZVQ5Vll0Tmd3eFN3TW1MRGZnK2FHNHh2ZGZVVlBnWDVDd1pHVFBEUXdNOVZYYlROVEhtMU1GOTFVRWROZGdhd0FvRTg0Z2g4ZXhDQytabFByUGVBa2RGckZYaXRWaU9KR2toZ2U4dThJdDY3SmtkTTU4bVpxOWJoaW04c3FGOHlWd2xoa2ZTSHZKeHNHK2ErMWZZS3FNeFZlSFlzekVXUEZQM1k3c0Y1SXRkdkErcVE5a3IyWDI0cFFmcEhNVkdKQVpRNFIxQTVhU1QwWDEzaDJVS0hLY0Q2YkNzT1pSTXRwTDRyN2o3eXZaNlBIUitadmFYMnB4NjVQSEZwK1haK29HdUVsTEs2SXRBakhCVlhJOTh0dzBKcXJxY09vUzc5SVl2RkNSeVpEL2N0SnpEMnJaY3dZT0ZGaVZQaUVnK3pHVHorQzlDbFNSOGFsaXlaOHJsSDFObU5OVUFYRExoS1R1bGpObk5zdWVVdmFUaVdZcWpUUzBVclk3L0UyMXYzcmI4UDk1REE2cUxnZkp5dFl4OHNlYkdxMmxwZTRXQWJxR3JiWllEN29CQXkwcVFLQTF5bUhLRUR0S0plNlhhNVREbENCZ1ZOcFFBNVRhNVFneGU2eUNnaHlJQ29RSzBvZ04wRUhaRUJVSUZhZUVWcHNFRnJrUnBVRERnM1JHbEJhVVJybENCMklvS0EwM1JXbFFoOFdzZ0VCdWpkMEpSY2tLdXFjU2N3NkNBQ1Y1MVdURU43YmRGNUdXTm5vMHg5MGdwZ1FEOUVtK3FlNXA4VmtHR2U3TnpjK3FVcXFpOXdFTU1mSVRaQ29MM3U1U2s3SGpxaXRtdjFTOVRQdjk2MU1lUGdyU2tEZEllcW16ZEFrbUJDaDd3RzlWWmhHZ1cwVHFYNlFWVmg1OTRHL1ZGcXFuVmV5SFF4T01vSkY5MDNaYktlVjBoL0ZjVDkzdzA3NzZWd3ZOZUttZWVYVmZnOHJxR2JhMDAwRmpzTExoZWNzVzFhZzIzUFJibWx3MmpJeVpXalVaWCs4VFBKL2FLaTZVc0drSWJBYmsrWnVwc0crNjM2b3pXREpzMG5qWlVWWko4U3RjUmZhOXRsUTEwNDBsQ3hmbVZGYkp1VWhlNTVSNmgydHhTNWdMajFRYmJMTVNUQ2lrQXRVZE93Q3dSWkRSeEEzamRadUZKd3VFTlNnMFJkeW91UkNOa040VW9ORUR3aEhoRVF6d2wwZEJucW9JcENHZVVEUkFhOGVGNXdzb29LSVl1dkU3TEJDd2QwRkJucnJCNkxGbE04SUdna1lXQ1ZsUlBLWFFaaGVYbGgzS0Nna1p1dkFXVVZJY0lHZ2tRa2FsM3hYS1pKdVZnallvS0RRcmV5YXBweTA4cE4vS2kwMlBLVTBkU05pZ3JTMGl4VjNTWThJeTI1SzFDQ1d3VExKVGZsS2xHeDBaVWRJb2NZWlVOc1QrS2FleGttNEYxenFrcm5RdUhpUDFXellmam9hQUM2NlM0RmxaR1hqSHVhVTlUMUpieVZYMDFYSE5ZN2Jvc3BBRjJxbThab3h5RjlEVzdiSnVDc0pJM1dyd1Z4aUlDdElLOGJLdktCYmhrTnBncVRwNVIvZlMzcXRmaHJSYmxITlNMSGRWM0V0eHlGNDNGeU9xbTNGTlI1V3NpcXNUdXB0cmdEeWdjUml5RzVVMklYQXVVOUJNQ1FTVnBsUGlZRnQxWncxK3ExbkpUaVdJek4xcHE5c05oZFhOTFVzcUFGb0ZQVmJnNmlyeWl4VVIyRjBseExDbFp1aldob0JINzFGOVNXS29oeE11QTNSalZraTZTNGpreXpqcnpzRll3MVpaWTNXdHRxamZoT3cxbDdKVGlHcEcwUVZwZU55bm82bXdHNjFXT3N0MVRjVmNiY3BUaUVtYlREVUFqbEhpbnU3bGFyRmlXL3hKMkxFQVI4U0hhY3MyQ29tMjVRQSszVlZZckE2MTNJdnZJSTVRdUlhWTIrYTNWWlpWVzZwQjB3UFZSNzVxRGFIWTlOVjZnbGpKY29FbFFMSUpxUnVoMmhiaHQ3d09xQkxWRGhLUzFIcWxaYWdEcXB0SnVIalZqelFaYW9YNVZjK2YxUzhrKy9LbTBtNHNYMUhxZ3ZxVDVxdWRVWDZvTDU3ZFVXMEhjV0pxejVxRWxTZk5WcHF3T3FGSlZBZFVhaUE1Rms2cDlVck5Wa2RWV3lZZ0czM1NOUmlndWQwVzBEY1cwdGRZY3BDb3J1ZDFUVk9LWDZwUTExK1NpU0JVN0xTU3UzNVNzbFVUMVNFbFdEMVM3cXExOTAxUkpLUlpPcURZN3BLcHE5Ti9FUHFxNnJ4ZHNUVHVGcmxkam10eHM1TlVDcFBMUmIxK0pHeDhTb3A2OHVKM1NMcTR6SGxZYkVaRGU1UmJTcnVZWjFRWEZTRExickRZUTFUakJKODFLR0xrTERxSnRaUFJVaGtGeW9VMFo4bFl4a2dXc3VERkVoRkNHa0prTlhtd25uZEhqaTlGeXh5Um1KdDA3QzNoUWpaWURaTk5ic05rRmpZeFBXVTJEZFNheTZJMW15R3h5UjU3UnA1UzcyaS9LUExHeHBHaHhLQ2FkcjNBdmNXaEZrU2lURmNpSWlCL3dEZGU3cFNxV3dhQUdTRW02azBXQ0hHbE1aT1d3SDNLOTNTSVNGN1JkY3k0dG8zRmszQTlDeUc3cWZLS3h2b2dJa0RZRXl5RUZoNFVtczI0VUcvcStxSU54NEZTelJJVWhpOCtsaHNyQ3FsMUEyVkxWU0VYdnY4MFNLMG84bXZWMHBON3JyM3N0V09jSTkvOWFQNExqbUt6RHVucnJIc29TRjJjVzczL1dqK0MxOUgzTURxUDNXZm9aanUxWTlWMTcyVDJPRzlmSXF1OWw2TmRqdzJUNzRlL3FwM1M0S3lISTRnc1pCVTJteUFEd3NncmdJeUQ2ckljbHc1VEJVSU10TmtWcnR1VW9DaUFxRUcybEZhVXMxM0NLMXloQmtPUm1uMVNvZHNwdGNvUWNZYjlVUU8ydWsyTzlVVU9VSU1SVDdwcHMzcXE4RVhSV3Zzb2puY3NvcHR4ZmpxbjQ2dUFFUjByU3lVOVR4ZFVZZnNtNldRTUlOOTF5VWJGYjNqbGFObGJEVFl2UVRZZmlyZStocUc2SEFIb3ZnMzJzZlk4cTh2NHBWWmp5dEN4bEE0K0dOdG5PQUIzNDlENUw3YWJVa09CQjRWeEZYVTFiU3ZwcXlLT2VON1MwaVZvZGE0dDFWT2VCU1BUYUhxYzhOTlA2bjRxVXVKVDB0VzZtcTJQaGtqY1dFU05MZURicXRraWMxOFljQ0NEMVgybDdTbnNRVTJjb0tuR3NyeHl5VlZpUkhDd3RicU8vUSthK0dNZHc3R096akVuNFRqMEh1cFk3dTJGMTducjFDODdtMHJWbjIzcHZ0QnA5VnRXUnIrckx1TTM2bzhZTWZKM1ZiUVZFYzBUWkM3OVFlSGVhc0d2Wkx2cU8yeXhwNFhGbjBERkxGbWhlRnIrZ0tzcFcxUkJpR2tqNHI5VWhRNHBpV1FjWmh4ekRKQkZJSkc2eU55V2c3OGZNcTNhN3ZQQ3dJZFJRbHJTSkc2Z2RyRlNPV1VESTFYVDNsdmYreCtpdnN4ZTFKUWRybURVOUZWMVBkVHhoa0R1L2RvdVFMSDR2a3UyMWVINlpuUGdjMlNOeHZkaERoYjdsK05kTFVZbmszRUdWdUdUVFFodmkweHlGZ3Z6MFgyWjdQWHR1MGxMQkRoT1lxaUdPd0VlcDVEbmMzNnIwK20xaWsxYlBqblUvWmpQb1l1Y2JmOUQ2MW1pYkhLNGtiMlNybVhPeXNzRHgvTHVkNFJXWU5XZThtUUhZV3QrOUhxTUZrcDdrdE5sNkxIT000OXo1anFzdWJETndlTmxBOWlFVytTdEpLT01rNjNFZkpCZlR4eC9BYi9BRFM1NFUyY3c0dkhWeTRFZEI5VmpRZlZPR0o0K3pzdkJydU5LUFl2VVZMUjVZLzlSaWVncVFpMlRudXppTDZWaU9JeW0wZzBqMFhWR1BxQ3NMWDNuWUJrVndwaURaTmlqWTM0U1NVMURoa3NvMmJkRlVWNWxxTUlmaEs2R0czUk93VXJwbkFOQlB5VG9pcEtHSXV4Ri9jUmpseTV6bjcya3NtOW10TklhWEVZNWFrRDRKUTNuNmxWTW10akZmOEF1YU9uME9xbTFIRmpidjBSMUNLZ3BxT0YwdFRORkNHTkxqM2p3M2dlcStkZTNuMnhxTEltR1ZlRFlMTTg0bzRIdTVZcnVhQ0I2ZlB6WHpmMnQrMXhtYnRKcVphZkNtc1pUdjhBdFFTYWRyNzhCY2hvOEZxNmljMUZaSkxQSTg2ajNyaTYxOStxODVxK29YYVQrcDlUNkY3SDVaeWpuenhmazZjUXVMVnVKOXFPTnpZbGo3L2VIRi9lUm0xckcxdXYzcTJnZzkzWUtKbXdadjZmNDJVNmFJd2dOYXdBZWdUVG90ZS9COHd2STU5Vk9UUDBQMG5wMlBCalVJUVVhL0k5Q3pTT1ZndEpjc3NhSS9DNDdsRHFhc1VyZW0vVXF0TlNsMk5LRWRyK0xnTzRob0c2Rk05djJOaXFpZkhLU251K2FYU3F5b3pmRk1iUXVEandFZUhGTnZsRTFXVEFzYlQxQ2p4Ni93RHVkTjdLY3BZWG1QSEpHNHNXZHlIaSt0NGJ0dDVydjV3ZnNUeUJpUm5ycUx2NTRmRUhSVE1PNDQ0YVY4WFJzelJqcmhGaFVMd1hiYW9ubHAvQUxlY24reWgyZ1p6ZXlXc1pYbHIvQUlqMzBoMlhxdE5ocEswZkV1dStET1VrdGVsL1g4djFQcC9NMzhvSGxUTDFKN3RnTU5XeU9Gb1kxcld1ZHdMRGhxNWRqZnQ2NXp6aUhVMlcyVjhManRkOU5LUi9CYmJrVDJBY0t3dVdLZkdaNnRydG5PRWdjNGZpNWZRMlZ1eW5LZVE2WnNkRFIwdFRJMFd2TFRNSi9pdlI0TVhObnlEVlBRd1cxT0wrUjhxWmF5ajJ1ZHNkUEhQaU9JUk5iSWJ2RXpTdzI1UHhPWFpNbWV6RGd1V25SVFl4VHNubDJjOHh1YnVldm11eHlWb2NDMk9saHBXOU81WUcvdUNTZk01M0xpZm1Wb1NWSG5jbXF3d2JVS01VdUY0WmdzRFlzSGlNQmFMZUkvM0JTRlE1NS8wNDk1L3crYUM1MWtOejczVGNabFpwNXN6K0d4alVPbXc2TDEvVkxCeWsxeUE0TnRjcEJ5VjFJZ2RkUWd5MG9nS1hZNUZEbENCQTVUYVVBRlRhNVFnd0NpZzdKWUd5a0hLRUdtbXlJRHZ5bFd1UldsUWd5RHdpTk4wczA4SXJEWlFNWmFVUWRFdTF5SzF5aEJocFJXOElEQ0VZTzJVSWZHdmFIZ3d3UEVZNDdXdTIvd0M1YXZMV0RRd0Fyckh0TFlZYURNRUFhMGdkMWY4QUFMakVUZFVrWXVPVmxUeEkzWXN0Nk54Y1NENUlNN1RjbzhKRVV4SG92VklHa2xWMUJKaDJWc2o5SVNVOG1vcVZiTnBKU1BmRTNWL0hFcnlZWjBseHlneVNXUVJMdnVvUGwzVElJUXBFdDNrSitDVVF1YmNKT0FYSXVzWW5VdGdBc2VubW5SanlJeXZnMDd0RnhRTWhJQzRMamRVNnBrUHpYVU8wTEUydmJhNjVOTk0xN2w2alJZK0RCelBrajhJQ3lYQU5KUTZoMXJXOGtPU1Q5VWQraXZTUWhpTmZQdVF0ZHJYM3VyQ3VtT3B5cEo1dFJPNnJQdUxYY1dkOFpSUVFHckRXNmxJdDJURWl6RVhMdHlvdWNpbU1YVVRHbDBjUVBVdkFLUmpYbWhTZzBZSXVFTnd0ZEdQQ0c0Y3JsQm9YUXp3aUhrb1o0U3pwRXFKQ2t2RWVhRmtBa2JLQkNLNVFkWUlLSVFJc29scUlva1dTNkNJS1IrRlpXRHdoWWFJcUo1VWxFOHBZWmhZZHlzckR1VUZCSWlzM3VGZzhMQlBSQ0VqeE82d2Vxd1RaWXVnRFFKN0VMU1FtaTI0VVN4VnhsQTQzRUo2RndOa29HSm1HTWhjYU9wREZ3T0VTT29MU0xGQ0xkbGdOUEtHZ2tYTkRpcjQzQzVLdnFiRnhJMEFsYVgzdW5oTlU5U1Ixc2tPSmFqSTNWdFExMjl3bVlxbXhHNjFTR3RJSHhKNkN1dVJ1cWs0bHVFamJJcXl3NVJ2ZmpibFVGUFU2Z1BFRTQyUzdlVlRraTNHUll0cXI5Vkx2N25sVllsSVdUVWxwNm9XaHNaRjlCTDZxd2dyTkpHNjFlR3YwamxNVTljWEhsSmxFdVFrYmpCWDM2cTFwYW05amRhVkRXVyswUHFyQ254WXNJRjBwb3VSWnZkTGloQkE4bGF4NGpjQmFUUzF6ZGpkV2tPSXRJNVNtaDZadERhMEZPd1ZJMjNXc1ExclNCdW5vcWpqeEJKY1EwelkyMVlIVk14Vmd0eXRaRlNmUDhVZUtwdHk0SkxRYVpzVFpyRzkwWmxacDZyWFRpUHF2TnhBay9FdVVGWnRESy8xUlBmejVyVzJWbTN4SW42US9wZmlob0pHd2l2STZyUHYvQUtyV3ppUUgybEg5S1grMGdvWWJLK3V2MVEvZmI5VnI3NjgvdEtJcnllcVZRTmw1SlYrcVhscXdlcXFYMTNxbDVLd25xcFJMTGcxUVBWQWxxUFZWZnZoL2FRMzFkenl1MFN5eE5SYnFneTFRQTVWZEpWZ0Q0aDlVaFBYSHpUS0YyV1V0YmJxa3BjU0p2dXE1OVdUZmRKU1RuelIwQTJXY2xhVGZkSVZGU1NUdWxqVTdjcFdlcE82S2dISWRNNGQxUTNPdDFTRWNoRzVOa09vcis2RzVYRWhjV1B1Skl2ZFZ1SVlnSVdIZmhMZnBxOXdEZFUrTFN2a0J0MVZpQ1FjbndKNGhqRHBaQ0FVR0FPbTNKUXFlZ01yeVNySnRPSUFyS2laZVNUc2kybkRUZlpNUjdiTERXM0lURU1HKzZYUmFVU0lpYzdoT3dVd3VFYUdOb0NiWlRnYm9HT2pFbEJDMndSeEdBc1J4a0poc0pKU3hxUkpyUllJakF2Qm5DUEhFbDJNU1BNQ09IY0tjY0lzaUNLNVFzZEZIb3pkRjArRXFjVUtaN2dhVHNnYkhKRldhVXpna1NhVTdSNWJ4R3JqY1lJSktnQWN0Q3U4dTVBeFhOY2JuNGZCSm9EdEpPZ25kZlFuWlJUNFBrcWxsanpER1hTYWJXQkEzMjlDc2ZWNnQ5a2FXbndKSzZzK1dKTUdxcU9ZdHFxZDBCSDdhdzl0Z3U0ZHVPTlpieDJwbC9ROFRvM1h2ZHg5ZmtGdzhueEVlcWJvZFM1UGtyNnZEd25RSU5KS094bHd2TllDaWpaYVdmS3l2cGNkaTdZL0VqdFpzcHNaYzNSQ0FHcmc1SUhxQUNVY0hPS1BJU0Nza2hyYm5aR0cwS1NNRFdrdVd2WXBVTVpxdFpXV0tWMmhwQUsxT3VsZE00a2xFaEVrVkdKVEVzZjhBTmRqOWt0eE9jRy8vQURSL0JjV3J2NXR5N1Q3SlF2bkJ0dC8xZy9ndGZSOXp6WFVmdXMvUTNIRC9BS2U5VmwxWVk4ZitrSGhWcFhvMTJQQzVQdmhBVmtGUWFWbTZPSUxDQnlrSElOL1ZUQlhBUW9jRk1PUUE1VEJVSUhEbE1PdWdBN2NvbC9WUWd5MTZLMSt5VWE1RllWQ0RRZnNpQis2V0RsTU85VkNEVFg3b29lbEd1UlE1UWdjUDNSR3licGJVc2gxMUFjVHZ1TmlaRTc4c1NPcTNWVEV1dlpSTVBKQk10S2VzRHVTbkJVaTRzVlFnRnA1Q1lpa054dUVYY0NDbzIyaXh6M1Z6WUhQdTEyK2p6V2xkcXZZQmxUdFF3eC9lME5MVFZ6Mm5UTTRIVnE4K3FzM1RRZDQyVndKbWFObko2R3BubkxIdWVQQnUzMFNjbUJNdWFmSm1oTGRGbjV3OXNYc2o1bTdNcXFXcW9wWjhTb21td1pHM3c4L0lMajdjVnE4TmtNTmJRdnA5SnNTLzArOWZzcTdGS2JHS1kwZU1BejA1QkdsdnI5VnhMdFY5ai9LL2FIVHpTWUxTTWduZUR2SzlvM1AzQlllbzB5OGtmUnVrZTFXWFJWREkzNWRrajg4YVNyZ3FHQjhjN1E3bXdUc01uZjhBaExycmZ1MGoyUXMwZG5UNVpvR01saHZjQ0Z1cmI3aXVPKzhZcmdsUVlxdWtxV2tja3hPSDhGNS9MaHA5ajY5b2V2UTZoRk8vblJzN29CSnRJM1UzMVZaWDVhaG1JbHBwRzAwbzN1M202elQ0NmFvdEdzTUZ1SEd5dFkzMDcyWHVDNjNJS1RHVHg4bTVrbmoxcTJaT1I3Sm5iTm16c3lraUVGWFZWVVVaSGhiYXhINEw2WjdQL2I4YlVHR0xFOEtjMndEWE9rY04vd0RtWHl3MHRkY1AzYjVCSlZXQTRkV1g3dUloeDZsWHNmVVpRNFBNNnYyUDBlcXVhZ3IvQUZaK21PWGZhcHlmbUtCZ2VhV25lNGIzY2Z6VzQwZWVzcVlxQTVtTTBrZCtseitTL0pLUExjbEM3WFRscmZ2VDhPSzVsbzdlNjFUR0FjZjR1dEtIVkcrNTQ3VWV3OG90K0RTL3F6OWJ4aVdYNUFMWTNUMitaL0plTmJsOGIvcHVuK3AvSmZsQkgyZ1o2WllERUdXRzNCL3RJNDdRczlPSC9hTWYwUDhBYVJQcUw5VEcvd0FEOVN2NHB4K2Ivc2ZxbEpqbVg0YjN4cW5zUFUva3FqRU8wN0t1RnRjNDRyU3YwOUxsZmwvSm5UUE10d2NRanNmUS93QnBKT216QlYzOTZxR1B2dWJmKzZyeTZtMGFPbjloTXJhOFZwLzFaK2tlTWUxVmxMQTRuQm9wcWh3SFJ4L05jZHpuN2VGUFR1bFpoK0VsKzFnWXovOEFjdmprWldkV08xVEFPS3NxVExWRFNBYW83dUhCQlZaOVZsNm5yZE43QjZTbHZndm16Yzg2KzB4bXpQQmxpaGRWNGN4OTdHN2JEOTYwUnVGNG5pVWhxTVJ4SjllWGVMUS8vd0JsY3hpQ0VhWjNBK1cvUmVmVlJVZmphOW9aejhTenBhaVVqMytqNkowL3BWUExENU5nNkRENFcrRmtBcHlPb1Q5ekZ6d3E0MWsyTkhUUlNEWDAzdWlESkdjc1JJYkhISVFlRDNUdnpWYmJMSXphbHI5TGlqY09FaDM5SVF4anhFSmViR29yK0Z3c3JURHZaOXp4aStuYlRmOEFhakkvaXQ3eTk3R2VjTVEwbVdXQnJUenFzUDhBNmsrT2gzK1I1bldlMldtMGoyNDd2K245emo5ZG1TQ0NkcGJLMTV0d0VrekZLdkhzUWdwNEtWN2c1MXRUVjlkNWE5Z2FJdlpMaUxhZC9CZGFSbjVycitVdlpueUhrOTdIVDRjWFRNKzB4elR2OUZyWXVucVRxanczVS84QXhCeDVJTllISlA4QVJIengyZCt5Rk5uN0NZS2lvcXhTWE55SGo1SHlLN1JsTDJMY3ZZVTVqcW1wcGFndHRjT0IzL0JkcUZUUzRQVGlud1pwZ2lIUjNsK0NSbnhJbS9kTzB1UEpQbXR2RjB1S1YwZktOZDdUOVIxVW5XVGpueVJYNFQyWDVUeW5ac2VEMHM3bS9hRi96VjNKaU5MU3REYU9rYlNEb0cvKzZxZmZabWttVjRQeVFLbXE3NzREWTg3cTZ0S29Ia2Mrb25tZDVuWlpWV0lUVEQ5Wk1XRDFWYStkclNTSlJJZlJMdXF4S0xWQjFnYmJJTHZkaHZDMGcrcXVZNEpHZW9MTndHbGxrazR1MEtCa1ErOWxQMmhaREw3OVZ6SURMUXlqekZvSzZSUU1pRVgrcWdYWDZxWWgrTjU4Zkc0WTFxWWZ3bGdkdVZOcnZWY0JHZGFJMSt5VkR2VkVhNVFnMng2SzE2VVk1RkRyS0VHQTY2bTF5QUhEelUydTlWQ0J3VklPUWRYcXBnK3FoQmhqa1Zya3MxeUswK3FoQmhya1Zqa3UxeUkwMlVER1E1RmE1TE5PM0tLMHFFR21PUm11U3NadWp0S2hEbS90WlpWMDRiTmlyR1hFTVZyMjlQN2w4azBsSzU3MlMzTnVWK2pQYkJsZHVhOGxWMUhwQmZJTEQ2RmZCTmZoZjZKeGV0b25pM2RPMGkvM0xOa2pReGk0TEhYZVR1a3BwZ2I3cGlTbmNDUURzazlBSk82U2x5WGwySzZyc1R5bG12WU9xYnJJTDhGVlVsTzRINGxvNDBWcHZraFhUYVJzZzBzaGU3ZFlxbkJ6YmMyVXNPYUM0cXh1c1ROOEQ3cWtRc043TFhNWHJoSEU4bHl1TVdCallTRnpyTldKbUdKNHVWYXd4NU1yTkkwUE9kZjNzN3ZFVHY1clRnUTRwdkhLdDlSTzdjbmRWOElKWHBNQ3BHUk44aFhjWFNGWElRRHVtNUpBQXFtc201UmdGZFZ5WDFLbnQ0ajgwL1VQdVNsQTNkQ3cwWllMS1I0V1FMQllQQ0FNRXNPVXlGRWhBTXNpb25sVDBxSkNoTEJPRmxBb3BVTEtFc0FidTZLUGRKcDRhMGRFdVNYSFpRbGtOSUNnUzZVMkFDYWpwaSt5ZFpUeFJOQjJRaElxUkE0QzVDQkxFYnF5ckpXZ1diWkpEeElXR21DMDdCUkl1aUVXVVMxS2FPQTdlaThwbFlJUU1ORUhCUkkyUkNGRXRRdEJwZzdLQlJOS2lSZElPMlFJdW9FSWhCQ2paQ3cweUJGMUd5bVdyQ0FNdzVEc2lrWFdBMUxvSk1uR0xJckZCb3NGTm5LQm9KTU0wck54NUtBTmxndVFOQnBoZEM4UENvQ1JadmRBMFdFd2dtTFR5angxdGp5bEN4Uk1aQ1RKSVltWFZQaVA5TDhWWnc0bUFCNGxwK3R6T0NwdHJIdHR1bE5CcG05eFlrMDIzQ2FiVXNlT2kwYUd2Y0xYS3NhZkZDTFhLcnRGbE0yZHdEdHd2TmVmTlVyTVdIbW1vTVFZNDhwTWtXWXpvc3UrY3c4bjZwcURFQzNrcEJrN0g5UW1JMk5jT1FsTkZoWlM0cDhWTng0ajlWYzBlS0d3OFg0clRXTWUwbmxOeFZiNGxVY0M2c3lOOGl4UWdjcG1IRzd1dHFXaERHSE4yVEVHTEM0M1ZhVUdXSTVVem8wR0theDhTWUZkZjdSV2owdUtYQTNUemNTNDNWWjQyUFUwYmdLd1c1VTIxZ3R5dFhiaWdJRzZrTVQ5VVRpUlROcEZkL1NRMzRoL1NXdS9wTDFYdmZMbmxBNGpZeUwwMS84QVNLa3l1OVZSQ3BCM3VzaXBzZVVEaU5VallmZnY2Ulh2ZnY2U294VThickpxZlZkT3RsdzZ2djhBYVVUVytxcFRVK3FoNzE2cUMyeTZkV2VxRzZzdUR1cVkxZnFvR3E5VkFiTFIweEcrb29MNnNEcWtYMWUzS1ZrcUw5VVNnUnpWRmc2ckJKM1FKWmRYVkppUy9WQ2ZLVzN1VWFpVlp6R3liZFV2TE9HcFdYRVdzQjNWUldZdUxteFRGRXJPUloxdUpSdy9hV3ZZbmpuZURTMHBLcXFIMUJObkZGd3pEQlBNM1c0VzlVYzZvaXllSk5JZHdDbW5xM2cySkN1TVNvakMwWEhSYnprL0I2R0dsTG5GbHcwOC9KYXRtV3BqZEpJMXR0aVFMS3A1bnExcHJ3YnZ5TmRhNE51QUY0YXJyTU5uT1QwTk9IVzJWeURQTlBKNFdSb0ZCVGtrSitPbUpIQ05CVGJqWlBSd1c2SmJZOUNzZE1iRGxOUlFtNFRNY1F0d2pzaEFQQ0JqVWlNTVBDYWJEYm9wUnNzT0VZQkMyTlFNUituNElySWw1b3VVeEcxSUdKRUd3a0RxbUkyWFUyZ0lrTE4xQTBTWkY2Sm1uRFJOSHEyYnFGL2xkU1l3V1VYZkVPZ1VmWU5IMlAyQzlvT1Q4cFpVZkRVdXB6TTV6WGZySW1FMzM4MTgvd0RibG11aXh6TUU4MkgxSmJHWkxnUkhTTFc5Q3VlMUZUVVU5bXcxaGEwaTlncXVzWTk1RG55NjNIeldManh1K1N3b3FNbkpkMkJmTFBOSWZFNTQ4eVNVSnJEYzM1VEVZTVVkK1VKcHU1YTJPTklOT3dqR2JLZGxPTUFvbWdLU0xVU0Jpc0Y0QU41S3hMSnNsSko3ZFZ5SWJqWWFaN1FxdkVzUkRtRUEvUlJxYWwyKzZwWjNsOTkwK0lsd0Y2bVV2SnVTVlUxUXZlM1ZXRTJ3VmJVTzNLc0lVNFVVOVpHV3UwNzdydkhzaTA1aHpTOXdGeDNnNSs1Y0xySGEybDQ2Ykw2aTlpSExqOFRxc1lxbnRzSVFITkovOUt2YU9QeEhuT3AxdFo5bDQ0UDlOZk52WjJ5UThreGlFL2Z4QWRicFFjQmVrWFkrZFpWOGJKOVZnZFZIcXZkRklrWEFVSGhTQnNnaDZ6ZEVDR0J1cGFrRU91cGExQ0JRNUZZVXNISXJIS0VHdzdoVERrdHJVMnZVSU1oeUlISlZyOTBUV29RWmE1VDFKWVA0VTlhaEJnRloxSUd0WkQ5MUNERjlsRU8zMlE5YXdIYnFIUmxyL1ZFYkpzazlhbDNxaHdlYkx1bW9xamJraFV3bTlVUnRRUjFVT292V1ZJRzVLZHA4VExuRHVwSGJkQVZyYmFtL1ZNTnFSQjhCdWZSY29OTTNabUxVODhCaHJLU25tYVJhOHNiWGZ2QzBYTm5ZTGs3UHZldWxqaXAzdkIvbVlHajl4Q2JpcW56SHhFdCthYVpXKzdqYWV4WEhGZWcrT1dVZVV6NWI3US9ZQWh0Tk5najZ1YVEzTFFOUUg0RmNNeC8yWHUwYktoZjNPRVNTUXQ0Yzh1NCtpL1NmRDhhbHQ0NXk0WFRUOFVvNmtsbFRUTm5iMTFMSW5wTDhqMWVrOXFOZEJwU2lxL3IvQUhQeVNyTUh6SGdFaGJpVkdJWERrYi9rbGhtRjFML09BTlg2dTR2a3ZLR0w2alBsK2xrTHRydXYrYTA3RXZac3loalRYYUtDa2gxYjhPMlZESm9XL0k5MW92YStsL25OTCtqUHpYWm5HaWZzK1VBL2NtV1ptb1J4S0Q5RjkyWXA3RStYNmx4ZEhOVFEzMzJCL0pVei9ZYndrbnc0bEFCOGovWlZHWFQ1ZWg2S0h0bDArdmp5TDVNK0xCbVhENy96by9CRmJtYkQvd0R6UitDKzFCN0QrRDIvN1FwL29meVdSN0VHRGoveENuK2gvc3FmWmt2ekMveDVvUDVpK1RQaTBabXcvd0Q4MGZncC93Q1ZWRGZhVWZndnRKdnNRWVAvQUx3cC9vZnlSaDdFMkN4a1hyNmY2SDhsUHN1WG9jL3g3b1A1aStUUGloK2NhTm90M28vQk9ZWmk5SGlMMnQ3NDZuYkFEelgya2ZZandPUmx4WDAxL2tmeVVhYjJOTUpvWGdzcjRBVzdnZ0g4bFBzdVhvZGZ0N29VdU1pK1RQbWVnN0JjYXpVV1MwOE16ZzRBdDBsMjRLMnFqOWpITStOTVpHK2xxR3M0dUM1ZlMrRWRqRlZsMlJuYzQxclkzZ05IOXk2Umd6cWpCb0FIVkxwWEFjclR4OUtjZWFQRDYvOEE4UWRacUU0N1kvSi8zUG1uSVBzVWY1SHpRMUZjYWtPWVFTSk5SSDRsZlVHQTRSaHVGMGtNWncrbGQzYld0dTZCdDloOGxDcnpCTFdFaDdqOTZTYmlaYUNIY0xXeDZYdzEyUG5XcjY3cWRYSnVYSDZXYkE3R3FLbmZwWlEwcmZsRTBmd1VhckhZM3Q4RWNiUCtGb0MxZVNzWTUxOWtHZXVGdGxidFI4ak5XUno1a3kvZGk3aHc4ajVGS1RZa1hibDEvbVZUZStBamxEZlUzNnJ0SVhaWnVyNzlVQjArL0tyalA2cUJxUFZkSVBQbXYxUWpMNnBNenFCbVVPRGVyNXFPdjFRTzl1Rmd5V1VERGw1OHlvNnZtZzk0c2ExQ1dIMWZOZTFJR3RlMXFFRDZsN1VnbDZ3SDdxQURiWEk3WGNKSVAyUkd5S0VIV3ZSQTVKdGtSUklvUWFEcm9ySEpScjlrVmowUUkyQ3BoeVdhL2RGRGxDRERUZEZhNUxNY2l0Y29RYkR1RVJwdWx3NUVZNUNOR1d1UjJtNlVhNUhhL2hRZzFHVVpwU3JISXdjb1E2bzlnbDhEdDJub3ZpZnR3eU83Q016VDFiWTlMYWlXOS9QYis1ZmJqbXREd2I3K1M1UDI3WkxHWjhFZFZSeCtPa1lYZUVjODgvVlVwTGd1UWZKOFhUeEdKaDh5cU4xTzdVN2NibGJMTTBzWVd5aTB2VUxYYTcvUkNlNk9zbmZkS1M1TDZmQlgxUmRIeVZYU1RuUzc1SitXR1NvYVhTRFNPZGxXVE5iRyt6VGY1clF4cmdyemZKWHNhWGwxK2I4SnloZ2MyVGNFQkJrYURVdGVOZ0FyS0d2Wks2T01BQThiQkZDRGJLV1NkSXhpMU8zM1Y3aVFOanlWd1hPMkplT1ZyWFhzU05sMW50SnhQOUY0YTZ6eUxtM0srZU1VeFR2bnlFbTl5ZVZzNE1WR1BsblpUeXk2M3VKUWpQcE95ak5NQzRrZmdnT2tHNjJzYTJvbzl6TTBsd2QxVlZUcjNURXNoRjBqUExlNjRRUmw1S2dBcHY4QUV2RnV5RmhvaW9PTzZrNEtCYmU2QUk5WVdVYktYZHIxckJTZ3lCRmxpeW5kWXVQSlNpQVhCUWNFZHpMcUpoK2FsRUFkeVhLUXB3emRGUENHN2RBY3NtS2tSdHNrNXAzK2ZLSTV0MUI0Q0VOTVcwdWVkeXNuOVdwa2VTeGJxVUxDc0dva1dSQ0ZpeUdpV1FVUzFUSVdMSVdna3lCM1VTRk1oWXQ2SUtEVEJMQkNLUmRSdDZKTkJXQ1BDR1V3V3FCYWx0QkpnU3NIaEZJOUZHM29ob05NZzFTQXNwNmR2SllzaG9LekNrRHh1cEFiRlI1NklYRU5NbGZaUUpOMU1EMFdRUFJCdENUUEJtd0t5Tmw1ZVMzRWNtWjd6ZEdKQkNYdXZha21TRFVpWmpEaXZDbXV2TmNqdGVMSlRRYVl0YTJ5azF4VTlpVk1OdjBTSEVzN2pMWkQ1cWNkUzVwNVVPNnVzdXB5MEpEaWQzRHNPSnViMVZwVFl1YkM3bHJnQkNZWXdrYkVwVGlkM00yK0xIbzNBQy80cHVLc2puSEkrcTBVd3ZqM3VVV0hFSHhHMm83ZXE0NEQxa1p2b3A0M2prZlZTWlJhVHlQcXRTZ3hsdyswZnFyR0hNVnlOd2xQR1dvWlRaR2wwUVdIWWc5dlFxc2d4dHJ3TDJUak1TaWVMRzIvb2t2RWkwc3cyM0V6dGR5WWp4Sy8yeDlWV09wSVpOdzgzS1Zrb25NM2E1eCs5STJCcktiTTNFTC9BR2g5VVZtSWYwdnhXbW1TZUh6K3FsK2tYanIrS0I0eHF6RzdpdnVQaUgxV2ZmajVyVFljVWNEdTc4VTdEaXdBM2NnOE1hc3B0YmE3amRTZFdsYXpGaUxTZmlUaks1aEc3a3Z3eHZpbHNhMDNValVtM0txSFZiTDhyQnhDTWZhWFBESjRoYXVxRkF6bTZxdjBsRUQ4UzkrbElySHhMdmhzNzRoYkdlL1ZEZlBZY3FrZml6QWZpU2MrTFh1QTVXZHBWZVF2bjE0WWZpL0ZJMWVNYldCV3Z5NGc1eDUvRlFFeGNOeXB0QTNOamsySXVrTnJwWjBicFRlNFF1N0x5ckNqcENTMEc2bElHbXoxUFFsMXVGWVEwN29MRUVKODRVWVdOZFk4WFN6M2FEWklmSll5WWZBa3BEc0dOMU5Ld3RhK3d0Wkl5U1BxcENUdmNyd2JyVE5QSGJvbFZ5YkVkZC9rN2Z5TXcwZWtBcCtqZ0pjTmtKakNTRmNVREFBTGo4RTFPak54WWZlSnRob2FjQzJ5UDNWbGtOc3B4N3BkbGhSb2pHeXhDZlpCc0VPT0s5dGxZTWhOZ2diR3hpQmJDczkwbVd4RzZtSWR1Q2hzY2tMdGdSV1JXUmhIWlRhMnlXZG9nR2JvalJheW0xaUlHQlFOSWlIMkM4YkhxcG1NV1EzUnFCcEEzUXNhMHVJM1MrZ1RPK1NNOEVpMjZIM0p2MVFLQ1JZb2pJeDN3ZzdMd2d0dWlpSzNtb1N5YUFtTnBJT01TQmRvUVgxWmIxUVpxd2NCS1BjWkRzcThtWFl3ZERFdFpkS3ZxYjNXSFFhZDkwdktRMGNvb2psQUZVVFh1a0h5WHZaTVNPQnVrSnBqQUN5MTc3N3A4VGtvSkMxVklkL0pWMGhEZzdkV2M1WTZFbDJ4SVZLOXpJemJVYkhaV1VVNXRJVGVDNkY3UUw3OUYraFhzcVpXYmxUSjVxakdXR3VnQnVldTQvSmZFL1pUa3VYT1hhQmgrQlU3RExCVkc3bld1UWJqODErbDJIWWN6TG1Vc013eHJBeDFKRm9OaFk4azcvVmJlbXgwendtdjFDa21SbU5wRDVLT3BZSUxhTmxUenFOdDE0RzRCV3UrRWp4MDJwU3NscXNzYWhaWUpVU3VSQWZZbGRaQlVCd3BBb2dTZC9WU3ZzaHJJS2hBZ0tLdytxQmV5a0NvUVl2NnFiWElBUENtQ29RWWE1VHY2b0FLeUNvUVphNVQxZXFXQlJBVkNCdzY2eUhKZTVYcmxRZzFmMVdDK3lYMUh6V05SVUlNNi9WWTFuelM5eXZYS2hCb0gxWGkreVgxcjJ0UUxzTWQ0Zk5IRW9ZQmJsSWExbjNpeWhMTEZ0VEk3N1d5bUpxY0g5YTB1UG9xejNoZTk0VUp1TDJPcWlZQUdnaEZiS1Rad0lzcUFWWHFpTnF6NW83UXVPU2Y0VFlSWE90WWxIWmlNa2R0THJMV3hWbnpSUlhlcTVVV1dWTys3bzJRWWpVUzh2RmxJWWcyTWVJM1BvdGE5L0k2cjN2eFBWRHNqNkhHb1BueEViTCtrQ2VEK0t4K2tIZnRMWGZmZlZlOTk5VkxqNkhmR2grRTJMOUl1SFZSbXJ6TGF6bHIvdnZxbysvSHpVdVBvVHg0ZmdOaUZlNkpueElUY1ZMaVFTYnFpOStKNnJIdm5xRkxqNkU4ZUg0QzVPSk9qdnZ1bHBxeWI0aThhZkpWTHF3b2Jxd2xPOGFQb0d0ZGhueDRhTGR1SXd1MmNEZEJucm11MmJkVlh2S2o3d2djMHpzcFk1cmlLUllCeGNMM1E1WnRLVDk1SzhhaTZIWlpRbkYzd002ejVyT28rYVQ3dythOTNoOHl1REJzdTlWSFY2cGJ2Q3NhajVxRUdiK3F3WFdTK28rYTlxUG1vUWExckJkNnBiVWZOZTFIelVER05henE5VXJjck9vK2FoQm0vcXZYOVV0cVBtdmFqNXFFR2k1ZURrc0hLUUtnQTIxMjNLbTE2VkJSR3VVSU5NY2loK3lVWTVGRGxDRGpYYklySEpScnVFVmprUUkySFdSbXVTYlhJb2NvUWNZNUZhVW94M3FqTmRaUWc0MXlJd3BWcmtaaFFqUmxwUjJuaExOZHNpdEtoQnFNMlIycGFNcGhwVUlkVHFOZnYwWkh3VzNRY1ZwbTFWTStuYzBPWk1OTGsrNFhhUjFRNU5tZ2RlaXJQc1dvSHhYMjQ5bnMyWHN6MVZSQkdSU0hadWtiY2xjaHFLZHNRTGo0ejVMNy93QzBYSmJNMzRKSkM1bXFRQXV1VjhTWjl5ek5sQ3JuYlVSdURRNXhGaDB1bHBjbDJMNE5EcUozVE9MQXpRT0ZXMWxNS2NGeGRjcTBucm9aWVhQamFRNEM2MVd1eEo4cjN0Y2VCZGFPTkZlYjVBelZHa25kSXg0a0tXZnZDN1lHNnJYNHJxYkpjMnNiYnJXc1d4bDFuZ0ZhT0hFck16TkxnejJvNW1iaWRPNk5ydnRYWEhLbHhKZHYxVjdqbFcrV1oxM1hDb0toOTcyVzdqeHBJdzhrdVJPUTJTa3N0aWp5UDVTa291VWI0QWlRbGZkcVFrSkxrMjQzMnVndWp1Z0RGeDFYa1ZzVG51czFwY2ZJQzZMTlJTd0FkN0crTysvakJDQmpGRitnazQzQ2dUWk5PaVVEQ2hPaTJzMzRXUWJwczBnQS92UTN4QnFJZ0F0VWJCRU95aGU2NlFnWDJVVE4wVWl5NngzQlVJQ3VWa3FaYllJYnRrazRtWU5rSndVaVNDdk9GMElhQUVMRnJxWjVXRUxEUkV0c29sdDBiU29rTHB3RVcyV0MzZEYwckZrRERRRXRzc0ZxS1dyQ0NnckJGdGxFdHVqV0htb2xKb0lFVzJVQzBJNUFVQ0VMUWFBbHFqcFJpTHJGa0FTWkV0MlEwZDNDRTVkb0pNd09WbTNrb29nR3c4MERRU01BWFVyYkwxcmxTSEJRVUdnZWxaMHJLOWRBME1USWx1eUc3aEdQQ2dSZEprZzB5RFNqQjFnaGdLWUNVMEhaa09SNFRkS2syUklua0ZWMmhpa1dNYkFlaU4zWWZzZ3dQMkNhWUxHNlZKRmlQSVAzUHF2YU5DYkQ5cktMb3c5SmFMQ2lBY1E4VzJRSDBtbzNUWXBkTzY4UnAyUUhkb2wzSlliWFIyUld0dXBsbW9yTFdGY1p5NkNzZVc4RkU5NmUzZ2xEYnNzRWhEUnp4R013NGhNMDd2S3M2ZkZ0dkZ1cU1rbFlCTFVyYVBVemFHMTBVZzNhTjFsOEViaGZiZGE0eXFEYko2S3NjYmJvSEVkR1k5SlRnY0pkMGJ4d2lOcUNSeXA5K1BOQnRIS1l1MHl0UEpSQlV5dDZsRk1yUDhGRGM5cEtteEhQRVpFMTB2bVVHU29uTjdha2NCcFJob3QxVTJJTlpHVlQ1Nmp6Y29kOVVIcTVYQVl3OUVRUXhrY0tiRU1VMlZZTXBBdVNwTlk4bmU2c2hHM3lVakFEd2tzNmhSa0FJM1JSVDJSREVRZGtkdzJHeUJzWWtSZ2gzM1ZuVGdSbHZHeFNzRGJwZ2l5WFk1UkxtcHhGcjQydEZ1QUZVdnZJOVIwSFpIaGl1Zk5LR2FySjRyU0NVOFcyNmRoaHNWbUdMdzhKcGpMRWJMdERJNmYvQUM3L0FDSlF3M0kyVmxUczBJTk94T0FBTGdXbHllRktpWkd5bkV5NVVXbTVUa0VmQ1haWnF4bW5pQkF1bkJZSWNRc0VUU2dZNktKdHNpQXFBYXBnV1FEVWlXbTFsSU5YdUFDc2Fycmh5aWV5aUwzV0xySmZZS0JJeVNRRU56MUY4OXVxV2txUnZ1b0dnNWtBVUhWQUFTRDZnM05paGQ4WEZBNUdodEhuMWRnVWxKVUdRMldRM1YxVUd4YVhYUzNJZENDc0c2RXVON3FRajBEbEVkSm9CU3MwL0s1M05HRUZSQ2FZMk5sWHpPY1NqR1M1UTN1Um82b2l4WVV2TTBHb2JxSDFUTWt3YnpzcSt0cVJKTzBOMlQ0bGZMd2l1cjNtU2JRMTFnQ3FxcWFaS2tVN0Rxa2NRMFc4eWpWTXJvWHl1dnY2THAzczU5a05WMmw1d2pta2hKZ2p0THFlTEEydWVUOGxhU1BPYWpMVm4wTjdHZlpJN0xlRG5NT0tSM3JJcFE2UHZCNHRKSk8zMEMraWEyZjMyb2xQQWNkZ2lPcG9jTG9LV2lwRzZJb29XTWVQVU5BL05KNnU2ZmRlcHdSbytXNnJPMjJZdmVNVXA0YnVvazJzUEpTZUFaWFNqcW9GV3BtZkNWc3dUWllKdXNMeE5rR01iSXlEWlpCdW9BM1dVUUlUVXMzQ2pkZVVJVHZaU0JVQVZsUWdVT3NwaHlDQ3BBN0tFRGgxMUlPc2hYOVZrRlFnY09VdzY2QUR0eWlYOVZDQkxoZXVGRFV2YTFDRTdoZXVGRFd2YTFDRTdoZXVGRFd2YWxEb1RYNkwzZWVpRHJYdGFoMWh0Zm9wQ3h0d2w5UzlmMVVBWXo0ZlJlT2xMMzlWN1Y2cUFXR3UxWkRnRHlnM0tpU2ZOY29MeE1qOHhvU0M2OTNvU21vK2FsY3JsQXVFcDl4bnZRdmQ4RXR2NXJOeXBZUHVsalhlanpYdTlIbWxOL05lMzgxM3d4dTBiNzBlYWozbzlFdHY1cjIvbXA0WktRejNvOUY3dlI2SmJmelhqZnpVOE1sSVljOFg1V0M0SHFscm56V1FUMUtqd1VEc3dSN1JEM0NsNGR1RXZjK2E5ZjFRS05NNnB3WDNVTWVIMFhqcHNsNytxOXE5Vlppd3QxaGRmb3ZkNTZJT3RlMXBSQTJ2MFdMaEMxcVdwUWhPNFhyaFExcjJ0UTZUdUY2NFVOYTlyVUNKM0M5Y0tHdGUxS0VKM0M5Y0tHcGUxS0VDQjFsTU9RQTY2bUR0eW9BSERycVlmdWczOVY0RlFnMDErNksxNlVhNUZEaW9RZGEvaEVhL2RLTmRZRGRGYTVFQ050ZWlCKzZWRHZWRmE1UWcyeDZPMTZUamNqTmNvUWVhNUdZNUt0ZGRHak4wSTBhYTVHWTVMTk5rWmhVSU54dVREWEpOaFREU29RN0hZM1dTUE1MeXo4U3FORnhrbXRCWWJnRmNnN2RPeWFQT3VDMUU5SkRmRUd0MHNqWTJ3TzNwOGd1d0FlQWhLaHVnbGozYWllcFhZT21MWitYZVk4TW55eGlGWFJWVE83bVk3VHBQbXRDcjNTUlR5eU9iWVdLL1FYdDk3QmFiTmVIVFlqUXNaQlZSTkx5R0Eza1ArQ3Z6dno5RGlXVnErYWxycVNTRnplZGV5MjhHUlVKZkJxZGZVbWR6M2ZEWW5oYWJqbUkxRFNXc2FDUE5IeHJHZThhOFFQM1BRTFZLakU1U0hOZTBrbnpXNWowOWNtRGsxTml0WE5OTzQzRzZyNUNkMDFFNTdaSFBmY0FqcWs1RGR4K2F1VnRSbk9XOWdIN29SYmU2SzdkUUkyS3FUbTdvZkdGaU5SRVkybVE3V1hvNDNQZEdBTGg2T1A4QVNJM05kNGQrcWc2b2JGcGEzY3M2aFRMQjBPakpZTWlrenJtUk1nNFJTNGRGaXRkSzV0K2poY1hIM3JYTzJQSE1QeFdzalpSaU5qV1I2UDFiUUwyQUhSYWZXWm14R3Z3OXRCQlVTUXRZZFcxdjhkRlRkMU5VdExwWlM5dzJ1VlJXSjJldysyY2Z1K3pqdDZCNmh6ZmQ0dEo0Q2lKZGRNMXR0N29UWXpZdExyMlF3OHhQSTZMVXhRNFBIeWw0K1J5UWN1dUVKeHVzOHJ4UTBJOHdSRnl2VzlGUFpZdGRjb05BeUZncVpGbGdpNmxCb0VSZERjRWN0VUhOWFJpQUVMQkNLV3JCYmRMWVNZRXQ5THJGcmRFV3lpV0xnWkN3WGlObDdoZVBDRUFnUW9xWjRVRUFhQnVVRGU2TVFvRnFBTXdvSW1sUkl1aG83WkFpNkdqT0ZrT3dRdEJJaXZLVmd2V0NDZzB5RGxEU2lFS09sY0NQQnV5OWIwVWd2SUdHbVJzc1dJVTE0Y29Bcm9qcjE3TDNjdVBDTEkxb2JjQVhRZEx5ZGlRazcxRUp5V1RpSkxSTTM3R3lFOE5ad2JsSGJHN3JJc2FJL3dCb0ZBODZmQXlFbmorOExoejNmWjJSV2tORy9LODk0WncyNnl5THZUdWJKRWx2TGFocDgzTGs3SVczUkdEZFlJc2JLVFRheXJ0SEJtTTJUVEhlcVRZVXd4MTBtUmFpTXRkc3BhckZDYTZ5eVhwVFJZVDRHUkp3czN1a3hKdnlpdGtRU2RnWTlTcGNCQ0xYVUMvWlJNZ0s4UnNxN1ZzTEl0eDdXcE5laDIzVWczWk9qSGc1amhRY0RZSVVnVW12MlhuRzVTV2pxSXNad25JMmtXUUloZXliRGdBZ1k2SVZ1dzVXUzZ5RjNpeURkQzBQVENhanNwQjFrSW5aZTN1a2pVSDcyeWxIVlhOdGtxU3BSRGRBeHFIMnlCeVlqakR0N3BCbHdtWVhPWExHSWMwZ0tOOTlrSHZyN2RWSnZpU2lJTUhpNlliSDZJRElyMlR0dGhaQXhzVERkaHdwZ1hVUUxvekdvUnFSanVDYmNwNmtiM2ZJVVl3TmtWcmJrV1VEUllSZU8xZ25XeFdBMlFLR080RjFaQmdzRUxIUkFzYmJvaURoRmJHRkx1aDZJQnFSbU1laWVnNENWYXkxa3hFYkpka2doNXFteVN5aEh1RVJ6UXBaZWkwa0VEZzVUYXhRaWhMa3gzSmJ5cHdGdlBNdTdheUlJTnJxYjVJNDI5THBHb3hJTjJDQ2duT3hoN0dzdWxKYXNBRVhTY3RlNTk3RkpQbUpLQm9CUmNtTXpWTnpzVXVaQ2VxRmNrb3JJeVVORm1HRm5vallxVDNBOExCWnBYZzBrOExrcEd0REhaNWdLbVpFUnJMQkJMZDFWY3JaZmhpSVNPdUVySWIzVFQyb0xtY3JxWTdaUXJIRU4wQ1NRUkVxZFJJWWRsWHp6Z3RKSlZ1VTk2cEMzSHcxYkIxMVFIQTIyVkZWNGk1dE8vU0FYamhTeEN2MEVnS1dYc3UxMmNNVGlvcUNCODBzaHNHc0c2YmcwN2NyUFA2N1Z4akZxL1VleUprdXB6M2p0SlJVckhTUGxrRFhBWDJYNlI5a1BaMUIyUzVXZ3c1MERXWWpHQ0g2bUFPc1FCeno1clZPd1RzSG9lelRBSXNScTJSMVdJVk1lb05jRHFoZGY3dkw4VjFXb3EzNGhmdkw5N3lYbmtyMWVtaHRYSjgzMXVwM1NkTVZtY1h2Y1QxTjB1N2xHZnNndTVXZ2VjWkU4S0trZUZGUWhCZVhsNVFoNWVYbDVRaDVUSENnc2cyVUlFQ3loZzNVdFNoQ1lLbGV5SGNMTjdLRUNnM1Vod2hBcVlVSVRCc3BJWWNwWHNGQ0JOUzlxUWRTOXFVSUcxTDJwQjFMMnBRZ2JVdmFrSFV2YWxDQnRTOXFRZFM5cVVJRzFMMnBCMUwycFFnYlV2YWtIVXZhbENCdFM5cVFkUzlxVUlHMUwycEIxTDJwUWdiVXZha0hVdmFsQ0J0UzlxUWRTOXFVSUcxTDJwQjFMMnBRZ2JVdmFrSFV2YWxDQnRTOXFRZFM5cVVJRzFMMnBCMUwycFFnYlV2YWtIVXZhbENCdFM5cVFkUzlxVUlHMUwycEIxTDJwUWdiVXZha0hVdmFsQ0J0UzlxUWRTOXFVSUcxTE90QTFMMnBRZ2ZXdmEwRFV2YWxDQndzNmtJT1dRNnloQTF5aXRQQ1dEdDBWcmxDRExEWkZhNUxNY2loeWhCZ09SV2xMQnlLeHlnQXkwb3JTbGc2NksxeWhCcGh1ak5LVlk1R2E1UWc0dzhKcUlwRmprMUc1UU1kWVFpTk55Z01jaU5LaEJxTXBocVZqS1lZVkNIYVZrQ3l6YjBXUU4xV3N0Tm5od1VGMGJYeUFrSFY1cGhZc1BKQ0NLek5ZNGhyd1NGd1AyaWZab3d2dFB3dXBxS0dtRGNWSUxueVBJc1FOL3pYME5wQjZCWWMwRnB1QWJqeVRZemNYd0ExWitGSGE5MlM0ejJYNDdORk5UeWQySE9OMlJtMWdmTmM4eENYOVRHODdPNUk2cjl2ZTEvc053RHRRb3BhZXNnamltZTNTREhDTDhlZXkvT0h0MjlpVE1tVEt5cHJjS29KcDZFdUxnNTRkYlQrSzlIaDZncEk4OWswalI4b1ZNa2xYU3QwR3h2ZmRKUHUzWThxMnhiRHFuQUtwME5VenU1UnkxVmIyQ29lQzdiNUxVaG5VMFVaWVhBQzVZQUhQUmVxWE9qTFdnYmVhRk00c2pCYWJtNmI0YWx5RDRqaUxZakpwYmVMWkw5MzNFWWUvY3ZIUk16UkVpNUNBUU9DVXlTVER2eHlUYWVTR25GWEc0RFg0YlgzL3dBYnFHbDRCRitkMWx6bWdhZFJ0NUxOaDVvRmpRUGh5N0MwZ2RHN25sUzBoNHVlVVVnRlkwYmJLeEZLS0NUZUhsa0NMSVR0a1VDNVdTQlpWS09pcEpCUkxYQVdTQXZiS1VNUkcxbGdpNm12V0NsQklIWlFjRVV1Q2lTQXUwRllFaFlJdWpFZ3FKYUVEUVlFdFVTM1pGY0FvRUJCUVNZc1F2RWJJNWFGQnpRdVVCWURvVkZHSUM4V2dJR2cwd0t6cDIzUkMwRllJc2dvT3dLaVZNdFdDMElhQ3NnZUVQU2lscWlRRU5CV1FzUE5lMHJPa0tRQXNnb0t3UkNpaUZxd1doRFFWbUdyS3hwVXdSWkEwR21SWGxMWllOa05CcGhJNCsvSWJIRzV4UDdJdXIzQ01xVmVJT3NJSkJmZ2xoVU1yNDJNRGxFam9vMzJOL0cwRmRBaTdiWDBzUVpGUTBtd3RmUTM4bG01bGE0UGE5RldoYlhqYmUvblhvSjBIWWhpV0l4Nm1salIvU3NQNHFuekQyU3lZQXh6M1RRT0kzSWE5cC9pdG1kMjk0bDNVakdVMERRNXBHMWgvQmMweFhNdFhpRWtyM3l2SmU0bXhlU04xbVJUM2VadTlTK3pGai95dHQwL1FxcWhqS2FVc2R2WTIyVUNTZmgyV0NKWlhFbHQxa2g3Und0ZkQyNVBtbVN0L3dEbG1GNVlMWkwvQUFxVFJKK3lxclJjU0NOUm1HeUUwU1crRlN1L3lTV2gwV010S3lUdHlsL0hiaFJKZU9pUzBOc1l2WXJPdExHU1FmWldETEoreWtVS3dZZHJ0aCs4TjBjdjhJVmYzc243SVJXeXl5N0ZvWFZFczVKYlVOYTFrUDJLQU5UQmNoUk1qajBSWFFpTTIrd2RqN2xFMXBhSXZhTndzQjd5L2hKb3NsakU0S1psS1dFYm5OdlpUQWtIMlVMUWFZWnJ5bUdjY3BWbXY5bEdicjhrRkJiZzROK3FrQWdnamJkR1lSNXBMUTVTSnRqdW1JNlMxamNmVkNiWWhUYSt4NUtVeXhGMkdNWVlwc2tBODBOandVWUZ0dUVsc3NJd0dYUjQyMlVHTUFJNVRNWmFGdzZrR1liQlRZKzVReDRreEZEcDNRTWFrRmpadGRHRFFvdE5rZUtMVWhISkh0R2xNVTR2eXN4eGdjb29EZWlHdzBocGszZEFXVFRLZ215UWpqQjZwcGpCNW9HeHFRNUhQZE1za0pTVWJCZmxQMHpCdHVnc2NrR3RzRktNRU82cHVPRnBBUjJVN1J1bDJIVkVJVVp3c3MrQm81UzgxYTBBN3FXZEhvYWhzWTNLQldZd0dYQXVxaWF1RjluSmQxVzA4bTZsaEpOamttSU9mMVN6NVM0OG9EcG12NEt3MkxVYjNLRGNXWVlwTVlFdGxndVU0NllXNm93b3g2b1hJMDhXQUF6Y3B1SnFsSFROQjVUYkkyQUlOeHFRd0M3NDc5Rm1PSUk3aTIzS0JJUjVxcTVGckhqNU1TN2NJQitxeTRnOVZDU1EwN2VMbmxBdVM2b3BJaEk2d1Nza3Ryb3pYNnlYUytGcVF4T3JqRzFPZGFmR0xLMDhpaXdGWk1IZzdyWDhRcUN6WUZPMUQzT08zd2RTclhKMlFzU3ovaTBWSGhjQnFScTB5V3Z0L2paVzlQaGszeVltdTEwRkYwL3FVR1g4cjFXWnF5R0tHbmtsTWp3M3dNSjVLKyt2Wjc5bm5EK3kzQ0lzdzRqQzEySXMweXhtTnd1QWQrTno1SzU3RXV3YkRleXpDb3FpcmdFdUthUzE4VThZY0c3YzcvTXJvY3NwY0hNdlpsL2g2ZlJlczAyQlVqNWYxRFh0eWFUOWZNeFBVdm1NazVQZ2Z1MGRRbEhTdG1nSGRnaVhxVDVJam43VzZlU0hxdHdQb0ZvN2R2WTh0TEk1c0M3OFVGM0tNUUw4b2JnRVIwR2VGRzZtUUxjb2VrS0VJM1hycnhhUE5lMGhRaDY2OWRSMGVxOTNmcW9RbGRZRHJyR2dlYXhZZWFoQ2QvVlR1aEFBTE5oNXFFQ1hXUVZHdzgxNnpmTXFFQ1g5VklPOVVIYnpVN2p6VUlGQnVwQnlFQzN6V2JqelVJR3N2V1VManpYcmp6VUlUc3ZXVUxqelhyanpVSVRzdldVTGp6WHJqelVJVHN2V1VManpYcmp6VUlUc3ZXVUxqelhyanpVSVRzdldVTGp6WHJqelVJVHN2V1VManpYcmp6VUlUc3ZXVUxqelhyanpVSVRzdldVTGp6WHJqelVJVHN2V1VManpYcmp6VUlUc3ZXVUxqelhyanpVSVRzdldVTGp6WHJqelVJVHN2V1VManpYcmp6VUlUc3ZXVUxqelVOYWhBMWw2eURyWHRhaEExbDZ5QmNyMTNlcWhBOWw2eUJkM3F2WGQ2cUVEMlhySUYzZXE5ZDNxb1FQWmVzZ1hkNnIxM2VxaEE1Q2haRHVWSzVVSVNzdldVYmxldVZDRXIrcXlDb2dLUUYxQ0Vyb3JYSUlGbE1jS0VHR215SzEyM0tWSENtb1FiYVVWcFN6ZUFpdEtnQXkxeUswOEpadkNLMDJVSU5NTmtkcFNrYmtkcHVWRG80d3BtSXBOaHZaTVJsUUllYWJJekRaSnNjbVc5RkNEY1pURENsSTlnbUdLRU81cnloZFpIS28yV0NTOHZMeU1oNVlQQldEeXNPM0JDNFFRY1dzbHVCM2hVY1J3ZWh4bW03dXZwMlR4dUZ0RDB4REMyQU9kYmU2eTNUVU9JZHZaQkZ0QXRKbnpiMjBleGRsbnRGZ25sdyttcGNObGRjaHpRNi9uNnI0QzdZdllmekxrK2VhWERoUFhSdHVRSW0vM0Jmc2VRUWRFZTFrS3FwWWF5TXhUdExnZVZvNHRUS0JWbnAxTS9udXpCa25ITXZreFYyR1R3dWJ0ZDRINXJXVExMVDdQZ0x1bTYvZDdQL3N3NUx6M3FkWFljWlpIYjMxTjUraSthdTByK1Rqb3EyT1YyWDZhR204dThleis1YkdQWHBKSnNvejBLZkorV3pqY1g0dnZaRERtajdOMTlkWnIvay9zM1lJSlhtb3BOSUp0WnpmN1M0cm1iMmY4ZXl4SzlzODBKMG43Skg1cldoT3lqcDhhaEZzNVRKTHZidVZLdytTMkdweXpVVVpMWlhOSkhrcTkyRG5lMWxhVWluN3l2RjIvbVZwYUw4cndJQXRkV0J3ZDl1aWoraUhnZEV1VTJpNXFJYm8ySUJnSjVDeVdOdHlFMk1MZjZMSnd0d0hLN1JYUlhPamI1aGU3dHZtRTZjTWVmSlkvUmJ2TlNoaUUrN2I1aFk3dHRqdUU3K2kzZWE5K2kzZWFsQklyaXh2bUZBeGdIa0t5L1JUL0FQQlVUaFR2UlFoWEdNVzVDd1FMY3F4L1JMMUg5RHY5RUxDUld1QTgwTWdYNVZtY0hmNktCd2Qvb2dDSzRnVzVVSEFlYXN2ME8vMFVEZzcvQUVRZ2xZUUw4ckpBc04xWWZvZC9vdmZvZC9vaFlTSzZ3ODFGd0htckU0Ty8wK3F4K2gzK2lBTXJDMERxc0ZvUFVLek9ET3QwVWYwTy93QkVOSGJLd2dlYWdRUE5XaHdkL29oT3dkOStpQmpFVjFtK2F5QUxjcDM5RHZ2MFUyNE8rL1JEUVZsY1dnZFZndEI2aFdad1p3OGxIOUR2OUVKMHJDQjVxTzNtck00Ty93QkZIOUN2OUVERFJYYmVZWGhielZqK2hYK2k4Y0dmNklReExWckZsRW51eHhkT25DcEc4RUx3d2FxZnc0SlBocVE5d1dMbUlnYWg1MkVaK2F5STc3M1Q1d3FxaUJHcHFoSGc5UzQ3dUNXOU91NHlFWGsrOEozSTJVUzF6K3FzSDRIVUEvRUZPUENaeDFDUy9nTGFucDhIRW9zcmRMZ09WN3hlYXNqZzgvN1FVZjBSUCswRldZWGNTQmQ1cklhZjJrNk1JcUxmRUZBWUxWZnROU1dkUXZwTnZpVUMwajdTZC9RdFZiNG1xRHNGcXYybXBUQ3NTMUU5VkV1UFFwMDRMVS90QlkvUXRSKzBGRkVONXFRa0hIelJHemtjSTR3V3A4Mm9rZUN6ODNDR1NvcStJNXlvWERuU2N1c3MyMC9hdW1JTUZxWjV3d09iY213WFVjcGRodGJqdEU2Y3VqTm1PZHVSMEYvTlVaU3BucDlGb2xramJPVHVrdHRkVGlqTHR3NVhPTjVMcXFDcGxqRG0rQnhiejVGVjhXRDFVWStJSnhtdmhrTlQyL2FSR3lPUFZUWmhWU1Q4UVJSaFUvN1FRTTREWTkzbWloN2gxVTJZVlVIN1FSaGhVOS9pQ0NnYkJ0ZURiZEdZNGVhSTNDWGp5Um1ZUS8wU21oMFhaQmpoNW9vWU50MFZ1RXZ1T0V3M0NuMlZlUmNnQVl3ZWFPMWc4MGVQQzNqeVJoaFRsVlpiaUJhR25xalJSZzIzUjJZTzgrU1paaFRtam9qQ0l4UU44d25vS1VQSVFXMFQybm9yU2twSE1zVUxISkdHNFlMWHVGTnRLR1gzQ2VFTHJBWFdEU09kZEFPU0svU0FlVmpSWThwdGxBNXprUTRhNzBTckNRS25idHltV05IbXN4MExoNUk3S0Yvb2dZNkpGb0htbmFjaXczUzRvM1hUY0ZHL3pDR3h5SElxaG90dWptcWFHOHF1OTBlT3F3Nm5meGRLc2F3ODFZQ1Q0a2xKTHFCM1huVWJ5ZVFzL285NTZoU3lSWElxNGFqeXN0Z3Z0ZFBSWVU0bm9yQ0hCU2Q5bExMK1BHbVZjVkFTUnZzbm9xSU5IS3RHWWFRT2luK2ozZWlwT1p1dzA2SzN1UTBMeGFmTldCdzV4UFJSTkE1QTVtakRFa2l2c1FlVk1PZGJsTi9vNTNvcEREbldRYjJNMjBLV0I2b2IyK3FiTkc0S0JvM2VpS2pzRUpHTzNWU1lXU01KZllFZENtZmMzQkt6VWJwRHFiOEk1VElMazVsbHRSVTFsUVh5YUxhRzN0ZEp5d2R6YnV2MTduRzFndGdwc0xialU3S1dJV2tKMDNQQytqZXhmMlZING15R3R4QnNVc1E4UkFjTDdDNjBNY0xQTWFuVU9OdXppL1pQMkE0dDJqNGxERzVrbEpTU09zNllqd2pmNzE5dFpJN0w4QjdKc0xpZ2hwb0txdGV6UzZkdDdnMzU2ZVMyakQ4S3BjcTBqYUxMekRTd05hQkkxM1Z3K25xb1NVZ2tKZk9OVXAzdVBOZW14NmRSbytaYW5xRTUyckY1WlpaWEdXU1FrSHFVRnpoWk1lNFR2UGpJTUhSdnFvdXBGcFErSGc4M2xtOGo1RW5FS0dybE12cFZEM1kyVExza0lDeFlEMVVITUhtbURUUFVEU3VVSUx1WVBOQklGK1UyYVY1V0RoNy9BRVVJS0VEelVkSTh3bkRoN3ZSUjl3Y0ZDQzRhTGNyT2tlWVJ2Y1hMM3VMbENBZEk4MUh1eDVoTWU0dVdQZEgraWhBSVlQTlNFZnFFVVVyZ3BlNlA5RkNBdTdIbUY3dXg1aEhGSSszUmU5MGY2S0VBZDJQTUtPamZrSm4zUjZ4N2s1UWdFTXYxQ2tHK3FNS0oxbG4zTnloQUdrZVlYdEk4d2orNU9YdmNuS0VBYVI1aGUwanpDUDdrNWU5eWNvUUJwSG1GN1NQTUkvdVRsNzNKeWhBR2tlWVh0STh3ais1T1h2Y25LRUFhUjVoZTBqekNQN2s1ZTl5Y29RQnBIbUY3U1BNSS91VGw3M0p5aEFHa2VZWHRJOHdqKzVPWHZjbktFQWFSNWhlMGp6Q1A3azVlOXljb1FCcEhtRjdTUE1JL3VUbDczSnloQUdrZVlYdEk4d2orNU9YdmNuS0VBYVI1aGUwanpDUDdrNWU5eWNvUUJwSG1GN1NQTUkvdVRsNzNKeWhBR2tlWVh0STh3ais1T1h2Y25LRUFXSG1vNmdtZmMzS1B1aWhBR29MMm9JL3VpOTdvb1FIcUM5cUhvcGU3RmU5MktoQ09vZWk5cUhvcGU3RmU5MktoQ09vZWk5cUhvcGU3RmU5MktoQ09vZWk5cUhvcGU3RmU5MktoQ09vZWk5cUhvcGU3Rlk3ZytTaERHb2VpOXFDejNCOHZ4WHU0UGtvUWpxV1d1VWhFc2lKUWhIVWpqZ0tIZEtZVUlTSENJaGpoRVVJRmFiSXJUWkJhVVJpZ0FkcFJXdVFRYklnNktFR0dGSGFVc3hIYW9kR1dPVEVia293bzhaVUNIR09UVFhqWkl0UldQVUlXTVR3bUd2RmxYUlBURFhteWhELy8yUT09IiBhbHQ9IkFyZW5hIG9mIFZhbG9yIiBzdHlsZT0id2lkdGg6NjRweDtoZWlnaHQ6NjRweDtvYmplY3QtZml0OmNvdmVyO2JvcmRlci1yYWRpdXM6MTBweDtkaXNwbGF5OmJsb2NrIj4KPHNwYW4gc3R5bGU9ImZvbnQtd2VpZ2h0OjgwMDtsZXR0ZXItc3BhY2luZzouM3B4Ij5BUkVOQSBPRiBWQUxPUjxicj48L3NwYW4+CjwvbGFiZWw+CjwvZGl2Pgo8aW5wdXQgdHlwZT0iZmlsZSIgbmFtZT0iYnVuZGxlIiByZXF1aXJlZD4KPGJ1dHRvbiB0eXBlPSJzdWJtaXQiPkFOQUxZWkUgQlVORExFPC9idXR0b24+CjwvZm9ybT4KPC9kaXY+Cgp7JSBpZiBjdXJyZW50ICV9CjxkaXYgY2xhc3M9InBhbmVsIiBpZD0iaW5mby1wYW5lbCI+CjxoMj5CVU5ETEUgSU5GT1JNQVRJT048L2gyPgo8cD57e2N1cnJlbnQubmFtZX19PC9wPgo8ZGl2IGNsYXNzPSJzdGF0cyI+CiA8ZGl2IGNsYXNzPSJzdGF0Ij48Yj57e3RvdGFsfX08L2I+PHNtYWxsPlRvdGFsIE9iamVjdHM8L3NtYWxsPjwvZGl2PgogPGRpdiBjbGFzcz0ic3RhdCI+PGI+e3t0eXBlc3xsZW5ndGh9fTwvYj48c21hbGw+QXNzZXQgVHlwZXM8L3NtYWxsPjwvZGl2Pgo8L2Rpdj4KPGJyPgo8YSBjbGFzcz0iYnRuIiBocmVmPSIvZG93bmxvYWQve3tjdXJyZW50LmlkfX0iPkRPV05MT0FEIE9SSUdJTkFMPC9hPgo8YSBjbGFzcz0iYnRuIiBocmVmPSIvZG93bmxvYWQtbW9kaWZpZWQve3tjdXJyZW50LmlkfX0iPkRPV05MT0FEIE1PRElGSUVEPC9hPgo8L2Rpdj4KCjxkaXYgY2xhc3M9InBhbmVsIiBpZD0iZXhwbG9yZXItcGFuZWwiPgo8aDI+QVNTRVQgRVhQTE9SRVI8L2gyPgoKPGlucHV0IHR5cGU9InNlYXJjaCIgaWQ9InNlYXJjaCIgcGxhY2Vob2xkZXI9IkNhcmkgbmFtYSwgdHlwZSwgUGF0aCBJRCwgQ2xhc3MgSUQuLi4iPgo8ZGl2IGNsYXNzPSJhc3NldC1jb250cm9scyI+CiA8ZGl2IGNsYXNzPSJkcm9wZG93bi13cmFwIj4KICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9Im5hdGl2ZS1tZW51LWJ1dHRvbiIgaWQ9ImZpbHRlckJ1dHRvbiI+CiAgIEZpbHRlciA8c3BhbiBjbGFzcz0ibWVudS1pY29uIj7imLA8L3NwYW4+CiAgPC9idXR0b24+CiAgPGRpdiBjbGFzcz0ibmF0aXZlLWRyb3Bkb3duIiBpZD0iZmlsdGVyTWVudSI+CiAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZHJvcGRvd24tb3B0aW9uIGFjdGl2ZSIgZGF0YS1maWx0ZXI9Il9fYWxsX18iPkFsbCB0eXBlczwvYnV0dG9uPgogICB7JSBmb3IgdHlwZV9uYW1lIGluIHR5cGVzLmtleXMoKXxzb3J0ICV9CiAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZHJvcGRvd24tb3B0aW9uIiBkYXRhLWZpbHRlcj0ie3t0eXBlX25hbWV9fSI+e3t0eXBlX25hbWV9fTwvYnV0dG9uPgogICB7JSBlbmRmb3IgJX0KICA8L2Rpdj4KIDwvZGl2PgogPGRpdiBjbGFzcz0iZHJvcGRvd24td3JhcCI+CiAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJuYXRpdmUtbWVudS1idXR0b24iIGlkPSJzb3J0QnV0dG9uIj4KICAgTWVueW9ydGlyIDxzcGFuIGNsYXNzPSJtZW51LWljb24iPuKYtzwvc3Bhbj4KICA8L2J1dHRvbj4KICA8ZGl2IGNsYXNzPSJuYXRpdmUtZHJvcGRvd24iIGlkPSJzb3J0TWVudSI+CiAgIDxidXR0b24gdHlwZT0iYnV0dG9uIiBjbGFzcz0iZHJvcGRvd24tb3B0aW9uIGFjdGl2ZSIgZGF0YS1zb3J0PSJpbmRleCI+SW5kZXg8L2J1dHRvbj4KICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJkcm9wZG93bi1vcHRpb24iIGRhdGEtc29ydD0ibmFtZSI+TmFtZTwvYnV0dG9uPgogICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImRyb3Bkb3duLW9wdGlvbiIgZGF0YS1zb3J0PSJ0eXBlIj5KZW5pczwvYnV0dG9uPgogICA8YnV0dG9uIHR5cGU9ImJ1dHRvbiIgY2xhc3M9ImRyb3Bkb3duLW9wdGlvbiIgZGF0YS1zb3J0PSJzaXplIj5Va3VyYW48L2J1dHRvbj4KICAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGNsYXNzPSJkcm9wZG93bi1vcHRpb24iIGRhdGEtc29ydD0ibW9kaWZpZWQiPkRpbW9kaWZpa2FzaTwvYnV0dG9uPgogIDwvZGl2PgogPC9kaXY+CiA8c3BhbiBjbGFzcz0iYXNzZXQtY291bnQiIGlkPSJhc3NldENvdW50Ij57e2Fzc2V0c3xsZW5ndGh9fSBhc3NldHM8L3NwYW4+CjwvZGl2PgoKPGRpdiBjbGFzcz0ic2Nyb2xsIj4KPHRhYmxlPgo8dGhlYWQ+PHRyPgo8dGg+IzwvdGg+PHRoPk5BTUU8L3RoPjx0aD5UWVBFPC90aD48dGg+UEFUSCBJRDwvdGg+PHRoPkNMQVNTIElEPC90aD48dGg+U0laRTwvdGg+PHRoPkFDVElPTjwvdGg+CjwvdHI+PC90aGVhZD4KPHRib2R5IGlkPSJhc3NldHMiPgp7JSBmb3IgYSBpbiBhc3NldHMgJX0KPHRyIGRhdGEtaW5kZXg9Int7YS5pbmRleH19IiBkYXRhLW5hbWU9Int7YS5uYW1lfGxvd2VyfX0iCiBkYXRhLXR5cGU9Int7YS50eXBlfX0iIGRhdGEtc2l6ZT0ie3thLnNpemV9fSIgZGF0YS1tb2RpZmllZD0ie3thLm1vZGlmaWVkfX0iPgo8dGQgY2xhc3M9ImFzc2V0LWluZGV4Ij57e2EuaW5kZXh9fTwvdGQ+Cjx0ZD57e2EubmFtZX19PC90ZD4KPHRkIGNsYXNzPSJ0YWciPnt7YS50eXBlfX08L3RkPgo8dGQ+e3thLnBhdGh9fTwvdGQ+Cjx0ZD57e2EuY2xhc3NpZH19PC90ZD4KPHRkPnt7YS5zaXplfX0gQjwvdGQ+Cjx0ZCBjbGFzcz0iYWN0aW9uLWNlbGwiPgo8ZGl2IGNsYXNzPSJhY3Rpb24tZ3JvdXAiPgoKeyUgaWYgYS50eXBlID09ICJNZXNoIiAlfQogPGEgaHJlZj0iL21lc2gtZXhwb3J0L3t7Y3VycmVudC5pZH19L3t7YS5wYXRofX0iPkVYUE9SVCBPQko8L2E+CiA8Zm9ybSBtZXRob2Q9InBvc3QiCiAgICAgICBhY3Rpb249Ii9tZXNoLWRlbGV0ZS97e2N1cnJlbnQuaWR9fS97e2EucGF0aH19IgogICAgICAgb25zdWJtaXQ9InJldHVybiBjb25maXJtKCdIYXB1cyBNZXNoIGluaT8nKSI+CiAgPGJ1dHRvbiB0eXBlPSJzdWJtaXQiIGNsYXNzPSJhY3Rpb24tZGFuZ2VyIj5ERUxFVEU8L2J1dHRvbj4KIDwvZm9ybT4KIDxmb3JtIG1ldGhvZD0icG9zdCIKICAgICAgIGFjdGlvbj0iL21lc2gtaW1wb3J0L3t7Y3VycmVudC5pZH19L3t7YS5wYXRofX0iCiAgICAgICBlbmN0eXBlPSJtdWx0aXBhcnQvZm9ybS1kYXRhIgogICAgICAgY2xhc3M9Im1lc2gtaW1wb3J0LWZvcm0iPgogIDxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Il9jc3JmX3Rva2VuIiB2YWx1ZT0ie3tjc3JmX3Rva2VuKCl9fSI+CiAgPGlucHV0IHR5cGU9ImZpbGUiIG5hbWU9Im9ial9maWxlIiBhY2NlcHQ9Ii5vYmoiIHJlcXVpcmVkPgogIDxidXR0b24gdHlwZT0ic3VibWl0Ij5JTVBPUlQgT0JKPC9idXR0b24+CiA8L2Zvcm0+Cgp7JSBlbGlmIGEudHlwZSA9PSAiVGV4dHVyZTJEIiAlfQogPGEgaHJlZj0iL3RleHR1cmUtZXhwb3J0L3t7Y3VycmVudC5pZH19L3t7YS5wYXRofX0iPkVYUE9SVCBQTkc8L2E+CiA8YSBocmVmPSIvdGV4dHVyZS1pbXBvcnQve3tjdXJyZW50LmlkfX0ve3thLnBhdGh9fSI+SU1QT1JUPC9hPgogPGEgaHJlZj0iL3RleHR1cmUtcHJldmlldy97e2N1cnJlbnQuaWR9fS97e2EucGF0aH19IiB0YXJnZXQ9Il9ibGFuayI+UFJFVklFVzwvYT4KCnslIGVsc2UgJX0KIHslIGlmIGN1cnJlbnQuZ2FtZV9tb2RlID09ICJtbGJiIiAlfQogIDxhIGhyZWY9Ii9hc3NldC1qc29uLWV4cG9ydC97e2N1cnJlbnQuaWR9fS97e2EucGF0aH19Ij5FWFBPUlQgSlNPTjwvYT4KICA8YSBocmVmPSIvYXNzZXQtanNvbi1pbXBvcnQve3tjdXJyZW50LmlkfX0ve3thLnBhdGh9fSI+SU1QT1JUIEpTT048L2E+CiAgPGEgaHJlZj0iL2Fzc2V0LWpzb24tcHJldmlldy97e2N1cnJlbnQuaWR9fS97e2EucGF0aH19IiB0YXJnZXQ9Il9ibGFuayI+UFJFVklFVyBKU09OPC9hPgogeyUgZWxzZSAlfQogIDxhIGhyZWY9Ii9hc3NldC1qc29uLWV4cG9ydC97e2N1cnJlbnQuaWR9fS97e2EucGF0aH19Ij5FWFBPUlQgVFhUPC9hPgogIDxhIGhyZWY9Ii9hc3NldC1qc29uLWltcG9ydC97e2N1cnJlbnQuaWR9fS97e2EucGF0aH19Ij5JTVBPUlQgVFhUPC9hPgogIDxhIGhyZWY9Ii9hc3NldC1qc29uLXByZXZpZXcve3tjdXJyZW50LmlkfX0ve3thLnBhdGh9fSIgdGFyZ2V0PSJfYmxhbmsiPlBSRVZJRVcgVFhUPC9hPgogeyUgZW5kaWYgJX0KeyUgZW5kaWYgJX0KCjwvZGl2Pgo8L3RkPgo8L3RyPgp7JSBlbmRmb3IgJX0KPC90Ym9keT4KPC90YWJsZT4KPC9kaXY+CjwvZGl2PgoKCjxkaXYgY2xhc3M9InBhbmVsIiBpZD0ib2JqLXByZXZpZXctcGFuZWwiIHN0eWxlPSJncmlkLWNvbHVtbjoxLy0xIj4KIDxoMj4zRCBPQkogUFJFVklFVzwvaDI+CiA8cCBjbGFzcz0ibXV0ZWQiPlBpbGloIGZpbGUgT0JKIGhhc2lsIEVYUE9SVCBPQkogdW50dWsgbWVsaWhhdCBtb2RlbCAzRC48L3A+CiA8aW5wdXQgdHlwZT0iZmlsZSIgaWQ9Im9iai1maWxlLWlucHV0IiBhY2NlcHQ9Ii5vYmoiPgogPGRpdiBzdHlsZT0iZGlzcGxheTpmbGV4O2dhcDo4cHg7ZmxleC13cmFwOndyYXA7bWFyZ2luOjhweCAwIDE0cHgiPgogIDxidXR0b24gdHlwZT0iYnV0dG9uIiBpZD0ib2JqLXJlc2V0Ij5SRVNFVCBWSUVXPC9idXR0b24+CiAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJvYmotd2lyZSI+V0lSRUZSQU1FPC9idXR0b24+CiAgPGJ1dHRvbiB0eXBlPSJidXR0b24iIGlkPSJvYmotcm90YXRlIj5BVVRPIFJPVEFURTwvYnV0dG9uPgogPC9kaXY+CiA8ZGl2IGlkPSJvYmotcHJldmlldy1zdGF0dXMiIHN0eWxlPSJwYWRkaW5nOjEwcHg7YmFja2dyb3VuZDojMDkwYTEwO2JvcmRlcjoxcHggc29saWQgIzM1Mzk0ODtib3JkZXItcmFkaXVzOjdweDtjb2xvcjojYWFhIj4KICBNZW51bmdndSBmaWxlIE9CSi4uLgogPC9kaXY+CiA8ZGl2IHN0eWxlPSJ3aWR0aDoxMDAlO2hlaWdodDo0MjBweDtiYWNrZ3JvdW5kOiMwODA5MGQ7Ym9yZGVyOjFweCBzb2xpZCAjMzUzOTQ4O2JvcmRlci1yYWRpdXM6OHB4O292ZXJmbG93OmhpZGRlbjttYXJnaW4tdG9wOjEwcHgiPgogIDxjYW52YXMgaWQ9Im9iai1wcmV2aWV3LWNhbnZhcyIgc3R5bGU9IndpZHRoOjEwMCU7aGVpZ2h0OjEwMCU7ZGlzcGxheTpibG9jayI+PC9jYW52YXM+CiA8L2Rpdj4KIDxkaXYgaWQ9Im9iai1pbmZvIiBjbGFzcz0ibXV0ZWQiIHN0eWxlPSJtYXJnaW4tdG9wOjEwcHgiPjwvZGl2Pgo8L2Rpdj4KCjxkaXYgY2xhc3M9InBhbmVsIiBpZD0ic3VtbWFyeS1wYW5lbCI+CjxoMj5BU1NFVCBUWVBFIFNVTU1BUlk8L2gyPgp7JSBmb3IgbmFtZSxjb3VudCBpbiB0eXBlcy5pdGVtcygpICV9CjxwPnt7bmFtZX19IDxzcGFuIGNsYXNzPSJ0YWciPih7e2NvdW50fX0pPC9zcGFuPjwvcD4KeyUgZW5kZm9yICV9CjwvZGl2Pgp7JSBlbmRpZiAlfQoKCjxkaXYgY2xhc3M9InBhbmVsIiBpZD0idG9vbHMtcGFuZWwiPgo8aDI+VE9PTFM8L2gyPgo8cD5Vbml0eSBBc3NldEJ1bmRsZSBQYXJzZXI6IDxzcGFuIGNsYXNzPSJ0YWciPlVuaXR5UHk8L3NwYW4+PC9wPgo8cD5Bc3NldCBpbnNwZWN0aW9uOiA8c3BhbiBjbGFzcz0idGFnIj5SZWFkLW9ubHkgVjE8L3NwYW4+PC9wPgo8cCBjbGFzcz0ibXV0ZWQiPk9yaWdpbmFsIGZpbGUgdGlkYWsgZGl0aW1wYSBzZWxhbWEgcHJvc2VzIGFuYWxpc2lzLjwvcD4KPC9kaXY+CjwvbWFpbj4KPHNjcmlwdD4KKCgpID0+IHsKIGNvbnN0IGJvZHkgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiYXNzZXRzIik7CiBpZiAoIWJvZHkpIHJldHVybjsKCiBjb25zdCBzZWFyY2ggPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2VhcmNoIik7CiBjb25zdCBmbSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJmaWx0ZXJNZW51Iik7CiBjb25zdCBzbSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzb3J0TWVudSIpOwogY29uc3QgZmIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgiZmlsdGVyQnV0dG9uIik7CiBjb25zdCBzYiA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzb3J0QnV0dG9uIik7CiBjb25zdCBjb3VudCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJhc3NldENvdW50Iik7CiBsZXQgc2VsZWN0ZWRUeXBlID0gIl9fYWxsX18iOwogbGV0IHNlbGVjdGVkU29ydCA9ICJpbmRleCI7CgogZnVuY3Rpb24gY2xvc2VNZW51cygpIHsKICBmbS5jbGFzc0xpc3QucmVtb3ZlKCJvcGVuIik7CiAgc20uY2xhc3NMaXN0LnJlbW92ZSgib3BlbiIpOwogfQogZmIuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCBlID0+IHsKICBlLnN0b3BQcm9wYWdhdGlvbigpOwogIGNvbnN0IG9wZW4gPSAhZm0uY2xhc3NMaXN0LmNvbnRhaW5zKCJvcGVuIik7CiAgY2xvc2VNZW51cygpOwogIGlmIChvcGVuKSBmbS5jbGFzc0xpc3QuYWRkKCJvcGVuIik7CiB9KTsKIHNiLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgZSA9PiB7CiAgZS5zdG9wUHJvcGFnYXRpb24oKTsKICBjb25zdCBvcGVuID0gIXNtLmNsYXNzTGlzdC5jb250YWlucygib3BlbiIpOwogIGNsb3NlTWVudXMoKTsKICBpZiAob3Blbikgc20uY2xhc3NMaXN0LmFkZCgib3BlbiIpOwogfSk7CgogZm0ucXVlcnlTZWxlY3RvckFsbCgiW2RhdGEtZmlsdGVyXSIpLmZvckVhY2goYnV0dG9uID0+IHsKICBidXR0b24uYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgIHNlbGVjdGVkVHlwZSA9IGJ1dHRvbi5kYXRhc2V0LmZpbHRlcjsKICAgZm0ucXVlcnlTZWxlY3RvckFsbCgiLmRyb3Bkb3duLW9wdGlvbiIpLmZvckVhY2goeCA9PgogICAgeC5jbGFzc0xpc3QudG9nZ2xlKCJhY3RpdmUiLCB4ID09PSBidXR0b24pKTsKICAgZmIuc2V0QXR0cmlidXRlKCJhcmlhLWxhYmVsIiwKICAgIHNlbGVjdGVkVHlwZSA9PT0gIl9fYWxsX18iID8gIkZpbHRlcjogQWxsIHR5cGVzIiA6ICJGaWx0ZXI6ICIgKyBzZWxlY3RlZFR5cGUpOwogICBjbG9zZU1lbnVzKCk7CiAgIHVwZGF0ZSgpOwogIH0pOwogfSk7Cgogc20ucXVlcnlTZWxlY3RvckFsbCgiW2RhdGEtc29ydF0iKS5mb3JFYWNoKGJ1dHRvbiA9PiB7CiAgYnV0dG9uLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogICBzZWxlY3RlZFNvcnQgPSBidXR0b24uZGF0YXNldC5zb3J0OwogICBzbS5xdWVyeVNlbGVjdG9yQWxsKCIuZHJvcGRvd24tb3B0aW9uIikuZm9yRWFjaCh4ID0+CiAgICB4LmNsYXNzTGlzdC50b2dnbGUoImFjdGl2ZSIsIHggPT09IGJ1dHRvbikpOwogICBjbG9zZU1lbnVzKCk7CiAgIHNvcnRSb3dzKCk7CiAgIHVwZGF0ZSgpOwogIH0pOwogfSk7CgogZnVuY3Rpb24gc29ydFJvd3MoKSB7CiAgY29uc3Qgcm93cyA9IFsuLi5ib2R5LnF1ZXJ5U2VsZWN0b3JBbGwoInRyIildOwogIGNvbnN0IGNvbGxhdG9yID0gbmV3IEludGwuQ29sbGF0b3IodW5kZWZpbmVkLAogICB7bnVtZXJpYzp0cnVlLCBzZW5zaXRpdml0eToiYmFzZSJ9KTsKICByb3dzLnNvcnQoKGEsYikgPT4gewogICBjb25zdCB4ID0gYS5kYXRhc2V0W3NlbGVjdGVkU29ydF0gfHwgIiI7CiAgIGNvbnN0IHkgPSBiLmRhdGFzZXRbc2VsZWN0ZWRTb3J0XSB8fCAiIjsKICAgaWYgKFsiaW5kZXgiLCJzaXplIiwibW9kaWZpZWQiXS5pbmNsdWRlcyhzZWxlY3RlZFNvcnQpKQogICAgcmV0dXJuIE51bWJlcih4KSAtIE51bWJlcih5KTsKICAgcmV0dXJuIGNvbGxhdG9yLmNvbXBhcmUoeCx5KTsKICB9KTsKICBpZiAoc2VsZWN0ZWRTb3J0ID09PSAic2l6ZSIgfHwgc2VsZWN0ZWRTb3J0ID09PSAibW9kaWZpZWQiKQogICByb3dzLnJldmVyc2UoKTsKICByb3dzLmZvckVhY2goKHJvdyxpKSA9PiB7CiAgIGJvZHkuYXBwZW5kQ2hpbGQocm93KTsKICAgY29uc3QgY2VsbCA9IHJvdy5xdWVyeVNlbGVjdG9yKCIuYXNzZXQtaW5kZXgiKTsKICAgaWYgKGNlbGwpIGNlbGwudGV4dENvbnRlbnQgPSBpICsgMTsKICB9KTsKIH0KCiBmdW5jdGlvbiB1cGRhdGUoKSB7CiAgY29uc3QgcSA9IChzZWFyY2gudmFsdWUgfHwgIiIpLnRvTG93ZXJDYXNlKCk7CiAgbGV0IHZpc2libGUgPSAwOwogIGJvZHkucXVlcnlTZWxlY3RvckFsbCgidHIiKS5mb3JFYWNoKHJvdyA9PiB7CiAgIGNvbnN0IHR5cGVPSyA9IHNlbGVjdGVkVHlwZSA9PT0gIl9fYWxsX18iIHx8CiAgICByb3cuZGF0YXNldC50eXBlID09PSBzZWxlY3RlZFR5cGU7CiAgIGNvbnN0IHNlYXJjaE9LID0gcm93LmlubmVyVGV4dC50b0xvd2VyQ2FzZSgpLmluY2x1ZGVzKHEpOwogICByb3cuc3R5bGUuZGlzcGxheSA9IHR5cGVPSyAmJiBzZWFyY2hPSyA/ICIiIDogIm5vbmUiOwogICBpZiAodHlwZU9LICYmIHNlYXJjaE9LKSB2aXNpYmxlKys7CiAgfSk7CiAgY291bnQudGV4dENvbnRlbnQgPSB2aXNpYmxlICsgIiBhc3NldHMiOwogfQogc2VhcmNoLmFkZEV2ZW50TGlzdGVuZXIoImlucHV0IiwgdXBkYXRlKTsKIGRvY3VtZW50LmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgZSA9PiB7CiAgaWYgKCFlLnRhcmdldC5jbG9zZXN0KCIuZHJvcGRvd24td3JhcCIpKSBjbG9zZU1lbnVzKCk7CiB9KTsKIHNvcnRSb3dzKCk7CiB1cGRhdGUoKTsKfSkoKTsKPC9zY3JpcHQ+Cgo8c2NyaXB0IHR5cGU9Im1vZHVsZSI+CmltcG9ydCAqIGFzIFRIUkVFIGZyb20gImh0dHBzOi8vY2RuLmpzZGVsaXZyLm5ldC9ucG0vdGhyZWVAMC4xNjAuMC9idWlsZC90aHJlZS5tb2R1bGUuanMiOwppbXBvcnQgeyBPcmJpdENvbnRyb2xzIH0gZnJvbSAiaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS90aHJlZUAwLjE2MC4wL2V4YW1wbGVzL2pzbS9jb250cm9scy9PcmJpdENvbnRyb2xzLmpzIjsKaW1wb3J0IHsgT0JKTG9hZGVyIH0gZnJvbSAiaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS90aHJlZUAwLjE2MC4wL2V4YW1wbGVzL2pzbS9sb2FkZXJzL09CSkxvYWRlci5qcyI7CgooKCkgPT4gewogY29uc3QgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm9iai1wcmV2aWV3LWNhbnZhcyIpOwogaWYgKCFjYW52YXMpIHJldHVybjsKCiBjb25zdCBzdGF0dXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgib2JqLXByZXZpZXctc3RhdHVzIik7CiBjb25zdCBpbmZvID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm9iai1pbmZvIik7CiBjb25zdCBpbnB1dCA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJvYmotZmlsZS1pbnB1dCIpOwoKIGNvbnN0IHNjZW5lID0gbmV3IFRIUkVFLlNjZW5lKCk7CiBzY2VuZS5iYWNrZ3JvdW5kID0gbmV3IFRIUkVFLkNvbG9yKDB4MDgwOTBkKTsKCiBjb25zdCBjYW1lcmEgPSBuZXcgVEhSRUUuUGVyc3BlY3RpdmVDYW1lcmEoNDUsIDEsIDAuMDEsIDEwMDAwMCk7CiBjYW1lcmEucG9zaXRpb24uc2V0KDQsIDMsIDUpOwoKIGNvbnN0IHJlbmRlcmVyID0gbmV3IFRIUkVFLldlYkdMUmVuZGVyZXIoe2NhbnZhcywgYW50aWFsaWFzOnRydWV9KTsKIHJlbmRlcmVyLnNldFBpeGVsUmF0aW8oTWF0aC5taW4od2luZG93LmRldmljZVBpeGVsUmF0aW8gfHwgMSwgMikpOwoKIHNjZW5lLmFkZChuZXcgVEhSRUUuSGVtaXNwaGVyZUxpZ2h0KDB4ZmZmZmZmLCAweDQ0NDQ1NSwgMikpOwogY29uc3QgbGlnaHQgPSBuZXcgVEhSRUUuRGlyZWN0aW9uYWxMaWdodCgweGZmZmZmZiwgMi41KTsKIGxpZ2h0LnBvc2l0aW9uLnNldCg1LCA4LCA2KTsKIHNjZW5lLmFkZChsaWdodCk7CgogY29uc3QgY29udHJvbHMgPSBuZXcgT3JiaXRDb250cm9scyhjYW1lcmEsIHJlbmRlcmVyLmRvbUVsZW1lbnQpOwogY29udHJvbHMuZW5hYmxlRGFtcGluZyA9IHRydWU7CgogY29uc3QgZ3JpZCA9IG5ldyBUSFJFRS5HcmlkSGVscGVyKDEwLCAyMCwgMHg0NDQ0NTUsIDB4MjIyMjMzKTsKIHNjZW5lLmFkZChncmlkKTsKCiBsZXQgb2JqZWN0ID0gbnVsbDsKIGxldCB3aXJlID0gZmFsc2U7CiBsZXQgcm90YXRpbmcgPSBmYWxzZTsKCiBmdW5jdGlvbiByZXNpemUoKSB7CiAgY29uc3QgcmVjdCA9IGNhbnZhcy5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsKICBpZiAoIXJlY3Qud2lkdGggfHwgIXJlY3QuaGVpZ2h0KSByZXR1cm47CiAgcmVuZGVyZXIuc2V0U2l6ZShyZWN0LndpZHRoLCByZWN0LmhlaWdodCwgZmFsc2UpOwogIGNhbWVyYS5hc3BlY3QgPSByZWN0LndpZHRoIC8gcmVjdC5oZWlnaHQ7CiAgY2FtZXJhLnVwZGF0ZVByb2plY3Rpb25NYXRyaXgoKTsKIH0KIG5ldyBSZXNpemVPYnNlcnZlcihyZXNpemUpLm9ic2VydmUoY2FudmFzKTsKIHJlc2l6ZSgpOwoKIGZ1bmN0aW9uIGZyYW1lT2JqZWN0KG9iaikgewogIGNvbnN0IGJveCA9IG5ldyBUSFJFRS5Cb3gzKCkuc2V0RnJvbU9iamVjdChvYmopOwogIGlmIChib3guaXNFbXB0eSgpKSByZXR1cm47CgogIGNvbnN0IHNpemUgPSBib3guZ2V0U2l6ZShuZXcgVEhSRUUuVmVjdG9yMygpKTsKICBjb25zdCBjZW50ZXIgPSBib3guZ2V0Q2VudGVyKG5ldyBUSFJFRS5WZWN0b3IzKCkpOwogIGNvbnN0IG1heFNpemUgPSBNYXRoLm1heChzaXplLngsIHNpemUueSwgc2l6ZS56LCAwLjAxKTsKICBjb25zdCBkaXN0YW5jZSA9IG1heFNpemUgKiAyLjI7CgogIGNvbnRyb2xzLnRhcmdldC5jb3B5KGNlbnRlcik7CiAgY2FtZXJhLnBvc2l0aW9uLnNldCgKICAgY2VudGVyLnggKyBkaXN0YW5jZSwKICAgY2VudGVyLnkgKyBkaXN0YW5jZSAqIDAuNywKICAgY2VudGVyLnogKyBkaXN0YW5jZQogICk7CiAgY2FtZXJhLm5lYXIgPSBNYXRoLm1heChtYXhTaXplIC8gMTAwMCwgMC4wMDEpOwogIGNhbWVyYS5mYXIgPSBtYXhTaXplICogMTAwOwogIGNhbWVyYS51cGRhdGVQcm9qZWN0aW9uTWF0cml4KCk7CiAgY29udHJvbHMudXBkYXRlKCk7CgogIGluZm8udGV4dENvbnRlbnQgPQogICAiVmVydGljZXM6ICIgKyBvYmouY2hpbGRyZW4ucmVkdWNlKChzdW0sIGNoaWxkKSA9PiB7CiAgICBjaGlsZC50cmF2ZXJzZShub2RlID0+IHsKICAgICBpZiAobm9kZS5pc01lc2ggJiYgbm9kZS5nZW9tZXRyeS5hdHRyaWJ1dGVzLnBvc2l0aW9uKQogICAgICBzdW0gKz0gbm9kZS5nZW9tZXRyeS5hdHRyaWJ1dGVzLnBvc2l0aW9uLmNvdW50OwogICAgfSk7CiAgICByZXR1cm4gc3VtOwogICB9LCAwKSArCiAgICIgfCBVa3VyYW46ICIgKwogICBzaXplLngudG9GaXhlZCgzKSArICIgw5cgIiArCiAgIHNpemUueS50b0ZpeGVkKDMpICsgIiDDlyAiICsKICAgc2l6ZS56LnRvRml4ZWQoMyk7CiB9CgogaW5wdXQuYWRkRXZlbnRMaXN0ZW5lcigiY2hhbmdlIiwgYXN5bmMgKCkgPT4gewogIGNvbnN0IGZpbGUgPSBpbnB1dC5maWxlcyAmJiBpbnB1dC5maWxlc1swXTsKICBpZiAoIWZpbGUpIHJldHVybjsKCiAgc3RhdHVzLnRleHRDb250ZW50ID0gIk1lbXVhdCAiICsgZmlsZS5uYW1lICsgIi4uLiI7CgogIHRyeSB7CiAgIGNvbnN0IHRleHQgPSBhd2FpdCBmaWxlLnRleHQoKTsKICAgY29uc3QgbG9hZGVyID0gbmV3IE9CSkxvYWRlcigpOwogICBjb25zdCBsb2FkZWQgPSBsb2FkZXIucGFyc2UodGV4dCk7CgogICBpZiAob2JqZWN0KSB7CiAgICBzY2VuZS5yZW1vdmUob2JqZWN0KTsKICAgIG9iamVjdC50cmF2ZXJzZShub2RlID0+IHsKICAgICBpZiAobm9kZS5pc01lc2gpIHsKICAgICAgbm9kZS5nZW9tZXRyeS5kaXNwb3NlKCk7CiAgICAgIGlmIChBcnJheS5pc0FycmF5KG5vZGUubWF0ZXJpYWwpKQogICAgICAgbm9kZS5tYXRlcmlhbC5mb3JFYWNoKG1hdGVyaWFsID0+IG1hdGVyaWFsLmRpc3Bvc2UoKSk7CiAgICAgIGVsc2UgaWYgKG5vZGUubWF0ZXJpYWwpIG5vZGUubWF0ZXJpYWwuZGlzcG9zZSgpOwogICAgIH0KICAgIH0pOwogICB9CgogICBsb2FkZWQudHJhdmVyc2Uobm9kZSA9PiB7CiAgICBpZiAobm9kZS5pc01lc2gpIHsKICAgICBub2RlLm1hdGVyaWFsID0gbmV3IFRIUkVFLk1lc2hTdGFuZGFyZE1hdGVyaWFsKHsKICAgICAgY29sb3I6MHhkOTM2NTAsCiAgICAgIG1ldGFsbmVzczowLjE1LAogICAgICByb3VnaG5lc3M6MC43LAogICAgICBzaWRlOlRIUkVFLkRvdWJsZVNpZGUsCiAgICAgIHdpcmVmcmFtZTp3aXJlCiAgICAgfSk7CiAgICB9CiAgIH0pOwoKICAgb2JqZWN0ID0gbG9hZGVkOwogICBzY2VuZS5hZGQob2JqZWN0KTsKICAgZnJhbWVPYmplY3Qob2JqZWN0KTsKICAgc3RhdHVzLnRleHRDb250ZW50ID0gIkJlcmhhc2lsIG1lbXVhdDogIiArIGZpbGUubmFtZTsKICB9IGNhdGNoIChlcnJvcikgewogICBjb25zb2xlLmVycm9yKGVycm9yKTsKICAgc3RhdHVzLnRleHRDb250ZW50ID0gIkdhZ2FsIG1lbWJhY2EgT0JKOiAiICsgZXJyb3IubWVzc2FnZTsKICB9CiB9KTsKCiBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgib2JqLXJlc2V0IikuYWRkRXZlbnRMaXN0ZW5lcigiY2xpY2siLCAoKSA9PiB7CiAgaWYgKG9iamVjdCkgZnJhbWVPYmplY3Qob2JqZWN0KTsKIH0pOwoKIGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJvYmotd2lyZSIpLmFkZEV2ZW50TGlzdGVuZXIoImNsaWNrIiwgKCkgPT4gewogIHdpcmUgPSAhd2lyZTsKICBpZiAob2JqZWN0KSBvYmplY3QudHJhdmVyc2Uobm9kZSA9PiB7CiAgIGlmIChub2RlLmlzTWVzaCkgbm9kZS5tYXRlcmlhbC53aXJlZnJhbWUgPSB3aXJlOwogIH0pOwogfSk7CgogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoIm9iai1yb3RhdGUiKS5hZGRFdmVudExpc3RlbmVyKCJjbGljayIsICgpID0+IHsKICByb3RhdGluZyA9ICFyb3RhdGluZzsKICBjb250cm9scy5hdXRvUm90YXRlID0gcm90YXRpbmc7CiB9KTsKCiBmdW5jdGlvbiBhbmltYXRlKCkgewogIHJlcXVlc3RBbmltYXRpb25GcmFtZShhbmltYXRlKTsKICBjb250cm9scy51cGRhdGUoKTsKICByZW5kZXJlci5yZW5kZXIoc2NlbmUsIGNhbWVyYSk7CiB9CiBhbmltYXRlKCk7Cn0pKCk7Cjwvc2NyaXB0PgoKPC9ib2R5Pgo8L2h0bWw+Cg=='
HTML = _template_base64.b64decode(_HTML_B64).decode('utf-8')
HTML = HTML.replace('<a href="/app-dumper"><span>▣</span> APP DUMPER</a>', '<a href="/dashboard"><span>▣</span> Workspace</a>')
def load_bundle(path):
    env = UnityPy.load(str(path))
    assets = []
    types = {}

    try:
        bundle_modified = int(Path(path).stat().st_mtime)
    except Exception:
        bundle_modified = 0

    for index, obj in enumerate(env.objects):
        try:
            name = obj.type.name
        except Exception:
            name = str(obj.type)

        try:
            path_id = obj.path_id
        except Exception:
            path_id = "Unknown"

        try:
            class_id = int(obj.type)
        except Exception:
            class_id = "Unknown"

        try:
            asset_name = obj.peek_name() or f"{name}_{path_id}"
        except Exception:
            asset_name = f"{name}_{path_id}"

        try:
            asset_size = len(obj.get_raw_data())
        except Exception:
            asset_size = 0

        assets.append({
            "index": index,
            "name": str(asset_name),
            "type": name,
            "path": path_id,
            "classid": class_id,
            "size": asset_size,
            "modified": bundle_modified
        })
        types[name] = types.get(name, 0) + 1

    return assets, types


AUTH_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=Noto+Serif+JP:wght@400;600;700;900&display=swap');
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 14px;
background:radial-gradient(ellipse at 50% 0%,#34334b 0%,#171a2b 48%,#10131f 100%);
color:#f7eee4;font-family:'Noto Serif JP',serif;overflow-x:hidden;position:relative}
body:before,body:after{content:"";position:fixed;pointer-events:none;opacity:.28;
width:230px;height:230px;background:
radial-gradient(ellipse at 50% 12%,#f4a7b9 0 12%,transparent 13%),
radial-gradient(ellipse at 88% 42%,#f4a7b9 0 12%,transparent 13%),
radial-gradient(ellipse at 72% 86%,#f4a7b9 0 12%,transparent 13%),
radial-gradient(ellipse at 28% 86%,#f4a7b9 0 12%,transparent 13%),
radial-gradient(ellipse at 12% 42%,#f4a7b9 0 12%,transparent 13%)}
body:before{top:12px;left:-75px;transform:rotate(-18deg)}
body:after{right:-75px;bottom:12px;transform:rotate(22deg)}
.auth-card{position:relative;width:min(100%,460px);padding:30px 26px;
background:linear-gradient(145deg,#24283bF2,#171a2bf5);
border:1px solid #b68a9b;border-radius:4px 28px 4px 28px;
box-shadow:0 20px 65px #050711aa}
.brand{font-size:23px;font-weight:900;letter-spacing:3px;color:#f1b6c5}
.sub{font-size:10px;letter-spacing:4px;color:#d7c4b6;margin:8px 0 28px}
.japan-mark{position:absolute;right:25px;top:24px;width:48px;height:48px;border-radius:50%;
display:grid;place-items:center;background:#a8324b;color:#fff1e8;font-size:25px;
box-shadow:0 0 0 5px #a8324b33}
h1{font-size:24px;margin:0 0 8px;color:#fff0e7}
p{font-size:13px;line-height:1.8;color:#d0c3c5}
label{display:block;font-size:12px;color:#f0c6cf;margin:17px 0 7px}
input{width:100%;padding:14px;background:#101321;border:1px solid #776476;
border-radius:5px;color:#fff;font:inherit}
input:focus{outline:none;border-color:#e7a9b9;box-shadow:0 0 0 3px #e7a9b922}
button{width:100%;margin-top:24px;padding:14px;background:linear-gradient(110deg,#b52d4b,#d96b82);
border:1px solid #f0aaba;border-radius:5px;color:#fff8f0;font-weight:900;letter-spacing:2px}
a{color:#f0aaba;text-decoration:none}.foot{text-align:center;margin-top:22px;font-size:13px}
.msg{padding:11px;border:1px solid #b86d83;background:#402433;border-radius:5px;
color:#ffe0e6;font-size:13px;margin:13px 0}
.kamon{text-align:center;color:#d8b98d;font-size:11px;letter-spacing:5px;margin-top:22px}
"""

def auth_page(title, body):
    return render_template_string("""
    <!doctype html><html lang="id"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{{title}} - HanZihan Uabe</title><style>""" + AUTH_STYLE + """</style></head>
    <body><section class="auth-card"><div class="japan-mark">桜</div>
    <div class="brand">HanZihan Uabe</div>
    <div class="sub">HanZihan Uabe</div>""" + body + """
    <div class="kamon">和 · 桜 · 日本</div></section></body></html>
    """, title=title)

@app.route("/create-account", methods=["GET", "POST"])
def create_account():
    error = ""
    if request.method == "POST":
        if not valid_csrf():
            abort(400)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not re.fullmatch(r"[A-Za-z0-9_]{3,24}", username):
            error = "Username harus 3–24 karakter (huruf, angka, underscore)."
        elif len(password) < 8:
            error = "Password minimal 8 karakter."
        elif password != confirm:
            error = "Konfirmasi password tidak sama."
        else:
            try:
                with db_connect() as conn:
                    conn.execute(
                        "INSERT INTO accounts(username,password_hash) VALUES(?,?)",
                        (username, generate_password_hash(password))
                    )
                return redirect(url_for("login", registered="1"))
            except sqlite3.IntegrityError:
                error = "Username sudah digunakan."
    body = """
    <h1>アカウント作成 · Buat Akun</h1><p>Buat akun untuk memasuki workspace HanZihan Uabe.</p>
    {% if error %}<div class="msg">{{error}}</div>{% endif %}
    <form method="post">
      <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
      <label>USERNAME</label><input name="username" minlength="3" maxlength="24" autocomplete="username" required>
      <label>PASSWORD</label><input type="password" name="password" minlength="8" autocomplete="new-password" required>
      <label>KONFIRMASI PASSWORD</label><input type="password" name="confirm_password" minlength="8" autocomplete="new-password" required>
      <button type="submit">CREATE ACCOUNT</button>
    </form><div class="foot">Sudah punya akun? <a href="{{url_for('login')}}">Login</a></div>
    """
    return auth_page("Create Account", body_with_context(body, error))

def body_with_context(body, error):
    return render_template_string(body, error=error)

LOGIN_FAILS = {}

def _login_key(username):
    return (request.remote_addr or "?", username.lower())

def login_blocked(username):
    # Maksimal 5 login gagal per 10 menit untuk kombinasi IP + username.
    now = time.time()
    hits = [t for t in LOGIN_FAILS.get(_login_key(username), []) if now - t < 600]
    LOGIN_FAILS[_login_key(username)] = hits
    return len(hits) >= 5

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        if not valid_csrf():
            abort(400)
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if login_blocked(username):
            error = "Terlalu banyak percobaan login. Coba lagi dalam 10 menit."
        else:
            with db_connect() as conn:
                account = conn.execute(
                    "SELECT * FROM accounts WHERE username=? COLLATE NOCASE",
                    (username,)
                ).fetchone()
            if account and check_password_hash(account["password_hash"], password):
                LOGIN_FAILS.pop(_login_key(username), None)
                session.clear()
                session["user_id"] = account["id"]
                session["username"] = account["username"]
                return redirect(url_for("index"))
            LOGIN_FAILS.setdefault(_login_key(username), []).append(time.time())
            error = "Username atau password salah."
    body = """
    <h1>ログイン · Login</h1><p>おかえりなさい。Masuk ke workspace HanZihan Uabe.</p>
    {% if registered %}<div class="msg">Akun berhasil dibuat. Silakan login.</div>{% endif %}
    {% if error %}<div class="msg">{{error}}</div>{% endif %}
    <form method="post">
      <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
      <label>USERNAME</label><input name="username" autocomplete="username" required>
      <label>PASSWORD</label><input type="password" name="password" autocomplete="current-password" required>
      <button type="submit">LOGIN · ログイン</button>
    </form><div class="foot">Belum punya akun? <a href="{{url_for('create_account')}}">Create Account</a></div>
    """
    return auth_page("Login", render_template_string(
        body, error=error, registered=request.args.get("registered") == "1"
    ))

@app.route("/logout", methods=["POST"])
def logout():
    if not valid_csrf():
        abort(400)
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@app.route("/dashboard")
def index():
    current = None
    assets = []
    types = {}

    mine = [k for k, v in sessions.items() if v.get("owner") == session.get("user_id")]
    if mine:
        current = sessions[mine[-1]]
        # Dashboard must remain reachable even when the latest session is AOV.
        assets = current.get("assets", [])
        types = current.get("types", {})

    return render_template_string(
        HTML,
        current=current,
        assets=assets,
        types=types,
        total=len(assets)
    )

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("bundle")

    if not file or not file.filename:
        flash("Pilih file terlebih dahulu.")
        return redirect(url_for("index"))

    # Tidak membatasi ekstensi: nama file game bisa memakai ekstensi khusus
    # atau bahkan tanpa ekstensi. Validasi dilakukan oleh parser berdasarkan isi file.
    original = secure_filename(file.filename) or "uploaded_asset"

    uid = uuid.uuid4().hex[:12]
    path = UPLOADS / f"{uid}_{original}"
    file.save(path)

    game_mode = request.form.get("game_mode", "freefire").lower()
    if game_mode not in ("freefire", "mlbb", "aov"):
        game_mode = "freefire"

    try:
        # AOV .bytes are analyzed as raw/nested binary data. Do not pass them
        # through UnityPy's AssetBundle loader.
        if game_mode == "aov":
            report = aov_analyzer.analyze_path(path)
            summary = aov_analyzer.summarize(report)
            sessions[uid] = {
                "game_mode": "aov",
                "id": uid,
                "owner": session.get("user_id"),
                "name": original,
                "path": path,
                "original_path": path,
                "original_name": original,
                "working_path": None,
                "edit_log": [],
                "assets": [],
                "types": {"AOV Bytes Analysis": 1},
                "aov_report": report,
                "aov_summary": summary
            }
            flash("Analisis AOV selesai. File asli tetap tidak diubah.")
            return redirect(url_for("aov_analysis", uid=uid))

        # Existing Free Fire and MLBB processing remains on the original path.
        assets, types = load_bundle(path)
        sessions[uid] = {
            "game_mode": game_mode,
            "id": uid,
                "owner": session.get("user_id"),
            "name": original,
            "path": path,
            "original_path": path,
            "original_name": original,
            "assets": assets,
            "types": types
        }
        flash(f"Berhasil membaca {len(assets)} object.")
    except Exception as e:
        path.unlink(missing_ok=True)
        flash("Bundle gagal dibaca: " + str(e)[:250])

    return redirect(url_for("index"))



@app.route("/aov-analysis/<uid>")
def aov_analysis(uid):
    item = sessions.get(uid)
    if not item or item.get("game_mode") != "aov":
        return "Sesi analisis AOV tidak ditemukan", 404

    import html
    summary = html.escape(item.get("aov_summary", ""))
    report = item.get("aov_report", {})
    if "files" in report:
        file_count = report.get("file_count", len(report.get("files", [])))
        items = report.get("files", [])
    else:
        file_count = 1
        items = [report]

    rows = []
    for entry in items[:1000]:
        rows.append(
            "<tr><td>" + html.escape(str(entry.get("name", "(unknown)"))) +
            "</td><td>" + html.escape(str(entry.get("size", "-"))) +
            "</td><td>" + html.escape(", ".join(entry.get("magic", []))) +
            "</td><td>" + html.escape(str(entry.get("sha256", "-"))) +
            "</td></tr>"
        )
    table_rows = "".join(rows) or '<tr><td colspan="4">Tidak ada file yang dapat dianalisis.</td></tr>'

    page = """<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AOV Bytes Analysis</title>
<style>
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
 margin:0;min-height:100vh;padding:20px 14px 45px;
 background:radial-gradient(ellipse at 50% 0%,#34334b 0%,#191b30 48%,#0d101b 100%);
 color:#f7edf1;font:15px 'Noto Serif JP',Georgia,serif;overflow-x:hidden
}
body:before{
 content:'桜';position:fixed;right:12px;top:8px;
 font-size:110px;color:#f4a7b9;opacity:.07;pointer-events:none
}
.wrap{position:relative;max-width:1100px;margin:auto}
.panel{
 background:linear-gradient(145deg,#25283cf5,#171a2bf7);
 border:1px solid #62566d;border-radius:5px 22px 5px 22px;
 padding:20px;margin:14px 0;min-width:0;
 box-shadow:0 14px 38px #05071166
}
h1,h2{color:#f0b6c5;letter-spacing:1.4px}
h1{font-size:clamp(23px,5vw,34px);line-height:1.3}
h2{font-size:19px;border-bottom:1px solid #62536a;padding-bottom:12px}
small,.muted{color:#c9bdcc;line-height:1.7}
a,button{
 display:inline-block;padding:12px 15px;margin:5px 5px 5px 0;
 border-radius:5px 13px 5px 13px;
 background:linear-gradient(110deg,#922d49,#cf607c);
 color:#fff8f5;text-decoration:none;border:1px solid #e7a4b6;
 font-weight:900;letter-spacing:.5px;cursor:pointer
}
a:active,button:active{transform:scale(.98)}
.scroll{overflow:auto;max-width:100%;border:1px solid #51465c;border-radius:8px}
table{width:100%;border-collapse:collapse;min-width:620px}
th,td{
 text-align:left;padding:12px;border-bottom:1px solid #51465c;
 vertical-align:top;overflow-wrap:anywhere
}
th{background:#29243a;color:#f0b6c5;font-size:12px;letter-spacing:.7px}
td{color:#eee4eb}
pre{
 white-space:pre-wrap;overflow-wrap:anywhere;
 background:#101321;padding:15px;border:1px solid #62536a;
 border-radius:8px;max-height:70vh;overflow:auto;
 font-size:12px;line-height:1.7;color:#f3dce5
}
@media(max-width:600px){
 body{padding:12px 10px 32px}
 .panel{padding:16px;border-radius:5px 17px 5px 17px}
 a,button{font-size:11px;padding:11px 12px}
 h2{font-size:16px}
}
@media(prefers-reduced-motion:reduce){
 *,*::before,*::after{scroll-behavior:auto!important;transition:none!important}
}
</style></head><body><div class="wrap">
<div class="panel"><p class="muted">和 · 桜 · JAPANESE PROJECT WORKSPACE</p><h1>AOV UNIVERSAL BYTES ANALYZER</h1>
<p>File: """ + html.escape(item.get("original_name", item.get("name", ""))) + """</p>
<p class="muted">Read-only analysis • """ + str(file_count) + """ file(s) inspected • File sumber tidak dimodifikasi.</p>
<a href="/aov-report/""" + uid + """/json">DOWNLOAD JSON REPORT</a>
<a href="/aov-report/""" + uid + """/txt">DOWNLOAD TXT REPORT</a>
<a href="/aov-edit/""" + uid + """">EDIT TEXT</a>
<a href="/aov-export/""" + uid + """">EXPORT BYTES</a>
<a href="/dashboard">BACK TO DASHBOARD</a>
</div>
<div class="panel"><h2>FILE SUMMARY</h2><div class="scroll"><table><thead><tr><th>NAME</th><th>SIZE</th><th>DETECTED FORMAT</th><th>SHA256</th></tr></thead><tbody>""" + table_rows + """</tbody></table></div></div>
<div class="panel"><h2>DETAILED ANALYSIS</h2><pre>""" + summary + """</pre></div>
<div class="panel"><p class="muted">Catatan: analyzer ini mendeteksi signature, string, entropy, ZIP bersarang, dan kandidat wrapper/Zstandard. Ini bukan decoder atau builder format AOV yang belum diketahui.</p></div>
</div></body></html>"""
    return page


@app.route("/aov-edit/<uid>", methods=["GET", "POST"])
def aov_edit(uid):
    import html

    item = sessions.get(uid)
    if not item or item.get("game_mode") != "aov":
        return "Sesi AOV tidak ditemukan", 404

    active_path = Path(item.get("working_path") or item["original_path"])
    if not active_path.is_file():
        return "File AOV tidak ditemukan", 404

    message = ""
    error = ""
    old_text = ""
    new_text = ""
    if request.method == "POST":
        if not valid_csrf():
            abort(400)
        old_text = request.form.get("old_text", "")
        new_text = request.form.get("new_text", "")
        try:
            if not old_text:
                raise ValueError("Teks yang ingin diganti wajib diisi.")
            old_bytes = old_text.encode("utf-8")
            new_bytes = new_text.encode("utf-8")
            if len(old_bytes) > 1024 * 1024 or len(new_bytes) > 1024 * 1024:
                raise ValueError("Maksimal 1 MiB untuk teks lama atau pengganti.")

            source_path = Path(item.get("working_path") or item["original_path"])
            data = source_path.read_bytes()
            count = data.count(old_bytes)
            if count == 0:
                raise ValueError("Teks tidak ditemukan sebagai teks UTF-8 di file. Jika file terkompresi, teks mungkin belum bisa dibaca langsung.")
            if count > 10000:
                raise ValueError(f"Ditemukan {count} kemunculan. Terlalu banyak untuk satu operasi; pilih teks yang lebih spesifik.")

            updated = data.replace(old_bytes, new_bytes)
            original_path = Path(item["original_path"])
            working_path = Path(item.get("working_path") or (UPLOADS / (uid + "_aov_edited_" + original_path.name.split("_", 1)[-1])))
            temp_path = working_path.with_name(working_path.name + ".writing")
            temp_path.write_bytes(updated)
            temp_path.replace(working_path)

            item["working_path"] = working_path
            item["path"] = working_path
            item.setdefault("edit_log", []).append({
                "old_text": old_text,
                "new_text": new_text,
                "count": count,
                "old_hex": old_bytes.hex(" "),
                "new_hex": new_bytes.hex(" "),
            })
            try:
                item["aov_report"] = aov_analyzer.analyze_path(working_path)
                item["aov_summary"] = aov_analyzer.summarize(item["aov_report"])
            except Exception:
                pass
            message = f"Berhasil mengganti {count} kemunculan teks. Byte UTF-8 diperbarui otomatis; ukuran file sekarang {len(updated):,} byte."
            active_path = working_path
            old_text = ""
            new_text = ""
        except (ValueError, OSError, UnicodeError) as exc:
            error = str(exc)

    data = active_path.read_bytes()
    # Tampilkan string ASCII yang terbaca, beserta offset-nya. Ini hanya daftar
    # kandidat teks; data terkompresi atau terenkripsi mungkin tidak menampilkan string.
    found = []
    for match in re.finditer(rb"[ -~]{4,}", data):
        try:
            value = match.group().decode("utf-8")
        except UnicodeDecodeError:
            continue
        found.append((match.start(), value))
        if len(found) >= 300:
            break
    string_rows = "".join(
        "<tr><td>0x" + format(offset, "X") + "</td><td><code>" + html.escape(value) + "</code></td></tr>"
        for offset, value in found
    ) or '<tr><td colspan="2">Belum ada teks terbaca. File mungkin terkompresi atau memakai encoding lain.</td></tr>'

    logs = item.get("edit_log", [])
    log_rows = "".join(
        "<tr><td>" + str(i + 1) + "</td><td><code>" + html.escape(str(entry.get("old_text", ""))) +
        "</code></td><td><code>" + html.escape(str(entry.get("new_text", ""))) +
        "</code></td><td>" + str(entry.get("count", 0)) + "</td></tr>"
        for i, entry in enumerate(logs[-100:])
    ) or '<tr><td colspan="4">Belum ada perubahan.</td></tr>'

    csrf_input = '<input type="hidden" name="_csrf_token" value="' + html.escape(csrf_token(), quote=True) + '">'
    page = """<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>AOV Text Editor</title>
<style>
:root{--pink:#f0b6c5;--rose:#d96b82;--line:#62536a}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;padding:22px 14px 48px;background:radial-gradient(ellipse at 50% 0%,#34334b 0%,#171a2b 48%,#10131f 100%);color:#f7eee4;font:15px 'Noto Serif JP',Georgia,serif;overflow-x:hidden}
body:before{content:'桜';position:fixed;right:12px;top:8px;font-size:100px;color:#f4a7b9;opacity:.08;pointer-events:none}.wrap{position:relative;max-width:1080px;margin:auto}
.panel{background:linear-gradient(145deg,#24283bf2,#171a2bf5);border:1px solid #776476;border-radius:5px 22px 5px 22px;padding:20px;margin:14px 0;box-shadow:0 14px 40px #05071166;min-width:0}
h1,h2{color:var(--pink);letter-spacing:1.5px}h1{font-size:clamp(21px,4vw,30px)}h2{font-size:16px;border-bottom:1px solid var(--line);padding-bottom:12px}
a,button{display:inline-block;padding:12px 16px;margin:5px;border-radius:5px;background:linear-gradient(110deg,#a8324b,#d96b82);color:#fff8f0;text-decoration:none;border:1px solid #f0aaba;font-weight:900;letter-spacing:1px;cursor:pointer}
input,textarea{width:100%;padding:14px;margin:8px 0 16px;background:#101321;color:#fff;border:1px solid #776476;border-radius:5px;font-size:16px}textarea{min-height:100px;resize:vertical}input:focus,textarea:focus{outline:none;border-color:#e7a9b9;box-shadow:0 0 0 3px #e7a9b922}
label{display:block;color:#f0c6cf;font-size:12px;letter-spacing:1px;margin:12px 0 5px}.muted{color:#d0c3d0;line-height:1.7}.msg,.err{padding:12px;border-radius:5px;margin-top:12px}.msg{background:#20372f;border:1px solid #54856c}.err{background:#402433;border:1px solid #b86d83;color:#ffe0e6}
.scroll{overflow:auto;max-height:55vh;border:1px solid var(--line);border-radius:7px}table{width:100%;border-collapse:collapse;min-width:440px}td,th{text-align:left;padding:11px;border-bottom:1px solid #51465c;vertical-align:top;overflow-wrap:anywhere}th{position:sticky;top:0;background:#29243a;color:var(--pink);font-size:11px}code{white-space:pre-wrap;overflow-wrap:anywhere;color:#ffd2dc}
@media(max-width:600px){body{padding:12px 10px 32px}.panel{padding:16px;border-radius:5px 17px 5px 17px}a,button{font-size:11px;padding:11px 12px}}
</style></head><body><div class="wrap">
<div class="panel"><p class="muted">和 · 桜 · JAPANESE PROJECT WORKSPACE</p><h1>AOV TEXT EDITOR</h1><p>File: """ + html.escape(item.get("original_name", "AOV bytes")) + """</p>
<p class="muted">Ukuran file aktif: """ + f"{len(data):,}""" + """ byte. File asli tetap aman dan tidak ditimpa.</p>
<a href="/aov-analysis/""" + uid + """">ANALYSIS</a><a href="/aov-export/""" + uid + """">EXPORT EDITED FILE</a><a href="/dashboard">DASHBOARD</a>
""" + ("<div class='msg'>" + html.escape(message) + "</div>" if message else "") + ("<div class='err'>" + html.escape(error) + "</div>" if error else "") + """
</div>
<div class="panel"><h2>EDIT TEXT</h2><form method="post">""" + csrf_input + """
<label>TEKS ASLI YANG MAU DIGANTI</label><textarea name="old_text" placeholder="Masukkan teks yang ditemukan di file" required>""" + html.escape(old_text) + """</textarea>
<label>TEKS PENGGANTI</label><textarea name="new_text" placeholder="Ketik teks baru di sini">""" + html.escape(new_text) + """</textarea>
<p class="muted">Byte HEX akan dibuat otomatis dari teks UTF-8. Semua kemunculan teks yang sama akan diganti. Panjang file dapat berubah jika panjang teks pengganti berbeda. File sumber asli tidak diubah.</p>
<button type="submit">APPLY TEXT EDIT</button></form></div>
<div class="panel"><h2>DETECTED TEXT</h2><p class="muted">Pilih teks dari daftar ini lalu salin ke kolom TEKS ASLI. Maksimal 300 teks pertama yang terbaca ditampilkan.</p><div class="scroll"><table><thead><tr><th>OFFSET</th><th>TEXT</th></tr></thead><tbody>""" + string_rows + """</tbody></table></div></div>
<div class="panel"><h2>EDIT HISTORY</h2><div class="scroll"><table><thead><tr><th>#</th><th>OLD TEXT</th><th>NEW TEXT</th><th>COUNT</th></tr></thead><tbody>""" + log_rows + """</tbody></table></div></div>
</div></body></html>"""
    return page


@app.route("/aov-export/<uid>")
def aov_export(uid):
    item = sessions.get(uid)
    if not item or item.get("game_mode") != "aov":
        return "Sesi AOV tidak ditemukan", 404
    export_path = Path(item.get("working_path") or item["original_path"])
    if not export_path.is_file():
        return "File untuk export tidak ditemukan", 404
    original_name = secure_filename(item.get("original_name", "aov_bytes")) or "aov_bytes"
    if item.get("working_path"):
        stem = Path(original_name).stem
        suffix = Path(original_name).suffix or ".bytes"
        download_name = stem + "_edited" + suffix
    else:
        download_name = original_name
    return send_file(export_path, as_attachment=True, download_name=download_name,
                     mimetype="application/octet-stream")


@app.route("/aov-report/<uid>/<fmt>")
def aov_report_download(uid, fmt):
    item = sessions.get(uid)
    if not item or item.get("game_mode") != "aov":
        return "Laporan AOV tidak ditemukan", 404

    from io import BytesIO
    if fmt == "json":
        payload = json.dumps(
            item.get("aov_report", {}),
            ensure_ascii=False,
            indent=2
        ).encode("utf-8")
        mimetype = "application/json; charset=utf-8"
        filename = "aov_bytes_report.json"
    elif fmt == "txt":
        payload = item.get("aov_summary", "").encode("utf-8")
        mimetype = "text/plain; charset=utf-8"
        filename = "aov_bytes_report.txt"
    else:
        return "Format laporan tidak didukung", 400

    return send_file(
        BytesIO(payload),
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )

@app.route("/download/<uid>")
def download(uid):
    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    original_path = Path(item.get("original_path", item["path"]))
    if not original_path.is_file():
        return "File original tidak ditemukan", 404

    return send_file(
        original_path,
        as_attachment=True,
        download_name=item.get("original_name", original_path.name)
    )


@app.route("/download-modified/<uid>")
def download_modified(uid):
    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    modified_path = Path(item["path"])
    if not modified_path.is_file():
        return "File hasil modifikasi tidak ditemukan", 404

    return send_file(
        modified_path,
        as_attachment=True,
        download_name=item["name"]
    )


@app.route("/preview/<uid>/<int:index>")
def preview(uid, index):
    from io import BytesIO
    import traceback

    item = sessions.get(uid)

    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))
        objects = list(env.objects)

        if index < 0 or index >= len(objects):
            return "Index asset tidak ditemukan", 404

        obj = objects[index]

        if obj.type.name != "Texture2D":
            return "Asset bukan Texture2D", 400

        # Gunakan parser Texture2D UnityPy.
        tex = obj.parse_as_object()
        image = tex.image

        output = BytesIO()
        image.save(output, format="PNG")
        output.seek(0)

        return send_file(
            output,
            mimetype="image/png",
            download_name=f"texture_{obj.path_id}.png"
        )

    except Exception as e:
        print("\n===== TEXTURE PREVIEW ERROR =====")
        traceback.print_exc()
        return "Preview gagal: " + str(e)[:500], 500


def find_asset_by_path(env, path_id):
    for obj in env.objects:
        if str(obj.path_id) == str(path_id):
            return obj
    return None


def merge_unity_asset_data(original, imported):
    """
    Merge data import secara konservatif.
    Objek khusus UnityPy dipertahankan jika tidak dapat direkonstruksi
    dari representasi TXT/JSON.
    """
    if isinstance(original, dict):
        if not isinstance(imported, dict):
            return original

        merged = {}
        for key, old_value in original.items():
            if key in imported:
                merged[key] = merge_unity_asset_data(
                    old_value, imported[key]
                )
            else:
                merged[key] = old_value

        return merged

    if isinstance(original, list):
        if not isinstance(imported, list):
            return original

        merged = []
        for index, old_value in enumerate(original):
            if index < len(imported):
                merged.append(
                    merge_unity_asset_data(old_value, imported[index])
                )
            else:
                merged.append(old_value)

        return merged

    primitive = (str, int, float, bool)

    # Nilai sederhana boleh diperbarui dengan nilai sederhana.
    if isinstance(original, primitive):
        if isinstance(imported, primitive):
            if isinstance(original, bool):
                return imported if isinstance(imported, bool) else original

            if isinstance(original, int) and not isinstance(original, bool):
                if isinstance(imported, int) and not isinstance(imported, bool):
                    return imported
                if isinstance(imported, float):
                    return imported
                return original

            if isinstance(original, float):
                if isinstance(imported, (int, float)) and not isinstance(imported, bool):
                    return imported
                return original

            if isinstance(original, str):
                return imported if isinstance(imported, str) else original

        return original

    # Objek khusus, bytes, dan tipe UnityPy lain tidak diganti
    # dengan string/dictionary yang tidak kompatibel.
    return original

def patch_unity_asset(obj, imported_data):
    """Patch asset dengan mempertahankan seluruh field wajib dari asset asli."""
    original_data = obj.parse_as_dict()
    if not isinstance(original_data, dict):
        raise ValueError("UnityPy tidak dapat membaca struktur asset asli.")
    merged_data = merge_unity_asset_data(original_data, imported_data)
    obj.patch(merged_data)
    return merged_data


def json_safe(value, depth=0):
    if depth > 10:
        return str(value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return {"bytes_hex": value[:2048].hex(),
                "truncated": len(value) > 2048}
    if isinstance(value, dict):
        return {str(k): json_safe(v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v, depth + 1) for v in value]
    return str(value)


def unity_dump_value(value):
    import json
    if isinstance(value, bool):
        return "bool", "1" if value else "0"
    if isinstance(value, str):
        return "string", json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return "int", str(value)
    if isinstance(value, float):
        return "float", repr(value)
    if value is None or isinstance(value, (dict, list, tuple)):
        return "json", json.dumps(json_safe(value), ensure_ascii=False)
    return "string", json.dumps(str(value), ensure_ascii=False)


def format_unity_text_dump(data, class_name="Object"):
    if not isinstance(data, dict):
        raise ValueError("Data asset bukan dictionary")
    lines = [f"0 {class_name} Base"]
    for key, value in data.items():
        typ, rendered = unity_dump_value(value)
        lines.append(f" 1 {typ} {key} = {rendered}")
    return "\n".join(lines)


def parse_unity_text_dump(raw):
    import json

    raw = raw.lstrip("\ufeff")
    if "\\n" in raw and "\n" not in raw:
        raw = raw.replace("\\n", "\n")

    lines = raw.splitlines()
    header_re = re.compile(r"^\s*0\s+.+\s+Base\s*$")

    if not lines or not header_re.match(lines[0]):
        raise ValueError(
            "Header dump Unity tidak ditemukan. "
            f"Awal file: {raw[:100]!r}"
        )

    field_re = re.compile(
        r"^\s*1\s+(string|int|SInt32|UInt32|float|bool|UInt8|SInt64|UInt64|json)\s+([^=]+?)\s*=\s*(.*)$"
    )

    data = {}
    i = 1

    while i < len(lines):
        if not lines[i].strip():
            i += 1
            continue

        match = field_re.match(lines[i])
        if not match:
            raise ValueError(f"Baris dump tidak dikenali: {i + 1}")

        typ, name, value = match.groups()
        chunks = [value]
        i += 1

        while i < len(lines) and not field_re.match(lines[i]) and not header_re.match(lines[i]):
            chunks.append(lines[i])
            i += 1

        value = "\n".join(chunks).strip()
        name = name.strip()

        if typ == "json":
            data[name] = json.loads(value)
        elif typ == "string":
            data[name] = json.loads(value) if value.startswith('"') else value
        elif typ == "bool":
            data[name] = value.lower() in ("1", "true", "yes")
        elif typ == "float":
            data[name] = float(value)
        else:
            data[name] = int(value, 0)

    return data

def asset_text_dump(obj, game_mode="freefire"):
    parsed = json_safe(obj.parse_as_dict())
    if game_mode == "mlbb":
        return json.dumps(parsed, ensure_ascii=False, indent=2)
    class_name = getattr(getattr(obj, "type", None), "name", None) or "Object"
    return format_unity_text_dump(parsed, str(class_name))



@app.route("/asset-json-preview/<uid>/<path:path_id>",
           methods=["GET", "POST"])
def asset_json_preview(uid, path_id):
    import json
    import html

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    def editor_page(content, error=""):
        safe_content = html.escape(content, quote=False)
        safe_path = html.escape(str(path_id), quote=True)
        safe_error = html.escape(error)
        game_mode = item.get("game_mode", "freefire")
        editor_format = "JSON" if game_mode == "mlbb" else "TXT"
        editor_title = "JSON VIEWER / EDITOR" if game_mode == "mlbb" else "TXT VIEWER / EDITOR"

        return """<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>""" + editor_title + """</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#090909;color:#eee;
font-family:Arial,sans-serif;padding:16px}
.wrap{max-width:1100px;margin:auto}
h2{color:#ff354d;margin-bottom:8px}
.info{color:#999;font-size:13px;margin-bottom:15px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
button,a{border:0;border-radius:6px;padding:11px 16px;
font-weight:bold;text-decoration:none;cursor:pointer;font-size:12px}
.edit{background:#333;color:white}
.save{background:#c51e38;color:white}
.cancel{background:#292929;color:white}
textarea{width:100%;min-height:68vh;background:#101010;
color:#b9efc5;border:1px solid #444;border-radius:9px;
padding:15px;font:13px/1.6 monospace;resize:vertical;
outline:none;tab-size:2}
textarea:focus{border-color:#e52c46}
.status{color:#aaa;font-size:12px;margin:10px 0}
.error{background:#481722;color:#ffc4cd;padding:12px;
border-radius:7px;margin-bottom:12px}

/* MLBB PREMIUM LAYOUT V2 */
:root {
  --bg:#08090e;
  --panel:#12151f;
  --panel2:#191d29;
  --red:#ff3657;
  --line:#292e3b;
  --muted:#969bad;
}

* {
  box-sizing:border-box;
}

html {
  width:100%;
  min-width:0;
  scroll-behavior:smooth;
}

body {
  width:100%;
  min-width:0 !important;
  max-width:100%;
  overflow-x:hidden;
  background:
    radial-gradient(ellipse at 80% 0%,#35101c33,transparent 38%),
    var(--bg);
  color:#f4f5fa;
}

header {
  min-width:0;
  box-shadow:0 5px 25px #0005;
  backdrop-filter:blur(14px);
}

main {
  width:calc(100% - 250px);
  max-width:1600px;
  min-width:0;
  margin-left:250px;
  padding:28px;
  display:grid;
  grid-template-columns:repeat(12,minmax(0,1fr));
  gap:18px;
  align-items:start;
}

main > .panel {
  grid-column:span 12;
  width:100%;
  min-width:0;
}

#upload-panel,
#info-panel,
#explorer-panel,
#tools-panel {
  grid-column:span 12;
}

#summary-panel {
  grid-column:span 12;
}

.panel {
  min-width:0;
  overflow:hidden;
  padding:22px;
  border:1px solid var(--line);
  border-radius:15px;
  background:linear-gradient(145deg,#171a25,#10121a);
  box-shadow:0 12px 32px #0003;
  transition:border-color .2s ease,transform .2s ease;
}

.panel h2 {
  display:flex;
  align-items:center;
  gap:10px;
  font-size:14px;
  letter-spacing:1.2px;
  line-height:1.5;
}

.panel h2:before {
  content:"";
  width:4px;
  height:17px;
  flex-shrink:0;
  border-radius:5px;
  background:var(--red);
  box-shadow:0 0 12px #ff365766;
}

.stats {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}

.stat {
  min-width:0;
  padding:18px;
  border:1px solid #303545;
  border-radius:12px;
  background:linear-gradient(145deg,#202432,#171a24);
}

.stat b {
  font-size:26px;
  overflow-wrap:anywhere;
}

input:not([type=checkbox]),
select,
textarea {
  width:100%;
  max-width:100%;
  min-height:44px;
  padding:12px 14px;
  color:#f5f5f8;
  background:#0b0d14;
  border:1px solid #343a49;
  border-radius:9px;
  font:inherit;
}

input:focus,
select:focus,

/* JSON PREVIEW FIX */
textarea {
    display: block !important;
    width: 100% !important;
    max-width: 100% !important;
    height: 75vh !important;
    min-height: 500px !important;
    overflow-x: hidden !important;
    overflow-y: auto !important;
    white-space: pre-wrap !important;
    overflow-wrap: anywhere !important;
    word-break: break-word !important;
    font-family: monospace !important;
    font-size: 14px !important;
    line-height: 1.65 !important;
    resize: vertical !important;
    tab-size: 2;
    -webkit-overflow-scrolling: touch;
}

/* Pastikan preview JSON membungkus baris panjang di layar HP. */
#jsonData {
    white-space: pre-wrap !important;
    overflow-wrap: anywhere !important;
    word-break: break-all !important;
    overflow-x: hidden !important;
    max-width: 100% !important;
}

textarea:focus {
  outline:none;
  border-color:var(--red);
  box-shadow:0 0 0 3px #ff36571c;
}

button,
.btn {
  min-height:42px;
  padding:11px 16px;
  border-radius:9px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.4px;
}

button:active,
.btn:active {
  transform:scale(.97);
}

a {
  overflow-wrap:anywhere;
}

.scroll {
  width:100%;
  max-width:100%;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  -webkit-overflow-scrolling:touch;
}

table {
  width:100%;
  min-width:650px;
  border-collapse:collapse;
}

th {
  background:#1b1e2a;
}

th,td {
  padding:13px 12px;
  vertical-align:middle;
}

tbody tr:nth-child(even) {
  background:#ffffff05;
}

.asset-controls {
  display:flex;
  align-items:center;
  flex-wrap:wrap;
  gap:10px;
}

.native-menu-button {
  min-height:44px;
  border-radius:9px;
}

.asset-count {
  margin-left:auto;
  font-weight:700;
}

.action-cell {
  min-width:200px;
}

.action-group {
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  gap:7px;
}

.action-group a,
.action-group button {
  min-height:36px;
  padding:8px 11px;
  border-radius:7px;
  font-size:10px;
}

.notice {
  border-radius:10px;
  padding:14px 16px;
}

.developer-card {
  border-radius:14px;
}

.developer-link {
  min-height:46px;
  border-radius:10px;
}

@media(min-width:1101px) {
  #info-panel {
    grid-column:span 5;
  }
  #summary-panel {
    grid-column:span 4;
  }
  #tools-panel {
    grid-column:span 3;
  }
}

@media(max-width:1100px) {
  main {
    width:100%;
    margin-left:0;
    padding:20px;
  }
}

@media(max-width:760px) {
  header {
    left:0;
    right:0;
    height:70px;
    padding:9px 12px;
    gap:8px;
  }

  header .logo {
    font-size:15px;
    letter-spacing:1px;
  }

  header .sub {
    display:none;
  }

  .menu-toggle {
    display:block;
    min-width:78px;
    min-height:40px;
    padding:9px 11px;
    font-size:11px;
  }

  .sidebar {
    top:70px;
    bottom:0;
    width:min(285px,85vw);
    padding:17px 13px 85px;
    overflow-y:auto;
    transform:translateX(-105%);
    transition:transform .25s ease;
    box-shadow:15px 0 40px #0009;
  }

  body.sidebar-open .sidebar {
    transform:translateX(0);
  }

  main {
    display:flex;
    flex-direction:column;
    width:100%;
    min-width:0;
    margin:70px 0 0;
    padding:13px;
    gap:13px;
  }

  main > .panel {
    width:100%;
    min-width:0;
  }

  .panel {
    padding:15px;
    border-radius:13px;
  }

  .panel h2 {
    font-size:13px;
    margin-bottom:15px;
  }

  .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:9px;
  }

  .stat {
    padding:13px;
  }

  .stat b {
    font-size:21px;
  }

  .asset-controls {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:8px;
  }

  .asset-controls .dropdown-wrap,
  .asset-controls .native-menu-button {
    width:100%;
  }

  .asset-count {
    grid-column:1/-1;
    margin:3px 0;
  }

  .native-dropdown {
    min-width:0;
    width:min(240px,calc(100vw - 45px));
  }

  .action-cell {
    min-width:180px;
  }

  .action-group {
    gap:6px;
  }

  .action-group a,
  .action-group button {
    min-height:38px;
    padding:9px;
  }

  #upload-panel form {
    width:100%;
  }

  #upload-panel button,
  #upload-panel input[type=file] {
    width:100%;
  }

  .developer-card {
    padding:16px 10px;
  }

  .side-status {
    position:static;
    margin-top:20px;
  }

  .scroll {
    max-height:65vh;
  }
}

@media(max-width:380px) {
  main {
    padding:10px;
  }

  .panel {
    padding:12px;
  }

  .stats {
    gap:7px;
  }

  .stat {
    padding:11px;
  }

  .stat b {
    font-size:19px;
  }
}

/* Shared mobile layout for standalone manager pages */
@media(max-width:760px) {
  body {
    padding:12px !important;
  }

  body > h2 {
    font-size:17px;
  }

  body > .panel {
    width:100%;
    padding:14px;
    margin-bottom:13px;
  }

  body > .panel .btn,
  body > .panel button {
    margin:4px 0;
  }

  body > header {
    padding:0 12px;
  }

  body > main {
    margin:0;
    padding:12px 0;
  }

  body > main .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}

@media(prefers-reduced-motion:reduce) {
  *,*::before,*::after {
    animation:none !important;
    transition:none !important;
    scroll-behavior:auto !important;
  }
}

</style>
</head>
<body>
<div class="wrap">
<h2>""" + editor_title + """</h2>
<div class="info">PATH ID: """ + safe_path + """</div>
""" + ('<div class="error">' + safe_error + '</div>' if error else '') + """
<div class="json-search" id="jsonSearchPanel">
  <div class="find-title">Cari dalam """ + editor_format + """</div>
  <div class="find-entry">
    <span>Menemukan</span>
    <input type="search" id="jsonSearch" placeholder="Masukkan teks pencarian..." autocomplete="off">
    <button type="button" class="find-close" onclick="closeFind()" aria-label="Tutup pencarian">×</button>
  </div>
  <div class="find-options">
    <span id="searchCount">Hasil: 0</span>
    <button type="button" class="find-toggle" id="caseToggle" aria-pressed="false" onclick="toggleFindOption('case')">Cc</button>
    <button type="button" class="find-toggle" id="wordToggle" aria-pressed="false" onclick="toggleFindOption('word')">W</button>
    <button type="button" class="find-toggle" id="regexToggle" aria-pressed="false" onclick="toggleFindOption('regex')">.*</button>
  </div>
  <div class="find-actions">
    <button type="button" class="search-nav" onclick="findMatch(-1)">SEBELUMNYA</button>
    <button type="button" class="search-nav" onclick="findMatch(1)">BERIKUTNYA</button>
    <button type="button" class="search-nav find-all" onclick="selectAllMatches()">SEMUA</button>
  </div>
</div>
<form method="post" id="jsonForm">
<div class="toolbar">
<button type="button" class="edit" id="editBtn"
onclick="enableEdit()">EDIT</button>
<button type="submit" class="save" id="saveBtn" disabled>
SIMPAN """ + editor_format + """
</button>
<button type="button" class="cancel" onclick="cancelEdit()">
BATAL
</button>
</div>
<textarea name="json_data" id="jsonData"
spellcheck="false" wrap="soft" readonly required>""" + safe_content + """</textarea>
<div class="status" id="statusText">
MODE PREVIEW — Tekan EDIT untuk mengubah teks.
</div>
</form>
</div>
<script>
const editor=document.getElementById("jsonData");
const saveBtn=document.getElementById("saveBtn");
const statusText=document.getElementById("statusText");
const original=editor.value;
const searchInput=document.getElementById("jsonSearch");
const searchCount=document.getElementById("searchCount");
let matches=[];
let activeMatch=-1;
const findOptions={case:false,word:false,regex:false};

function buildSearchMatches(){
 const q=searchInput.value;
 matches=[];
 activeMatch=-1;
 if(!q){searchCount.textContent="Hasil: 0";return;}
 let source=editor.value;
 try{
  let pattern=findOptions.regex?q:q.replace(/[.*+?^${}()|[\\]\\]/g,"\\$&");
  if(findOptions.word) pattern="\\b(?:"+pattern+")\\b";
  const flags=findOptions.case?"g":"gi";
  const re=new RegExp(pattern,flags);
  let m;
  while((m=re.exec(source))!==null){
   matches.push({start:m.index,end:m.index+m[0].length});
   if(m[0].length===0) re.lastIndex++;
  }
  searchCount.textContent="Hasil: "+matches.length;
 }catch(err){searchCount.textContent="Pola regex tidak valid";}
}

function refreshMatches(){buildSearchMatches();}
function findMatch(direction){
 buildSearchMatches();
 if(!matches.length){searchCount.textContent="Tidak ditemukan";return;}
 activeMatch=activeMatch<0?(direction>0?0:matches.length-1):(activeMatch+direction+matches.length)%matches.length;
 const hit=matches[activeMatch];
 editor.focus();
 editor.setSelectionRange(hit.start,hit.end);
 const before=editor.value.slice(0,hit.start);
 const line=before.split("\n").length;
 const lineHeight=parseFloat(getComputedStyle(editor).lineHeight)||22;
 editor.scrollTop=Math.max(0,(line-3)*lineHeight);
 searchCount.textContent=(activeMatch+1)+" / "+matches.length;
}
function toggleFindOption(name){
 findOptions[name]=!findOptions[name];
 const ids={case:"caseToggle",word:"wordToggle",regex:"regexToggle"};
 const btn=document.getElementById(ids[name]);
 btn.classList.toggle("active",findOptions[name]);
 btn.setAttribute("aria-pressed",String(findOptions[name]));
 buildSearchMatches();
}
function selectAllMatches(){
 buildSearchMatches();
 if(!matches.length)return;
 editor.focus();
 editor.setSelectionRange(matches[0].start,matches[matches.length-1].end);
 searchCount.textContent=matches.length+" hasil dipilih";
}
function closeFind(){
 searchInput.value="";buildSearchMatches();
}
searchInput.addEventListener("input",buildSearchMatches);
searchInput.addEventListener("keydown",function(e){
 if(e.key==="Enter"){e.preventDefault();findMatch(e.shiftKey?-1:1);}
});

function enableEdit(){
 editor.readOnly=false;
 editor.focus();
 saveBtn.disabled=false;
 statusText.textContent="MODE EDIT — Perubahan belum disimpan.";
}

function cancelEdit(){
 editor.value=original;
 editor.readOnly=true;
 saveBtn.disabled=true;
 statusText.textContent="MODE PREVIEW";
}

document.getElementById("jsonForm").addEventListener("submit",function(e){
 if(editor.readOnly){
  e.preventDefault();
  return;
 }
 if(!confirm("Simpan perubahan teks ke bundle?")){
  e.preventDefault();
  return;
 }
 saveBtn.disabled=true;
 saveBtn.textContent="MENYIMPAN...";
});
</script>
</body>
</html>"""

    try:
        if request.method == "GET":
            env = UnityPy.load(str(item["path"]))
            obj = find_asset_by_path(env, path_id)

            if obj is None:
                return "Asset tidak ditemukan", 404

            data = asset_text_dump(obj, item.get("game_mode", "freefire"))
            return editor_page(data)

        raw = request.form.get("json_data", "")

        if len(raw.encode("utf-8")) > 10 * 1024 * 1024:
            return "File teks maksimal 10 MB", 413

        try:
            first_line = raw.splitlines()[0].strip() if raw.splitlines() else ""
            if first_line.startswith("{"):
                data = json.loads(raw)
            elif re.match(r"^\s*0\s+.+\s+Base\s*$", first_line):
                data = parse_unity_text_dump(raw)
            else:
                raise ValueError("Gunakan JSON object atau Unity dump TXT.")
        except (ValueError, json.JSONDecodeError) as e:
            return editor_page(raw, "Format TXT/JSON tidak valid: " + str(e)[:250]), 400

        if not isinstance(data, dict):
            return editor_page(
                raw, "Teks harus berisi object/dictionary asset."
            ), 400

        env = UnityPy.load(str(item["path"]))
        obj = find_asset_by_path(env, path_id)

        if obj is None:
            return "Asset tidak ditemukan", 404

        patch_unity_asset(obj, data)

        suffix = "_json_edit" if item.get("game_mode") == "mlbb" else "_txt_edit"
        output = save_edited_bundle(env, item, suffix)
        item["assets"], item["types"] = load_bundle(output)

        flash("Perubahan teks berhasil disimpan: " + output.name)
        return redirect(url_for("index"))

    except Exception as e:
        return "Preview/Edit teks gagal: " + str(e)[:500], 500


@app.route("/asset-json-export/<uid>/<path:path_id>")
def asset_json_export(uid, path_id):
    import json
    from io import BytesIO
    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404
    try:
        env = UnityPy.load(str(item["path"]))
        obj = find_asset_by_path(env, path_id)
        if obj is None:
            return "Asset tidak ditemukan", 404
        game_mode = item.get("game_mode", "freefire")
        data = asset_text_dump(obj, game_mode).encode("utf-8")
        ext = "json" if game_mode == "mlbb" else "txt"
        mimetype = "application/json; charset=utf-8" if game_mode == "mlbb" else "text/plain; charset=utf-8"
        return send_file(BytesIO(data), mimetype=mimetype,
                         as_attachment=True,
                         download_name=f"asset_{path_id}.{ext}")
    except Exception as e:
        return "Export TXT gagal: " + str(e)[:300], 500


@app.route("/asset-json-import/<uid>/<path:path_id>",
           methods=["GET", "POST"])
def asset_json_import(uid, path_id):
    import json
    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    if request.method == "GET":
        return """
        <html><meta name="viewport" content="width=device-width,initial-scale=1">
        <body style="background:#090909;color:white;font-family:Arial;padding:20px">
        <h2>IMPORT """ + ("JSON" if item.get("game_mode") == "mlbb" else "TXT") + """</h2>
        <p>Path ID: """ + str(path_id) + """</p>
        <form method="post" enctype="multipart/form-data">
        <input type="file" name="jsonfile" accept=".txt,.json,text/plain,application/json" required>
        <button>IMPORT """ + ("JSON" if item.get("game_mode") == "mlbb" else "TXT") + """</button></form>
        </body></html>
        """

    try:
        f = request.files.get("jsonfile")
        if not f or not f.filename.lower().endswith((".txt", ".json")):
            return "Pilih file TXT", 400
        raw = f.read()
        if len(raw) > 10 * 1024 * 1024:
            return "File teks maksimal 10 MB", 413
        text_data = raw.decode("utf-8-sig")
        if "\\n" in text_data and "\n" not in text_data:
            text_data = text_data.replace("\\n", "\n")
        first_line = text_data.splitlines()[0].strip() if text_data.splitlines() else ""
        if first_line.startswith("{"):
            data = json.loads(text_data)
        elif re.match(r"^\s*0\s+.+\s+Base\s*$", first_line):
            data = parse_unity_text_dump(text_data)
        else:
            raise ValueError("Gunakan JSON object atau Unity dump TXT.")
        if not isinstance(data, dict):
            return "Isi teks tidak sesuai struktur asset", 400

        env = UnityPy.load(str(item["path"]))
        obj = find_asset_by_path(env, path_id)
        if obj is None:
            return "Asset tidak ditemukan", 404

        patch_unity_asset(obj, data)
        suffix = "_json_import" if item.get("game_mode") == "mlbb" else "_txt_import"
        output = save_edited_bundle(env, item, suffix)
        item["assets"], item["types"] = load_bundle(output)
        flash("File TXT/JSON berhasil diterapkan: " + output.name)
        return redirect(url_for("index"))
    except Exception as e:
        import traceback
        print("\\n===== HANZIHAN UABE IMPORT TRACEBACK =====")
        traceback.print_exc()
        return "Import TXT/JSON gagal: " + str(e)[:300], 500




@app.route("/mesh-import/<uid>/<path:path_id>", methods=["POST"])
def mesh_import(uid, path_id):
    import math
    import struct
    import traceback

    if not valid_csrf():
        return "CSRF token tidak valid. Muat ulang dashboard lalu coba lagi.", 400

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan. Upload bundle terlebih dahulu.", 404

    upload = request.files.get("obj_file")
    if upload is None or not upload.filename:
        return "Pilih file OBJ terlebih dahulu.", 400
    if not upload.filename.lower().endswith(".obj"):
        return "Format file harus .obj", 400

    try:
        raw = upload.read()
        if not raw or len(raw) > 100 * 1024 * 1024:
            return "File OBJ kosong atau melebihi 100 MB.", 400

        text_data = raw.decode("utf-8-sig")
        vertices, uvs, normals, faces = [], [], [], []

        def obj_index(value, count, line_no):
            index = int(value)
            index = index - 1 if index > 0 else count + index
            if index < 0 or index >= count:
                raise ValueError(f"Indeks OBJ tidak valid pada baris {line_no}.")
            return index

        for line_no, line in enumerate(text_data.splitlines(), 1):
            parts = line.strip().split()
            if not parts or parts[0].startswith("#"):
                continue

            kind = parts[0]
            if kind in ("v", "vn"):
                if len(parts) < 4:
                    return f"Data {kind} tidak lengkap pada baris {line_no}.", 400
                value = tuple(float(x) for x in parts[1:4])
                if not all(math.isfinite(x) for x in value):
                    return f"Nilai {kind} tidak valid pada baris {line_no}.", 400
                (vertices if kind == "v" else normals).append(value)

            elif kind == "vt":
                if len(parts) < 3:
                    return f"UV tidak lengkap pada baris {line_no}.", 400
                value = tuple(float(x) for x in parts[1:3])
                if not all(math.isfinite(x) for x in value):
                    return f"UV tidak valid pada baris {line_no}.", 400
                uvs.append(value)

            elif kind == "f":
                if len(parts) < 4:
                    return f"Face harus memiliki minimal 3 titik pada baris {line_no}.", 400

                polygon = []
                for token in parts[1:]:
                    fields = token.split("/")
                    vi = obj_index(fields[0], len(vertices), line_no)

                    ti = None
                    ni = None
                    if len(fields) > 1 and fields[1]:
                        ti = obj_index(fields[1], len(uvs), line_no)
                    if len(fields) > 2 and fields[2]:
                        ni = obj_index(fields[2], len(normals), line_no)

                    polygon.append((vi, ti, ni))

                # Triangulasi polygon sederhana menggunakan fan.
                for i in range(1, len(polygon) - 1):
                    faces.append((polygon[0], polygon[i], polygon[i + 1]))

        
        # Bangun ulang vertex berdasarkan kombinasi indeks OBJ.
        # OBJ mengizinkan indeks posisi, UV, dan normal berbeda.
        remap = {}
        rebuilt_vertices = []
        rebuilt_uvs = []
        rebuilt_normals = []
        rebuilt_faces = []

        for face in faces:
            new_face = []
            for vi, ti, ni in face:
                key = (vi, ti, ni)
                if key not in remap:
                    remap[key] = len(rebuilt_vertices)
                    rebuilt_vertices.append(vertices[vi])
                    rebuilt_uvs.append(uvs[ti] if ti is not None else (0.0, 0.0))
                    rebuilt_normals.append(normals[ni] if ni is not None else (0.0, 0.0, 0.0))
                new_face.append((remap[key], remap[key], remap[key]))
            rebuilt_faces.append(tuple(new_face))

        vertices = rebuilt_vertices
        uvs = rebuilt_uvs
        normals = rebuilt_normals
        faces = rebuilt_faces

        if not vertices or not faces:

            return "OBJ harus memiliki vertex dan face.", 400

        target_path_id = int(path_id)
        env = UnityPy.load(str(item["path"]))
        mesh_obj = next(
            (o for o in env.objects
             if o.type.name == "Mesh" and int(o.path_id) == target_path_id),
            None
        )
        if mesh_obj is None:
            return "Mesh tidak ditemukan untuk Path ID tersebut.", 404

        mesh = mesh_obj.parse_as_object()
        from UnityPy.classes.generated import ChannelInfo, StreamInfo

        vd = mesh.m_VertexData
        if vd is None:
            raise ValueError("Mesh tidak memiliki VertexData.")

        new_count = len(vertices)
        if new_count < 3:
            return "OBJ minimal harus memiliki 3 vertex.", 400

        # Buat layout VertexData baru, tanpa memakai stream lama.
        stride = 32
        data = bytearray(new_count * stride)

        channels = [
            ChannelInfo(dimension=3, format=0, offset=0, stream=0),
            ChannelInfo(dimension=3, format=0, offset=12, stream=0),
            ChannelInfo(dimension=2, format=0, offset=24, stream=0),
        ]

        streams = [
            StreamInfo(channelMask=7, offset=0, stride=stride)
        ]

        for i in range(new_count):
            base = i * stride
            x, y, z = vertices[i]
            nx, ny, nz = normals[i]
            u, v = uvs[i]

            # Konversi sumbu X mengikuti exporter UnityPy.
            struct.pack_into(
                "<8f", data, base,
                -x, y, z,
                -nx, ny, nz,
                u, v
            )

        vd.m_VertexCount = new_count
        vd.m_DataSize = bytes(data)
        vd.m_Channels = channels
        vd.m_Streams = streams
        vd.m_CurrentChannels = 7

        # Susun ulang triangle index.
        indices = []
        for tri in faces:
            a, b, c = (v[0] for v in tri)
            indices.extend((c, b, a))

        if max(indices) > 0xFFFFFFFF:
            return "Indeks vertex melebihi batas Unity.", 400

        index_format = getattr(mesh, "m_IndexFormat", 0)
        use_16 = int(index_format or 0) == 0
        if use_16 and max(indices) > 65535:
            use_16 = False

        fmt = "<" + ("H" if use_16 else "I") * len(indices)
        index_bytes = struct.pack(fmt, *indices)
        mesh.m_IndexBuffer = list(index_bytes)

        submeshes = mesh.m_SubMeshes or []
        if not submeshes:
            return "Mesh tidak memiliki SubMesh yang bisa diperbarui.", 400

        # Patch pertama mempertahankan satu material/submesh.
        sub = submeshes[0]
        sub.firstByte = 0
        sub.firstVertex = 0
        sub.indexCount = len(indices)
        sub.vertexCount = new_count
        sub.topology = 0
        if hasattr(sub, "triangleCount"):
            sub.triangleCount = len(indices) // 3

        # Hilangkan submesh tambahan agar tidak menunjuk ke index lama.
        mesh.m_SubMeshes = [sub]

        vd.m_DataSize = bytes(data)
        mesh.save()

        output = save_edited_bundle(env, item, "_mesh_import")
        item["assets"], item["types"] = load_bundle(output)

        flash(
            f"Import OBJ berhasil: {output.name} "
            f"({new_count} vertex, {len(indices)//3} triangle) [TEST MODE]."
        )
        return redirect(url_for("index"))

    except UnicodeDecodeError:
        return "File OBJ harus menggunakan teks UTF-8.", 400
    except Exception as e:
        traceback.print_exc()
        return "Import OBJ gagal: " + str(e)[:500], 500


@app.route("/health")
def health():
    return {"status": "online", "app": "HanZihan Uabe"}


def save_edited_bundle(env, item, suffix):
    import shutil

    original = item["path"]
    backup = original.with_name(original.name + ".original")

    if not backup.exists():
        shutil.copy2(original, backup)

    # Pertahankan ekstensi/nama sumber, termasuk ekstensi khusus Free Fire.
    output = original.with_name(original.name + suffix)

    output.write_bytes(env.file.save())
    item["path"] = output
    item["name"] = output.name
    return output


@app.route("/mesh-manager/<uid>")
def mesh_manager(uid):
    item = sessions.get(uid)

    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))
        meshes = []

        for obj in env.objects:
            if obj.type.name != "Mesh":
                continue

            try:
                name = obj.peek_name() or "(Tanpa nama)"
            except Exception:
                name = "(Tidak diketahui)"

            meshes.append({
                "name": name,
                "path": obj.path_id,
                "classid": obj.class_id
            })

        page = """
        <!DOCTYPE html>
        <html lang="id">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport"
        content="width=device-width,initial-scale=1">
        <title>Mesh Manager</title>
        <style>
        *{box-sizing:border-box}
        body{background:#090909;color:#eee;
        font-family:Arial;padding:15px}
        .panel{background:#151515;padding:17px;
        border:1px solid #442027;border-radius:10px;
        margin-bottom:15px}
        h2{color:#ff465d}
        input{width:100%;padding:12px;background:#090909;
        border:1px solid #555;color:white;margin:7px 0}
        button,.btn{padding:10px;background:#c91f38;
        color:white;border:0;border-radius:6px;
        text-decoration:none;display:inline-block}
        table{width:100%;font-size:12px;border-collapse:collapse}
        td,th{padding:12px 6px;border-bottom:1px solid #333;
        text-align:left}
        th{color:#ff465d}
        .scroll{overflow-x:auto}
        .danger{background:#8d1726}
        small{color:#aaa}
        
/* MLBB PREMIUM LAYOUT V2 */
:root {
  --bg:#08090e;
  --panel:#12151f;
  --panel2:#191d29;
  --red:#ff3657;
  --line:#292e3b;
  --muted:#969bad;
}

* {
  box-sizing:border-box;
}

html {
  width:100%;
  min-width:0;
  scroll-behavior:smooth;
}

body {
  width:100%;
  min-width:0 !important;
  max-width:100%;
  overflow-x:hidden;
  background:
    radial-gradient(ellipse at 80% 0%,#35101c33,transparent 38%),
    var(--bg);
  color:#f4f5fa;
}

header {
  min-width:0;
  box-shadow:0 5px 25px #0005;
  backdrop-filter:blur(14px);
}

main {
  width:calc(100% - 250px);
  max-width:1600px;
  min-width:0;
  margin-left:250px;
  padding:28px;
  display:grid;
  grid-template-columns:repeat(12,minmax(0,1fr));
  gap:18px;
  align-items:start;
}

main > .panel {
  grid-column:span 12;
  width:100%;
  min-width:0;
}

#upload-panel,
#info-panel,
#explorer-panel,
#tools-panel {
  grid-column:span 12;
}

#summary-panel {
  grid-column:span 12;
}

.panel {
  min-width:0;
  overflow:hidden;
  padding:22px;
  border:1px solid var(--line);
  border-radius:15px;
  background:linear-gradient(145deg,#171a25,#10121a);
  box-shadow:0 12px 32px #0003;
  transition:border-color .2s ease,transform .2s ease;
}

.panel h2 {
  display:flex;
  align-items:center;
  gap:10px;
  font-size:14px;
  letter-spacing:1.2px;
  line-height:1.5;
}

.panel h2:before {
  content:"";
  width:4px;
  height:17px;
  flex-shrink:0;
  border-radius:5px;
  background:var(--red);
  box-shadow:0 0 12px #ff365766;
}

.stats {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}

.stat {
  min-width:0;
  padding:18px;
  border:1px solid #303545;
  border-radius:12px;
  background:linear-gradient(145deg,#202432,#171a24);
}

.stat b {
  font-size:26px;
  overflow-wrap:anywhere;
}

input:not([type=checkbox]),
select,
textarea {
  width:100%;
  max-width:100%;
  min-height:44px;
  padding:12px 14px;
  color:#f5f5f8;
  background:#0b0d14;
  border:1px solid #343a49;
  border-radius:9px;
  font:inherit;
}

input:focus,
select:focus,
textarea:focus {
  outline:none;
  border-color:var(--red);
  box-shadow:0 0 0 3px #ff36571c;
}

button,
.btn {
  min-height:42px;
  padding:11px 16px;
  border-radius:9px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.4px;
}

button:active,
.btn:active {
  transform:scale(.97);
}

a {
  overflow-wrap:anywhere;
}

.scroll {
  width:100%;
  max-width:100%;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  -webkit-overflow-scrolling:touch;
}

table {
  width:100%;
  min-width:650px;
  border-collapse:collapse;
}

th {
  background:#1b1e2a;
}

th,td {
  padding:13px 12px;
  vertical-align:middle;
}

tbody tr:nth-child(even) {
  background:#ffffff05;
}

.asset-controls {
  display:flex;
  align-items:center;
  flex-wrap:wrap;
  gap:10px;
}

.native-menu-button {
  min-height:44px;
  border-radius:9px;
}

.asset-count {
  margin-left:auto;
  font-weight:700;
}

.action-cell {
  min-width:200px;
}

.action-group {
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  gap:7px;
}

.action-group a,
.action-group button {
  min-height:36px;
  padding:8px 11px;
  border-radius:7px;
  font-size:10px;
}

.notice {
  border-radius:10px;
  padding:14px 16px;
}

.developer-card {
  border-radius:14px;
}

.developer-link {
  min-height:46px;
  border-radius:10px;
}

@media(min-width:1101px) {
  #info-panel {
    grid-column:span 5;
  }
  #summary-panel {
    grid-column:span 4;
  }
  #tools-panel {
    grid-column:span 3;
  }
}

@media(max-width:1100px) {
  main {
    width:100%;
    margin-left:0;
    padding:20px;
  }
}

@media(max-width:760px) {
  header {
    left:0;
    right:0;
    height:70px;
    padding:9px 12px;
    gap:8px;
  }

  header .logo {
    font-size:15px;
    letter-spacing:1px;
  }

  header .sub {
    display:none;
  }

  .menu-toggle {
    display:block;
    min-width:78px;
    min-height:40px;
    padding:9px 11px;
    font-size:11px;
  }

  .sidebar {
    top:70px;
    bottom:0;
    width:min(285px,85vw);
    padding:17px 13px 85px;
    overflow-y:auto;
    transform:translateX(-105%);
    transition:transform .25s ease;
    box-shadow:15px 0 40px #0009;
  }

  body.sidebar-open .sidebar {
    transform:translateX(0);
  }

  main {
    display:flex;
    flex-direction:column;
    width:100%;
    min-width:0;
    margin:70px 0 0;
    padding:13px;
    gap:13px;
  }

  main > .panel {
    width:100%;
    min-width:0;
  }

  .panel {
    padding:15px;
    border-radius:13px;
  }

  .panel h2 {
    font-size:13px;
    margin-bottom:15px;
  }

  .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:9px;
  }

  .stat {
    padding:13px;
  }

  .stat b {
    font-size:21px;
  }

  .asset-controls {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:8px;
  }

  .asset-controls .dropdown-wrap,
  .asset-controls .native-menu-button {
    width:100%;
  }

  .asset-count {
    grid-column:1/-1;
    margin:3px 0;
  }

  .native-dropdown {
    min-width:0;
    width:min(240px,calc(100vw - 45px));
  }

  .action-cell {
    min-width:180px;
  }

  .action-group {
    gap:6px;
  }

  .action-group a,
  .action-group button {
    min-height:38px;
    padding:9px;
  }

  #upload-panel form {
    width:100%;
  }

  #upload-panel button,
  #upload-panel input[type=file] {
    width:100%;
  }

  .developer-card {
    padding:16px 10px;
  }

  .side-status {
    position:static;
    margin-top:20px;
  }

  .scroll {
    max-height:65vh;
  }
}

@media(max-width:380px) {
  main {
    padding:10px;
  }

  .panel {
    padding:12px;
  }

  .stats {
    gap:7px;
  }

  .stat {
    padding:11px;
  }

  .stat b {
    font-size:19px;
  }
}

/* Shared mobile layout for standalone manager pages */
@media(max-width:760px) {
  body {
    padding:12px !important;
  }

  body > h2 {
    font-size:17px;
  }

  body > .panel {
    width:100%;
    padding:14px;
    margin-bottom:13px;
  }

  body > .panel .btn,
  body > .panel button {
    margin:4px 0;
  }

  body > header {
    padding:0 12px;
  }

  body > main {
    margin:0;
    padding:12px 0;
  }

  body > main .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}

@media(prefers-reduced-motion:reduce) {
  *,*::before,*::after {
    animation:none !important;
    transition:none !important;
    scroll-behavior:auto !important;
  }
}


.json-search{display:flex;flex-direction:column;gap:8px;margin:14px 0;padding:10px;background:#17191f;border:1px solid #30343e;border-radius:10px}
.find-title{font-size:13px;color:#aeb4c0;font-weight:700}
.find-entry{display:flex;align-items:center;gap:8px;min-width:0;color:#c9ced8;font-size:13px}
.find-entry input{flex:1;min-width:0;width:100%;padding:11px 12px;background:#090c13;color:#fff;border:1px solid #3b4352;border-radius:7px;font-size:15px;outline:none}
.find-entry input:focus{border-color:#397fc7}
.find-close{background:transparent;color:#aeb4c0;border:0;font-size:25px;padding:2px 8px}
.find-options,.find-actions{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
#searchCount{flex:1;color:#b9c0cc;font-size:13px;min-width:90px}
.find-toggle{background:#242832;color:#cbd1dc;border:1px solid #414957;border-radius:6px;padding:7px 10px;font-weight:700}
.find-toggle.active{background:#245b91;border-color:#3988d1;color:white}
.json-search button.search-nav{background:#292d36;color:#eee;border:1px solid #414653;border-radius:7px;padding:9px 11px;font-size:12px;font-weight:700;flex:1}
.json-search button.find-all{flex:0 0 auto}
@media(max-width:420px){.find-entry{flex-wrap:wrap}.find-entry input{flex-basis:100%;order:2}.find-close{margin-left:auto}.find-actions{gap:5px}.json-search button.search-nav{padding:9px 7px;font-size:11px}}
#jsonData{display:block;width:100%;max-width:100%;min-height:70vh;box-sizing:border-box;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;tab-size:2;line-height:1.55;overflow-x:hidden}
</style>
        </head>
        <body>
        <h2>MLBB / MESH MANAGER</h2>
        <div class="panel">
        <b>{{filename}}</b><br>
        <small>Total Mesh: {{meshes|length}}</small>

        <form method="post"
        action="/mesh-delete-all/{{uid}}"
        onsubmit="return confirm('PERINGATAN: Hapus SEMUA objek Mesh dari output bundle? File upload asli tidak ditimpa. Lanjutkan?')">
        <button class="danger" type="submit"
        style="width:100%;margin:12px 0;font-weight:bold">
        HAPUS SEMUA MESH
        </button>
        </form>

        <p><a class="btn" href="/">BACK TO DASHBOARD</a></p>
        </div>
        <div class="panel">
        <input id="search" placeholder="Search Mesh...">
        <div class="scroll">
        <table>
        <thead><tr>
        <th>NAME</th><th>PATH ID</th><th>CLASS ID</th><th>TOOLS</th>
        </tr></thead>
        <tbody id="meshlist">
        {% for m in meshes %}
        <tr>
        <td>{{m.name}}</td>
        <td>{{m.path}}</td>
        <td>{{m.classid}}</td>
        <td>
        <a href="/mesh-export/{{uid}}/{{m.path}}">OBJ</a>
        <a href="/mesh-edit/{{uid}}/{{m.path}}">EDIT</a>
        <form method="post"
        action="/mesh-delete/{{uid}}/{{m.path}}"
        onsubmit="return confirm('Hapus Mesh ini?')">
        <button class="danger">DELETE</button>
        </form>
        </td>
        </tr>
        {% endfor %}
        </tbody>
        </table>
        </div>
        </div>
        <script>
        document.getElementById('search').oninput=function(){
          let q=this.value.toLowerCase();
          document.querySelectorAll('#meshlist tr').forEach(r=>{
            r.style.display=r.innerText.toLowerCase().includes(q)?'':'none';
          });
        };
        </script>
        </body></html>
        """

        return render_template_string(
            page, meshes=meshes, uid=uid,
            filename=item["name"]
        )

    except Exception as e:
        return "Mesh scan error: " + str(e)[:300], 500



@app.route("/animationclip-manager/<uid>")
def animationclip_manager(uid):
    from html import escape

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))
        clips = []

        for obj in env.objects:
            if obj.type.name != "AnimationClip":
                continue

            try:
                name = obj.peek_name() or "(Tanpa nama)"
            except Exception:
                name = "(Tidak diketahui)"

            clips.append({
                "name": name,
                "path": obj.path_id
            })

        rows = []

        for index, clip in enumerate(clips, 1):
            pid = str(clip["path"])
            name = escape(str(clip["name"]))
            base = f"/asset-json-"

            rows.append(f"""
            <tr>
              <td>{index}</td>
              <td>{name}</td>
              <td>{escape(pid)}</td>
              <td>
                <div class="actions">
                  <a class="btn" href="{base}preview/{uid}/{pid}">PREVIEW TXT</a>
                  <a class="btn" href="{base}export/{uid}/{pid}">EXPORT TXT</a>
                  <a class="btn" href="{base}import/{uid}/{pid}">IMPORT TXT</a>
                  <form method="post"
                    action="/animationclip-delete/{uid}/{pid}"
                    onsubmit="return confirm('Hapus AnimationClip ini?')">
                    <button class="danger" type="submit">DELETE</button>
                  </form>
                </div>
              </td>
            </tr>
            """)

        table_rows = "".join(rows) or """
        <tr><td colspan="4">Tidak ada AnimationClip.</td></tr>
        """

        page = """
        <!DOCTYPE html>
        <html lang="id">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport"
                content="width=device-width,initial-scale=1">
          <title>AnimationClip Manager</title>
          <style>
            *{box-sizing:border-box}
            body{
              margin:0;padding:18px;
              background:#090a10;color:#eee;
              font-family:Arial,sans-serif
            }
            .panel{
              background:#151722;border:1px solid #34303d;
              border-radius:12px;padding:17px;margin-bottom:16px
            }
            h1,h2{color:#ff465d}
            .muted{color:#a4a6b5}
            .scroll{width:100%;overflow-x:hidden}
            table{width:100%;table-layout:fixed;
              border-collapse:collapse;font-size:13px}
            th,td{padding:10px 6px;text-align:left;
              border-bottom:1px solid #343442;overflow-wrap:anywhere;word-break:break-word}
            th:nth-child(1),td:nth-child(1){width:9%}
            th:nth-child(2),td:nth-child(2){width:29%}
            th:nth-child(3),td:nth-child(3){width:22%}
            th:nth-child(4),td:nth-child(4){width:40%}
            .actions{display:flex;flex-wrap:wrap;gap:4px;align-items:center}
            .actions .btn,.actions button{margin:2px;padding:8px 7px;font-size:10px}
            th{color:#ff667a}
            .btn,button{
              display:inline-block;padding:9px 11px;
              margin:3px;border:0;border-radius:6px;
              background:#c91f38;color:white;
              text-decoration:none;font-weight:bold;
              font-size:11px
            }
            .danger{background:#8d1726}
            .back{background:#343746}
            @media(max-width:600px){body{padding:10px}.panel{padding:12px}th,td{font-size:11px;padding:8px 4px}.actions{flex-direction:column;align-items:stretch}.actions .btn,.actions button{display:block;width:100%;text-align:center}.actions form{width:100%}}
          </style>
        </head>
        <body>
          <section class="panel">
            <h1>ANIMATIONCLIP MANAGER</h1>
            <p class="muted">Kelola AnimationClip dalam bundle.</p>
            <a class="btn back"
               href="/assets/UID_PLACEHOLDER/animationclip">
              BACK TO ASSETS
            </a>
          </section>

          <section class="panel">
            <h2>ACTION ANIMATIONCLIP</h2>
            <div class="scroll">
              <table>
                <thead>
                  <tr>
                    <th>#</th>
                    <th>ANIMATIONCLIP</th>
                    <th>PATH ID</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  ROWS_PLACEHOLDER
                </tbody>
              </table>
            </div>
          </section>

          <section class="panel">
            <h2>ADD ANIMATION</h2>
            <p class="muted">
              Panel pembuatan AnimationClip baru dan registrasi
              AnimatorController. Fitur ini akan diaktifkan
              setelah sistem pembuatan state dan referensi controller
              selesai divalidasi.
            </p>
            <button type="button" disabled
                    style="opacity:.5">
              ADD ANIMATION — COMING SOON
            </button>
          </section>
        </body>
        </html>
        """

        page = page.replace("UID_PLACEHOLDER", escape(uid))
        page = page.replace("ROWS_PLACEHOLDER", table_rows)
        return page

    except Exception as e:
        return "AnimationClip Manager gagal: " + str(e)[:400], 500


@app.route("/mesh-edit/<uid>/<path:path_id>", methods=["GET", "POST"])
def mesh_edit(uid, path_id):
    try:
        path_id = int(path_id)
    except (TypeError, ValueError):
        return "Path ID tidak valid", 400

    item = sessions.get(uid)

    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))
        obj = next(
            o for o in env.objects
            if o.type.name == "Mesh" and o.path_id == path_id
        )

        data = obj.parse_as_dict()
        old_name = data.get("m_Name", "")

        if request.method == "POST":
            new_name = request.form.get("name", "").strip()

            if not new_name or len(new_name) > 120:
                return "Nama tidak valid", 400

            data["m_Name"] = new_name
            obj.patch(data)

            output = save_edited_bundle(env, item, "_mesh_edit")
            flash("Mesh berhasil diedit. Output: " + output.name)

            return redirect(url_for("mesh_manager", uid=uid))

        page = """
        <html><head>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
        body{background:#090909;color:white;font-family:Arial;padding:20px}
        input{width:100%;padding:13px;background:#171717;
        color:white;border:1px solid #555}
        button{padding:12px;background:#d51f35;color:white;border:0}
        
/* MLBB PREMIUM LAYOUT V2 */
:root {
  --bg:#08090e;
  --panel:#12151f;
  --panel2:#191d29;
  --red:#ff3657;
  --line:#292e3b;
  --muted:#969bad;
}

* {
  box-sizing:border-box;
}

html {
  width:100%;
  min-width:0;
  scroll-behavior:smooth;
}

body {
  width:100%;
  min-width:0 !important;
  max-width:100%;
  overflow-x:hidden;
  background:
    radial-gradient(ellipse at 80% 0%,#35101c33,transparent 38%),
    var(--bg);
  color:#f4f5fa;
}

header {
  min-width:0;
  box-shadow:0 5px 25px #0005;
  backdrop-filter:blur(14px);
}

main {
  width:calc(100% - 250px);
  max-width:1600px;
  min-width:0;
  margin-left:250px;
  padding:28px;
  display:grid;
  grid-template-columns:repeat(12,minmax(0,1fr));
  gap:18px;
  align-items:start;
}

main > .panel {
  grid-column:span 12;
  width:100%;
  min-width:0;
}

#upload-panel,
#info-panel,
#explorer-panel,
#tools-panel {
  grid-column:span 12;
}

#summary-panel {
  grid-column:span 12;
}

.panel {
  min-width:0;
  overflow:hidden;
  padding:22px;
  border:1px solid var(--line);
  border-radius:15px;
  background:linear-gradient(145deg,#171a25,#10121a);
  box-shadow:0 12px 32px #0003;
  transition:border-color .2s ease,transform .2s ease;
}

.panel h2 {
  display:flex;
  align-items:center;
  gap:10px;
  font-size:14px;
  letter-spacing:1.2px;
  line-height:1.5;
}

.panel h2:before {
  content:"";
  width:4px;
  height:17px;
  flex-shrink:0;
  border-radius:5px;
  background:var(--red);
  box-shadow:0 0 12px #ff365766;
}

.stats {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}

.stat {
  min-width:0;
  padding:18px;
  border:1px solid #303545;
  border-radius:12px;
  background:linear-gradient(145deg,#202432,#171a24);
}

.stat b {
  font-size:26px;
  overflow-wrap:anywhere;
}

input:not([type=checkbox]),
select,
textarea {
  width:100%;
  max-width:100%;
  min-height:44px;
  padding:12px 14px;
  color:#f5f5f8;
  background:#0b0d14;
  border:1px solid #343a49;
  border-radius:9px;
  font:inherit;
}

input:focus,
select:focus,
textarea:focus {
  outline:none;
  border-color:var(--red);
  box-shadow:0 0 0 3px #ff36571c;
}

button,
.btn {
  min-height:42px;
  padding:11px 16px;
  border-radius:9px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.4px;
}

button:active,
.btn:active {
  transform:scale(.97);
}

a {
  overflow-wrap:anywhere;
}

.scroll {
  width:100%;
  max-width:100%;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  -webkit-overflow-scrolling:touch;
}

table {
  width:100%;
  min-width:650px;
  border-collapse:collapse;
}

th {
  background:#1b1e2a;
}

th,td {
  padding:13px 12px;
  vertical-align:middle;
}

tbody tr:nth-child(even) {
  background:#ffffff05;
}

.asset-controls {
  display:flex;
  align-items:center;
  flex-wrap:wrap;
  gap:10px;
}

.native-menu-button {
  min-height:44px;
  border-radius:9px;
}

.asset-count {
  margin-left:auto;
  font-weight:700;
}

.action-cell {
  min-width:200px;
}

.action-group {
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  gap:7px;
}

.action-group a,
.action-group button {
  min-height:36px;
  padding:8px 11px;
  border-radius:7px;
  font-size:10px;
}

.notice {
  border-radius:10px;
  padding:14px 16px;
}

.developer-card {
  border-radius:14px;
}

.developer-link {
  min-height:46px;
  border-radius:10px;
}

@media(min-width:1101px) {
  #info-panel {
    grid-column:span 5;
  }
  #summary-panel {
    grid-column:span 4;
  }
  #tools-panel {
    grid-column:span 3;
  }
}

@media(max-width:1100px) {
  main {
    width:100%;
    margin-left:0;
    padding:20px;
  }
}

@media(max-width:760px) {
  header {
    left:0;
    right:0;
    height:70px;
    padding:9px 12px;
    gap:8px;
  }

  header .logo {
    font-size:15px;
    letter-spacing:1px;
  }

  header .sub {
    display:none;
  }

  .menu-toggle {
    display:block;
    min-width:78px;
    min-height:40px;
    padding:9px 11px;
    font-size:11px;
  }

  .sidebar {
    top:70px;
    bottom:0;
    width:min(285px,85vw);
    padding:17px 13px 85px;
    overflow-y:auto;
    transform:translateX(-105%);
    transition:transform .25s ease;
    box-shadow:15px 0 40px #0009;
  }

  body.sidebar-open .sidebar {
    transform:translateX(0);
  }

  main {
    display:flex;
    flex-direction:column;
    width:100%;
    min-width:0;
    margin:70px 0 0;
    padding:13px;
    gap:13px;
  }

  main > .panel {
    width:100%;
    min-width:0;
  }

  .panel {
    padding:15px;
    border-radius:13px;
  }

  .panel h2 {
    font-size:13px;
    margin-bottom:15px;
  }

  .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:9px;
  }

  .stat {
    padding:13px;
  }

  .stat b {
    font-size:21px;
  }

  .asset-controls {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:8px;
  }

  .asset-controls .dropdown-wrap,
  .asset-controls .native-menu-button {
    width:100%;
  }

  .asset-count {
    grid-column:1/-1;
    margin:3px 0;
  }

  .native-dropdown {
    min-width:0;
    width:min(240px,calc(100vw - 45px));
  }

  .action-cell {
    min-width:180px;
  }

  .action-group {
    gap:6px;
  }

  .action-group a,
  .action-group button {
    min-height:38px;
    padding:9px;
  }

  #upload-panel form {
    width:100%;
  }

  #upload-panel button,
  #upload-panel input[type=file] {
    width:100%;
  }

  .developer-card {
    padding:16px 10px;
  }

  .side-status {
    position:static;
    margin-top:20px;
  }

  .scroll {
    max-height:65vh;
  }
}

@media(max-width:380px) {
  main {
    padding:10px;
  }

  .panel {
    padding:12px;
  }

  .stats {
    gap:7px;
  }

  .stat {
    padding:11px;
  }

  .stat b {
    font-size:19px;
  }
}

/* Shared mobile layout for standalone manager pages */
@media(max-width:760px) {
  body {
    padding:12px !important;
  }

  body > h2 {
    font-size:17px;
  }

  body > .panel {
    width:100%;
    padding:14px;
    margin-bottom:13px;
  }

  body > .panel .btn,
  body > .panel button {
    margin:4px 0;
  }

  body > header {
    padding:0 12px;
  }

  body > main {
    margin:0;
    padding:12px 0;
  }

  body > main .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}

@media(prefers-reduced-motion:reduce) {
  *,*::before,*::after {
    animation:none !important;
    transition:none !important;
    scroll-behavior:auto !important;
  }
}

</style></head><body>
        <h2 style="color:#ff465d">EDIT MESH</h2>
        <p>Path ID: {{path}}</p>
        <form method="post">
        <label>Mesh Name</label>
        <input name="name" value="{{name}}" required maxlength="120">
        <br><br><button>SAVE MESH</button>
        </form>
        <p><a href="/mesh-manager/{{uid}}" style="color:#ff6477">Back</a></p>
        </body></html>
        """
        return render_template_string(
            page, name=old_name, path=path_id, uid=uid
        )

    except Exception as e:
        return "Edit error: " + str(e)[:300], 500


@app.route("/mesh-delete/<uid>/<path:path_id>", methods=["POST"])
def mesh_delete(uid, path_id):
    try:
        path_id = int(path_id)
    except (TypeError, ValueError):
        return "Path ID tidak valid", 400

    item = sessions.get(uid)

    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))

        obj = next(
            o for o in env.objects
            if o.type.name == "Mesh" and o.path_id == path_id
        )

        # Hapus hanya objek Mesh yang dipilih.
        asset_file = obj.assets_file
        asset_file.objects.pop(path_id)

        output = save_edited_bundle(env, item, "_mesh_delete")
        flash("Mesh dihapus dari output: " + output.name)

        return redirect(url_for("mesh_manager", uid=uid))

    except Exception as e:
        return "Delete error: " + str(e)[:300], 500


@app.route("/mesh-delete-all/<uid>", methods=["POST"])
def mesh_delete_all(uid):
    item = sessions.get(uid)

    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))

        # Kumpulkan semua objek Mesh sebelum mengubah daftar objek.
        mesh_objects = [
            obj for obj in env.objects
            if obj.type.name == "Mesh"
        ]

        if not mesh_objects:
            flash("Tidak ada objek Mesh untuk dihapus.")
            return redirect(url_for("mesh_manager", uid=uid))

        removed = 0
        failed = 0

        # Hapus berdasarkan Path ID dari file Asset masing-masing.
        for obj in mesh_objects:
            try:
                asset_file = obj.assets_file
                objects_map = asset_file.objects
                path_id = obj.path_id

                if path_id in objects_map:
                    objects_map.pop(path_id)
                    removed += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

        if removed == 0:
            flash("Tidak ada Mesh yang berhasil dihapus.")
            return redirect(url_for("mesh_manager", uid=uid))

        # Simpan sebagai output baru, bukan menimpa file upload.
        output = save_edited_bundle(
            env, item, "_mesh_delete_all"
        )

        flash(
            f"Berhasil menghapus {removed} Mesh. "
            f"Gagal: {failed}. Output: {output.name}"
        )

        return redirect(url_for("mesh_manager", uid=uid))

    except Exception as e:
        return "Delete all Mesh error: " + str(e)[:300], 500


@app.route("/mesh-export/<uid>/<path:path_id>")
def mesh_export(uid, path_id):
    try:
        path_id = int(path_id)
    except (TypeError, ValueError):
        return "Path ID tidak valid", 400

    item = sessions.get(uid)

    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))

        obj = next(
            o for o in env.objects
            if o.type.name == "Mesh" and o.path_id == path_id
        )

        mesh = obj.parse_as_object()
        content = mesh.export()

        from io import BytesIO
        output = BytesIO(content.encode("utf-8"))

        return send_file(
            output,
            mimetype="text/plain",
            as_attachment=True,
            download_name=f"mesh_{path_id}.obj"
        )

    except Exception as e:
        return "Export error: " + str(e)[:300], 500



@app.route("/texture-manager/<uid>")
def texture_manager(uid):
    from PIL import Image

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))
        textures = []

        for obj in env.objects:
            if obj.type.name != "Texture2D":
                continue

            try:
                tex = obj.parse_as_object()
                name = tex.m_Name
                width = tex.m_Width
                height = tex.m_Height
            except Exception:
                name = "(Unknown)"
                width = height = 0

            textures.append({
                "name": name,
                "path": obj.path_id,
                "classid": int(obj.type),
                "width": width,
                "height": height
            })

        page = """
        <!DOCTYPE html>
        <html lang="id">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>Texture2D Manager</title>
        <style>
        *{box-sizing:border-box}
        body{background:#090909;color:#eee;font-family:Arial;padding:15px}
        .panel{background:#151515;border:1px solid #422027;
        border-radius:10px;padding:16px;margin-bottom:15px}
        h2{color:#ff465d}
        input{width:100%;padding:12px;background:#090909;
        color:white;border:1px solid #555;border-radius:6px;margin:8px 0}
        button,.btn{background:#c91f38;color:white;padding:11px;
        border:0;border-radius:6px;text-decoration:none;display:inline-block}
        table{border-collapse:collapse;width:100%;font-size:12px}
        td,th{padding:12px 7px;border-bottom:1px solid #333;text-align:left}
        th{color:#ff465d}
        .scroll{overflow-x:auto}
        .preview{max-width:100%;max-height:280px;object-fit:contain;
        background:#080808;border:1px solid #333;border-radius:8px}
        small{color:#aaa}
        
/* MLBB PREMIUM LAYOUT V2 */
:root {
  --bg:#08090e;
  --panel:#12151f;
  --panel2:#191d29;
  --red:#ff3657;
  --line:#292e3b;
  --muted:#969bad;
}

* {
  box-sizing:border-box;
}

html {
  width:100%;
  min-width:0;
  scroll-behavior:smooth;
}

body {
  width:100%;
  min-width:0 !important;
  max-width:100%;
  overflow-x:hidden;
  background:
    radial-gradient(ellipse at 80% 0%,#35101c33,transparent 38%),
    var(--bg);
  color:#f4f5fa;
}

header {
  min-width:0;
  box-shadow:0 5px 25px #0005;
  backdrop-filter:blur(14px);
}

main {
  width:calc(100% - 250px);
  max-width:1600px;
  min-width:0;
  margin-left:250px;
  padding:28px;
  display:grid;
  grid-template-columns:repeat(12,minmax(0,1fr));
  gap:18px;
  align-items:start;
}

main > .panel {
  grid-column:span 12;
  width:100%;
  min-width:0;
}

#upload-panel,
#info-panel,
#explorer-panel,
#tools-panel {
  grid-column:span 12;
}

#summary-panel {
  grid-column:span 12;
}

.panel {
  min-width:0;
  overflow:hidden;
  padding:22px;
  border:1px solid var(--line);
  border-radius:15px;
  background:linear-gradient(145deg,#171a25,#10121a);
  box-shadow:0 12px 32px #0003;
  transition:border-color .2s ease,transform .2s ease;
}

.panel h2 {
  display:flex;
  align-items:center;
  gap:10px;
  font-size:14px;
  letter-spacing:1.2px;
  line-height:1.5;
}

.panel h2:before {
  content:"";
  width:4px;
  height:17px;
  flex-shrink:0;
  border-radius:5px;
  background:var(--red);
  box-shadow:0 0 12px #ff365766;
}

.stats {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}

.stat {
  min-width:0;
  padding:18px;
  border:1px solid #303545;
  border-radius:12px;
  background:linear-gradient(145deg,#202432,#171a24);
}

.stat b {
  font-size:26px;
  overflow-wrap:anywhere;
}

input:not([type=checkbox]),
select,
textarea {
  width:100%;
  max-width:100%;
  min-height:44px;
  padding:12px 14px;
  color:#f5f5f8;
  background:#0b0d14;
  border:1px solid #343a49;
  border-radius:9px;
  font:inherit;
}

input:focus,
select:focus,
textarea:focus {
  outline:none;
  border-color:var(--red);
  box-shadow:0 0 0 3px #ff36571c;
}

button,
.btn {
  min-height:42px;
  padding:11px 16px;
  border-radius:9px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.4px;
}

button:active,
.btn:active {
  transform:scale(.97);
}

a {
  overflow-wrap:anywhere;
}

.scroll {
  width:100%;
  max-width:100%;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  -webkit-overflow-scrolling:touch;
}

table {
  width:100%;
  min-width:650px;
  border-collapse:collapse;
}

th {
  background:#1b1e2a;
}

th,td {
  padding:13px 12px;
  vertical-align:middle;
}

tbody tr:nth-child(even) {
  background:#ffffff05;
}

.asset-controls {
  display:flex;
  align-items:center;
  flex-wrap:wrap;
  gap:10px;
}

.native-menu-button {
  min-height:44px;
  border-radius:9px;
}

.asset-count {
  margin-left:auto;
  font-weight:700;
}

.action-cell {
  min-width:200px;
}

.action-group {
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  gap:7px;
}

.action-group a,
.action-group button {
  min-height:36px;
  padding:8px 11px;
  border-radius:7px;
  font-size:10px;
}

.notice {
  border-radius:10px;
  padding:14px 16px;
}

.developer-card {
  border-radius:14px;
}

.developer-link {
  min-height:46px;
  border-radius:10px;
}

@media(min-width:1101px) {
  #info-panel {
    grid-column:span 5;
  }
  #summary-panel {
    grid-column:span 4;
  }
  #tools-panel {
    grid-column:span 3;
  }
}

@media(max-width:1100px) {
  main {
    width:100%;
    margin-left:0;
    padding:20px;
  }
}

@media(max-width:760px) {
  header {
    left:0;
    right:0;
    height:70px;
    padding:9px 12px;
    gap:8px;
  }

  header .logo {
    font-size:15px;
    letter-spacing:1px;
  }

  header .sub {
    display:none;
  }

  .menu-toggle {
    display:block;
    min-width:78px;
    min-height:40px;
    padding:9px 11px;
    font-size:11px;
  }

  .sidebar {
    top:70px;
    bottom:0;
    width:min(285px,85vw);
    padding:17px 13px 85px;
    overflow-y:auto;
    transform:translateX(-105%);
    transition:transform .25s ease;
    box-shadow:15px 0 40px #0009;
  }

  body.sidebar-open .sidebar {
    transform:translateX(0);
  }

  main {
    display:flex;
    flex-direction:column;
    width:100%;
    min-width:0;
    margin:70px 0 0;
    padding:13px;
    gap:13px;
  }

  main > .panel {
    width:100%;
    min-width:0;
  }

  .panel {
    padding:15px;
    border-radius:13px;
  }

  .panel h2 {
    font-size:13px;
    margin-bottom:15px;
  }

  .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:9px;
  }

  .stat {
    padding:13px;
  }

  .stat b {
    font-size:21px;
  }

  .asset-controls {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:8px;
  }

  .asset-controls .dropdown-wrap,
  .asset-controls .native-menu-button {
    width:100%;
  }

  .asset-count {
    grid-column:1/-1;
    margin:3px 0;
  }

  .native-dropdown {
    min-width:0;
    width:min(240px,calc(100vw - 45px));
  }

  .action-cell {
    min-width:180px;
  }

  .action-group {
    gap:6px;
  }

  .action-group a,
  .action-group button {
    min-height:38px;
    padding:9px;
  }

  #upload-panel form {
    width:100%;
  }

  #upload-panel button,
  #upload-panel input[type=file] {
    width:100%;
  }

  .developer-card {
    padding:16px 10px;
  }

  .side-status {
    position:static;
    margin-top:20px;
  }

  .scroll {
    max-height:65vh;
  }
}

@media(max-width:380px) {
  main {
    padding:10px;
  }

  .panel {
    padding:12px;
  }

  .stats {
    gap:7px;
  }

  .stat {
    padding:11px;
  }

  .stat b {
    font-size:19px;
  }
}

/* Shared mobile layout for standalone manager pages */
@media(max-width:760px) {
  body {
    padding:12px !important;
  }

  body > h2 {
    font-size:17px;
  }

  body > .panel {
    width:100%;
    padding:14px;
    margin-bottom:13px;
  }

  body > .panel .btn,
  body > .panel button {
    margin:4px 0;
  }

  body > header {
    padding:0 12px;
  }

  body > main {
    margin:0;
    padding:12px 0;
  }

  body > main .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}

@media(prefers-reduced-motion:reduce) {
  *,*::before,*::after {
    animation:none !important;
    transition:none !important;
    scroll-behavior:auto !important;
  }
}

</style>
        </head>
        <body>
        <h2>TEXTURE2D MANAGER</h2>
        <div class="panel">
        <b>{{filename}}</b><br>
        <small>Total Texture2D: {{textures|length}}</small>
        <p><a class="btn" href="/">DASHBOARD</a></p>
        </div>

        <div class="panel">
        <h2>TEXTURE EXPLORER</h2>
        <input id="search" placeholder="Cari nama atau Path ID...">
        <div class="scroll">
        <table>
        <thead><tr>
        <th>NAME</th><th>PATH ID</th><th>SIZE</th><th>ACTION</th>
        </tr></thead>
        <tbody id="texture-list">
        {% for t in textures %}
        <tr>
        <td>{{t.name}}</td>
        <td>{{t.path}}</td>
        <td>{{t.width}} x {{t.height}}</td>
        <td>
        <a href="/texture-preview/{{uid}}/{{t.path}}">VIEW</a>
        </td>
        </tr>
        {% endfor %}
        </tbody>
        </table>
        </div>
        </div>

        <script>
        document.getElementById("search").oninput=function(){
          let q=this.value.toLowerCase();
          document.querySelectorAll("#texture-list tr").forEach(r=>{
            r.style.display=r.innerText.toLowerCase().includes(q)?"":"none";
          });
        };
        </script>
        </body></html>
        """

        return render_template_string(
            page, textures=textures,
            uid=uid, filename=item["name"]
        )

    except Exception as e:
        return "Texture scan error: " + str(e)[:300], 500


@app.route("/texture-preview/<uid>/<path:path_id>")
def texture_preview(uid, path_id):
    from io import BytesIO

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))
        obj = next(
            o for o in env.objects
            if o.type.name == "Texture2D"
            and o.path_id == int(path_id)
        )

        tex = obj.parse_as_object()
        image = tex.image

        output = BytesIO()
        image.save(output, format="PNG")
        output.seek(0)

        return send_file(
            output,
            mimetype="image/png",
            download_name=f"texture_{path_id}.png"
        )

    except Exception as e:
        return "Preview error: " + str(e)[:300], 500


@app.route("/texture-export/<uid>/<path:path_id>")
def texture_export(uid, path_id):
    from io import BytesIO

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))
        obj = next(
            o for o in env.objects
            if o.type.name == "Texture2D"
            and o.path_id == int(path_id)
        )

        tex = obj.parse_as_object()
        output = BytesIO()
        tex.image.save(output, format="PNG")
        output.seek(0)

        return send_file(
            output,
            mimetype="image/png",
            as_attachment=True,
            download_name=f"{tex.m_Name or path_id}.png"
        )

    except Exception as e:
        return "Export error: " + str(e)[:300], 500


@app.route("/texture-import/<uid>/<path:path_id>",
           methods=["GET", "POST"])
def texture_import(uid, path_id):
    from PIL import Image
    from io import BytesIO

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        env = UnityPy.load(str(item["path"]))

        obj = next(
            o for o in env.objects
            if o.type.name == "Texture2D"
            and o.path_id == int(path_id)
        )

        tex = obj.parse_as_object()

        if request.method == "POST":
            upload = request.files.get("texture")

            if not upload or not upload.filename:
                flash("Pilih gambar terlebih dahulu.")
                return redirect(request.url)

            if Path(upload.filename).suffix.lower() not in (
                ".png", ".jpg", ".jpeg", ".webp"
            ):
                return "Format gambar tidak didukung", 400

            raw = upload.read()

            if len(raw) > 30 * 1024 * 1024:
                return "Ukuran gambar maksimal 30 MB", 413

            try:
                replacement = Image.open(BytesIO(raw))
                replacement.load()
                replacement = replacement.convert("RGBA")
            except Exception:
                return "File gambar tidak valid", 400

            # Pertahankan ukuran tekstur asli agar tidak
            # mengubah dimensi secara tidak sengaja.
            if replacement.size != (tex.m_Width, tex.m_Height):
                return (
                    f"Ukuran gambar harus {tex.m_Width}x{tex.m_Height}",
                    400
                )

            # UnityPy mengubah PIL Image menjadi data Texture2D.
            tex.image = replacement
            tex.save()

            output = save_edited_bundle(
                env, item, "_texture_edit"
            )

            flash("Texture berhasil diganti: " + output.name)
            return redirect(url_for("texture_manager", uid=uid))

        page = """
        <!DOCTYPE html>
        <html lang="id">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
        body{background:#090909;color:white;font-family:Arial;padding:18px}
        .panel{background:#151515;padding:16px;border:1px solid #422027;
        border-radius:10px}
        h2{color:#ff465d}
        input{width:100%;padding:12px;background:#090909;
        color:white;border:1px solid #555}
        button,.btn{padding:12px;background:#c91f38;
        color:white;border:0;border-radius:6px}
        img{max-width:100%;max-height:300px;object-fit:contain;
        background:#080808}
        a{color:#ff6477}
        
/* MLBB PREMIUM LAYOUT V2 */
:root {
  --bg:#08090e;
  --panel:#12151f;
  --panel2:#191d29;
  --red:#ff3657;
  --line:#292e3b;
  --muted:#969bad;
}

* {
  box-sizing:border-box;
}

html {
  width:100%;
  min-width:0;
  scroll-behavior:smooth;
}

body {
  width:100%;
  min-width:0 !important;
  max-width:100%;
  overflow-x:hidden;
  background:
    radial-gradient(ellipse at 80% 0%,#35101c33,transparent 38%),
    var(--bg);
  color:#f4f5fa;
}

header {
  min-width:0;
  box-shadow:0 5px 25px #0005;
  backdrop-filter:blur(14px);
}

main {
  width:calc(100% - 250px);
  max-width:1600px;
  min-width:0;
  margin-left:250px;
  padding:28px;
  display:grid;
  grid-template-columns:repeat(12,minmax(0,1fr));
  gap:18px;
  align-items:start;
}

main > .panel {
  grid-column:span 12;
  width:100%;
  min-width:0;
}

#upload-panel,
#info-panel,
#explorer-panel,
#tools-panel {
  grid-column:span 12;
}

#summary-panel {
  grid-column:span 12;
}

.panel {
  min-width:0;
  overflow:hidden;
  padding:22px;
  border:1px solid var(--line);
  border-radius:15px;
  background:linear-gradient(145deg,#171a25,#10121a);
  box-shadow:0 12px 32px #0003;
  transition:border-color .2s ease,transform .2s ease;
}

.panel h2 {
  display:flex;
  align-items:center;
  gap:10px;
  font-size:14px;
  letter-spacing:1.2px;
  line-height:1.5;
}

.panel h2:before {
  content:"";
  width:4px;
  height:17px;
  flex-shrink:0;
  border-radius:5px;
  background:var(--red);
  box-shadow:0 0 12px #ff365766;
}

.stats {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}

.stat {
  min-width:0;
  padding:18px;
  border:1px solid #303545;
  border-radius:12px;
  background:linear-gradient(145deg,#202432,#171a24);
}

.stat b {
  font-size:26px;
  overflow-wrap:anywhere;
}

input:not([type=checkbox]),
select,
textarea {
  width:100%;
  max-width:100%;
  min-height:44px;
  padding:12px 14px;
  color:#f5f5f8;
  background:#0b0d14;
  border:1px solid #343a49;
  border-radius:9px;
  font:inherit;
}

input:focus,
select:focus,
textarea:focus {
  outline:none;
  border-color:var(--red);
  box-shadow:0 0 0 3px #ff36571c;
}

button,
.btn {
  min-height:42px;
  padding:11px 16px;
  border-radius:9px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.4px;
}

button:active,
.btn:active {
  transform:scale(.97);
}

a {
  overflow-wrap:anywhere;
}

.scroll {
  width:100%;
  max-width:100%;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  -webkit-overflow-scrolling:touch;
}

table {
  width:100%;
  min-width:650px;
  border-collapse:collapse;
}

th {
  background:#1b1e2a;
}

th,td {
  padding:13px 12px;
  vertical-align:middle;
}

tbody tr:nth-child(even) {
  background:#ffffff05;
}

.asset-controls {
  display:flex;
  align-items:center;
  flex-wrap:wrap;
  gap:10px;
}

.native-menu-button {
  min-height:44px;
  border-radius:9px;
}

.asset-count {
  margin-left:auto;
  font-weight:700;
}

.action-cell {
  min-width:200px;
}

.action-group {
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  gap:7px;
}

.action-group a,
.action-group button {
  min-height:36px;
  padding:8px 11px;
  border-radius:7px;
  font-size:10px;
}

.notice {
  border-radius:10px;
  padding:14px 16px;
}

.developer-card {
  border-radius:14px;
}

.developer-link {
  min-height:46px;
  border-radius:10px;
}

@media(min-width:1101px) {
  #info-panel {
    grid-column:span 5;
  }
  #summary-panel {
    grid-column:span 4;
  }
  #tools-panel {
    grid-column:span 3;
  }
}

@media(max-width:1100px) {
  main {
    width:100%;
    margin-left:0;
    padding:20px;
  }
}

@media(max-width:760px) {
  header {
    left:0;
    right:0;
    height:70px;
    padding:9px 12px;
    gap:8px;
  }

  header .logo {
    font-size:15px;
    letter-spacing:1px;
  }

  header .sub {
    display:none;
  }

  .menu-toggle {
    display:block;
    min-width:78px;
    min-height:40px;
    padding:9px 11px;
    font-size:11px;
  }

  .sidebar {
    top:70px;
    bottom:0;
    width:min(285px,85vw);
    padding:17px 13px 85px;
    overflow-y:auto;
    transform:translateX(-105%);
    transition:transform .25s ease;
    box-shadow:15px 0 40px #0009;
  }

  body.sidebar-open .sidebar {
    transform:translateX(0);
  }

  main {
    display:flex;
    flex-direction:column;
    width:100%;
    min-width:0;
    margin:70px 0 0;
    padding:13px;
    gap:13px;
  }

  main > .panel {
    width:100%;
    min-width:0;
  }

  .panel {
    padding:15px;
    border-radius:13px;
  }

  .panel h2 {
    font-size:13px;
    margin-bottom:15px;
  }

  .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:9px;
  }

  .stat {
    padding:13px;
  }

  .stat b {
    font-size:21px;
  }

  .asset-controls {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:8px;
  }

  .asset-controls .dropdown-wrap,
  .asset-controls .native-menu-button {
    width:100%;
  }

  .asset-count {
    grid-column:1/-1;
    margin:3px 0;
  }

  .native-dropdown {
    min-width:0;
    width:min(240px,calc(100vw - 45px));
  }

  .action-cell {
    min-width:180px;
  }

  .action-group {
    gap:6px;
  }

  .action-group a,
  .action-group button {
    min-height:38px;
    padding:9px;
  }

  #upload-panel form {
    width:100%;
  }

  #upload-panel button,
  #upload-panel input[type=file] {
    width:100%;
  }

  .developer-card {
    padding:16px 10px;
  }

  .side-status {
    position:static;
    margin-top:20px;
  }

  .scroll {
    max-height:65vh;
  }
}

@media(max-width:380px) {
  main {
    padding:10px;
  }

  .panel {
    padding:12px;
  }

  .stats {
    gap:7px;
  }

  .stat {
    padding:11px;
  }

  .stat b {
    font-size:19px;
  }
}

/* Shared mobile layout for standalone manager pages */
@media(max-width:760px) {
  body {
    padding:12px !important;
  }

  body > h2 {
    font-size:17px;
  }

  body > .panel {
    width:100%;
    padding:14px;
    margin-bottom:13px;
  }

  body > .panel .btn,
  body > .panel button {
    margin:4px 0;
  }

  body > header {
    padding:0 12px;
  }

  body > main {
    margin:0;
    padding:12px 0;
  }

  body > main .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}

@media(prefers-reduced-motion:reduce) {
  *,*::before,*::after {
    animation:none !important;
    transition:none !important;
    scroll-behavior:auto !important;
  }
}

</style>
        </head>
        <body>
        <div class="panel">
        <h2>TEXTURE IMPORTER</h2>
        <p>{{name}}</p>
        <p>Path ID: {{path}}</p>
        <p>Original size: {{width}} x {{height}}</p>
        <img src="/texture-preview/{{uid}}/{{path}}">
        <hr>
        <form method="post" enctype="multipart/form-data">
        <label>Import replacement image</label>
        <input type="file" name="texture"
        accept=".png,.jpg,.jpeg,.webp" required>
        <p>PNG, JPG, WEBP. Maksimal 30 MB.</p>
        <button type="submit">REPLACE TEXTURE</button>
        </form>
        <p><a href="/texture-export/{{uid}}/{{path}}">EXPORT PNG</a></p>
        <p><a href="/texture-manager/{{uid}}">BACK</a></p>
        </div>
        </body></html>
        """

        return render_template_string(
            page, name=tex.m_Name, path=path_id,
            width=tex.m_Width, height=tex.m_Height,
            uid=uid
        )

    except Exception as e:
        return "Texture import error: " + str(e)[:300], 500




@app.route("/animationclip-delete/<uid>/<path:path_id>", methods=["POST"])
def animationclip_delete(uid, path_id):
    import re

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan", 404

    try:
        target_id = int(path_id)
        env = UnityPy.load(str(item["path"]))

        clip = next(
            (o for o in env.objects
             if o.type.name == "AnimationClip"
             and int(o.path_id) == target_id),
            None
        )
        if clip is None:
            return "AnimationClip tidak ditemukan", 404

        # Pemeriksaan konservatif: jangan hapus jika objek lain
        # masih menyimpan Path ID target dalam data typetree.
        references = []
        for other in env.objects:
            if other.path_id == target_id:
                continue
            try:
                raw = repr(other.parse_as_dict())
            except Exception:
                continue

            if re.search(
                r"""['"]m_PathID['"]\s*:\s*""" + str(target_id) + r"\b",
                raw
            ):
                references.append(
                    f"{other.type.name} (Path ID {other.path_id})"
                )

        if references:
            return (
                "Penghapusan dibatalkan: AnimationClip masih mungkin "
                "direferensikan oleh objek lain. Referensi terdeteksi: "
                + ", ".join(references[:10])
                + ". Belum ada perubahan pada bundle.",
                409
            )

        clip.assets_file.objects.pop(target_id)
        output = save_edited_bundle(env, item, "_animationclip_delete")
        item["assets"], item["types"] = load_bundle(output)

        flash("AnimationClip berhasil dihapus: " + output.name)
        return redirect(url_for("asset_category",
                                uid=uid, category="animationclip"))

    except Exception as e:
        return "Delete AnimationClip gagal: " + str(e)[:400], 500


@app.route("/assets/<uid>/<category>")
def asset_category(uid, category):
    # AnimationClip category opens its dedicated manager directly.
    # This avoids leaving users on the generic asset-list page.
    if category == "animationclip":
        return redirect(url_for("animationclip_manager", uid=uid))

    item = sessions.get(uid)
    if not item:
        return "Bundle tidak ditemukan. Upload bundle terlebih dahulu.", 404

    categories = {
        "assetbundle": ("ASSETBUNDLE", None),
        "gameobject": ("GAMEOBJECT", {"GameObject"}),
        "texture2d": ("TEXTURE 2D", {"Texture2D"}),
        "mesh": ("MESH", {"Mesh"}),
        "animationclip": ("ANIMATIONCLIP", {"AnimationClip"}),
        "material": ("MATERIAL", {"Material"}),
        "sprite": ("SPRITE", {"Sprite"}),
        "audioclip": ("AUDIOCLIP", {"AudioClip"}),
        "monobehaviour": ("MONOBEHAVIOUR", {"MonoBehaviour"}),
    }

    if category == "other":
        known = {
            "GameObject", "Texture2D", "Mesh", "AnimationClip",
            "Material", "Sprite", "AudioClip", "MonoBehaviour"
        }
        title = "OTHER ASSETS"
        selected = [
            a for a in item["assets"]
            if a["type"] not in known
        ]
    elif category in categories:
        title, allowed = categories[category]
        selected = (
            item["assets"] if allowed is None
            else [a for a in item["assets"] if a["type"] in allowed]
        )
    else:
        return "Kategori tidak ditemukan", 404

    type_counts = {}
    for asset in selected:
        type_counts[asset["type"]] = type_counts.get(asset["type"], 0) + 1

    page = """
    <!DOCTYPE html>
    <html lang="id">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>HanZihan Uabe - {{title}}</title>
    <style>
    *{box-sizing:border-box}
    body{margin:0;background:#090a10;color:#eee;
      font-family:Arial,sans-serif;min-width:0}
    header{height:70px;background:#11131b;border-bottom:1px solid #34303b;
      display:flex;align-items:center;justify-content:space-between;
      padding:0 20px}
    .brand{font-size:17px;font-weight:900;color:#ff405b;letter-spacing:1px}
    main{max-width:1300px;margin:auto;padding:22px}
    .panel{background:#141620;border:1px solid #302c38;
      border-radius:10px;padding:18px;margin-bottom:15px}
    h2{font-size:15px;color:#ff405b;letter-spacing:1px}
    .muted{color:#9295a4;font-size:12px}
    .stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}
    .stat{background:#1c1e2a;padding:15px;border-radius:7px}
    .stat b{display:block;font-size:23px;color:#ff405b}
    .scroll{overflow:auto;max-height:65vh}
    table{border-collapse:collapse;width:100%;min-width:600px;font-size:12px}
    th,td{padding:13px 10px;text-align:left;border-bottom:1px solid #30303a}
    th{color:#ff526b;background:#1b1d28;position:sticky;top:0}
    tr:hover{background:#241720}
    input{width:100%;padding:13px;background:#090a10;color:white;
      border:1px solid #45404a;border-radius:6px;margin:10px 0}
    a{color:#ff7183}
    .btn{display:inline-block;padding:10px 14px;background:#c91f38;
      border-radius:6px;color:white;text-decoration:none;font-size:11px;
      font-weight:bold}
    .tag{color:#ff7183}
    @media(max-width:600px){
      main{padding:12px}
      .panel{padding:13px}
      .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
      header{padding:0 12px}
      .brand{font-size:14px}
    }
    
/* MLBB PREMIUM LAYOUT V2 */
:root {
  --bg:#08090e;
  --panel:#12151f;
  --panel2:#191d29;
  --red:#ff3657;
  --line:#292e3b;
  --muted:#969bad;
}

* {
  box-sizing:border-box;
}

html {
  width:100%;
  min-width:0;
  scroll-behavior:smooth;
}

body {
  width:100%;
  min-width:0 !important;
  max-width:100%;
  overflow-x:hidden;
  background:
    radial-gradient(ellipse at 80% 0%,#35101c33,transparent 38%),
    var(--bg);
  color:#f4f5fa;
}

header {
  min-width:0;
  box-shadow:0 5px 25px #0005;
  backdrop-filter:blur(14px);
}

main {
  width:calc(100% - 250px);
  max-width:1600px;
  min-width:0;
  margin-left:250px;
  padding:28px;
  display:grid;
  grid-template-columns:repeat(12,minmax(0,1fr));
  gap:18px;
  align-items:start;
}

main > .panel {
  grid-column:span 12;
  width:100%;
  min-width:0;
}

#upload-panel,
#info-panel,
#explorer-panel,
#tools-panel {
  grid-column:span 12;
}

#summary-panel {
  grid-column:span 12;
}

.panel {
  min-width:0;
  overflow:hidden;
  padding:22px;
  border:1px solid var(--line);
  border-radius:15px;
  background:linear-gradient(145deg,#171a25,#10121a);
  box-shadow:0 12px 32px #0003;
  transition:border-color .2s ease,transform .2s ease;
}

.panel h2 {
  display:flex;
  align-items:center;
  gap:10px;
  font-size:14px;
  letter-spacing:1.2px;
  line-height:1.5;
}

.panel h2:before {
  content:"";
  width:4px;
  height:17px;
  flex-shrink:0;
  border-radius:5px;
  background:var(--red);
  box-shadow:0 0 12px #ff365766;
}

.stats {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}

.stat {
  min-width:0;
  padding:18px;
  border:1px solid #303545;
  border-radius:12px;
  background:linear-gradient(145deg,#202432,#171a24);
}

.stat b {
  font-size:26px;
  overflow-wrap:anywhere;
}

input:not([type=checkbox]),
select,
textarea {
  width:100%;
  max-width:100%;
  min-height:44px;
  padding:12px 14px;
  color:#f5f5f8;
  background:#0b0d14;
  border:1px solid #343a49;
  border-radius:9px;
  font:inherit;
}

input:focus,
select:focus,
textarea:focus {
  outline:none;
  border-color:var(--red);
  box-shadow:0 0 0 3px #ff36571c;
}

button,
.btn {
  min-height:42px;
  padding:11px 16px;
  border-radius:9px;
  font-size:12px;
  font-weight:800;
  letter-spacing:.4px;
}

button:active,
.btn:active {
  transform:scale(.97);
}

a {
  overflow-wrap:anywhere;
}

.scroll {
  width:100%;
  max-width:100%;
  overflow:auto;
  border:1px solid var(--line);
  border-radius:10px;
  -webkit-overflow-scrolling:touch;
}

table {
  width:100%;
  min-width:650px;
  border-collapse:collapse;
}

th {
  background:#1b1e2a;
}

th,td {
  padding:13px 12px;
  vertical-align:middle;
}

tbody tr:nth-child(even) {
  background:#ffffff05;
}

.asset-controls {
  display:flex;
  align-items:center;
  flex-wrap:wrap;
  gap:10px;
}

.native-menu-button {
  min-height:44px;
  border-radius:9px;
}

.asset-count {
  margin-left:auto;
  font-weight:700;
}

.action-cell {
  min-width:200px;
}

.action-group {
  display:flex;
  flex-wrap:wrap;
  align-items:center;
  gap:7px;
}

.action-group a,
.action-group button {
  min-height:36px;
  padding:8px 11px;
  border-radius:7px;
  font-size:10px;
}

.notice {
  border-radius:10px;
  padding:14px 16px;
}

.developer-card {
  border-radius:14px;
}

.developer-link {
  min-height:46px;
  border-radius:10px;
}

@media(min-width:1101px) {
  #info-panel {
    grid-column:span 5;
  }
  #summary-panel {
    grid-column:span 4;
  }
  #tools-panel {
    grid-column:span 3;
  }
}

@media(max-width:1100px) {
  main {
    width:100%;
    margin-left:0;
    padding:20px;
  }
}

@media(max-width:760px) {
  header {
    left:0;
    right:0;
    height:70px;
    padding:9px 12px;
    gap:8px;
  }

  header .logo {
    font-size:15px;
    letter-spacing:1px;
  }

  header .sub {
    display:none;
  }

  .menu-toggle {
    display:block;
    min-width:78px;
    min-height:40px;
    padding:9px 11px;
    font-size:11px;
  }

  .sidebar {
    top:70px;
    bottom:0;
    width:min(285px,85vw);
    padding:17px 13px 85px;
    overflow-y:auto;
    transform:translateX(-105%);
    transition:transform .25s ease;
    box-shadow:15px 0 40px #0009;
  }

  body.sidebar-open .sidebar {
    transform:translateX(0);
  }

  main {
    display:flex;
    flex-direction:column;
    width:100%;
    min-width:0;
    margin:70px 0 0;
    padding:13px;
    gap:13px;
  }

  main > .panel {
    width:100%;
    min-width:0;
  }

  .panel {
    padding:15px;
    border-radius:13px;
  }

  .panel h2 {
    font-size:13px;
    margin-bottom:15px;
  }

  .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:9px;
  }

  .stat {
    padding:13px;
  }

  .stat b {
    font-size:21px;
  }

  .asset-controls {
    display:grid;
    grid-template-columns:repeat(2,minmax(0,1fr));
    gap:8px;
  }

  .asset-controls .dropdown-wrap,
  .asset-controls .native-menu-button {
    width:100%;
  }

  .asset-count {
    grid-column:1/-1;
    margin:3px 0;
  }

  .native-dropdown {
    min-width:0;
    width:min(240px,calc(100vw - 45px));
  }

  .action-cell {
    min-width:180px;
  }

  .action-group {
    gap:6px;
  }

  .action-group a,
  .action-group button {
    min-height:38px;
    padding:9px;
  }

  #upload-panel form {
    width:100%;
  }

  #upload-panel button,
  #upload-panel input[type=file] {
    width:100%;
  }

  .developer-card {
    padding:16px 10px;
  }

  .side-status {
    position:static;
    margin-top:20px;
  }

  .scroll {
    max-height:65vh;
  }
}

@media(max-width:380px) {
  main {
    padding:10px;
  }

  .panel {
    padding:12px;
  }

  .stats {
    gap:7px;
  }

  .stat {
    padding:11px;
  }

  .stat b {
    font-size:19px;
  }
}

/* Shared mobile layout for standalone manager pages */
@media(max-width:760px) {
  body {
    padding:12px !important;
  }

  body > h2 {
    font-size:17px;
  }

  body > .panel {
    width:100%;
    padding:14px;
    margin-bottom:13px;
  }

  body > .panel .btn,
  body > .panel button {
    margin:4px 0;
  }

  body > header {
    padding:0 12px;
  }

  body > main {
    margin:0;
    padding:12px 0;
  }

  body > main .stats {
    grid-template-columns:repeat(2,minmax(0,1fr));
  }
}

@media(prefers-reduced-motion:reduce) {
  *,*::before,*::after {
    animation:none !important;
    transition:none !important;
    scroll-behavior:auto !important;
  }
}

</style>
    </head>
    <body>
    <header>
      <div class="brand">HanZihan Uabe / {{title}}</div>
      <a class="btn" href="/">DASHBOARD</a>
    </header>
    <main>
      <section class="panel">
        <h2>{{title}}</h2>
        <div class="muted">Bundle: {{filename}}</div>
        <br>
        <div class="stats">
          <div class="stat"><b>{{total}}</b><small>Total Objects</small></div>
          <div class="stat"><b>{{type_total}}</b><small>Asset Types</small></div>
          <div class="stat"><b>UNITY</b><small>Asset Parser</small></div>
        </div>
      </section>

      {% if category == "assetbundle" %}
      <section class="panel">
        <h2>BUNDLE INFORMATION</h2>
        <p>Nama file: {{filename}}</p>
        <p>Total asset: {{all_total}}</p>
        <a class="btn" href="/download/{{uid}}">DOWNLOAD ORIGINAL</a>
        <a class="btn" href="/download-modified/{{uid}}">DOWNLOAD MODIFIED</a>
      </section>
      {% endif %}

      {% if category != "animationclip" %}
<section class="panel">
        <h2>ASSET LIST</h2>
        <input id="search" placeholder="Cari Type, Path ID, Class ID...">
        <div class="scroll">
        <table>
          <thead><tr>
            <th>#</th><th>TYPE</th><th>PATH ID</th><th>CLASS ID</th><th>ACTION</th>
          </tr></thead>
          <tbody id="asset-list">
          {% for a in assets %}
          <tr>
            <td>{{loop.index}}</td>
            <td class="tag">{{a.type}}</td>
            <td>{{a.path}}</td>
            <td>{{a.classid}}</td>
<td>
{% if category == "mesh" and a.type == "Mesh" %}
<form method="POST"
      action="/mesh-import/{{uid}}/{{a.path}}"
      enctype="multipart/form-data"
      style="min-width:180px">
  <input type="hidden" name="_csrf_token" value="{{csrf_token()}}">
  <input type="file" name="obj_file" accept=".obj" required>
  <button class="btn" type="submit">IMPORT OBJ</button>
</form>
{% else %}
<span class="muted">—</span>
{% endif %}
</td>
          </tr>
          {% else %}
          <tr><td colspan="4">Tidak ada asset dalam kategori ini.</td></tr>
          {% endfor %}
          </tbody>
        </table>
        </div>
      </section>
{% endif %}

      
      {% if category == "animationclip" %}
      <!-- ANIMATIONCLIP MANAGER BUTTON -->
      <section class="panel">
        <h2>ANIMATIONCLIP</h2>
        <p class="muted">
          Buka manager untuk mengelola seluruh AnimationClip.
        </p>
        <a class="btn"
           href="/animationclip-manager/{{uid}}">
          OPEN ANIMATIONCLIP MANAGER
        </a>
      </section>
      {% endif %}

{% if category == "mesh" %}
      <section class="panel">
        <h2>3D MODEL PREVIEW</h2>
        <p class="muted">Pilih OBJ pada form IMPORT OBJ untuk melihat model di sini.</p>

        <div id="obj-preview-box" style="
          width:100%;height:390px;position:relative;overflow:hidden;
          background:#080b12;border:1px solid #343b4d;border-radius:12px">
          <canvas id="obj-preview-canvas" style="width:100%;height:100%;display:block"></canvas>
          <div id="obj-preview-status" style="
            position:absolute;left:12px;top:12px;color:#ff6464;
            background:#080b12dd;padding:7px 10px;border-radius:7px;
            font-size:12px">BELUM ADA MODEL</div>
        </div>

        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px">
          <button type="button" class="btn" id="obj-reset-camera">RESET CAMERA</button>
          <button type="button" class="btn" id="obj-wireframe">WIREFRAME: OFF</button>
          <button type="button" class="btn" id="obj-auto-rotate">AUTO ROTATE: OFF</button>
        </div>
        <p class="muted" id="obj-preview-info" style="margin-top:10px">
          Pilih file OBJ untuk memulai preview.
        </p>
      </section>

      <section class="panel">
        <h2>MESH TOOLS</h2>
        <p class="muted">Pilih file OBJ pada baris Mesh di tabel Asset List untuk mengimpor model.</p>
      </section>
      {% elif category == "texture2d" %}
      <section class="panel">
        <h2>TEXTURE TOOLS</h2>
        <a class="btn" href="/texture-manager/{{uid}}">OPEN TEXTURE MANAGER</a>
      </section>
      {% endif %}
    </main>
    <script>
    document.getElementById("search").addEventListener("input",function(){
      const q=this.value.toLowerCase();
      document.querySelectorAll("#asset-list tr").forEach(row=>{
        row.style.display=row.innerText.toLowerCase().includes(q)?"":"none";
      });
    });

    </script>

    {% if category == "mesh" %}
    <script type="module">
    import * as THREE from "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.module.js";
    import { OrbitControls } from "https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/controls/OrbitControls.js";
    import { OBJLoader } from "https://cdn.jsdelivr.net/npm/three@0.160.0/examples/jsm/loaders/OBJLoader.js";

    const box = document.getElementById("obj-preview-box");
    const canvas = document.getElementById("obj-preview-canvas");
    const status = document.getElementById("obj-preview-status");
    const info = document.getElementById("obj-preview-info");

    if (box && canvas) {
      const scene = new THREE.Scene();
      scene.background = new THREE.Color(0x080b12);

      const camera = new THREE.PerspectiveCamera(45, 1, 0.01, 100000);
      camera.position.set(4, 3, 5);

      const renderer = new THREE.WebGLRenderer({
        canvas,
        antialias: true,
        alpha: false
      });
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      renderer.outputColorSpace = THREE.SRGBColorSpace;

      scene.add(new THREE.HemisphereLight(0xffffff, 0x333344, 2));

      const light = new THREE.DirectionalLight(0xffffff, 2.5);
      light.position.set(5, 8, 6);
      scene.add(light);

      const controls = new OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.07;

      const grid = new THREE.GridHelper(10, 20, 0x555566, 0x292d38);
      scene.add(grid);

      let currentModel = null;
      let wireframe = false;
      let autoRotate = false;

      function resize() {
        const w = box.clientWidth;
        const h = box.clientHeight;
        if (!w || !h) return;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h, false);
      }

      new ResizeObserver(resize).observe(box);
      resize();

      function frameModel(model) {
        const bounds = new THREE.Box3().setFromObject(model);
        const size = bounds.getSize(new THREE.Vector3());
        const center = bounds.getCenter(new THREE.Vector3());
        const maxSize = Math.max(size.x, size.y, size.z);

        if (!Number.isFinite(maxSize) || maxSize <= 0) {
          throw new Error("Ukuran model tidak valid.");
        }

        model.position.sub(center);

        const distance = maxSize * 1.8;
        camera.position.set(distance, distance * 0.7, distance);
        camera.near = Math.max(maxSize / 10000, 0.001);
        camera.far = maxSize * 100;
        camera.updateProjectionMatrix();

        controls.target.set(0, 0, 0);
        controls.minDistance = maxSize * 0.05;
        controls.maxDistance = maxSize * 20;
        controls.update();

        grid.position.y = -size.y / 2;
        grid.scale.setScalar(Math.max(maxSize / 10, 0.01));
      }

      function loadOBJ(file) {
        if (!file) return;

        if (!file.name.toLowerCase().endsWith(".obj")) {
          status.textContent = "FILE HARUS OBJ";
          return;
        }

        status.textContent = "MEMUAT MODEL...";
        info.textContent = file.name;

        const reader = new FileReader();

        reader.onerror = () => {
          status.textContent = "GAGAL MEMBACA FILE";
        };

        reader.onload = () => {
          try {
            const loader = new OBJLoader();
            const model = loader.parse(reader.result);

            let meshes = 0;
            let vertices = 0;

            model.traverse(obj => {
              if (!obj.isMesh) return;

              meshes++;
              vertices += obj.geometry.attributes.position?.count || 0;

              obj.material = new THREE.MeshStandardMaterial({
                color: 0xb8becb,
                metalness: 0.15,
                roughness: 0.7,
                side: THREE.DoubleSide,
                wireframe
              });

              if (!obj.geometry.attributes.normal) {
                obj.geometry.computeVertexNormals();
              }
            });

            if (!meshes) throw new Error("OBJ tidak memiliki geometry.");

            if (currentModel) {
              scene.remove(currentModel);
              currentModel.traverse(obj => {
                if (obj.isMesh) obj.geometry.dispose();
              });
            }

            currentModel = model;
            scene.add(model);
            frameModel(model);

            status.textContent = "MODEL BERHASIL DIMUAT";
            info.textContent =
              file.name + " | " + meshes + " mesh | " +
              vertices.toLocaleString() + " vertex";
          } catch (error) {
            console.error(error);
            status.textContent = "GAGAL MEMUAT OBJ";
            info.textContent = error.message;
          }
        };

        reader.readAsText(file);
      }

      document.querySelectorAll('input[name="obj_file"]').forEach(input => {
        input.addEventListener("change", () => loadOBJ(input.files[0]));
      });

      document.getElementById("obj-reset-camera").onclick = () => {
        if (currentModel) frameModel(currentModel);
      };

      document.getElementById("obj-wireframe").onclick = event => {
        wireframe = !wireframe;
        currentModel?.traverse(obj => {
          if (obj.isMesh) obj.material.wireframe = wireframe;
        });
        event.target.textContent = "WIREFRAME: " + (wireframe ? "ON" : "OFF");
      };

      document.getElementById("obj-auto-rotate").onclick = event => {
        autoRotate = !autoRotate;
        event.target.textContent = "AUTO ROTATE: " + (autoRotate ? "ON" : "OFF");
      };

      renderer.setAnimationLoop(() => {
        if (autoRotate && currentModel) currentModel.rotation.y += 0.006;
        controls.update();
        renderer.render(scene, camera);
      });
    }
    </script>
    {% endif %}
    </body>
    </html>
    """

    return render_template_string(
        page,
        uid=uid,
        category=category,
        title=title,
        filename=item["name"],
        assets=selected,
        total=len(selected),
        type_total=len(type_counts),
        all_total=len(item["assets"])
    )

def error_page(code, title, message):
    return render_template_string("""
    <!doctype html><html lang="id"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{{code}} - HanZihan Uabe</title><style>""" + AUTH_STYLE + """</style></head>
    <body><section class="auth-card"><div class="japan-mark">!</div>
    <div class="brand">HanZihan Uabe</div><div class="sub">ERROR {{code}}</div>
    <h1>{{title}}</h1><p>{{message}}</p>
    <a href="/dashboard"><button type="button">KEMBALI KE WORKSPACE</button></a>
    </section></body></html>
    """, code=code, title=title, message=message), code

_ERROR_TEXT = {
    400: ("Permintaan tidak valid", "Sesi formulir sudah kedaluwarsa. Muat ulang halaman lalu coba lagi."),
    403: ("Akses ditolak", "Permintaan ini ditolak. Muat ulang halaman dan coba lagi."),
    404: ("Halaman tidak ditemukan", "Halaman atau file yang kamu cari tidak ada. Kalau server baru di-restart, upload ulang bundle-nya."),
    413: ("File terlalu besar", "Ukuran file melebihi batas 300 MB."),
    500: ("Terjadi kesalahan di server", "Ada error saat memproses permintaan. Coba lagi, atau upload ulang file-nya."),
}
for _code, (_title, _msg) in _ERROR_TEXT.items():
    app.register_error_handler(
        _code, lambda e, _c=_code, _t=_title, _m=_msg: error_page(_c, _t, _m))

if __name__ == "__main__":
    print("HanZihan Uabe STARTED")
    print("Open http://127.0.0.1:4444")
    app.run(host="127.0.0.1", port=4444, debug=False)
