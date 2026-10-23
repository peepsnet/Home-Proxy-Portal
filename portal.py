#!/usr/bin/env python3
"""
Home Portal - a password-protected gateway to the web servers on your LAN.

Open ONE port on your router -> log in -> pick a server -> it is proxied
through that single port (HTTP, streaming, uploads, WebSockets).

    pip install aiohttp
    python3 portal.py --set-password     # once
    python3 portal.py                    # run

Only servers listed in config.json can be reached (this is NOT an open proxy).
config.json is re-read automatically when you edit it.
"""
import asyncio
import base64
import getpass
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlsplit

import aiohttp
from aiohttp import web, WSMsgType
from yarl import URL

CONFIG_PATH = Path(os.environ.get("PORTAL_CONFIG") or Path(__file__).with_name("config.json"))
SESSION_COOKIE = "portal_session"
TARGET_COOKIE = "portal_target"
MAX_FAILS, FAIL_WINDOW = 5, 15 * 60

DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8443,
    "password_hash": "",
    "session_hours": 12,
    "tls_cert": "",
    "tls_key": "",
    "behind_https_proxy": False,
    "inject_back_button": True,
    "targets": [
        {"id": "server1", "name": "Server 1", "url": "http://192.168.1.100:8080"},
        {"id": "server2", "name": "Server 2", "url": "http://192.168.1.100:8888"},
    ],
}

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "trailers", "transfer-encoding", "upgrade"}
ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# ----------------------------------------------------------------- config
_cache = {"mtime": None, "data": None}


def save_config(cfg):
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")
    try:
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def load_config():
    if not CONFIG_PATH.exists():
        save_config(DEFAULT_CONFIG)
        print(f"Created sample config at {CONFIG_PATH}")
    mtime = CONFIG_PATH.stat().st_mtime
    if mtime != _cache["mtime"]:
        try:
            data = {**DEFAULT_CONFIG, **json.loads(CONFIG_PATH.read_text())}
            data["targets"] = [t for t in data["targets"]
                               if ID_RE.match(str(t.get("id", ""))) and t.get("url", "").startswith(("http://", "https://"))]
            _cache.update(mtime=mtime, data=data)
        except Exception as e:  # keep the last good config on a typo
            print(f"!! config.json error, keeping previous config: {e}")
            if _cache["data"] is None:
                raise
            _cache["mtime"] = mtime
    return _cache["data"]


def find_target(cfg, tid):
    return next((t for t in cfg["targets"] if t["id"] == tid), None)


# --------------------------------------------------------------- passwords
def hash_pw(pw, salt=None):
    salt = salt or os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def check_pw(pw, stored):
    try:
        _, s, h = stored.split("$")
        expected = base64.b64decode(h)
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(s), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(got, expected)
    except Exception:
        return False


# ---------------------------------------------------------------- sessions
SESSIONS = {}   # token -> expiry
FAILS = {}      # ip -> [timestamps]


def is_authed(request):
    tok = request.cookies.get(SESSION_COOKIE)
    exp = SESSIONS.get(tok)
    if exp and exp > time.time():
        return True
    SESSIONS.pop(tok, None)
    return False


def locked_out(ip):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW]
    return len(FAILS[ip]) >= MAX_FAILS


def cookie_secure(request, cfg):
    return request.secure or bool(cfg.get("behind_https_proxy"))


# ------------------------------------------------------------------- pages
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%%TITLE%%</title>
<style>
:root{color-scheme:light dark;--bg:#f5f5f7;--card:#fff;--fg:#1d1d1f;--mut:#6e6e73;--acc:#2563eb;--bd:#d9d9de}
@media (prefers-color-scheme:dark){:root{--bg:#111214;--card:#1c1d20;--fg:#f2f2f4;--mut:#9a9aa3;--acc:#6ea0ff;--bd:#2d2f34}}
*{box-sizing:border-box}body{margin:0;font:16px/1.4 system-ui,sans-serif;background:var(--bg);color:var(--fg);
padding:max(20px,env(safe-area-inset-top)) 20px 40px}
main{max-width:720px;margin:0 auto}h1{font-size:1.5rem;margin:.5em 0 1em}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fill,minmax(220px,1fr))}
a.card{display:block;padding:16px;background:var(--card);border:1px solid var(--bd);border-radius:12px;
text-decoration:none;color:var(--fg)}a.card:hover{border-color:var(--acc)}
a.card small{display:block;color:var(--mut);margin-top:4px;word-break:break-all}
form{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:20px;max-width:360px;margin:12vh auto 0}
input[type=password]{width:100%;padding:12px;font-size:1rem;border-radius:8px;border:1px solid var(--bd);
background:var(--bg);color:var(--fg)}
button{margin-top:12px;width:100%;padding:12px;font-size:1rem;border:0;border-radius:8px;background:var(--acc);color:#fff}
.err{color:#d33;margin:8px 0}.top{display:flex;justify-content:space-between;align-items:center}
.top a{color:var(--mut);font-size:.9rem}
</style></head><body>%%BODY%%</body></html>"""


def page(title, body, status=200):
    out = PAGE.replace("%%TITLE%%", html.escape(title)).replace("%%BODY%%", body)
    return web.Response(text=out, status=status, content_type="text/html",
                        headers={"Cache-Control": "no-store"})


def landing(cfg):
    cards = "".join(
        f'<a class="card" href="/t/{html.escape(t["id"])}/"><strong>{html.escape(t.get("name", t["id"]))}</strong>'
        f'<small>{html.escape(t["url"])}</small></a>'
        for t in cfg["targets"]
    ) or "<p>No servers configured. Edit config.json.</p>"
    return page("Home Portal",
                f'<main><div class="top"><h1>Home Portal</h1><a href="/_portal/logout">Sign out</a></div>'
                f'<div class="grid">{cards}</div></main>')


def safe_next(n):
    if not n or not n.startswith("/") or n.startswith("//") or "\\" in n or n.startswith("/_portal"):
        return "/"
    return n


async def login(request, cfg):
    ip = request.remote or "?"
    nxt, error, status = safe_next(request.query.get("next", "/")), "", 200
    if request.method == "POST":
        data = await request.post()
        nxt = safe_next(data.get("next", "/"))
        if locked_out(ip):
            error, status = "Too many attempts. Try again in 15 minutes.", 429
        elif check_pw(str(data.get("password", "")), cfg["password_hash"]):
            FAILS.pop(ip, None)
            now = time.time()
            for k in [k for k, v in SESSIONS.items() if v < now]:
                del SESSIONS[k]
            tok = secrets.token_urlsafe(32)
            SESSIONS[tok] = now + cfg["session_hours"] * 3600
            resp = web.Response(status=302, headers={"Location": nxt})
            resp.set_cookie(SESSION_COOKIE, tok, httponly=True, samesite="Lax", path="/",
                            secure=cookie_secure(request, cfg), max_age=int(cfg["session_hours"] * 3600))
            return resp
        else:
            FAILS.setdefault(ip, []).append(time.time())
            await asyncio.sleep(1)
            error, status = "Incorrect password.", 401
    err = f'<div class="err">{html.escape(error)}</div>' if error else ""
    return page("Sign in", f'<form method="post"><h1>Home Portal</h1>{err}'
                           f'<input type="hidden" name="next" value="{html.escape(nxt)}">'
                           f'<input type="password" name="password" placeholder="Password" autofocus required>'
                           f'<button type="submit">Sign in</button></form>', status)


# ------------------------------------------------------------------- proxy
BACK_BUTTON = (
    b'<a href="/" id="__portal_back" title="Back to Home Portal" style="all:initial;position:fixed;'
    b'left:12px;bottom:calc(12px + env(safe-area-inset-bottom,0px));z-index:2147483647;padding:8px 12px;'
    b'font:600 13px system-ui,sans-serif;color:#fff;background:rgba(30,30,35,.78);border-radius:999px;'
    b'text-decoration:none;cursor:pointer;opacity:.55" '
    b'onmouseover="this.style.opacity=1" onmouseout="this.style.opacity=.55">&#9664; Portal</a>'
)


def inject_button(body):
    low = body.lower()
    if b"<html" not in low and b"<body" not in low:
        return body  # an HTML fragment, leave it alone
    i = low.rfind(b"</body>")
    return body[:i] + BACK_BUTTON + body[i:] if i != -1 else body + BACK_BUTTON


def upstream_headers(request, base, prefix, ws=False):
    origin = str(URL(base).origin())
    h = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP or lk in ("host", "cookie", "origin", "referer"):
            continue
        if ws and lk.startswith("sec-websocket-"):
            continue
        h[k] = v
    cookies = "; ".join(f"{k}={v}" for k, v in request.cookies.items()
                        if k not in (SESSION_COOKIE, TARGET_COOKIE))
    if cookies:
        h["Cookie"] = cookies
    if "Origin" in request.headers:
        h["Origin"] = origin
    ref = request.headers.get("Referer")
    if ref:
        p = urlsplit(ref)
        path = p.path
        if path.startswith(prefix):
            path = path[len(prefix):] or "/"
        h["Referer"] = origin + path + ("?" + p.query if p.query else "")
    h["X-Forwarded-For"] = request.remote or ""
    h["X-Forwarded-Proto"] = request.scheme
    return h


def rewrite_location(loc, base, prefix):
    origin = str(URL(base).origin())
    if loc.startswith(origin):
        loc = loc[len(origin):] or "/"
    if loc.startswith("/") and not loc.startswith("//"):
        return prefix + loc
    return loc


async def proxy_ws(request, url, hdrs):
    session = request.app["session"]
    protos = [p.strip() for p in request.headers.get("Sec-WebSocket-Protocol", "").split(",") if p.strip()]
    ws_url = "ws" + url[4:]  # http->ws, https->wss
    try:
        up = await session.ws_connect(URL(ws_url, encoded=True), headers=hdrs,
                                      protocols=protos, max_msg_size=0)
    except Exception as e:
        return web.Response(status=502, text=f"WebSocket upstream failed: {e}")
    ws = web.WebSocketResponse(protocols=[up.protocol] if up.protocol else (), max_msg_size=0)
    await ws.prepare(request)

    async def pipe(src, dst):
        try:
            async for msg in src:
                if msg.type == WSMsgType.TEXT:
                    await dst.send_str(msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await dst.send_bytes(msg.data)
                else:
                    break
        except (ConnectionError, RuntimeError):
            pass

    tasks = [asyncio.create_task(pipe(ws, up)), asyncio.create_task(pipe(up, ws))]
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await up.close()
    await ws.close()
    return ws


async def proxy(request, target, tail, set_target=False):
    base = target["url"].rstrip("/")
    prefix = f"/t/{target['id']}"
    if ".." in tail.split("/"):
        return web.Response(status=400, text="Bad path")
    qs = request.rel_url.raw_query_string
    url = base + tail + ("?" + qs if qs else "")

    if request.headers.get("Upgrade", "").lower() == "websocket":
        return await proxy_ws(request, url, upstream_headers(request, base, prefix, ws=True))

    cfg = load_config()
    hdrs = upstream_headers(request, base, prefix)
    data = request.content if request.body_exists else None
    # Only top-level page loads (not iframes/XHR/assets) get the "back" button.
    want_inject = (cfg.get("inject_back_button", True) and request.method == "GET"
                   and request.headers.get("Sec-Fetch-Dest", "document") == "document"
                   and "text/html" in request.headers.get("Accept", ""))
    if want_inject:
        hdrs["Accept-Encoding"] = "identity"  # so the HTML can be edited
    resp = None
    try:
        async with request.app["session"].request(
                request.method, URL(url, encoded=True), headers=hdrs, data=data,
                allow_redirects=False) as up:
            buffered = (want_inject and up.status == 200
                        and up.headers.get("Content-Type", "").lower().startswith("text/html")
                        and "Content-Encoding" not in up.headers)
            if buffered:
                resp = web.Response(status=up.status, body=inject_button(await up.read()))
            else:
                resp = web.StreamResponse(status=up.status, reason=up.reason)
            for k, v in up.headers.items():
                lk = k.lower()
                if lk in HOP_BY_HOP or (buffered and lk == "content-length"):
                    continue
                if lk == "location":
                    v = rewrite_location(v, base, prefix)
                elif lk == "set-cookie":
                    v = re.sub(r";\s*domain=[^;]*", "", v, flags=re.I)
                if buffered and lk != "set-cookie":
                    resp.headers[k] = v
                else:
                    resp.headers.add(k, v)
            if set_target:
                resp.set_cookie(TARGET_COOKIE, target["id"], httponly=True, samesite="Lax", path="/",
                                secure=request.secure or bool(cfg.get("behind_https_proxy")),
                                max_age=30 * 86400)
            if buffered:
                return resp
            await resp.prepare(request)
            if request.method != "HEAD":
                async for chunk in up.content.iter_any():
                    await resp.write(chunk)
            await resp.write_eof()
            return resp
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
        if resp is not None and resp.prepared:
            return resp
        return page("Can't reach server",
                    f'<main><h1>Can\'t reach {html.escape(target.get("name", target["id"]))}</h1>'
                    f'<p>{html.escape(target["url"])}</p><p>{html.escape(str(e))}</p>'
                    f'<p><a href="/">Back to portal</a></p></main>', 502)


# ----------------------------------------------------------------- routing
async def handle(request):
    cfg = load_config()
    path = request.rel_url.raw_path

    if path == "/_portal/login":
        return await login(request, cfg)
    if path == "/_portal/logout":
        SESSIONS.pop(request.cookies.get(SESSION_COOKIE), None)
        resp = web.Response(status=302, headers={"Location": "/_portal/login"})
        resp.del_cookie(SESSION_COOKIE, path="/")
        resp.del_cookie(TARGET_COOKIE, path="/")
        return resp
    if path.startswith("/_portal/"):
        return web.Response(status=404, text="Not found")

    if not is_authed(request):
        if request.method in ("GET", "HEAD") and "text/html" in request.headers.get("Accept", ""):
            nxt = quote(path + ("?" + request.rel_url.raw_query_string if request.rel_url.raw_query_string else ""))
            return web.Response(status=302, headers={"Location": f"/_portal/login?next={nxt}"})
        return web.Response(status=401, text="Not signed in")

    if path == "/":
        return landing(cfg)

    m = re.match(r"^/t/([A-Za-z0-9_-]+)(/.*)?$", path)
    if m:
        target = find_target(cfg, m.group(1))
        if not target:
            return web.Response(status=404, text="Unknown server")
        if m.group(2) is None:
            qs = request.rel_url.raw_query_string
            return web.Response(status=302, headers={"Location": f"/t/{target['id']}/" + (f"?{qs}" if qs else "")})
        return await proxy(request, target, m.group(2), set_target=True)

    # Fallback: apps that use absolute paths (/static/app.js, /api/...) go to
    # whichever server you opened last.
    target = find_target(cfg, request.cookies.get(TARGET_COOKIE, ""))
    if not target:
        return web.Response(status=404, text="Not found. Open a server from the portal first.")
    return await proxy(request, target, path)


async def on_startup(app):
    app["session"] = aiohttp.ClientSession(
        auto_decompress=False,                      # pass bytes through untouched
        cookie_jar=aiohttp.DummyCookieJar(),        # cookies belong to the browser
        connector=aiohttp.TCPConnector(ssl=False, limit=0),  # allow self-signed HTTPS on the LAN
        timeout=aiohttp.ClientTimeout(total=None, sock_connect=10),
    )


async def on_cleanup(app):
    await app["session"].close()


def set_password():
    load_config()
    cfg = json.loads(CONFIG_PATH.read_text())
    pw = getpass.getpass("New password (min 12 chars): ")
    if len(pw) < 12:
        sys.exit("Too short. Use a long passphrase.")
    if pw != getpass.getpass("Repeat: "):
        sys.exit("Passwords don't match.")
    cfg["password_hash"] = hash_pw(pw)
    save_config(cfg)
    print("Password saved.")


def main():
    if "--set-password" in sys.argv:
        return set_password()
    cfg = load_config()
    if not cfg.get("password_hash"):
        sys.exit("No password set. Run:  python3 portal.py --set-password")
    ctx = None
    if cfg.get("tls_cert") and cfg.get("tls_key"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cfg["tls_cert"], cfg["tls_key"])
    else:
        print("WARNING: no TLS configured - passwords travel in clear text. "
              "Fine on your LAN, NOT OK across the internet.")
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handle)
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    web.run_app(app, host=cfg["listen_host"], port=cfg["listen_port"], ssl_context=ctx, access_log=None)


if __name__ == "__main__":
    main()
