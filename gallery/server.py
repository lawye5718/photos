#!/usr/bin/env python3
"""
Gallery Studio —— 轻量元数据服务 / 私密门禁
=================================================
一个文件搞定：门禁鉴权 + 媒体元数据 + 分类/精选 + Lsky Pro 同步 + 私密文件流。

设计要点
--------
* 两级口令（都用 PBKDF2 加盐哈希存储，明文不落盘）
    - 长期口令 scope=full    : 进站 + 私密分类 + 管理接口
    - 限时口令 scope=visitor : 进站 + 公开分类（私密分类返回 403），到期自动失效
* 全站门禁：所有 /api/media 都必须带 token，「没有密码进不来」
* 存储解耦：大文件仍由 Lsky Pro / 群晖直链提供；本服务只存元数据（几 MB 级）
* 私密分类不走 Lsky 直链，改为 /api/file/{id} 带权限校验流式输出，避免链接被猜中

CLI
---
    python server.py serve                     # 启动服务（默认）
    python server.py setperm <密码>            # 设置/更换长期口令
    python server.py settemp <密码> --days 7   # 设置限时口令（N 天后失效）
    python server.py rotate --days 7           # 随机生成一个限时口令并打印
    python server.py genperm                   # 随机生成新的长期口令并打印（旧令牌失效）
    python server.py revoke                    # 停用限时口令
    python server.py status                    # 查看当前口令状态
    python server.py sync                      # 从 Lsky Pro 同步图片元数据
    python server.py set <id> [--category ai] [--featured 1] [--title 标题]
"""
from __future__ import annotations

import hashlib
import io
import hmac
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import sys
import time
import bcrypt
from contextlib import contextmanager
from typing import Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
import urllib.request
import urllib.error
from PIL import Image as PILImage, ImageOps
from pydantic import BaseModel

# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
DATA_DIR = os.environ.get("GALLERY_DATA", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
WEB_DIR = os.environ.get("GALLERY_WEB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "web"))
DB_PATH = os.path.join(DATA_DIR, "gallery.db")

LSKY_STORAGE = os.environ.get("LSKY_STORAGE", "")          # 可选：直接读 Lsky sqlite（仅兜底，默认不挂载）
LSKY_APP_URL = os.environ.get("LSKY_APP_URL", "https://pic.damingxing.vip").rstrip("/")
LSKY_UPLOAD_SUBDIR = os.environ.get("LSKY_UPLOAD_SUBDIR", "app/uploads")
# Lsky 的「Gallery 专用 HTTP 接口」：内网直连优先（不绕公网/Cloudflare），失败回落公网域名
LSKY_API_URL = os.environ.get("LSKY_API_URL", "").rstrip("/")
# 与 Lsky 容器环境变量 GALLERY_VERIFY_SECRET 一致；两边都配才生效
LSKY_VERIFY_SECRET = os.environ.get("LSKY_VERIFY_SECRET", "")

TOKEN_TTL = int(os.environ.get("TOKEN_TTL", str(7 * 86400)))   # 长期口令签发的 token 有效期
CATEGORIES = ("ai", "me", "other", "private")
PUBLIC_CATEGORIES = ("ai", "me", "other")

THUMB_DIR = os.path.join(DATA_DIR, "thumbs")
THUMB_WIDTH = int(os.environ.get("THUMB_WIDTH", "720"))
THUMB_QUALITY = int(os.environ.get("THUMB_QUALITY", "82"))
PREVIEW_DIR = os.path.join(DATA_DIR, "previews")
PREVIEW_WIDTH = int(os.environ.get("PREVIEW_WIDTH", "2000"))      # 灯箱/悬停预览的最大边（大图不直出原图）
PREVIEW_QUALITY = int(os.environ.get("PREVIEW_QUALITY", "86"))
MIN_PASSWORD_LEN = 6
LOGIN_MAX_FAILS = int(os.environ.get("LOGIN_MAX_FAILS", "8"))     # 同一 IP 窗口内最多失败次数
LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW", "600"))
VIDEO_EXTS = (".mp4", ".mov", ".webm", ".m4v", ".mkv", ".avi")
THUMB_HEADERS = {"Referrer-Policy": "no-referrer", "Cache-Control": "private, max-age=86400"}

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(THUMB_DIR, exist_ok=True)
os.makedirs(PREVIEW_DIR, exist_ok=True)


def lsky_source_bytes(row: sqlite3.Row) -> Optional[bytes]:
    """经 Lsky 的 PHP 路由（{key}.{ext}）拉取原图字节，用于本地生成缩略图/预览。
    不再依赖挂载的 storage 目录，全走 HTTP（契合内网穿透 + Cloudflare 边缘缓存）。"""
    url = row["url"]
    if not url or not re.match(r"^https?://", url or "", re.I):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GalleryStudio/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    except Exception:
        return None


def proxy_lsky(row: sqlite3.Row, range_header: Optional[str]) -> "StreamingResponse":
    """私密文件：服务端拉取 Lsky PHP 路由并流式转发（保留门禁），支持 Range 透传。"""
    req = urllib.request.Request(row["url"])
    if range_header:
        req.add_header("Range", range_header)
    try:
        resp = urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as e:
        raise HTTPException(status_code=e.code, detail="Lsky 返回错误")
    except Exception:
        raise HTTPException(status_code=502, detail="无法连接 Lsky")
    headers = {
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "private, max-age=600",
        "Accept-Ranges": resp.headers.get("Accept-Ranges", "bytes"),
        "Content-Type": resp.headers.get("Content-Type", "application/octet-stream"),
    }
    if resp.headers.get("Content-Length") is not None:
        headers["Content-Length"] = resp.headers["Content-Length"]
    if resp.headers.get("Content-Range") is not None:
        headers["Content-Range"] = resp.headers["Content-Range"]

    def gen():
        try:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            resp.close()

    return StreamingResponse(gen(), status_code=resp.status, headers=headers)

# --------------------------------------------------------------------------- #
# 数据库
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS media (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT,
    type        TEXT NOT NULL DEFAULT 'image',          -- image | video
    url         TEXT NOT NULL,
    thumbnail   TEXT,
    category    TEXT NOT NULL DEFAULT 'other',          -- ai | me | other | private
    is_featured INTEGER NOT NULL DEFAULT 0,
    width       INTEGER,
    height      INTEGER,
    source      TEXT DEFAULT 'manual',                  -- manual | lsky
    source_id   TEXT UNIQUE,                            -- 去重用（lsky 的 path）
    created_at  TEXT DEFAULT (datetime('now', 'localtime'))
);
CREATE INDEX IF NOT EXISTS idx_media_cat ON media(category, id DESC);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


@contextmanager
def db():
    """每次用完即关，避免长跑服务泄漏文件描述符。"""
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def migrate_db() -> None:
    """存量库补齐新列（tags / visibility），幂等。"""
    with db() as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(media)")}
        if "tags" not in cols:
            conn.execute("ALTER TABLE media ADD COLUMN tags TEXT DEFAULT ''")
        if "visibility" not in cols:
            conn.execute(
                "ALTER TABLE media ADD COLUMN visibility TEXT DEFAULT 'public' "
                "CHECK(visibility IN ('public', 'private'))"
            )


def init_db() -> None:
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
    migrate_db()
    if not get_setting("jwt_secret"):
        set_setting("jwt_secret", secrets.token_urlsafe(48))


def get_setting(key: str, default: Optional[str] = None) -> Optional[str]:
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )


# --------------------------------------------------------------------------- #
# 口令：PBKDF2 加盐哈希
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"pbkdf2_sha256$200000${salt}${dk.hex()}"


def verify_password(password: str, stored: Optional[str]) -> bool:
    if not stored:
        return False
    try:
        algo, iters, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iters))
        return hmac.compare_digest(dk.hex(), digest)
    except Exception:
        return False


class LskyUnavailable(Exception):
    """Lsky 的 HTTP 接口不可达（网络/配置问题），区别于「账号密码错误」。"""


def _lsky_api_call(path: str, payload: Optional[dict] = None, timeout: float = 8.0) -> dict:
    """调用 Lsky 的 Gallery 专用 HTTP 接口（零挂载：不再直读 lsky.sqlite）。
    依次尝试内网直连 LSKY_API_URL 与公网 LSKY_APP_URL，任一成功即返回。
    凭证类错误（401/403/422）直接返回带 _error 的 dict，不继续重试。"""
    bases = [u for u in (LSKY_API_URL, LSKY_APP_URL) if u]
    if not bases:
        raise LskyUnavailable("未配置 LSKY_API_URL / LSKY_APP_URL")
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "GalleryStudio/1.0",
    }
    if LSKY_VERIFY_SECRET:
        headers["X-Gallery-Verify-Key"] = LSKY_VERIFY_SECRET
    last = ""
    for base in dict.fromkeys(bases):
        req = urllib.request.Request(f"{base}{path}", data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "ignore")[:200]
            if e.code in (401, 403, 422):
                return {"_error": e.code, "detail": body}
            last = f"HTTP {e.code} {body}"
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
    raise LskyUnavailable(last or "Lsky 接口不可用")


def verify_lsky_user(email: str, password: str) -> Optional[dict]:
    """校验 Lsky Pro 账号（邮箱 + 密码），返回 {id, is_adminer} 或 None（凭证错误）。
    主路径：经 Lsky 的 POST /api/auth/verify（PHP 侧用 Auth::validate 校验 bcrypt）。
    兜底：若仍挂载了 Lsky 的 sqlite（LSKY_STORAGE），本地 bcrypt 校验（Lsky 是 $2y$ 前缀，
    Python bcrypt 需先换成 $2a$）。Lsky 整体不可达时抛 LskyUnavailable。"""
    if not email or not password:
        return None
    res = _lsky_api_call("/api/auth/verify", {"email": email.strip(), "password": password})
    if res.get("status") is True:
        return {"id": res.get("user_id"), "is_adminer": bool(res.get("is_adminer"))}
    if res.get("_error") in (401, 422):
        return None
    # 403/网络类：若本地仍挂载了 Lsky 的 sqlite，退回到本地校验
    local = _verify_lsky_user_local(email, password)
    if local is not None:
        return local
    raise LskyUnavailable(res.get("detail") or "Lsky 校验接口不可用")


def _verify_lsky_user_local(email: str, password: str) -> Optional[dict]:
    """（兜底）读只读挂载的 Lsky users 表做 bcrypt 校验；未挂载则返回 None。"""
    db_file = os.path.join(LSKY_STORAGE, "app", "lsky.sqlite") if LSKY_STORAGE else ""
    if not db_file or not os.path.isfile(db_file) or not email or not password:
        return None
    try:
        src = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
        src.row_factory = sqlite3.Row
        row = src.execute(
            "SELECT id, email, password, is_adminer FROM users WHERE LOWER(email) = ?",
            (email.strip().lower(),),
        ).fetchone()
        src.close()
    except Exception:
        return None
    if not row or not row["password"]:
        return None
    h = row["password"]
    try:
        if h.startswith("$2y$"):
            h = "$2a$" + h[4:]
        if bcrypt.checkpw(password.encode("utf-8"), h.encode("utf-8")):
            return {"id": row["id"], "is_adminer": bool(row["is_adminer"])}
    except Exception:
        return None
    return None


def jwt_secret() -> str:
    return get_setting("jwt_secret") or ""


def token_version(scope: str) -> int:
    return int(get_setting(f"tv_{scope}", "0") or 0)


def bump_token_version(scope: str) -> int:
    """口令被修改/重置后令牌版本 +1，旧令牌立即失效。"""
    v = token_version(scope) + 1
    set_setting(f"tv_{scope}", str(v))
    return v


def issue_token(scope: str, expires_at: int) -> str:
    now = int(time.time())
    payload = {"scope": scope, "iat": now, "exp": expires_at, "jti": secrets.token_hex(8),
               "tv": token_version(scope)}
    return jwt.encode(payload, jwt_secret(), algorithm="HS256")


def parse_token(authorization: Optional[str], token_qs: Optional[str]) -> dict:
    raw = None
    if authorization and authorization.lower().startswith("bearer "):
        raw = authorization.split(" ", 1)[1].strip()
    elif token_qs:
        raw = token_qs.strip()
    if not raw:
        raise HTTPException(status_code=401, detail="未提供访问令牌")
    try:
        payload = jwt.decode(raw, jwt_secret(), algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="令牌已过期，请重新输入口令")
    except Exception:
        raise HTTPException(status_code=401, detail="令牌无效")
    scope = payload.get("scope")
    if scope not in ("full", "visitor") or int(payload.get("tv", 0)) != token_version(scope):
        raise HTTPException(status_code=401, detail="口令已被修改，请重新输入口令")
    return payload


def require_token(
    authorization: Optional[str] = Header(None),
    t: Optional[str] = Query(None, description="图片/视频标签无法带 header，用 ?t= 传令牌"),
) -> dict:
    return parse_token(authorization, t)


def require_full(payload: dict = Depends(require_token)) -> dict:
    if payload.get("scope") != "full":
        raise HTTPException(status_code=403, detail="该内容需要长期口令")
    return payload


# --------------------------------------------------------------------------- #
# API 模型
# --------------------------------------------------------------------------- #
class LoginReq(BaseModel):
    password: str


class UserLoginReq(BaseModel):
    email: str
    password: str
    kind: str = "user"   # admin | user


class MediaPatch(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    is_featured: Optional[int] = None
    tags: Optional[str] = None
    visibility: Optional[str] = None


class PasswordChange(BaseModel):
    current_password: str
    kind: str = "perm"                  # perm 长期口令 | temp 限时口令
    new_password: Optional[str] = None  # 留空则随机生成
    days: float = 1                     # 仅限时口令使用，默认 24 小时


class BulkReq(BaseModel):
    ids: list[int]
    action: str                         # delete | category | feature | unfeature
    category: Optional[str] = None


class MediaCreate(BaseModel):
    url: str
    type: str = "image"
    title: Optional[str] = None
    thumbnail: Optional[str] = None
    category: str = "other"
    is_featured: int = 0
    tags: Optional[str] = None
    visibility: str = "public"


# --------------------------------------------------------------------------- #
# 应用
# --------------------------------------------------------------------------- #
app = FastAPI(title="Gallery Studio API", docs_url=None, redoc_url=None, openapi_url=None)


def _row_to_item(row: sqlite3.Row, scope: str) -> dict:
    """所有媒体统一走本服务的 /api/{file,thumb,preview}/{id}：
    - 私密项：这些端点带门禁校验后，经 Lsky PHP 路由拉取/转发（直链不暴露给前端）；
    - 公开/精选项：/api/file 302 到 Lsky PHP 路由（Cloudflare 缓存、零带宽），
      /api/thumb、/api/preview 由本服务从 Lsky 拉原图后本地生成并缓存。
    原 Lsky /i/... 静态直链（依赖 public/storage 软链）已废弃。"""
    item_id = row["id"]
    is_private = row["category"] == "private"
    url = f"/api/file/{item_id}"
    thumb = f"/api/thumb/{item_id}"
    preview = f"/api/preview/{item_id}" if row["type"] == "image" else url
    return {
        "id": item_id,
        "title": row["title"] or "",
        "type": row["type"],
        "url": url,
        "thumbnail": thumb,
        "preview": preview,
        "category": row["category"],
        "is_featured": row["is_featured"],
        "tags": row["tags"] or "",
        "visibility": row["visibility"] or ("private" if is_private else "public"),
        "width": row["width"],
        "height": row["height"],
        "created_at": row["created_at"],
    }


_FAILS: dict = {}


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else "") or (request.client.host if request.client else "?")


def _check_throttle(ip: str) -> None:
    now = time.time()
    hits = [t for t in _FAILS.get(ip, []) if now - t < LOGIN_WINDOW]
    _FAILS[ip] = hits
    if len(hits) >= LOGIN_MAX_FAILS:
        wait = int(LOGIN_WINDOW - (now - hits[0])) + 1
        raise HTTPException(status_code=429, detail=f"尝试次数过多，请 {wait} 秒后再试")


@app.post("/api/auth/login")
def login(req: LoginReq, request: Request):
    pwd = req.password or ""
    now = int(time.time())
    ip = _client_ip(request)
    _check_throttle(ip)

    if not get_setting("perm_hash"):
        raise HTTPException(status_code=503, detail="管理员尚未设置长期口令（python server.py setperm <密码>）")

    if verify_password(pwd, get_setting("perm_hash")):
        _FAILS.pop(ip, None)
        exp = now + TOKEN_TTL
        return {"code": 200, "token": issue_token("full", exp), "scope": "full",
                "expires_at": exp, "label": "完整访问"}

    temp_exp = int(get_setting("temp_expires_at") or 0)
    if temp_exp > now and verify_password(pwd, get_setting("temp_hash")):
        _FAILS.pop(ip, None)
        exp = min(now + TOKEN_TTL, temp_exp)
        return {"code": 200, "token": issue_token("visitor", exp), "scope": "visitor",
                "expires_at": exp, "label": "访客访问"}

    if temp_exp and temp_exp <= now and verify_password(pwd, get_setting("temp_hash")):
        raise HTTPException(status_code=401, detail="限时口令已到期，请向管理员索取新口令")

    _FAILS.setdefault(ip, []).append(time.time())
    raise HTTPException(status_code=401, detail="口令错误")


@app.post("/api/auth/login/user")
def login_user(req: UserLoginReq, request: Request):
    """已注册人员 / 管理员：用 Lsky Pro 邮箱 + 密码登录（经 Lsky 的 /api/auth/verify 校验）。
    管理员(is_adminer) -> scope=full；其他已注册用户 -> scope=visitor。"""
    _check_throttle(_client_ip(request))
    try:
        u = verify_lsky_user(req.email, req.password)
    except LskyUnavailable as e:
        raise HTTPException(status_code=503, detail=f"账号校验服务不可用：{e}")
    if not u:
        _FAILS.setdefault(_client_ip(request), []).append(time.time())
        raise HTTPException(status_code=401, detail="邮箱或密码错误")
    _FAILS.pop(_client_ip(request), None)
    if req.kind == "admin" and not u["is_adminer"]:
        raise HTTPException(status_code=403, detail="该账号不是管理员，请用「已注册人员登录」")
    scope = "full" if (req.kind == "admin" and u["is_adminer"]) else "visitor"
    exp = int(time.time()) + TOKEN_TTL
    return {"code": 200, "token": issue_token(scope, exp), "scope": scope,
            "expires_at": exp, "label": "完整访问" if scope == "full" else "访客访问"}


@app.get("/api/auth/me")
def me(payload: dict = Depends(require_token)):
    return {"code": 200, "scope": payload.get("scope"), "expires_at": payload.get("exp")}


@app.get("/api/stats")
def stats(payload: dict = Depends(require_token)):
    with db() as conn:
        rows = conn.execute(
            "SELECT category, COUNT(*) n FROM media GROUP BY category"
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) n FROM media WHERE category != 'private'").fetchone()["n"]
        featured = conn.execute(
            "SELECT COUNT(*) n FROM media WHERE is_featured = 1 AND category != 'private'"
        ).fetchone()["n"]
    out = {"latest": total, "featured": featured, "all": total}
    for r in rows:
        if r["category"] != "private" or payload.get("scope") == "full":
            out[r["category"]] = r["n"]
    return {"code": 200, "data": out}


@app.get("/api/media")
def list_media(
    tab: str = Query("all"),
    category: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    payload: dict = Depends(require_token),
):
    scope = payload.get("scope")
    where = []
    params: list = []

    if category == "private":
        if scope != "full":
            raise HTTPException(status_code=403, detail="私密专区需要长期口令")
        where.append("category = 'private'")
    else:
        where.append("category != 'private'")
        if category in PUBLIC_CATEGORIES:
            where.append("category = ?")
            params.append(category)

    if tab == "featured":
        where.append("is_featured = 1")

    sql = "SELECT * FROM media WHERE " + " AND ".join(where) + " ORDER BY id DESC"
    if tab == "latest":
        sql += " LIMIT 10"
    else:
        sql += " LIMIT ? OFFSET ?"
        params.extend([page_size, (page - 1) * page_size])

    with db() as conn:
        rows = conn.execute(sql, params).fetchall()
        total = conn.execute(
            "SELECT COUNT(*) n FROM media WHERE " + " AND ".join(where), params[: len(params) - (2 if tab != 'latest' else 0)]
        ).fetchone()["n"]

    items = [_row_to_item(r, scope) for r in rows]
    fetched = (page - 1) * page_size + len(items)
    return {
        "code": 200,
        "data": items,
        "page": page,
        "total": total if tab == "latest" else total,
        "has_more": tab != "latest" and fetched < total,
    }


@app.get("/api/file/{media_id}")
def media_file(media_id: int, request: Request, payload: dict = Depends(require_token)):
    with db() as conn:
        row = conn.execute("SELECT * FROM media WHERE id = ?", (media_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="资源不存在")
    if row["category"] == "private" and payload.get("scope") != "full":
        raise HTTPException(status_code=403, detail="私密专区需要长期口令")

    # 公开/精选：302 到 Lsky PHP 路由（Cloudflare 边缘缓存、gallery 零带宽）
    # 私密：服务端代理 Lsky PHP 路由并透传 Range（保留门禁，直链不落地前端）
    if row["category"] == "private":
        return proxy_lsky(row, request.headers.get("Range"))
    return RedirectResponse(row["url"], status_code=302)


@app.get("/api/thumb/{media_id}")
def media_thumb(media_id: int, payload: dict = Depends(require_token)):
    """自建缩略图：首访从 Lsky PHP 路由拉原图生成并落盘缓存，之后直出 JPEG。"""
    with db() as conn:
        row = conn.execute("SELECT * FROM media WHERE id = ?", (media_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="资源不存在")
    if row["category"] == "private" and payload.get("scope") != "full":
        raise HTTPException(status_code=403, detail="私密专区需要长期口令")

    cached = os.path.join(THUMB_DIR, f"{media_id}.jpg")
    if os.path.isfile(cached):
        return FileResponse(cached, media_type="image/jpeg", headers=THUMB_HEADERS)

    src = lsky_source_bytes(row)
    # 私密：拉取失败直接 404（不泄露直链）；公开：回退原图
    if not src:
        if row["category"] == "private":
            raise HTTPException(status_code=404, detail="私密文件不存在")
        return RedirectResponse(row["url"], status_code=302)
    # 非图片 / 动图(svg,gif)：私密代理、公开 302 到原图
    if row["type"] != "image" or row["url"].lower().endswith((".svg", ".gif")):
        if row["category"] == "private":
            return proxy_lsky(row, None)
        return RedirectResponse(row["url"], status_code=302)

    try:
        with PILImage.open(io.BytesIO(src)) as im:
            im = ImageOps.exif_transpose(im).convert("RGB")
            if im.width > THUMB_WIDTH:
                im = im.resize((THUMB_WIDTH, max(1, round(im.height * THUMB_WIDTH / im.width))), PILImage.LANCZOS)
            tmp = cached + ".tmp"
            im.save(tmp, "JPEG", quality=THUMB_QUALITY, optimize=True, progressive=True)
        os.replace(tmp, cached)
    except Exception:
        # 解码失败（损坏文件/不支持的格式）时退回原图，绝不让页面裂图
        if row["category"] == "private":
            return proxy_lsky(row, None)
        return RedirectResponse(row["url"], status_code=302)
    return FileResponse(cached, media_type="image/jpeg", headers=THUMB_HEADERS)


@app.get("/api/preview/{media_id}")
def media_preview(media_id: int, payload: dict = Depends(require_token)):
    """灯箱/悬停用的中等尺寸预览（长边 PREVIEW_WIDTH），避免直接加载 5MB+ 原图导致大图不显示。"""
    with db() as conn:
        row = conn.execute("SELECT * FROM media WHERE id = ?", (media_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="资源不存在")
    if row["category"] == "private" and payload.get("scope") != "full":
        raise HTTPException(status_code=403, detail="私密专区需要长期口令")

    cached = os.path.join(PREVIEW_DIR, f"{media_id}.jpg")
    if os.path.isfile(cached):
        return FileResponse(cached, media_type="image/jpeg", headers=THUMB_HEADERS)

    src = lsky_source_bytes(row)
    if not src or row["type"] != "image" or row["url"].lower().endswith((".svg", ".gif")):
        return _original_response(row)

    try:
        with PILImage.open(io.BytesIO(src)) as im:
            im = ImageOps.exif_transpose(im)
            im = im.convert("RGB")
            if max(im.size) > PREVIEW_WIDTH:
                im.thumbnail((PREVIEW_WIDTH, PREVIEW_WIDTH), PILImage.LANCZOS)
            tmp = cached + ".tmp"
            im.save(tmp, "JPEG", quality=PREVIEW_QUALITY, optimize=True, progressive=True)
        os.replace(tmp, cached)
    except Exception:
        return _original_response(row)
    return FileResponse(cached, media_type="image/jpeg", headers=THUMB_HEADERS)


def _original_response(row: sqlite3.Row):
    # 私密：代理 Lsky PHP 路由（保留门禁，直链不落地前端）；公开：302 到原图
    if row["category"] == "private":
        return proxy_lsky(row, None)
    return RedirectResponse(row["url"], status_code=302)


def drop_caches(media_id: int) -> None:
    for d in (THUMB_DIR, PREVIEW_DIR):
        try:
            os.remove(os.path.join(d, f"{media_id}.jpg"))
        except OSError:
            pass


# ------------------------------ 管理接口 ----------------------------------- #
@app.patch("/api/admin/media/{media_id}")
def admin_patch(media_id: int, patch: MediaPatch, payload: dict = Depends(require_full)):
    sets, params = [], []
    with db() as conn:
        row = conn.execute("SELECT category FROM media WHERE id = ?", (media_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="资源不存在")
        if patch.category is not None and patch.category not in CATEGORIES:
            raise HTTPException(status_code=400, detail="分类必须是 ai/me/other/private")
        if patch.visibility is not None and patch.visibility not in ("public", "private"):
            raise HTTPException(status_code=400, detail="权限必须是 public/private")
        # 分类与权限始终保持一致：private 分类 <=> private 权限
        new_cat = patch.category
        if new_cat is None and patch.visibility is not None:
            if patch.visibility == "private":
                new_cat = "private"
            elif row["category"] == "private":
                new_cat = "other"
        if new_cat is not None:
            sets.append("category = ?"); params.append(new_cat)
            sets.append("visibility = ?"); params.append("private" if new_cat == "private" else "public")
        if patch.title is not None:
            sets.append("title = ?"); params.append(patch.title)
        if patch.tags is not None:
            sets.append("tags = ?"); params.append(patch.tags)
        if patch.is_featured is not None:
            sets.append("is_featured = ?"); params.append(1 if patch.is_featured else 0)
        if not sets:
            raise HTTPException(status_code=400, detail="没有需要更新的字段")
        params.append(media_id)
        conn.execute("UPDATE media SET " + ", ".join(sets) + " WHERE id = ?", params)
    return {"code": 200, "message": "已更新", "category": new_cat or row["category"]}


@app.post("/api/admin/media")
def admin_create(item: MediaCreate, payload: dict = Depends(require_full)):
    if item.category not in CATEGORIES:
        raise HTTPException(status_code=400, detail="分类必须是 ai/me/other/private")
    if item.type not in ("image", "video"):
        raise HTTPException(status_code=400, detail="类型必须是 image/video")
    if not re.match(r"^https?://", item.url or "", re.I):
        raise HTTPException(status_code=400, detail="url 必须是 http(s) 链接")
    visibility = "private" if item.category == "private" else "public"
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO media(title, type, url, thumbnail, category, is_featured, tags, visibility, source) "
            "VALUES(?,?,?,?,?,?,?,?, 'manual')",
            (item.title, item.type, item.url, item.thumbnail or item.url, item.category,
             1 if item.is_featured else 0, item.tags or "", visibility),
        )
        new_id = cur.lastrowid
    return {"code": 200, "id": new_id}


@app.delete("/api/admin/media/{media_id}")
def admin_delete(media_id: int, payload: dict = Depends(require_full)):
    with db() as conn:
        cur = conn.execute("DELETE FROM media WHERE id = ?", (media_id,))
    if not cur.rowcount:
        raise HTTPException(status_code=404, detail="资源不存在")
    drop_caches(media_id)
    return {"code": 200, "message": "已删除（仅移出展馆，图床原文件未删除）"}


@app.post("/api/admin/media/bulk")
def admin_bulk(req: BulkReq, payload: dict = Depends(require_full)):
    ids = list(dict.fromkeys(req.ids))[:500]
    if not ids:
        raise HTTPException(status_code=400, detail="未选择任何条目")
    marks = ",".join("?" * len(ids))
    with db() as conn:
        if req.action == "delete":
            cur = conn.execute(f"DELETE FROM media WHERE id IN ({marks})", ids)
            for i in ids:
                drop_caches(i)
        elif req.action == "category":
            if req.category not in CATEGORIES:
                raise HTTPException(status_code=400, detail="分类必须是 ai/me/other/private")
            cur = conn.execute(
                f"UPDATE media SET category = ?, visibility = ? WHERE id IN ({marks})",
                [req.category, "private" if req.category == "private" else "public", *ids],
            )
        elif req.action in ("feature", "unfeature"):
            cur = conn.execute(
                f"UPDATE media SET is_featured = ? WHERE id IN ({marks})",
                [1 if req.action == "feature" else 0, *ids],
            )
        else:
            raise HTTPException(status_code=400, detail="未知操作")
    return {"code": 200, "affected": cur.rowcount}


@app.get("/api/admin/status")
def admin_status(payload: dict = Depends(require_full)):
    now = int(time.time())
    exp = int(get_setting("temp_expires_at") or 0)
    with db() as conn:
        n = conn.execute("SELECT COUNT(*) n FROM media").fetchone()["n"]
    return {"code": 200, "perm_set": bool(get_setting("perm_hash")),
            "temp_set": bool(get_setting("temp_hash")), "temp_expires_at": exp,
            "temp_active": bool(get_setting("temp_hash")) and exp > now, "media_count": n}


@app.post("/api/admin/password")
def admin_password(req: PasswordChange, request: Request, payload: dict = Depends(require_full)):
    """修改/重置/随机生成口令。必须验证当前长期口令；修改后对应身份的旧令牌全部失效。"""
    ip = _client_ip(request)
    _check_throttle(ip)
    if not verify_password(req.current_password or "", get_setting("perm_hash")):
        _FAILS.setdefault(ip, []).append(time.time())
        raise HTTPException(status_code=403, detail="当前长期口令不正确")
    if req.kind not in ("perm", "temp"):
        raise HTTPException(status_code=400, detail="kind 必须是 perm/temp")
    new_pwd = (req.new_password or "").strip()
    generated = not new_pwd
    if generated:
        new_pwd = secrets.token_urlsafe(9)
    elif len(new_pwd) < MIN_PASSWORD_LEN:
        raise HTTPException(status_code=400, detail=f"口令至少 {MIN_PASSWORD_LEN} 位")
    out: dict = {"code": 200, "generated": generated}
    if generated:
        out["password"] = new_pwd
    if req.kind == "perm":
        if verify_password(new_pwd, get_setting("temp_hash")) and int(get_setting("temp_expires_at") or 0) > time.time():
            raise HTTPException(status_code=400, detail="长期口令不能与有效的限时口令相同")
        set_setting("perm_hash", hash_password(new_pwd))
        bump_token_version("full")
        exp = int(time.time()) + TOKEN_TTL
        out.update(message="长期口令已更新，其它设备需重新登录",
                   token=issue_token("full", exp), scope="full", expires_at=exp)
    else:
        if not 0 < req.days <= 365:
            raise HTTPException(status_code=400, detail="有效天数需在 0~365 之间")
        if verify_password(new_pwd, get_setting("perm_hash")):
            raise HTTPException(status_code=400, detail="限时口令不能与长期口令相同")
        exp = int(time.time() + req.days * 86400)
        set_setting("temp_hash", hash_password(new_pwd))
        set_setting("temp_expires_at", str(exp))
        bump_token_version("visitor")
        out.update(message="限时口令已更新，旧访客令牌已失效", temp_expires_at=exp)
    return out


@app.delete("/api/admin/password/temp")
def admin_revoke_temp(payload: dict = Depends(require_full)):
    set_setting("temp_hash", "")
    set_setting("temp_expires_at", "0")
    bump_token_version("visitor")
    return {"code": 200, "message": "限时口令已停用，访客令牌已失效"}


@app.post("/api/admin/sync")
def admin_sync(payload: dict = Depends(require_full)):
    added, skipped = sync_from_lsky()
    return {"code": 200, "added": added, "skipped": skipped}


# ------------------------- Lsky Pro Webhook ------------------------------ #
# 失败关闭：必须设置环境变量 LSKY_WEBHOOK_SECRET 才能接收；调用方在请求头
# X-Gallery-Webhook-Key 或 URL 参数 ?key= 中携带相同密钥。未配置密钥时接口
# 直接拒绝（503），避免任何人知道 URL 就能向展馆灌入媒体（"任何人可上传"漏洞）。
@app.post("/api/webhook/lsky")
async def lsky_webhook(request: Request):
    secret = os.environ.get("LSKY_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(status_code=503, detail="webhook 未配置密钥（LSKY_WEBHOOK_SECRET），已拒绝接收")
    provided = request.headers.get("X-Gallery-Webhook-Key", "") or (request.query_params.get("key") or "")
    if not hmac.compare_digest(provided, secret):
        raise HTTPException(status_code=401, detail="无效的 webhook 密钥")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求体不是合法 JSON")

    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="请求体格式错误")

    # 兼容 {data:[...]} 与单对象两种形态
    items = payload.get("data")
    if not isinstance(items, list):
        items = [payload] if isinstance(payload.get("url") or (payload.get("links", {}) or {}).get("url"), str) else []

    added = skipped = 0
    with db() as conn:
        for it in items:
            if not isinstance(it, dict):
                continue
            links = it.get("links", {}) or {}
            url = links.get("url") or it.get("url")
            if not url or not isinstance(url, str):
                continue
            thumb = links.get("thumbnail_url") or it.get("thumbnail_url") or it.get("thumbnail") or url
            media_type = "video" if url.lower().split("?")[0].endswith(VIDEO_EXTS) else "image"

            # 去重键：规范化后的 PHP 路由 URL（同步与 webhook 共用，{key}.{ext}）
            norm = url.split("?")[0].rstrip("/")
            if conn.execute("SELECT 1 FROM media WHERE url = ?", (norm,)).fetchone():
                skipped += 1
                continue
            sid = norm

            title = it.get("name") or it.get("origin_name") or it.get("alias_name") or "新上传素材"
            conn.execute(
                "INSERT INTO media(title, type, url, thumbnail, category, visibility, tags, is_featured, source, source_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (title, media_type, url, thumb, "other", "public", "", 0, "webhook", sid),
            )
            added += 1
    return {"status": "success", "added": added, "skipped": skipped}


# --------------------------- Lsky 同步 ------------------------------------- #
def is_video_name(name: str) -> bool:
    return name.lower().endswith(VIDEO_EXTS)


def _lsky_image_rows() -> list[dict]:
    """取 Lsky 图片元数据：优先经 Lsky HTTP 接口（零挂载），失败回落只读挂载的 sqlite。"""
    detail = ""
    try:
        res = _lsky_api_call("/api/gallery/images", timeout=30)
        rows = res.get("data")
        if isinstance(rows, list):
            return [
                {
                    "key": r.get("key") or "",
                    "path": r.get("path") or "",
                    "name": r.get("name") or "",
                    "origin_name": r.get("origin_name"),
                    "alias_name": r.get("alias_name"),
                    "width": r.get("width"),
                    "height": r.get("height"),
                    "extension": r.get("extension") or "",
                    "created_at": r.get("created_at"),
                }
                for r in rows
                if isinstance(r, dict)
            ]
        detail = str(res.get("detail") or res.get("message") or "")
    except LskyUnavailable as e:
        detail = str(e)

    db_file = os.path.join(LSKY_STORAGE, "app", "lsky.sqlite") if LSKY_STORAGE else ""
    if not db_file or not os.path.isfile(db_file):
        raise HTTPException(status_code=503, detail=f"Lsky 接口不可用（{detail or '未知原因'}）且未挂载数据库")
    src = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    out = [dict(r) for r in src.execute(
        "SELECT path, name, origin_name, alias_name, md5, width, height, extension, key, created_at "
        "FROM images ORDER BY id DESC"
    ).fetchall()]
    src.close()
    return out


def sync_from_lsky() -> tuple[int, int]:
    rows = _lsky_image_rows()

    added = skipped = 0
    with db() as conn:
        for r in rows:
            # ⚠️ Lsky 的 path 只是目录（如 2026/10/03），文件名在 name 列，两者拼接才是完整相对路径
            path = str(r["path"] or "").strip("/")
            name = str(r["name"] or "").strip("/")
            if not path or not name:
                continue
            pathname = f"{path}/{name}"
            exists = conn.execute("SELECT 1 FROM media WHERE source_id = ?", (pathname,)).fetchone()
            if exists:
                skipped += 1
                continue
            title = (r["alias_name"] or r["origin_name"] or r["name"] or "").strip() or None
            # 原图统一走 Lsky PHP 路由（{key}.{extension}），不再用 /i/... 静态直链
            url = f"{LSKY_APP_URL}/{r['key']}.{r['extension']}"
            thumb = url  # 缩略图由 gallery 本地生成（/api/thumb），不依赖 Lsky 静态缩略图
            is_video = is_video_name(pathname)
            conn.execute(
                "INSERT INTO media(title, type, url, thumbnail, category, is_featured, width, height, source, source_id, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (title, "video" if is_video else "image", url, thumb, "other", 0, r["width"], r["height"], "lsky", pathname,
                 r["created_at"] or time.strftime("%Y-%m-%d %H:%M:%S")),
            )
            added += 1
    return added, skipped


# ------------------------------ 静态前端 ----------------------------------- #
@app.get("/")
def index():
    idx = os.path.join(WEB_DIR, "index.html")
    if not os.path.isfile(idx):
        return JSONResponse({"code": 500, "message": "前端文件缺失"}, status_code=500)
    return FileResponse(idx, media_type="text/html", headers={"Referrer-Policy": "no-referrer"})


@app.exception_handler(HTTPException)
def http_exc(_: Request, exc: HTTPException):
    return JSONResponse({"code": exc.status_code, "message": exc.detail}, status_code=exc.status_code)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def cli_serve() -> None:
    import uvicorn
    init_db()
    port = int(os.environ.get("GALLERY_PORT", "8890"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info", access_log=False)


def _need_valid(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        print(f"❌ 口令至少 {MIN_PASSWORD_LEN} 位")
        sys.exit(1)


def cli_setperm(password: str) -> None:
    _need_valid(password)
    set_setting("perm_hash", hash_password(password))
    bump_token_version("full")
    print("✅ 长期口令已更新（scope=full：进站 + 私密 + 管理），旧令牌已失效")


def cli_genperm() -> None:
    pwd = secrets.token_urlsafe(12)
    set_setting("perm_hash", hash_password(pwd))
    bump_token_version("full")
    print(f"新的长期口令：{pwd}\n（仅显示这一次，旧令牌已失效）")


def cli_revoke() -> None:
    set_setting("temp_hash", "")
    set_setting("temp_expires_at", "0")
    bump_token_version("visitor")
    print("✅ 限时口令已停用，访客令牌已失效")


def cli_settemp(password: str, days: float) -> None:
    _need_valid(password)
    if not 0 < days <= 365:
        print("❌ 有效天数需在 0~365 之间"); sys.exit(1)
    bump_token_version("visitor")
    exp = int(time.time() + days * 86400)
    set_setting("temp_hash", hash_password(password))
    set_setting("temp_expires_at", str(exp))
    print(f"✅ 限时口令已设置，将于 {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))} 失效（{days} 天）")


def cli_rotate(days: float) -> None:
    if not 0 < days <= 365:
        print("❌ 有效天数需在 0~365 之间"); sys.exit(1)
    pwd = secrets.token_urlsafe(9)
    exp = int(time.time() + days * 86400)
    bump_token_version("visitor")
    set_setting("temp_hash", hash_password(pwd))
    set_setting("temp_expires_at", str(exp))
    print(f"新的限时口令：{pwd}")
    print(f"有效期至：{time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}")


def cli_status() -> None:
    perm = "已设置" if get_setting("perm_hash") else "❌ 未设置"
    exp = int(get_setting("temp_expires_at") or 0)
    if get_setting("temp_hash") and exp > time.time():
        temp = f"有效至 {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}"
    elif get_setting("temp_hash"):
        temp = "已过期（需重新 rotate/settemp）"
    else:
        temp = "❌ 未设置"
    with db() as conn:
        n = conn.execute("SELECT COUNT(*) n FROM media").fetchone()["n"]
    print(f"长期口令：{perm}\n限时口令：{temp}\n媒体条数：{n}")


def cli_sync() -> None:
    added, skipped = sync_from_lsky()
    print(f"同步完成：新增 {added} 条，跳过已存在 {skipped} 条")


def cli_set(media_id: int, category: Optional[str], featured: Optional[int], title: Optional[str]) -> None:
    sets, params = [], []
    if category:
        if category not in CATEGORIES:
            print("❌ 分类必须是 ai/me/other/private"); sys.exit(1)
        sets.append("category = ?"); params.append(category)
        sets.append("visibility = ?"); params.append("private" if category == "private" else "public")
    if featured is not None:
        sets.append("is_featured = ?"); params.append(featured)
    if title:
        sets.append("title = ?"); params.append(title)
    if not sets:
        print("没有要修改的字段"); return
    params.append(media_id)
    with db() as conn:
        conn.execute("UPDATE media SET " + ", ".join(sets) + " WHERE id = ?", params)
    print(f"✅ 已更新 #{media_id}")


def main(argv: list[str]) -> None:
    init_db()
    cmd = argv[1] if len(argv) > 1 else "serve"
    args = argv[2:]

    def opt(name: str, default=None):
        return args[args.index(name) + 1] if name in args else default

    if cmd == "serve":
        cli_serve()
    elif cmd == "setperm" and args:
        cli_setperm(args[0])
    elif cmd == "settemp" and args:
        cli_settemp(args[0], float(opt("--days", 1)))
    elif cmd == "rotate":
        cli_rotate(float(opt("--days", 1)))
    elif cmd == "genperm":
        cli_genperm()
    elif cmd == "revoke":
        cli_revoke()
    elif cmd == "status":
        cli_status()
    elif cmd == "sync":
        cli_sync()
    elif cmd == "set" and args:
        cli_set(int(args[0]), opt("--category"), None if opt("--featured") is None else int(opt("--featured")), opt("--title"))
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
