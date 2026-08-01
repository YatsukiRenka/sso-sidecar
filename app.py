#!/usr/bin/env python3
"""
SillyTavern SSO Sidecar — transparent reverse proxy that:
1. Reads X-Authentik-Uid (stable UUID) from Authentik outpost headers
2. Maps uid → existing ST handle via _storage records (ssoUid field)
3. Auto-creates ST account if uid is new (admin session via passwordless login)
4. Rewrites X-Authentik-Username to the mapped handle so ST's native SSO kicks in
"""

import asyncio
import json
import os
import re
import secrets
import time
import logging
from typing import Optional
from aiohttp import web, ClientSession, ClientTimeout

# ─── Config ──────────────────────────────────────────────────────────────────
ST_BACKEND = os.getenv("ST_BACKEND", "http://sillytavern:8000")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8001"))
# admin handle used for auto-provisioning (must be passwordless + enabled)
ADMIN_HANDLE = os.getenv("ADMIN_HANDLE", "admin")
# groups that grant admin in SillyTavern
ADMIN_GROUPS = set(os.getenv("ADMIN_GROUPS", "admins,staff").split(","))
# where the ST data volume is mounted inside this container
ST_DATA_DIR = os.getenv("ST_DATA_DIR", "/st-data/data")
# slugify rule matching ST's lodash.slugify
SLUG_RE = re.compile(r"[^a-z0-9]+")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SSO] %(levelname)s %(message)s",
)
log = logging.getLogger("sso-sidecar")

# ─── Helpers ──────────────────────────────────────────────────────────────────

def slugify(text: str) -> str:
    """Match ST's slugify: deburr(lower(trim)) → [^a-z0-9]+ → '-' → strip hyphens."""
    import unicodedata
    text = text.strip().lower()
    # deburr: strip diacritical marks (NFKD → keep ASCII)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = SLUG_RE.sub("-", text)
    return text.strip("-")


def storage_path(handle: str) -> str:
    """Where ST stores user:<handle> as a JSON file in _storage."""
    # ST uses sha256 hash of the key as filename
    import hashlib
    key = f"user:{handle}"
    fname = hashlib.sha256(key.encode()).hexdigest()
    return os.path.join(ST_DATA_DIR, "_storage", fname)


def read_user_record(handle: str) -> Optional[dict]:
    """Read a ST user record from disk (sidecar mounts the same volume)."""
    path = storage_path(handle)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data.get("value", data)
    except (json.JSONDecodeError, IOError):
        return None


def write_user_record(handle: str, user: dict) -> bool:
    """Write a ST user record back to disk (adding ssoUid field)."""
    path = storage_path(handle)
    key = f"user:{handle}"
    try:
        with open(path, "r") as f:
            raw = json.load(f)
        raw["value"] = user
        with open(path, "w") as f:
            json.dump(raw, f)
        return True
    except (IOError, json.JSONDecodeError) as e:
        log.error(f"Failed to write user record for {handle}: {e}")
        return False


def find_handle_by_uid(uid: str) -> Optional[str]:
    """Scan all user records for a matching ssoUid field."""
    storage_dir = os.path.join(ST_DATA_DIR, "_storage")
    if not os.path.isdir(storage_dir):
        return None
    for fname in os.listdir(storage_dir):
        path = os.path.join(storage_dir, fname)
        try:
            with open(path, "r") as f:
                data = json.load(f)
            user = data.get("value", data)
            if user.get("ssoUid") == uid:
                return user.get("handle")
        except (json.JSONDecodeError, IOError):
            continue
    return None


def find_handle_by_username(username: str) -> Optional[dict]:
    """Find user by handle (fallback for pre-existing accounts without ssoUid)."""
    handle = slugify(username)
    user = read_user_record(handle)
    if user and user.get("enabled", True):
        return {"handle": handle, "user": user}
    return None


# ─── ST API Client ────────────────────────────────────────────────────────────

async def st_get_csrf(session: ClientSession) -> tuple[str, str]:
    """Get CSRF token + session cookie from ST."""
    async with session.get(f"{ST_BACKEND}/csrf-token") as resp:
        data = await resp.json()
        token = data.get("token", "")
        # aiohttp keeps cookies automatically via cookie_jar
        return token


async def st_admin_login(session: ClientSession, csrf: str) -> bool:
    """Login as admin (passwordless account) to get an admin session."""
    headers = {"Content-Type": "application/json", "x-csrf-token": csrf}
    async with session.post(
        f"{ST_BACKEND}/api/users/login",
        json={"handle": ADMIN_HANDLE},
        headers=headers,
    ) as resp:
        if resp.status == 200:
            log.info(f"Admin login successful as '{ADMIN_HANDLE}'")
            return True
        body = await resp.text()
        log.warning(f"Admin login failed ({resp.status}): {body[:200]}")
        return False


async def st_create_user(session: ClientSession, csrf: str, handle: str, name: str, is_admin: bool) -> bool:
    """Create a new ST user via admin API."""
    headers = {"Content-Type": "application/json", "x-csrf-token": csrf}
    body = {"handle": handle, "name": name, "admin": is_admin}
    async with session.post(
        f"{ST_BACKEND}/api/users/create",
        json=body,
        headers=headers,
    ) as resp:
        if resp.status == 200:
            log.info(f"Created ST user: handle={handle}, name={name}, admin={is_admin}")
            return True
        text = await resp.text()
        log.error(f"Create user failed ({resp.status}): {text[:300]}")
        return False


# ─── Auto-provisioning ───────────────────────────────────────────────────────

async def ensure_user(uid: str, username: str, display_name: str, groups: str) -> Optional[str]:
    """
    Given Authentik uid + username + groups, ensure a ST account exists.
    Returns the ST handle to use, or None on failure.
    """
    # 1. Check if we already have a mapping by uid
    existing_handle = find_handle_by_uid(uid)
    if existing_handle:
        log.debug(f"UID {uid} → existing handle {existing_handle}")
        # Update username header to mapped handle
        return existing_handle

    # 2. Check if a user with this username already exists (pre-created)
    existing = find_handle_by_username(username)
    if existing:
        handle = existing["handle"]
        log.info(f"Found pre-existing handle '{handle}' for username '{username}', stamping ssoUid={uid}")
        user = existing["user"]
        user["ssoUid"] = uid
        write_user_record(handle, user)
        return handle

    # 3. Auto-create new account
    handle = slugify(username)
    if not handle:
        log.warning(f"Cannot slugify username '{username}' to a valid handle")
        return None

    is_admin = any(g.strip() in ADMIN_GROUPS for g in groups.split(",")) if groups else False

    timeout = ClientTimeout(total=10)
    async with ClientSession(timeout=timeout) as session:
        # Get CSRF token first (sets session cookie)
        csrf = await st_get_csrf(session)
        if not csrf:
            log.error("Failed to get CSRF token from ST")
            return None

        # Login as admin
        if not await st_admin_login(session, csrf):
            log.error("Cannot auto-provision without admin session")
            return None

        # Get fresh CSRF after login (session changed)
        csrf = await st_get_csrf(session)

        # Create the user
        if not await st_create_user(session, csrf, handle, display_name or username, is_admin):
            return None

    # 4. Stamp the new user record with ssoUid
    user = read_user_record(handle)
    if user:
        user["ssoUid"] = uid
        write_user_record(handle, user)
    else:
        log.warning(f"User {handle} created but record not found for stamping")

    log.info(f"Auto-provisioned: uid={uid}, handle={handle}, admin={is_admin}")
    return handle


# ─── Proxy ───────────────────────────────────────────────────────────────────

# Headers that should NOT be forwarded as-is (we manipulate them)
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "host", "content-length",  # aiohttp recalculates
}

# Cache: uid → mapped handle (avoids scanning _storage on every request)
_UID_CACHE: dict[str, str] = {}
# Tracks uids we've already attempted provisioning for (even if failed)
_UID_TRIED: set[str] = set()
# Protect the first-login provisioning path from concurrent static/page requests
_PROVISION_LOCK = asyncio.Lock()

# Static file extensions — skip provisioning for these
_STATIC_EXTS = {".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                 ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".webm",
                 ".mp3", ".mp4", ".ogg", ".wav", ".json", ".xml", ".txt",
                 ".wasm", ".worker.js"}

def is_static_request(path: str) -> bool:
    """Check if this is a static resource request (skip SSO logic)."""
    for ext in _STATIC_EXTS:
        if path.endswith(ext):
            return True
    # API calls that don't need SSO header rewriting
    if path.startswith("/api/"):
        return True
    if path.startswith("/outpost.goauthentik.io"):
        return True
    return False

async def handle_request(request: web.Request) -> web.StreamResponse:
    """Transparent proxy: inject mapped username, forward everything else."""
    path = request.rel_url.path

    # Build outgoing headers
    out_headers = {}
    for key, val in request.headers.items():
        if key.lower() in _HOP_BY_HOP:
            continue
        if key in out_headers:
            # Multi-valued header — comma-join
            out_headers[key] += ", " + val
        else:
            out_headers[key] = val

    # SSO mapping: only for page loads (not static/API), and only once per uid
    uid = request.headers.get("X-Authentik-Uid", "")
    username = request.headers.get("X-Authentik-Username", "")

    if uid and username and not is_static_request(path):
        if uid in _UID_CACHE:
            out_headers["X-Authentik-Username"] = _UID_CACHE[uid]
            log.debug(f"Cache hit: uid={uid} → handle={_UID_CACHE[uid]}")
        elif uid not in _UID_TRIED:
            async with _PROVISION_LOCK:
                # Another request may have completed provisioning while we waited.
                if uid in _UID_CACHE:
                    out_headers["X-Authentik-Username"] = _UID_CACHE[uid]
                elif uid not in _UID_TRIED:
                    _UID_TRIED.add(uid)
                    display_name = request.headers.get("X-Authentik-Name", "")
                    groups = request.headers.get("X-Authentik-Groups", "")
                    try:
                        mapped_handle = await ensure_user(uid, username, display_name, groups)
                        if mapped_handle:
                            _UID_CACHE[uid] = mapped_handle
                            out_headers["X-Authentik-Username"] = mapped_handle
                            log.info(f"Provisioned: uid={uid} username={username} → handle={mapped_handle}")
                        else:
                            log.warning(f"Provisioning failed for uid={uid} username={username}")
                    except Exception as e:
                        log.error(f"Provisioning exception for uid={uid}: {e}")
        else:
            # Already tried and failed — pass through with original username
            log.debug(f"Already tried uid={uid}, passing through")
    elif uid and username and is_static_request(path):
        # For static requests, still rewrite if we have a cached mapping
        if uid in _UID_CACHE:
            out_headers["X-Authentik-Username"] = _UID_CACHE[uid]

    # Read body
    body = await request.read()

    # Forward to ST
    target_url = f"{ST_BACKEND}{request.rel_url.path_qs}"
    timeout = ClientTimeout(total=120, sock_connect=10, sock_read=120)

    # Use a session with cookie_jar=None to avoid swallowing Set-Cookie headers
    # from upstream. We pass them through manually in the response.
    async with ClientSession(timeout=timeout, auto_decompress=False, cookie_jar=None) as fwd_session:
        async with fwd_session.request(
            method=request.method,
            url=target_url,
            headers=out_headers,
            data=body,
            allow_redirects=False,
        ) as upstream:
            # Build response
            resp = web.StreamResponse(
                status=upstream.status,
                reason=upstream.reason,
            )
            # Copy headers (skip hop-by-hop) — use .add() for multi-valued headers
            # like Set-Cookie (using .[]= overwrites previous values)
            for key, val in upstream.headers.items():
                if key.lower() in _HOP_BY_HOP:
                    continue
                resp.headers.add(key, val)

            await resp.prepare(request)
            async for chunk in upstream.content.iter_any():
                await resp.write(chunk)
            await resp.write_eof()
            return resp


async def health(request: web.Request) -> web.Response:
    return web.json_response({
        "status": "ok",
        "st_backend": ST_BACKEND,
    })


def main():
    app = web.Application(client_max_size=100 * 1024 * 1024)  # 100MB
    app.router.add_get("/_sso_health", health)
    app.router.add_route("*", "/{tail:.*}", handle_request)

    log.info(f"SSO sidecar starting on :{LISTEN_PORT} → {ST_BACKEND}")
    log.info(f"Admin handle: {ADMIN_HANDLE}, Admin groups: {ADMIN_GROUPS}")
    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT, access_log=None)


if __name__ == "__main__":
    main()
