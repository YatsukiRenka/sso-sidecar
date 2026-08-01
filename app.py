#!/usr/bin/env python3
"""Secure Authentik-to-SillyTavern SSO sidecar and narrow LLM API relay."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
import unicodedata
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, TypeVar
from urllib.parse import urlsplit

from aiohttp import (
    ClientError,
    ClientSession,
    ClientTimeout,
    CookieJar,
    DummyCookieJar,
    web,
)
from multidict import CIMultiDict

VERSION = "0.2.0"
ConfigurationValue = TypeVar("ConfigurationValue")
CONFIGURATION_PARSE_ERRORS: list[str] = []
CONFIGURATION_INVALID_NAMES: set[str] = set()


def _load_configuration_value(
    name: str,
    loader: Callable[[], ConfigurationValue],
    fallback: ConfigurationValue,
) -> ConfigurationValue:
    """Collect import-time configuration errors for one clean startup failure."""
    try:
        return loader()
    except ValueError as exc:
        CONFIGURATION_PARSE_ERRORS.append(str(exc))
        CONFIGURATION_INVALID_NAMES.add(name)
        return fallback


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def env_log_level(name: str, default: str) -> str:
    value = os.getenv(name, default).strip().upper()
    if value not in logging.getLevelNamesMapping():
        raise ValueError(f"{name} must name a standard Python logging level")
    return value


def csv_values(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def env_secret(name: str) -> str:
    """Read a secret from NAME or NAME_FILE, never both."""
    value = os.getenv(name)
    file_path = os.getenv(f"{name}_FILE")
    if value is not None and file_path:
        raise ValueError(f"set only one of {name} and {name}_FILE")
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return file.read().rstrip("\r\n")
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"cannot read {name}_FILE: {exc}") from exc
    return value or ""


def parse_trusted_networks(value: str) -> tuple[ipaddress._BaseNetwork, ...]:
    return tuple(ipaddress.ip_network(item, strict=False) for item in csv_values(value))


# SillyTavern connection and account provisioning.
ST_BACKEND = os.getenv("ST_BACKEND", "http://sillytavern:8000").rstrip("/")
LISTEN_PORT = _load_configuration_value(
    "LISTEN_PORT", lambda: env_int("LISTEN_PORT", 8001), 8001
)
ADMIN_HANDLE = os.getenv("ADMIN_HANDLE", "admin").strip()
ADMIN_PASSWORD = _load_configuration_value(
    "ADMIN_PASSWORD", lambda: env_secret("ADMIN_PASSWORD"), ""
)
USER_PASSWORD_SECRET = _load_configuration_value(
    "USER_PASSWORD_SECRET", lambda: env_secret("USER_PASSWORD_SECRET"), ""
)
ADMIN_GROUPS = frozenset(csv_values(os.getenv("ADMIN_GROUPS", "admins,staff")))
AUTO_PROVISION = _load_configuration_value(
    "AUTO_PROVISION", lambda: env_bool("AUTO_PROVISION", True), True
)
ALLOW_USERNAME_LINKING = _load_configuration_value(
    "ALLOW_USERNAME_LINKING",
    lambda: env_bool("ALLOW_USERNAME_LINKING", False),
    False,
)

# Authentik is trusted only when its TCP source address is explicitly listed.
TRUSTED_PROXY_CIDRS = os.getenv("TRUSTED_PROXY_CIDRS", "")
try:
    TRUSTED_PROXY_NETWORKS = parse_trusted_networks(TRUSTED_PROXY_CIDRS)
    TRUSTED_PROXY_ERROR = ""
except ValueError as exc:
    TRUSTED_PROXY_NETWORKS = ()
    TRUSTED_PROXY_ERROR = str(exc)

# Read-only legacy data access is used only to migrate old ssoUid records.
ST_DATA_DIR = os.getenv("ST_DATA_DIR", "/st-data/data")
STATE_FILE = os.getenv("STATE_FILE", "/var/lib/sso-sidecar/mappings.json")

# Narrow, service-authenticated OpenAI-compatible relay.
API_PROXY_ENABLED = _load_configuration_value(
    "API_PROXY_ENABLED", lambda: env_bool("API_PROXY_ENABLED", True), True
)
API_BASE_URL = os.getenv("API_BASE_URL", "https://api.example.com/v1").rstrip("/")
API_KEY = _load_configuration_value("API_KEY", lambda: env_secret("API_KEY"), "")
API_PROXY_TOKEN = _load_configuration_value(
    "API_PROXY_TOKEN", lambda: env_secret("API_PROXY_TOKEN"), ""
)
ALLOWED_MODELS = csv_values(os.getenv("ALLOWED_MODELS", "deepseek-v4-flash"))
ALLOWED_MODEL_SET = frozenset(ALLOWED_MODELS)
DEFAULT_MODEL = os.getenv(
    "DEFAULT_MODEL",
    ALLOWED_MODELS[0] if ALLOWED_MODELS else "deepseek-v4-flash",
).strip()
# SillyTavern calls custom endpoints server-side, so this should be an internal URL.
API_URL_FOR_USERS = os.getenv("ST_API_BASE", "http://sso-sidecar:8001/v1").rstrip("/")
API_MAX_BODY_BYTES = _load_configuration_value(
    "API_MAX_BODY_BYTES",
    lambda: env_int("API_MAX_BODY_BYTES", 10 * 1024 * 1024),
    10 * 1024 * 1024,
)
SSO_MAX_BODY_BYTES = _load_configuration_value(
    "SSO_MAX_BODY_BYTES",
    lambda: env_int("SSO_MAX_BODY_BYTES", 500 * 1024 * 1024),
    500 * 1024 * 1024,
)
UID_CACHE_TTL = _load_configuration_value(
    "UID_CACHE_TTL", lambda: env_int("UID_CACHE_TTL", 300), 300
)
SSO_BINDING_COOKIE_SECURE = _load_configuration_value(
    "SSO_BINDING_COOKIE_SECURE",
    lambda: env_bool("SSO_BINDING_COOKIE_SECURE", True),
    True,
)
LOG_LEVEL = _load_configuration_value(
    "LOG_LEVEL", lambda: env_log_level("LOG_LEVEL", "INFO"), "INFO"
)

SLUG_RE = re.compile(r"[^a-z0-9]+")
SAFE_UID_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,512}$")
HEX_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
SSO_BINDING_COOKIE_NAME = "sso-sidecar-binding"
SSO_BINDING_COOKIE_MAX_AGE = 400 * 24 * 60 * 60
ST_SESSION_COOKIE_RE = re.compile(r"^session-[a-f0-9]{8}(?:\.sig)?$", re.IGNORECASE)

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [SSO] %(levelname)s %(message)s",
)
log = logging.getLogger("sso-sidecar")


class StateError(RuntimeError):
    """The sidecar mapping state is invalid or unavailable."""


class ProvisioningError(RuntimeError):
    """SillyTavern provisioning failed and may be retried."""


class IdentityConflict(RuntimeError):
    """An SSO identity would take over or collide with another account."""


@dataclass(frozen=True)
class MappingRecord:
    handle: str
    provisioned: bool
    managed: bool
    api_config_digest: str


@dataclass(frozen=True)
class CachedIdentity:
    handle: str
    expected_admin: bool
    expires_at: float


@dataclass
class BodyStreamState:
    actual_size: int = 0
    exceeded_limit: bool = False


@dataclass
class ProvisionLockEntry:
    lock: asyncio.Lock
    references: int = 0


UID_CACHE_KEY = web.AppKey("uid_cache", dict)
PROVISION_LOCKS_KEY = web.AppKey("provision_locks", dict)
_STATE_LOCK = threading.RLock()


@asynccontextmanager
async def _uid_provision_lock(
    application: web.Application,
    uid: str,
) -> AsyncIterator[None]:
    """Serialize one UID's reconciliation and reclaim idle lock entries."""
    locks: dict[str, ProvisionLockEntry] = application[PROVISION_LOCKS_KEY]
    entry = locks.get(uid)
    if entry is None:
        entry = ProvisionLockEntry(lock=asyncio.Lock())
        locks[uid] = entry
    entry.references += 1
    try:
        async with entry.lock:
            yield
    finally:
        entry.references -= 1
        if entry.references == 0 and locks.get(uid) is entry:
            locks.pop(uid, None)


def slugify(text: str) -> str:
    """Match SillyTavern's lodash-based handle slugification."""
    normalized = unicodedata.normalize("NFKD", text.strip().lower())
    normalized = "".join(
        character for character in normalized if not unicodedata.combining(character)
    )
    return SLUG_RE.sub("-", normalized).strip("-")


def storage_path(handle: str) -> str:
    """Return the legacy node-persist record path for a SillyTavern handle."""
    filename = hashlib.sha256(f"user:{handle}".encode()).hexdigest()
    return os.path.join(ST_DATA_DIR, "_storage", filename)


def _unwrap_user_record(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    value = raw.get("value", raw)
    return value if isinstance(value, dict) else None


def read_user_record(handle: str) -> dict[str, Any] | None:
    """Read a legacy SillyTavern user record without ever modifying it."""
    try:
        with open(storage_path(handle), "r", encoding="utf-8") as file:
            return _unwrap_user_record(json.load(file))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _iter_legacy_users() -> list[dict[str, Any]]:
    storage_dir = os.path.join(ST_DATA_DIR, "_storage")
    try:
        entries = list(os.scandir(storage_dir))
    except OSError:
        return []

    users: list[dict[str, Any]] = []
    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            continue
        try:
            with open(entry.path, "r", encoding="utf-8") as file:
                user = _unwrap_user_record(json.load(file))
            if user is not None:
                users.append(user)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
    return users


def _atomic_write_json(path: str, payload: dict[str, Any]) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.",
        dir=directory,
        text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2, sort_keys=True)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass


def _empty_state() -> dict[str, Any]:
    return {"version": 2, "mappings": {}}


def _validate_mapping_value(
    uid: Any,
    value: Any,
    source_version: int,
) -> dict[str, Any]:
    if not isinstance(uid, str) or not SAFE_UID_RE.fullmatch(uid):
        raise StateError("mapping state contains an invalid UID")

    if isinstance(value, str):
        value = {
            "handle": value,
            "provisioned": True,
            "managed": False,
            "api_config_digest": "",
        }
    if not isinstance(value, dict):
        raise StateError(f"mapping for UID {uid!r} is not an object")

    handle = value.get("handle")
    managed = value.get("managed", False)
    if source_version == 1:
        configured = value.get("configured", True)
        provisioned = configured if managed else True
        api_config_digest = ""
    else:
        provisioned = value.get("provisioned", True)
        api_config_digest = value.get("api_config_digest", "")

    if not isinstance(handle, str) or not handle or slugify(handle) != handle:
        raise StateError(f"mapping for UID {uid!r} has an invalid handle")
    if handle == ADMIN_HANDLE:
        raise StateError(
            f"mapping for UID {uid!r} targets the provisioning administrator"
        )
    if not isinstance(provisioned, bool) or not isinstance(managed, bool):
        raise StateError(f"mapping for UID {uid!r} has invalid flags")
    if not isinstance(api_config_digest, str) or (
        api_config_digest and not HEX_DIGEST_RE.fullmatch(api_config_digest)
    ):
        raise StateError(f"mapping for UID {uid!r} has an invalid API config digest")
    if not managed and not provisioned:
        raise StateError(f"unmanaged mapping for UID {uid!r} cannot be pending")
    if not managed and api_config_digest:
        raise StateError(
            f"unmanaged mapping for UID {uid!r} cannot own API configuration"
        )
    return {
        "handle": handle,
        "provisioned": provisioned,
        "managed": managed,
        "api_config_digest": api_config_digest,
    }


def _load_state_unlocked() -> dict[str, Any]:
    if not os.path.exists(STATE_FILE):
        return _empty_state()
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as file:
            raw = json.load(file)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise StateError(f"cannot read mapping state: {exc}") from exc

    if not isinstance(raw, dict):
        raise StateError("mapping state root is not an object")
    source_version = raw.get("version", 1)
    if source_version not in {1, 2}:
        raise StateError(f"unsupported mapping state version: {source_version!r}")

    raw_mappings = raw.get("mappings", raw.get("uid_to_handle", {}))
    if not isinstance(raw_mappings, dict):
        raise StateError("mapping state mappings field is not an object")

    mappings: dict[str, dict[str, Any]] = {}
    handles: dict[str, str] = {}
    for uid, value in raw_mappings.items():
        record = _validate_mapping_value(uid, value, source_version)
        other_uid = handles.get(record["handle"])
        if other_uid is not None and other_uid != uid:
            raise StateError(f"handle {record['handle']!r} is bound to multiple UIDs")
        mappings[uid] = record
        handles[record["handle"]] = uid
    return {"version": 2, "mappings": mappings}


def _record_from_value(value: dict[str, Any]) -> MappingRecord:
    return MappingRecord(
        handle=value["handle"],
        provisioned=value["provisioned"],
        managed=value["managed"],
        api_config_digest=value["api_config_digest"],
    )


def _legacy_handles_for_uid(uid: str) -> list[str]:
    handles = {
        user.get("handle")
        for user in _iter_legacy_users()
        if user.get("ssoUid") == uid and isinstance(user.get("handle"), str)
    }
    return sorted(handle for handle in handles if handle)


def legacy_uid_for_handle(handle: str) -> str | None:
    user = read_user_record(handle)
    uid = user.get("ssoUid") if user else None
    return uid if isinstance(uid, str) and uid else None


def find_mapping(uid: str) -> MappingRecord | None:
    """Read sidecar state and lazily import one unambiguous legacy ssoUid."""
    with _STATE_LOCK:
        state = _load_state_unlocked()
        value = state["mappings"].get(uid)
        if value is not None:
            return _record_from_value(value)

        legacy_handles = _legacy_handles_for_uid(uid)
        if len(legacy_handles) > 1:
            raise IdentityConflict("the legacy UID is bound to multiple handles")
        if not legacy_handles:
            return None
        return save_mapping(uid, legacy_handles[0], provisioned=True, managed=False)


def find_uid_by_handle(handle: str) -> str | None:
    with _STATE_LOCK:
        state = _load_state_unlocked()
        matches = [
            uid for uid, value in state["mappings"].items() if value["handle"] == handle
        ]
        if len(matches) > 1:
            raise StateError(f"handle {handle!r} is bound to multiple UIDs")
        if matches:
            return matches[0]
        return legacy_uid_for_handle(handle)


def save_mapping(
    uid: str,
    handle: str,
    *,
    provisioned: bool,
    managed: bool,
    api_config_digest: str = "",
) -> MappingRecord:
    if not SAFE_UID_RE.fullmatch(uid):
        raise IdentityConflict("the SSO UID has an invalid format")
    if not handle or slugify(handle) != handle:
        raise IdentityConflict("the SillyTavern handle is invalid")
    if handle == ADMIN_HANDLE:
        raise IdentityConflict("the provisioning administrator cannot be SSO-bound")

    with _STATE_LOCK:
        state = _load_state_unlocked()
        mappings = state["mappings"]
        existing = mappings.get(uid)
        if existing is not None and existing["handle"] != handle:
            raise IdentityConflict("the UID is already bound to another handle")
        for other_uid, value in mappings.items():
            if other_uid != uid and value["handle"] == handle:
                raise IdentityConflict("the handle is already bound to another UID")

        if existing is not None:
            provisioned = existing["provisioned"] or provisioned
            managed = existing["managed"]
            api_config_digest = existing["api_config_digest"] or api_config_digest
        value = {
            "handle": handle,
            "provisioned": provisioned,
            "managed": managed,
            "api_config_digest": api_config_digest,
        }
        mappings[uid] = _validate_mapping_value(uid, value, 2)
        _atomic_write_json(STATE_FILE, state)
        return _record_from_value(mappings[uid])


def mark_mapping_provisioned(
    uid: str,
    *,
    reset_api_config: bool,
) -> MappingRecord:
    with _STATE_LOCK:
        state = _load_state_unlocked()
        value = state["mappings"].get(uid)
        if value is None:
            raise StateError("cannot provision a missing UID mapping")
        if not value["managed"]:
            raise StateError("cannot provision an unmanaged UID mapping")
        value["provisioned"] = True
        if reset_api_config:
            value["api_config_digest"] = ""
        _atomic_write_json(STATE_FILE, state)
        return _record_from_value(value)


def mark_mapping_api_configured(uid: str, digest: str) -> MappingRecord:
    if not HEX_DIGEST_RE.fullmatch(digest):
        raise StateError("cannot store an invalid API config digest")
    with _STATE_LOCK:
        state = _load_state_unlocked()
        value = state["mappings"].get(uid)
        if value is None:
            raise StateError("cannot configure a missing UID mapping")
        if not value["managed"] or not value["provisioned"]:
            raise StateError("cannot configure an unmanaged or pending UID mapping")
        value["api_config_digest"] = digest
        _atomic_write_json(STATE_FILE, state)
        return _record_from_value(value)


def parse_authentik_groups(value: str) -> frozenset[str]:
    """Authentik serializes proxy groups with a pipe delimiter."""
    return frozenset(group.strip() for group in value.split("|") if group.strip())


def groups_grant_admin(value: str) -> bool:
    return bool(parse_authentik_groups(value) & ADMIN_GROUPS)


def derive_user_password(uid: str) -> str:
    digest = hmac.new(
        USER_PASSWORD_SECRET.encode("utf-8"),
        f"sso-sidecar:user:{uid}".encode(),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def identity_binding_token(uid: str) -> str:
    """Bind a browser's long-lived SillyTavern session to one stable SSO UID."""
    return hmac.new(
        USER_PASSWORD_SECRET.encode("utf-8"),
        f"sso-sidecar:browser:{uid}".encode(),
        hashlib.sha256,
    ).hexdigest()


def request_has_valid_identity_binding(request: web.Request, uid: str) -> bool:
    provided = request.cookies.get(SSO_BINDING_COOKIE_NAME, "")
    return bool(
        provided and secrets.compare_digest(provided, identity_binding_token(uid))
    )


def current_api_config_digest() -> str:
    payload = json.dumps(
        {
            "schema": 1,
            "url": API_URL_FOR_USERS,
            "default_model": DEFAULT_MODEL,
            "relay_token": API_PROXY_TOKEN,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def _safe_response_text(response: Any, limit: int = 300) -> str:
    try:
        return (await response.text())[:limit]
    except (ClientError, UnicodeError, LookupError):
        return "<unreadable response>"


async def st_get_csrf(session: ClientSession) -> str:
    try:
        async with session.get(f"{ST_BACKEND}/csrf-token") as response:
            if response.status != 200:
                body = await _safe_response_text(response)
                raise ProvisioningError(
                    f"SillyTavern CSRF request failed ({response.status}): {body}"
                )
            payload = await response.json(content_type=None)
    except (
        ClientError,
        asyncio.TimeoutError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise ProvisioningError(f"SillyTavern CSRF request failed: {exc}") from exc
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token:
        raise ProvisioningError("SillyTavern returned an invalid CSRF token")
    return token


async def st_login(
    session: ClientSession,
    csrf: str,
    handle: str,
    password: str,
) -> None:
    headers = {"Content-Type": "application/json", "x-csrf-token": csrf}
    try:
        async with session.post(
            f"{ST_BACKEND}/api/users/login",
            json={"handle": handle, "password": password},
            headers=headers,
        ) as response:
            if response.status != 200:
                body = await _safe_response_text(response)
                raise ProvisioningError(
                    f"SillyTavern login for {handle!r} failed "
                    f"({response.status}): {body}"
                )
    except (ClientError, asyncio.TimeoutError) as exc:
        raise ProvisioningError(
            f"SillyTavern login for {handle!r} failed: {exc}"
        ) from exc


async def st_verify_user_credentials(handle: str, password: str) -> None:
    """Confirm that an existing account is still owned by the sidecar."""
    timeout = ClientTimeout(total=15, sock_connect=5, sock_read=15)
    async with ClientSession(
        timeout=timeout,
        cookie_jar=CookieJar(unsafe=True),
    ) as session:
        csrf = await st_get_csrf(session)
        await st_login(session, csrf, handle, password)


@asynccontextmanager
async def st_admin_session() -> AsyncIterator[tuple[ClientSession, str]]:
    timeout = ClientTimeout(total=15, sock_connect=5, sock_read=15)
    async with ClientSession(
        timeout=timeout,
        cookie_jar=CookieJar(unsafe=True),
    ) as session:
        csrf = await st_get_csrf(session)
        await st_login(session, csrf, ADMIN_HANDLE, ADMIN_PASSWORD)
        csrf = await st_get_csrf(session)
        yield session, csrf


async def st_list_users(session: ClientSession, csrf: str) -> list[dict[str, Any]]:
    headers = {"Content-Type": "application/json", "x-csrf-token": csrf}
    try:
        async with session.post(
            f"{ST_BACKEND}/api/users/get",
            json={},
            headers=headers,
        ) as response:
            if response.status != 200:
                body = await _safe_response_text(response)
                raise ProvisioningError(
                    f"SillyTavern user list failed ({response.status}): {body}"
                )
            payload = await response.json(content_type=None)
    except (
        ClientError,
        asyncio.TimeoutError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise ProvisioningError(f"SillyTavern user list failed: {exc}") from exc
    if not isinstance(payload, list) or not all(
        isinstance(item, dict) for item in payload
    ):
        raise ProvisioningError("SillyTavern returned an invalid user list")
    return payload


async def st_create_user(
    session: ClientSession,
    csrf: str,
    handle: str,
    name: str,
    password: str,
    is_admin: bool,
) -> str:
    headers = {"Content-Type": "application/json", "x-csrf-token": csrf}
    body = {
        "handle": handle,
        "name": name,
        "password": password,
        "admin": is_admin,
    }
    try:
        async with session.post(
            f"{ST_BACKEND}/api/users/create",
            json=body,
            headers=headers,
        ) as response:
            if response.status != 200:
                response_body = await _safe_response_text(response)
                raise ProvisioningError(
                    f"SillyTavern user creation failed ({response.status}): "
                    f"{response_body}"
                )
            payload = await response.json(content_type=None)
    except (
        ClientError,
        asyncio.TimeoutError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise ProvisioningError(f"SillyTavern user creation failed: {exc}") from exc
    created_handle = payload.get("handle") if isinstance(payload, dict) else None
    if created_handle != handle:
        raise ProvisioningError("SillyTavern returned an unexpected created handle")
    log.info("Created managed SillyTavern account %r (admin=%s)", handle, is_admin)
    return handle


async def st_sync_admin_role(
    session: ClientSession,
    csrf: str,
    user: dict[str, Any],
    desired_admin: bool,
) -> None:
    handle = user.get("handle")
    if not isinstance(handle, str):
        raise ProvisioningError("SillyTavern returned a user without a handle")
    current_admin = bool(user.get("admin"))
    if current_admin == desired_admin:
        return
    action = "promote" if desired_admin else "demote"
    headers = {"Content-Type": "application/json", "x-csrf-token": csrf}
    try:
        async with session.post(
            f"{ST_BACKEND}/api/users/{action}",
            json={"handle": handle},
            headers=headers,
        ) as response:
            if response.status not in {200, 204}:
                body = await _safe_response_text(response)
                raise ProvisioningError(
                    f"SillyTavern {action} failed ({response.status}): {body}"
                )
    except (ClientError, asyncio.TimeoutError) as exc:
        raise ProvisioningError(f"SillyTavern {action} failed: {exc}") from exc
    log.info("Reconciled admin role for %r to %s", handle, desired_admin)


async def st_apply_default_api_config(uid: str, handle: str) -> None:
    """Configure a managed user through SillyTavern's authenticated APIs."""
    password = derive_user_password(uid)
    timeout = ClientTimeout(total=20, sock_connect=5, sock_read=20)
    async with ClientSession(
        timeout=timeout,
        cookie_jar=CookieJar(unsafe=True),
    ) as session:
        csrf = await st_get_csrf(session)
        await st_login(session, csrf, handle, password)
        csrf = await st_get_csrf(session)
        headers = {"Content-Type": "application/json", "x-csrf-token": csrf}

        try:
            async with session.post(
                f"{ST_BACKEND}/api/settings/get",
                json={},
                headers=headers,
            ) as response:
                if response.status != 200:
                    body = await _safe_response_text(response)
                    raise ProvisioningError(
                        f"SillyTavern settings read failed ({response.status}): {body}"
                    )
                payload = await response.json(content_type=None)
        except (
            ClientError,
            asyncio.TimeoutError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            raise ProvisioningError(f"SillyTavern settings read failed: {exc}") from exc

        raw_settings = payload.get("settings") if isinstance(payload, dict) else None
        try:
            settings = (
                json.loads(raw_settings)
                if isinstance(raw_settings, str)
                else raw_settings
            )
        except json.JSONDecodeError as exc:
            raise ProvisioningError(
                "SillyTavern returned invalid settings JSON"
            ) from exc
        if not isinstance(settings, dict):
            raise ProvisioningError("SillyTavern returned invalid settings")

        oai_settings = settings.get("oai_settings")
        if not isinstance(oai_settings, dict):
            oai_settings = {}
            settings["oai_settings"] = oai_settings
        oai_settings["chat_completion_source"] = "custom"
        oai_settings["custom_url"] = API_URL_FOR_USERS
        oai_settings["custom_model"] = DEFAULT_MODEL
        oai_settings["openai_model"] = DEFAULT_MODEL
        settings["main_api"] = "openai"

        try:
            async with session.post(
                f"{ST_BACKEND}/api/settings/save",
                json=settings,
                headers=headers,
            ) as response:
                if response.status != 200:
                    body = await _safe_response_text(response)
                    raise ProvisioningError(
                        f"SillyTavern settings write failed ({response.status}): {body}"
                    )
                result = await response.json(content_type=None)
                if not isinstance(result, dict) or result.get("result") != "ok":
                    raise ProvisioningError(
                        "SillyTavern did not confirm the settings write"
                    )
            async with session.post(
                f"{ST_BACKEND}/api/secrets/write",
                json={
                    "key": "api_key_custom",
                    "value": API_PROXY_TOKEN,
                    "label": "SSO sidecar relay",
                },
                headers=headers,
            ) as response:
                if response.status != 200:
                    body = await _safe_response_text(response)
                    raise ProvisioningError(
                        f"SillyTavern secret write failed ({response.status}): {body}"
                    )
                result = await response.json(content_type=None)
                if not isinstance(result, dict) or not isinstance(
                    result.get("id"), str
                ):
                    raise ProvisioningError(
                        "SillyTavern did not confirm the secret write"
                    )
        except (
            ClientError,
            asyncio.TimeoutError,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ) as exc:
            raise ProvisioningError(
                f"SillyTavern default configuration failed: {exc}"
            ) from exc
    log.info("Applied default API configuration for %r", handle)


async def ensure_user(
    uid: str,
    username: str,
    display_name: str,
    groups: str,
) -> str:
    """Resolve, safely link, or provision one Authentik identity."""
    if not SAFE_UID_RE.fullmatch(uid):
        raise IdentityConflict("the SSO UID has an invalid format")

    desired_admin = groups_grant_admin(groups)
    record = await asyncio.to_thread(find_mapping, uid)
    if record is not None and record.handle == ADMIN_HANDLE:
        raise IdentityConflict("the provisioning administrator cannot be SSO-bound")
    handle_from_username = slugify(username) if record is None else ""
    if record is None and not handle_from_username:
        raise IdentityConflict("the SSO username cannot form a valid handle")

    async with st_admin_session() as (session, csrf):
        users = await st_list_users(session, csrf)
        users_by_handle = {
            item.get("handle"): item
            for item in users
            if isinstance(item.get("handle"), str)
        }

        if record is not None:
            handle = record.handle
            user = users_by_handle.get(handle)
            if user is None:
                if not record.managed:
                    raise IdentityConflict(
                        "the mapped SillyTavern account no longer exists"
                    )
                if not AUTO_PROVISION:
                    raise ProvisioningError("automatic provisioning is disabled")
                await st_create_user(
                    session,
                    csrf,
                    handle,
                    display_name or username,
                    derive_user_password(uid),
                    desired_admin,
                )
                user = {"handle": handle, "enabled": True, "admin": desired_admin}
                record = await asyncio.to_thread(
                    mark_mapping_provisioned,
                    uid,
                    reset_api_config=True,
                )
            else:
                if not bool(user.get("enabled", True)):
                    raise IdentityConflict("the mapped SillyTavern account is disabled")
                if record.managed:
                    await st_verify_user_credentials(
                        handle,
                        derive_user_password(uid),
                    )
                    if not record.provisioned:
                        record = await asyncio.to_thread(
                            mark_mapping_provisioned,
                            uid,
                            reset_api_config=True,
                        )
            await st_sync_admin_role(session, csrf, user, desired_admin)
        else:
            handle = handle_from_username
            if handle == ADMIN_HANDLE:
                raise IdentityConflict(
                    "the SSO username collides with the administrator"
                )

            bound_uid = await asyncio.to_thread(find_uid_by_handle, handle)
            if bound_uid is not None and bound_uid != uid:
                raise IdentityConflict(
                    "the requested handle belongs to another SSO identity"
                )

            user = users_by_handle.get(handle)
            if user is not None:
                if not bool(user.get("enabled", True)):
                    raise IdentityConflict(
                        "the matching SillyTavern account is disabled"
                    )
                if bound_uid != uid and not ALLOW_USERNAME_LINKING:
                    raise IdentityConflict(
                        "the matching account is unbound and username linking is disabled"
                    )
                record = await asyncio.to_thread(
                    save_mapping,
                    uid,
                    handle,
                    provisioned=True,
                    managed=False,
                )
                await st_sync_admin_role(session, csrf, user, desired_admin)
                log.info("Linked existing SillyTavern account %r", handle)
                return handle

            if not AUTO_PROVISION:
                raise ProvisioningError("automatic provisioning is disabled")

            # Persist a pending managed mapping before the network mutation. If
            # the create response is lost, a retry can verify ownership using
            # the deterministic high-entropy account password.
            record = await asyncio.to_thread(
                save_mapping,
                uid,
                handle,
                provisioned=False,
                managed=True,
            )
            await st_create_user(
                session,
                csrf,
                handle,
                display_name or username,
                derive_user_password(uid),
                desired_admin,
            )
            record = await asyncio.to_thread(
                mark_mapping_provisioned,
                uid,
                reset_api_config=True,
            )

    if record.managed and API_PROXY_ENABLED:
        desired_config_digest = current_api_config_digest()
        if record.api_config_digest != desired_config_digest:
            await st_apply_default_api_config(uid, handle)
            await asyncio.to_thread(
                mark_mapping_api_configured,
                uid,
                desired_config_digest,
            )

    log.info("Resolved SSO identity to SillyTavern handle %r", handle)
    return handle


_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
}

_AUTO_DECOMPRESSED_ENCODINGS = frozenset({"gzip", "deflate", "br", "zstd"})
_DECODED_BODY_INTEGRITY_HEADERS = frozenset(
    {"content-md5", "digest", "content-digest", "repr-digest"}
)

_AUTHENTIK_HEADERS = (
    "X-Authentik-Uid",
    "X-Authentik-Email",
    "X-Authentik-Name",
    "X-Authentik-Groups",
    "X-Authentik-Entitlements",
    "X-Authentik-Meta-Outpost",
    "X-Authentik-Meta-Provider",
    "X-Authentik-Meta-App",
    "X-Authentik-Meta-Version",
)

# Browser-facing account access is fail-closed. These self-service routes were
# verified against SillyTavern release commit 8172dcd0ee67 (2026-07-07).
_ALLOWED_BROWSER_ACCOUNT_PATHS = frozenset(
    {
        "/api/users/me",
        "/api/users/logout",
        "/api/users/backup",
        "/api/users/change-avatar",
        "/api/users/change-name",
        "/api/users/reset-settings",
        "/api/users/reset-step1",
        "/api/users/reset-step2",
    }
)

# Never let browser-supplied alternative identity assertions reach the trusted
# SillyTavern hop. Authentik's own headers are stripped separately and then
# rebuilt below from the normalized identity.
_UNTRUSTED_IDENTITY_HEADERS = frozenset(
    {
        "x-forwarded-user",
        "x-forwarded-email",
        "x-forwarded-name",
        "x-forwarded-groups",
        "x-forwarded-preferred-username",
    }
)
_UNTRUSTED_IDENTITY_HEADER_PREFIXES = (
    "remote-",
    "x-remote-",
    "x-auth-request-",
)

_API_ROUTE_METHODS = {
    "/v1/models": frozenset({"GET"}),
    "/v1/chat/completions": frozenset({"POST"}),
    "/v1/completions": frozenset({"POST"}),
}

_API_SUFFIXES = {
    "/v1/models": "/models",
    "/v1/chat/completions": "/chat/completions",
    "/v1/completions": "/completions",
}


def is_trusted_proxy(request: web.Request) -> bool:
    remote = request.remote
    if not remote:
        return False
    try:
        address = ipaddress.ip_address(remote.split("%", 1)[0])
    except ValueError:
        return False
    candidates = [address]
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        candidates.append(address.ipv4_mapped)
    return any(
        candidate.version == network.version and candidate in network
        for candidate in candidates
        for network in TRUSTED_PROXY_NETWORKS
    )


def _bearer_token(request: web.Request) -> str | None:
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def _api_auth_valid(request: web.Request) -> bool:
    provided = _bearer_token(request)
    return bool(
        provided
        and API_PROXY_TOKEN
        and secrets.compare_digest(provided, API_PROXY_TOKEN)
    )


def _reject_nonstandard_json(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


async def _read_limited_body(request: web.Request, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.content.iter_chunked(64 * 1024):
        total += len(chunk)
        if total > limit:
            raise web.HTTPRequestEntityTooLarge(max_size=limit, actual_size=total)
        chunks.append(chunk)
    return b"".join(chunks)


async def _stream_limited_body(
    request: web.Request,
    limit: int,
    state: BodyStreamState,
) -> AsyncIterator[bytes]:
    """Stream an automatically decoded request body while enforcing its limit."""
    async for chunk in request.content.iter_chunked(64 * 1024):
        state.actual_size += len(chunk)
        if state.actual_size > limit:
            state.exceeded_limit = True
            raise ValueError("request body exceeds SSO_MAX_BODY_BYTES")
        yield chunk


def _connection_header_names(headers: Any) -> set[str]:
    """Return hop-by-hop field names nominated by Connection headers."""
    names: set[str] = set()
    for value in headers.getall("Connection", ()):
        names.update(
            token.strip().lower() for token in value.split(",") if token.strip()
        )
    return names


def _request_body_was_auto_decompressed(request: web.Request) -> bool:
    content_encoding = request.headers.get("Content-Encoding", "").strip().lower()
    return content_encoding in _AUTO_DECOMPRESSED_ENCODINGS


def _response_sets_st_session_cookie(headers: Any) -> bool:
    """Recognize SillyTavern's hostname-scoped cookie-session cookies."""
    return any(
        ST_SESSION_COOKIE_RE.fullmatch(value.partition("=")[0].strip())
        for value in headers.getall("Set-Cookie", ())
    )


def _normalized_route_path(path: str) -> str:
    """Normalize decoded paths like Express's case-insensitive route matching."""
    segments: list[str] = []
    for segment in path.split("/"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return ("/" + "/".join(segments)).lower()


def _same_origin_relative_location(location: str, origin: str) -> str:
    """Hide an internal origin in absolute redirects emitted by a backend."""
    try:
        target = urlsplit(location)
        backend = urlsplit(origin)
        backend_scheme = backend.scheme.lower()
        # A network-path reference (//host/path) inherits the browser's scheme.
        # Use the configured backend scheme solely for same-origin comparison.
        target_scheme = target.scheme.lower() or backend_scheme
        target_port = target.port
        if target_port is None:
            target_port = {"http": 80, "https": 443}.get(target_scheme)
        backend_port = backend.port
        if backend_port is None:
            backend_port = {"http": 80, "https": 443}.get(backend_scheme)
    except ValueError:
        return location

    target_origin = (
        target_scheme,
        (target.hostname or "").lower().rstrip("."),
        target_port,
    )
    backend_origin = (
        backend_scheme,
        (backend.hostname or "").lower().rstrip("."),
        backend_port,
    )
    if not target.netloc or target_origin != backend_origin:
        return location

    path = target.path or "/"
    # A Location beginning with // is a network-path reference. Prefixing /.
    # keeps it on the browser's current origin while retaining the path.
    if path.startswith("//"):
        path = f"/.{path}"
    if target.query:
        path = f"{path}?{target.query}"
    if target.fragment:
        path = f"{path}#{target.fragment}"
    return path


async def _copy_upstream_response(
    request: web.Request,
    upstream: Any,
    *,
    strip_cookies: bool,
    identity_binding: str | None = None,
    identity_binding_confirmed: bool = False,
    rewrite_location_origin: str | None = None,
) -> web.StreamResponse:
    response = web.StreamResponse(status=upstream.status, reason=upstream.reason)
    blocked_headers = _HOP_BY_HOP | _connection_header_names(upstream.headers)
    for key, value in upstream.headers.items():
        lower = key.lower()
        if lower in blocked_headers or (strip_cookies and lower == "set-cookie"):
            continue
        if lower == "location" and rewrite_location_origin is not None:
            value = _same_origin_relative_location(value, rewrite_location_origin)
        response.headers.add(key, value)
    if identity_binding is not None and (
        identity_binding_confirmed or _response_sets_st_session_cookie(upstream.headers)
    ):
        response.set_cookie(
            SSO_BINDING_COOKIE_NAME,
            identity_binding,
            max_age=SSO_BINDING_COOKIE_MAX_AGE,
            httponly=True,
            secure=SSO_BINDING_COOKIE_SECURE,
            samesite="Lax",
            path="/",
        )
    await response.prepare(request)
    async for chunk in upstream.content.iter_any():
        await response.write(chunk)
    await response.write_eof()
    return response


async def handle_api_proxy(request: web.Request) -> web.StreamResponse:
    if not API_PROXY_ENABLED:
        raise web.HTTPNotFound()
    if not _api_auth_valid(request):
        return web.json_response(
            {"error": {"message": "API relay authentication failed"}},
            status=401,
            headers={"WWW-Authenticate": "Bearer"},
        )

    path = request.path
    allowed_methods = _API_ROUTE_METHODS.get(path)
    if allowed_methods is None:
        raise web.HTTPNotFound()
    if request.method not in allowed_methods:
        return web.json_response(
            {"error": {"message": "Method not allowed"}},
            status=405,
            headers={"Allow": ", ".join(sorted(allowed_methods))},
        )
    if request.query_string:
        return web.json_response(
            {"error": {"message": "Query parameters are not supported"}},
            status=400,
        )

    if path == "/v1/models":
        return web.json_response(
            {
                "object": "list",
                "data": [
                    {
                        "id": model,
                        "object": "model",
                        "created": 0,
                        "owned_by": "sso-sidecar",
                    }
                    for model in ALLOWED_MODELS
                ],
            }
        )

    body = b""
    if request.method == "POST":
        if request.content_type != "application/json":
            return web.json_response(
                {"error": {"message": "Content-Type must be application/json"}},
                status=415,
            )
        if (
            request.content_length is not None
            and not _request_body_was_auto_decompressed(request)
            and request.content_length > API_MAX_BODY_BYTES
        ):
            raise web.HTTPRequestEntityTooLarge(
                max_size=API_MAX_BODY_BYTES,
                actual_size=request.content_length,
            )
        body = await _read_limited_body(request, API_MAX_BODY_BYTES)
        try:
            payload = json.loads(body, parse_constant=_reject_nonstandard_json)
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            ValueError,
            RecursionError,
        ):
            return web.json_response(
                {"error": {"message": "Request body must be valid JSON"}},
                status=400,
            )
        if not isinstance(payload, dict):
            return web.json_response(
                {"error": {"message": "Request JSON must be an object"}},
                status=400,
            )
        model = payload.get("model")
        if not isinstance(model, str) or not model:
            return web.json_response(
                {"error": {"message": "A model is required"}},
                status=400,
            )
        if model not in ALLOWED_MODEL_SET:
            log.warning("Blocked disallowed model %r", model)
            return web.json_response(
                {
                    "error": {
                        "message": "The requested model is not allowed",
                        "allowed_models": list(ALLOWED_MODELS),
                    }
                },
                status=400,
            )
        try:
            body = json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (ValueError, RecursionError):
            return web.json_response(
                {"error": {"message": "Request body must be valid JSON"}},
                status=400,
            )

    outbound_headers = CIMultiDict()
    for name in ("Accept", "Content-Type", "User-Agent", "X-Request-Id"):
        value = request.headers.get(name)
        if value:
            outbound_headers[name] = value
    if request.method == "POST":
        outbound_headers["Content-Type"] = "application/json"
    outbound_headers["Authorization"] = f"Bearer {API_KEY}"

    target_url = f"{API_BASE_URL}{_API_SUFFIXES[path]}"
    timeout = ClientTimeout(total=300, sock_connect=15, sock_read=300)
    try:
        async with (
            ClientSession(
                timeout=timeout,
                auto_decompress=False,
                cookie_jar=DummyCookieJar(),
            ) as session,
            session.request(
                method=request.method,
                url=target_url,
                headers=outbound_headers,
                data=body or None,
                allow_redirects=False,
            ) as upstream,
        ):
            return await _copy_upstream_response(
                request,
                upstream,
                strip_cookies=True,
            )
    except asyncio.TimeoutError:
        return web.json_response(
            {"error": {"message": "Upstream API timed out"}}, status=504
        )
    except ClientError as exc:
        log.error("Upstream API request failed: %s", exc)
        return web.json_response(
            {"error": {"message": "Upstream API is unavailable"}}, status=502
        )


def _backend_cookie_header(request: web.Request) -> str:
    segments: list[str] = []
    for raw_value in request.headers.getall("Cookie", ()):
        for raw_segment in raw_value.split(";"):
            segment = raw_segment.strip()
            name, separator, _value = segment.partition("=")
            if not segment or (separator and name.strip() == SSO_BINDING_COOKIE_NAME):
                continue
            segments.append(segment)
    return "; ".join(segments)


def _build_st_headers(
    request: web.Request,
    mapped_handle: str,
    *,
    forward_cookies: bool,
) -> CIMultiDict[str]:
    headers: CIMultiDict[str] = CIMultiDict()
    blocked_headers = _HOP_BY_HOP | _connection_header_names(request.headers)
    # aiohttp automatically decodes recognized request encodings before the
    # handler sees the body. Do not label the decoded stream as compressed.
    if _request_body_was_auto_decompressed(request):
        blocked_headers.update({"content-encoding"} | _DECODED_BODY_INTEGRITY_HEADERS)
    for key, value in request.headers.items():
        lower = key.lower()
        if (
            lower in blocked_headers
            or lower in {"authorization", "cookie"}
            or lower.startswith("x-authentik-")
            or lower in _UNTRUSTED_IDENTITY_HEADERS
            or lower.startswith(_UNTRUSTED_IDENTITY_HEADER_PREFIXES)
        ):
            continue
        headers.add(key, value)
    if forward_cookies:
        cookie_header = _backend_cookie_header(request)
        if cookie_header:
            headers["Cookie"] = cookie_header
    for name in _AUTHENTIK_HEADERS:
        value = request.headers.get(name)
        if value:
            headers[name] = value
    headers["X-Authentik-Username"] = mapped_handle
    return headers


async def _resolve_request_identity(request: web.Request) -> str:
    uid = request.headers.get("X-Authentik-Uid", "").strip()
    username = request.headers.get("X-Authentik-Username", "").strip()
    if not uid or not username:
        raise web.HTTPUnauthorized(
            text=json.dumps({"error": "Missing Authentik identity headers"}),
            content_type="application/json",
        )

    groups = request.headers.get("X-Authentik-Groups", "")
    expected_admin = groups_grant_admin(groups)
    now = time.monotonic()
    cache: dict[str, CachedIdentity] = request.app[UID_CACHE_KEY]
    cached = cache.get(uid)
    if (
        cached is not None
        and cached.expires_at > now
        and cached.expected_admin == expected_admin
    ):
        return cached.handle

    async with _uid_provision_lock(request.app, uid):
        now = time.monotonic()
        for cached_uid, cached_identity in tuple(cache.items()):
            if cached_identity.expires_at <= now:
                cache.pop(cached_uid, None)
        cached = cache.get(uid)
        if (
            cached is not None
            and cached.expires_at > now
            and cached.expected_admin == expected_admin
        ):
            return cached.handle
        try:
            handle = await ensure_user(
                uid,
                username,
                request.headers.get("X-Authentik-Name", "").strip(),
                groups,
            )
        except IdentityConflict as exc:
            log.warning("Rejected SSO identity conflict: %s", exc)
            raise web.HTTPConflict(
                text=json.dumps(
                    {
                        "error": "SSO identity conflicts with an existing account; "
                        "contact an administrator"
                    }
                ),
                content_type="application/json",
            ) from exc
        except Exception as exc:
            log.exception("SSO provisioning failed")
            raise web.HTTPServiceUnavailable(
                text=json.dumps(
                    {"error": "SSO account provisioning failed; retry later"}
                ),
                content_type="application/json",
                headers={"Retry-After": "5"},
            ) from exc
        cache[uid] = CachedIdentity(
            handle=handle,
            expected_admin=expected_admin,
            expires_at=time.monotonic() + UID_CACHE_TTL,
        )
        return handle


async def handle_request(request: web.Request) -> web.StreamResponse:
    path = request.path
    if path == "/v1" or path.startswith("/v1/"):
        return await handle_api_proxy(request)

    if not is_trusted_proxy(request):
        return web.json_response(
            {"error": "Request did not originate from a trusted Authentik proxy"},
            status=403,
        )

    uid = request.headers.get("X-Authentik-Uid", "").strip()
    username = request.headers.get("X-Authentik-Username", "").strip()
    if not uid or not username:
        return web.json_response(
            {"error": "Missing Authentik identity headers"}, status=401
        )

    # The sidecar calls these directly on the isolated backend. They are never
    # exposed through the browser-facing SSO proxy.
    account_path = _normalized_route_path(path)
    if account_path == "/api/users" or (
        account_path.startswith("/api/users/")
        and account_path not in _ALLOWED_BROWSER_ACCOUNT_PATHS
    ):
        raise web.HTTPNotFound()

    mapped_handle = await _resolve_request_identity(request)
    forward_cookies = request_has_valid_identity_binding(request, uid)
    if request.headers.get("Cookie") and not forward_cookies:
        log.info("Discarded a stale or unbound SillyTavern browser session")
    headers = _build_st_headers(
        request,
        mapped_handle,
        forward_cookies=forward_cookies,
    )
    if (
        request.content_length is not None
        and not _request_body_was_auto_decompressed(request)
        and request.content_length > SSO_MAX_BODY_BYTES
    ):
        raise web.HTTPRequestEntityTooLarge(
            max_size=SSO_MAX_BODY_BYTES,
            actual_size=request.content_length,
        )
    body_state = BodyStreamState()
    body = (
        _stream_limited_body(request, SSO_MAX_BODY_BYTES, body_state)
        if request.can_read_body
        else None
    )
    target_url = f"{ST_BACKEND}{request.raw_path}"
    timeout = ClientTimeout(total=120, sock_connect=10, sock_read=120)
    try:
        async with (
            ClientSession(
                timeout=timeout,
                auto_decompress=False,
                cookie_jar=DummyCookieJar(),
            ) as session,
            session.request(
                method=request.method,
                url=target_url,
                headers=headers,
                data=body or None,
                allow_redirects=False,
            ) as upstream,
        ):
            return await _copy_upstream_response(
                request,
                upstream,
                strip_cookies=False,
                identity_binding=identity_binding_token(uid),
                identity_binding_confirmed=forward_cookies,
                rewrite_location_origin=ST_BACKEND,
            )
    except asyncio.TimeoutError:
        return web.json_response({"error": "SillyTavern timed out"}, status=504)
    except ClientError as exc:
        if body_state.exceeded_limit:
            raise web.HTTPRequestEntityTooLarge(
                max_size=SSO_MAX_BODY_BYTES,
                actual_size=body_state.actual_size,
            ) from exc
        log.error("SillyTavern proxy request failed: %s", exc)
        return web.json_response({"error": "SillyTavern is unavailable"}, status=502)


async def health(_request: web.Request) -> web.Response:
    return web.json_response(
        {
            "status": "ok",
            "version": VERSION,
            "api_proxy_enabled": API_PROXY_ENABLED,
        }
    )


def _valid_http_url(value: str) -> bool:
    if value != value.strip() or any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    ):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and bool(hostname)
        and (port is None or 1 <= port <= 65535)
        and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
    )


def validate_configuration() -> None:
    errors = list(CONFIGURATION_PARSE_ERRORS)
    if not _valid_http_url(ST_BACKEND):
        errors.append(
            "ST_BACKEND must be an http(s) URL without credentials, query, or fragment"
        )
    if not 1 <= LISTEN_PORT <= 65535:
        errors.append("LISTEN_PORT must be between 1 and 65535")
    if not ADMIN_HANDLE or slugify(ADMIN_HANDLE) != ADMIN_HANDLE:
        errors.append("ADMIN_HANDLE must already be a valid SillyTavern handle")
    if "ADMIN_PASSWORD" not in CONFIGURATION_INVALID_NAMES and len(ADMIN_PASSWORD) < 20:
        errors.append("ADMIN_PASSWORD must be set to at least 20 characters")
    if (
        "USER_PASSWORD_SECRET" not in CONFIGURATION_INVALID_NAMES
        and len(USER_PASSWORD_SECRET) < 32
    ):
        errors.append("USER_PASSWORD_SECRET must be set to at least 32 characters")
    if ADMIN_PASSWORD and ADMIN_PASSWORD == USER_PASSWORD_SECRET:
        errors.append("ADMIN_PASSWORD and USER_PASSWORD_SECRET must be independent")
    if TRUSTED_PROXY_ERROR:
        errors.append(f"TRUSTED_PROXY_CIDRS is invalid: {TRUSTED_PROXY_ERROR}")
    elif not TRUSTED_PROXY_NETWORKS:
        errors.append(
            "TRUSTED_PROXY_CIDRS must list the Authentik outpost source CIDR(s)"
        )
    if not os.path.isabs(STATE_FILE):
        errors.append("STATE_FILE must be an absolute path")

    if API_PROXY_ENABLED and "API_PROXY_ENABLED" not in CONFIGURATION_INVALID_NAMES:
        if not _valid_http_url(API_BASE_URL):
            errors.append(
                "API_BASE_URL must be an http(s) URL without credentials, query, or fragment"
            )
        elif urlsplit(API_BASE_URL).hostname == "api.example.com":
            errors.append("API_BASE_URL must not use the example placeholder")
        if "API_KEY" not in CONFIGURATION_INVALID_NAMES and not API_KEY:
            errors.append("API_KEY must be set when API_PROXY_ENABLED=true")
        if API_KEY and API_KEY in {ADMIN_PASSWORD, USER_PASSWORD_SECRET}:
            errors.append("API_KEY must be independent from account secrets")
        if (
            "API_PROXY_TOKEN" not in CONFIGURATION_INVALID_NAMES
            and len(API_PROXY_TOKEN) < 32
        ):
            errors.append("API_PROXY_TOKEN must be set to at least 32 characters")
        if API_KEY and API_PROXY_TOKEN == API_KEY:
            errors.append("API_PROXY_TOKEN must not equal the upstream API_KEY")
        if API_PROXY_TOKEN and API_PROXY_TOKEN in {
            ADMIN_PASSWORD,
            USER_PASSWORD_SECRET,
        }:
            errors.append("API_PROXY_TOKEN must be independent from account secrets")
        if not ALLOWED_MODELS:
            errors.append("ALLOWED_MODELS must contain at least one model")
        if DEFAULT_MODEL not in ALLOWED_MODEL_SET:
            errors.append("DEFAULT_MODEL must be present in ALLOWED_MODELS")
        if not _valid_http_url(API_URL_FOR_USERS):
            errors.append(
                "ST_API_BASE must be an http(s) URL without credentials, query, or fragment"
            )
        if API_MAX_BODY_BYTES <= 0:
            errors.append("API_MAX_BODY_BYTES must be positive")
    if UID_CACHE_TTL < 0:
        errors.append("UID_CACHE_TTL cannot be negative")
    if SSO_MAX_BODY_BYTES <= 0:
        errors.append("SSO_MAX_BODY_BYTES must be positive")
    if errors:
        raise ValueError("Invalid configuration:\n- " + "\n- ".join(errors))


def create_app(*, validate: bool = True) -> web.Application:
    if validate:
        validate_configuration()
    relay_limit = API_MAX_BODY_BYTES if API_PROXY_ENABLED else 0
    application = web.Application(client_max_size=max(SSO_MAX_BODY_BYTES, relay_limit))
    application[UID_CACHE_KEY] = {}
    application[PROVISION_LOCKS_KEY] = {}
    application.router.add_get("/_sso_health", health)
    application.router.add_route("*", "/{tail:.*}", handle_request)
    return application


def main() -> None:
    try:
        application = create_app()
    except ValueError as exc:
        log.critical("%s", exc)
        raise SystemExit(2) from exc
    log.info("SSO sidecar %s starting on port %s", VERSION, LISTEN_PORT)
    log.info("Trusted proxy CIDRs: %s", TRUSTED_PROXY_CIDRS)
    log.info("Admin groups: %s", ", ".join(sorted(ADMIN_GROUPS)))
    web.run_app(
        application,
        host="0.0.0.0",
        port=LISTEN_PORT,
        access_log=None,
    )


if __name__ == "__main__":
    main()
