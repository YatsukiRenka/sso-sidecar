import gzip
import ipaddress
import json
import os
import tempfile
import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

from aiohttp import ClientSession, web
from aiohttp.test_utils import TestClient, TestServer
from yarl import URL

import app

IDENTITY_HEADERS = {
    "X-Authentik-Uid": "uid-alice",
    "X-Authentik-Username": "Alice",
    "X-Authentik-Name": "Alice Example",
    "X-Authentik-Groups": "users|admins",
}


class ApiProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.upstream_requests = []

        async def upstream_handler(request):
            self.upstream_requests.append(
                {
                    "method": request.method,
                    "path": request.path,
                    "query": request.query_string,
                    "headers": request.headers.copy(),
                    "body": await request.read(),
                }
            )
            return web.Response(
                text=json.dumps({"ok": True}),
                content_type="application/json",
                headers={
                    "Set-Cookie": "upstream-secret=leak",
                    "Connection": "X-Upstream-Leak",
                    "X-Upstream-Leak": "must-not-leak",
                },
            )

        upstream_app = web.Application()
        upstream_app.router.add_route("*", "/{tail:.*}", upstream_handler)
        self.upstream_server = TestServer(upstream_app)
        await self.upstream_server.start_server()

        self.patches = [
            patch.object(app, "API_PROXY_ENABLED", True),
            patch.object(
                app,
                "API_BASE_URL",
                str(self.upstream_server.make_url("/v1")).rstrip("/"),
            ),
            patch.object(app, "API_KEY", "real-upstream-secret"),
            patch.object(app, "API_PROXY_TOKEN", "relay-token-which-is-long-enough"),
            patch.object(app, "ALLOWED_MODELS", ("model-a", "model-b")),
            patch.object(app, "ALLOWED_MODEL_SET", frozenset({"model-a", "model-b"})),
        ]
        for active_patch in self.patches:
            active_patch.start()

        self.sidecar_server = TestServer(app.create_app(validate=False))
        self.client = TestClient(self.sidecar_server)
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.upstream_server.close()
        for active_patch in reversed(self.patches):
            active_patch.stop()

    def relay_headers(self, **extra):
        headers = {"Authorization": f"Bearer {app.API_PROXY_TOKEN}"}
        headers.update(extra)
        return headers

    async def test_relay_requires_service_token(self):
        response = await self.client.get("/v1/models")
        self.assertEqual(401, response.status)
        self.assertEqual([], self.upstream_requests)

    async def test_models_lists_only_allowed_models_without_contacting_upstream(self):
        response = await self.client.get(
            "/v1/models",
            headers=self.relay_headers(),
        )
        self.assertEqual(200, response.status)
        payload = await response.json()
        self.assertEqual(
            ["model-a", "model-b"],
            [model["id"] for model in payload["data"]],
        )
        self.assertEqual([], self.upstream_requests)

    async def test_relay_injects_real_key_and_strips_sensitive_headers(self):
        payload = {"model": "model-a", "messages": [{"role": "user", "content": "hi"}]}
        response = await self.client.post(
            "/v1/chat/completions",
            json=payload,
            headers=self.relay_headers(
                Cookie="st-session=secret",
                **{
                    "X-Authentik-Uid": "attacker-controlled",
                    "X-Api-Key": "client-supplied-key",
                    "Connection": "X-Connection-Leak",
                    "X-Connection-Leak": "must-not-leak",
                },
            ),
        )
        self.assertEqual(200, response.status)
        self.assertNotIn("Set-Cookie", response.headers)
        self.assertNotIn("X-Upstream-Leak", response.headers)
        self.assertEqual(1, len(self.upstream_requests))
        forwarded = self.upstream_requests[0]
        self.assertEqual("/v1/chat/completions", forwarded["path"])
        self.assertEqual("", forwarded["query"])
        self.assertEqual(
            "Bearer real-upstream-secret", forwarded["headers"]["Authorization"]
        )
        self.assertNotIn("Cookie", forwarded["headers"])
        self.assertNotIn("X-Authentik-Uid", forwarded["headers"])
        self.assertNotIn("X-Api-Key", forwarded["headers"])
        self.assertNotIn("X-Connection-Leak", forwarded["headers"])
        self.assertEqual(payload, json.loads(forwarded["body"]))

    async def test_relay_rejects_arbitrary_routes_and_methods(self):
        response = await self.client.delete(
            "/v1/files/file-123",
            headers=self.relay_headers(),
        )
        self.assertEqual(404, response.status)

        response = await self.client.delete(
            "/v1/models",
            headers=self.relay_headers(),
        )
        self.assertEqual(405, response.status)

        response = await self.client.post(
            "/v1/chat/completions?model=model-b",
            json={"model": "model-a", "messages": []},
            headers=self.relay_headers(),
        )
        self.assertEqual(400, response.status)
        self.assertEqual([], self.upstream_requests)

    async def test_relay_does_not_allow_encoded_path_escape(self):
        base = str(self.sidecar_server.make_url("/"))
        url = URL(f"{base}v1/%2e%2e/admin", encoded=True)
        async with (
            ClientSession() as session,
            session.get(url, headers=self.relay_headers()) as response,
        ):
            self.assertIn(response.status, {403, 404})
        self.assertEqual([], self.upstream_requests)

    async def test_relay_validates_json_shape_content_type_and_model(self):
        response = await self.client.post(
            "/v1/chat/completions",
            data=b"raw-audio",
            headers=self.relay_headers(**{"Content-Type": "application/octet-stream"}),
        )
        self.assertEqual(415, response.status)

        response = await self.client.post(
            "/v1/chat/completions",
            json=[{"model": "model-a"}],
            headers=self.relay_headers(),
        )
        self.assertEqual(400, response.status)

        response = await self.client.post(
            "/v1/chat/completions",
            json={"model": "model-c"},
            headers=self.relay_headers(),
        )
        self.assertEqual(400, response.status)
        self.assertEqual([], self.upstream_requests)

    async def test_chunked_relay_body_is_bounded_while_streaming(self):
        async def chunks():
            yield b'{"model"'
            yield b':"model-a","messages":[]}'

        with patch.object(app, "API_MAX_BODY_BYTES", 16):
            response = await self.client.post(
                "/v1/chat/completions",
                data=chunks(),
                headers=self.relay_headers(**{"Content-Type": "application/json"}),
            )
        self.assertEqual(413, response.status)
        self.assertEqual([], self.upstream_requests)

    async def test_compressed_relay_body_is_limited_after_decoding(self):
        payload = b'{"model":"model-a"}'
        compressed = gzip.compress(payload)
        self.assertGreater(len(compressed), len(payload))

        with patch.object(app, "API_MAX_BODY_BYTES", len(payload)):
            response = await self.client.post(
                "/v1/chat/completions",
                data=compressed,
                headers=self.relay_headers(
                    **{
                        "Content-Type": "application/json",
                        "Content-Encoding": "gzip",
                    }
                ),
            )

        self.assertEqual(200, response.status)
        self.assertEqual(payload, self.upstream_requests[0]["body"])
        self.assertNotIn("Content-Encoding", self.upstream_requests[0]["headers"])

    async def test_relay_normalizes_strict_json_before_forwarding(self):
        response = await self.client.post(
            "/v1/chat/completions",
            data=b'{"model":"model-b","model":"model-a","temperature":0.5}',
            headers=self.relay_headers(**{"Content-Type": "application/json"}),
        )
        self.assertEqual(200, response.status)
        forwarded = self.upstream_requests[0]
        self.assertEqual(1, forwarded["body"].count(b'"model"'))
        self.assertEqual("model-a", json.loads(forwarded["body"])["model"])
        self.assertEqual("application/json", forwarded["headers"]["Content-Type"])

        response = await self.client.post(
            "/v1/chat/completions",
            data=b'{"model":"model-a","temperature":NaN}',
            headers=self.relay_headers(**{"Content-Type": "application/json"}),
        )
        self.assertEqual(400, response.status)
        self.assertEqual(1, len(self.upstream_requests))


class SsoProxyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.backend_requests = []

        async def backend_handler(request):
            self.backend_requests.append(
                {
                    "path": request.path,
                    "headers": request.headers.copy(),
                    "body": await request.read(),
                }
            )
            response = web.Response(text="ok")
            response.set_cookie("theme", "dark")
            if request.path == "/login":
                response.set_cookie("session-deadbeef", "current")
                response.set_cookie("session-deadbeef.sig", "signature")
            return response

        backend_app = web.Application()
        backend_app.router.add_route("*", "/{tail:.*}", backend_handler)
        self.backend_server = TestServer(backend_app)
        await self.backend_server.start_server()

        self.patches = [
            patch.object(
                app,
                "ST_BACKEND",
                str(self.backend_server.make_url("/")).rstrip("/"),
            ),
            patch.object(
                app,
                "TRUSTED_PROXY_NETWORKS",
                (ipaddress.ip_network("127.0.0.1/32"),),
            ),
            patch.object(app, "UID_CACHE_TTL", 300),
        ]
        for active_patch in self.patches:
            active_patch.start()

        self.sidecar_server = TestServer(app.create_app(validate=False))
        self.client = TestClient(self.sidecar_server)
        await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close()
        await self.backend_server.close()
        for active_patch in reversed(self.patches):
            active_patch.stop()

    async def test_untrusted_source_and_missing_identity_fail_closed(self):
        with patch.object(
            app,
            "TRUSTED_PROXY_NETWORKS",
            (ipaddress.ip_network("10.0.0.0/8"),),
        ):
            response = await self.client.get("/", headers=IDENTITY_HEADERS)
            self.assertEqual(403, response.status)

        response = await self.client.get("/")
        self.assertEqual(401, response.status)
        self.assertEqual([], self.backend_requests)

    async def test_native_account_and_provisioning_apis_are_not_forwarded(self):
        with patch.object(
            app, "ensure_user", AsyncMock(return_value="alice")
        ) as ensure:
            responses = [
                await self.client.post(
                    path,
                    json={"handle": "admin"},
                    headers=IDENTITY_HEADERS,
                )
                for path in (
                    "/api/users/login",
                    "/api/users/login/",
                    "/api/users/change-password",
                    "/api/users/get",
                    "/api/users/create",
                    "/api/users/promote",
                    "/api/users/delete",
                    "/API/USERS/LOGIN",
                    "/api//users/login",
                )
            ]
            base = str(self.sidecar_server.make_url("/"))
            async with ClientSession() as session:
                for encoded_path in (
                    "api/users/login/%2e",
                    "api/users%2flogin",
                ):
                    url = URL(f"{base}{encoded_path}", encoded=True)
                    async with session.post(
                        url,
                        json={"handle": "admin"},
                        headers=IDENTITY_HEADERS,
                    ) as response:
                        responses.append(response)
        self.assertTrue(all(response.status == 404 for response in responses))
        ensure.assert_not_awaited()
        self.assertEqual([], self.backend_requests)

    async def test_transient_provisioning_failure_retries_without_fail_open(self):
        attempts = 0

        async def flaky_ensure(*_args):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise app.ProvisioningError("temporary failure")
            return "alice"

        with patch.object(app, "ensure_user", side_effect=flaky_ensure):
            first = await self.client.get("/", headers=IDENTITY_HEADERS)
            second = await self.client.get("/", headers=IDENTITY_HEADERS)
            third = await self.client.get("/asset.js", headers=IDENTITY_HEADERS)

        self.assertEqual(503, first.status)
        self.assertEqual(200, second.status)
        self.assertEqual(200, third.status)
        self.assertEqual(2, attempts)
        self.assertEqual(2, len(self.backend_requests))
        self.assertTrue(
            all(
                request["headers"]["X-Authentik-Username"] == "alice"
                for request in self.backend_requests
            )
        )

    async def test_only_normalized_authentik_headers_are_forwarded(self):
        headers = dict(IDENTITY_HEADERS)
        headers["X-Authentik-Jwt"] = "must-not-leak"
        headers["Authorization"] = "Bearer must-not-leak"
        headers["Connection"] = "X-Connection-Leak"
        headers["X-Connection-Leak"] = "must-not-leak"
        with patch.object(app, "ensure_user", AsyncMock(return_value="alice")):
            response = await self.client.get("/", headers=headers)
        self.assertEqual(200, response.status)
        forwarded = self.backend_requests[0]["headers"]
        self.assertEqual("alice", forwarded["X-Authentik-Username"])
        self.assertEqual("uid-alice", forwarded["X-Authentik-Uid"])
        self.assertNotIn("X-Authentik-Jwt", forwarded)
        self.assertNotIn("Authorization", forwarded)
        self.assertNotIn("X-Connection-Leak", forwarded)

    async def test_compressed_sso_body_is_decoded_once_and_streamed(self):
        plain_body = b'{"chat":"a sufficiently compressible payload"}'
        compressed_body = gzip.compress(plain_body)
        headers = dict(IDENTITY_HEADERS)
        headers.update(
            {
                "Content-Encoding": "gzip",
                "Content-Type": "application/json",
                "Content-Digest": "sha-256=:stale-after-decoding:",
            }
        )
        self.assertGreater(len(compressed_body), len(plain_body))

        with (
            patch.object(app, "ensure_user", AsyncMock(return_value="alice")),
            patch.object(app, "SSO_MAX_BODY_BYTES", len(plain_body)),
        ):
            response = await self.client.post(
                "/api/chats/save",
                data=compressed_body,
                headers=headers,
            )

        self.assertEqual(200, response.status)
        forwarded = self.backend_requests[0]
        self.assertEqual(plain_body, forwarded["body"])
        self.assertNotIn("Content-Encoding", forwarded["headers"])
        self.assertNotIn("Content-Digest", forwarded["headers"])

    async def test_chunked_sso_body_is_bounded_while_streaming(self):
        async def chunks():
            yield b"12345678"
            yield b"901234567890"

        with (
            patch.object(app, "ensure_user", AsyncMock(return_value="alice")),
            patch.object(app, "SSO_MAX_BODY_BYTES", 16),
        ):
            response = await self.client.post(
                "/api/echo",
                data=chunks(),
                headers=IDENTITY_HEADERS,
            )

        self.assertEqual(413, response.status)
        self.assertEqual([], self.backend_requests)

    async def test_binding_waits_until_backend_issues_current_sso_session(self):
        headers = dict(IDENTITY_HEADERS)
        headers["Cookie"] = (
            f"session-deadbeef=stale; {app.SSO_BINDING_COOKIE_NAME}=invalid-binding"
        )
        with patch.object(app, "ensure_user", AsyncMock(return_value="alice")):
            static_response = await self.client.get("/asset.js", headers=headers)
            login_response = await self.client.get("/login", headers=headers)

        self.assertEqual(200, static_response.status)
        self.assertEqual(200, login_response.status)
        self.assertNotIn("Cookie", self.backend_requests[0]["headers"])
        self.assertNotIn("Cookie", self.backend_requests[1]["headers"])
        self.assertNotIn(app.SSO_BINDING_COOKIE_NAME, static_response.cookies)
        self.assertEqual(
            app.identity_binding_token("uid-alice"),
            login_response.cookies[app.SSO_BINDING_COOKIE_NAME].value,
        )
        self.assertTrue(login_response.cookies[app.SSO_BINDING_COOKIE_NAME]["httponly"])

    async def test_matching_identity_binding_preserves_only_backend_cookies(self):
        headers = dict(IDENTITY_HEADERS)
        headers["Cookie"] = (
            "session-deadbeef=valid; "
            f"{app.SSO_BINDING_COOKIE_NAME}="
            f"{app.identity_binding_token('uid-alice')}"
        )
        with patch.object(app, "ensure_user", AsyncMock(return_value="alice")):
            response = await self.client.get("/", headers=headers)

        self.assertEqual(200, response.status)
        forwarded = self.backend_requests[0]["headers"]
        self.assertEqual("session-deadbeef=valid", forwarded["Cookie"])
        self.assertNotIn(app.SSO_BINDING_COOKIE_NAME, forwarded["Cookie"])


class ConfigurationTests(unittest.TestCase):
    def test_http_urls_reject_whitespace_credentials_and_invalid_ports(self):
        self.assertTrue(app._valid_http_url("https://api.example.test/v1"))
        self.assertFalse(app._valid_http_url("http://bad host/v1"))
        self.assertFalse(app._valid_http_url("https://user:pass@example.test/v1"))
        self.assertFalse(app._valid_http_url("https://example.test:70000/v1"))

    def test_relay_token_must_not_equal_upstream_key(self):
        shared_secret = "shared-secret-that-is-at-least-32-characters"
        with (
            patch.object(app, "ST_BACKEND", "http://sillytavern:8000"),
            patch.object(app, "LISTEN_PORT", 8001),
            patch.object(app, "ADMIN_HANDLE", "admin"),
            patch.object(app, "ADMIN_PASSWORD", "admin-password-long-enough"),
            patch.object(
                app,
                "USER_PASSWORD_SECRET",
                "independent-user-password-secret-long-enough",
            ),
            patch.object(app, "TRUSTED_PROXY_ERROR", ""),
            patch.object(
                app,
                "TRUSTED_PROXY_NETWORKS",
                (ipaddress.ip_network("10.0.0.1/32"),),
            ),
            patch.object(app, "STATE_FILE", "/state/mappings.json"),
            patch.object(app, "API_PROXY_ENABLED", True),
            patch.object(app, "API_BASE_URL", "https://api.example.test/v1"),
            patch.object(app, "API_KEY", shared_secret),
            patch.object(app, "API_PROXY_TOKEN", shared_secret),
            patch.object(app, "ALLOWED_MODELS", ("model-a",)),
            patch.object(app, "ALLOWED_MODEL_SET", frozenset({"model-a"})),
            patch.object(app, "DEFAULT_MODEL", "model-a"),
            patch.object(app, "API_URL_FOR_USERS", "http://sidecar:8001/v1"),
            patch.object(app, "API_MAX_BODY_BYTES", 1024),
            patch.object(app, "UID_CACHE_TTL", 300),
            self.assertRaisesRegex(
                ValueError,
                "API_PROXY_TOKEN must not equal the upstream API_KEY",
            ),
        ):
            app.validate_configuration()

    def test_upstream_key_must_not_equal_an_account_secret(self):
        account_secret = "account-secret-that-is-at-least-32-characters"
        with (
            patch.multiple(
                app,
                ST_BACKEND="http://sillytavern:8000",
                LISTEN_PORT=8001,
                ADMIN_HANDLE="admin",
                ADMIN_PASSWORD="admin-password-long-enough",
                USER_PASSWORD_SECRET=account_secret,
                TRUSTED_PROXY_ERROR="",
                TRUSTED_PROXY_NETWORKS=(ipaddress.ip_network("10.0.0.1/32"),),
                STATE_FILE="/state/mappings.json",
                API_PROXY_ENABLED=True,
                API_BASE_URL="https://api.example.test/v1",
                API_KEY=account_secret,
                API_PROXY_TOKEN="independent-relay-token-that-is-long-enough",
                ALLOWED_MODELS=("model-a",),
                ALLOWED_MODEL_SET=frozenset({"model-a"}),
                DEFAULT_MODEL="model-a",
                API_URL_FOR_USERS="http://sidecar:8001/v1",
                API_MAX_BODY_BYTES=1024,
                UID_CACHE_TTL=300,
            ),
            self.assertRaisesRegex(
                ValueError,
                "API_KEY must be independent from account secrets",
            ),
        ):
            app.validate_configuration()


class StateAndProvisioningTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(
            self.temporary_directory.name, "state", "mappings.json"
        )
        self.data_dir = os.path.join(self.temporary_directory.name, "st-data")
        os.makedirs(os.path.join(self.data_dir, "_storage"), exist_ok=True)
        self.patches = [
            patch.object(app, "STATE_FILE", self.state_file),
            patch.object(app, "ST_DATA_DIR", self.data_dir),
            patch.object(app, "ADMIN_HANDLE", "admin"),
            patch.object(app, "ADMIN_GROUPS", frozenset({"admins"})),
            patch.object(app, "API_PROXY_ENABLED", False),
        ]
        for active_patch in self.patches:
            active_patch.start()

    async def asyncTearDown(self):
        for active_patch in reversed(self.patches):
            active_patch.stop()
        self.temporary_directory.cleanup()

    async def test_mapping_never_rebinds_a_handle_or_uid(self):
        app.save_mapping(
            "uid-old",
            "alice",
            provisioned=True,
            managed=False,
        )
        with self.assertRaises(app.IdentityConflict):
            app.save_mapping(
                "uid-new",
                "alice",
                provisioned=True,
                managed=False,
            )
        with self.assertRaises(app.IdentityConflict):
            app.save_mapping(
                "uid-old",
                "bob",
                provisioned=True,
                managed=False,
            )
        self.assertEqual("alice", app.find_mapping("uid-old").handle)

    def test_scalar_legacy_storage_record_is_ignored(self):
        path = app.storage_path("alice")
        with open(path, "w", encoding="utf-8") as file:
            json.dump("not-an-object", file)
        self.assertIsNone(app.read_user_record("alice"))
        self.assertIsNone(app.find_mapping("uid-alice"))

    async def test_authentik_pipe_groups_control_admin_role(self):
        self.assertTrue(app.groups_grant_admin("users|admins"))
        self.assertFalse(app.groups_grant_admin("users,admins"))

    async def test_existing_username_is_not_claimed_by_default(self):
        @asynccontextmanager
        async def fake_admin_session():
            yield object(), "csrf"

        with (
            patch.object(app, "ALLOW_USERNAME_LINKING", False),
            patch.object(app, "st_admin_session", fake_admin_session),
            patch.object(
                app,
                "st_list_users",
                AsyncMock(
                    return_value=[{"handle": "alice", "enabled": True, "admin": False}]
                ),
            ),
            self.assertRaises(app.IdentityConflict),
        ):
            await app.ensure_user("uid-new", "Alice", "Alice", "users")
        self.assertIsNone(app.find_mapping("uid-new"))

    async def test_pending_managed_account_is_verified_before_role_change(self):
        app.save_mapping(
            "uid-alice",
            "alice",
            provisioned=False,
            managed=True,
        )

        @asynccontextmanager
        async def fake_admin_session():
            yield object(), "csrf"

        verify = AsyncMock(side_effect=app.ProvisioningError("wrong password"))
        sync = AsyncMock()
        with (
            patch.object(app, "st_admin_session", fake_admin_session),
            patch.object(
                app,
                "st_list_users",
                AsyncMock(
                    return_value=[{"handle": "alice", "enabled": True, "admin": False}]
                ),
            ),
            patch.object(app, "st_verify_user_credentials", verify),
            patch.object(app, "st_sync_admin_role", sync),
            self.assertRaises(app.ProvisioningError),
        ):
            await app.ensure_user("uid-alice", "Alice", "Alice", "admins")

        verify.assert_awaited_once()
        sync.assert_not_awaited()
        self.assertFalse(app.find_mapping("uid-alice").provisioned)

    async def test_provisioned_managed_account_replacement_is_rejected(self):
        app.save_mapping(
            "uid-alice",
            "alice",
            provisioned=True,
            managed=True,
        )

        @asynccontextmanager
        async def fake_admin_session():
            yield object(), "csrf"

        verify = AsyncMock(side_effect=app.ProvisioningError("wrong password"))
        sync = AsyncMock()
        with (
            patch.object(app, "st_admin_session", fake_admin_session),
            patch.object(
                app,
                "st_list_users",
                AsyncMock(
                    return_value=[{"handle": "alice", "enabled": True, "admin": False}]
                ),
            ),
            patch.object(app, "st_verify_user_credentials", verify),
            patch.object(app, "st_sync_admin_role", sync),
            self.assertRaises(app.ProvisioningError),
        ):
            await app.ensure_user("uid-alice", "Alice", "Alice", "admins")

        verify.assert_awaited_once()
        sync.assert_not_awaited()

    async def test_verified_pending_account_is_resumed_and_marked_provisioned(self):
        app.save_mapping(
            "uid-alice",
            "alice",
            provisioned=False,
            managed=True,
        )

        @asynccontextmanager
        async def fake_admin_session():
            yield object(), "csrf"

        with (
            patch.object(app, "st_admin_session", fake_admin_session),
            patch.object(
                app,
                "st_list_users",
                AsyncMock(
                    return_value=[{"handle": "alice", "enabled": True, "admin": False}]
                ),
            ),
            patch.object(
                app,
                "st_verify_user_credentials",
                AsyncMock(),
            ) as verify,
            patch.object(app, "st_sync_admin_role", AsyncMock()),
        ):
            handle = await app.ensure_user(
                "uid-alice",
                "Alice",
                "Alice",
                "users",
            )

        self.assertEqual("alice", handle)
        verify.assert_awaited_once()
        self.assertTrue(app.find_mapping("uid-alice").provisioned)

    def test_version_one_pending_state_is_migrated_safely(self):
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as file:
            json.dump(
                {
                    "version": 1,
                    "mappings": {
                        "uid-alice": {
                            "handle": "alice",
                            "configured": False,
                            "managed": True,
                        }
                    },
                },
                file,
            )

        record = app.find_mapping("uid-alice")
        self.assertFalse(record.provisioned)
        self.assertEqual("", record.api_config_digest)

    async def test_api_config_digest_changes_when_relay_config_rotates(self):
        with (
            patch.object(app, "API_PROXY_TOKEN", "token-one"),
            patch.object(app, "DEFAULT_MODEL", "model-a"),
            patch.object(app, "API_URL_FOR_USERS", "http://sidecar:8001/v1"),
        ):
            original = app.current_api_config_digest()
        with (
            patch.object(app, "API_PROXY_TOKEN", "token-two"),
            patch.object(app, "DEFAULT_MODEL", "model-a"),
            patch.object(app, "API_URL_FOR_USERS", "http://sidecar:8001/v1"),
        ):
            rotated = app.current_api_config_digest()
        self.assertNotEqual(original, rotated)

    async def test_full_managed_user_provisioning_and_api_configuration(self):
        users = {
            "admin": {
                "handle": "admin",
                "name": "Administrator",
                "password": "admin-password-that-is-long-enough",
                "enabled": True,
                "admin": True,
            }
        }
        create_requests = []
        settings_writes = []
        secret_writes = []

        async def csrf_handler(_request):
            return web.json_response({"token": "csrf-token"})

        async def login_handler(request):
            body = await request.json()
            user = users.get(body.get("handle"))
            if user is None or body.get("password") != user["password"]:
                return web.Response(status=403)
            response = web.json_response({"handle": user["handle"]})
            response.set_cookie("session", user["handle"])
            return response

        def is_session(request, handle):
            return request.cookies.get("session") == handle

        async def list_users_handler(request):
            if not is_session(request, "admin"):
                return web.Response(status=403)
            return web.json_response(
                [
                    {key: value for key, value in user.items() if key != "password"}
                    for user in users.values()
                ]
            )

        async def create_user_handler(request):
            if not is_session(request, "admin"):
                return web.Response(status=403)
            body = await request.json()
            create_requests.append(body)
            users[body["handle"]] = {
                **body,
                "enabled": True,
            }
            return web.json_response({"handle": body["handle"]})

        async def settings_get_handler(request):
            if not is_session(request, "alice"):
                return web.Response(status=403)
            return web.json_response({"settings": json.dumps({})})

        async def settings_save_handler(request):
            if not is_session(request, "alice"):
                return web.Response(status=403)
            settings_writes.append(await request.json())
            return web.json_response({"result": "ok"})

        async def secret_write_handler(request):
            if not is_session(request, "alice"):
                return web.Response(status=403)
            secret_writes.append(await request.json())
            return web.json_response({"id": "secret-id"})

        fake_st = web.Application()
        fake_st.router.add_get("/csrf-token", csrf_handler)
        fake_st.router.add_post("/api/users/login", login_handler)
        fake_st.router.add_post("/api/users/get", list_users_handler)
        fake_st.router.add_post("/api/users/create", create_user_handler)
        fake_st.router.add_post("/api/settings/get", settings_get_handler)
        fake_st.router.add_post("/api/settings/save", settings_save_handler)
        fake_st.router.add_post("/api/secrets/write", secret_write_handler)
        server = TestServer(fake_st)
        await server.start_server()

        relay_token = "relay-token-that-is-long-enough"
        password_secret = "user-password-secret-that-is-long-enough"
        try:
            with (
                patch.object(
                    app,
                    "ST_BACKEND",
                    str(server.make_url("/")).rstrip("/"),
                ),
                patch.object(
                    app,
                    "ADMIN_PASSWORD",
                    users["admin"]["password"],
                ),
                patch.object(app, "USER_PASSWORD_SECRET", password_secret),
                patch.object(app, "API_PROXY_ENABLED", True),
                patch.object(app, "API_PROXY_TOKEN", relay_token),
                patch.object(app, "API_URL_FOR_USERS", "http://sidecar:8001/v1"),
                patch.object(app, "DEFAULT_MODEL", "model-a"),
            ):
                handle = await app.ensure_user(
                    "uid-alice",
                    "Alice",
                    "Alice Example",
                    "users|admins",
                )
                self.assertEqual("alice", handle)
                self.assertEqual(1, len(create_requests))
                self.assertEqual(
                    app.derive_user_password("uid-alice"),
                    create_requests[0]["password"],
                )
                self.assertTrue(create_requests[0]["admin"])
                self.assertEqual(1, len(settings_writes))
                self.assertEqual("openai", settings_writes[0]["main_api"])
                self.assertEqual(
                    "http://sidecar:8001/v1",
                    settings_writes[0]["oai_settings"]["custom_url"],
                )
                self.assertEqual(
                    "model-a",
                    settings_writes[0]["oai_settings"]["custom_model"],
                )
                self.assertEqual(
                    {
                        "key": "api_key_custom",
                        "value": relay_token,
                        "label": "SSO sidecar relay",
                    },
                    secret_writes[0],
                )
                record = app.find_mapping("uid-alice")
                self.assertTrue(record.provisioned)
                self.assertTrue(record.managed)
                self.assertEqual(
                    app.current_api_config_digest(),
                    record.api_config_digest,
                )

                # A repeat login still reconciles the account but must not
                # duplicate user creation or rewrite an unchanged API secret.
                self.assertEqual(
                    "alice",
                    await app.ensure_user(
                        "uid-alice",
                        "Alice",
                        "Alice Example",
                        "users|admins",
                    ),
                )
                self.assertEqual(1, len(create_requests))
                self.assertEqual(1, len(settings_writes))
                self.assertEqual(1, len(secret_writes))
        finally:
            await server.close()

    async def test_admin_role_is_reconciled_for_mapped_user(self):
        app.save_mapping(
            "uid-alice",
            "alice",
            provisioned=True,
            managed=False,
        )

        @asynccontextmanager
        async def fake_admin_session():
            yield object(), "csrf"

        sync = AsyncMock()
        with (
            patch.object(app, "st_admin_session", fake_admin_session),
            patch.object(
                app,
                "st_list_users",
                AsyncMock(
                    return_value=[{"handle": "alice", "enabled": True, "admin": True}]
                ),
            ),
            patch.object(app, "st_sync_admin_role", sync),
        ):
            handle = await app.ensure_user("uid-alice", "Alice", "Alice", "users")
        self.assertEqual("alice", handle)
        self.assertFalse(sync.await_args.args[3])

    async def test_mapped_uid_survives_an_unusable_username_change(self):
        app.save_mapping(
            "uid-alice",
            "alice",
            provisioned=True,
            managed=False,
        )

        @asynccontextmanager
        async def fake_admin_session():
            yield object(), "csrf"

        with (
            patch.object(app, "st_admin_session", fake_admin_session),
            patch.object(
                app,
                "st_list_users",
                AsyncMock(
                    return_value=[{"handle": "alice", "enabled": True, "admin": False}]
                ),
            ),
            patch.object(app, "st_sync_admin_role", AsyncMock()),
        ):
            handle = await app.ensure_user("uid-alice", "用户", "Alice", "users")

        self.assertEqual("alice", handle)


if __name__ == "__main__":
    unittest.main()
