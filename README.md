# SillyTavern SSO Sidecar

A fail-closed reverse proxy between an Authentik proxy outpost and
SillyTavern. It maps stable Authentik UIDs to SillyTavern handles, safely
provisions accounts, reconciles admin-group membership, and exposes a narrow
service-authenticated relay for an OpenAI-compatible LLM API.

## Security model

The sidecar treats browser traffic and SillyTavern's server-side LLM traffic
as two separate trust paths:

```text
Browser -> Authentik outpost -> sidecar /... -> SillyTavern
                                  ^
SillyTavern server ---------------+-- /v1 -> upstream LLM API
                                      relay token   real API key
```

- Normal SillyTavern requests are accepted only from an address in
  `TRUSTED_PROXY_CIDRS` and must contain both `X-Authentik-Uid` and
  `X-Authentik-Username`. Missing or untrusted identity data fails closed.
- Native password login/recovery, password changes, and SillyTavern's local
  user-administration endpoints are not forwarded. Authentik remains the
  identity and role source of truth. The SillyTavern backend must also stay on
  a private network.
- Provisioning logs in with a password-protected SillyTavern administrator.
  New SSO-only users receive a deterministic high-entropy password that is
  never returned to a browser.
- A signed binding cookie ties SillyTavern's long-lived browser session to the
  stable Authentik UID. A missing or mismatched binding discards the old
  backend cookie until SillyTavern issues a session cookie for the current SSO
  identity, preventing a browser user switch from reusing the previous user's
  SillyTavern session.
- UID mappings live in the sidecar's own atomically replaced state file.
  SillyTavern's `_storage`, `settings.json`, and `secrets.json` are never
  modified directly. Run exactly one sidecar replica for each `STATE_FILE`;
  the in-process lock does not coordinate concurrent replicas.
- `/v1` accepts only `GET /v1/models`, `POST /v1/chat/completions`, and
  `POST /v1/completions`. It requires a separate bearer relay token, validates
  and normalizes a strict JSON object and allowlisted model, rejects query
  parameters, strips client cookies and identity headers, and then injects the
  real upstream key. The models endpoint is generated locally from
  `ALLOWED_MODELS`, so it does not disclose the upstream catalog.

Authentik documents that proxy groups are pipe-separated (`foo|bar|baz`),
which is the format this sidecar parses. See the
[Authentik proxy header reference](https://docs.goauthentik.io/add-secure-apps/providers/proxy/#headers-sent-to-upstream-applications).

## Required SillyTavern configuration

Configure multi-user mode and native Authentik SSO in SillyTavern's
`config.yaml`:

```yaml
enableUserAccounts: true

sso:
  authentikAuth: true
  trustedProxies:
    - 172.30.0.20 # the sidecar address, not the Authentik outpost address
```

The sidecar address must be trusted because it is the immediate TCP peer that
forwards the normalized Authentik headers to SillyTavern. The
[SillyTavern SSO documentation](https://docs.sillytavern.app/administration/sso/)
explains the same trusted-proxy requirement.

Also:

1. Set a strong password on the SillyTavern account named by `ADMIN_HANDLE`.
   Never leave that administrator passwordless.
2. Keep SillyTavern's port private. Only the sidecar should reach it.
3. Assign the Authentik outpost and sidecar stable private addresses (or stable
   narrowly scoped CIDRs). Configure the outpost address in
   `TRUSTED_PROXY_CIDRS`.

The two trust lists intentionally contain different peers:

| Setting | Trusts |
|---|---|
| Sidecar `TRUSTED_PROXY_CIDRS` | Authentik outpost source address |
| SillyTavern `sso.trustedProxies` | Sidecar source address |

## Configuration

### SSO and provisioning

| Variable | Default | Description |
|---|---|---|
| `ST_BACKEND` | `http://sillytavern:8000` | Private SillyTavern URL |
| `LISTEN_PORT` | `8001` | Sidecar listen port |
| `ADMIN_HANDLE` | `admin` | Password-protected SillyTavern provisioning administrator |
| `ADMIN_PASSWORD` / `_FILE` | required | Administrator password; minimum 20 characters |
| `USER_PASSWORD_SECRET` / `_FILE` | required | Stable key used to derive managed-user passwords; minimum 32 characters |
| `ADMIN_GROUPS` | `admins,staff` | Comma-separated Authentik groups that grant SillyTavern admin |
| `AUTO_PROVISION` | `true` | Create a missing mapped account through the admin API |
| `ALLOW_USERNAME_LINKING` | `false` | Allow an unbound pre-existing handle to be claimed by a matching username |
| `TRUSTED_PROXY_CIDRS` | none | Required comma-separated Authentik outpost source CIDRs |
| `STATE_FILE` | `/var/lib/sso-sidecar/mappings.json` | Sidecar-owned atomic UID mapping file |
| `ST_DATA_DIR` | `/st-data/data` | Optional read-only legacy data root for importing old `ssoUid` mappings |
| `UID_CACHE_TTL` | `300` | Successful mapping/role cache lifetime in seconds |
| `SSO_MAX_BODY_BYTES` | `524288000` | Maximum decoded SillyTavern request size; bodies are streamed rather than buffered |
| `SSO_BINDING_COOKIE_SECURE` | `true` | Mark the UID-binding cookie Secure; disable only for local plain-HTTP testing |

`ALLOW_USERNAME_LINKING=false` prevents username reuse from taking over an
existing SillyTavern account. Old `ssoUid` records are imported read-only and
do not require this switch. For a deliberate one-time migration of unbound
accounts, enable the switch only while the intended users sign in, verify the
state file, and disable it again.

### LLM relay

| Variable | Default | Description |
|---|---|---|
| `API_PROXY_ENABLED` | `true` | Enable the narrow `/v1` relay and default user configuration |
| `API_BASE_URL` | placeholder | Upstream OpenAI-compatible base URL, normally ending in `/v1` |
| `API_KEY` / `_FILE` | required | Real upstream API key; never written to user data |
| `API_PROXY_TOKEN` / `_FILE` | required | Independent random relay bearer token; minimum 32 characters |
| `ALLOWED_MODELS` | `deepseek-v4-flash` | Ordered comma-separated model allowlist |
| `DEFAULT_MODEL` | first allowed model | Must also appear in `ALLOWED_MODELS` |
| `ST_API_BASE` | `http://sso-sidecar:8001/v1` | Internal URL written into managed users' custom API settings |
| `API_MAX_BODY_BYTES` | `10485760` | Maximum relay JSON body size |

`ST_API_BASE` must be reachable from the SillyTavern container. Do not point it
at a public Authentik-protected browser URL: SillyTavern performs custom API
requests server-side. The sidecar writes `API_PROXY_TOKEN`, not the real API
key, into the managed user's `api_key_custom` secret through SillyTavern's own
authenticated secrets API.

Every secret supports a Docker/Kubernetes-style file variant. For example,
set `API_KEY_FILE=/run/secrets/api_key` instead of `API_KEY`. Setting both forms
for the same secret is rejected.

Generate independent random values, for example:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Startup requires all four trust-domain secrets to be independent: it rejects
reuse among the upstream key, relay token, administrator password, and
managed-user derivation key.

## Compose example

This example assumes the Authentik outpost is `172.30.0.10`, the sidecar is
`172.30.0.20`, and both SillyTavern and the outpost join the same private
network. Do not publish the sidecar or SillyTavern ports directly.

```yaml
services:
  sso-sidecar:
    build: ./sso-sidecar
    restart: unless-stopped
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    environment:
      ST_BACKEND: http://sillytavern:8000
      ADMIN_HANDLE: admin
      ADMIN_PASSWORD_FILE: /run/secrets/st_admin_password
      USER_PASSWORD_SECRET_FILE: /run/secrets/user_password_secret
      ADMIN_GROUPS: admins,staff
      TRUSTED_PROXY_CIDRS: 172.30.0.10/32
      STATE_FILE: /var/lib/sso-sidecar/mappings.json
      ST_DATA_DIR: /st-data/data
      API_PROXY_ENABLED: "true"
      API_BASE_URL: https://your-llm-provider.example/v1
      API_KEY_FILE: /run/secrets/upstream_api_key
      API_PROXY_TOKEN_FILE: /run/secrets/api_proxy_token
      ALLOWED_MODELS: deepseek-v4-flash
      DEFAULT_MODEL: deepseek-v4-flash
      ST_API_BASE: http://sso-sidecar:8001/v1
    secrets:
      - st_admin_password
      - user_password_secret
      - upstream_api_key
      - api_proxy_token
    volumes:
      - sillytavern_data:/st-data/data:ro
      - sidecar_state:/var/lib/sso-sidecar
    networks:
      sso_internal:
        ipv4_address: 172.30.0.20

networks:
  sso_internal:
    external: true

volumes:
  sillytavern_data:
    external: true
  sidecar_state:

secrets:
  st_admin_password:
    file: ./secrets/st_admin_password
  user_password_secret:
    file: ./secrets/user_password_secret
  upstream_api_key:
    file: ./secrets/upstream_api_key
  api_proxy_token:
    file: ./secrets/api_proxy_token
```

Point the Authentik proxy provider's internal host at
`http://sso-sidecar:8001`. Make sure the network still permits the sidecar to
reach the configured LLM provider, or attach a separate egress network.

## Mapping and failure behavior

- A UID already in the state file always maps to the same handle, even if the
  Authentik username changes or the new username cannot form an ASCII handle.
- One UID cannot be rebound to another handle, and one handle cannot be bound
  to multiple UIDs.
- A provisioning or storage failure returns `503` and is retried on a later
  request. The original Authentik username is never passed through as a
  fallback.
- Removing a user from every configured admin group demotes the mapped account
  on the next uncached role check; adding a group promotes it.
- Managed accounts are credential-verified on every uncached reconciliation;
  a deleted/re-created account or changed password fails closed before role
  synchronization. Pending accounts can also resume after an interrupted
  creation/config sequence. Keep `USER_PASSWORD_SECRET` stable so that
  verification remains possible.
- Managed-user API configuration is fingerprinted. Rotating
  `API_PROXY_TOKEN`, changing `DEFAULT_MODEL`, or changing `ST_API_BASE`
  reapplies the settings and relay secret on that user's next uncached login.
- Run one sidecar replica per `STATE_FILE`. Horizontal replicas require
  separate state files or an external transactional state store.

## Development

Install the pinned runtime dependency and run the regression suite:

```sh
python -m pip install -r requirements-dev.txt
ruff check app.py tests
ruff format --check app.py tests
python -m unittest discover -s tests -v
python -m py_compile app.py
```

The test suite covers relay authentication and route restrictions, encoded
path traversal, bounded chunked bodies, sensitive-header stripping,
strict JSON and model validation, bounded streaming and compressed SSO bodies,
trusted proxy enforcement, stale-session replacement, blocked native account
routes, credential-verified retry behavior, immutable UID bindings, state
migration, legacy-record robustness, and Authentik group parsing.
