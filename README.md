# SillyTavern SSO Sidecar

Transparent reverse proxy that sits between an Authentik proxy outpost and
SillyTavern. It maps stable Authentik user UUIDs to SillyTavern accounts,
auto-provisions new users on first login, and can proxy an upstream LLM API
channel (`/v1/*`) with the real API key injected **server-side**, so users
never see the endpoint key in their browser.

## Features

- **SSO identity mapping** — reads `X-Authentik-Uid` / `X-Authentik-Username`
  headers injected by the Authentik proxy outpost and rewrites them to the
  mapped SillyTavern handle, so SillyTavern's native SSO login just works.
- **Auto-provisioning** — a new Authentik user is automatically created as a
  SillyTavern account on first page load (via a passwordless admin session).
- **Default API config injection** — after provisioning, the user's
  `settings.json` / `secrets.json` are written with a default Chat Completion
  connection pointing at the sidecar's own `/v1` endpoint, so the user can
  start chatting immediately without configuring anything.
- **Server-side API key proxy** — `/v1/*` is forwarded to the upstream API
  channel with `Authorization: Bearer <API_KEY>` injected by the sidecar.
  Users only ever see a placeholder key; the real key lives in the sidecar's
  environment. A model whitelist rejects any other model with HTTP 400.

## Architecture

```
Browser ──► NPM/nginx ──► Authentik proxy outpost ──► sso-sidecar ──► SillyTavern
                 │                │                        │
                 │                └─ X-Authentik-Uid ──────┤
                 │                                         └─ /v1/* ──► upstream LLM API (key injected here)
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ST_BACKEND` | `http://sillytavern:8000` | SillyTavern upstream URL |
| `LISTEN_PORT` | `8001` | Sidecar listen port |
| `ADMIN_HANDLE` | `admin` | SillyTavern admin handle used for auto-provisioning (must be passwordless + enabled) |
| `ADMIN_GROUPS` | `admins,staff` | Authentik groups that map to SillyTavern admins |
| `ST_DATA_DIR` | `/st-data/data` | Mounted SillyTavern data root |
| `API_BASE_URL` | `https://api.example.com/v1` | Upstream LLM API base URL (proxied at `/v1/*`) |
| `API_KEY` | *(empty)* | Real API key, injected server-side only |
| `ALLOWED_MODELS` | `deepseek-v4-flash` | Comma-separated model whitelist |
| `DEFAULT_MODEL` | first allowed model | Model written into user settings |
| `ST_API_BASE` | `https://st.example.com/v1` | Browser-facing API endpoint written into user settings |

## Requirements

- SillyTavern with `enableUserAccounts: true` and a passwordless admin account
- Authentik proxy provider/outpost forwarding `X-Authentik-*` headers

## Example compose snippet

```yaml
services:
  sso-sidecar:
    build: ./sso-sidecar
    container_name: sso-sidecar
    restart: unless-stopped
    environment:
      ST_BACKEND: http://sillytavern:8000
      LISTEN_PORT: "8001"
      ADMIN_HANDLE: "admin"
      ADMIN_GROUPS: "admins,staff"
      API_BASE_URL: ${API_BASE_URL}
      API_KEY: ${API_KEY}
      ALLOWED_MODELS: ${ALLOWED_MODELS:-deepseek-v4-flash}
    volumes:
      - ./data/data:/st-data/data
    networks:
      - authentik_default
```

## Security notes

- The real API key must only ever live in the sidecar's environment
  (e.g. `.env`), never in user data or the browser.
- Model whitelist is enforced at the sidecar; SillyTavern's own model picker
  is not locked down — users changing the model get HTTP 400 from the sidecar.
- The sidecar is not a general-purpose internet proxy: keep it behind the
  Authentik outpost / an authenticated reverse proxy.
