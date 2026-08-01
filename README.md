# SillyTavern SSO Sidecar

Transparent reverse proxy that bridges Authentik SSO into SillyTavern's native
username-based SSO.

## How it works

```
Browser → Authentik outpost → sso-sidecar → SillyTavern
```

Authentik's proxy outpost authenticates the user and forwards identity headers
(`X-Authentik-Uid`, `X-Authentik-Username`, `X-Authentik-Groups`, ...).
SillyTavern's native SSO mode trusts `X-Authentik-Username` and auto-logs-in /
creates the account on first visit — but it keys accounts off the **username
string**, so a renamed user or changed email breaks the mapping.

This sidecar sits between the outpost and SillyTavern and:

1. Reads the stable `X-Authentik-Uid` (UUID) from the outpost headers.
2. Maps uid → existing ST handle via a `ssoUid` field stamped into ST's
   `_storage` user records (the sidecar mounts the same data volume).
3. Auto-provisions a new ST account on first login (admin session via a
   passwordless admin account + ST's admin API).
4. Rewrites `X-Authentik-Username` to the mapped handle so ST's native SSO
   always sees a consistent identity.

## Requirements

- Authentik proxy provider + outpost in front of this sidecar
- SillyTavern with:
  - `whitelistMode: true`
  - `enableForwardedWhitelist: false`
  - the outpost container IP added to the whitelist
- A **passwordless** (no password set) admin account in SillyTavern,
  used only for auto-provisioning API calls

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `ST_BACKEND` | `http://sillytavern:8000` | Upstream SillyTavern address |
| `LISTEN_PORT` | `8001` | Sidecar listen port |
| `ADMIN_HANDLE` | `admin` | Passwordless admin handle for auto-provisioning |
| `ADMIN_GROUPS` | `admins,staff` | Comma-separated Authentik group names that map to ST admins |
| `ST_DATA_DIR` | `/st-data/data` | Where the SillyTavern data volume is mounted |

## Deployment (docker compose)

```yaml
services:
  sillytavern:
    image: ghcr.io/sillytavern/sillytavern:latest
    container_name: sillytavern
    restart: unless-stopped
    volumes:
      - ./data/config:/home/node/app/config
      - ./data/data:/home/node/app/data
      - ./data/plugins:/home/node/app/plugins
      - ./data/extensions:/home/node/app/public/scripts/extensions/third-party
    networks:
      - authentik_default

  sso-sidecar:
    build: ./sso-sidecar
    container_name: sso-sidecar
    restart: unless-stopped
    environment:
      ST_BACKEND: http://sillytavern:8000
      LISTEN_PORT: "8001"
      ADMIN_HANDLE: "admin"              # must be passwordless in ST
      ADMIN_GROUPS: "admins,staff"       # Authentik groups → ST admin
    volumes:
      - ./data/data:/st-data/data
    networks:
      - authentik_default
    depends_on:
      - sillytavern

  authentik-proxy-outpost:
    image: ghcr.io/goauthentik/proxy:2026.5.6
    container_name: authentik-proxy-outpost
    restart: unless-stopped
    ports:
      - "127.0.0.1:9200:9000"
    environment:
      AUTHENTIK_HOST: https://auth.example.com
      AUTHENTIK_TOKEN: ${AUTHENTIK_OUTPOST_TOKEN}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - authentik_default
    depends_on:
      - sso-sidecar

networks:
  authentik_default:
    external: true
```

Authentik proxy provider settings:

- **External host**: the public URL of SillyTavern
- **Internal host**: `http://sso-sidecar:8001`
- Headers forwarded by the outpost (`X-Authentik-Uid`, etc.) are on by default

## Health check

```
GET /_sso_health
```

## Caveats

- The `ssoUid` stamping relies on the sidecar writing ST's `_storage` records
  directly; keep the data volume mounted read-write.
- Auto-provisioning needs a fresh CSRF token after the admin login (ST rotates
  the session); the code fetches it twice for this reason.
- The mapping cache is in-memory, so a sidecar restart re-scans `_storage`
  on the next request — no data loss.
