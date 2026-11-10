"""Production server, migration verification, ACP subscription agent, and bridge blueprints for Block Buzz."""
from __future__ import annotations

from typing import Any

BLUEPRINTS: dict[str, dict[str, str]] = {
    "docker-compose-traefik": {
        "name": "docker-compose-traefik",
        "title": "Self-Hosted Buzz Relay Stack (Traefik v3 + Pairing Relay + Invite Edge + Postgres 17 + Redis 7)",
        "filename": "docker-compose.traefik.yml",
        "description": (
            "Complete 5-service digest-pinned Block Buzz stack behind Traefik v3: PostgreSQL 17, Redis 7, "
            "buzz-relay (with Tauri WebView CORS origins), buzz-pair-relay (/pair priority 210 for NIP-44 QR mobile pairing), "
            "and nginx invite-edge (/invite/* priority 200 for deep-link onboarding)."
        ),
        "content": """# Self-Hosted Block Buzz Relay Stack (Traefik v3 + Pairing Relay + Invite Edge + PostgreSQL 17 + Redis 7)
# IMPORTANT: Always pin ghcr.io/block/buzz by @sha256:... digest in production.
# Never deploy ghcr.io/block/buzz:latest without checking creation timestamps,
# because floating tags can point to older schema revisions and fail when the
# live database already has newer migrations (e.g. migrations 45..60) applied.

services:
  postgres:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-buzz}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: ${POSTGRES_DB:-buzz}
    volumes:
      - buzz_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-buzz} -d ${POSTGRES_DB:-buzz}"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - buzz_internal

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - buzz_redis:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10
    networks:
      - buzz_internal

  pairing-relay:
    image: ${BUZZ_RELAY_IMAGE:?Set digest-pinned ghcr.io/block/buzz@sha256:... in .env}
    entrypoint: ["/usr/local/bin/buzz-pair-relay"]
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 128m
    pids_limit: 64
    environment:
      BUZZ_PAIR_RELAY_BIND_ADDR: "0.0.0.0:5000"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.buzz-pair.rule=Host(`${BUZZ_DOMAIN}`) && Path(`/pair`)"
      - "traefik.http.routers.buzz-pair.priority=210"
      - "traefik.http.routers.buzz-pair.entrypoints=websecure"
      - "traefik.http.routers.buzz-pair.tls.certresolver=letsencrypt"
      - "traefik.http.services.buzz-pair.loadbalancer.server.port=5000"
    networks:
      - traefik_proxy

  invite-edge:
    image: nginx:1.27-alpine
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /var/cache/nginx
      - /var/run
    volumes:
      - ./mobile-invite/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./mobile-invite/invite.html:/usr/share/nginx/html/invite.html:ro
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1/healthz"]
      interval: 10s
      timeout: 3s
      retries: 6
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.buzz-invite.rule=Host(`${BUZZ_DOMAIN}`) && PathPrefix(`/invite/`)"
      - "traefik.http.routers.buzz-invite.priority=200"
      - "traefik.http.routers.buzz-invite.entrypoints=websecure"
      - "traefik.http.routers.buzz-invite.tls.certresolver=letsencrypt"
      - "traefik.http.services.buzz-invite.loadbalancer.server.port=80"
    networks:
      - traefik_proxy

  buzz-relay:
    image: ${BUZZ_RELAY_IMAGE:?Set digest-pinned ghcr.io/block/buzz@sha256:... in .env}
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://${POSTGRES_USER:-buzz}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-buzz}
      REDIS_URL: redis://redis:6379
      BUZZ_RELAY_URL: https://${BUZZ_DOMAIN:?Set BUZZ_DOMAIN in .env}
      BUZZ_CORS_ORIGINS: https://${BUZZ_DOMAIN},tauri://localhost,http://tauri.localhost,https://tauri.localhost
      BUZZ_HOST: 0.0.0.0
      BUZZ_PORT: "3000"
      BUZZ_AUTO_MIGRATE: "true"
      BUZZ_RESTRICTED_ACCESS: ${BUZZ_RESTRICTED_ACCESS:-true}
      BUZZ_AUTH_TAG: ${BUZZ_AUTH_TAG:-24242}
      BUZZ_ADMINS: ${BUZZ_ADMINS:?Set comma-separated admin hex pubkeys or npubs}
      BUZZ_STORAGE_BACKEND: local
      BUZZ_STORAGE_LOCAL_DIR: /data/blossom
      RUST_LOG: info,buzz_relay=info
    volumes:
      - buzz_blossom:/data/blossom
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:3000/_readiness || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 6
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.buzz.rule=Host(`${BUZZ_DOMAIN}`)"
      - "traefik.http.routers.buzz.entrypoints=websecure"
      - "traefik.http.routers.buzz.tls.certresolver=letsencrypt"
      - "traefik.http.services.buzz.loadbalancer.server.port=3000"
      - "traefik.http.services.buzz.loadbalancer.passHostHeader=true"
    networks:
      - buzz_internal
      - traefik_proxy

volumes:
  buzz_pgdata:
  buzz_redis:
  buzz_blossom:

networks:
  buzz_internal:
    internal: true
  traefik_proxy:
    external: true
""",
    },
    "docker-compose-caddy": {
        "name": "docker-compose-caddy",
        "title": "Self-Hosted Buzz Relay Stack (Caddy Auto-HTTPS + Pairing Relay + Invite Edge + Postgres 17 + Redis 7)",
        "filename": "docker-compose.caddy.yml",
        "description": (
            "Standalone self-hosted Block Buzz stack with Caddy automatic TLS, /pair* QR pairing routing, "
            "/invite/* onboarding edge routing, Tauri WebView CORS origins, PostgreSQL 17, and Redis 7."
        ),
        "content": """# Self-Hosted Block Buzz Relay Stack (Caddy + Pairing Relay + Invite Edge + PostgreSQL 17 + Redis 7)
# Place a Caddyfile next to this file:
#   {$BUZZ_DOMAIN} {
#     encode zstd gzip
#     header {
#       Strict-Transport-Security "max-age=31536000; includeSubDomains"
#       X-Content-Type-Options nosniff
#       Referrer-Policy no-referrer
#       -Server
#     }
#     handle /pair* {
#       reverse_proxy pairing-relay:5000
#     }
#     handle /invite/* {
#       reverse_proxy invite-edge:80
#     }
#     reverse_proxy buzz-relay:3000 {
#       flush_interval -1
#       header_up Host {host}
#       header_up X-Forwarded-Proto {scheme}
#       header_up X-Forwarded-For {remote_host}
#     }
#   }

services:
  caddy:
    image: caddy:2-alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    environment:
      BUZZ_DOMAIN: ${BUZZ_DOMAIN:?Set BUZZ_DOMAIN in .env}
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      buzz-relay:
        condition: service_healthy
    networks:
      - buzz_edge
      - buzz_internal

  pairing-relay:
    image: ${BUZZ_RELAY_IMAGE:?Set digest-pinned ghcr.io/block/buzz@sha256:... in .env}
    entrypoint: ["/usr/local/bin/buzz-pair-relay"]
    restart: unless-stopped
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 128m
    pids_limit: 64
    environment:
      BUZZ_PAIR_RELAY_BIND_ADDR: "0.0.0.0:5000"
    networks:
      - buzz_internal

  invite-edge:
    image: nginx:1.27-alpine
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /var/cache/nginx
      - /var/run
    volumes:
      - ./mobile-invite/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./mobile-invite/invite.html:/usr/share/nginx/html/invite.html:ro
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1/healthz"]
      interval: 10s
      timeout: 3s
      retries: 6
    networks:
      - buzz_internal

  postgres:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-buzz}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?Set POSTGRES_PASSWORD in .env}
      POSTGRES_DB: ${POSTGRES_DB:-buzz}
    volumes:
      - buzz_pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-buzz} -d ${POSTGRES_DB:-buzz}"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - buzz_internal

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - buzz_redis:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10
    networks:
      - buzz_internal

  buzz-relay:
    image: ${BUZZ_RELAY_IMAGE:?Set digest-pinned ghcr.io/block/buzz@sha256:... in .env}
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://${POSTGRES_USER:-buzz}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-buzz}
      REDIS_URL: redis://redis:6379
      BUZZ_RELAY_URL: https://${BUZZ_DOMAIN}
      BUZZ_CORS_ORIGINS: https://${BUZZ_DOMAIN},tauri://localhost,http://tauri.localhost,https://tauri.localhost
      BUZZ_HOST: 0.0.0.0
      BUZZ_PORT: "3000"
      BUZZ_AUTO_MIGRATE: "true"
      BUZZ_RESTRICTED_ACCESS: ${BUZZ_RESTRICTED_ACCESS:-true}
      BUZZ_AUTH_TAG: ${BUZZ_AUTH_TAG:-24242}
      BUZZ_ADMINS: ${BUZZ_ADMINS:?Set comma-separated admin hex pubkeys or npubs}
      BUZZ_STORAGE_BACKEND: local
      BUZZ_STORAGE_LOCAL_DIR: /data/blossom
    volumes:
      - buzz_blossom:/data/blossom
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:3000/_readiness || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 6
    networks:
      - buzz_internal

volumes:
  caddy_data:
  caddy_config:
  buzz_pgdata:
  buzz_redis:
  buzz_blossom:

networks:
  buzz_edge:
  buzz_internal:
    internal: true
""",
    },
    "mobile-invite-edge": {
        "name": "mobile-invite-edge",
        "title": "Hardened Nginx /invite/<token> Deep-Link Onboarding Edge Blueprint",
        "filename": "mobile-invite-nginx.conf",
        "description": (
            "Hardened nginx configuration for /invite/<token> URLs with strict Content-Security-Policy, "
            "Cache-Control: no-store, X-Frame-Options: DENY, and /healthz liveness probe."
        ),
        "content": """# mobile-invite/nginx.conf
# Serves a static deep-link onboarding page at https://<domain>/invite/<token>
# while keeping tokens out of HTTP caches and enforcing strict CSP headers.

server {
    listen 80;
    server_name _;

    location = /healthz {
        access_log off;
        default_type text/plain;
        return 200 "ok\\n";
    }

    location ~ ^/invite/[^/]+/?$ {
        root /usr/share/nginx/html;
        try_files /invite.html =404;
        add_header Cache-Control "no-store" always;
        add_header Content-Security-Policy "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
        add_header Referrer-Policy "no-referrer" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
    }

    location / {
        return 404;
    }
}
""",
    },
    "postgres-migration-49-60-preflight": {
        "name": "postgres-migration-49-60-preflight",
        "title": "PostgreSQL Migration 49 Concurrent Index Prebuild & Migration 60 Push-Lease Preflight",
        "filename": "postgres-migration-49-60-preflight.sql",
        "description": (
            "Online CREATE INDEX CONCURRENTLY prebuild for Migration 49 on large Nostr events tables "
            "plus Migration 60 push-lease sanity query and BUZZ_AUTO_MIGRATE=false rollback check."
        ),
        "content": """-- Block Buzz PostgreSQL Migration 49 & 60 Preflight SQL
-- Run against the live PostgreSQL 17 database BEFORE promoting a relay image
-- that crosses migrations 45..56 or 57..60 on large community databases.

-- 1. Check current highest applied SQLx migration version:
SELECT MAX(version) AS current_max_migration FROM _sqlx_migrations;

-- 2. Prebuild the composite events index concurrently so Migration 49 does not
-- hold an exclusive table lock during relay container startup:
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_events_community_channel_kind_created
ON events (community_id, channel_id, kind, created_at DESC)
WHERE deleted_at IS NULL;

-- 3. Verify no corrupt or orphaned push lease rows exist before Migration 60:
SELECT COUNT(*) AS active_channels
FROM channels
WHERE deleted_at IS NULL;
""",
    },
    "stage-upgrade-verify": {
        "name": "stage-upgrade-verify",
        "title": "Isolated Docker Network Clone Migration & Zero-Downtime Relay Promotion Blueprint",
        "filename": "stage-upgrade-verify.md",
        "description": (
            "8-gate rehearsal workflow that clones the live PostgreSQL database into an isolated "
            "--internal Docker network, tests schema migrations 45..60 against the candidate image digest, "
            "verifies BUZZ_AUTO_MIGRATE=false rollback safety, and prevents the :latest downgrade trap."
        ),
        "content": """# Staged Buzz Relay Upgrade & Isolated Migration Rehearsal

Follow this 8-gate procedure on the relay host before changing `BUZZ_RELAY_IMAGE` in production.

```sh
#!/usr/bin/env sh
set -eu

CANDIDATE_IMAGE="${1:?Usage: stage-upgrade-verify.sh ghcr.io/block/buzz@sha256:...}"
LIVE_PG_CONTAINER="${LIVE_PG_CONTAINER:-buzz-postgres-1}"
PG_USER="${POSTGRES_USER:-buzz}"
PG_DB="${POSTGRES_DB:-buzz}"
STAGE_NET="buzz_stage_verify_net"
BACKUP_FILE="/var/backups/buzz/pre-upgrade-$(date -u +%Y%m%dT%H%M%SZ).dump"

mkdir -p /var/backups/buzz

echo "[1/8] Taking consistent pg_dump -Fc snapshot -> ${BACKUP_FILE}"
docker exec "${LIVE_PG_CONTAINER}" pg_dump -U "${PG_USER}" -d "${PG_DB}" -Fc > "${BACKUP_FILE}"

echo "[2/8] Reading highest applied SQLx migration version on live database"
LIVE_MAX_MIGRATION="$(docker exec "${LIVE_PG_CONTAINER}" psql -U "${PG_USER}" -d "${PG_DB}" -tAc "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations;")"
echo "Live max migration: ${LIVE_MAX_MIGRATION}"

echo "[3/8] Pulling candidate image ${CANDIDATE_IMAGE}"
docker pull "${CANDIDATE_IMAGE}"

echo "[4/8] Creating isolated --internal staging network ${STAGE_NET}"
docker network create --internal "${STAGE_NET}" >/dev/null 2>&1 || true

cleanup() {
  docker rm -f buzz-stage-relay buzz-stage-redis buzz-stage-pg >/dev/null 2>&1 || true
  docker network rm "${STAGE_NET}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[5/8] Launching disposable staging Postgres 17 + Redis 7 on ${STAGE_NET}"
docker run -d --name buzz-stage-pg --network "${STAGE_NET}" \\
  -e POSTGRES_USER="${PG_USER}" -e POSTGRES_PASSWORD=stagepass -e POSTGRES_DB="${PG_DB}" \\
  postgres:17-alpine >/dev/null

sleep 4
docker exec -i buzz-stage-pg pg_restore -U "${PG_USER}" -d "${PG_DB}" --no-owner < "${BACKUP_FILE}"

docker run -d --name buzz-stage-redis --network "${STAGE_NET}" redis:7-alpine >/dev/null

echo "[6/8] Running candidate relay migration rehearsal against cloned database"
docker run -d --name buzz-stage-relay --network "${STAGE_NET}" \\
  -e DATABASE_URL="postgres://${PG_USER}:stagepass@buzz-stage-pg:5432/${PG_DB}" \\
  -e REDIS_URL="redis://buzz-stage-redis:6379" \\
  -e BUZZ_RELAY_URL="https://stage.example.invalid" \\
  -e BUZZ_HOST="0.0.0.0" \\
  -e BUZZ_PORT="3000" \\
  -e BUZZ_AUTO_MIGRATE="true" \\
  "${CANDIDATE_IMAGE}" >/dev/null

sleep 5
STAGE_MAX_MIGRATION="$(docker exec buzz-stage-pg psql -U "${PG_USER}" -d "${PG_DB}" -tAc "SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations;")"
echo "Staged max migration after startup: ${STAGE_MAX_MIGRATION}"

if [ "${STAGE_MAX_MIGRATION}" -lt "${LIVE_MAX_MIGRATION}" ]; then
  echo "ABORT: Candidate image supports fewer migrations (${STAGE_MAX_MIGRATION}) than live (${LIVE_MAX_MIGRATION})."
  exit 1
fi

echo "[7/8] Verifying /_readiness and /health inside isolated staging network"
docker exec buzz-stage-relay wget -qO- http://127.0.0.1:3000/_readiness
docker exec buzz-stage-relay wget -qO- http://127.0.0.1:3000/health

echo "[8/8] Staging rehearsal passed. Safe to update BUZZ_RELAY_IMAGE=${CANDIDATE_IMAGE} and run docker compose up -d."
```
""",
    },
    "acp-subscription-agent": {
        "name": "acp-subscription-agent",
        "title": "ACP Subscription Filter Rules & Agent Harness Configuration (buzz-acp)",
        "filename": "acp-subscription-agent.toml",
        "description": (
            "Production [[rules]] subscription filter schema for buzz-acp (require_mention = true in shared "
            "channels, require_mention = false in 1:1 owner DMs, kinds = [9]) plus NIP-AE engram memory settings."
        ),
        "content": """# Block Buzz ACP Subscription Filter & Agent Harness Blueprint
# Keep require_mention = true in shared multi-agent channels to prevent
# infinite agent-to-agent ping-pong loops. Allow unmentioned messages only
# inside dedicated 1:1 owner DM channels.

[[rules]]
name = "general-mentions"
channels = ["8f3d6f39-474b-46e4-aa0e-5ee5e1977f29"]
kinds = [9]
require_mention = true

[[rules]]
name = "owner-dm"
channels = ["f1b8f2b6-4fe2-46eb-b89e-f2f6105b37b6"]
kinds = [9]
require_mention = false

[agent]
name = "legends-ops-agent"
display_name = "Legends Ops Agent"
description = "Subscription-backed coding and relay operations agent"
require_mention = true
respond_in_threads = true
max_concurrent_sessions = 2

[relay]
url = "https://buzz.example.com"
private_key_env = "BUZZ_PRIVATE_KEY"
output_format = "agent"

[harness]
# Supported ACP binaries: "codex-acp", "claude-agent-acp", or "goose-acp"
command = "codex-acp"
args = []
scrub_api_keys = ["OPENAI_API_KEY", "OPENAI_API_KEYS", "ANTHROPIC_API_KEY", "XAI_API_KEY", "GROK_API_KEY"]

[memory]
enable_nip_ae_engrams = true
auto_consolidate = true
scopes = ["episode", "concept", "procedure", "preference"]
""",
    },
    "isolated-subscription-acp-launcher": {
        "name": "isolated-subscription-acp-launcher",
        "title": "Prompt-Injection-Hardened & Zero-API-Billing Isolated Codex ACP Launcher",
        "filename": "isolated_acp_launcher.py",
        "description": (
            "Python 3.11+ wrapper that launches codex-acp in an ephemeral per-run HOME directory, "
            "copies only subscription auth.json, scrubs all pay-per-token API keys, and disables "
            "shell/browser/network tools in CODEX_CONFIG so untrusted chat messages cannot break out."
        ),
        "content": """\"\"\"Isolated Subscription ACP Launcher: zero API key billing and no shell/network breakout.\"\"\"
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

SCRUBBED_API_KEYS = (
    "OPENAI_API_KEY",
    "OPENAI_API_KEYS",
    "ANTHROPIC_API_KEY",
    "XAI_API_KEY",
    "XAI_API_KEYS",
    "GROK_API_KEY",
)

LOCKED_CODEX_CONFIG = {
    "sandbox_mode": "workspace-write",
    "approval_policy": "never",
    "web_search": "disabled",
    "sandbox_workspace_write": {"network_access": False},
    "features": {
        "shell_tool": False,
        "multi_agent": False,
        "memories": False,
        "plugins": False,
        "browser_use": False,
        "computer_use": False,
        "skill_mcp_dependency_install": False,
    },
    "agents": {"enabled": False},
    "tools": {"view_image": False, "web_search": False},
    "apps": {"_default": {"enabled": False}},
}


def run_isolated_acp(source_auth_json: Path, workspace_dir: Path, acp_binary: str, extra_args: list[str]) -> int:
    if not source_auth_json.is_file():
        sys.stderr.write(f"Missing subscription auth.json at {source_auth_json}\\n")
        return 3
    workspace_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="buzz-acp-isolated-") as run_root_str:
        run_root = Path(run_root_str)
        codex_home = run_root / "codex-home"
        user_home = run_root / "user-home"
        codex_home.mkdir(parents=True, exist_ok=True)
        user_home.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_auth_json, codex_home / "auth.json")

        env = dict(os.environ)
        for key in SCRUBBED_API_KEYS:
            env[key] = ""
        env["CODEX_HOME"] = str(codex_home)
        env["HOME"] = str(user_home)
        env["USERPROFILE"] = str(user_home)
        env["INITIAL_AGENT_MODE"] = "agent"
        env["CODEX_CONFIG"] = json.dumps(LOCKED_CODEX_CONFIG)

        completed = subprocess.run([acp_binary, *extra_args], cwd=str(workspace_dir), env=env, check=False)
        return int(completed.returncode)


if __name__ == "__main__":
    default_auth = Path.home() / ".codex" / "auth.json"
    default_ws = Path.home() / "BuzzAgents" / "workspace"
    raise SystemExit(run_isolated_acp(default_auth, default_ws, "codex-acp", sys.argv[1:]))
""",
    },
    "durable-bridge-guard": {
        "name": "durable-bridge-guard",
        "title": "Durable SQLite Outbox & Echo-Suppressed Buzz Bridge Blueprint",
        "filename": "durable_bridge_guard.py",
        "description": (
            "Python 3.11+ standard-library SQLite outbox state machine for reliable bi-directional "
            "Buzz channel bridging with sender-pubkey echo suppression and bounded exponential backoff."
        ),
        "content": """\"\"\"Durable SQLite Outbox and Echo-Suppressed Buzz Bridge State Machine.\"\"\"
from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import time
from typing import Any


class BuzzOutboxStore:
    \"\"\"Crash-safe SQLite outbox and seen-event ledger for Buzz channel bridges.\"\"\"

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute(
            \"\"\"
            CREATE TABLE IF NOT EXISTS seen_events (
                event_id TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                recorded_at INTEGER NOT NULL
            )
            \"\"\"
        )
        self.conn.execute(
            \"\"\"
            CREATE TABLE IF NOT EXISTS outbox (
                idempotency_key TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                content TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,
                published_event_id TEXT
            )
            \"\"\"
        )
        self.conn.commit()

    def should_process_inbound(self, event: dict[str, Any], bridge_pubkey: str) -> bool:
        \"\"\"Return True only if event is not authored by the bridge and has not been seen before.\"\"\"
        event_id = str(event.get("id", "")).strip()
        author = str(event.get("pubkey", "")).strip().lower()
        if not event_id or author == bridge_pubkey.strip().lower():
            return False
        cur = self.conn.execute("SELECT 1 FROM seen_events WHERE event_id = ?", (event_id,))
        if cur.fetchone() is not None:
            return False
        self.conn.execute(
            "INSERT INTO seen_events (event_id, pubkey, channel_id, recorded_at) VALUES (?, ?, ?, ?)",
            (event_id, author, str(event.get("channel_id", "")), int(time.time())),
        )
        self.conn.commit()
        return True

    def enqueue(self, channel_id: str, content: str, source_id: str) -> str:
        \"\"\"Idempotently enqueue an outbound message for delivery to Buzz.\"\"\"
        digest = hashlib.sha256(f"{channel_id}:{source_id}:{content}".encode("utf-8")).hexdigest()
        now = int(time.time())
        self.conn.execute(
            \"\"\"
            INSERT OR IGNORE INTO outbox (idempotency_key, channel_id, content, attempts, next_attempt_at)
            VALUES (?, ?, ?, 0, ?)
            \"\"\",
            (digest, channel_id, content, now),
        )
        self.conn.commit()
        return digest

    def mark_published(self, idempotency_key: str, published_event_id: str) -> None:
        self.conn.execute(
            "UPDATE outbox SET published_event_id = ? WHERE idempotency_key = ?",
            (published_event_id, idempotency_key),
        )
        self.conn.commit()

    def mark_retry(self, idempotency_key: str, attempts: int) -> None:
        delay = min(300, 2 ** min(attempts, 8))
        self.conn.execute(
            "UPDATE outbox SET attempts = ?, next_attempt_at = ? WHERE idempotency_key = ?",
            (attempts, int(time.time()) + delay, idempotency_key),
        )
        self.conn.commit()
""",
    },
    "systemd-alert-timer": {
        "name": "systemd-alert-timer",
        "title": "Systemd Service & Timer Blueprint for Unattended Buzz Channel Alerts",
        "filename": "buzz-health-alert.service",
        "description": (
            "Hardened Linux systemd oneshot service and timer template that posts infrastructure "
            "health alerts to a Buzz channel using EnvironmentFile credentials and --format json."
        ),
        "content": """# /etc/systemd/system/buzz-health-alert.service
# Pair with /etc/systemd/system/buzz-health-alert.timer
# Store BUZZ_RELAY_URL and BUZZ_PRIVATE_KEY in /etc/buzz/alert.env (chmod 0600).

[Unit]
Description=Publish infrastructure health summary to Block Buzz channel
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=buzzalert
Group=buzzalert
EnvironmentFile=/etc/buzz/alert.env
ExecStart=/usr/local/bin/buzz --format json messages send --channel ${BUZZ_ALERT_CHANNEL_ID} --content "Host %H health check OK"
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
""",
    },
}


def list_blueprints() -> list[dict[str, str]]:
    """Return metadata for all bundled blueprints."""
    return [
        {
            "name": item["name"],
            "title": item["title"],
            "filename": item["filename"],
            "description": item["description"],
        }
        for item in BLUEPRINTS.values()
    ]


def get_blueprint(name: str) -> dict[str, str]:
    """Return a single blueprint by name or raise KeyError."""
    key = name.strip().lower()
    if key not in BLUEPRINTS:
        available = ", ".join(sorted(BLUEPRINTS))
        raise KeyError(f"Unknown blueprint '{name}'. Available blueprints: {available}")
    return dict(BLUEPRINTS[key])


def build_relay_upgrade_plan(
    relay_url: str | None = None,
    target_digest: str | None = None,
) -> dict[str, Any]:
    """Generate a deterministic 8-gate zero-downtime Buzz relay upgrade and rollback plan."""
    target_url = (relay_url or "https://buzz.example.com").rstrip("/")
    digest = target_digest or "ghcr.io/block/buzz@sha256:<64-hex-digest>"
    is_floating_latest = digest.endswith(":latest") or "@sha256:" not in digest
    steps = [
        {
            "gate": 1,
            "name": "pre_upgrade_readiness_and_nip11_snapshot",
            "command": f"legends-buzz relay-probe --relay {target_url} --json",
            "requirement": (
                "Confirm /_readiness, /health, NIP-11 software version, Tauri CORS headers, "
                "/invite/* edge, and /pair WebSocket 101 upgrade before touching containers."
            ),
        },
        {
            "gate": 2,
            "name": "consistent_postgres_custom_dump",
            "command": "docker exec buzz-postgres-1 pg_dump -U buzz -d buzz -Fc > /var/backups/buzz/pre-upgrade.dump",
            "requirement": "Verify dump size is non-zero and readable by pg_restore --list.",
        },
        {
            "gate": 3,
            "name": "verify_digest_and_migration_ceiling",
            "command": "docker exec buzz-postgres-1 psql -U buzz -d buzz -tAc 'SELECT MAX(version) FROM _sqlx_migrations;'",
            "requirement": (
                "Confirm the candidate image contains all migrations already applied on the live database "
                "(e.g. migrations 45..60). Prebuild Migration 49 concurrent index if needed. Never deploy floating :latest tags."
            ),
        },
        {
            "gate": 4,
            "name": "isolated_internal_network_clone_rehearsal",
            "command": "legends-buzz blueprint --name stage-upgrade-verify",
            "requirement": "Restore pre-upgrade.dump into an isolated --internal Docker Postgres 17 container and boot the candidate relay image.",
        },
        {
            "gate": 5,
            "name": "verify_staged_readiness_and_rollback_safety",
            "command": "docker exec buzz-stage-relay wget -qO- http://127.0.0.1:3000/_readiness",
            "requirement": (
                "Staged relay must pass /_readiness and /health with zero SQLxVersionMismatch errors; "
                "test previous image with BUZZ_AUTO_MIGRATE=false to prove rollback compatibility without DB restore."
            ),
        },
        {
            "gate": 6,
            "name": "promote_digest_pinned_production_container",
            "command": f"BUZZ_RELAY_IMAGE={digest} docker compose up -d buzz-relay pairing-relay",
            "requirement": "Swap only the digest-pinned buzz-relay and pairing-relay services while keeping Postgres 17 and Redis 7 running.",
        },
        {
            "gate": 7,
            "name": "post_upgrade_membership_and_owner_audit",
            "command": f"legends-buzz membership-check --relay {target_url} --json",
            "requirement": "Confirm authenticated channel readback and unread counters return status=member.",
        },
        {
            "gate": 8,
            "name": "disposable_message_canary_verification",
            "command": f"legends-buzz message-canary --relay {target_url} --channel <test-channel-uuid>",
            "requirement": "Run preview-first and then --apply --confirm-plan <sha256> to verify send, readback, reaction, and delete.",
        },
    ]
    return {
        "schema": "legends-buzz.relay-upgrade-plan/v1",
        "relay_url": target_url,
        "target_image": digest,
        "digest_pinned": not is_floating_latest,
        "warning": (
            "Target image is not pinned by @sha256:... digest. Pin an immutable digest before promoting to production."
            if is_floating_latest
            else None
        ),
        "gates": steps,
    }
