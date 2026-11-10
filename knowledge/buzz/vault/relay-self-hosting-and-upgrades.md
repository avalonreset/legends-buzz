# Self-Hosted Relay Setup, Migrations & Zero-Downtime Upgrades

## 1. Production Relay Topology (6-Surface Stack)

A complete self-hosted Block Buzz community stack requires six services behind a TLS-terminating reverse proxy (Traefik v3 or Caddy 2) so Desktop, CLI, and iOS/Android mobile clients all function without edge failures:

1. **`buzz-relay` (`ghcr.io/block/buzz@sha256:...`)**: Rust Axum + Tokio HTTP/WebSocket relay serving Nostr WebSocket connections (`/`), NIP-11 relay metadata (`Accept: application/nostr+json`), REST endpoints, `/health`, and `/_readiness` on port `3000`. Must set `BUZZ_CORS_ORIGINS=https://<domain>,tauri://localhost,http://tauri.localhost,https://tauri.localhost` so Tauri Desktop WebViews are never blocked by CORS.
2. **`pairing-relay` (`/usr/local/bin/buzz-pair-relay`, port `5000`, routed at `/pair` priority `210`)**: Ephemeral `kind:24134` NIP-44 encrypted WebSocket pairing broker used when pairing an iOS/Android phone with Buzz Desktop via QR code. Without `/pair` routed to `buzz-pair-relay`, mobile QR pairing fails with `404`.
3. **`invite-edge` (`nginx:1.27-alpine`, routed at `/invite/*` priority `200`)**: Hardened read-only static edge serving `/invite/<token>` onboarding deep-links with `Cache-Control: no-store` and strict `Content-Security-Policy` headers.
4. **PostgreSQL 17 (`postgres:17-alpine`)**: Primary durable store for Nostr events, `NIP-29` channel rosters, `NIP-34` repositories, `NIP-AE` memory engrams, and the `_sqlx_migrations` ledger.
5. **Redis 7 (`redis:7-alpine`)**: Real-time pub/sub fanout, ephemeral presence tracking, and rate-limiting cache (`--appendonly yes`).
6. **Blossom / Silo Media Storage**: Local volume (`/data/blossom`) or S3/MinIO object store for content-addressed `/media/<sha256>` attachments, custom emojis, voice notes, and diffs.

Generate drop-in production stacks and verify all 6 surfaces live with:
```bash
legends-buzz blueprint --name docker-compose-traefik
legends-buzz blueprint --name docker-compose-caddy
legends-buzz blueprint --name mobile-invite-edge
legends-buzz relay-probe --relay https://buzz.example.com --json
```

## 2. The `:latest` Container Tag Downgrade Trap

Never deploy `ghcr.io/block/buzz:latest` blindly in production:

- Upstream CI publishes both tagged release images and commit/branch images to `ghcr.io/block/buzz`. At multiple points in upstream history, the floating `:latest` tag pointed to an older build than the latest `desktop-v0.5.x` or `main` digest.
- Block Buzz uses **SQLx compile-time embedded migrations** (`_sqlx_migrations`). When `BUZZ_AUTO_MIGRATE=true` is set, the relay checks on startup that every row applied in the database's `_sqlx_migrations` table exists in the binary's compiled migration list.
- If a newer relay container has already applied migrations `45..60` (such as federated identity `NIP-FI` tables, `NIP-MP` project tables, or moderation audit columns) and you pull an older `:latest` image that only knows up to migration `44`, `buzz-relay` immediately panics and crash-loops with `MigrateError::VersionMissing`.

### Mandatory Digest-Pinning Rule

Always pin `BUZZ_RELAY_IMAGE=ghcr.io/block/buzz@sha256:<64-hex-digest>` in `.env` and verify the candidate image's migration ceiling against a cloned staging database before touching the live relay container.

## 3. Isolated `--internal` Network Clone Rehearsal (8-Gate Upgrade Pattern)

Before promoting any new `buzz-relay` image digest:

1. **Probe Pre-Upgrade Health**: Run `legends-buzz relay-probe --relay https://buzz.example.com --json` to record current `/_readiness`, `/health`, and NIP-11 metadata.
2. **Take Consistent Custom Dump**: Run `pg_dump -U buzz -d buzz -Fc > /var/backups/buzz/pre-upgrade.dump` inside the live Postgres container.
3. **Check Applied Migration Ceiling**: Query `SELECT MAX(version) FROM _sqlx_migrations;` on the live database.
4. **Create Isolated Internal Network**: Create a Docker network with `docker network create --internal buzz_stage_verify_net` so staging containers have zero outbound internet or production cross-talk.
5. **Restore Clone into Disposable Postgres 17 + Redis 7**: Boot `buzz-stage-pg` and `buzz-stage-redis` on `buzz_stage_verify_net` and run `pg_restore`.
6. **Boot Candidate Relay Against Cloned DB**: Start `buzz-stage-relay` with the candidate `@sha256:...` digest and `BUZZ_AUTO_MIGRATE=true`. Verify all new SQLx migrations apply cleanly and `STAGE_MAX_MIGRATION >= LIVE_MAX_MIGRATION`.
7. **Verify Staged Readiness**: Poll `http://127.0.0.1:3000/_readiness` and `/health` inside `buzz-stage-relay`, then tear down the staging containers.
8. **Promote & Run Live Canary**: Update `BUZZ_RELAY_IMAGE` to the verified `@sha256:...` digest, run `docker compose up -d buzz-relay`, verify `legends-buzz membership-check`, and run `legends-buzz message-canary`.

Generate the complete executable rehearsal script and gate checklist with:
```bash
legends-buzz blueprint --name stage-upgrade-verify
legends-buzz relay-upgrade-plan --relay https://buzz.example.com --target-digest ghcr.io/block/buzz@sha256:... --format markdown
```

## 4. Essential Relay Environment Variables

| Variable | Recommended Value | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `postgres://buzz:<pw>@postgres:5432/buzz` | PostgreSQL 17 connection URI |
| `REDIS_URL` | `redis://redis:6379` | Redis 7 connection URI |
| `BUZZ_RELAY_URL` | `https://buzz.example.com` | Canonical public URL used in NIP-11, invite links, and NIP-42/NIP-OA validation |
| `BUZZ_AUTO_MIGRATE` | `true` | Automatically applies forward SQLx migrations at startup |
| `BUZZ_RESTRICTED_ACCESS` | `true` | Restricts relay read/write access to invited/allowlisted community members |
| `BUZZ_AUTH_TAG` | `24242` | Expected Nostr event kind for `NIP-OA` HTTP authorization headers |
| `BUZZ_ADMINS` | `<hex-or-npub-csv>` | Comma-separated relay administrator public keys |
| `BUZZ_STORAGE_BACKEND` | `local` (or `s3`) | Blossom media storage backend |
| `BUZZ_STORAGE_LOCAL_DIR` | `/data/blossom` | Persistent volume path when `BUZZ_STORAGE_BACKEND=local` |

## 5. See Also

- [Identity, Relay Membership & NIP-FI Federated Auth](identity-membership-and-nip-fi.md)
- [Troubleshooting & Anti-Patterns](troubleshooting.md)
- [Relay Upgrade Receipt Template](templates/relay-upgrade-receipt.md)
