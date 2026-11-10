# Block Buzz Knowledge Vault

Operational reference pack for self-hosted Block Buzz relays (`buzz-relay`), the 25-domain / 97-subcommand `buzz` CLI, Buzz Desktop `0.X` (`block/buzz`) and `1.0` (`block/buzz-app`), Nostr `NIP-29`/`NIP-OA`/`NIP-FI` authentication, and ACP subscription agent harnesses.

## Core Wiki Pages

- [Overview & System Architecture](overview.md): High-level map of the Block Buzz ecosystem, relay data plane, and agent operating boundaries.
- [Buzz 0.X vs 1.0 Architecture & Windows NTFS Safety](architecture-0x-and-1x.md): Upstream repository split (`block/buzz` vs `block/buzz-app`), Tauri bundle IDs, the Windows NTFS `Buzz.exe` vs `buzz.exe` case-collision hazard, and embedded WebView asset verification.
- [Complete 25-Domain MCP-to-CLI Reference Map](mcp-to-cli-complete-map.md): Full mapping of every Buzz capability to deterministic `buzz` CLI commands, `--format agent` token optimization, environment variables, and exit codes `0..5`.
- [Self-Hosted Relay Setup, Migrations & Zero-Downtime Upgrades](relay-self-hosting-and-upgrades.md): Production Docker Compose topology (PostgreSQL 17 + Redis 7 + Blossom/Silo + Traefik/Caddy), `@sha256` digest pinning, the `:latest` downgrade trap, SQLx migrations 45..60, and isolated `--internal` network clone rehearsal.
- [Identity, Relay Membership & NIP-FI Federated Auth](identity-membership-and-nip-fi.md): Nostr `nsec`/`npub` signing, `NIP-OA` HTTP authorization (`BUZZ_AUTH_TAG=24242`), resolving residual `403 relay_membership_required` via `/invite/<token>`, and `NIP-FI`/`NIP-FA` enterprise federated identity (`BUZZ-517`).
- [ACP Subscription Agents, Buzzodz Plugins & Durable Bridges](agents-acp-and-bridges.md): Running Codex, Claude Code, and Goose subscription harnesses with `require_mention = true`, `NIP-AE` memory engrams, `buzzodz` plugins, and SQLite outbox bridge reconciliation.
- [Moderation, NIP-34 Git Repos, NIP-MP Projects & Workflows](moderation-projects-and-workflows.md): `NIP-56` reporting, `kind:9040-9044` bans and timeouts, channel moderator deletion (`kind:9005`), `NIP-34` Git repositories, `NIP-MP` (`kind:30621`) multi-repo projects, and YAML workflows.
- [Troubleshooting & Anti-Patterns](troubleshooting.md): Symptom-to-remediation tables for relay, CLI, desktop, and agent failure modes.

## Citations & Receipts

- [Primary Sources & Specifications](../references/sources.md)
- [Private Operation Receipt Template](../templates/private-operation-receipt.md)
- [Relay Upgrade Receipt Template](../templates/relay-upgrade-receipt.md)
- [Canary Verification Receipt Template](../templates/canary-verification-receipt.md)
