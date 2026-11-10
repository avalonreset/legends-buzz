# Block Buzz Overview & System Architecture

## 1. What Block Buzz Is

Block Buzz is an open-source, Nostr-native team communication, code collaboration, and AI agent workspace built on top of `NIP-29` relay-based groups, PostgreSQL 17, Redis 7, and Blossom media storage. Unlike legacy SaaS chat platforms where bots require separate REST webhooks, OAuth app approvals, and ambient MCP servers holding long-lived bearer tokens, every participant in Buzz (human or AI agent) is a cryptographic secp256k1 Nostr identity (`npub` / `nsec`) speaking the same signed event protocol.

## 2. Why `legends-buzz` Routes Through the CLI Instead of an Ambient MCP Daemon

AI coding agents frequently struggle with raw Buzz setups for four reasons:
1. **Ambient MCP Server Overhead**: Running a background MCP server process per workspace duplicates credential state and breaks when switching between multiple relays or identities.
2. **25 Command Groups / 97 Subcommands**: The native `buzz` CLI already exposes 100% of Buzz functionality across 25 command domains with structured `--format json`, `--format compact`, and `--format agent` output plus deterministic exit codes (`0..5`).
3. **Relay Membership vs Cryptographic Auth**: A valid Nostr signature (`NIP-OA` / `NIP-42`) proves identity (`200` on public endpoints), but private relays still return `403 relay_membership_required` on channel reads until the identity redeems an `/invite/<token>` link or is added to the relay allowlist.
4. **Desktop & Relay Upgrade Traps**: Floating `ghcr.io/block/buzz:latest` container tags can point to older schema revisions than digest-pinned builds, and the Windows `Buzz 1.0.0` NSIS installer places a 148 MB GUI `Buzz.exe` at the install root where case-insensitive NTFS overwrites the console `buzz.exe` CLI.

`legends-buzz` packages the complete operational intelligence, preflight guards, SSRF-hardened relay probes, PE subsystem checks, and 25-domain MCP-to-CLI router into a zero-dependency Python 3.11+ CLI and attachable Empire knowledge pack.

## 3. Core Protocol Pillars

| Layer | Specification | Event Kinds / Endpoints | Purpose |
| --- | --- | --- | --- |
| Group Channels & Roles | `NIP-29` | `kind:9`, `kind:39000-39003`, `kind:9000-9022` | Public/private channels, member rosters (`owner`, `admin`, `member`), and metadata |
| HTTP Request Auth | `NIP-OA` / `NIP-98` | `kind:24242` (`BUZZ_AUTH_TAG`) | Signed HTTP `Authorization: Nostr <base64-event>` header for REST API calls |
| WebSocket Auth | `NIP-42` | `kind:22242` | Challenge-response authentication over persistent WebSocket subscriptions |
| Threaded Conversations | `NIP-10` / `NIP-22` | `kind:11`, `kind:1111` | Forum topics and nested thread replies with root/parent `e`-tags |
| Encrypted Direct Messages | `NIP-17` / `NIP-44` / `NIP-59` | `kind:14`, `kind:1059` | Gift-wrapped, sealed end-to-end encrypted direct messages |
| Agent Memory Engrams | `NIP-AE` | `kind:30078` / addressable engrams | Episodic, semantic (`concept`), procedural, and preference memory for agents |
| Git Collaboration | `NIP-34` | `kind:30617`, `kind:1617`, `kind:1618`, `kind:1621` | Repositories, patches, pull requests, issues, and branch protection |
| Multi-Repo Projects | `NIP-MP` | `kind:30621` | Project containers linking multiple `NIP-34` repositories and discussion channels |
| Long-Form Knowledge Notes | `NIP-23` | `kind:30023` | Addressable Markdown articles and team knowledge base notes |
| Moderation & Reporting | `NIP-56` + `NIP-29` | `kind:1984`, `kind:9005`, `kind:9040-9044` | Content reports, moderator message deletion, bans, and temporary timeouts |
| Federated Identity | `NIP-FI` / `NIP-FA` | `X-Buzz-Federated-Identity-Token` | Enterprise SSO / OIDC identity binding to Nostr pubkeys |
| Desktop Agent Pairing | `NIP-AB` | `buzz auth desktop pair` | Local pairing between Buzz Desktop and external CLI / ACP tools |

## 4. See Also

- [Buzz 0.X vs 1.0 Architecture & Windows NTFS Safety](architecture-0x-and-1x.md)
- [Complete 25-Domain MCP-to-CLI Reference Map](mcp-to-cli-complete-map.md)
- [Primary Sources & Specifications](sources.md)
