# Operating legends-buzz

This is an on-demand module recipe, not a registered skill. The central `cto-legends` router owns discovery.

## Select knowledge first

Read [the Block Buzz knowledge vault](../wiki/index.md). Choose the runbook matching the requested outcome. Follow its [primary sources](../references/sources.md) when NIP event kinds, SQLx relay migrations, or desktop packaging details matter. The vault is reusable knowledge; the user's private workspace holds `.env` credential files, relay URLs, channel UUIDs, and operational receipts.

## Readiness

1. Run `legends-buzz doctor --json` (or `cto-legends run legends-buzz -- doctor --json`). This is offline, free, and verifies Python 3.11+, local knowledge pack integrity, `buzz` CLI capability inventory, Windows PE subsystem safety (`cui` vs `gui` NTFS collision detection), and Nostr key classification (`nsec` vs `hex64`).
2. For authorized live relay reads or channel work, supply `BUZZ_PRIVATE_KEY` and `BUZZ_RELAY_URL` in the environment or via `--env-file <path>`. Never echo `nsec1...`, 64-character hex private keys, or federated identity bearer tokens to terminal output or logs.
3. Run `legends-buzz doctor --live --relay <https-url> --env-file <path> --json` (or `legends-buzz membership-check`) to verify `/_readiness`, `/health`, NIP-11 relay metadata, and whether the identity is an active relay `member` or blocked by a residual `403 relay_membership_required` or `NIP-FI` federated identity gate.
4. Live canary verification (`message-canary`) is preview-first and returns a deterministic `plan_sha256`. Applying requires `--apply --confirm-plan <sha256>` and automatically deletes the disposable test message in a `finally:` block.

| Goal | Command | Interpretation |
|---|---|---|
| Offline readiness | `doctor --json` | Checks Python 3.11+, knowledge pack hashes, PE subsystem safety, and CLI inventory |
| Live relay & auth check | `doctor --live --relay URL [--env-file FILE]` | Verifies `/_readiness`, `/health`, NIP-11, and authenticated channel membership |
| Knowledge & blueprints | `resources --json` | Emits verified knowledge pack manifest path, recipe path, and blueprint names |
| 26-domain MCP-to-CLI map | `mcp-map [--domain D] [--intent Q] [--format json\|markdown]` | Maps all 26 Buzz command domains and 108 subcommands without an MCP daemon |
| Inspect installed `buzz` CLI | `cli-inventory [--buzz-bin PATH] --json` | Detects `1.0.0+` vs `0.5.x` CLI generation, `--format agent`, and command groups |
| Audit Desktop install | `desktop-audit [--install-dir DIR] --json` | Detects Windows NTFS `Buzz.exe`/`buzz.exe` collisions and embedded WebView assets |
| Probe 6 relay surfaces | `relay-probe --relay URL --json` | SSRF-guarded probe of `/_readiness`, `/health`, NIP-11, Tauri CORS (`tauri://localhost`), `/invite/*` CSP edge, and `/pair` RFC 6455 WebSocket `101` |
| Verify relay membership | `membership-check --relay URL [--env-file FILE] --json` | Distinguishes `member` access from `residual_403` (`/invite/<token>`) and `nip_fi_required` |
| Audit owner governance | `owner-access-audit --relay URL [--expected-pubkey PK] --json` | Verifies `owner`/`admin` role coverage (accepts `npub1...` or 64-char hex) and duplicate channel names across shared channels |
| Snapshot channel state | `channel-snapshot --channel UUID [--limit N] --json` | Captures channel metadata, members, canvas, and structured JSON messages |
| Reconstruct reply thread | `thread-context --channel UUID --event HEX64 [--limit N]` | Walks `kind:9` `["e", ...]` tags to isolate a connected reply thread without unrelated chatter |
| Verify & extract media | `media-inspect --channel UUID --event HEX64 --url URL --sha256 HEX64 --mime MIME` | Enforces 5 zero-trust attachment gates (`imeta`, SHA-256, magic bytes, XXE/zip-bomb guard) |
| Disposable message canary | `message-canary --channel UUID [--apply --confirm-plan HASH]` | Preview-first send -> readback -> reaction add/remove -> delete canary |
| Zero-downtime upgrade plan | `relay-upgrade-plan [--relay URL] [--target-digest DIGEST]` | Generates the 8-gate isolated `--internal` clone rehearsal and promotion plan |
| Server & agent blueprints | `blueprint --name docker-compose-traefik\|docker-compose-caddy\|mobile-invite-edge\|postgres-migration-49-60-preflight\|stage-upgrade-verify\|acp-subscription-agent\|isolated-subscription-acp-launcher\|durable-bridge-guard\|systemd-alert-timer` | Emits production Docker Compose stacks, `/invite/*` edge configs, migration preflights, isolated ACP launchers, and SQLite outbox bridges |

## Optional knowledge pack

The vault also ships as an attachable Empire knowledge pack (`knowledge/buzz/pack.json`, schema `legends.knowledge-pack/v1`, suggested home `wiki/library/legends-buzz/buzz`). Attachment is optional and explicit: preview the transaction into a selected vault, review it, then apply with the reviewed plan hash. See [knowledge packs](KNOWLEDGE-PACK.md) for the exact commands and ownership table.

## Limits and safety

- Outbound relay probes (`relay-probe`) enforce `https://` by default, verify that target hostnames resolve exclusively to globally routable public IP addresses, and disable automatic HTTP redirects.
- Never print `nsec1...`, 64-character hex private keys, or `BUZZ_FEDERATED_IDENTITY_TOKEN` values in terminal output, logs, or receipts.
- Never pass `--private-key` on the command line; `legends-buzz` passes `BUZZ_PRIVATE_KEY` strictly via child process environment variables (`shell=False`).
- On Windows, `legends-buzz` inspects PE subsystem headers (`IMAGE_SUBSYSTEM_WINDOWS_CUI = 3`) before executing `buzz.exe` so a GUI `Buzz.exe` collision never opens a window during automation.
- Never spawn hidden consoles, execution-policy bypass shell wrappers, or bulk file-overwrite loops.
