<a name="banner"></a>
<a name="legends-buzz"></a>

# ![legends-buzz](assets/banner.webp)

[![release](https://img.shields.io/github/v/release/avalonreset/legends-buzz?label=release&sort=date&style=flat-square&labelColor=000000&color=ff0000)](https://github.com/avalonreset/legends-buzz/releases/latest)
[![checks](https://img.shields.io/github/actions/workflow/status/avalonreset/legends-buzz/checks.yml?branch=main&label=checks&style=flat-square&labelColor=000000)](https://github.com/avalonreset/legends-buzz/actions/workflows/checks.yml)
[![license](https://img.shields.io/github/license/avalonreset/legends-buzz?label=license&style=flat-square&labelColor=000000&color=666666)](LICENSE)

**Self-hosted Block Buzz Nostr relay operations, 26-domain MCP-to-CLI AI agent chat routing, NIP-29/NIP-OA/NIP-FI membership diagnostics, and desktop PE/asset verification from Python or your terminal.**
`legends-buzz` connects coding agents, infrastructure scripts, and team operators to [Block Buzz](https://github.com/block/buzz) (`0.X`) and [Block Buzz App](https://github.com/block/buzz-app) (`1.0.0+`) without running an ambient MCP daemon. Built for `mcp vs cli` zero-daemon efficiency, it provides a complete 26-domain / 108-subcommand Nostr CLI router (`--format agent`), SSRF-guarded 6-surface Nostr relay readiness and NIP-11 probes, residual HTTP `403 relay_membership_required` vs `NIP-FI` federated identity diagnostics, Windows NTFS `Buzz.exe`/`buzz.exe` PE subsystem collision detection, connected-component `kind:9` reply thread reconstruction, 5-gate zero-trust attachment inspection, preview-first SHA-256 disposable message canaries, and drop-in PostgreSQL 17 + Redis 7 + Blossom server and ACP subscription agent blueprints.

Python 3.11+ | Windows, Linux, macOS | Zero runtime dependencies | MIT licensed

[Quick start](#quick-start) | [What you can build](#what-you-can-build) | [Operating recipe](docs/AGENT-RECIPE.md) | [Knowledge vault](wiki/index.md) | [Agent setup](#agent-setup-via-cto-legends) | [Releases](https://github.com/avalonreset/legends-buzz/releases)

## Agent setup (via `cto-legends`)

Part of the [cto-legends](https://github.com/avalonreset/cto-legends) ecosystem. `cto-legends` is the only registered skill; this repository vendors a pinned copy at [skills/cto-legends/SKILL.md](skills/cto-legends/SKILL.md).

The product, repository, Python distribution, and catalog ID are `legends-buzz`.

Install with `cto-legends install legends-buzz`, then follow the module recipe the router loads ([docs/AGENT-RECIPE.md](docs/AGENT-RECIPE.md)). Do not register this module as its own standalone skill.

## What you can build

| Workflow | Included CLI / Python interface | What you get |
| --- | --- | --- |
| 26-domain MCP-to-CLI agent router | `legends-buzz mcp-map` / `query_mcp_map()` | Maps all 26 Buzz command domains and 108 subcommands (`messages`, `channels`, `projects`, `repos`, `mem`, `sidebar`, `huddles`, `moderation`, `workflows`, `notes`) directly to `buzz` CLI calls (`--format agent`) without an MCP daemon |
| CLI capability & generation inventory | `legends-buzz cli-inventory` / `cli_inventory()` | Inspects the installed `buzz` binary (`0.5.x` vs `1.0.0+`), verifies `--format agent` and `NIP-FI` support, and enumerates live command groups |
| Windows Desktop PE & asset audit | `legends-buzz desktop-audit` / `audit_desktop_install()` | Inspects Windows PE headers (`IMAGE_SUBSYSTEM_WINDOWS_CUI` vs `GUI`) to catch the `Buzz.exe` vs `buzz.exe` NTFS case-collision overwrite and verifies embedded WebView `index.html` + `assets/` bundles |
| SSRF-guarded 6-surface relay probe | `legends-buzz relay-probe` / `probe_relay()` | Verifies `/_readiness`, `/health`, NIP-11 relay metadata (`Accept: application/nostr+json`), Tauri WebView CORS (`Origin: tauri://localhost`), `/invite/*` CSP onboarding edge, and `/pair` RFC 6455 WebSocket `101 Switching Protocols` (`buzz-pair-relay`) without following redirects |
| Authenticated relay membership check | `legends-buzz membership-check` / `membership_check()` | Distinguishes full `member` access (with channel list and `1.0.0` unread counts) from `residual_403` (`relay_membership_required` needing `/invite/<token>`) and `nip_fi_required` |
| Channel owner & duplicate governance audit | `legends-buzz owner-access-audit` / `owner_access_audit()` | Audits visible shared channels on a relay to verify `owner`/`admin` role coverage, detect duplicate shared channel names, and catch orphaned agent-created private channels |
| Bounded channel operational snapshot | `legends-buzz channel-snapshot` / `channel_snapshot()` | Captures channel metadata, member roster, collaborative Markdown canvas, and recent structured JSON messages (`--format json`) in a single JSON payload |
| Connected-component reply thread context | `legends-buzz thread-context` / `thread_context()` | Walks Nostr `kind:9` `["e", "<parent_id>"]` reply tags to isolate the exact conversation thread for an event without leaking unrelated shared-channel chatter (with conservative 1:1 DM fallback) |
| 5-gate zero-trust attachment inspector | `legends-buzz media-inspect` / `inspect_media_attachment()` | Verifies same-relay HTTPS origin, `/media/<64hex>` path binding, event `imeta` tag binding, SHA-256 digest, and magic bytes before bounded `.docx`/`.xlsx`/`.csv`/`.json`/`.md` extraction (with XXE and zip-bomb guards) |
| Preview-first disposable message canary | `legends-buzz message-canary` / `message_canary()` | Computes a deterministic `plan_sha256` in preview mode, then executes `messages send -> get -> reactions add -> reactions remove -> messages delete` with guaranteed `finally:` cleanup |
| Zero-downtime relay upgrade planner | `legends-buzz relay-upgrade-plan` / `build_relay_upgrade_plan()` | Generates an 8-gate isolated `--internal` Docker network Postgres 17 clone migration rehearsal and `@sha256` digest promotion checklist |
| Production server & ACP agent blueprints | `legends-buzz blueprint` / `get_blueprint()` | Emits 9 blueprints: `docker-compose-traefik`, `docker-compose-caddy`, `mobile-invite-edge`, `postgres-migration-49-60-preflight`, `stage-upgrade-verify`, `acp-subscription-agent`, `isolated-subscription-acp-launcher`, `durable-bridge-guard`, and `systemd-alert-timer` |

## Why `legends-buzz` exists

Teams and coding agents deploying or automating self-hosted Block Buzz workspaces hit the same operational traps repeatedly:

- **Ambient MCP Daemon Overhead**: Running a background MCP server per repository duplicates Nostr secret key state and breaks when switching relays. Meanwhile, the native `buzz` CLI already exposes 26 command groups and 108 subcommands with token-optimized `--format agent` output.
- **Windows NTFS `Buzz.exe` vs `buzz.exe` Collision**: In Buzz `0.5.28`, the desktop app is `buzz-desktop.exe` and the CLI is `buzz.exe`. In Buzz `1.0.0`, the 148 MB GUI desktop app is named `Buzz.exe` at the install root and the CLI moves to `bin\buzz.exe`. On case-insensitive Windows NTFS, installing `1.0.0` into `Programs\Buzz` overwrites `buzz.exe` with the GUI app (`IMAGE_SUBSYSTEM_WINDOWS_GUI`), causing every CLI automation script to pop open a desktop window and hang.
- **Residual HTTP `403` vs Cryptographic Auth**: A valid `BUZZ_PRIVATE_KEY` (`NIP-OA` / `NIP-42`) passes cryptographic verification while `/_readiness` and `/health` return `200 OK`, yet `buzz channels list` fails with exit code `3` (`403 relay_membership_required`) until the pubkey redeems an `/invite/<token>` link or provides a `NIP-FI` federated identity assertion (`BUZZ-517`).
- **The `:latest` Relay Container Downgrade Trap**: Floating `ghcr.io/block/buzz:latest` tags can point to an older schema revision than digest-pinned builds. Pulling an older image against a PostgreSQL 17 database that has already applied SQLx migrations `45..60` causes `buzz-relay` to crash-loop with `MigrateError::VersionMissing`.

`legends-buzz` solves these with a **zero-dependency Python 3.11+ standard-library CLI**, PE subsystem verification, SSRF-hardened probes, preview-first SHA-256 mutation locks, and an attachable `legends-empire` knowledge pack.

## Install

```bash
python -m pip install "https://github.com/avalonreset/legends-buzz/releases/download/v0.1.0/legends_buzz-0.1.0-py3-none-any.whl"
legends-buzz --version
legends-buzz doctor --json
```

For local editable development:

```bash
git clone https://github.com/avalonreset/legends-buzz.git
cd legends-buzz
python -m pip install -e .
legends-buzz doctor --json
legends-buzz resources --json
```

## Quick start

### 1. Run offline readiness, CLI capability inventory, and Desktop PE audit (`doctor`, `cli-inventory`, `desktop-audit`)

```bash
legends-buzz doctor --json
legends-buzz cli-inventory --json
legends-buzz desktop-audit --json
```

### 2. Query the 26-domain / 108-subcommand MCP-to-CLI router (`mcp-map`)

```bash
legends-buzz mcp-map --intent "unread channels and thread replies"
legends-buzz mcp-map --domain projects --format markdown
legends-buzz mcp-map --domain mem --format markdown
```

### 3. Probe relay readiness, NIP-11 metadata, and authenticated membership (`relay-probe`, `membership-check`)

```bash
legends-buzz relay-probe --relay https://buzz.example.com --json
legends-buzz membership-check --relay https://buzz.example.com --env-file buzz.env --json
```

### 4. Audit channel owner governance, capture snapshots, reconstruct threads, and verify attachments (`owner-access-audit`, `channel-snapshot`, `thread-context`, `media-inspect`)

```bash
legends-buzz owner-access-audit --relay https://buzz.example.com --env-file buzz.env --expected-pubkey <owner-npub-or-hex> --json
legends-buzz channel-snapshot --relay https://buzz.example.com --env-file buzz.env --channel <channel-uuid> --limit 10 --json
legends-buzz thread-context --relay https://buzz.example.com --env-file buzz.env --channel <channel-uuid> --event <64hex-event-id> --limit 20
legends-buzz media-inspect --relay https://buzz.example.com --env-file buzz.env --channel <channel-uuid> --event <64hex-event-id> --url https://buzz.example.com/media/<64hex-sha256>.csv --sha256 <64hex-sha256> --mime text/csv --extract-mode data
```

### 5. Run a preview-first disposable message canary (`message-canary`)

```bash
# Step 1: Preview and compute plan_sha256 (zero network mutations)
legends-buzz message-canary --relay https://buzz.example.com --env-file buzz.env --channel <test-channel-uuid>

# Step 2: Execute send -> readback -> reaction add/remove -> cleanup delete
legends-buzz message-canary --relay https://buzz.example.com --env-file buzz.env --channel <test-channel-uuid> --apply --confirm-plan <plan_sha256>
```

### 6. Generate self-hosted relay stacks, migration rehearsal scripts, and ACP agent blueprints (`relay-upgrade-plan`, `blueprint`)

```bash
legends-buzz relay-upgrade-plan --relay https://buzz.example.com --target-digest ghcr.io/block/buzz@sha256:<digest> --format markdown
legends-buzz blueprint --list
legends-buzz blueprint --name docker-compose-traefik --output docker-compose.yml
legends-buzz blueprint --name mobile-invite-edge
legends-buzz blueprint --name postgres-migration-49-60-preflight
legends-buzz blueprint --name stage-upgrade-verify
legends-buzz blueprint --name acp-subscription-agent
legends-buzz blueprint --name isolated-subscription-acp-launcher
legends-buzz blueprint --name durable-bridge-guard
```

## FAQ

### Do I need to run `buzz-dev-mcp` or an ambient MCP server to let AI agents use Block Buzz?
No. The standalone `buzz` CLI (`buzz-cli`) natively supports all 26 command domains and 108 subcommands with `--format agent` (which strips 64-byte Schnorr signatures and `NIP-OA` auth boilerplate while folding `NIP-10` thread markers into `reply_to` and `thread_root`). `legends-buzz mcp-map` gives any agent instant lookup of the exact CLI syntax and exit code semantics (`0..5`).

### How does `legends-buzz` prevent the Windows `Buzz.exe` vs `buzz.exe` collision?
Before invoking any `buzz.exe` binary on Windows, `legends-buzz` inspects its Portable Executable (PE) Optional Header `Subsystem` field. If `Programs\Buzz\buzz.exe` has subsystem `IMAGE_SUBSYSTEM_WINDOWS_GUI` (`2`) instead of `IMAGE_SUBSYSTEM_WINDOWS_CUI` (`3`), `legends-buzz` refuses to execute the GUI binary, falls back to `bin\buzz.exe`, and flags `ntfs_buzz_exe_case_collision` in `desktop-audit` and `doctor`.

### How does `legends-buzz` protect Nostr private keys (`nsec1...` / hex)?
Secret keys (`BUZZ_PRIVATE_KEY`, `BUZZ_NSEC`, `BUZZ_PRIVATE_KEY_HEX`) and federated identity tokens (`BUZZ_FEDERATED_IDENTITY_TOKEN`) are passed strictly through child process environment variables (`shell=False`), never via command-line flags, and are automatically scrubbed from all stdout, stderr, and exception outputs.

## Documentation and Knowledge Vault

- [Agent Operating Recipe](docs/AGENT-RECIPE.md)
- [Knowledge Pack & Empire Attachment Guide](docs/KNOWLEDGE-PACK.md)
- [Release & Verification Procedure](docs/RELEASE.md)
- [Block Buzz Knowledge Vault Index](wiki/index.md)
- [Primary Sources & Citations](references/sources.md)
- [Security Policy](SECURITY.md)
- [Support Guide](SUPPORT.md)
- [Contributing Guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

MIT License. See [LICENSE](LICENSE), [NOTICE.md](NOTICE.md), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

<p align="center"><a href="https://github.com/stars/avalonreset/lists/cto-legends"><img src="assets/collection-star-shrine.svg" width="100%" alt="GitHub Star List: The complete cto-legends collection on one page. Bookmark or star the router and every module from a single GitHub list."></a></p>

**Specification & benchmarks on cto-legends.com:**
- **Module specification & architecture matrix:** [cto-legends.com/modules/legends-buzz](https://cto-legends.com/modules/legends-buzz)
- **Related engineering dispatches:** [MCP vs CLI: The 46x Token Tax & Prompt-Cache Architecture](https://cto-legends.com/blog?post=mcp-vs-cli) · [AI Agent Governance: PreToolUse Kernel Gates & Context Compaction](https://cto-legends.com/blog?post=ai-agent-governance) · [Hetzner vs DigitalOcean: Sovereign Bare-Metal & Coolify TCO](https://cto-legends.com/blog?post=hetzner-vs-digitalocean)
- **Ecosystem hub:** [cto-legends.com/home](https://cto-legends.com/home)
