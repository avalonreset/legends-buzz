# Troubleshooting & Anti-Patterns

## 1. Rapid Symptom-to-Fix Matrix

| Symptom | Root Cause | Verification Command | Remediation |
| --- | --- | --- | --- |
| Running `buzz.exe` on Windows launches a GUI window and hangs the script | Windows NTFS `Buzz.exe` vs `buzz.exe` case-insensitive collision: `Buzz 1.0.0` installer overwrote console `buzz.exe` with 148 MB GUI `Buzz.exe` (`IMAGE_SUBSYSTEM_WINDOWS_GUI = 2`) | `legends-buzz desktop-audit --json` | Use `bin\buzz.exe` (`IMAGE_SUBSYSTEM_WINDOWS_CUI = 3`), copy `bin\buzz.exe` over root `buzz.exe` if keeping `0.5.28` `buzz-desktop.exe`, and stage `1.0.0` `Buzz.exe` in `Programs\Buzz-1.0\` |
| `/_readiness` and `/health` return `200 OK`, but `buzz channels list` exits with code `3` (`403 relay_membership_required`) | Cryptographic signature (`NIP-OA`) is valid, but the identity pubkey has not been admitted to the private relay (`BUZZ_RESTRICTED_ACCESS=true`) | `legends-buzz membership-check --relay <url> --json` | Redeem an `/invite/<token>` link in Buzz Desktop or have a relay admin admit the `npub` |
| `buzz-relay` container crash-loops after `docker compose pull` with `MigrateError::VersionMissing` | Floating `ghcr.io/block/buzz:latest` tag pointed to an older build than the database's applied `_sqlx_migrations` (e.g. migrations `45..60`) | `docker logs buzz-relay` and `SELECT MAX(version) FROM _sqlx_migrations;` | Pin `BUZZ_RELAY_IMAGE=ghcr.io/block/buzz@sha256:...` to a verified forward digest and rehearse upgrades with `legends-buzz blueprint --name stage-upgrade-verify` |
| Custom-built `buzz-desktop.exe` launches to a blank white screen | `cargo build --release` ran before `pnpm build`, producing an executable with `0` embedded frontend assets | `legends-buzz desktop-audit --json` (`has_index_html: false`, `asset_count: 0`) | Run `pnpm build` first and verify `asset_count > 200` via `legends-buzz desktop-audit` before installing |
| Two ACP agents in a channel reply to each other endlessly | One or both agents configured with `require_mention = false` | Inspect `agents.toml` / desktop agent config | Set `require_mention = true` on all agents in shared channels and enforce sender-pubkey echo suppression |
| Subscription ACP agent (`codex-acp` / `claude-agent-acp`) bills per-token API credits unexpectedly | `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` leaked into the ACP harness environment | Inspect parent process environment | Scrub `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` before launching subscription ACP harnesses |
| `buzz --version` fails with `error: unexpected argument '--version' found` | `buzz` CLI does not accept `--version`; it uses `--help` and subcommands | `legends-buzz cli-inventory --json` | Use `legends-buzz cli-inventory` or `buzz --help` to inspect CLI capabilities and SHA-256 |
| `buzz mem patch` exits with code `5` | Optimistic concurrency conflict (`--base-hash` does not match current slug value on relay) | `buzz mem hash <slug>` | Re-fetch `buzz mem get <slug>` and `buzz mem hash <slug>`, re-compute diff, and retry |
| Relay rejects CLI request with missing federated identity assertion (`BUZZ-517`) | Target relay enforces `NIP-FI` / `NIP-FA` enterprise SSO | `legends-buzz relay-probe --relay <url> --json` (`requires_nip_fi: true`) | Export `BUZZ_FEDERATED_IDENTITY_TOKEN` and `BUZZ_FEDERATED_IDENTITY_ADAPTER` |

## 2. Five Operational Anti-Patterns to Avoid

1. **Never pass `--private-key nsec1...` on the command line**: Command-line arguments are visible to other local processes via OS process tables. Always inject `BUZZ_PRIVATE_KEY` via environment variables or `--env-file`.
2. **Never run an ambient MCP server per repo when `buzz` CLI is installed**: `legends-buzz mcp-map` maps all 26 command domains and 108 subcommands directly to `buzz` CLI calls with `--format agent`.
3. **Never run live message tests without guaranteed cleanup**: Use `legends-buzz message-canary` (preview-first, then `--apply --confirm-plan <sha256>`), which wraps `messages delete` in a `finally:` block so test probes never litter production channels.
4. **Never upgrade a live Postgres-backed relay without an isolated clone rehearsal**: Always restore `pg_dump -Fc` into an `--internal` Docker network Postgres container first to prove SQLx migrations succeed.
5. **Never allow agents to create private channels without adding the human workspace owner**: Run `legends-buzz owner-access-audit` periodically to ensure human owners hold `owner` or `admin` roles across all shared channels.

## 3. See Also

- [Buzz 0.X vs 1.0 Architecture & Windows NTFS Safety](architecture-0x-and-1x.md)
- [Self-Hosted Relay Setup, Migrations & Zero-Downtime Upgrades](relay-self-hosting-and-upgrades.md)
- [Identity, Relay Membership & NIP-FI Federated Auth](identity-membership-and-nip-fi.md)
