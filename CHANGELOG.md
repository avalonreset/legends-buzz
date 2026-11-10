# Changelog

All notable changes to `legends-buzz` are documented in this file.

## [0.1.0] - 2026-11-10

### Added
- Initial public release of `legends-buzz` (`0.1.0`) for the `cto-legends` ecosystem.
- Complete 25-domain / 97-subcommand MCP-to-CLI reference map (`legends-buzz mcp-map`) and live CLI capability introspection (`legends-buzz cli-inventory`) covering both Buzz `0.5.x` (`block/buzz`) and Buzz `1.0.0+` (`block/buzz-app`).
- Desktop installation and NSIS bundle auditor (`legends-buzz desktop-audit`) with Windows PE subsystem detection (`IMAGE_SUBSYSTEM_WINDOWS_CUI` vs `IMAGE_SUBSYSTEM_WINDOWS_GUI`) to prevent the `Buzz.exe` vs `buzz.exe` NTFS case-insensitive overwrite trap and verify embedded WebView assets (`index.html` + `assets/`).
- SSRF-guarded, redirect-refusing relay readiness probe (`legends-buzz relay-probe`) inspecting `/_readiness`, `/health`, and NIP-11 relay metadata (`Accept: application/nostr+json`), including `NIP-FI` federated identity detection.
- Authenticated relay membership and channel-access diagnostics (`legends-buzz membership-check`, `legends-buzz owner-access-audit`, `legends-buzz channel-snapshot`) distinguishing `member` access from `residual_403` (`relay_membership_required`) and `nip_fi_required`.
- Preview-first SHA-256 plan-gated disposable message canary (`legends-buzz message-canary`) testing message send, readback, reaction add/remove, and cleanup deletion.
- Zero-downtime self-hosted relay upgrade planner (`legends-buzz relay-upgrade-plan`) and 6 drop-in server/agent blueprints (`legends-buzz blueprint`).
- Attachable Empire knowledge pack (`knowledge/buzz/pack.json`, `legends.knowledge-pack/v1`) with 9 vault notes and 3 private operation receipt templates.
