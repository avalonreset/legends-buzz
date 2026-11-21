# Changelog

All notable changes to `legends-buzz` are documented in this file.

## [0.1.2] - 2026-11-21

### Changed
- **Evergreen README & Outlined Legends Font Design System (`r1`)**: Added `scripts/render_cards.py` generating seven outlined Legends Font SVG architecture, plain-english routing, and comparison cards under `assets/cards/r1/`, reorganized `README.md` with collapsible `<details>` reference drawers and zero hardcoded version or module-count strings, and added `.svg` asset mirroring to `setup.py` and `MANIFEST.in`.

## [0.1.1] - 2026-11-11

### Security & Hardening
- **Hardened XML & Office Archive Media Inspection (`BUZ-P1-01`)**: Replaced prefix-only XML inspection with full-buffer UTF-8/UTF-16 scanning plus Expat `EntityDeclHandler`, `StartDoctypeDeclHandler`, and `ExternalEntityRefHandler` hooks to unconditionally reject `<!DOCTYPE` and `<!ENTITY` declarations (CWE-776). Bounded ZIP member decompression streams via `_read_bounded_zip_member` (`10 MB` per XML entry, `60 MB` cumulative decompressed stream ceiling, CWE-409) and made `inspect_media_attachment` Gate 3 fail closed across both list and `{"messages": [...]}` JSON shapes when NIP-92 `imeta` bindings cannot be verified (CWE-345).
- **Pinned-IP HTTP Relay Probes & Proxy Isolation (`BUZ-P1-02`, `BUZ-P3-01`)**: Added `urllib.request.ProxyHandler({})` and `_PinnedHTTPHandler` / `_PinnedHTTPSHandler` to `_http_get()` so all `relay-probe` HTTP endpoints connect directly to `resolved_ips[0]` while preserving TLS SNI and `Host` headers (preventing DNS rebinding TOCTOU). Updated `_probe_pairing_websocket()` to honor plaintext `ws://` when `--allow-private-network` is active and preserve non-root relay base paths on `/pair`.
- **Full BIP-173 Bech32 Key & Pubkey Validation (`BUZ-P2-01`)**: Hardened `classify_key()` and `normalize_pubkey()` with strict mixed-case rejection, exact 63-character length checks, full BIP-173 polymod checksum verification, non-zero 5-to-8 bit padding validation, and `HEX64_RE` validation on raw hex public keys.
- **Canonical Channel UUID & Event Hex64 Enforcement (`BUZ-P2-02`)**: Added `validate_channel_uuid()` and `validate_event_hex64()` across `channel_snapshot()`, `message_canary()`, and `owner_access_audit()` to prevent subprocess option injection from untrusted channel or event identifiers (CWE-88).
- **Pre-Resolve Symlink Refusal & Documentation Sync (`BUZ-P2-03`, `BUZ-P3-02`)**: Enforced `check_no_symlink_chain()` on un-resolved paths in `desktop.py` and `resolve_buzz_binary()`, restricted `/var`, `/tmp`, and `/etc` symlink exemptions to Darwin, and synchronized `README.md`, `AGENTS.md`, and `docs/AGENT-RECIPE.md`.

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
