# Buzz 0.X vs 1.0 Architecture & Windows NTFS Safety

## 1. The Upstream Repository Split (`2026-11-05` / `2026-11-10`)

Block Buzz is maintained across two open-source repositories under the `block` GitHub organization:

| Repository | Scope | Latest Reference Release | Tauri Bundle Identifier |
| --- | --- | --- | --- |
| [`block/buzz`](https://github.com/block/buzz) | Relay (`buzz-relay`), CLI (`buzz-cli`), Mobile (`mobile/`), Agent Harnesses (`buzz-acp`, `buzz-agent`), SQLx Migrations (`migrations/`), NIP Specifications (`docs/nips/`), and the Buzz `0.X` Desktop App (`desktop/`) | `desktop-v0.5.28` (`f87c10895`) | `xyz.block.buzz.app` |
| [`block/buzz-app`](https://github.com/block/buzz-app) | Next-generation Buzz `1.0` Desktop & Web Application adding the `buzzodz` plugin runtime, `buzz-agent-controller`, `buzz-ifc` Information Flow Control, `nsec-backup`, and `NIP-AB` pairing | `v1.0.0` (`4fb386b0b`) | `xyz.block.buzz.desktop` |

## 2. Critical Windows NTFS `Buzz.exe` vs `buzz.exe` Case-Insensitive Collision

On Windows NTFS (which is case-insensitive by default), the packaging layout changed between Buzz `0.5.x` and Buzz `1.0.0`:

- **Buzz `0.5.28` (`Buzz_0.5.28_x64-setup_alpha-unsigned.exe`)**:
  - GUI application: `%LOCALAPPDATA%\Programs\Buzz\buzz-desktop.exe` (PE subsystem `IMAGE_SUBSYSTEM_WINDOWS_GUI = 2`)
  - CLI binary: `%LOCALAPPDATA%\Programs\Buzz\buzz.exe` (PE subsystem `IMAGE_SUBSYSTEM_WINDOWS_CUI = 3`)
- **Buzz `1.0.0` (`Buzz_1.0.0_x64_unsigned.exe`)**:
  - GUI application: `%LOCALAPPDATA%\Programs\Buzz\Buzz.exe` (148 MB GUI binary, PE subsystem `IMAGE_SUBSYSTEM_WINDOWS_GUI = 2`)
  - CLI binary: `%LOCALAPPDATA%\Programs\Buzz\bin\buzz.exe` (PE subsystem `IMAGE_SUBSYSTEM_WINDOWS_CUI = 3`)

### Why This Matters for AI Agents and Operators

1. **Silent CLI Overwrite**: Running the `1.0.0` NSIS installer directly into `%LOCALAPPDATA%\Programs\Buzz\` overwrites `buzz.exe` at the install root with the 148 MB GUI `Buzz.exe`. Any script, scheduled task, or agent invoking `Programs\Buzz\buzz.exe` will spawn a GUI desktop window instead of running a console CLI command.
2. **Separate Tauri AppData Stores**: Buzz `0.X` stores its joined communities, WebView local storage, and managed ACP agent rosters under `%APPDATA%\xyz.block.buzz.app` and `%LOCALAPPDATA%\xyz.block.buzz.app`. Buzz `1.0.0` uses `xyz.block.buzz.desktop` and does not automatically migrate `0.X` joined communities or local ACP agent definitions.
3. **Windows Desktop Credential Transport Status**: In Buzz `1.0.0`, `BUZZ_CREDENTIAL_PROVIDER` and `buzz auth desktop pair` support macOS and Linux keychain sockets first; on native Windows, CLI and ACP agents authenticate reliably using `BUZZ_PRIVATE_KEY` (`nsec1...` or 64-char hex).

### Recommended Coexistence Layout on Windows

- Keep `Programs\Buzz\buzz-desktop.exe` (`0.5.28` or owner-patched `0.5.28-owner.1`) as the active `xyz.block.buzz.app` client when preserving existing `0.X` community state and Windows ACP harnesses.
- Upgrade `Programs\Buzz\bin\buzz.exe` AND `Programs\Buzz\buzz.exe` to the `1.0.0` console CLI binary (`c8d736642e1c`, PE subsystem `CUI = 3`) alongside `bin\buzz-agent-command.exe` and `bin\goose-acp.exe`.
- Stage the `1.0.0` GUI executable in a separate folder (`Programs\Buzz-1.0\Buzz.exe`) so `Buzz.exe` never collides with `Programs\Buzz\buzz.exe`.
- Run `legends-buzz desktop-audit --json` after any desktop update to verify PE subsystems (`cui` vs `gui`) and confirm zero NTFS collisions.

## 3. Preventing the Empty-Asset Custom Desktop Build Trap

When building `buzz-desktop.exe` from source on Windows (for example to apply custom moderation or notification patches), Tauri embeds the compiled frontend assets from `desktop/dist` (or the protected feature artifact staging directory) into the Rust executable only if `pnpm build` completes before `cargo build --release`.

- If `cargo build --release` is run against an unbuilt or cleaned frontend directory, Rust compiles a valid ~15 MB GUI binary containing zero embedded WebView assets (`has_index_html = false`, `asset_count = 0`), resulting in a blank white window at launch (first observed in `0.5.22`).
- `legends-buzz desktop-audit` scans the compiled executable for `index.html` and hashed `assets/...` bundle entries (expecting 200+ embedded assets in `1.0.0` and 480+ embedded assets in `0.5.28`) before the binary is promoted.

## 4. See Also

- [Overview & System Architecture](overview.md)
- [Complete 25-Domain MCP-to-CLI Reference Map](mcp-to-cli-complete-map.md)
- [Troubleshooting & Anti-Patterns](troubleshooting.md)
