# Agent Instructions for legends-buzz

Start with [docs/AGENT-RECIPE.md](docs/AGENT-RECIPE.md) and [wiki/index.md](wiki/index.md).

## Core Operating Rules

1. **Single Router Skill**: Discovery belongs to `skills/cto-legends/SKILL.md`. Do not add secondary skills under `skills/`.
2. **Zero Secret Exposure**: Never print or log `nsec1...` keys, 64-character hex private keys (`BUZZ_PRIVATE_KEY`), or `BUZZ_FEDERATED_IDENTITY_TOKEN` values.
3. **Preview-First Mutations**: Live canary mutations (`message-canary`) require a preview pass followed by `--apply --confirm-plan <sha256>`, and always clean up disposable test messages in a `finally:` block.
4. **Windows Defender, EDR, and Anti-Ransomware Guardrails**: Never spawn hidden consoles, execution-policy bypass shell wrappers, or background localhost daemons. Verify Windows PE subsystem headers (`IMAGE_SUBSYSTEM_WINDOWS_CUI`) before invoking `buzz.exe` so an NTFS `Buzz.exe` GUI binary collision never launches a desktop window.
5. **Release Hygiene**: Run `python scripts/check_release.py --root .` and `python -m unittest discover -s tests -v` before packaging.
