# Release procedure

This module ships the `legends-buzz` CLI, drop-in server/agent blueprints, and an attachable Block Buzz operational knowledge pack. Use the central [module release contract](https://github.com/avalonreset/cto-legends/blob/main/docs/MODULE-RELEASE.md) and keep private relay receipts outside the distributed repository.

## Pre-release verification

1. Run the offline release gate:
   ```bash
   python scripts/check_release.py --root .
   ```
2. Run the unit and packaging test suite:
   ```bash
   python -m unittest discover -s tests -v
   ```
3. Build the wheel and source distribution and verify the installed wheel mirror:
   ```bash
   python -m build
   python tests/test_packaging.py WheelSmoke -v
   ```
4. Verify knowledge pack attachment against `legends-empire` in a synthetic temporary vault:
   ```bash
   python scripts/verify_knowledge_attachment.py --empire-source /abs/path/to/legends-empire --pack knowledge/buzz/pack.json
   ```
5. Execute live relay and desktop verification (`doctor --live`, `cli-inventory`, `desktop-audit`, `relay-probe`, `membership-check`, `owner-access-audit`, `channel-snapshot`, and `message-canary`), and record sanitized receipts in the private Empire vault.
