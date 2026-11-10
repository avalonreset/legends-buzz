# Private Buzz Operation Receipt

- **Operation ID:** `<operation-id>`
- **Timestamp (UTC):** `<YYYY-MM-DDTHH:MM:SSZ>`
- **Relay URL:** `<https://buzz.example.com>`
- **Key Classification:** `<nsec|hex64>` (fingerprint: `<sha256:8hex>`)
- **Operator / Agent:** `<name>`

## 1. Preflight Verification

- `legends-buzz doctor --live`: `<pass|fail>`
- `legends-buzz membership-check`: `<member|residual_403|nip_fi_required>`
- `legends-buzz desktop-audit`: `<healthy: true|false>`

## 2. Executed Commands & Event Receipts

| Step | Command | Exit Code | Event / Channel ID |
| --- | --- | --- | --- |
| 1 | `<command>` | `0` | `<id>` |

## 3. Post-Condition Verification

- Channel / Roster Readback Verified: `<yes|no>`
- Rollback Required: `<no|yes>`
