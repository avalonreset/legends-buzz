# Buzz Channel Canary Verification Receipt

- **Canary Run ID:** `<canary-id>`
- **Timestamp (UTC):** `<YYYY-MM-DDTHH:MM:SSZ>`
- **Relay URL:** `<https://buzz.example.com>`
- **Channel UUID:** `<channel-uuid>`
- **Approved Plan SHA-256:** `<64-hex-plan-sha256>`
- **Canary Event ID:** `<64-hex-event-id>`

## Step Verification

| Step | Action | CLI Subcommand | Status |
| --- | --- | --- | --- |
| 1 | Publish disposable canary message | `buzz messages send --channel <uuid> --content ...` | `<PASS>` |
| 2 | Readback message from channel | `buzz messages get --channel <uuid> --limit 5` | `<PASS>` |
| 3 | Add reaction (`NIP-25` `kind:7`) | `buzz reactions add --event <id> --emoji 👍` | `<PASS>` |
| 4 | Remove reaction | `buzz reactions remove --event <id> --emoji 👍` | `<PASS>` |
| 5 | Delete canary message (`finally` cleanup) | `buzz messages delete --event <id>` | `<PASS>` |
