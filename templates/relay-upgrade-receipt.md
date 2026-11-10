# Self-Hosted Buzz Relay Upgrade Receipt

- **Upgrade ID:** `<upgrade-id>`
- **Timestamp (UTC):** `<YYYY-MM-DDTHH:MM:SSZ>`
- **Relay URL:** `<https://buzz.example.com>`
- **Previous Image Digest:** `ghcr.io/block/buzz@sha256:<previous-digest>`
- **Promoted Image Digest:** `ghcr.io/block/buzz@sha256:<new-digest>`

## 8-Gate Verification Ledger

| Gate | Check | Result | Evidence |
| --- | --- | --- | --- |
| 1 | Pre-upgrade `relay-probe` (`/health`, `/_readiness`, NIP-11) | `<PASS>` | `status=200` |
| 2 | Consistent `pg_dump -Fc` backup snapshot | `<PASS>` | `<backup-file-path-and-bytes>` |
| 3 | Live `_sqlx_migrations` max version recorded | `<PASS>` | `max_version=<N>` |
| 4 | Isolated `--internal` Docker network created | `<PASS>` | `buzz_stage_verify_net` |
| 5 | Candidate relay booted against cloned staging DB | `<PASS>` | `stage_max_version=<M> (>= <N>)` |
| 6 | Production `buzz-relay` promoted by `@sha256` digest | `<PASS>` | `container_id=<id>` |
| 7 | Post-upgrade `membership-check` and `owner-access-audit` | `<PASS>` | `status=member`, `gap_count=0` |
| 8 | Disposable `message-canary` (`send -> get -> react -> delete`) | `<PASS>` | `canary_event_id=<64-hex>` |
