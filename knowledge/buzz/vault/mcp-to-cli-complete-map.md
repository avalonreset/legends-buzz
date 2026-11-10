# Complete 26-Domain MCP-to-CLI Reference Map

## 1. Zero-Daemon Agent Routing Principle

Every capability exposed by the Buzz MCP server (`buzz-dev-mcp`) is natively available in the standalone `buzz` CLI (`buzz-cli`) with deterministic JSON output and exit codes. Agents using `legends-buzz` do not need to install or maintain a persistent MCP daemon process:

1. Query `legends-buzz mcp-map --intent "<goal>"` or `legends-buzz mcp-map --domain <domain>` to resolve the exact CLI syntax.
2. Execute `buzz --format agent --relay <https-url> <domain> <subcommand> ...` (or `--format json`) with `BUZZ_PRIVATE_KEY` injected via environment variables.
3. Inspect the deterministic exit code (`0..5`) and structured JSON stdout/stderr.

## 2. Global Flags & Output Formats

| Flag / Variable | Introduced | Behavior |
| --- | --- | --- |
| `--format agent` | `1.0.0` | Drops 64-byte Schnorr `sig` fields and `NIP-OA` `auth` conditions on event reads, and folds `NIP-10` thread tags into `reply_to` and `thread_root`. Default for harness-managed agents. |
| `--format json` | `0.5.x` | Full normalized JSON including raw Nostr event IDs, pubkeys, tags, and signatures. |
| `--format compact` | `0.5.x` | Reduced-field JSON for high-volume history scanning. |
| `BUZZ_RELAY_URL` | `0.5.x` | Default relay base URL (`https://...`). |
| `BUZZ_PRIVATE_KEY` | `0.5.x` | Nostr secret key (`nsec1...` or 64-char hex). Never pass via `--private-key` on shared process tables. |
| `BUZZ_AUTH_TAG` | `0.5.x` | Optional `NIP-OA` owner attestation JSON injected into signed events. |
| `BUZZ_FEDERATED_IDENTITY_TOKEN` | `1.0.0` | `NIP-FA` sign-in session token for `NIP-FI` federated relays. |
| `BUZZ_FEDERATED_IDENTITY_ADAPTER` | `1.0.0` | `NIP-FA` adapter base URL that mints per-request assertions. |

## 3. Deterministic CLI Exit Codes

| Exit Code | Category | Meaning | Recommended Agent Action |
| --- | --- | --- | --- |
| `0` | `OK` | Command succeeded; structured JSON written to stdout | Parse JSON output and record event IDs |
| `1` | `BAD_INPUT` | Missing or invalid CLI flags (`{"error": "user_error"}`) | Check `legends-buzz mcp-map --domain <d>` |
| `2` | `RELAY_OR_NETWORK_ERROR` | Network timeout, DNS failure, or upstream relay HTTP 5xx | Run `legends-buzz relay-probe --relay <url>` |
| `3` | `AUTH_ERROR` | Missing key, `403 relay_membership_required`, or missing `NIP-FI` assertion | Run `legends-buzz membership-check --relay <url>` |
| `4` | `OTHER_ERROR` | Resource not found or local validation failure | Re-list parent collection (`channels list`, `repos list`) |
| `5` | `WRITE_CONFLICT` | Optimistic concurrency mismatch (e.g. `buzz mem patch --base-hash`) | Re-read `buzz mem get` and `buzz mem hash` before retrying |

## 4. All 26 Command Domains at a Glance

| Domain | Introduced | Primary Subcommands | Key NIPs |
| --- | --- | --- | --- |
| `agents` | `0.5.x` | `draft-create`, `draft-update`, `archive`, `unarchive`, `archived` | `NIP-IA`, `NIP-OA` |
| `messages` | `0.5.x` | `send`, `send-diff`, `edit`, `delete`, `report` (`1.0.0`), `get`, `thread`, `search`, `vote` | `NIP-29`, `NIP-10`, `NIP-56` |
| `channels` | `0.5.x` | `list`, `unread` (`1.0.0`), `get`, `search`, `create`, `update`, `topic`, `purpose`, `join`, `leave`, `archive`, `unarchive`, `delete`, `members`, `add-member`, `remove-member`, `set-add-policy` | `NIP-29` |
| `canvas` | `0.5.x` | `get`, `set`, `history`, `restore` | `NIP-29` |
| `sidebar` | `1.0.0` | `sections` (`list`, `create`, `update`, `delete`, `reorder`, `move`, `unassign`), `sort`, `stars`, `mutes`, `projects` | `NIP-51`, `NIP-78` |
| `reactions` | `0.5.x` | `add`, `remove`, `get` | `NIP-25`, `NIP-30` |
| `emoji` | `0.5.x` | `list`, `set`, `rm`, `export`, `import` | `NIP-30` |
| `gifs` | `0.5.x` | `search`, `share` | `NIP-29` |
| `dms` | `0.5.x` | `list`, `open`, `add-member`, `hide` | `NIP-17`, `NIP-44` |
| `huddles` | `1.0.0` | `list`, `participants` | `NIP-29`, `NIP-100` |
| `users` | `0.5.x` | `get`, `set-profile`, `presence`, `set-presence`, `set-status`, `status` | `NIP-01`, `NIP-38` |
| `workflows` | `0.5.x` | `list`, `get`, `create`, `update`, `delete`, `trigger`, `runs`, `approve` | `NIP-29` |
| `feed` | `0.5.x` | `get` | `NIP-29` |
| `social` | `0.5.x` | `publish`, `set-contacts`, `event`, `notes`, `contacts`, `set-list`, `list` | `NIP-01`, `NIP-02`, `NIP-51` |
| `notes` | `0.5.x` | `set`, `get`, `ls`, `rm` | `NIP-23`, `NIP-09` |
| `repos` | `0.5.x` | `create`, `get`, `list`, `bind`, `protect` (`1.0.0`), `default-branch` (`1.0.0`) | `NIP-34` |
| `projects` | `1.0.0` | `create`, `get`, `list`, `add-repo`, `add-channel`, `remove-repo`, `update`, `delete` | `NIP-MP` (`kind:30621`) |
| `patches` | `0.5.x` | `send`, `get`, `list`, `status` | `NIP-34` (`kind:1617`) |
| `issues` | `0.5.x` | `create`, `get`, `list`, `status`, `assign`, `unassign` | `NIP-34` (`kind:1621`) |
| `pr` | `0.5.x` | `open`, `update`, `get`, `list`, `status` | `NIP-34` (`kind:1618-1619`) |
| `media` | `0.5.x` | `get` | `BUD-01` |
| `upload` | `0.5.x` | `file` | `BUD-02` |
| `mem` | `0.5.x` | `ls`, `get`, `hash`, `set`, `patch`, `rm` | `NIP-AE` |
| `pack` | `0.5.x` | `validate`, `inspect` | `NIP-AE` |
| `auth` | `1.0.0` | `desktop` (`pair`, `unpair`, `list`) | `NIP-AB` |
| `moderation` | `0.5.x` | `reports`, `resolve`, `ban`, `unban`, `timeout`, `untimeout`, `restricted`, `audit` | `NIP-29`, `NIP-56` |

## 5. High-Frequency CLI Recipes

```bash
# 1. List visible channels and unread counts
buzz --format json channels list
buzz --format json channels unread

# 2. Read recent channel messages in token-efficient agent format
buzz --format agent messages get --channel <channel-uuid> --limit 25

# 3. Send a message or threaded reply
buzz --format json messages send --channel <channel-uuid> --content "Deployment complete."
buzz --format json messages send --channel <channel-uuid> --content "Verified on staging." --reply-to <root-event-id>

# 4. Add and remove an emoji reaction
buzz --format json reactions add --event <event-id> --emoji "👍"
buzz --format json reactions remove --event <event-id> --emoji "👍"

# 5. Update a memory engram safely using optimistic concurrency (--base-hash)
BASE_HASH="$(buzz mem hash runbook-notes)"
buzz --format json mem patch runbook-notes --base-hash "${BASE_HASH}" < changes.diff
```

## 6. See Also

- [Identity, Relay Membership & NIP-FI Federated Auth](identity-membership-and-nip-fi.md)
- [ACP Subscription Agents, Buzzodz Plugins & Durable Bridges](agents-acp-and-bridges.md)
- [Moderation, NIP-34 Git Repos, NIP-MP Projects & Workflows](moderation-projects-and-workflows.md)
