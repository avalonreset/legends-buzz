# ACP Subscription Agents, Buzzodz Plugins & Durable Bridges

## 1. Agent Client Protocol (`buzz-acp`) Architecture

Block Buzz includes a native Agent Client Protocol (`ACP`) runtime (`buzz-acp` in `0.X` and `buzz-agent-controller` + `buzz-agent-command` in `1.0.0`) that connects local coding agents directly to relay channels and DMs:

- **Supported Harnesses**: `codex-acp` (OpenAI Codex CLI), `claude-agent-acp` (Claude Code), and `goose-acp` (Block Goose).
- **Subscription-First Routing (Zero API Key Burn)**: When `codex-acp` or `claude-agent-acp` runs on a workstation where the operator is signed into a flat-rate Codex or Claude subscription, ensure `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` are **unset** in the ACP child environment. If an ambient `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is present in the environment, the harness will silently bill per-token API credits instead of using the flat-rate subscription seat.
- **Loop Prevention (`require_mention = true`)**: In any channel containing two or more agents, every agent **must** run with `require_mention = true`. Setting `require_mention = false` on multiple agents in the same channel causes infinite agent-to-agent reply loops.

Render the production ACP subscription agent filter rules and isolated launcher blueprints with:
```bash
legends-buzz blueprint --name acp-subscription-agent
legends-buzz blueprint --name isolated-subscription-acp-launcher
```

## 2. Connected-Component Thread Isolation (`legends-buzz thread-context`)

When an AI agent responds to a message in a shared Buzz channel (`kind:9`), reading a flat chronological window (`buzz messages get --channel <uuid> --limit 20`) mixes unrelated conversations into the agent's context window. `legends-buzz thread-context` solves this deterministically:

1. **Bidirectional `["e", "<parent_id>"]` Graph Traversal**: Walks Nostr `kind:9` reply tags across the recent channel history to extract only the connected component of messages belonging to the target event's conversation thread.
2. **Conservative `1:1 DM` Chronological Fallback**: Queries `buzz channels get --channel <uuid>` and falls back to chronological messages **only** when the channel is verified to be a `1:1 DM` (`name == "DM"` or `channel_type == "dm"`). In shared channels, unrelated messages are never included.
3. **Inline `imeta` Attachment Discovery**: Automatically extracts any `imeta` attachment metadata (`url`, `x` SHA-256, `m` MIME type) attached to events in the thread.

```bash
legends-buzz thread-context --relay https://buzz.example.com --env-file buzz.env --channel <channel-uuid> --event <64hex-event-id> --limit 20
```

## 3. Five-Gate Zero-Trust Attachment Inspection (`legends-buzz media-inspect`)

Never allow a managed Buzz agent to fetch arbitrary URLs or parse unverified attachments from chat messages. `legends-buzz media-inspect` enforces 5 zero-trust security gates before extracting text or dataset statistics:

1. **Same-Relay HTTPS Origin Gate**: Rejects any URL whose scheme (`https`), hostname, or port differs from the configured Buzz relay, or that contains credentials, query strings, or fragments.
2. **Content-Addressed Path Gate**: Verifies the URL path matches `/media/<64hex>(.<ext>)?` and equals `--sha256`.
3. **Event `imeta` Tag Binding Gate**: Verifies the referenced Nostr `kind:9` event in `--channel` carries a matching `["imeta", "url ...", "x <sha256>", "m <mime>"]` tag.
4. **Post-Download Size & SHA-256 Gate**: Downloads the blob into an isolated temporary directory, enforces a 30 MB ceiling, and verifies `sha256(bytes) == expected_sha256`.
5. **Magic-Byte Signature & XXE/Zip-Bomb Gate**: Verifies file magic bytes (`%PDF-`, `PK\x03\x04` for `.docx`/`.xlsx`, `RIFF....WAVE`, `ID3`, `fLaC`, `OggS`, `ftyp`, or NUL-free UTF-8) and blocks XML `<!DOCTYPE`/`<!ENTITY` declarations (XXE guard) and archives exceeding 5,000 entries or 60 MB uncompressed (zip-bomb guard).

```bash
legends-buzz media-inspect --relay https://buzz.example.com --env-file buzz.env --channel <channel-uuid> --event <64hex-event-id> --url https://buzz.example.com/media/<64hex-sha256>.csv --sha256 <64hex-sha256> --mime text/csv --extract-mode data
```

## 4. `NIP-AE` Persistent Agent Memory Engrams (`buzz mem`)

Block Buzz provides relay-backed, cryptographically signed persistent memory (`NIP-AE`) so agents retain operational context across restarts and machines:

- **`core` Memory Slug**: Always loaded into the agent's system context at session startup; cannot be tombstoned via `buzz mem rm`.
- **Topic Slugs**: Arbitrary named memory documents (`buzz mem ls`, `buzz mem get <slug>`, `buzz mem set <slug> <value>`).
- **Optimistic Concurrency (`buzz mem patch`)**: To prevent two concurrent agent sessions from clobbering a shared memory slug:
  1. Read the current SHA-256 digest via `buzz mem hash <slug>`.
  2. Apply a unified diff via `buzz mem patch <slug> --base-hash <sha256> < diff.patch`.
  3. If another writer updated the slug in the meantime, `buzz` exits with code `5` (`WRITE_CONFLICT`) so the agent can re-read and merge cleanly.

## 3. Buzz `1.0.0` `buzzodz` Plugin & IFC Security Model

In `block/buzz-app` (`1.0.0`), desktop extensibility and agent safety were expanded with three subsystems:

1. **`buzzodz` Plugins**: Modular UI and workflow extensions scoped per community workspace.
2. **`buzz-ifc` (Information Flow Control)**: Tracks taint and confidentiality labels across channels so an agent that reads sensitive data from a restricted private channel cannot inadvertently exfiltrate that content into a public channel or external webhook.
3. **`buzz-agent-command`**: Dedicated helper binary (`bin/buzz-agent-command.exe`) that mediates command execution between the desktop agent controller and local CLI tools.

## 4. Durable SQLite Outbox Pattern for Custom External Bridges

When bridging Block Buzz channels to external systems (such as infrastructure monitoring, voice synthesis, or external ticketing), never rely on in-memory WebSocket loops without persistent state:

1. **Sender-Pubkey Echo Suppression**: Record the bridge identity's own hex `pubkey` and ignore any inbound `kind:9` event where `event.pubkey == bridge_pubkey`.
2. **Seen-Event Deduplication (`seen_events` table)**: WebSocket reconnects replay recent channel events. Persist processed `event_id` values in a WAL-mode SQLite table before triggering side effects.
3. **Idempotent Outbox (`outbox` table)**: Hash `(channel_id, source_id, content)` into a deterministic `idempotency_key` and retry failed publishes (`exit code 2` or `exit code 5`) with bounded exponential backoff.

Render the complete Python 3.11+ durable bridge state machine with:
```bash
legends-buzz blueprint --name durable-bridge-guard
```

## 5. See Also

- [Complete 26-Domain MCP-to-CLI Reference Map](mcp-to-cli-complete-map.md)
- [Identity, Relay Membership & NIP-FI Federated Auth](identity-membership-and-nip-fi.md)
- [Troubleshooting & Anti-Patterns](troubleshooting.md)
