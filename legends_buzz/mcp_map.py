"""Complete 26-domain / 108-subcommand MCP-to-CLI reference map and intent router for Block Buzz."""
from __future__ import annotations

from typing import Any

EXIT_CODES: dict[int, dict[str, str]] = {
    0: {
        "name": "OK",
        "meaning": "Operation completed and returned structured JSON on stdout.",
        "agent_action": "Parse JSON stdout and record event/channel receipts.",
    },
    1: {
        "name": "BAD_INPUT",
        "meaning": "Invalid CLI flags, missing --channel/--event/--content arguments, or malformed UUID/hex ID.",
        "agent_action": "Inspect JSON error on stderr ({\"error\": \"user_error\"}) and consult legends-buzz mcp-map.",
    },
    2: {
        "name": "RELAY_OR_NETWORK_ERROR",
        "meaning": "Relay unreachable, TLS handshake failure, timeout, or relay returned an upstream HTTP error.",
        "agent_action": "Run legends-buzz relay-probe --relay <url> and retry with bounded exponential backoff if retryable=true.",
    },
    3: {
        "name": "AUTH_ERROR",
        "meaning": "Missing or rejected BUZZ_PRIVATE_KEY, HTTP 403 relay_membership_required, or missing NIP-FI assertion.",
        "agent_action": "Run legends-buzz membership-check --relay <url> to distinguish residual 403 membership gaps from NIP-FI gates.",
    },
    4: {
        "name": "OTHER_ERROR",
        "meaning": "Target resource not found, unsupported operation, or local filesystem/pack error.",
        "agent_action": "Re-list the parent collection (channels list, repos list, notes ls) and verify identifiers.",
    },
    5: {
        "name": "WRITE_CONFLICT",
        "meaning": "Optimistic concurrency conflict on addressable state (e.g. mem patch --base-hash or canvas restore).",
        "agent_action": "Re-fetch current state and base hash (buzz mem get / buzz mem hash) before re-applying the patch.",
    },
}

ENV_VARS: list[dict[str, str]] = [
    {
        "name": "BUZZ_RELAY_URL",
        "introduced": "0.5.x",
        "purpose": "Default Buzz relay base URL (https:// or http://) so --relay can be omitted on each CLI invocation.",
    },
    {
        "name": "BUZZ_PRIVATE_KEY",
        "introduced": "0.5.x",
        "purpose": "Nostr identity secret key (nsec1... Bech32 or 64-char hex). Never pass on the command line.",
    },
    {
        "name": "BUZZ_AUTH_TAG",
        "introduced": "0.5.x",
        "purpose": "Optional NIP-OA owner attestation auth tag JSON injected into signed events.",
    },
    {
        "name": "BUZZ_OUTPUT_FORMAT",
        "introduced": "1.0.0",
        "purpose": "Default --format value: json (default), compact (reduced fields), or agent (drops sig/auth, folds NIP-10 threads).",
    },
    {
        "name": "BUZZ_FEDERATED_IDENTITY_TOKEN",
        "introduced": "1.0.0",
        "purpose": "Human NIP-FA sign-in session token used with BUZZ_FEDERATED_IDENTITY_ADAPTER on NIP-FI relays.",
    },
    {
        "name": "BUZZ_FEDERATED_IDENTITY_ADAPTER",
        "introduced": "1.0.0",
        "purpose": "NIP-FA adapter base URL that mints per-request federated identity assertions for the CLI.",
    },
    {
        "name": "BUZZ_CREDENTIAL_PROVIDER",
        "introduced": "1.0.0",
        "purpose": "Desktop credential transport selector (macOS/Linux in 1.0.0; Windows agents use BUZZ_PRIVATE_KEY).",
    },
]

GLOBAL_AGENT_FLAGS: list[dict[str, str]] = [
    {
        "flag": "--format agent",
        "introduced": "1.0.0",
        "description": "Event reads drop signature material (sig, NIP-OA auth conditions) and fold NIP-10 thread markers into reply_to/thread_root.",
    },
    {
        "flag": "--format json",
        "introduced": "0.5.x",
        "description": "Full normalized JSON output including event IDs, pubkeys, tags, and cryptographic signatures (default).",
    },
    {
        "flag": "--format compact",
        "introduced": "0.5.x",
        "description": "Reduced-field JSON output for fast agent scanning over large histories.",
    },
    {
        "flag": "--relay <URL>",
        "introduced": "0.5.x",
        "description": "Target Buzz relay URL (overrides BUZZ_RELAY_URL environment variable).",
    },
    {
        "flag": "--auth-tag <JSON>",
        "introduced": "0.5.x",
        "description": "NIP-OA owner attestation JSON injected into signed events (overrides BUZZ_AUTH_TAG).",
    },
]

MCP_DOMAINS: list[dict[str, Any]] = [
    {
        "domain": "agents",
        "introduced": "0.5.x",
        "nips": ["NIP-IA", "NIP-OA"],
        "summary": "Draft owner-reviewed agent creation/updates and manage NIP-IA identity archive state.",
        "keywords": ["agent", "draft-create", "draft-update", "archive", "unarchive", "nip-ia", "bot"],
        "subcommands": [
            {
                "name": "draft-create",
                "mcp_tool": "buzz_agents_draft_create",
                "syntax": "buzz --format json agents draft-create --name <name> [--description <text>]",
                "mutates": True,
                "notes": "Opens a prefilled create-agent form in the owner's Buzz Desktop.",
            },
            {
                "name": "draft-update",
                "mcp_tool": "buzz_agents_draft_update",
                "syntax": "buzz --format json agents draft-update --agent <pubkey> [--name <name>]",
                "mutates": True,
                "notes": "Opens a prefilled edit-agent form in the owner's Buzz Desktop.",
            },
            {
                "name": "archive",
                "mcp_tool": "buzz_agents_archive",
                "syntax": "buzz --format json agents archive --pubkey <pubkey>",
                "mutates": True,
                "notes": "Submits a NIP-IA archive request for an identity (kind:9035).",
            },
            {
                "name": "unarchive",
                "mcp_tool": "buzz_agents_unarchive",
                "syntax": "buzz --format json agents unarchive --pubkey <pubkey>",
                "mutates": True,
                "notes": "Submits a NIP-IA unarchive request for an identity (kind:9036).",
            },
            {
                "name": "archived",
                "mcp_tool": "buzz_agents_archived",
                "syntax": "buzz --format json agents archived",
                "mutates": False,
                "notes": "Reads the relay's current NIP-IA archive snapshot (kind:13535).",
            },
        ],
    },
    {
        "domain": "messages",
        "introduced": "0.5.x",
        "nips": ["NIP-29", "NIP-10", "NIP-09", "NIP-56"],
        "summary": "Send, read, edit, delete, report, thread-inspect, search, and vote on channel messages.",
        "keywords": ["message", "send", "send-diff", "edit", "delete", "report", "get", "thread", "search", "vote"],
        "subcommands": [
            {
                "name": "send",
                "mcp_tool": "buzz_messages_send",
                "syntax": "buzz --format json messages send --channel <uuid> --content <text> [--reply-to <event-id>] [--mention <pubkey>...] [--file <path>...]",
                "mutates": True,
                "notes": "Sends a message to a channel; use --content - to read from stdin.",
            },
            {
                "name": "send-diff",
                "mcp_tool": "buzz_messages_send_diff",
                "syntax": "buzz --format json messages send-diff --channel <uuid> --diff <patch-text-or-stdin>",
                "mutates": True,
                "notes": "Sends a formatted code diff or patch to a channel.",
            },
            {
                "name": "edit",
                "mcp_tool": "buzz_messages_edit",
                "syntax": "buzz --format json messages edit --event <event-id> --content <new-text>",
                "mutates": True,
                "notes": "Edits a previously sent message authored by the active identity.",
            },
            {
                "name": "delete",
                "mcp_tool": "buzz_messages_delete",
                "syntax": "buzz --format json messages delete --event <event-id> [--reason-code <code>] [--public-reason <text>]",
                "mutates": True,
                "notes": "Deletes a message by 64-char hex event ID.",
            },
            {
                "name": "report",
                "mcp_tool": "buzz_messages_report",
                "syntax": "buzz --format json messages report --event <event-id> --reason <category> [--comment <text>]",
                "mutates": True,
                "notes": "Added in 1.0.0 CLI: reports a message or user to community moderators (NIP-56 kind:1984).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_messages_get",
                "syntax": "buzz --format agent messages get --channel <uuid> [--limit <n>] [--before <ts>] [--since <ts>]",
                "mutates": False,
                "notes": "Retrieves messages from a channel; --format agent drops sigs and folds NIP-10 thread markers.",
            },
            {
                "name": "thread",
                "mcp_tool": "buzz_messages_thread",
                "syntax": "buzz --format agent messages thread --event <event-id-or-link>",
                "mutates": False,
                "notes": "Fetches the containing thread root and replies for a message or Buzz link.",
            },
            {
                "name": "search",
                "mcp_tool": "buzz_messages_search",
                "syntax": "buzz --format agent messages search --query <text> [--channel <uuid>] [--limit <n>]",
                "mutates": False,
                "notes": "Full-text search across channel messages.",
            },
            {
                "name": "vote",
                "mcp_tool": "buzz_messages_vote",
                "syntax": "buzz --format json messages vote --event <event-id> --direction <up|down>",
                "mutates": True,
                "notes": "Upvotes or downvotes a forum post.",
            },
        ],
    },
    {
        "domain": "channels",
        "introduced": "0.5.x",
        "nips": ["NIP-29"],
        "summary": "Create, configure, join, archive, manage members, and check unread counts for relay channels.",
        "keywords": ["channel", "list", "unread", "get", "search", "create", "update", "topic", "purpose", "join", "leave", "members"],
        "subcommands": [
            {
                "name": "list",
                "mcp_tool": "buzz_channels_list",
                "syntax": "buzz --format json channels list",
                "mutates": False,
                "notes": "Lists channels visible to the current identity.",
            },
            {
                "name": "unread",
                "mcp_tool": "buzz_channels_unread",
                "syntax": "buzz --format json channels unread",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: returns unread message counts from synced read state (read-only).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_channels_get",
                "syntax": "buzz --format json channels get --channel <uuid>",
                "mutates": False,
                "notes": "Gets details for a single channel.",
            },
            {
                "name": "search",
                "mcp_tool": "buzz_channels_search",
                "syntax": "buzz --format json channels search --query <name>",
                "mutates": False,
                "notes": "Searches channels by human-readable name.",
            },
            {
                "name": "create",
                "mcp_tool": "buzz_channels_create",
                "syntax": "buzz --format json channels create --name <name> [--visibility open|private]",
                "mutates": True,
                "notes": "Creates a new NIP-29 channel.",
            },
            {
                "name": "update",
                "mcp_tool": "buzz_channels_update",
                "syntax": "buzz --format json channels update --channel <uuid> [--name <name>] [--description <text>]",
                "mutates": True,
                "notes": "Updates channel name, description, visibility, join role, auto-join, or ephemeral TTL.",
            },
            {
                "name": "topic",
                "mcp_tool": "buzz_channels_topic",
                "syntax": "buzz --format json channels topic --channel <uuid> --topic <text>",
                "mutates": True,
                "notes": "Sets the channel topic.",
            },
            {
                "name": "purpose",
                "mcp_tool": "buzz_channels_purpose",
                "syntax": "buzz --format json channels purpose --channel <uuid> --purpose <text>",
                "mutates": True,
                "notes": "Sets the channel purpose.",
            },
            {
                "name": "join",
                "mcp_tool": "buzz_channels_join",
                "syntax": "buzz --format json channels join --channel <uuid>",
                "mutates": True,
                "notes": "Joins an open channel.",
            },
            {
                "name": "leave",
                "mcp_tool": "buzz_channels_leave",
                "syntax": "buzz --format json channels leave --channel <uuid>",
                "mutates": True,
                "notes": "Leaves a channel.",
            },
            {
                "name": "archive",
                "mcp_tool": "buzz_channels_archive",
                "syntax": "buzz --format json channels archive --channel <uuid>",
                "mutates": True,
                "notes": "Archives a channel.",
            },
            {
                "name": "unarchive",
                "mcp_tool": "buzz_channels_unarchive",
                "syntax": "buzz --format json channels unarchive --channel <uuid>",
                "mutates": True,
                "notes": "Unarchives a channel.",
            },
            {
                "name": "delete",
                "mcp_tool": "buzz_channels_delete",
                "syntax": "buzz --format json channels delete --channel <uuid>",
                "mutates": True,
                "notes": "Deletes a channel permanently.",
            },
            {
                "name": "members",
                "mcp_tool": "buzz_channels_members",
                "syntax": "buzz --format json channels members --channel <uuid>",
                "mutates": False,
                "notes": "Lists members and roles (owner, admin, member) of a channel.",
            },
            {
                "name": "add-member",
                "mcp_tool": "buzz_channels_add_member",
                "syntax": "buzz --format json channels add-member --channel <uuid> --pubkey <hex-or-npub> [--role admin|member]",
                "mutates": True,
                "notes": "Adds a member or promotes a role in a channel.",
            },
            {
                "name": "remove-member",
                "mcp_tool": "buzz_channels_remove_member",
                "syntax": "buzz --format json channels remove-member --channel <uuid> --pubkey <hex-or-npub>",
                "mutates": True,
                "notes": "Removes a member from a channel.",
            },
            {
                "name": "set-add-policy",
                "mcp_tool": "buzz_channels_set_add_policy",
                "syntax": "buzz --format json channels set-add-policy --policy <policy>",
                "mutates": True,
                "notes": "Sets your personal channel addition policy.",
            },
        ],
    },
    {
        "domain": "canvas",
        "introduced": "0.5.x",
        "nips": ["NIP-29"],
        "summary": "Get, set, inspect revision history, and restore channel collaborative Markdown canvases.",
        "keywords": ["canvas", "markdown", "pad", "history", "restore", "channel doc"],
        "subcommands": [
            {
                "name": "get",
                "mcp_tool": "buzz_canvas_get",
                "syntax": "buzz --format json canvas get --channel <uuid> [--revision <event-id>]",
                "mutates": False,
                "notes": "Gets the current or historical canvas document for a channel.",
            },
            {
                "name": "set",
                "mcp_tool": "buzz_canvas_set",
                "syntax": "buzz --format json canvas set --channel <uuid> --content <markdown-or-stdin>",
                "mutates": True,
                "notes": "Replaces the canvas document for a channel.",
            },
            {
                "name": "history",
                "mcp_tool": "buzz_canvas_history",
                "syntax": "buzz --format json canvas history --channel <uuid>",
                "mutates": False,
                "notes": "Lists canvas revision history for a channel, newest first.",
            },
            {
                "name": "restore",
                "mcp_tool": "buzz_canvas_restore",
                "syntax": "buzz --format json canvas restore --channel <uuid> --revision <event-id>",
                "mutates": True,
                "notes": "Restores the canvas to a previous revision by re-publishing its content.",
            },
        ],
    },
    {
        "domain": "sidebar",
        "introduced": "1.0.0",
        "nips": ["NIP-51", "NIP-78"],
        "summary": "Organize sidebar sections, sort modes, starred channels, muted channels, and project pins.",
        "keywords": ["sidebar", "sections", "sort", "stars", "mutes", "projects", "pin", "reorder"],
        "subcommands": [
            {
                "name": "sections",
                "mcp_tool": "buzz_sidebar_sections",
                "syntax": "buzz --format json sidebar sections <list|create|update|delete|reorder|move|unassign>",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: lists, creates, renames, reorders, or assigns channels to sidebar sections.",
            },
            {
                "name": "sort",
                "mcp_tool": "buzz_sidebar_sort",
                "syntax": "buzz --format json sidebar sort <list|set|reset>",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: lists or sets sidebar group sort mode (alpha vs recent activity).",
            },
            {
                "name": "stars",
                "mcp_tool": "buzz_sidebar_stars",
                "syntax": "buzz --format json sidebar stars <list|add|remove>",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: lists, stars, or unstars channels.",
            },
            {
                "name": "mutes",
                "mcp_tool": "buzz_sidebar_mutes",
                "syntax": "buzz --format json sidebar mutes <list|add|remove>",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: lists, mutes, or unmutes channels.",
            },
            {
                "name": "projects",
                "mcp_tool": "buzz_sidebar_projects",
                "syntax": "buzz --format json sidebar projects <list|add|remove>",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: lists, pins, or unpins NIP-MP projects in the sidebar.",
            },
        ],
    },
    {
        "domain": "reactions",
        "introduced": "0.5.x",
        "nips": ["NIP-25", "NIP-30"],
        "summary": "Add, remove, and list emoji or custom shortcode reactions on messages.",
        "keywords": ["reaction", "emoji", "like", "upvote", "nip-25"],
        "subcommands": [
            {
                "name": "add",
                "mcp_tool": "buzz_reactions_add",
                "syntax": "buzz --format json reactions add --event <event-id> --emoji <emoji> [--emoji-url <url>]",
                "mutates": True,
                "notes": "Adds an emoji reaction (kind:7) to a message.",
            },
            {
                "name": "remove",
                "mcp_tool": "buzz_reactions_remove",
                "syntax": "buzz --format json reactions remove --event <event-id> --emoji <emoji>",
                "mutates": True,
                "notes": "Removes an emoji reaction from a message.",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_reactions_get",
                "syntax": "buzz --format json reactions get --event <event-id>",
                "mutates": False,
                "notes": "Lists reactions on a message.",
            },
        ],
    },
    {
        "domain": "emoji",
        "introduced": "0.5.x",
        "nips": ["NIP-30"],
        "summary": "Manage custom NIP-30 workspace emoji sets (list, set, rm, export, import).",
        "keywords": ["emoji", "custom emoji", "shortcode", "nip-30", "palette"],
        "subcommands": [
            {
                "name": "list",
                "mcp_tool": "buzz_emoji_list",
                "syntax": "buzz --format json emoji list",
                "mutates": False,
                "notes": "Lists the workspace custom emoji palette (union of every member's set).",
            },
            {
                "name": "set",
                "mcp_tool": "buzz_emoji_set",
                "syntax": "buzz --format json emoji set --shortcode <name> --url <blossom-url>",
                "mutates": True,
                "notes": "Adds or updates a custom emoji in your own set.",
            },
            {
                "name": "rm",
                "mcp_tool": "buzz_emoji_rm",
                "syntax": "buzz --format json emoji rm --shortcode <name>",
                "mutates": True,
                "notes": "Removes a custom emoji from your own set.",
            },
            {
                "name": "export",
                "mcp_tool": "buzz_emoji_export",
                "syntax": "buzz --format json emoji export [--output <path>]",
                "mutates": False,
                "notes": "Exports custom emojis to stdout or a file.",
            },
            {
                "name": "import",
                "mcp_tool": "buzz_emoji_import",
                "syntax": "buzz --format json emoji import [--file <path>]",
                "mutates": True,
                "notes": "Imports custom emojis into your own set.",
            },
        ],
    },
    {
        "domain": "gifs",
        "introduced": "0.5.x",
        "nips": ["NIP-29"],
        "summary": "Search and share GIFs via the relay's KLIPY proxy.",
        "keywords": ["gif", "klipy", "media", "animate"],
        "subcommands": [
            {
                "name": "search",
                "mcp_tool": "buzz_gifs_search",
                "syntax": "buzz --format json gifs search [--query <text>]",
                "mutates": False,
                "notes": "Searches or browses trending GIFs via the relay's KLIPY proxy.",
            },
            {
                "name": "share",
                "mcp_tool": "buzz_gifs_share",
                "syntax": "buzz --format json gifs share --id <gif-id>",
                "mutates": True,
                "notes": "Reports a selected GIF to the provider so it enters Recents.",
            },
        ],
    },
    {
        "domain": "dms",
        "introduced": "0.5.x",
        "nips": ["NIP-17", "NIP-44", "NIP-59"],
        "summary": "List, open, add members to, and hide direct message conversations.",
        "keywords": ["dm", "direct message", "private", "conversation"],
        "subcommands": [
            {
                "name": "list",
                "mcp_tool": "buzz_dms_list",
                "syntax": "buzz --format json dms list",
                "mutates": False,
                "notes": "Lists direct message conversations.",
            },
            {
                "name": "open",
                "mcp_tool": "buzz_dms_open",
                "syntax": "buzz --format json dms open --pubkey <hex-or-npub>...",
                "mutates": True,
                "notes": "Opens a direct message conversation with one or more users.",
            },
            {
                "name": "add-member",
                "mcp_tool": "buzz_dms_add_member",
                "syntax": "buzz --format json dms add-member --channel <dm-id> --pubkey <hex-or-npub>",
                "mutates": True,
                "notes": "Adds a member to an existing group DM conversation.",
            },
            {
                "name": "hide",
                "mcp_tool": "buzz_dms_hide",
                "syntax": "buzz --format json dms hide --channel <dm-id>",
                "mutates": True,
                "notes": "Hides a DM conversation from your DM list.",
            },
        ],
    },
    {
        "domain": "huddles",
        "introduced": "1.0.0",
        "nips": ["NIP-29", "NIP-100"],
        "summary": "List channel audio/video huddles and inspect active huddle participants (read-only).",
        "keywords": ["huddle", "voice", "call", "participants", "audio", "video"],
        "subcommands": [
            {
                "name": "list",
                "mcp_tool": "buzz_huddles_list",
                "syntax": "buzz --format json huddles list --channel <uuid>",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: lists a channel's huddles with state and start/end times.",
            },
            {
                "name": "participants",
                "mcp_tool": "buzz_huddles_participants",
                "syntax": "buzz --format json huddles participants --huddle <id>",
                "mutates": False,
                "notes": "Added in 1.0.0 CLI: shows who is currently in a huddle.",
            },
        ],
    },
    {
        "domain": "users",
        "introduced": "0.5.x",
        "nips": ["NIP-01", "NIP-38"],
        "summary": "Look up user profiles, update profile metadata, and manage presence and NIP-38 statuses.",
        "keywords": ["user", "profile", "presence", "status", "nip-38", "kind:0", "lookup"],
        "subcommands": [
            {
                "name": "get",
                "mcp_tool": "buzz_users_get",
                "syntax": "buzz --format json users get [--pubkey <hex-or-npub>] [--query <name>]",
                "mutates": False,
                "notes": "Looks up user profiles by pubkey or name.",
            },
            {
                "name": "set-profile",
                "mcp_tool": "buzz_users_set_profile",
                "syntax": "buzz --format json users set-profile [--name <name>] [--about <text>] [--picture <url>]",
                "mutates": True,
                "notes": "Updates the current identity's kind:0 profile.",
            },
            {
                "name": "presence",
                "mcp_tool": "buzz_users_presence",
                "syntax": "buzz --format json users presence [--pubkey <hex-or-npub>...]",
                "mutates": False,
                "notes": "Gets presence status for users.",
            },
            {
                "name": "set-presence",
                "mcp_tool": "buzz_users_set_presence",
                "syntax": "buzz --format json users set-presence --status <online|away|offline>",
                "mutates": True,
                "notes": "Sets your presence status.",
            },
            {
                "name": "set-status",
                "mcp_tool": "buzz_users_set_status",
                "syntax": "buzz --format json users set-status --content <text> [--emoji <emoji>]",
                "mutates": True,
                "notes": "Sets your NIP-38 kind:30315 user status line.",
            },
            {
                "name": "status",
                "mcp_tool": "buzz_users_status",
                "syntax": "buzz --format json users status [--pubkey <hex-or-npub>...]",
                "mutates": False,
                "notes": "Reads user statuses (NIP-38 kind:30315).",
            },
        ],
    },
    {
        "domain": "workflows",
        "introduced": "0.5.x",
        "nips": ["NIP-29"],
        "summary": "Create, update, trigger, inspect runs, and approve steps on YAML channel workflows.",
        "keywords": ["workflow", "yaml", "trigger", "runs", "approve", "automation"],
        "subcommands": [
            {
                "name": "list",
                "mcp_tool": "buzz_workflows_list",
                "syntax": "buzz --format json workflows list --channel <uuid>",
                "mutates": False,
                "notes": "Lists workflows in a channel.",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_workflows_get",
                "syntax": "buzz --format json workflows get --workflow <id>",
                "mutates": False,
                "notes": "Gets details for a single workflow.",
            },
            {
                "name": "create",
                "mcp_tool": "buzz_workflows_create",
                "syntax": "buzz --format json workflows create --channel <uuid> --file <yaml-path>",
                "mutates": True,
                "notes": "Creates a workflow from a YAML definition.",
            },
            {
                "name": "update",
                "mcp_tool": "buzz_workflows_update",
                "syntax": "buzz --format json workflows update --workflow <id> --file <yaml-path>",
                "mutates": True,
                "notes": "Updates a workflow's YAML definition.",
            },
            {
                "name": "delete",
                "mcp_tool": "buzz_workflows_delete",
                "syntax": "buzz --format json workflows delete --workflow <id>",
                "mutates": True,
                "notes": "Deletes a workflow.",
            },
            {
                "name": "trigger",
                "mcp_tool": "buzz_workflows_trigger",
                "syntax": "buzz --format json workflows trigger --workflow <id> [--inputs <json>]",
                "mutates": True,
                "notes": "Triggers a workflow run.",
            },
            {
                "name": "runs",
                "mcp_tool": "buzz_workflows_runs",
                "syntax": "buzz --format json workflows runs --workflow <id>",
                "mutates": False,
                "notes": "Lists runs for a workflow.",
            },
            {
                "name": "approve",
                "mcp_tool": "buzz_workflows_approve",
                "syntax": "buzz --format json workflows approve --run <run-id> --step <step-id> [--deny]",
                "mutates": True,
                "notes": "Approves or denies a gated workflow step.",
            },
        ],
    },
    {
        "domain": "feed",
        "introduced": "0.5.x",
        "nips": ["NIP-29"],
        "summary": "Read recent activity feed entries, mentions, and thread notifications.",
        "keywords": ["feed", "activity", "mentions", "notifications", "inbox"],
        "subcommands": [
            {
                "name": "get",
                "mcp_tool": "buzz_feed_get",
                "syntax": "buzz --format agent feed get [--limit <n>]",
                "mutates": False,
                "notes": "Gets recent activity feed entries.",
            },
        ],
    },
    {
        "domain": "social",
        "introduced": "0.5.x",
        "nips": ["NIP-01", "NIP-02", "NIP-51", "NIP-65"],
        "summary": "Publish kind:1 social notes and manage NIP-02 contacts and NIP-51/NIP-65 lists.",
        "keywords": ["social", "kind:1", "contacts", "nip-02", "nip-51", "nip-65"],
        "subcommands": [
            {
                "name": "publish",
                "mcp_tool": "buzz_social_publish",
                "syntax": "buzz --format json social publish --content <text>",
                "mutates": True,
                "notes": "Publishes a Nostr text note (NIP-01 kind:1).",
            },
            {
                "name": "set-contacts",
                "mcp_tool": "buzz_social_set_contacts",
                "syntax": "buzz --format json social set-contacts --pubkey <hex-or-npub>...",
                "mutates": True,
                "notes": "Sets your contact list (NIP-02 kind:3).",
            },
            {
                "name": "event",
                "mcp_tool": "buzz_social_event",
                "syntax": "buzz --format json social event --id <event-id>",
                "mutates": False,
                "notes": "Gets a single Nostr event by ID.",
            },
            {
                "name": "notes",
                "mcp_tool": "buzz_social_notes",
                "syntax": "buzz --format json social notes --pubkey <hex-or-npub> [--limit <n>]",
                "mutates": False,
                "notes": "Gets recent social notes published by a user.",
            },
            {
                "name": "contacts",
                "mcp_tool": "buzz_social_contacts",
                "syntax": "buzz --format json social contacts --pubkey <hex-or-npub>",
                "mutates": False,
                "notes": "Gets a user's contact list.",
            },
            {
                "name": "set-list",
                "mcp_tool": "buzz_social_set_list",
                "syntax": "buzz --format json social set-list --kind <kind> --d-tag <slug>",
                "mutates": True,
                "notes": "Publishes a NIP-51/NIP-65 social list or set.",
            },
            {
                "name": "list",
                "mcp_tool": "buzz_social_list",
                "syntax": "buzz --format json social list --pubkey <hex-or-npub> --kind <kind>",
                "mutates": False,
                "notes": "Gets NIP-51/NIP-65 social lists or sets by author and kind.",
            },
        ],
    },
    {
        "domain": "notes",
        "introduced": "0.5.x",
        "nips": ["NIP-23", "NIP-09"],
        "summary": "Publish, read, list, and delete long-form NIP-23 team knowledge base notes (`kind:30023`).",
        "keywords": ["note", "knowledge", "wiki", "nip-23", "30023", "article", "naddr"],
        "subcommands": [
            {
                "name": "set",
                "mcp_tool": "buzz_notes_set",
                "syntax": "buzz --format json notes set --name <slug> --title <title> --content <markdown-or-stdin>",
                "mutates": True,
                "notes": "Creates or updates a long-form note (idempotent upsert keyed by author and --name).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_notes_get",
                "syntax": "buzz --format json notes get [--naddr <naddr> | --name <slug>]",
                "mutates": False,
                "notes": "Reads a note by exact --naddr or cross-author --name slug.",
            },
            {
                "name": "ls",
                "mcp_tool": "buzz_notes_ls",
                "syntax": "buzz --format json notes ls [--author <pubkey>]",
                "mutates": False,
                "notes": "Lists long-form notes on the relay.",
            },
            {
                "name": "rm",
                "mcp_tool": "buzz_notes_rm",
                "syntax": "buzz --format json notes rm --name <slug>",
                "mutates": True,
                "notes": "Deletes one of your own notes via NIP-09 (kind:5).",
            },
        ],
    },
    {
        "domain": "repos",
        "introduced": "0.5.x",
        "nips": ["NIP-34"],
        "summary": "Announce, discover, bind, protect branches/tags, and set default branches on NIP-34 Git repositories.",
        "keywords": ["repo", "git", "nip-34", "bind", "protect", "default-branch", "30617"],
        "subcommands": [
            {
                "name": "create",
                "mcp_tool": "buzz_repos_create",
                "syntax": "buzz --format json repos create --id <slug> --name <name> [--description <text>]",
                "mutates": True,
                "notes": "Announces a Git repository (NIP-34 kind:30617).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_repos_get",
                "syntax": "buzz --format json repos get --repo <id>",
                "mutates": False,
                "notes": "Gets a repository announcement.",
            },
            {
                "name": "list",
                "mcp_tool": "buzz_repos_list",
                "syntax": "buzz --format json repos list",
                "mutates": False,
                "notes": "Lists repository announcements on the relay.",
            },
            {
                "name": "bind",
                "mcp_tool": "buzz_repos_bind",
                "syntax": "buzz --format json repos bind --repo <id> --channel <uuid>",
                "mutates": True,
                "notes": "Binds or rebinds a repository to a channel.",
            },
            {
                "name": "protect",
                "mcp_tool": "buzz_repos_protect",
                "syntax": "buzz --format json repos protect <list|set|remove> --repo <id>",
                "mutates": True,
                "notes": "Added in 1.0.0 CLI: manages branch and tag protection rules on a repository.",
            },
            {
                "name": "default-branch",
                "mcp_tool": "buzz_repos_default_branch",
                "syntax": "buzz --format json repos default-branch <get|set> --repo <id> [--branch <name>]",
                "mutates": True,
                "notes": "Added in 1.0.0 CLI: inspects or changes the relay-hosted repository's default branch.",
            },
        ],
    },
    {
        "domain": "projects",
        "introduced": "1.0.0",
        "nips": ["NIP-MP", "NIP-34"],
        "summary": "Create and manage NIP-MP multi-repo projects (`kind:30621`).",
        "keywords": ["project", "multi-repo", "nip-mp", "30621", "add-repo", "add-channel"],
        "subcommands": [
            {
                "name": "create",
                "mcp_tool": "buzz_projects_create",
                "syntax": "buzz --format json projects create --slug <slug> --name <name> [--description <text>]",
                "mutates": True,
                "notes": "Creates a new multi-repo project (NIP-MP kind:30621).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_projects_get",
                "syntax": "buzz --format json projects get --slug <slug>",
                "mutates": False,
                "notes": "Gets a project by slug.",
            },
            {
                "name": "list",
                "mcp_tool": "buzz_projects_list",
                "syntax": "buzz --format json projects list",
                "mutates": False,
                "notes": "Lists NIP-MP projects on the relay.",
            },
            {
                "name": "add-repo",
                "mcp_tool": "buzz_projects_add_repo",
                "syntax": "buzz --format json projects add-repo --slug <slug> --repo <repo-coord>...",
                "mutates": True,
                "notes": "Adds one or more member repositories to a project.",
            },
            {
                "name": "add-channel",
                "mcp_tool": "buzz_projects_add_channel",
                "syntax": "buzz --format json projects add-channel --slug <slug> --name <channel-name>",
                "mutates": True,
                "notes": "Drafts a project-linked channel for owner review in Buzz Desktop.",
            },
            {
                "name": "remove-repo",
                "mcp_tool": "buzz_projects_remove_repo",
                "syntax": "buzz --format json projects remove-repo --slug <slug> --repo <repo-coord>...",
                "mutates": True,
                "notes": "Removes one or more member repositories from a project.",
            },
            {
                "name": "update",
                "mcp_tool": "buzz_projects_update",
                "syntax": "buzz --format json projects update --slug <slug> [--name <name>] [--description <text>]",
                "mutates": True,
                "notes": "Updates project metadata.",
            },
            {
                "name": "delete",
                "mcp_tool": "buzz_projects_delete",
                "syntax": "buzz --format json projects delete --slug <slug>",
                "mutates": True,
                "notes": "Deletes a project via head-based tombstone.",
            },
        ],
    },
    {
        "domain": "patches",
        "introduced": "0.5.x",
        "nips": ["NIP-34"],
        "summary": "Send, get, list, and set status on NIP-34 Git patches (`kind:1617`).",
        "keywords": ["patch", "git patch", "1617", "nip-34", "diff"],
        "subcommands": [
            {
                "name": "send",
                "mcp_tool": "buzz_patches_send",
                "syntax": "buzz --format json patches send --repo <id> --file <patch-file>",
                "mutates": True,
                "notes": "Sends a Git patch (NIP-34 kind:1617).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_patches_get",
                "syntax": "buzz --format json patches get --event <event-id>",
                "mutates": False,
                "notes": "Gets a patch by event ID.",
            },
            {
                "name": "list",
                "mcp_tool": "buzz_patches_list",
                "syntax": "buzz --format json patches list --repo <id>",
                "mutates": False,
                "notes": "Lists patches for a repository.",
            },
            {
                "name": "status",
                "mcp_tool": "buzz_patches_status",
                "syntax": "buzz --format json patches status --event <event-id> --status <open|merged|closed|draft>",
                "mutates": True,
                "notes": "Sets status on a patch (NIP-34 kind:1630-1633).",
            },
        ],
    },
    {
        "domain": "issues",
        "introduced": "0.5.x",
        "nips": ["NIP-34"],
        "summary": "Create, get, list, assign, unassign, and set status on NIP-34 Git issues (`kind:1621`).",
        "keywords": ["issue", "bug", "ticket", "assign", "unassign", "1621", "nip-34"],
        "subcommands": [
            {
                "name": "create",
                "mcp_tool": "buzz_issues_create",
                "syntax": "buzz --format json issues create --repo <id> --title <title> --content <body-or-stdin>",
                "mutates": True,
                "notes": "Creates a Git issue (NIP-34 kind:1621).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_issues_get",
                "syntax": "buzz --format json issues get --event <event-id>",
                "mutates": False,
                "notes": "Gets an issue by event ID.",
            },
            {
                "name": "list",
                "mcp_tool": "buzz_issues_list",
                "syntax": "buzz --format json issues list --repo <id>",
                "mutates": False,
                "notes": "Lists issues for a repository.",
            },
            {
                "name": "status",
                "mcp_tool": "buzz_issues_status",
                "syntax": "buzz --format json issues status --event <event-id> --status <open|resolved|closed|draft>",
                "mutates": True,
                "notes": "Sets status on an issue (NIP-34 kind:1630-1633).",
            },
            {
                "name": "assign",
                "mcp_tool": "buzz_issues_assign",
                "syntax": "buzz --format json issues assign --event <event-id> --pubkey <hex-or-npub>...",
                "mutates": True,
                "notes": "Assigns an issue to one or more people or agents.",
            },
            {
                "name": "unassign",
                "mcp_tool": "buzz_issues_unassign",
                "syntax": "buzz --format json issues unassign --event <event-id> --pubkey <hex-or-npub>...",
                "mutates": True,
                "notes": "Removes one or more assignees from an issue.",
            },
        ],
    },
    {
        "domain": "pr",
        "introduced": "0.5.x",
        "nips": ["NIP-34"],
        "summary": "Open, update tip, get, list, and set status on NIP-34 Git pull requests (`kind:1618-1619`).",
        "keywords": ["pr", "pull request", "merge", "1618", "1619", "nip-34"],
        "subcommands": [
            {
                "name": "open",
                "mcp_tool": "buzz_pr_open",
                "syntax": "buzz --format json pr open --repo <id> --title <title> --branch <branch> --commit <sha>",
                "mutates": True,
                "notes": "Opens a Git pull request (NIP-34 kind:1618).",
            },
            {
                "name": "update",
                "mcp_tool": "buzz_pr_update",
                "syntax": "buzz --format json pr update --event <pr-event-id> --commit <new-sha>",
                "mutates": True,
                "notes": "Updates a Git pull request tip (NIP-34 kind:1619).",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_pr_get",
                "syntax": "buzz --format json pr get --event <pr-event-id>",
                "mutates": False,
                "notes": "Gets a pull request by event ID.",
            },
            {
                "name": "list",
                "mcp_tool": "buzz_pr_list",
                "syntax": "buzz --format json pr list --repo <id>",
                "mutates": False,
                "notes": "Lists pull requests for a repository.",
            },
            {
                "name": "status",
                "mcp_tool": "buzz_pr_status",
                "syntax": "buzz --format json pr status --event <pr-event-id> --status <open|merged|closed|draft>",
                "mutates": True,
                "notes": "Sets status on a pull request (NIP-34 kind:1630-1633).",
            },
        ],
    },
    {
        "domain": "media",
        "introduced": "0.5.x",
        "nips": ["BUD-01", "NIP-98"],
        "summary": "Download authenticated Blossom media blobs from the relay.",
        "keywords": ["media", "download", "blossom", "blob", "attachment"],
        "subcommands": [
            {
                "name": "get",
                "mcp_tool": "buzz_media_get",
                "syntax": "buzz media get --url <blossom-url-or-sha256> --output <path>",
                "mutates": False,
                "notes": "Downloads relay media using signed Blossom get auth.",
            },
        ],
    },
    {
        "domain": "upload",
        "introduced": "0.5.x",
        "nips": ["BUD-02", "NIP-94"],
        "summary": "Upload files to the relay's Blossom media store.",
        "keywords": ["upload", "file", "blossom", "attachment", "image", "audio"],
        "subcommands": [
            {
                "name": "file",
                "mcp_tool": "buzz_upload_file",
                "syntax": "buzz --format json upload file <path>",
                "mutates": True,
                "notes": "Uploads a file to the relay's Blossom store and returns its SHA-256 and URL.",
            },
        ],
    },
    {
        "domain": "mem",
        "introduced": "0.5.x",
        "nips": ["NIP-AE"],
        "summary": "Manage persistent NIP-AE agent memory engrams (`ls`, `get`, `hash`, `set`, `patch`, `rm`).",
        "keywords": ["mem", "memory", "engram", "nip-ae", "slug", "patch", "base-hash", "core"],
        "subcommands": [
            {
                "name": "ls",
                "mcp_tool": "buzz_mem_ls",
                "syntax": "buzz --format json mem ls",
                "mutates": False,
                "notes": "Lists non-tombstoned NIP-AE memory entries.",
            },
            {
                "name": "get",
                "mcp_tool": "buzz_mem_get",
                "syntax": "buzz mem get <slug>",
                "mutates": False,
                "notes": "Prints the value of a memory slug to stdout.",
            },
            {
                "name": "hash",
                "mcp_tool": "buzz_mem_hash",
                "syntax": "buzz mem hash <slug>",
                "mutates": False,
                "notes": "Prints sha256(value) in hex for optimistic concurrency (--base-hash on mem patch).",
            },
            {
                "name": "set",
                "mcp_tool": "buzz_mem_set",
                "syntax": "buzz --format json mem set <slug> <value-or-dash-for-stdin>",
                "mutates": True,
                "notes": "Sets a memory slug's value.",
            },
            {
                "name": "patch",
                "mcp_tool": "buzz_mem_patch",
                "syntax": "buzz --format json mem patch <slug> --base-hash <sha256> <diff-or-stdin>",
                "mutates": True,
                "notes": "Applies a unified diff to a slug's value guarded by --base-hash (exits 5 on conflict).",
            },
            {
                "name": "rm",
                "mcp_tool": "buzz_mem_rm",
                "syntax": "buzz --format json mem rm <slug>",
                "mutates": True,
                "notes": "Publishes a tombstone for a memory slug (cannot be used on core).",
            },
        ],
    },
    {
        "domain": "pack",
        "introduced": "0.5.x",
        "nips": ["NIP-AE"],
        "summary": "Validate and inspect local agent persona packs offline without a relay connection.",
        "keywords": ["pack", "persona", "validate", "inspect", "agent config"],
        "subcommands": [
            {
                "name": "validate",
                "mcp_tool": "buzz_pack_validate",
                "syntax": "buzz --format json pack validate <directory>",
                "mutates": False,
                "notes": "Validates a persona pack directory locally.",
            },
            {
                "name": "inspect",
                "mcp_tool": "buzz_pack_inspect",
                "syntax": "buzz --format json pack inspect <directory>",
                "mutates": False,
                "notes": "Inspects a persona pack and prints metadata and effective config.",
            },
        ],
    },
    {
        "domain": "auth",
        "introduced": "1.0.0",
        "nips": ["NIP-AB", "NIP-OA"],
        "summary": "Pair the CLI with a running Buzz Desktop instance (`pair`, `unpair`, `list`).",
        "keywords": ["auth", "desktop", "pair", "unpair", "credential", "nip-ab"],
        "subcommands": [
            {
                "name": "desktop",
                "mcp_tool": "buzz_auth_desktop",
                "syntax": "buzz --format json auth desktop <pair|unpair|list>",
                "mutates": True,
                "notes": "Added in 1.0.0 CLI: pairs CLI with Buzz Desktop on macOS/Linux; use BUZZ_PRIVATE_KEY on Windows.",
            },
        ],
    },
    {
        "domain": "moderation",
        "introduced": "0.5.x",
        "nips": ["NIP-29", "NIP-56"],
        "summary": "Community moderation queue, report resolution, bans, timeouts, restricted roster, and audit trail.",
        "keywords": ["moderation", "reports", "resolve", "ban", "unban", "timeout", "untimeout", "restricted", "audit"],
        "subcommands": [
            {
                "name": "reports",
                "mcp_tool": "buzz_moderation_reports",
                "syntax": "buzz --format json moderation reports",
                "mutates": False,
                "notes": "Lists NIP-56 reports in the moderation queue (newest first).",
            },
            {
                "name": "resolve",
                "mcp_tool": "buzz_moderation_resolve",
                "syntax": "buzz --format json moderation resolve --report <event-id> [--dismiss]",
                "mutates": True,
                "notes": "Resolves or dismisses a moderation report (kind:9044).",
            },
            {
                "name": "ban",
                "mcp_tool": "buzz_moderation_ban",
                "syntax": "buzz --format json moderation ban --pubkey <hex-or-npub> [--reason <text>]",
                "mutates": True,
                "notes": "Bans a member from the community (kind:9040).",
            },
            {
                "name": "unban",
                "mcp_tool": "buzz_moderation_unban",
                "syntax": "buzz --format json moderation unban --pubkey <hex-or-npub>",
                "mutates": True,
                "notes": "Lifts a member's ban (kind:9041).",
            },
            {
                "name": "timeout",
                "mcp_tool": "buzz_moderation_timeout",
                "syntax": "buzz --format json moderation timeout --pubkey <hex-or-npub> --duration <secs> [--reason <text>]",
                "mutates": True,
                "notes": "Times out a member (write-block, kind:9042).",
            },
            {
                "name": "untimeout",
                "mcp_tool": "buzz_moderation_untimeout",
                "syntax": "buzz --format json moderation untimeout --pubkey <hex-or-npub>",
                "mutates": True,
                "notes": "Clears a member's timeout early (kind:9043).",
            },
            {
                "name": "restricted",
                "mcp_tool": "buzz_moderation_restricted",
                "syntax": "buzz --format json moderation restricted",
                "mutates": False,
                "notes": "Lists currently restricted members (active ban or timeout).",
            },
            {
                "name": "audit",
                "mcp_tool": "buzz_moderation_audit",
                "syntax": "buzz --format json moderation audit",
                "mutates": False,
                "notes": "Reads the moderation audit trail (newest first).",
            },
        ],
    },
]


def query_mcp_map(domain: str | None = None, intent: str | None = None) -> dict[str, Any]:
    """Filter the 26-domain MCP-to-CLI reference map by domain name or free-text intent."""
    domains = MCP_DOMAINS
    if domain:
        needle = domain.strip().lower()
        domains = [item for item in domains if item["domain"].lower() == needle]
    if intent:
        terms = [tok.lower() for tok in intent.strip().split() if tok.strip()]
        matched: list[dict[str, Any]] = []
        for item in domains:
            haystack = " ".join(
                [
                    item["domain"],
                    item["summary"],
                    " ".join(item.get("nips", [])),
                    " ".join(item.get("keywords", [])),
                    " ".join(
                        f"{sub['name']} {sub['mcp_tool']} {sub['syntax']} {sub['notes']}"
                        for sub in item["subcommands"]
                    ),
                ]
            ).lower()
            score = sum(1 for term in terms if term in haystack)
            if score > 0:
                copy_item = dict(item)
                copy_item["match_score"] = score
                matched.append(copy_item)
        matched.sort(key=lambda entry: (-int(entry.get("match_score", 0)), str(entry["domain"])))
        domains = matched

    total_subcommands = sum(len(item["subcommands"]) for item in domains)
    return {
        "schema": "legends-buzz.mcp-map/v1",
        "domain_count": len(domains),
        "subcommand_count": total_subcommands,
        "filter_domain": domain,
        "filter_intent": intent,
        "global_agent_flags": GLOBAL_AGENT_FLAGS,
        "environment_variables": ENV_VARS,
        "exit_codes": EXIT_CODES,
        "domains": domains,
    }


def render_mcp_map_markdown(payload: dict[str, Any]) -> str:
    """Render the MCP-to-CLI payload as clean ASCII Markdown (zero em-dashes or en-dashes)."""
    lines: list[str] = [
        "# Block Buzz MCP-to-CLI Reference Map",
        "",
        f"- **Matched domains:** {payload['domain_count']}",
        f"- **Matched subcommands:** {payload['subcommand_count']}",
        "",
        "## Global Agent Flags",
        "",
        "| Flag | Introduced | Purpose |",
        "| --- | --- | --- |",
    ]
    for item in payload["global_agent_flags"]:
        lines.append(f"| `{item['flag']}` | `{item['introduced']}` | {item['description']} |")
    lines.extend(
        [
            "",
            "## Environment Variables",
            "",
            "| Variable | Introduced | Purpose |",
            "| --- | --- | --- |",
        ]
    )
    for item in payload["environment_variables"]:
        lines.append(f"| `{item['name']}` | `{item['introduced']}` | {item['purpose']} |")
    lines.extend(
        [
            "",
            "## Deterministic Exit Codes",
            "",
            "| Exit Code | Name | Meaning | Agent Action |",
            "| --- | --- | --- | --- |",
        ]
    )
    for code, meta in sorted(payload["exit_codes"].items(), key=lambda pair: int(pair[0])):
        lines.append(f"| `{code}` | `{meta['name']}` | {meta['meaning']} | {meta['agent_action']} |")

    lines.extend(["", "## Command Domains", ""])
    for item in payload["domains"]:
        nips = ", ".join(item.get("nips", []))
        lines.append(f"### `{item['domain']}` (introduced in `{item['introduced']}`, NIPs: {nips})")
        lines.append("")
        lines.append(item["summary"])
        lines.append("")
        lines.append("| Subcommand | MCP Tool Equivalent | CLI Syntax | Mutates | Notes |")
        lines.append("| --- | --- | --- | --- | --- |")
        for sub in item["subcommands"]:
            mutates = "yes" if sub["mutates"] else "no"
            lines.append(
                f"| `{sub['name']}` | `{sub['mcp_tool']}` | `{sub['syntax']}` | {mutates} | {sub['notes']} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
