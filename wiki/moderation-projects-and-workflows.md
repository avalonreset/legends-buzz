# Moderation, NIP-34 Git Repos, NIP-MP Projects & Workflows

## 1. Community & Channel Moderation (`NIP-29` + `NIP-56`)

Block Buzz implements a two-tier moderation architecture with an immutable cryptographic audit trail:

### Tier 1: Channel Owner & Admin Message Deletion (`kind:9005`)

- Any message author can delete their own message via `NIP-09` (`kind:5`) or `buzz messages delete --event <event-id>`.
- Channel `owner` and `admin` roles (listed in `buzz channels members --channel <uuid>`) can delete any another author's message inside that channel by publishing a `NIP-29` `kind:9005` moderation deletion request (`buzz messages delete --event <event-id> --reason-code <code > --public-reason <text>`).
- In Buzz Desktop `0.5.28-owner.1`, the message action menu exposes `Delete message` directly to channel owners and admins even when they lack edit rights on the foreign author's message.

### Tier 2: Community-Wide Reports, Timeouts & Bans (`NIP-56` & `kind:9040-9044`)

| Action | CLI Command | Nostr Event Kind | Effect |
| --- | --- | --- | --- |
| File Content Report | `buzz messages report --event <id> --reason <cat>` | `kind:1984` (`NIP-56`) | Places the reported event/user in the community moderation queue |
| List Open Reports | `buzz moderation reports --format json` | Read API | Lists reports newest-first for moderator triage |
| Resolve / Dismiss Report | `buzz moderation resolve --report <id> [--dismiss]` | `kind:9044` | Marks a report resolved or dismissed in the audit trail |
| Temporary Timeout | `buzz moderation timeout --pubkey <pk> --duration <secs>` | `kind:9042` | Blocks the member from publishing new events for `<secs>` without removing read access |
| Lift Timeout Early | `buzz moderation untimeout --pubkey <pk>` | `kind:9043` | Clears an active timeout |
| Community Ban | `buzz moderation ban --pubkey <pk> [--reason <text>]` | `kind:9040` | Revokes relay membership and blocks events from `<pk>` |
| Lift Ban | `buzz moderation unban --pubkey <pk>` | `kind:9041` | Restores relay access for `<pk>` |
| Inspect Audit Log | `buzz moderation audit --format json` | Read API | Returns the chronological moderation audit trail |

## 2. `NIP-34` Git Repositories, Issues, PRs & Branch Protection

Block Buzz relays natively host and coordinate Git collaboration via `NIP-34`:

- **Repositories (`buzz repos`)**:
  - Announce a repository (`kind:30617`): `buzz repos create --id <slug> --name <name> --format json`
  - Bind a repository to a discussion channel: `buzz repos bind --repo <slug> --channel <uuid> --format json`
  - Configure branch/tag protection rules (`1.0.0+`): `buzz repos protect set --repo <slug> ...`
  - Read or change the relay-hosted default branch (`1.0.0+`): `buzz repos default-branch get --repo <slug>`
- **Issues (`buzz issues`, `kind:1621`)**:
  - Create, list, inspect, assign (`buzz issues assign`), unassign (`buzz issues unassign`), and transition status (`open`, `resolved`, `closed`, `draft` via `kind:1630-1633`).
- **Pull Requests (`buzz pr`, `kind:1618-1619`) & Patches (`buzz patches`, `kind:1617`)**:
  - Open a PR (`buzz pr open`), push a new tip commit (`buzz pr update`), or submit an email-style patch (`buzz patches send`), and update merge status (`buzz pr status --event <id> --status merged`).

## 3. `NIP-MP` Multi-Repo Projects (`kind:30621`)

Introduced in the `1.0.0` CLI, **Projects (`NIP-MP`, `kind:30621`)** group multiple `NIP-34` repositories and `NIP-29` channels into a single addressable workspace entity:

```bash
# Create a multi-repo project
buzz projects create --slug cto-legends --name "CTO Legends Suite" --format json

# Attach repositories and draft a project channel
buzz projects add-repo --slug cto-legends --repo <repo-coord> --format json
buzz projects add-channel --slug cto-legends --name "cto-legends-dev" --format json

# Pin the project in the user's sidebar
buzz sidebar projects add cto-legends --format json
```

## 4. Relay YAML Workflows (`buzz workflows`)

Channels can attach automated event-driven or cron-triggered YAML workflows:

- Inspect existing workflows: `buzz workflows list --channel <uuid> --format json`
- Deploy or update a workflow: `buzz workflows create --channel <uuid> --file workflow.yml --format json`
- Trigger a manual run and inspect execution logs: `buzz workflows trigger --workflow <id> --format json` and `buzz workflows runs --workflow <id> --format json`
- Approve or deny human-in-the-loop gated steps: `buzz workflows approve --run <run-id> --step <step-id> --format json`

## 5. See Also

- [Complete 26-Domain MCP-to-CLI Reference Map](mcp-to-cli-complete-map.md)
- [Identity, Relay Membership & NIP-FI Federated Auth](identity-membership-and-nip-fi.md)
- [Primary Sources & Specifications](../references/sources.md)
