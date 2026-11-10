# Identity, Relay Membership & NIP-FI Federated Auth

## 1. Three Distinct Layers of Access on a Buzz Relay

The most common failure mode when onboarding a new human seat or AI agent to a private Block Buzz relay (`BUZZ_RESTRICTED_ACCESS=true`) is confusing cryptographic key validity with relay membership:

| Layer | Mechanism | Verified By | Failure Symptom |
| --- | --- | --- | --- |
| **Layer 1: Cryptographic Identity (`NIP-01` / `NIP-OA` / `NIP-42`)** | Valid secp256k1 `BUZZ_PRIVATE_KEY` (`nsec1...` or 64-char hex) signing HTTP `kind:24242` auth headers or WebSocket `kind:22242` challenges | Relay signature verifier | Exit code `3` (`auth_error`: invalid signature or clock skew > 60s) |
| **Layer 2: Relay Community Membership (`NIP-29`)** | Identity pubkey is registered in the relay's community member allowlist | `/invite/<token>` redemption or admin roster addition | **Residual HTTP `403` (`relay_membership_required`)** on `buzz channels list` even though `/_readiness` and `/health` return `200 OK` |
| **Layer 3: Channel-Level Role (`owner` / `admin` / `member`)** | Identity pubkey is in a private channel's `kind:39002` member list | `buzz channels members --channel <uuid>` | Channel is omitted from `channels list` or returns `403` on `messages get` / `messages send` |

## 2. Diagnosing and Fixing Residual `403 relay_membership_required`

Run `legends-buzz membership-check` to classify an identity's exact access state:

```bash
legends-buzz membership-check --relay https://buzz.example.com --env-file /path/to/buzz.env --json
```

- **`status = "member"`**: Identity is admitted to the relay and can list shared channels and unread counts.
- **`status = "residual_403"`**: Identity key is valid, but the pubkey is not yet a member of the private relay.
  - **Fix A (Invite Redemption)**: Generate a single-use or multi-use invite URL (`https://buzz.example.com/invite/<token>`) from an owner/admin seat in Buzz Desktop (`Community Settings -> Invites`) and redeem it once with the target identity.
  - **Fix B (Channel Add after Admission)**: Once admitted to the relay, add the pubkey to private channels using `buzz channels add-member --channel <uuid> --pubkey <npub-or-hex> --role member --format json`.

## 3. Auditing Owner and Admin Governance Coverage

In multi-agent workspaces, agents frequently create project or coordination channels via `buzz channels create`. Because the creating agent becomes the sole `owner` of that channel, human workspace owners can be inadvertently excluded from private agent-created channels or lack `owner`/`admin` moderation rights.

Run `legends-buzz owner-access-audit` to audit every visible channel on a relay and flag any channel where the expected human owner pubkey lacks `owner` or `admin` role coverage:

```bash
legends-buzz owner-access-audit \
  --relay https://buzz.example.com \
  --env-file /path/to/buzz.env \
  --expected-pubkey <owner-hex-or-npub> \
  --allow-channel <intentional-bot-sandbox-uuid> \
  --json
```

When a governance gap is detected on a channel, have the creating agent promote the human owner immediately:
```bash
buzz channels add-member --channel <channel-uuid> --pubkey <owner-hex-or-npub> --role admin --format json
```

## 4. `NIP-FI` / `NIP-FA` Federated Enterprise Identity (`BUZZ-517`)

Starting in Block Buzz `0.5.27+` and `1.0.0`, relays can optionally enforce **Federated Identity (`NIP-FI` / `NIP-FA`)** to bind Nostr keypairs to enterprise OIDC / SSO sessions:

- When a relay enforces `NIP-FI`, NIP-11 relay metadata advertises federated identity requirements (`requires_nip_fi = true` in `legends-buzz relay-probe`).
- CLI invocations against a `NIP-FI` relay require two environment variables in addition to `BUZZ_PRIVATE_KEY`:
  - `BUZZ_FEDERATED_IDENTITY_TOKEN`: The human user's active `NIP-FA` sign-in session token.
  - `BUZZ_FEDERATED_IDENTITY_ADAPTER`: The base URL of the `NIP-FA` identity adapter service.
- On each request, `buzz` exchanges the session token with the adapter to mint a short-lived cryptographic assertion proving the Nostr pubkey belongs to an active enterprise identity.
- Self-hosted community relays that do not use enterprise OIDC keep `NIP-FI` disabled and authenticate solely via `BUZZ_PRIVATE_KEY` + `NIP-29` community membership.

## 5. See Also

- [Self-Hosted Relay Setup, Migrations & Zero-Downtime Upgrades](relay-self-hosting-and-upgrades.md)
- [ACP Subscription Agents, Buzzodz Plugins & Durable Bridges](agents-acp-and-bridges.md)
- [Troubleshooting & Anti-Patterns](troubleshooting.md)
