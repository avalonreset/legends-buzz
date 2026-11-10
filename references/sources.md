# Primary Sources & Specifications

## Upstream Repositories & Releases

1. **Block Buzz Core Repository (`block/buzz`)**:
   - URL: `https://github.com/block/buzz`
   - Scope: `buzz-relay`, `buzz-cli`, `buzz-acp`, `buzz-agent`, `buzz-db`, `migrations/` (`0001..0060`), `docs/nips/`, and Buzz `0.X` Desktop (`desktop/`, reference release `desktop-v0.5.28`, commit `f87c10895`).
   - License: Apache License 2.0.
2. **Block Buzz 1.0 Desktop & Web Application (`block/buzz-app`)**:
   - URL: `https://github.com/block/buzz-app`
   - Scope: Buzz `1.0.0` Tauri/Web client (`v1.0.0`, commit `4fb386b0be5966f5ad9e930a33d1c75b432625fb`), `buzzodz` plugin system, `buzz-agent-controller`, `buzz-ifc` Information Flow Control, `nsec-backup`, and `NIP-AB` desktop pairing. Also bundles `bin/buzz` CLI built from `block/buzz` commit `c8d736642e1cddaca5797c54c0c625d16a1724ed`.
   - License: Apache License 2.0.
3. **Block Buzz Container Registry**:
   - URL: `https://github.com/block/buzz/pkgs/container/buzz`
   - Image coordinates: `ghcr.io/block/buzz@sha256:<digest>`

## Nostr & Block Buzz NIP Specifications

| Specification | Title / Scope | Reference |
| --- | --- | --- |
| `NIP-01` | Basic protocol flow, event serialization, and secp256k1 Schnorr signatures | `https://github.com/nostr-protocol/nips/blob/master/01.md` |
| `NIP-09` | Event deletion request (`kind:5`) | `https://github.com/nostr-protocol/nips/blob/master/09.md` |
| `NIP-10` | Conventions for `e` and `p` tags in text events (threads and replies) | `https://github.com/nostr-protocol/nips/blob/master/10.md` |
| `NIP-11` | Relay Information Document (`Accept: application/nostr+json`) | `https://github.com/nostr-protocol/nips/blob/master/11.md` |
| `NIP-17` / `NIP-44` / `NIP-59` | Private Direct Messages using versioned encryption and gift wraps (`kind:14`, `kind:1059`) | `https://github.com/nostr-protocol/nips/blob/master/17.md` |
| `NIP-23` | Long-form Content (`kind:30023`) | `https://github.com/nostr-protocol/nips/blob/master/23.md` |
| `NIP-25` | Reactions (`kind:7`) | `https://github.com/nostr-protocol/nips/blob/master/25.md` |
| `NIP-29` | Relay-based Groups (channels, member roles, `kind:9000-9022`, `kind:39000-39003`) | `https://github.com/nostr-protocol/nips/blob/master/29.md` |
| `NIP-30` | Custom Emoji (`:shortcode:` tags) | `https://github.com/nostr-protocol/nips/blob/master/30.md` |
| `NIP-34` | `git` stuff (repositories `kind:30617`, patches `kind:1617`, PRs `kind:1618-1619`, issues `kind:1621`) | `https://github.com/nostr-protocol/nips/blob/master/34.md` |
| `NIP-38` | User Statuses (`kind:30315`) | `https://github.com/nostr-protocol/nips/blob/master/38.md` |
| `NIP-42` | Authentication of clients to relays (`kind:22242`) | `https://github.com/nostr-protocol/nips/blob/master/42.md` |
| `NIP-50` | Search capability | `https://github.com/nostr-protocol/nips/blob/master/50.md` |
| `NIP-56` | Reporting (`kind:1984`) | `https://github.com/nostr-protocol/nips/blob/master/56.md` |
| `NIP-OA` | Block Buzz Owner Attestation and HTTP request auth (`kind:24242` / `BUZZ_AUTH_TAG`) | `https://github.com/block/buzz/tree/main/docs/nips` |
| `NIP-AE` | Block Buzz Agent Engrams (persistent memory `buzz mem`) | `https://github.com/block/buzz/tree/main/docs/nips` |
| `NIP-IA` | Block Buzz Identity Archive (`kind:9035`, `kind:9036`, `kind:13535`) | `https://github.com/block/buzz/tree/main/docs/nips` |
| `NIP-MP` | Block Buzz Multi-Repo Projects (`kind:30621`) | `https://github.com/block/buzz/tree/main/docs/nips` |
| `NIP-FI` / `NIP-FA` | Block Buzz Federated Identity and Adapter Assertions | `https://github.com/block/buzz/tree/main/docs/nips` |
| `NIP-AB` | Block Buzz Agent / CLI Desktop Pairing (`buzz auth desktop`) | `https://github.com/block/buzz/tree/main/docs/nips` |
